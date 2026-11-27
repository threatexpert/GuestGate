package dnsrelay

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"time"

	"github.com/xjasonlyu/tun2socks/v2/transport/socks5"
	"golang.org/x/net/proxy"
)

var errUDPUnsupported = errors.New("SOCKS5 UDP ASSOCIATE command unsupported")

func negotiate(c net.Conn, auth *proxy.Auth) error {
	methods := []byte{5, 1, 0}
	if auth != nil {
		methods = []byte{5, 2, 0, 2}
	}
	if _, err := c.Write(methods); err != nil {
		return err
	}
	var reply [3]byte
	if _, err := io.ReadFull(c, reply[:2]); err != nil {
		return err
	}
	if reply[0] != 5 {
		return errors.New("invalid SOCKS5 negotiation")
	}
	switch reply[1] {
	case 0:
	case 2:
		if auth == nil || len(auth.User) == 0 || len(auth.User) > 255 || len(auth.Password) == 0 || len(auth.Password) > 255 {
			return errors.New("invalid SOCKS5 credentials")
		}
		msg := append([]byte{1, byte(len(auth.User))}, auth.User...)
		msg = append(msg, byte(len(auth.Password)))
		msg = append(msg, auth.Password...)
		if _, err := c.Write(msg); err != nil {
			return err
		}
		if _, err := io.ReadFull(c, reply[:2]); err != nil {
			return err
		}
		if reply[0] != 1 || reply[1] != 0 {
			return errors.New("SOCKS5 authentication failed")
		}
	default:
		return errors.New("SOCKS5 authentication method unavailable")
	}
	return nil
}

// Keep the numeric reply code: only REP 7 on the association request enables TCP DNS.
func requestDNSAssociation(c net.Conn, auth *proxy.Auth) (socks5.Addr, error) {
	if err := negotiate(c, auth); err != nil {
		return nil, err
	}
	var reply [3]byte
	if _, err := c.Write([]byte{5, byte(socks5.CmdUDPAssociate), 0, 1, 0, 0, 0, 0, 0, 0}); err != nil {
		return nil, err
	}
	if _, err := io.ReadFull(c, reply[:]); err != nil {
		return nil, err
	}
	if reply[0] != 5 || reply[2] != 0 {
		return nil, errors.New("invalid SOCKS5 command reply")
	}
	bound, err := socks5.ReadAddr(c, make([]byte, socks5.MaxAddrLen))
	if err != nil {
		return nil, err
	}
	switch reply[1] {
	case 0:
		return bound, nil
	case 7:
		return nil, errUDPUnsupported
	default:
		return nil, fmt.Errorf("SOCKS5 UDP ASSOCIATE reply %d", reply[1])
	}
}

func openDNSAssociation(parent context.Context, server string, auth *proxy.Auth) (*dnsAssociation, error) {
	ctx, cancel := context.WithTimeout(parent, 6*time.Second)
	defer cancel()
	var dialer net.Dialer
	control, err := dialer.DialContext(ctx, "tcp", server)
	if err != nil {
		return nil, err
	}
	stop := context.AfterFunc(ctx, func() { control.Close() })
	defer stop()
	deadline, _ := ctx.Deadline()
	control.SetDeadline(deadline)
	bound, err := requestDNSAssociation(control, auth)
	if err != nil {
		control.Close()
		return nil, err
	}
	host, port, err := net.SplitHostPort(bound.String())
	if err != nil || port == "0" || host == "" {
		control.Close()
		return nil, errors.New("invalid SOCKS5 UDP relay endpoint")
	}
	if ip := net.ParseIP(host); ip != nil && ip.IsUnspecified() {
		host, _, _ = net.SplitHostPort(control.RemoteAddr().String())
	}
	udp, err := dialer.DialContext(ctx, "udp", net.JoinHostPort(host, port))
	if err != nil {
		control.Close()
		return nil, err
	}
	if !stop() {
		control.Close()
		udp.Close()
		return nil, ctx.Err()
	}
	control.SetDeadline(time.Time{})
	return newDNSAssociation(control, udp), nil
}

func exchangeTCPDNS(ctx context.Context, dialer proxy.ContextDialer, target string, query []byte) ([]byte, error) {
	c, err := dialer.DialContext(ctx, "tcp", target)
	if err != nil {
		return nil, err
	}
	defer c.Close()
	stop := context.AfterFunc(ctx, func() { c.Close() })
	defer stop()
	if deadline, ok := ctx.Deadline(); ok {
		c.SetDeadline(deadline)
	}
	frame := binary.BigEndian.AppendUint16(nil, uint16(len(query)))
	if _, err = c.Write(append(frame, query...)); err != nil {
		return nil, err
	}
	if _, err = io.ReadFull(c, frame); err != nil {
		return nil, err
	}
	reply := make([]byte, binary.BigEndian.Uint16(frame))
	if _, err = io.ReadFull(c, reply); err != nil {
		return nil, err
	}
	if len(reply) < 12 || reply[2]&0x80 == 0 || binary.BigEndian.Uint16(reply) != binary.BigEndian.Uint16(query) {
		return nil, errors.New("invalid TCP DNS response")
	}
	return reply, nil
}
