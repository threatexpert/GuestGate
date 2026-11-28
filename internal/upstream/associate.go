package upstream

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"github.com/threatexpert/gonc/v2/secure"
	"github.com/xjasonlyu/tun2socks/v2/transport/socks5"
	"golang.org/x/net/proxy"
)

var ErrHTTPUDPUnsupported = errors.New("HTTP CONNECT 不支持 UDP")
var ErrUDPUnsupported = errors.New("SOCKS5 UDP ASSOCIATE command unsupported")
var ErrUDPAssociateEOF = fmt.Errorf("%w: EOF before command reply", ErrUDPUnsupported)

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

func requestAssociation(c net.Conn, auth *proxy.Auth) (socks5.Addr, error) {
	if err := negotiate(c, auth); err != nil {
		return nil, err
	}
	var reply [3]byte
	if _, err := c.Write([]byte{5, byte(socks5.CmdUDPAssociate), 0, 1, 0, 0, 0, 0, 0, 0}); err != nil {
		return nil, err
	}
	if n, err := io.ReadFull(c, reply[:]); err != nil {
		// Some TCP-only proxies close on UDP ASSOCIATE without sending a reply.
		if n == 0 && errors.Is(err, io.EOF) {
			return nil, ErrUDPAssociateEOF
		}
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
		return nil, ErrUDPUnsupported
	default:
		return nil, fmt.Errorf("SOCKS5 UDP ASSOCIATE reply %d", reply[1])
	}
}

func (p *Client) Associate(parent context.Context) (net.Conn, net.Conn, error) {
	if p.Scheme == "http" {
		return nil, nil, ErrHTTPUDPUnsupported
	}
	if parent.Value(purposeKey{}) == nil {
		parent = WithPurpose(parent, DNSControl, p.Server)
	}
	ctx, cancel := context.WithTimeout(parent, 6*time.Second)
	defer cancel()
	var dialer net.Dialer
	control, err := p.transport.DialContext(ctx, "tcp", p.Server)
	if err != nil {
		return nil, nil, err
	}
	stop := context.AfterFunc(ctx, func() { control.Close() })
	defer stop()
	deadline, _ := ctx.Deadline()
	control.SetDeadline(deadline)
	bound, err := requestAssociation(control, p.auth)
	if err != nil {
		control.Close()
		return nil, nil, err
	}
	host, port, err := net.SplitHostPort(bound.String())
	if err != nil || port == "0" || host == "" {
		control.Close()
		return nil, nil, errors.New("invalid SOCKS5 UDP relay endpoint")
	}
	if ip := net.ParseIP(host); ip != nil && (ip.IsUnspecified() || (p.Scheme == "socks5s" && ip.IsPrivate())) {
		host, _, _ = net.SplitHostPort(control.RemoteAddr().String())
	}
	udp, err := dialer.DialContext(ctx, "udp", net.JoinHostPort(host, port))
	if err != nil {
		control.Close()
		return nil, nil, err
	}
	if p.Scheme == "socks5s" {
		state := control.(*tls.Conn).ConnectionState()
		key, exportErr := state.ExportKeyingMaterial("EXPERIMENTAL-SERVER-KEY", nil, 32)
		if exportErr != nil {
			control.Close()
			udp.Close()
			return nil, nil, exportErr
		}
		secured, wrapErr := secure.NewSecurePacketConn(udp, [32]byte(key))
		if wrapErr != nil {
			control.Close()
			udp.Close()
			return nil, nil, wrapErr
		}
		udp = secured
	}
	if !stop() {
		control.Close()
		udp.Close()
		return nil, nil, ctx.Err()
	}
	// Closing the generation must also synchronously close the UDP data socket.
	if registry := p.transport.connections; registry != nil {
		socket := control
		if secured, ok := socket.(*tls.Conn); ok {
			socket = secured.NetConn()
		}
		tracked := socket.(*observedConn)
		registry.mu.Lock()
		_, live := registry.active[tracked]
		if live && !registry.closed {
			tracked.datagram = udp
		} else {
			live = false
		}
		registry.mu.Unlock()
		if !live {
			control.Close()
			udp.Close()
			return nil, nil, net.ErrClosed
		}
	}
	control.SetDeadline(time.Time{})
	return control, udp, nil
}

func (p *Client) CheckSOCKS(ctx context.Context) error {
	c, err := p.transport.DialContext(ctx, "tcp", p.Server)
	if err != nil {
		return err
	}
	defer c.Close()
	stop := context.AfterFunc(ctx, func() { c.Close() })
	defer stop()
	if d, ok := ctx.Deadline(); ok {
		c.SetDeadline(d)
	}
	if err := negotiate(c, p.auth); err != nil {
		return fmt.Errorf("端口可达，SOCKS5 握手或认证失败 · %w", err)
	}
	return nil
}

type packetConn struct {
	net.Conn
	control net.Conn
	readMu  sync.Mutex
	frame   [65535]byte
}

func (p *Client) DialPacket(ctx context.Context) (net.PacketConn, error) {
	control, udp, err := p.Associate(ctx)
	if err != nil {
		return nil, err
	}
	go func() {
		io.Copy(io.Discard, control)
		udp.Close()
		control.Close()
	}()
	return &packetConn{Conn: udp, control: control}, nil
}
func (p *packetConn) Close() error {
	p.control.Close()
	return p.Conn.Close()
}
func (p *packetConn) WriteTo(b []byte, addr net.Addr) (int, error) {
	peer := socks5.ParseAddr(addr)
	if !peer.Valid() {
		return 0, errors.New("invalid UDP destination")
	}
	frame, err := socks5.EncodeUDPPacket(peer, b)
	if err != nil {
		return 0, err
	}
	if _, err = p.Write(frame); err != nil {
		return 0, err
	}
	return len(b), nil
}
func (p *packetConn) ReadFrom(b []byte) (int, net.Addr, error) {
	p.readMu.Lock()
	defer p.readMu.Unlock()
	n, err := p.Read(p.frame[:])
	if err != nil {
		return 0, nil, err
	}
	addr, payload, err := socks5.DecodeUDPPacket(p.frame[:n])
	if err != nil {
		return 0, nil, err
	}
	peer := addr.UDPAddr()
	if peer == nil {
		return 0, nil, errors.New("invalid UDP source")
	}
	return copy(b, payload), peer, nil
}
