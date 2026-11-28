package dnsrelay

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"

	"golang.org/x/net/proxy"

	"guestgate/internal/upstream"
)

func exchangeTCPDNS(ctx context.Context, dialer proxy.ContextDialer, target string, query []byte) ([]byte, error) {
	c, err := dialer.DialContext(upstream.WithPurpose(ctx, "DNS TCP", target), "tcp", target)
	if err != nil {
		return nil, err
	}
	defer c.Close()
	return queryDNSConn(ctx, c, query)
}

func queryDNSConn(ctx context.Context, c net.Conn, query []byte) ([]byte, error) {
	stop := context.AfterFunc(ctx, func() { c.Close() })
	defer stop()
	if deadline, ok := ctx.Deadline(); ok {
		c.SetDeadline(deadline)
	}
	frame := binary.BigEndian.AppendUint16(nil, uint16(len(query)))
	if _, err := c.Write(append(frame, query...)); err != nil {
		return nil, err
	}
	if _, err := io.ReadFull(c, frame); err != nil {
		return nil, err
	}
	reply := make([]byte, binary.BigEndian.Uint16(frame))
	if _, err := io.ReadFull(c, reply); err != nil {
		return nil, err
	}
	if len(reply) < 12 || reply[2]&0x80 == 0 || binary.BigEndian.Uint16(reply) != binary.BigEndian.Uint16(query) {
		return nil, errors.New("invalid TCP DNS response")
	}
	return reply, nil
}
