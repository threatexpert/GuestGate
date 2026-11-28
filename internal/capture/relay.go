package capture

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"time"
)

// Both sockets are already connected. This code has no dialer and cannot open a
// second path to the destination, even when certificate verification fails.
func (r *Recorder) Relay(ctx context.Context, guest, remote net.Conn, target, crlURL string) error {
	return r.relay(ctx, guest, remote, target, crlURL, r.lib.roots)
}

type buffered struct {
	net.Conn
	reader *bufio.Reader
}

func (c buffered) Read(p []byte) (int, error) { return c.reader.Read(p) }
func (c buffered) CloseWrite() error {
	if w, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return w.CloseWrite()
	}
	return c.Conn.Close()
}

// Go TLS accepts bare transport EOF between records. Keep it distinguishable
// from an authenticated close_notify in the recording's completion flags.
type tlsTransport struct{ net.Conn }

func (c tlsTransport) Read(b []byte) (int, error) {
	n, err := c.Conn.Read(b)
	if err == io.EOF {
		return n, errors.New("TLS transport closed without close_notify")
	}
	return n, err
}

// A server-first banner must flow even if the guest waits for it before sending.
func clientTLS(guest, remote buffered) (bool, error) {
	type first struct {
		side int
		b    byte
		err  error
	}
	ready := make(chan first, 2)
	for i, c := range []buffered{guest, remote} {
		go func() {
			b, e := c.reader.Peek(1)
			var v byte
			if len(b) > 0 {
				v = b[0]
			}
			ready <- first{i, v, e}
		}()
	}
	firstByte := <-ready
	other := remote
	if firstByte.side == 1 {
		other = guest
	}
	other.SetReadDeadline(time.Now())
	<-ready
	other.SetReadDeadline(time.Time{})
	if firstByte.err != nil && !errors.Is(firstByte.err, io.EOF) {
		return false, firstByte.err
	}
	if firstByte.side != 0 || firstByte.b != 22 {
		return false, nil
	}
	guest.SetReadDeadline(time.Now().Add(15 * time.Second))
	defer guest.SetReadDeadline(time.Time{})
	head, err := guest.reader.Peek(3)
	if err != nil {
		return false, err
	}
	return head[1] == 3 && head[2] <= 4, nil
}
func (r *Recorder) relay(ctx context.Context, g, u net.Conn, target, crlURL string, roots *x509.CertPool) (result error) {
	defer g.Close()
	defer u.Close()
	stop := context.AfterFunc(ctx, func() { g.Close(); u.Close() })
	defer stop()
	guest := buffered{g, bufio.NewReader(g)}
	remote := buffered{u, bufio.NewReader(u)}
	var tap *Tap
	var name, alpn string
	defer func() {
		reason := ""
		if result != nil {
			reason = result.Error()
		}
		if tap == nil && result != nil {
			tap = r.Open(target, name, "", false, false)
		}
		tap.Close(reason)
	}()
	encrypted, err := clientTLS(guest, remote)
	if err != nil {
		return err
	}
	var client, server net.Conn = guest, remote
	if encrypted {
		host, _, err := net.SplitHostPort(target)
		if err != nil {
			return err
		}
		handshake, cancel := context.WithTimeout(ctx, 26*time.Second)
		defer cancel()
		down := tls.Server(tlsTransport{guest}, &tls.Config{GetConfigForClient: func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
			name = hello.ServerName
			if name == "" {
				name = host
			}
			up := tls.Client(tlsTransport{remote}, &tls.Config{ServerName: name, RootCAs: roots, NextProtos: hello.SupportedProtos})
			if err := up.HandshakeContext(handshake); err != nil {
				return nil, fmt.Errorf("上游 TLS 握手或证书验证失败：%w", err)
			}
			server = up
			alpn = up.ConnectionState().NegotiatedProtocol
			cert, err := r.ca.leaf(name, crlURL)
			if err != nil {
				return nil, err
			}
			cfg := &tls.Config{Certificates: []tls.Certificate{cert}}
			if alpn != "" {
				cfg.NextProtos = []string{alpn}
			}
			return cfg, nil
		}})
		if err = down.HandshakeContext(handshake); err != nil {
			return fmt.Errorf("TLS 解密失败：%w", err)
		}
		cancel()
		client = down
	}
	tap = r.Open(target, name, alpn, encrypted, false)
	return relayStreams(client, server, tap)
}
func relayStreams(guest, remote net.Conn, tap *Tap) error {
	done := make(chan error, 2)
	copySide := func(dst, src net.Conn, side uintptr) {
		buf := make([]byte, 32<<10)
		for {
			n, err := src.Read(buf)
			if n > 0 {
				tap.Data(side, buf[:n])
				wrote, e := dst.Write(buf[:n])
				if e == nil && wrote != n {
					e = io.ErrShortWrite
				}
				if e != nil {
					done <- e
					return
				}
			}
			if err != nil {
				if errors.Is(err, io.EOF) {
					tap.EOF(side)
					if cw, ok := dst.(interface{ CloseWrite() error }); ok {
						cw.CloseWrite()
					}
					dst.SetReadDeadline(time.Now().Add(30 * time.Second))
					err = nil
				}
				done <- err
				return
			}
		}
	}
	go copySide(remote, guest, 0)
	go copySide(guest, remote, 1)
	err := <-done
	if err != nil {
		guest.Close()
		remote.Close()
	}
	return errors.Join(err, <-done)
}
