// Package upstream implements the host-side connection to a guest's selected proxy.
package upstream

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/threatexpert/gonc/v2/secure"
	"golang.org/x/net/proxy"
)

type Client struct {
	Scheme, Server string
	auth           *proxy.Auth
	transport      controlDialer
	socks          proxy.ContextDialer
}

func Parse(raw string) (*Client, error) {
	raw = strings.TrimSpace(raw)
	if !strings.Contains(raw, "://") {
		raw = "socks5://" + raw
	}
	u, err := url.Parse(raw)
	if err != nil || u.Hostname() == "" || u.Path != "" || u.Fragment != "" {
		return nil, errors.New("请输入有效的上游代理地址和端口")
	}
	port, err := strconv.Atoi(u.Port())
	if err != nil || port < 1 || port > 65535 {
		return nil, errors.New("上游代理端口无效")
	}
	c := &Client{Server: net.JoinHostPort(u.Hostname(), u.Port()), Scheme: u.Scheme}
	if name := u.User.Username(); name != "" {
		pass, _ := u.User.Password()
		c.auth = &proxy.Auth{User: name, Password: pass}
	}
	switch c.Scheme {
	case "connect":
		c.Scheme = "http"
	case "http", "socks5", "socks5s":
	default:
		return nil, errors.New("支持 SOCKS5、HTTP CONNECT 和 GONC SOCKS5S")
	}
	if c.Scheme == "socks5s" {
		q, err := url.ParseQuery(u.RawQuery)
		if err != nil || len(q) != 1 || len(q["psk"]) != 1 || q.Get("psk") == "" {
			return nil, errors.New("GONC SOCKS5S 需要一个非空的 psk 参数")
		}
		key, err := secure.ReadPSKFile(q.Get("psk"))
		if err != nil || key == "" {
			return nil, errors.New("无法读取有效的 GONC PSK")
		}
		cert, err := secure.GenerateECDSACertificate(u.Hostname(), key)
		if err != nil {
			return nil, errors.New("无法生成 GONC PSK 客户端证书")
		}
		// GONC authenticates the peer by its PSK-derived public key instead of a public CA.
		c.transport.tls = &tls.Config{ServerName: u.Hostname(), Certificates: []tls.Certificate{*cert},
			InsecureSkipVerify: true, VerifyPeerCertificate: secure.VerifyPeerCertificateByPSK(key)}
	} else if u.RawQuery != "" || u.ForceQuery {
		return nil, errors.New("此代理协议不支持查询参数")
	}
	return c.FreshTransport()
}

// Rebuild the SOCKS dialer around a fresh socket registry without rereading a PSK file.
func (c *Client) FreshTransport() (*Client, error) {
	next := &Client{Server: c.Server, Scheme: c.Scheme, auth: c.auth, transport: controlDialer{tls: c.transport.tls}}
	if c.Scheme != "http" {
		d, err := proxy.SOCKS5("tcp", next.Server, next.auth, &next.transport)
		if err != nil {
			return nil, err
		}
		next.socks = d.(proxy.ContextDialer)
	}
	return next, nil
}

type controlDialer struct {
	tls         *tls.Config
	connections *Connections
}

func (d *controlDialer) Dial(network, address string) (net.Conn, error) {
	return d.DialContext(context.Background(), network, address)
}
func (d *controlDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	dialer := &net.Dialer{Timeout: 6 * time.Second}
	ctx, cancel := context.WithTimeout(ctx, 6*time.Second)
	defer cancel()
	if d.connections != nil {
		if d.connections.ctx.Err() != nil {
			return nil, net.ErrClosed
		}
		stop := context.AfterFunc(d.connections.ctx, cancel)
		defer stop()
	}
	raw, err := dialer.DialContext(ctx, network, address)
	if err != nil {
		return nil, err
	}
	label, ok := ctx.Value(purposeKey{}).(purpose)
	if !ok {
		label = purpose{"上游握手", address}
	}
	guest, _ := ctx.Value(guestKey{}).(*guestFlow)
	conn, err := d.connections.register(raw, label, guest)
	if err != nil {
		return nil, err
	}
	if d.tls == nil {
		return conn, nil
	}
	secure := tls.Client(conn, d.tls)
	if err = secure.HandshakeContext(ctx); err != nil {
		conn.Close()
		return nil, err
	}
	return secure, nil
}

func (c *Client) Display() string {
	if c.Scheme == "socks5" {
		return c.Server
	}
	return c.Scheme + "://" + c.Server
}

func (c *Client) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	if network != "tcp" && network != "tcp4" && network != "tcp6" {
		return nil, errors.ErrUnsupported
	}
	if ctx.Value(purposeKey{}) == nil {
		ctx = WithPurpose(ctx, "TCP", address)
	}
	ctx, cancel := context.WithTimeout(ctx, 26*time.Second)
	defer cancel()
	if c.socks != nil {
		return c.socks.DialContext(ctx, "tcp", address)
	}
	conn, err := c.transport.DialContext(ctx, "tcp", c.Server)
	if err != nil {
		return nil, err
	}
	stop := context.AfterFunc(ctx, func() { conn.Close() })
	defer stop()
	deadline, _ := ctx.Deadline()
	conn.SetDeadline(deadline)
	tunnel, err := c.connectHTTP(conn, address)
	if err != nil {
		conn.Close()
		return nil, err
	}
	if !stop() {
		conn.Close()
		return nil, ctx.Err()
	}
	if err = conn.SetDeadline(time.Time{}); err != nil {
		conn.Close()
		return nil, err
	}
	return tunnel, nil
}

type bufferedConn struct {
	net.Conn
	reader io.Reader
}

func (c *bufferedConn) Read(b []byte) (int, error) { return c.reader.Read(b) }

func (c *bufferedConn) CloseWrite() error {
	if cw, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return cw.CloseWrite()
	}
	return errors.ErrUnsupported
}

func (c *Client) connectHTTP(conn net.Conn, target string) (net.Conn, error) {
	req := &http.Request{Method: http.MethodConnect, URL: &url.URL{Opaque: target}, Host: target, Header: make(http.Header)}
	if c.auth != nil {
		credentials := base64.StdEncoding.EncodeToString([]byte(c.auth.User + ":" + c.auth.Password))
		req.Header.Set("Proxy-Authorization", "Basic "+credentials)
	}
	if err := req.Write(conn); err != nil {
		return nil, err
	}
	// Limit the response headers without discarding tunnel data read in the same packet.
	limited := &io.LimitedReader{R: conn, N: 64 << 10}
	r := bufio.NewReader(limited)
	resp, err := http.ReadResponse(r, req)
	if err != nil {
		var netErr net.Error
		if errors.As(err, &netErr) {
			return nil, netErr
		}
	}
	if err != nil || limited.N == 0 {
		return nil, errors.New("HTTP CONNECT 响应无效或响应头过大")
	}
	if resp.StatusCode/100 != 2 {
		return nil, HTTPStatusError(resp.StatusCode)
	}
	prefix := make([]byte, r.Buffered())
	if _, err = io.ReadFull(r, prefix); err != nil {
		return nil, err
	}
	if len(prefix) == 0 {
		return conn, nil
	}
	return &bufferedConn{Conn: conn, reader: io.MultiReader(bytes.NewReader(prefix), conn)}, nil
}

// HTTPStatusError reports an HTTP response without exposing upstream headers or credentials.
type HTTPStatusError int

func (s HTTPStatusError) Error() string {
	return fmt.Sprintf("HTTP CONNECT 被拒绝（HTTP %d）", int(s))
}
