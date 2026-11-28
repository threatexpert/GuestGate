package upstream

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestProxyURLs(t *testing.T) {
	for _, tc := range []struct{ raw, label string }{
		{"127.0.0.1:1080", "127.0.0.1:1080"},
		{"connect://name:p%40ss@[::1]:8080", "http://[::1]:8080"},
		{"socks5s://name:pass@localhost:1080?psk=key%26more", "socks5s://localhost:1080"},
	} {
		c, err := Parse(tc.raw)
		if err != nil || c.Display() != tc.label {
			t.Fatalf("unexpected display or parse failure: %v", err)
		}
	}
	for _, raw := range []string{"socks5s://localhost:1080", "socks5s://localhost:1080?psk=", "socks5s://localhost:1080?psk=a&psk=b", "socks5://localhost:1080?psk=test", "http://localhost:65536"} {
		if _, err := Parse(raw); err == nil {
			t.Error("accepted invalid proxy URL", raw)
		}
	}
}

func TestHTTPConnect(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodConnect || r.Host != "example.invalid:443" {
			t.Error("unexpected CONNECT target", r.Method, r.Host)
		}
		if r.Header.Get("Proxy-Authorization") != "Basic dXNlcjpwQHNz" || r.Header.Get("Authorization") != "" {
			w.WriteHeader(407)
			return
		}
		conn, _, err := w.(http.Hijacker).Hijack()
		if err != nil {
			t.Error(err)
			return
		}
		defer conn.Close()
		io.WriteString(conn, "HTTP/1.1 200 Connection established\r\n\r\nready")
	}))
	defer srv.Close()
	c, err := Parse(strings.Replace(srv.URL, "://", "://user:p%40ss@", 1))
	if err != nil {
		t.Fatal(err)
	}
	conn, err := c.DialContext(t.Context(), "tcp", "example.invalid:443")
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	b := make([]byte, 5)
	if _, err = io.ReadFull(conn, b); err != nil || string(b) != "ready" {
		t.Fatalf("tunnel payload %q: %v", b, err)
	}
	if _, err = c.DialPacket(t.Context()); !errors.Is(err, ErrHTTPUDPUnsupported) {
		t.Fatal("unexpected UDP result", err)
	}
	unauth, err := Parse(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = unauth.DialContext(context.Background(), "tcp", "example.invalid:443"); !errors.Is(err, HTTPStatusError(407)) {
		t.Fatal("unexpected auth result", err)
	}
}
