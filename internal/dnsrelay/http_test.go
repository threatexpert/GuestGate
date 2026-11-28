package dnsrelay

import (
	"encoding/binary"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"

	"guestgate/internal/upstream"
)

func TestHTTPResolver(t *testing.T) {
	dns := netip.MustParseAddrPort("192.0.2.1:53")
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if req.Method != http.MethodConnect || req.Host != dns.String() {
			w.WriteHeader(403)
			return
		}
		conn, rw, err := w.(http.Hijacker).Hijack()
		if err != nil {
			t.Error(err)
			return
		}
		defer conn.Close()
		io.WriteString(conn, "HTTP/1.1 200 OK\r\n\r\n")
		var size [2]byte
		if _, err = io.ReadFull(rw, size[:]); err != nil {
			t.Error(err)
			return
		}
		query := make([]byte, binary.BigEndian.Uint16(size[:]))
		if _, err = io.ReadFull(rw, query); err != nil || len(query) < 12 {
			t.Error("invalid TCP DNS query", err)
			return
		}
		query[2] |= 0x80
		conn.Write(append(size[:], query...))
	}))
	defer proxy.Close()
	client, err := upstream.Parse(proxy.URL)
	if err != nil {
		t.Fatal(err)
	}
	r := New(t.Context(), client)
	h := r.Check(t.Context(), dns.Addr())
	if h.Service.State != "ok" || h.TCP.State != "ok" || h.UDP.State != "unsupported" {
		t.Fatal(h)
	}
	query := rootNSQuery()
	query[0] = 42
	reply, err := r.Exchange(t.Context(), dns, query)
	if err != nil || reply[0] != 42 {
		t.Fatal("DNS through HTTP CONNECT failed", err)
	}
	h = r.Check(t.Context(), netip.MustParseAddr("192.0.2.2"))
	if h.Service.State != "ok" || h.TCP.State != "error" || h.UDP.State != "unsupported" {
		t.Fatal(h)
	}
}
