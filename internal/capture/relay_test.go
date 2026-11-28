package capture

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/net/http2"
	"golang.org/x/sys/windows"

	"guestgate/internal/upstream"
)

func TestSharedRoot(t *testing.T) {
	dir := t.TempDir()
	type result struct {
		ca  *authority
		err error
	}
	results := make(chan result, 8)
	for range cap(results) {
		go func() { ca, err := loadAuthorityFrom(dir); results <- result{ca, err} }()
	}
	var der []byte
	for range cap(results) {
		r := <-results
		if r.err != nil {
			t.Fatal(r.err)
		}
		if der == nil {
			der = r.ca.cert.Raw
		} else if !bytes.Equal(der, r.ca.cert.Raw) {
			t.Fatal("different roots published concurrently")
		}
	}
	reloaded, err := loadAuthorityFrom(dir)
	if err != nil || !bytes.Equal(reloaded.cert.Raw, der) {
		t.Fatal("persisted root changed", err)
	}
}

func TestPrivateCADirectory(t *testing.T) {
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	sid := user.User.Sid.String()
	sddl := "O:" + sid + "D:P(A;OICI;FA;;;" + sid + ")(A;OICI;FA;;;SY)"
	dir := filepath.Join(t.TempDir(), "CA")
	for range 2 {
		if err := ensureCADirectory(dir, sddl); err != nil {
			t.Fatal(err)
		}
	}
	unsafeDir := t.TempDir()
	if err := ensureCADirectory(unsafeDir, sddl); err == nil {
		t.Fatal("accepted an inherited ACL")
	}
	if windows.GetCurrentProcessToken().IsElevated() {
		if err := ensureCADirectory(filepath.Join(t.TempDir(), "admin-ca"), hostCAPermissions); err != nil {
			t.Fatal(err)
		}
	}
}

func recorderForTest(t *testing.T) *library {
	t.Helper()
	dll := os.Getenv("GUESTGATE_TEST_RECORDER")
	if dll == "" {
		dll, _ = filepath.Abs("../../native/recorder/target/release/guestgate_recorder.dll")
		if _, err := os.Stat(dll); os.IsNotExist(err) {
			t.Skip("build the native recorder first")
		}
	}
	lib, err := bindLibrary(dll)
	if err != nil {
		t.Fatal(err)
	}
	return lib
}

func TestProxyLaneRecording(t *testing.T) {
	lib := recorderForTest(t)
	t.Setenv("LocalAppData", t.TempDir())
	dir := t.TempDir()
	shared, err := loadAuthorityFrom(dir)
	if err != nil {
		t.Fatal(err)
	}
	rec, err := lib.startVM(filepath.Join(t.TempDir(), "test.vmx"), filepath.Join(t.TempDir(), "中文 [沙箱]"), shared)
	if err != nil {
		t.Fatal(err)
	}
	defer rec.Close()
	ca := rec.ca
	other, err := loadAuthorityFrom(dir)
	if err != nil {
		t.Fatal(err)
	}
	peer, err := lib.startVM(filepath.Join(t.TempDir(), "test.vmx"), "", other)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(ca.cert.Raw, peer.ca.cert.Raw) {
		t.Fatal("guests must share the host CA")
	}
	if rec.Directory == peer.Directory {
		t.Fatal("recording directory collision")
	}
	observation := peer.Open("192.0.2.2:80", "", "", false, false)
	observation.Data(0, []byte("GET /other-guest HTTP/1.0\r\n\r\n"))
	observation.Close("")
	if err = peer.Close(); err != nil {
		t.Fatal(err)
	}
	guestRoots := x509.NewCertPool()
	guestRoots.AddCert(ca.cert)
	const body = "sandbox-response-5982"
	origin := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, body) }))
	origin.EnableHTTP2 = true
	origin.StartTLS()
	defer origin.Close()
	roots := x509.NewCertPool()
	roots.AddCert(origin.Certificate())
	const target = "192.0.2.194:8443"
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if req.Method != http.MethodConnect || req.Host != target {
			w.WriteHeader(403)
			return
		}
		back, e := net.Dial("tcp", origin.Listener.Addr().String())
		if e != nil {
			t.Error(e)
			return
		}
		defer back.Close()
		front, _, e := w.(http.Hijacker).Hijack()
		if e != nil {
			t.Error(e)
			return
		}
		defer front.Close()
		io.WriteString(front, "HTTP/1.1 200 OK\r\n\r\n")
		go func() { io.Copy(back, front); back.Close() }()
		io.Copy(front, back)
	}))
	defer proxy.Close()
	route, err := upstream.Parse(proxy.URL)
	if err != nil {
		t.Fatal(err)
	}
	connect := func(verify *x509.CertPool) (net.Conn, <-chan error) {
		u, err := route.DialContext(t.Context(), "tcp", target)
		if err != nil {
			t.Fatal(err)
		}
		g, client := net.Pipe()
		done := make(chan error, 1)
		ctx, cancel := context.WithTimeout(t.Context(), 6*time.Second)
		go func() { defer cancel(); done <- rec.relay(ctx, g, u, target, "http://192.0.2.1"+rec.CRLPath(), verify) }()
		client.SetDeadline(time.Now().Add(6 * time.Second))
		return client, done
	}
	raw, done := connect(roots)
	guest := tls.Client(raw, &tls.Config{ServerName: "example.com", RootCAs: guestRoots})
	if err = guest.Handshake(); err != nil {
		t.Fatal(err)
	}
	if points := guest.ConnectionState().PeerCertificates[0].CRLDistributionPoints; len(points) != 1 || points[0] != "http://192.0.2.1"+rec.CRLPath() {
		t.Fatal("wrong CRL endpoint on intercepted TLS connection", points)
	}
	if !bytes.Equal(guest.ConnectionState().VerifiedChains[0][1].Raw, ca.cert.Raw) {
		t.Fatal("guest did not see its sandbox CA")
	}
	fmt.Fprint(guest, "GET /sample-check HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n")
	res, err := http.ReadResponse(bufio.NewReader(guest), nil)
	if err != nil {
		t.Fatal(err)
	}
	data, err := io.ReadAll(res.Body)
	res.Body.Close()
	if err != nil || string(data) != body {
		t.Fatal(string(data), err)
	}
	raw.Close()
	<-done
	h2raw, h2done := connect(roots)
	h2guest := tls.Client(h2raw, &tls.Config{ServerName: "example.com", RootCAs: guestRoots, NextProtos: []string{"h2"}})
	if err = h2guest.Handshake(); err != nil || h2guest.ConnectionState().NegotiatedProtocol != "h2" {
		t.Fatal("h2 handshake", err)
	}
	h2, err := new(http2.Transport).NewClientConn(h2guest)
	if err != nil {
		t.Fatal(err)
	}
	req, _ := http.NewRequestWithContext(t.Context(), "GET", "https://example.com/h2-sample", nil)
	response, err := h2.RoundTrip(req)
	if err != nil {
		t.Fatal(err)
	}
	content, err := io.ReadAll(response.Body)
	response.Body.Close()
	if err != nil || string(content) != body || response.ProtoMajor != 2 {
		t.Fatal("h2 response", err)
	}
	h2raw.Close()
	<-h2done
	raw, done = connect(x509.NewCertPool())
	guest = tls.Client(raw, &tls.Config{ServerName: "example.com", RootCAs: guestRoots})
	if err = guest.Handshake(); err == nil {
		t.Fatal("untrusted upstream accepted")
	}
	raw.Close()
	if err = <-done; err == nil {
		t.Fatal("missing upstream verification error")
	}
	raw, done = connect(roots)
	guest = tls.Client(raw, &tls.Config{ServerName: "example.com", RootCAs: x509.NewCertPool()})
	if err = guest.Handshake(); err == nil {
		t.Fatal("untrusted guest CA accepted")
	}
	raw.Close()
	<-done

	c, s := net.Pipe()
	up, server := net.Pipe()
	ctx, cancel := context.WithTimeout(t.Context(), 4*time.Second)
	defer cancel()
	plainDone := make(chan error, 1)
	go func() { plainDone <- rec.Relay(ctx, s, up, "192.0.2.1:25", "http://192.0.2.1"+rec.CRLPath()) }()
	go io.WriteString(server, "banner\n")
	c.SetDeadline(time.Now().Add(time.Second))
	banner, err := bufio.NewReader(c).ReadString('\n')
	if err != nil || banner != "banner\n" {
		t.Fatal("server-first protocol", banner, err)
	}
	c.Close()
	server.Close()
	<-plainDone
	tap := rec.Open("192.0.2.53:53", "", "", false, true)
	if tap == nil {
		t.Fatal("missing DNS tap")
	}
	tap.Data(0, []byte{0, 1, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 2, 0, 1})
	tap.Close("")
	if err = rec.Close(); err != nil {
		t.Fatal(err)
	}
	manifest, err := os.ReadFile(filepath.Join(rec.Directory, "manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if json.Unmarshal(manifest, &m) != nil || m["has_data"] != true || m["version"] != float64(2) {
		t.Fatalf("manifest: %s", manifest)
	}
	recorded := os.DirFS(rec.Directory)
	files, err := fs.Glob(recorded, "payload/*/*.response.bin")
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, file := range files {
		b, _ := fs.ReadFile(recorded, file)
		found = found || string(b) == body
	}
	if !found {
		t.Fatal("missing decrypted HTTP response payload", files)
	}
	events, err := os.ReadFile(filepath.Join(rec.Directory, "events-000001.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(events), "other-guest") {
		t.Fatal("recordings mixed traffic from two guests")
	}
	if !strings.Contains(string(events), "sample-check") || !strings.Contains(string(events), "h2-sample") {
		t.Fatal("missing HTTP exchange")
	}
	if original := os.Getenv("GUESTGATE_TEST_PROXYLANE_DLL"); original != "" {
		d, err := windows.LoadDLL(original)
		if err != nil {
			t.Fatal(err)
		}
		query, err := d.FindProc("plm_protocol")
		if err != nil {
			t.Fatal(err)
		}
		ask := func(req map[string]any) string {
			b, _ := json.Marshal(req)
			b = append(b, 0)
			out := make([]byte, 32000)
			n, _, _ := query.Call(uintptr(unsafe.Pointer(&b[0])), uintptr(unsafe.Pointer(&out[0])), uintptr(len(out)))
			if int32(n) <= 0 || n > uintptr(len(out)) {
				t.Fatal("ProxyLane reader", windows.ByteSliceToString(out))
			}
			return windows.ByteSliceToString(out)
		}
		reply := ask(map[string]any{"type": "recording_open", "path": rec.Directory})
		if !strings.Contains(reply, "run_id") {
			t.Fatal(reply)
		}
		ask(map[string]any{"type": "recording_close"})
	}
}
