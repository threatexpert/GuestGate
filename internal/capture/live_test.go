package capture

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"io"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestStopRecordingKeepsOpenStreamAndFinalizesFiles(t *testing.T) {
	lib := recorderForTest(t)
	ca, err := loadAuthorityFrom(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	vm := filepath.Join(t.TempDir(), "Guest.vmx")
	r, err := lib.startVM(vm, "", ca)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	guest, local := net.Pipe()
	remote, service := net.Pipe()
	defer guest.Close()
	defer service.Close()
	deadline := time.Now().Add(3 * time.Second)
	guest.SetDeadline(deadline)
	service.SetDeadline(deadline)
	done := make(chan error, 1)
	roots := x509.NewCertPool()
	roots.AddCert(ca.cert)
	url := "http://192.0.2.2" + r.CRLPath()
	leaf, err := ca.leaf("capture.test", url)
	if err != nil {
		t.Fatal(err)
	}
	app := tls.Client(guest, &tls.Config{RootCAs: roots, ServerName: "capture.test"})
	origin := tls.Server(service, &tls.Config{Certificates: []tls.Certificate{leaf}})
	go func() { done <- r.relay(context.Background(), local, remote, "192.0.2.99:443", url, roots) }()
	exchange := func(s string) {
		result := make(chan error, 1)
		go func() { _, err := io.WriteString(app, s); result <- err }()
		b := make([]byte, len(s))
		if _, err := io.ReadFull(origin, b); err != nil || string(b) != s {
			t.Fatalf("forwarding: %q %v", b, err)
		}
		if err := <-result; err != nil {
			t.Fatal(err)
		}
	}
	exchange("GET /first HTTP/1.1\r\nHost: example.test\r\n\r\n")
	if err := r.Close(); err != nil {
		t.Fatal(err)
	}
	const marker = "stop-boundary-test-marker"
	exchange("GET /" + marker + " HTTP/1.1\r\nHost: example.test\r\n\r\n")
	guest.Close()
	service.Close()
	<-done
	entries, err := os.ReadDir(r.Directory)
	if err != nil || len(entries) == 0 {
		t.Fatal("missing recording", err)
	}
	err = filepath.WalkDir(r.Directory, func(path string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		b, err := os.ReadFile(path)
		if bytes.Contains(b, []byte(marker)) {
			t.Fatalf("post-stop payload persisted: %s", d.Name())
		}
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	next, err := lib.startVM(vm, "", ca)
	if err != nil {
		t.Fatal(err)
	}
	defer next.Close()
	if next.Directory == r.Directory {
		t.Fatal("restart reused finalized recording")
	}
}
