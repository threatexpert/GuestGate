package capture

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestUpgradeCARequiresConfirmation(t *testing.T) {
	dir := t.TempDir()
	old := filepath.Join(dir, "authority.dpapi")
	if err := os.WriteFile(old, []byte("previous sealed authority"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadAuthorityFrom(dir); !errors.Is(err, errLegacyCA) {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, caFilename)); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("created new root before approval", err)
	}
	a, err := readOrCreateCA(dir, true)
	if err != nil {
		t.Fatal(err)
	}
	again, err := readOrCreateCA(dir, true)
	if err != nil || !bytes.Equal(a.cert.Raw, again.cert.Raw) {
		t.Fatal("repeated approval replaced root", err)
	}
	if needed, err := needsUpgrade(dir); err != nil || needed {
		t.Fatal(needed, err)
	}
	oldData, err := os.ReadFile(old)
	if err != nil || string(oldData) != "previous sealed authority" {
		t.Fatal("legacy CA changed", err)
	}
}

func TestCRLHTTP(t *testing.T) {
	a, err := loadAuthorityFrom(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	r := &Recorder{ca: a}
	for _, tc := range []struct {
		method, path string
		status       int
	}{{"GET", r.CRLPath(), 200}, {"HEAD", r.CRLPath(), 200}, {"GET", "/any", 404}, {"POST", r.CRLPath(), 405}, {"CONNECT", "example.com:443", 404}} {
		client, server := net.Pipe()
		go r.ServeCRL(server)
		fmt.Fprintf(client, "%s %s HTTP/1.1\r\nHost: 192.0.2.2\r\n\r\n", tc.method, tc.path)
		res, err := http.ReadResponse(bufio.NewReader(client), &http.Request{Method: tc.method})
		if err != nil {
			t.Fatal(err)
		}
		body, err := io.ReadAll(res.Body)
		res.Body.Close()
		client.Close()
		if err != nil || res.StatusCode != tc.status {
			t.Fatal(tc, res.Status, err)
		}
		if tc.method == "GET" && tc.status == 200 {
			list, err := x509.ParseRevocationList(body)
			if err != nil {
				t.Fatal(err)
			}
			if err = list.CheckSignatureFrom(a.cert); err != nil {
				t.Fatal(err)
			}
			if time.Now().Before(list.ThisUpdate) || !time.Now().Before(list.NextUpdate) || len(list.RevokedCertificateEntries) != 0 {
				t.Fatal("invalid CRL")
			}
		} else if len(body) != 0 {
			t.Fatal("unexpected body", tc)
		}
	}
	next, err := a.revocationList(time.Now().Add(25 * time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	list, err := x509.ParseRevocationList(next)
	if err != nil || !list.NextUpdate.After(time.Now().Add(25*time.Hour)) {
		t.Fatal("list did not refresh", err)
	}
}

// Use a fresh temporary CA and URL per run. No OS trust store changes.
// A failing negative control verifies that curl actually checks revocation.
func TestWindowsSchannelCRL(t *testing.T) {
	curl := filepath.Join(os.Getenv("SystemRoot"), "System32", "curl.exe")
	version, err := exec.Command(curl, "-V").Output()
	if err != nil || !bytes.Contains(version, []byte("Schannel")) {
		t.Skip("Windows Schannel curl unavailable")
	}
	dir := t.TempDir()
	a, err := loadAuthorityFrom(dir)
	if err != nil {
		t.Fatal(err)
	}
	r := &Recorder{ca: a}
	roots := filepath.Join(dir, "test-ca.pem")
	if err = os.WriteFile(roots, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: a.cert.Raw}), 0600); err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	var requests atomic.Int32
	go func() {
		for {
			c, e := listener.Accept()
			if e != nil {
				return
			}
			requests.Add(1)
			go r.ServeCRL(c)
		}
	}()
	check := func(url string) (string, error) {
		leaf, e := a.leaf("schannel.test", url)
		if e != nil {
			t.Fatal(e)
		}
		site := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) { io.WriteString(w, "schannel-ok") }))
		site.TLS = &tls.Config{Certificates: []tls.Certificate{leaf}}
		site.StartTLS()
		defer site.Close()
		_, port, _ := net.SplitHostPort(site.Listener.Addr().String())
		cmd := exec.Command(curl, "--disable", "--noproxy", "*", "--cacert", roots, "--max-time", "12", "-fsS", "--resolve", "schannel.test:"+port+":127.0.0.1", "https://schannel.test:"+port)
		data, e := cmd.CombinedOutput()
		return string(data), e
	}
	base := "http://" + listener.Addr().String()
	msg, err := check(base + "/missing.crl")
	if err == nil || !(strings.Contains(msg, "REVOCATION") || strings.Contains(msg, "0x800920")) {
		t.Fatalf("Schannel negative control: %v %s", err, msg)
	}
	before := requests.Load()
	msg, err = check(base + r.CRLPath())
	if err != nil || msg != "schannel-ok" || requests.Load() <= before {
		t.Fatalf("Schannel CRL lookup failed (requests %d -> %d): %v %s", before, requests.Load(), err, msg)
	}
	t.Log("Schannel rejected the unavailable CRL, fetched the signed CRL and accepted the site")
}
