package capture

import (
	"bufio"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"time"
)

func (r *Recorder) CRLPath() string {
	return fmt.Sprintf("/pki/%x.crl", sha256.Sum256(r.ca.cert.Raw))
}

// GuestGate currently has no individual leaf revocation operation. A signed
// empty list represents this issuer's current state, with a bounded validity.
func (a *authority) revocationList(now time.Time) ([]byte, error) {
	hour := now.UTC().Truncate(time.Hour)
	a.crlMu.Lock()
	defer a.crlMu.Unlock()
	if a.crlHour.Equal(hour) {
		return a.crlDER, nil
	}
	next := hour.Add(24 * time.Hour)
	if next.After(a.cert.NotAfter) {
		next = a.cert.NotAfter
	}
	if !now.Before(next) {
		return nil, fmt.Errorf("宿主机 CA 已过期")
	}
	list := &x509.RevocationList{Number: big.NewInt(hour.Unix()), ThisUpdate: hour, NextUpdate: next}
	der, err := x509.CreateRevocationList(rand.Reader, list, a.cert, a.key)
	if err != nil {
		return nil, err
	}
	a.crlHour, a.crlDER = hour, der
	return der, nil
}

// ServeCRL handles one request on an already accepted virtual TCP stream.
func (r *Recorder) ServeCRL(conn net.Conn) bool {
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(10 * time.Second))
	req, err := http.ReadRequest(bufio.NewReader(io.LimitReader(conn, 16<<10)))
	status := http.StatusOK
	var body []byte
	switch {
	case err != nil:
		status = http.StatusBadRequest
	case req.RequestURI != r.CRLPath():
		status = http.StatusNotFound
	case req.Method != http.MethodGet && req.Method != http.MethodHead:
		status = http.StatusMethodNotAllowed
	default:
		body, err = r.ca.revocationList(time.Now())
		if err != nil {
			status = http.StatusServiceUnavailable
		}
	}
	fmt.Fprintf(conn, "HTTP/1.1 %d %s\r\nConnection: close\r\nContent-Length: %d\r\n", status, http.StatusText(status), len(body))
	if status == http.StatusOK {
		io.WriteString(conn, "Content-Type: application/pkix-crl\r\n")
	}
	if status == http.StatusMethodNotAllowed {
		io.WriteString(conn, "Allow: GET, HEAD\r\n")
	}
	io.WriteString(conn, "\r\n")
	if len(body) > 0 && req.Method != http.MethodHead {
		_, err = conn.Write(body)
		return err == nil && status == http.StatusOK
	}
	return false
}
