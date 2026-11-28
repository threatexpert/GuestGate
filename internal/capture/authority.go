package capture

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"

	"golang.org/x/sys/windows"

	"guestgate/internal/usersecret"
)

type authority struct {
	cert    *x509.Certificate
	key     *ecdsa.PrivateKey
	crlMu   sync.Mutex
	crlHour time.Time
	crlDER  []byte
}
type storedAuthority struct{ Cert, Key []byte }

func loadAuthority() (*authority, error) {
	dir, err := hostCADirectory()
	if err != nil {
		return nil, err
	}
	return loadAuthorityFrom(dir)
}

func loadAuthorityFrom(dir string) (*authority, error) {
	return readOrCreateCA(dir, false)
}

const caFilename = "authority-crl.dpapi"

var errLegacyCA = errors.New("当前宿主机 CA 缺少吊销列表签名用途。请点击“导出宿主机 CA”，确认升级，并在客户机导入新证书。")

func needsUpgrade(dir string) (bool, error) {
	if _, err := os.Stat(filepath.Join(dir, caFilename)); err == nil {
		return false, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return false, err
	}
	if _, err := os.Stat(filepath.Join(dir, "authority.dpapi")); err == nil {
		return true, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return false, err
	}
	return false, nil
}
func HostCANeedsUpgrade() (bool, error) {
	dir, err := hostCADirectory()
	if err != nil {
		return false, err
	}
	return needsUpgrade(dir)
}

func readOrCreateCA(dir string, approve bool) (*authority, error) {
	path := filepath.Join(dir, caFilename)
	sealed, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		if !approve {
			legacy, e := needsUpgrade(dir)
			if e != nil {
				return nil, e
			}
			if legacy {
				return nil, errLegacyCA
			}
		}
		cert, key, err := newRoot()
		if err != nil {
			return nil, err
		}
		clear, err := json.Marshal(storedAuthority{cert, key})
		if err != nil {
			return nil, err
		}
		sealed, err = usersecret.SealMachine(clear)
		if err != nil {
			return nil, err
		}
		if err = publishFile(path, sealed, false); err != nil {
			if !errors.Is(err, os.ErrExist) {
				return nil, err
			}
			sealed, err = os.ReadFile(path)
			if err != nil {
				return nil, err
			}
		}
	} else if err != nil {
		return nil, err
	}
	clear, err := usersecret.Protect(sealed, false)
	if err != nil {
		return nil, err
	}
	var store storedAuthority
	if err = json.Unmarshal(clear, &store); err != nil {
		return nil, err
	}
	cert, err := x509.ParseCertificate(store.Cert)
	if err != nil {
		return nil, err
	}
	key, err := x509.ParseECPrivateKey(store.Key)
	if err != nil {
		return nil, err
	}
	if !key.PublicKey.Equal(cert.PublicKey) || !cert.IsCA || cert.KeyUsage&x509.KeyUsageCRLSign == 0 || time.Now().After(cert.NotAfter) {
		return nil, errors.New("宿主机 CA 无效或已过期")
	}
	return &authority{cert: cert, key: key}, nil
}
func serial() (*big.Int, error) { return rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128)) }
func newRoot() ([]byte, []byte, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	id, err := serial()
	if err != nil {
		return nil, nil, err
	}
	now := time.Now()
	root := &x509.Certificate{SerialNumber: id, Subject: pkix.Name{CommonName: "GuestGate Host CA " + fmt.Sprintf("%032x", id)[:8]}, NotBefore: now.Add(-time.Hour), NotAfter: now.AddDate(5, 0, 0), IsCA: true, BasicConstraintsValid: true, MaxPathLenZero: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign}
	cert, err := x509.CreateCertificate(rand.Reader, root, root, &key.PublicKey, key)
	if err != nil {
		return nil, nil, err
	}
	der, err := x509.MarshalECPrivateKey(key)
	return cert, der, err
}

// Export only the public DER certificate to a folder visible to Explorer.
func ExportCA(approve bool) (string, error) {
	store, err := hostCADirectory()
	if err != nil {
		return "", err
	}
	ca, err := readOrCreateCA(store, approve)
	if err != nil {
		return "", err
	}
	root, err := os.UserCacheDir()
	if err != nil {
		return "", err
	}
	dir := filepath.Join(root, "GuestGate", "public")
	if err = os.MkdirAll(dir, 0700); err != nil {
		return "", err
	}
	path := filepath.Join(dir, "GuestGate-host-ca.cer")
	return path, publishFile(path, ca.cert.Raw, true)
}

func publishFile(path string, data []byte, replace bool) error {
	f, err := os.CreateTemp(filepath.Dir(path), ".ca-*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	_, err = f.Write(data)
	if err == nil {
		err = f.Sync()
	}
	if closeErr := f.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	src, err := windows.UTF16PtrFromString(f.Name())
	if err != nil {
		return err
	}
	dst, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return err
	}
	flags := uint32(windows.MOVEFILE_WRITE_THROUGH)
	if replace {
		flags |= windows.MOVEFILE_REPLACE_EXISTING
	}
	return windows.MoveFileEx(src, dst, flags)
}

func (a *authority) leaf(name, crlURL string) (tls.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}
	id, err := serial()
	if err != nil {
		return tls.Certificate{}, err
	}
	now := time.Now()
	expires := now.AddDate(0, 0, 7)
	if expires.After(a.cert.NotAfter) {
		expires = a.cert.NotAfter
	}
	if crlURL == "" {
		return tls.Certificate{}, errors.New("网关 CRL 地址尚未就绪")
	}
	leaf := &x509.Certificate{CRLDistributionPoints: []string{crlURL}, SerialNumber: id, NotBefore: now.Add(-time.Hour), NotAfter: expires, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, BasicConstraintsValid: true}
	if ip := net.ParseIP(name); ip != nil {
		leaf.IPAddresses = []net.IP{ip}
	} else {
		leaf.DNSNames = []string{name}
	}
	cert, err := x509.CreateCertificate(rand.Reader, leaf, a.cert, &key.PublicKey, a.key)
	return tls.Certificate{Certificate: [][]byte{cert}, PrivateKey: key}, err
}
