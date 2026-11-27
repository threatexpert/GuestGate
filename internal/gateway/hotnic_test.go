package gateway

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
)

func TestNetworkSelection(t *testing.T) {
	nets := map[string]netip.Prefix{"vmnet1": netip.MustParsePrefix("192.168.7.0/24"), "vmnet3": netip.MustParsePrefix("192.168.3.0/24")}
	for _, c := range []struct {
		kind, vnet, want string
		change           bool
	}{
		{"nat", "", "vmnet1", true}, {"bridged", "", "vmnet1", true}, {"custom", "VMnet10", "vmnet1", true}, {"custom", "vmnet8", "vmnet1", true}, {"hostonly", "", "vmnet1", false}, {"custom", "VMnet3", "vmnet3", false},
	} {
		path := filepath.Join(t.TempDir(), "sample.vmx")
		body := fmt.Sprintf("ethernet0.present = \"TRUE\"\nethernet0.generatedAddress = \"00:0c:29:00:00:01\"\nethernet0.connectionType = %q\nethernet0.vnet = %q\n", c.kind, c.vnet)
		if err := os.WriteFile(path, []byte(body), 0600); err != nil {
			t.Fatal(err)
		}
		v, err := readVM(path, nets)
		if err != nil || v.Reason != "" || v.Network != c.want || v.NeedsSwitch != c.change {
			t.Fatalf("%s/%s: %+v, %v", c.kind, c.vnet, v, err)
		}
		if err := os.WriteFile(path, []byte(body+"ethernet1.present = \"TRUE\""), 0600); err != nil {
			t.Fatal(err)
		}
		v, err = readVM(path, nets)
		if err != nil || v.Reason == "" {
			t.Fatal("multiple NICs accepted")
		}
	}
}
func TestRESTCredentialsOwnership(t *testing.T) {
	path := filepath.Join(t.TempDir(), "vmrest.cfg")
	_, _, _, err := restCredentials(path, "")
	if err != nil {
		t.Fatal(err)
	}
	// Simulate a crash. A second worker may reclaim our exact configuration.
	_, _, cleanup, err := restCredentials(path, "")
	if err != nil {
		t.Fatal(err)
	}
	cleanup()
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatal("temporary configuration remained")
	}
	existing := []byte("username=existing\r\n")
	if err := os.WriteFile(path, existing, 0600); err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := restCredentials(path, ""); err == nil {
		t.Fatal("missing credential accepted")
	}
	name, _, cleanup, err := restCredentials(path, "secret")
	if err != nil || name != "existing" {
		t.Fatal(err)
	}
	cleanup()
	got, err := os.ReadFile(path)
	if err != nil || string(got) != string(existing) {
		t.Fatal("existing configuration changed")
	}
}

type routeToTestServer struct{ server *httptest.Server }

func (rt routeToTestServer) RoundTrip(req *http.Request) (*http.Response, error) {
	req = req.Clone(req.Context())
	req.URL.Host = rt.server.Listener.Addr().String()
	return http.DefaultTransport.RoundTrip(req)
}
func TestRESTChecksGuestMACBeforeUpdate(t *testing.T) {
	var puts int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/vms":
			fmt.Fprint(w, `[{"id":"chosen","path":"chosen.vmx"}]`)
		case "/api/vms/chosen/nic":
			fmt.Fprint(w, `{"nics":[{"index":4,"macAddress":"00:0c:29:00:00:02"}]}`)
		default:
			puts++
			w.WriteHeader(http.StatusBadRequest)
		}
	}))
	defer srv.Close()
	r := vmREST{client: &http.Client{Transport: routeToTestServer{srv}}}
	if err := r.switchNIC(context.Background(), VM{Path: "chosen.vmx", MAC: "00:0c:29:00:00:01"}); err == nil || puts != 0 {
		t.Fatal("attempted to update different guest NIC")
	}
}
