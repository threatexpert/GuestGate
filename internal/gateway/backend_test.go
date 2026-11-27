package gateway

import (
	"context"
	"errors"
	"net/netip"
	"strings"
	"testing"

	"guestgate/internal/vmnet"
)

type testPort struct{ closed bool }

func (*testPort) ReadFrame() ([]byte, error) { return nil, nil }
func (*testPort) WriteFrame([]byte) error    { return nil }
func (p *testPort) Close()                   { p.closed = true }

func TestBackendSelection(t *testing.T) {
	unavailable := errors.New("unavailable")
	for _, tc := range []struct {
		name              string
		openErr, probeErr error
		want              string
		second            bool
	}{
		{"native", nil, nil, "VMware", false},
		{"open failure", unavailable, nil, "Npcap", true},
		{"I/O failure", nil, unavailable, "Npcap", true},
		{"address conflict", nil, errGatewayInUse, "", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			native, fallback := &testPort{}, &testPort{}
			called := false
			drivers := []frameBackend{
				{"VMware", func() (vmnet.Port, error) {
					if tc.openErr != nil {
						return nil, tc.openErr
					}
					return native, nil
				}},
				{"Npcap", func() (vmnet.Port, error) { called = true; return fallback, nil }},
			}
			p, name, err := selectPort(context.Background(), drivers, func(_ context.Context, port vmnet.Port) error {
				if port == native {
					return tc.probeErr
				}
				return nil
			})
			if name != tc.want || called != tc.second || native.closed != (tc.probeErr != nil) {
				t.Fatalf("backend=%q fallback=%v closed=%v err=%v", name, called, native.closed, err)
			}
			if tc.want == "" {
				if p != nil || !errors.Is(err, errGatewayInUse) {
					t.Fatal("address conflict lost")
				}
			} else if err != nil || p == nil {
				t.Fatalf("selection failed: %v", err)
			}
		})
	}
	drivers := []frameBackend{{"VMware", func() (vmnet.Port, error) { return nil, unavailable }}, {"Npcap", func() (vmnet.Port, error) { return nil, unavailable }}}
	p, _, err := selectPort(context.Background(), drivers, nil)
	if p != nil || err == nil || !strings.Contains(err.Error(), "VMware") || !strings.Contains(err.Error(), "Npcap") {
		t.Fatal("missing both backend errors")
	}
}

func TestARPConflictUsesSender(t *testing.T) {
	ip := netip.MustParseAddr("192.168.59.2")
	f := make([]byte, 42)
	copy(f[12:22], []byte{8, 6, 0, 1, 8, 0, 6, 4, 0, 1})
	copy(f[38:42], ip.AsSlice())
	if claimsAddress(f, ip) || claimsAddress(f[:20], ip) {
		t.Fatal("own probe or short frame flagged")
	}
	copy(f[28:32], ip.AsSlice())
	if !claimsAddress(f, ip) {
		t.Fatal("failed to detect a peer using the gateway")
	}
}
