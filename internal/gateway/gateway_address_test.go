package gateway

import (
	"bytes"
	"context"
	"errors"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"

	"guestgate/internal/vmnet"
)

func TestVMnetPrefix(t *testing.T) {
	for _, tc := range []struct{ ip, mask, want string }{
		{"10.33.1.1", "255.255.0.0", "10.33.0.0/16"},
		{"172.18.9.137", "255.255.255.192", "172.18.9.128/26"},
		{"192.168.7.0", "255.255.255.0", "192.168.7.0/24"},
		{"10.0.0.0", "255.0.255.0", ""}, {"10.0.0.0", "255.255.255.254", ""},
		{"::1", "255.255.255.0", ""},
	} {
		p, ok := vmnetPrefix(tc.ip, tc.mask)
		if (tc.want != "") != ok || ok && p.String() != tc.want {
			t.Fatalf("prefix %s %s: %v %v", tc.ip, tc.mask, p, ok)
		}
	}
}

type gatewayTestPort struct {
	testPort
	targets  []netip.Addr
	response []byte
	occupied netip.Addr
}

func (p *gatewayTestPort) WriteFrame(f []byte) error {
	ip, _ := netip.AddrFromSlice(f[38:42])
	p.targets = append(p.targets, ip)
	if ip == p.occupied {
		p.response = bytes.Clone(f)
		p.response[21] = 2
		copy(p.response[28:32], ip.AsSlice())
	}
	return nil
}
func (p *gatewayTestPort) ReadFrame() ([]byte, error) {
	if p.response != nil {
		r := p.response
		p.response = nil
		return r, nil
	}
	time.Sleep(4 * time.Millisecond)
	return nil, nil
}

func TestSelectAndShareGatewayOnCustomSubnet(t *testing.T) {
	subnet := netip.MustParsePrefix("172.18.9.128/26")
	base := []byte("subnet 172.18.9.128 netmask 255.255.255.192 { pool { range 172.18.9.130 172.18.9.150; } }\r\nhost VMnet1 { fixed-address 172.18.9.129, 172.18.9.151; }\r\n")
	scope, err := readGatewayScope(base, subnet)
	if err != nil {
		t.Fatal(err)
	}
	local := netip.MustParseAddr("172.18.9.152")
	scope.excluded = append(scope.excluded, addressSpan{local, local})
	p := &gatewayTestPort{occupied: netip.MustParseAddr("172.18.9.153")}
	var pool networkPool
	opens := 0
	drivers := []frameBackend{{"test", func() (vmnet.Port, error) { opens++; return p, nil }}}
	first := &gateway{guest: net.HardwareAddr{0, 1, 2, 3, 4, 5}, addresses: scope}
	second := &gateway{guest: net.HardwareAddr{0, 1, 2, 3, 4, 6}, addresses: scope}
	for _, g := range []*gateway{first, second} {
		if _, err = pool.attach(context.Background(), "vmnet1", g, drivers); err != nil {
			t.Fatal(err)
		}
		defer pool.detach("vmnet1", g)
		if g.ip.String() != "172.18.9.154" || !bytes.Equal(g.mac, gatewayMAC(g.ip)) {
			t.Fatalf("gateway %s %s", g.ip, g.mac)
		}
	}
	if opens != 1 || len(p.targets) != 4 || p.targets[0] != p.occupied {
		t.Fatalf("opens %d, probed %v", opens, p.targets)
	}
	dhcp, err := renderDHCP(base, map[string]VM{"a": {MAC: first.guest.String(), subnet: subnet, gatewayIP: first.ip, dns: netip.MustParseAddr("8.8.8.8")}})
	if err != nil || !strings.Contains(string(dhcp), "option routers 172.18.9.154;") {
		t.Fatalf("DHCP gateway: %s %v", dhcp, err)
	}
}

func TestGatewayPoolLimits(t *testing.T) {
	subnet := netip.MustParsePrefix("10.16.0.0/12")
	base := []byte("subnet 10.16.0.0 netmask 255.240.0.0 { range 10.16.0.1 10.31.255.253; }")
	a, err := readGatewayScope(base, subnet)
	if err != nil {
		t.Fatal(err)
	}
	free := netip.MustParseAddr("10.31.255.254")
	if got := a.nextFree(subnet.Addr().Next()); got != free || a.allows(free.Next()) {
		t.Fatalf("wrong address %v", got)
	}
	a.excluded = append(a.excluded, addressSpan{free, free})
	g := &gateway{addresses: a}
	p := &gatewayTestPort{}
	if err = g.chooseAddress(context.Background(), p); !errors.Is(err, errGatewayInUse) || len(p.targets) != 0 {
		t.Fatalf("pool exhaustion: %v, probes %v", err, p.targets)
	}
	existing := bytes.Replace(base, []byte("range"), []byte("option routers 10.16.0.1; range"), 1)
	if _, err = readGatewayScope(existing, subnet); err == nil {
		t.Fatal("existing subnet router accepted")
	}
}
