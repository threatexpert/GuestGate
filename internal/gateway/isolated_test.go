package gateway

import (
	"net"
	"net/netip"
	"strings"
	"testing"
)

func TestIsolatedProxyDestinations(t *testing.T) {
	for _, literal := range []string{"127.0.0.1", "0.0.0.0", "169.254.3.4", "255.255.255.255", "224.0.0.251", "::1"} {
		if !hostDestination(netip.MustParseAddr(literal).AsSlice()) {
			t.Errorf("accepted %s", literal)
		}
	}
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		t.Fatal(err)
	}
	for _, a := range addrs {
		if n, ok := a.(*net.IPNet); ok && !hostDestination(n.IP) {
			t.Errorf("accepted host IP %s", n.IP)
		}
	}
}

func TestIsolatedAssignmentIdentity(t *testing.T) {
	a := `D:\VMs\a\Windows.vmx`
	if ownerID(a) != ownerID(strings.ToLower(a)) || ownerID(a) == ownerID(`D:\VMs\b\Windows.vmx`) {
		t.Fatal("ambiguous VM identity")
	}
	got := networkArray([]string{"VMnet19", "nat", "VMNet1", "VMnet2';throw"})
	if got != "@('vmnet19','vmnet1')" {
		t.Fatalf("invalid VMware network list: %s", got)
	}
}
