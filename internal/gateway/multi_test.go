package gateway

import (
	"bytes"
	"context"
	"encoding/binary"
	"io"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"

	"guestgate/internal/vmnet"
)

func TestSharedDHCPAndRenewHint(t *testing.T) {
	base := []byte("subnet 192.168.7.0 netmask 255.255.255.0 {\r\n range 192.168.7.128 192.168.7.254;\r\n}\r\n")
	a := VM{MAC: "00:0c:29:00:00:01", subnet: netip.MustParsePrefix("192.168.7.0/24")}
	a.gatewayIP = netip.MustParseAddr("192.168.7.2")
	a.dns, _ = DNSAddress("")
	b := a
	b.MAC = "00:0c:29:00:00:02"
	b.dns, _ = DNSAddress("9.9.9.9")
	peers := map[string]VM{a.MAC: a, b.MAC: b}
	both, err := renderDHCP(base, peers)
	if err != nil {
		t.Fatal(err)
	}
	for _, v := range peers {
		block := "hardware ethernet " + v.MAC + ";\r\n option routers 192.168.7.2;\r\n option domain-name-servers " + v.dns.String() + ";"
		if !strings.Contains(string(both), block) {
			t.Fatal("missing reservation", block)
		}
	}
	delete(peers, a.MAC)
	remaining, err := renderDHCP(both, peers)
	if err != nil || bytes.Contains(remaining, []byte(a.MAC)) || !bytes.Contains(remaining, []byte(b.MAC)) {
		t.Fatal("independent removal", err)
	}
	clean, err := renderDHCP(remaining, nil)
	if err != nil || !bytes.Equal(base, clean) {
		t.Fatal("DHCP restore", err)
	}
	if leaseHintDue(10*time.Second-time.Nanosecond, netip.Addr{}, 0) || !leaseHintDue(10*time.Second, netip.Addr{}, 0) || leaseHintDue(time.Minute, a.dns, 0) || leaseHintDue(time.Minute, netip.Addr{}, 1) {
		t.Fatal("incorrect DHCP timeout hint")
	}
}

type testWire struct{ in, out chan []byte }

func (w *testWire) ReadFrame() ([]byte, error) {
	select {
	case f := <-w.in:
		return f, nil
	case <-time.After(4 * time.Millisecond):
		return nil, nil
	}
}
func (w *testWire) WriteFrame(b []byte) error { w.out <- bytes.Clone(b); return nil }
func (w *testWire) Close()                    {}

// Provide an actual loopback SOCKS5 endpoint and pause between its success
// header and its bound address. A SYN-ACK at either pause is premature.
func controlledSOCKS(t *testing.T) (string, chan net.Conn) {
	t.Helper()
	l, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ch := make(chan net.Conn, 4)
	t.Cleanup(func() { l.Close() })
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				c.SetDeadline(time.Now().Add(8 * time.Second))
				var greeting [3]byte
				if _, err := io.ReadFull(c, greeting[:]); err != nil {
					c.Close()
					return
				}
				c.Write([]byte{5, 0})
				var req [10]byte
				if _, err := io.ReadFull(c, req[:]); err != nil || req[0] != 5 || req[1] != 1 || req[3] != 1 {
					c.Close()
					return
				}
				ch <- c
			}(c)
		}
	}()
	return l.Addr().String(), ch
}

func guestSYN(g *gateway, port uint16) []byte {
	frame := make([]byte, 54)
	copy(frame, g.mac)
	copy(frame[6:], g.guest)
	binary.BigEndian.PutUint16(frame[12:], 0x800)
	src := tcpip.AddrFrom4([4]byte{192, 168, 7, byte(port%100 + 100)})
	dst := tcpip.AddrFrom4([4]byte{198, 51, 100, 42})
	ip := header.IPv4(frame[14:34])
	ip.Encode(&header.IPv4Fields{TotalLength: 40, TTL: 64, Protocol: 6, SrcAddr: src, DstAddr: dst})
	ip.SetChecksum(^ip.CalculateChecksum())
	tcp := header.TCP(frame[34:])
	tcp.Encode(&header.TCPFields{SrcPort: port, DstPort: 80, SeqNum: 100, DataOffset: 20, Flags: header.TCPFlagSyn, WindowSize: 65535})
	tcp.SetChecksum(^tcp.CalculateChecksum(header.PseudoHeaderChecksum(6, src, dst, 20)))
	return frame
}
func TestTwoGuestsWaitForOwnSOCKSReply(t *testing.T) {
	wire := &testWire{make(chan []byte, 8), make(chan []byte, 32)}
	var pool networkPool
	ip := netip.MustParseAddr("192.168.7.2")
	opened := 0
	drivers := []frameBackend{{"test", func() (vmnet.Port, error) { opened++; return wire, nil }}}
	attach := func(mac byte, server string) (*gateway, func()) {
		ctx, cancel := context.WithCancel(context.Background())
		g := &gateway{activity: new(activityBatch), addresses: gatewayAddresses{subnet: netip.MustParsePrefix("192.168.7.0/24")}, guest: net.HardwareAddr{0, 12, 41, 0, 0, mac}, mac: gatewayMAC(ip), ip: ip, link: channel.New(64, 1500, "")}
		_, closeStack, err := g.startStack(ctx, server, "", "")
		if err != nil {
			t.Fatal(err)
		}
		if _, err = pool.attach(ctx, "vmnet1", g, drivers); err != nil {
			t.Fatal(err)
		}
		done := make(chan error, 1)
		go func() { done <- g.transmit(ctx) }()
		stop := func() { cancel(); <-done; pool.detach("vmnet1", g); closeStack() }
		return g, stop
	}
	server1, requests1 := controlledSOCKS(t)
	server2, requests2 := controlledSOCKS(t)
	g1, stop1 := attach(1, server1)
	g2, stop2 := attach(2, server2)
	defer stop2()
	closed1 := false
	defer func() {
		if !closed1 {
			stop1()
		}
	}()
	if opened != 1 {
		t.Fatalf("opened VMnet %d times", opened)
	}
	for len(wire.out) > 0 {
		<-wire.out
	} // discard gateway address probes
	request := func(g *gateway, port uint16, ch chan net.Conn) net.Conn {
		wire.in <- guestSYN(g, port)
		select {
		case c := <-ch:
			t.Cleanup(func() { c.Close() })
			return c
		case <-time.After(2 * time.Second):
			t.Fatal("SOCKS CONNECT not received")
			return nil
		}
	}
	silent := func() {
		select {
		case f := <-wire.out:
			t.Fatalf("unexpected frame while CONNECT pending: %x", f)
		case <-time.After(120 * time.Millisecond):
		}
	}
	expect := func(g *gateway, flags byte) {
		select {
		case f := <-wire.out:
			if len(f) < 54 || !bytes.Equal(f[:6], g.guest) || f[47]&flags != flags || flags == 4 && f[47]&2 != 0 {
				t.Fatalf("wrong guest or TCP flags %x", f)
			}
		case <-time.After(2 * time.Second):
			t.Fatal("missing TCP response")
		}
	}
	c1 := request(g1, 41001, requests1)
	c2 := request(g2, 41002, requests2)
	silent()
	c1.Write([]byte{5, 5, 0, 1, 0, 0, 0, 0, 0, 0})
	expect(g1, 4)
	entries := g1.activity.drain()
	if len(entries) != 2 || entries[0].Kind != "TCP" || entries[0].Message != "198.51.100.42:80 · 请求连接" || entries[1].Kind != "错误" {
		t.Fatalf("failed guest activity: %+v", entries)
	}
	if entries = g2.activity.drain(); len(entries) != 1 || entries[0].Kind != "TCP" {
		t.Fatalf("other guest activity: %+v", entries)
	}
	invalid := request(g1, 41004, requests1)
	invalid.Write([]byte{4, 0, 0, 1, 127, 0, 0, 1, 0, 80})
	expect(g1, 4)
	stop1()
	closed1 = true
	wire.in <- guestSYN(g1, 41003)
	c2.Write([]byte{5, 0, 0, 1})
	silent()
	c2.Write([]byte{127, 0, 0, 1, 0, 80})
	expect(g2, 0x12)
	select {
	case <-requests1:
		t.Fatal("stopped guest still forwarded")
	default:
	}
}
