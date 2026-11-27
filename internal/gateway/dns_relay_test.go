package gateway

import (
	"bytes"
	"context"
	"encoding/binary"
	"io"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/xjasonlyu/tun2socks/v2/transport/socks5"
	"golang.org/x/net/proxy"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"

	"guestgate/internal/dnsrelay"
)

func dnsListener(t *testing.T) *net.TCPListener {
	t.Helper()
	l, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	return l
}

func acceptDNSControl(t *testing.T, l *net.TCPListener, method byte) net.Conn {
	t.Helper()
	l.SetDeadline(time.Now().Add(3 * time.Second))
	c, err := l.Accept()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	c.SetDeadline(time.Now().Add(3 * time.Second))
	greeting := readDNSBytes(t, c, 2)
	methods := readDNSBytes(t, c, int(greeting[1]))
	if greeting[0] != 5 || !bytes.Contains(methods, []byte{method}) {
		t.Fatalf("unexpected SOCKS greeting %x %x", greeting, methods)
	}
	writeDNSBytes(t, c, []byte{5, method})
	return c
}

func readDNSBytes(t *testing.T, c io.Reader, n int) []byte {
	t.Helper()
	b := make([]byte, n)
	if _, err := io.ReadFull(c, b); err != nil {
		t.Fatal(err)
	}
	return b
}
func writeDNSBytes(t *testing.T, c io.Writer, b []byte) {
	t.Helper()
	if _, err := c.Write(b); err != nil {
		t.Fatal(err)
	}
}

func expectDNSCommand(t *testing.T, c net.Conn, cmd byte, target string) {
	t.Helper()
	if actual := readDNSBytes(t, c, 3); !bytes.Equal(actual, []byte{5, cmd, 0}) {
		t.Fatalf("unexpected command %x (want %d)", actual, cmd)
	}
	addr, err := socks5.ReadAddr(c, make([]byte, socks5.MaxAddrLen))
	if err != nil || addr.String() != target {
		t.Fatalf("SOCKS target %v, %v; want %s", addr, err, target)
	}
}

func dnsReplyCode(t *testing.T, c net.Conn, rep byte, port int) {
	t.Helper()
	writeDNSBytes(t, c, binary.BigEndian.AppendUint16([]byte{5, rep, 0, 1, 0, 0, 0, 0}, uint16(port)))
}

func dnsStack(t *testing.T, l *net.TCPListener, user, password string) *gateway {
	t.Helper()
	ip := netip.MustParseAddr("192.168.7.2")
	g := &gateway{guest: net.HardwareAddr{0, 12, 41, 0, 0, 1}, mac: gatewayMAC(ip), ip: ip, link: channel.New(64, 1500, "")}
	_, stop, err := g.startStack(t.Context(), l.Addr().String(), user, password)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(stop)
	return g
}

func guestDNSQuery(t *testing.T, g *gateway, target string, port uint16, label byte) []byte {
	t.Helper()
	// All clients deliberately use the same transaction ID.
	q := []byte{0x12, 0x34, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 1, label, 0, 0, 1, 0, 1}
	frame := make([]byte, 14+20+8+len(q))
	copy(frame, g.mac)
	copy(frame[6:], g.guest)
	binary.BigEndian.PutUint16(frame[12:], 0x800)
	src := tcpip.AddrFrom4([4]byte{192, 168, 7, 101})
	dst := tcpip.AddrFrom4(netip.MustParseAddr(target).As4())
	ip := header.IPv4(frame[14:34])
	ip.Encode(&header.IPv4Fields{TotalLength: uint16(len(frame) - 14), TTL: 64, Protocol: 17, SrcAddr: src, DstAddr: dst})
	ip.SetChecksum(^ip.CalculateChecksum())
	udp := header.UDP(frame[34:42])
	udp.Encode(&header.UDPFields{SrcPort: port, DstPort: 53, Length: uint16(len(q) + 8)})
	copy(frame[42:], q)
	if err := g.accept(frame); err != nil {
		t.Fatal(err)
	}
	return q
}

func expectGuestDNS(t *testing.T, g *gateway, target string, port uint16, query []byte) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
	defer cancel()
	p := g.link.ReadContext(ctx)
	if p == nil {
		t.Fatal("guest received no DNS response")
	}
	defer p.DecRef()
	b := p.ToBuffer()
	defer b.Release()
	frame := b.Flatten()
	ip := header.IPv4(frame)
	if ip.SourceAddress().String() != target || ip.DestinationAddress().String() != "192.168.7.101" || ip.Protocol() != 17 {
		t.Fatalf("wrong guest IP header %x", frame)
	}
	payload := frame[ip.HeaderLength():]
	udp := header.UDP(payload)
	want := bytes.Clone(query)
	want[2] |= 0x80
	if udp.SourcePort() != 53 || udp.DestinationPort() != port || !bytes.Equal(payload[8:], want) {
		t.Fatalf("wrong guest UDP response %x (want %d, %x)", payload, port, want)
	}
}

func testUDPRelay(t *testing.T) *net.UDPConn {
	t.Helper()
	c, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	return c
}

func readRelayDNS(t *testing.T, u *net.UDPConn, target string) ([]byte, *net.UDPAddr) {
	t.Helper()
	u.SetDeadline(time.Now().Add(3 * time.Second))
	buf := make([]byte, 1500)
	n, peer, err := u.ReadFromUDP(buf)
	if err != nil {
		t.Fatal(err)
	}
	a, q, err := socks5.DecodeUDPPacket(buf[:n])
	if err != nil || a.String() != target || len(q) < 12 {
		t.Fatalf("wrong UDP relay request %x, %v", buf[:n], err)
	}
	q[2] |= 0x80
	return buf[:n], peer
}

func TestGuestDNSRelayAndReconnect(t *testing.T) {
	l := dnsListener(t)
	u := testUDPRelay(t)
	g := dnsStack(t, l, "guest", "secret")
	setup := func() net.Conn {
		t.Helper()
		c := acceptDNSControl(t, l, 2)
		if !bytes.Equal(readDNSBytes(t, c, 14), []byte("\x01\x05guest\x06secret")) {
			t.Fatal("wrong authentication frame")
		}
		writeDNSBytes(t, c, []byte{1, 0})
		expectDNSCommand(t, c, 3, "0.0.0.0:0")
		dnsReplyCode(t, c, 0, u.LocalAddr().(*net.UDPAddr).Port)
		return c
	}
	first := guestDNSQuery(t, g, "1.1.1.1", 53001, 'a')
	control := setup()
	answer1, peer := readRelayDNS(t, u, "1.1.1.1:53")
	second := guestDNSQuery(t, g, "1.1.1.1", 53002, 'b')
	answer2, peer2 := readRelayDNS(t, u, "1.1.1.1:53")
	if peer.String() != peer2.String() || bytes.Equal(answer1[10:12], answer2[10:12]) {
		t.Fatal("shared relay did not distinguish identical transaction IDs")
	}
	wrong := bytes.Clone(answer1)
	copy(wrong[4:8], []byte{8, 8, 8, 8})
	wrong[len(wrong)-1] = 99
	if _, err := u.WriteToUDP(wrong, peer); err != nil {
		t.Fatal(err)
	}
	if _, err := u.WriteToUDP(answer2, peer); err != nil {
		t.Fatal(err)
	}
	expectGuestDNS(t, g, "1.1.1.1", 53002, second)
	if _, err := u.WriteToUDP(answer1, peer); err != nil {
		t.Fatal(err)
	}
	expectGuestDNS(t, g, "1.1.1.1", 53001, first)
	control.Close()
	setup() // The upstream sees a fresh association before the next guest query.
	third := guestDNSQuery(t, g, "8.8.8.8", 53003, 'c')
	answer3, peer3 := readRelayDNS(t, u, "8.8.8.8:53")
	if _, err := u.WriteToUDP(answer3, peer3); err != nil {
		t.Fatal(err)
	}
	expectGuestDNS(t, g, "8.8.8.8", 53003, third)
}

func TestGuestDNSTCPOnlyOnUnsupported(t *testing.T) {
	l := dnsListener(t)
	g := dnsStack(t, l, "", "")
	for i, target := range []string{"1.1.1.1", "8.8.8.8"} {
		port := uint16(53101 + i)
		q := guestDNSQuery(t, g, target, port, 'a'+byte(i))
		if i == 0 {
			c := acceptDNSControl(t, l, 0)
			expectDNSCommand(t, c, 3, "0.0.0.0:0")
			dnsReplyCode(t, c, 7, 0)
			c.Close()
		}
		c := acceptDNSControl(t, l, 0)
		expectDNSCommand(t, c, 1, target+":53")
		dnsReplyCode(t, c, 0, 0)
		size := binary.BigEndian.Uint16(readDNSBytes(t, c, 2))
		payload := readDNSBytes(t, c, int(size))
		if !bytes.Equal(payload, q) {
			t.Fatalf("wrong TCP DNS request %x", payload)
		}
		payload[2] |= 0x80
		writeDNSBytes(t, c, append(binary.BigEndian.AppendUint16(nil, size), payload...))
		expectGuestDNS(t, g, target, port, q)
		c.Close()
	}
}

func TestDNSAssociateFailuresRetryUDP(t *testing.T) {
	for _, failure := range []string{"authentication", "EOF", "malformed 07", "truncated 07", "general failure", "connection refused", "address unsupported"} {
		t.Run(failure, func(t *testing.T) {
			l := dnsListener(t)
			g := dnsStack(t, l, "guest", "secret")
			guestDNSQuery(t, g, "1.1.1.1", 53201, 'a')
			if failure == "authentication" {
				c := acceptDNSControl(t, l, 2)
				readDNSBytes(t, c, 14)
				writeDNSBytes(t, c, []byte{1, 7})
				c.Close()
			} else {
				c := acceptDNSControl(t, l, 0)
				expectDNSCommand(t, c, 3, "0.0.0.0:0")
				switch failure {
				case "malformed 07":
					writeDNSBytes(t, c, []byte{4, 7, 0, 1, 0, 0, 0, 0, 0, 0})
				case "truncated 07":
					writeDNSBytes(t, c, []byte{5, 7, 0})
				case "general failure":
					dnsReplyCode(t, c, 1, 0)
				case "connection refused":
					dnsReplyCode(t, c, 5, 0)
				case "address unsupported":
					dnsReplyCode(t, c, 8, 0)
				}
				c.Close()
			}
			c := acceptDNSControl(t, l, 0)
			expectDNSCommand(t, c, 3, "0.0.0.0:0")
		})
	}
}

func TestDNSUDPTimeoutRetainsAssociation(t *testing.T) {
	l := dnsListener(t)
	u := testUDPRelay(t)
	ctx, cancel := context.WithCancel(t.Context())
	d, err := proxy.SOCKS5("tcp", l.Addr().String(), nil, proxy.Direct)
	if err != nil {
		t.Fatal(err)
	}
	r := dnsrelay.New(ctx, l.Addr().String(), nil, d.(proxy.ContextDialer))
	defer func() { cancel(); <-r.Done() }()
	q := []byte{0, 1, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 1}
	target := netip.MustParseAddrPort("1.1.1.1:53")
	result := make(chan error, 1)
	requestCtx, expire := context.WithTimeout(ctx, 500*time.Millisecond)
	defer expire()
	go func() { _, e := r.Exchange(requestCtx, target, q); result <- e }()
	c := acceptDNSControl(t, l, 0)
	expectDNSCommand(t, c, 3, "0.0.0.0:0")
	dnsReplyCode(t, c, 0, u.LocalAddr().(*net.UDPAddr).Port)
	readRelayDNS(t, u, target.String())
	if err = <-result; err != context.DeadlineExceeded {
		t.Fatalf("UDP loss: %v", err)
	}
	next, stop := context.WithTimeout(ctx, 2*time.Second)
	defer stop()
	go func() { _, e := r.Exchange(next, target, q); result <- e }()
	response, peer := readRelayDNS(t, u, target.String())
	if _, err = u.WriteToUDP(response, peer); err != nil {
		t.Fatal(err)
	}
	if err = <-result; err != nil {
		t.Fatal(err)
	}
	l.SetDeadline(time.Now().Add(50 * time.Millisecond))
	if extra, err := l.Accept(); err == nil {
		extra.Close()
		t.Fatal("UDP loss opened an additional SOCKS connection")
	}
}
