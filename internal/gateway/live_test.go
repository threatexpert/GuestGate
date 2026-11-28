package gateway

import (
	"context"
	"encoding/binary"
	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"io"
	"net"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"guestgate/internal/upstream"
)

// Use real loopback SOCKS connections and the guest's deferred SYN path.
func TestSwitchDropsTCPAndUDPControlBeforeNewForwarding(t *testing.T) {
	oldServer, newServer := dnsListener(t), dnsListener(t)
	ip := netip.MustParseAddr("192.0.2.2")
	wire := &testWire{make(chan []byte, 8), make(chan []byte, 32)}
	g := &gateway{activity: new(activityBatch), guest: net.HardwareAddr{0, 12, 41, 0, 0, 1}, mac: gatewayMAC(ip), ip: ip, hub: &networkHub{port: wire}}
	makeRoute := func(server net.Addr) *forwarding {
		c, err := upstream.Parse(server.String())
		if err != nil {
			t.Fatal(err)
		}
		f, err := g.newForwarding(t.Context(), c)
		if err != nil {
			t.Fatal(err)
		}
		return f
	}
	old := makeRoute(oldServer.Addr())
	g.link = old.link
	old.transmit(g)
	f := old
	defer func() { f.close() }()
	if err := g.accept(guestSYN(g, 23000)); err != nil {
		t.Fatal(err)
	}
	tcp := acceptDNSControl(t, oldServer, 0)
	expectDNSCommand(t, tcp, 1, "198.51.100.42:80")
	dnsReplyCode(t, tcp, 0, 1080)
	select {
	case <-wire.out:
	case <-time.After(2 * time.Second):
		t.Fatal("missing SYN-ACK")
	}
	associate := func(target string) (net.PacketConn, net.Conn) {
		t.Helper()
		packet := make(chan net.PacketConn, 1)
		go func() {
			c, _ := old.client.DialPacket(upstream.WithPurpose(old.ctx, upstream.UDPControl, target))
			packet <- c
		}()
		control := acceptDNSControl(t, oldServer, 0)
		expectDNSCommand(t, control, 3, "0.0.0.0:0")
		dnsReplyCode(t, control, 0, 1081)
		pc := <-packet
		if pc == nil {
			t.Fatal("missing UDP association")
		}
		t.Cleanup(func() { pc.Close() })
		return pc, control
	}
	pc, control := associate("192.0.2.53:42")
	single, remoteControl := associate("192.0.2.54:43")
	match := old.sockets.Page(0, ":43", upstream.UDPControl)
	if match.Matched != 1 {
		t.Fatalf("control lookup: %+v", match)
	}
	if err := old.sockets.Disconnect(match.Items[0].ID); err != nil {
		t.Fatal(err)
	}
	remoteControl.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := remoteControl.Read(make([]byte, 1)); err == nil {
		t.Fatal("selected control socket stayed open")
	} else if e, ok := err.(net.Error); ok && e.Timeout() {
		t.Fatal(err)
	}
	if _, err := single.WriteTo([]byte{1}, &net.UDPAddr{IP: net.IPv4(192, 0, 2, 54), Port: 43}); err == nil {
		t.Fatal("selected control left UDP socket open")
	}
	snap := old.sockets.Page(0, "", "")
	if snap.Total != 2 || snap.Controls != 1 || snap.Items[0].Target != "198.51.100.42:80" || snap.Items[1].Kind != upstream.UDPControl {
		t.Fatalf("unexpected connections: %+v", snap)
	}
	next := makeRoute(newServer.Addr())
	if err := g.switchForwarding(old, next); err != nil {
		t.Fatal(err)
	}
	f = next
	for _, c := range []net.Conn{tcp, control} {
		c.SetReadDeadline(time.Now().Add(time.Second))
		if _, err := c.Read(make([]byte, 1)); err == nil {
			t.Fatal("connection survived switch")
		} else if ne, ok := err.(net.Error); ok && ne.Timeout() {
			t.Fatal("old socket still open")
		}
	}
	if _, err := pc.WriteTo([]byte{42}, &net.UDPAddr{IP: net.IPv4(192, 0, 2, 53), Port: 42}); err == nil {
		t.Fatal("retired UDP socket accepted payload")
	}
	if _, err := old.client.DialContext(context.Background(), "tcp", "192.0.2.80:80"); err == nil {
		t.Fatal("retired proxy dialled after switch")
	}
	if err := g.accept(guestSYN(g, 23001)); err != nil {
		t.Fatal(err)
	}
	fresh := acceptDNSControl(t, newServer, 0)
	expectDNSCommand(t, fresh, 1, "198.51.100.42:80")
	same, err := next.client.FreshTransport()
	if err != nil {
		t.Fatal(err)
	}
	reconnect, err := g.newForwarding(t.Context(), same)
	if err != nil {
		t.Fatal(err)
	}
	if err := g.switchForwarding(next, reconnect); err != nil {
		t.Fatal(err)
	}
	f = reconnect
	fresh.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := fresh.Read(make([]byte, 1)); err == nil {
		t.Fatal("old pending dial survived disconnect")
	} else if e, ok := err.(net.Error); ok && e.Timeout() {
		t.Fatal("pending socket stayed open")
	}
	if err := g.accept(guestSYN(g, 23002)); err != nil {
		t.Fatal(err)
	}
	afterReset := acceptDNSControl(t, newServer, 0)
	expectDNSCommand(t, afterReset, 1, "198.51.100.42:80")
}

// Exercise idle readers on an independent guest TCP stack through the actual
// VMnet frame interface and SOCKS negotiation, including the final RST.
func TestIdleGuestReadsNoticeSingleAndAllDisconnect(t *testing.T) {
	wire := &testWire{out: make(chan []byte, 64)}
	host := netip.MustParseAddr("192.0.2.2")
	g := &gateway{activity: new(activityBatch), guest: net.HardwareAddr{0, 12, 41, 0, 0, 1}, mac: gatewayMAC(host), ip: host, hub: &networkHub{port: wire}}
	proxy := dnsListener(t)
	client, err := upstream.Parse(proxy.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	route, err := g.newForwarding(t.Context(), client)
	if err != nil {
		t.Fatal(err)
	}
	g.link = route.link
	route.transmit(g)
	defer func() { route.close() }()
	guest := stack.New(stack.Options{NetworkProtocols: []stack.NetworkProtocolFactory{ipv4.NewProtocol}, TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol}})
	link := channel.New(64, 1500, "")
	if e := guest.CreateNIC(1, link); e != nil {
		t.Fatal(e)
	}
	addr := tcpip.AddrFrom4([4]byte{192, 0, 2, 11})
	if e := guest.AddProtocolAddress(1, tcpip.ProtocolAddress{Protocol: ipv4.ProtocolNumber, AddressWithPrefix: tcpip.AddressWithPrefix{Address: addr, PrefixLen: 24}}, stack.AddressProperties{}); e != nil {
		t.Fatal(e)
	}
	guest.SetRouteTable([]tcpip.Route{{Destination: header.IPv4EmptySubnet, NIC: 1}})
	ctx, cancel := context.WithCancel(t.Context())
	var pumps sync.WaitGroup
	pumps.Go(func() {
		for {
			pkt := link.ReadContext(ctx)
			if pkt == nil {
				return
			}
			b := pkt.ToBuffer()
			frame := make([]byte, 14)
			copy(frame, g.mac)
			copy(frame[6:], g.guest)
			binary.BigEndian.PutUint16(frame[12:], 0x800)
			frame = append(frame, b.Flatten()...)
			b.Release()
			pkt.DecRef()
			g.hub.mu.RLock()
			_ = g.accept(frame)
			g.hub.mu.RUnlock()
		}
	})
	pumps.Go(func() {
		for {
			select {
			case <-ctx.Done():
				return
			case frame := <-wire.out:
				pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithData(frame[14:])})
				link.InjectInbound(ipv4.ProtocolNumber, pkt)
				pkt.DecRef()
			}
		}
	})
	defer func() { cancel(); pumps.Wait(); guest.Close(); guest.Wait(); link.Close() }()
	connect := func() (net.Conn, net.Conn) {
		ready := make(chan net.Conn, 1)
		go func() {
			ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
			defer cancel()
			conn, err := gonet.DialContextTCP(ctx, guest, tcpip.FullAddress{NIC: 1, Addr: tcpip.AddrFrom4([4]byte{198, 51, 100, 42}), Port: 80}, ipv4.ProtocolNumber)
			if err != nil {
				ready <- nil
				return
			}
			ready <- conn
		}()
		upstreamConn := acceptDNSControl(t, proxy, 0)
		expectDNSCommand(t, upstreamConn, 1, "198.51.100.42:80")
		dnsReplyCode(t, upstreamConn, 0, 1080)
		conn := <-ready
		if conn == nil {
			t.Fatal("guest handshake failed")
		}
		// Receiving upstream data proves handoff to the forwarding handler.
		conn.SetReadDeadline(time.Now().Add(time.Second))
		if _, err := upstreamConn.Write([]byte{7}); err != nil {
			t.Fatal(err)
		}
		if _, err := io.ReadFull(conn, make([]byte, 1)); err != nil {
			t.Fatal(err)
		}
		return conn, upstreamConn
	}
	idleRead := func(conn net.Conn) <-chan error {
		result := make(chan error, 1)
		conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		go func() { _, err := conn.Read(make([]byte, 1)); result <- err }()
		return result
	}
	requireReset := func(result <-chan error) {
		t.Helper()
		if err := <-result; err == nil || !strings.Contains(err.Error(), "reset") {
			t.Fatalf("idle reader got %v, want reset", err)
		}
	}
	first, _ := connect()
	defer first.Close()
	second, remote := connect()
	defer second.Close()
	page := route.sockets.Page(0, first.LocalAddr().String(), "TCP")
	if page.Total != 2 || page.Matched != 1 {
		t.Fatalf("filtered snapshot %+v", page)
	}
	reading := idleRead(first)
	if err := route.sockets.Disconnect(page.Items[0].ID); err != nil {
		t.Fatal(err)
	}
	requireReset(reading)
	if _, err := remote.Write([]byte{8}); err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadFull(second, make([]byte, 1)); err != nil {
		t.Fatalf("unselected connection: %v", err)
	}
	reading = idleRead(second)
	fresh, err := client.FreshTransport()
	if err != nil {
		t.Fatal(err)
	}
	next, err := g.newForwarding(t.Context(), fresh)
	if err != nil {
		t.Fatal(err)
	}
	if err := g.switchForwarding(route, next); err != nil {
		t.Fatal(err)
	}
	route = next
	requireReset(reading)
	third, _ := connect()
	defer third.Close()
	if err := route.sockets.Disconnect(page.Items[0].ID); err == nil {
		t.Fatal("stale connection ID accepted")
	}
}
