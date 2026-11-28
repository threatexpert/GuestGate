package gateway

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"sync"
	"testing"
	"time"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"

	"guestgate/internal/upstream"
)

// Exercise both sides of the SYN handshake, including the deferred callback
// that must route the local HTTP stream around the recording and proxy paths.
func TestCRLOnVirtualGateway(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 6*time.Second)
	defer cancel()
	wire := channel.New(64, 1500, "")
	g := &gateway{link: channel.New(64, 1500, ""), isolated: true, ip: netip.MustParseAddr("192.0.2.77"), activity: new(activityBatch)}
	proxy, requests := controlledSOCKS(t)
	route, err := upstream.Parse(proxy)
	if err != nil {
		t.Fatal(err)
	}
	h, closeStack, err := g.startStack(ctx, route)
	if err != nil {
		t.Fatal(err)
	}
	defer closeStack()
	h.serveCRL = func(c net.Conn) {
		defer c.Close()
		req, e := http.ReadRequest(bufio.NewReader(c))
		if e == nil && req.RequestURI == "/pki/test.crl" {
			io.WriteString(c, "HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\ncrl")
		}
	}
	guest := stack.New(stack.Options{NetworkProtocols: []stack.NetworkProtocolFactory{ipv4.NewProtocol}, TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol}})
	defer func() { guest.Close(); guest.Wait() }()
	if e := guest.CreateNIC(1, wire); e != nil {
		t.Fatal(e)
	}
	local := tcpip.ProtocolAddress{Protocol: ipv4.ProtocolNumber, AddressWithPrefix: tcpip.AddressWithPrefix{Address: tcpip.AddrFrom4([4]byte{192, 0, 2, 128}), PrefixLen: 24}}
	if e := guest.AddProtocolAddress(1, local, stack.AddressProperties{}); e != nil {
		t.Fatal(e)
	}
	guest.SetRouteTable([]tcpip.Route{{Destination: header.IPv4EmptySubnet, NIC: 1}})
	var pumps sync.WaitGroup
	pump := func(src, dst *channel.Endpoint) {
		for {
			pkt := src.ReadContext(ctx)
			if pkt == nil {
				return
			}
			copy := stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: pkt.ToBuffer()})
			dst.InjectInbound(pkt.NetworkProtocolNumber, copy)
			copy.DecRef()
			pkt.DecRef()
		}
	}
	pumps.Go(func() { pump(wire, g.link) })
	pumps.Go(func() { pump(g.link, wire) })
	defer func() { cancel(); pumps.Wait() }()
	dial := func(port uint16) (net.Conn, error) {
		return gonet.DialContextTCP(ctx, guest, tcpip.FullAddress{NIC: 1, Addr: tcpip.AddrFrom4(g.ip.As4()), Port: port}, ipv4.ProtocolNumber)
	}
	c, e := dial(80)
	if e != nil {
		t.Fatal(e)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(3 * time.Second))
	fmt.Fprint(c, "GET /pki/test.crl HTTP/1.1\r\nHost: 192.0.2.77\r\n\r\n")
	res, e := http.ReadResponse(bufio.NewReader(c), nil)
	if e != nil {
		t.Fatal(e)
	}
	body, e := io.ReadAll(res.Body)
	res.Body.Close()
	if e != nil || string(body) != "crl" {
		t.Fatal(string(body), e)
	}
	if other, e := dial(445); e == nil {
		other.Close()
		t.Fatal("gateway exposed unrelated port")
	}
	select {
	case <-requests:
		t.Fatal("virtual gateway dialed upstream")
	default:
	}
}
