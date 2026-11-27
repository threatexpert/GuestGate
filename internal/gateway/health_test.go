package gateway

import (
	"context"
	"encoding/binary"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"

	"golang.org/x/net/proxy"

	"guestgate/internal/dnsrelay"
)

// Exercise the service greeting and both paths through a local SOCKS server.
// No external resolver is contacted.
func TestSessionHealth(t *testing.T) {
	for _, mode := range []string{"both", "no-udp", "bad-greeting", "closed"} {
		t.Run(mode, func(t *testing.T) {
			l := dnsListener(t)
			u := testUDPRelay(t)
			server := l.Addr().String()
			if mode == "closed" {
				l.Close()
			}
			d, err := proxy.SOCKS5("tcp", server, nil, proxy.Direct)
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithCancel(t.Context())
			r := dnsrelay.New(ctx, server, nil, d.(proxy.ContextDialer))
			defer func() { cancel(); <-r.Done() }()
			result := make(chan dnsrelay.Health, 1)
			target := netip.MustParseAddr("192.0.2.53")
			go func() { result <- r.Check(ctx, target) }()
			switch mode {
			case "bad-greeting":
				l.SetDeadline(time.Now().Add(2 * time.Second))
				c, err := l.Accept()
				if err != nil {
					t.Fatal(err)
				}
				defer c.Close()
				readDNSBytes(t, c, 3)
				writeDNSBytes(t, c, []byte{4, 0})
			case "both", "no-udp":
				acceptDNSControl(t, l, 0).Close()
				for i := 0; i < 2; i++ {
					c := acceptDNSControl(t, l, 0)
					request := readDNSBytes(t, c, 10)
					switch request[1] {
					case 1:
						if string(request[4:10]) != string([]byte{192, 0, 2, 53, 0, 53}) {
							t.Fatalf("TCP probe to wrong resolver: %x", request)
						}
						dnsReplyCode(t, c, 0, 0)
						size := readDNSBytes(t, c, 2)
						query := readDNSBytes(t, c, int(binary.BigEndian.Uint16(size)))
						query[2] |= 0x80
						writeDNSBytes(t, c, append(size, query...))
					case 3:
						if mode == "no-udp" {
							dnsReplyCode(t, c, 7, 0)
							continue
						}
						dnsReplyCode(t, c, 0, u.LocalAddr().(*net.UDPAddr).Port)
						response, peer := readRelayDNS(t, u, "192.0.2.53:53")
						if _, err := u.WriteToUDP(response, peer); err != nil {
							t.Fatal(err)
						}
					default:
						t.Fatalf("unexpected command %x", request)
					}
				}
			}
			h := <-result
			switch mode {
			case "both":
				if h.Service.State != "ok" || h.TCP.State != "ok" || h.UDP.State != "ok" {
					t.Fatal(h)
				}
			case "no-udp":
				if h.Service.State != "ok" || h.TCP.State != "ok" || h.UDP.State != "unsupported" {
					t.Fatal(h)
				}
			default:
				if h.Service.State != "error" || h.TCP.State != "blocked" || h.UDP.State != "blocked" {
					t.Fatal(h)
				}
				if (mode == "bad-greeting") != strings.Contains(h.Service.Detail, "端口可达") {
					t.Fatal(h)
				}
			}
		})
	}
}

func TestSessionRatesReturnToIdle(t *testing.T) {
	start := time.Now()
	last := trafficSample{at: start}
	var s SessionStats
	s.sample(&last, start.Add(2*time.Second), 3072, 8192)
	if s.UpRate != 1536 || s.DownRate != 4096 {
		t.Fatal(s)
	}
	s.sample(&last, start.Add(3*time.Second), 3072, 8192)
	if s.UpRate != 0 || s.DownRate != 0 || s.UpBytes != 3072 || s.DownBytes != 8192 {
		t.Fatal(s)
	}
}
