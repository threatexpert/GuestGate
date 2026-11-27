package gateway

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/xjasonlyu/tun2socks/v2/core"
	"github.com/xjasonlyu/tun2socks/v2/core/adapter"
	"github.com/xjasonlyu/tun2socks/v2/proxy/socks5"
	"github.com/xjasonlyu/tun2socks/v2/tunnel"
	"github.com/xjasonlyu/tun2socks/v2/tunnel/statistic"
	xproxy "golang.org/x/net/proxy"
	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/stack"

	"guestgate/internal/dnsrelay"
	"guestgate/internal/vmnet"
)

type gatewayHandler struct {
	*tunnel.DeferredTCPHandler
	lastTCP atomic.Int32
	dialer  xproxy.ContextDialer
	dns     *dnsrelay.Relay
	ctx     context.Context
}

func (h *gatewayHandler) DialTCP(ctx context.Context, id stack.TransportEndpointID) (net.Conn, error) {
	// The deferred forwarder creates the guest endpoint only after this returns.
	// Read and validate the entire SOCKS5 CONNECT reply, including BND.ADDR and port.
	dialCtx, cancel := context.WithTimeout(ctx, 26*time.Second)
	defer cancel()
	destination := net.JoinHostPort(id.LocalAddress.String(), strconv.Itoa(int(id.LocalPort)))
	conn, err := h.dialer.DialContext(dialCtx, "tcp", destination)
	if err != nil {
		h.lastTCP.Store(-1)
	} else {
		h.lastTCP.Store(1)
	}
	return conn, err
}

func (h *gatewayHandler) HandleUDP(c adapter.UDPConn) {
	if c.ID().LocalPort != 53 {
		h.DeferredTCPHandler.HandleUDP(c)
		return
	}
	go h.serveDNS(c)
}
func (h *gatewayHandler) serveDNS(c adapter.UDPConn) {
	defer c.Close()
	cancelRead := context.AfterFunc(h.ctx, func() { c.Close() })
	defer cancelRead()
	id := c.ID()
	dest, ok := netip.AddrFromSlice(id.LocalAddress.AsSlice())
	if !ok {
		return
	}
	target := netip.AddrPortFrom(dest.Unmap(), id.LocalPort)
	msg := make([]byte, 65535)
	for {
		c.SetReadDeadline(time.Now().Add(20 * time.Second))
		n, from, err := c.ReadFrom(msg)
		if err != nil {
			return
		}
		ctx, cancel := context.WithTimeout(h.ctx, 6*time.Second)
		reply, err := h.dns.Exchange(ctx, target, msg[:n])
		cancel()
		if err != nil {
			continue
		}
		if _, err = c.WriteTo(reply, from); err != nil {
			return
		}
	}
}

type gateway struct {
	addresses   gatewayAddresses
	guest, mac  net.HardwareAddr
	ip          netip.Addr
	hub         *networkHub
	link        *channel.Endpoint
	count       atomic.Uint64
	answeredARP atomic.Bool
}

func (g *gateway) ethernet(data []byte, protocol uint16) error {
	frame := make([]byte, max(60, 14+len(data)))
	copy(frame, g.guest)
	copy(frame[6:], g.mac)
	binary.BigEndian.PutUint16(frame[12:], protocol)
	copy(frame[14:], data)
	return g.hub.write(frame)
}
func (g *gateway) accept(frame []byte) error {
	switch binary.BigEndian.Uint16(frame[12:14]) {
	case 0x0806:
		if len(frame) < 42 || !bytes.Equal(frame[14:22], []byte{0, 1, 8, 0, 6, 4, 0, 1}) || !bytes.Equal(frame[38:42], g.ip.AsSlice()) {
			return nil
		}
		reply := append([]byte(nil), frame[14:42]...)
		reply[7] = 2
		copy(reply[18:24], g.guest)
		copy(reply[24:], frame[28:32])
		copy(reply[8:14], g.mac)
		copy(reply[14:18], g.ip.AsSlice())
		if e := g.ethernet(reply, 0x0806); e != nil {
			return e
		}
		g.answeredARP.Store(true)
	case 0x0800:
		if !bytes.Equal(frame[:6], g.mac) || len(frame) < 34 {
			return nil
		}
		// SOCKS5 carries TCP and UDP. Do not synthesize Internet ping replies.
		if frame[14]>>4 != 4 || (frame[23] != 6 && frame[23] != 17) {
			return nil
		}
		size := int(binary.BigEndian.Uint16(frame[16:18]))
		if size < 20 || size > len(frame)-14 {
			return nil
		}
		pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithData(frame[14 : 14+size])})
		g.link.InjectInbound(header.IPv4ProtocolNumber, pkt)
		pkt.DecRef()
		g.count.Add(1)
	}
	return nil
}
func (g *gateway) transmit(ctx context.Context) error {
	for {
		pkt := g.link.ReadContext(ctx)
		if pkt == nil {
			return nil
		}
		b := pkt.ToBuffer()
		e := g.ethernet(b.Flatten(), 0x0800)
		b.Release()
		pkt.DecRef()
		if e != nil {
			return e
		}
	}
}

// Probe the proposed gateway before advertising it in DHCP. A live peer
// owning this address could otherwise still answer ARP after GuestGate exits.
func (g *gateway) probeAddress(ctx context.Context, port vmnet.Port) error {
	probe := make([]byte, 60)
	copy(probe, []byte{255, 255, 255, 255, 255, 255})
	copy(probe[6:12], g.mac)
	copy(probe[12:22], []byte{8, 6, 0, 1, 8, 0, 6, 4, 0, 1})
	copy(probe[22:28], g.mac)
	copy(probe[38:42], g.ip.AsSlice())
	for attempt := 0; attempt < 3; attempt++ {
		if err := port.WriteFrame(probe); err != nil {
			return err
		}
		until := time.Now().Add(350 * time.Millisecond)
		for time.Now().Before(until) {
			if err := ctx.Err(); err != nil {
				return err
			}
			frame, err := port.ReadFrame()
			if err != nil {
				return err
			}
			if claimsAddress(frame, g.ip) {
				return fmt.Errorf("%w: %s", errGatewayInUse, g.ip)
			}
		}
	}
	return nil
}

var errGatewayInUse = errors.New("虚拟网关地址已被占用")

// Check the Ethernet/IPv4 ARP sender IP, not the target IP of our own probe.
func claimsAddress(frame []byte, ip netip.Addr) bool {
	return len(frame) >= 42 && bytes.Equal(frame[12:20], []byte{8, 6, 0, 1, 8, 0, 6, 4}) && bytes.Equal(frame[28:32], ip.AsSlice())
}

type frameBackend struct {
	name string
	open func() (vmnet.Port, error)
}

func selectPort(ctx context.Context, backends []frameBackend, probe func(context.Context, vmnet.Port) error) (vmnet.Port, string, error) {
	var failures error
	for _, b := range backends {
		if err := ctx.Err(); err != nil {
			return nil, "", err
		}
		p, err := b.open()
		if err == nil {
			err = probe(ctx, p)
			if err == nil {
				return p, b.name, nil
			}
			p.Close()
			if errors.Is(err, errGatewayInUse) || ctx.Err() != nil {
				return nil, "", err
			}
		}
		failures = errors.Join(failures, fmt.Errorf("%s: %w", b.name, err))
	}
	// The worker protocol uses one line per UI status.
	return nil, "", fmt.Errorf("无法打开虚拟网卡：%s", strings.ReplaceAll(failures.Error(), "\n", " / "))
}

func (g *gateway) status(lease netip.Addr, lastTCP int32, linkErr error) string {
	if n := g.count.Load(); n > 0 {
		state := "已收到代理流量"
		if lastTCP > 0 {
			state = "最近一次 SOCKS5 TCP 连接成功"
		} else if lastTCP < 0 {
			state = "最近一次 SOCKS5 TCP 连接失败，已阻断该连接"
		}
		return fmt.Sprintf("%s · %d 个 IPv4 包", state, n)
	}
	parts := []string{"网关 " + g.ip.String() + " 已就绪"}
	if lease.IsValid() {
		parts = append(parts, "DHCP 已分配 "+lease.String())
	}
	if g.answeredARP.Load() {
		parts = append(parts, "已应答 guest 的网关 ARP")
	}
	if linkErr != nil && !lease.IsValid() && !g.answeredARP.Load() {
		parts = append(parts, "VMware 网卡重连失败："+strings.Join(strings.Fields(linkErr.Error()), " "))
	}
	return strings.Join(append(parts, "等待首个 TCP/UDP 包"), " · ")
}

func (g *gateway) startStack(ctx context.Context, server, user, password string) (*gatewayHandler, func(), error) {
	upstream, e := socks5.New(server, user, password)
	if e != nil {
		return nil, nil, e
	}
	var auth *xproxy.Auth
	if user != "" {
		auth = &xproxy.Auth{User: user, Password: password}
	}
	tcpDialer, e := xproxy.SOCKS5("tcp", server, auth, &net.Dialer{Timeout: 6 * time.Second})
	if e != nil {
		return nil, nil, e
	}
	child, cancel := context.WithCancel(ctx)
	t := tunnel.New(upstream, statistic.DefaultManager)
	t.ProcessAsync()

	h := &gatewayHandler{DeferredTCPHandler: tunnel.NewDeferredTCPHandler(child, t), dialer: tcpDialer.(xproxy.ContextDialer), ctx: child}
	h.dns = dnsrelay.New(child, server, auth, h.dialer)
	s, e := core.CreateStack(&core.Config{LinkEndpoint: g.link, TransportHandler: h, RejectIPv6: true, DeferredTCP: &core.DeferredTCPConfig{Context: child}})
	if e != nil {
		cancel()
		<-h.dns.Done()
		h.Close()
		t.Close()
		return nil, nil, e
	}
	return h, func() {
		cancel()
		<-h.dns.Done()
		h.Close()
		s.Close()
		s.Wait()
		t.Close()
		g.link.Close()
	}, nil
}

func (m *manager) gatewayRun(ctx context.Context, v VM, dev, server, user, password string, p *setupProgress) (result error) {
	// Detach and shut down this guest's stack before waiting for vmrun or
	// restarting DHCP. Existing VMnet peers retain their own data paths.
	var reconnected chan error
	var dhcpInstalled bool
	defer func() {
		if reconnected != nil {
			<-reconnected
		}
		if dhcpInstalled {
			if err := m.dhcp.change(v, false); err != nil {
				result = errors.Join(result, fmt.Errorf("撤销 DHCP: %w", err))
			}
		}
	}()
	p.step(openGateway, "active", "正在打开 "+v.Network+" 并选择网关地址")
	guest, e := net.ParseMAC(v.MAC)
	if e != nil {
		return e
	}
	g := gateway{guest: guest, addresses: v.scope, link: channel.New(512, 1500, "")}
	child, cancel := context.WithCancel(ctx)
	defer cancel()
	h, closeStack, e := g.startStack(child, server, user, password)
	if e != nil {
		return e
	}
	defer closeStack()
	hub, e := m.networks.attach(child, v.Network, &g, []frameBackend{
		{"VMware 驱动", func() (vmnet.Port, error) { return vmnet.Open(v.Network) }},
		{"Npcap 回退", func() (vmnet.Port, error) { return vmnet.OpenNpcap(dev) }},
	})
	if e != nil {
		return e
	}
	defer m.networks.detach(v.Network, &g)
	p.step(openGateway, "done", hub.backend+" · "+g.ip.String())
	p.step(setDHCP, "active", "正在更新该网卡的 DHCP 配置")
	since := time.Now()
	v.gatewayIP = g.ip
	if e = m.dhcp.change(v, true); e != nil {
		return e
	}
	dhcpInstalled = true
	p.step(setDHCP, "done", "网关 "+g.ip.String()+" · DNS "+v.dns.String())
	p.step(confirmGuest, "active", "正在重连虚拟网卡，等待本次租约或首个 TCP/UDP 包")
	results := make(chan error, 1)
	go func() { results <- g.transmit(child) }()
	waitingSince := time.Now()
	var lease netip.Addr
	previous := g.status(lease, 0, nil)

	// Keep reporting while vmrun reconnects the NIC. Finish reconnecting even
	// if Stop is pressed between disconnectNamedDevice and connectNamedDevice.
	reconnected = make(chan error, 1)
	go func() {
		defer close(reconnected)
		reconnected <- renewLink(v)
	}()
	var linkErr error
	var nextLeaseRead time.Time
	var linkResult <-chan error = reconnected
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		select {
		case err := <-results:
			return err
		case <-hub.done:
			cancel()
			<-results
			return hub.err
		case linkErr = <-linkResult:
			linkResult = nil
		case now := <-ticker.C:
			if g.count.Load() == 0 && !now.Before(nextLeaseRead) {
				if observed := currentLease(v, since, now); observed.IsValid() {
					lease = observed
				}
				nextLeaseRead = now.Add(3 * time.Second)
			}
			packets := g.count.Load()
			if p.state.Phase != "ready" && (lease.IsValid() || packets > 0) {
				evidence := "已收到虚拟机 TCP/UDP 流量"
				if lease.IsValid() {
					evidence = "已确认本次 DHCP 租约 " + lease.String()
				}
				p.step(confirmGuest, "done", evidence)
			}
			status := g.status(lease, h.lastTCP.Load(), linkErr)
			if leaseHintDue(now.Sub(waitingSince), lease, g.count.Load()) {
				status += " · 长时间未观察到本次 DHCP 租约，请在 guest 内禁用再启用网络连接设备"
			}
			if status != previous {
				if p.state.Phase == "ready" {
					p.state.Status = status
					p.report(p.state)
				} else {
					p.step(confirmGuest, "active", status)
				}
				previous = status
			}
		}
	}
}

func leaseHintDue(elapsed time.Duration, lease netip.Addr, packets uint64) bool {
	return elapsed >= 45*time.Second && !lease.IsValid() && packets == 0
}
