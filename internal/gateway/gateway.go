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
	"github.com/xjasonlyu/tun2socks/v2/metadata"
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

const proxyTCPTimeout = 26 * time.Second

type gatewayHandler struct {
	activity *activityBatch
	isolated bool
	*tunnel.DeferredTCPHandler

	lastTCPError atomic.Pointer[string]
	dialer       xproxy.ContextDialer
	dns          *dnsrelay.Relay
	ctx          context.Context
}

func (h *gatewayHandler) DialTCP(ctx context.Context, id stack.TransportEndpointID) (net.Conn, error) {
	// The deferred forwarder creates the guest endpoint only after this returns.
	// Read and validate the entire SOCKS5 CONNECT reply, including BND.ADDR and port.
	destination := net.JoinHostPort(id.LocalAddress.String(), strconv.Itoa(int(id.LocalPort)))
	if h.isolated && hostDestination(id.LocalAddress.AsSlice()) {
		h.activity.add("阻断", "TCP "+destination+" · 隔离策略")
		return nil, errors.New("隔离策略阻断宿主机地址")
	}
	dialCtx, cancel := context.WithTimeout(ctx, proxyTCPTimeout)
	defer cancel()
	h.activity.add("TCP", destination+" · 请求连接")
	conn, err := h.dialer.DialContext(dialCtx, "tcp", destination)
	if err != nil {
		detail := destination + " · " + err.Error()
		h.activity.add("错误", "TCP "+detail)
		h.lastTCPError.Store(&detail)
	} else {
		h.activity.add("TCP", destination+" · SOCKS5 已连接")
		h.lastTCPError.Store(nil)
	}
	return conn, err
}

func (h *gatewayHandler) HandleUDP(c adapter.UDPConn) {
	id := c.ID()
	if h.isolated && hostDestination(id.LocalAddress.AsSlice()) {
		h.activity.add("阻断", "UDP "+net.JoinHostPort(id.LocalAddress.String(), strconv.Itoa(int(id.LocalPort)))+" · 隔离策略")
		c.Close()
		return
	}
	if id.LocalPort != 53 {
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
		ctx, cancel := context.WithTimeout(h.ctx, proxyTCPTimeout)
		query := dnsQuestion(msg[:n]) + " → " + target.String()
		h.activity.add("DNS", query)
		reply, err := h.dns.Exchange(ctx, target, msg[:n])
		cancel()
		if err != nil {
			h.activity.add("错误", "DNS "+query+" · "+err.Error())
			continue
		}
		if _, err = c.WriteTo(reply, from); err != nil {
			return
		}
	}
}

type gateway struct {
	activity           *activityBatch
	isolated           bool
	addresses          gatewayAddresses
	guest, mac         net.HardwareAddr
	ip                 netip.Addr
	hub                *networkHub
	link               *channel.Endpoint
	upBytes, downBytes atomic.Uint64
	answeredARP        atomic.Bool
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
		g.upBytes.Add(uint64(size))
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
		data := b.Flatten()
		size := len(data)
		e := g.ethernet(data, 0x0800)
		b.Release()
		pkt.DecRef()
		if e != nil {
			return e
		}
		g.downBytes.Add(uint64(size))
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

func (g *gateway) status(lease netip.Addr, linkErr error) string {
	if g.upBytes.Load() > 0 {
		return "已收到虚拟机代理流量"
	}
	parts := []string{"网关 " + g.ip.String()}
	if lease.IsValid() {
		parts = append(parts, "DHCP 已分配 "+lease.String())
	}
	if g.answeredARP.Load() {
		parts = append(parts, "已应答 guest 的网关 ARP")
	}
	if linkErr != nil && !lease.IsValid() && !g.answeredARP.Load() {
		parts = append(parts, "VMware 网卡重连失败："+strings.Join(strings.Fields(linkErr.Error()), " "))
	}
	return strings.Join(append(parts, "等待虚拟机续租或发起网络连接"), " · ")
}

type activityProxy struct {
	*socks5.Socks5
	activity *activityBatch
}

func (p activityProxy) DialUDP(m *metadata.Metadata) (net.PacketConn, error) {
	dst := m.DestinationAddress()
	p.activity.add("UDP", dst+" · 请求转发")
	conn, err := p.Socks5.DialUDP(m)
	if err != nil {
		p.activity.add("错误", "UDP "+dst+" · "+err.Error())
	}
	return conn, err
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
	t := tunnel.New(activityProxy{upstream, g.activity}, statistic.DefaultManager)
	t.ProcessAsync()

	h := &gatewayHandler{activity: g.activity, isolated: g.isolated, DeferredTCPHandler: tunnel.NewDeferredTCPHandler(child, t), dialer: tcpDialer.(xproxy.ContextDialer), ctx: child}
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

func (m *manager) gatewayRun(ctx context.Context, v VM, dev, server, user, password string, p *setupProgress, probe <-chan struct{}) (result error) {
	// Detach and shut down this guest's stack before waiting for vmrun or
	// restarting DHCP. Existing VMnet peers retain their own data paths.
	var reconnected chan error
	var dhcpInstalled bool
	defer func() {
		if reconnected != nil {
			p.cleaning("等待 VMware 完成虚拟网卡重连")
			if err := <-reconnected; err != nil {
				p.cleanupErr = fmt.Errorf("虚拟网卡重连失败: %w", err)
			}
		}
		if dhcpInstalled {
			p.cleaning("正在撤销该网卡的 DHCP 配置并重新加载 DHCP 服务")
			if err := m.dhcp.change(v, false); err != nil {
				p.cleanupErr = errors.Join(p.cleanupErr, fmt.Errorf("撤销 DHCP: %w", err))
			}
		}
		result = errors.Join(result, p.cleanupErr)
	}()
	p.step(openGateway, "active", "正在打开 "+v.Network+" 并选择网关地址")
	guest, e := net.ParseMAC(v.MAC)
	if e != nil {
		return e
	}
	g := gateway{activity: p.activity, isolated: v.isolated, guest: guest, addresses: v.scope, link: channel.New(512, 1500, "")}
	child, cancel := context.WithCancel(ctx)
	defer cancel()
	h, closeStack, e := g.startStack(child, server, user, password)
	if e != nil {
		return e
	}
	defer func() { p.cleaning("正在关闭代理连接和协议栈"); closeStack() }()
	drivers := []frameBackend{{"VMware 驱动", func() (vmnet.Port, error) { return vmnet.Open(v.Network) }}}
	if !v.isolated {
		drivers = append(drivers, frameBackend{"Npcap 回退", func() (vmnet.Port, error) { return vmnet.OpenNpcap(dev) }})
	}
	hub, e := m.networks.attach(child, v.Network, &g, drivers)
	if e != nil {
		return e
	}
	defer func() { p.cleaning("正在停止转发并释放虚拟网络端口"); m.networks.detach(v.Network, &g) }()
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
	p.state.Stats.Server, p.state.Stats.DNS = server, v.dns.String()
	sample := trafficSample{at: since}
	var probeResult chan dnsrelay.Health
	defer func() {
		if probeResult != nil {
			cancel()
			<-probeResult
		}
	}()

	// Keep reporting while vmrun reconnects the NIC. Finish reconnecting even
	// if Stop is pressed between disconnectNamedDevice and connectNamedDevice.
	reconnected = make(chan error, 1)
	go func() {
		defer close(reconnected)
		reconnected <- renewLink(v)
	}()
	guardFailure := make(chan error, 1)
	guardDone := make(chan struct{})
	go func() { defer close(guardDone); m.watchNetwork(child, v, guardFailure) }()
	defer func() { cancel(); <-guardDone }()
	var linkErr error
	var nextLeaseRead time.Time
	var linkResult <-chan error = reconnected
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		select {
		case err := <-guardFailure:
			cancel()
			<-results
			return err
		case <-p.activity.flush:
			p.report(p.state)
		case <-probe:
			if probeResult != nil || p.state.Phase != "ready" || child.Err() != nil {
				continue
			}
			probeResult = make(chan dnsrelay.Health, 1)
			p.state.Stats.Probing = true
			p.report(p.state)
			go func(out chan<- dnsrelay.Health) { out <- h.dns.Check(child, v.dns) }(probeResult)
		case health := <-probeResult:
			probeResult = nil
			p.state.Stats.Probing = false
			p.state.Stats.Health = health
			for _, check := range []struct {
				name   string
				result dnsrelay.CheckResult
			}{
				{"SOCKS5 服务", health.Service},
				{"TCP 转发探测", health.TCP},
				{"UDP 转发探测", health.UDP},
			} {
				if check.result.State == "error" || check.result.State == "unsupported" {
					p.activity.add("上游", check.name+" · "+check.result.Detail)
				}
			}
			p.report(p.state)
		case err := <-results:
			return err
		case <-hub.done:
			cancel()
			<-results
			return hub.err
		case linkErr = <-linkResult:
			if linkErr != nil {
				p.activity.add("错误", "虚拟网卡重连 · "+linkErr.Error())
			}
			linkResult = nil
			reconnected = nil // The reconnect command has returned; no wait during shutdown.
		case now := <-ticker.C:
			before := p.state
			up := g.upBytes.Load()
			if up == 0 && !now.Before(nextLeaseRead) {
				if observed := currentLease(v, since, now); observed.IsValid() {
					lease = observed
				}
				nextLeaseRead = now.Add(3 * time.Second)
			}
			p.state.Stats.sample(&sample, now, up, g.downBytes.Load())
			p.state.Stats.LastTCPError = ""
			if detail := h.lastTCPError.Load(); detail != nil {
				p.state.Stats.LastTCPError = *detail
			}
			if p.state.Phase != "ready" && (lease.IsValid() || up > 0) {
				evidence := "已收到虚拟机 TCP/UDP 流量"
				if lease.IsValid() {
					evidence = "已确认本次 DHCP 租约 " + lease.String()
				}
				p.step(confirmGuest, "done", evidence)
			}
			status := g.status(lease, linkErr)
			p.state.ShowGuestHelp = leaseHintDue(now.Sub(waitingSince), lease, up)
			if p.state.Phase != "ready" {
				p.state.Steps[confirmGuest].Detail = status
			}
			if p.state != before || p.activity.pending() {
				p.report(p.state)
			}
		}
	}
}

func leaseHintDue(elapsed time.Duration, lease netip.Addr, receivedBytes uint64) bool {
	return elapsed >= 10*time.Second && !lease.IsValid() && receivedBytes == 0
}
