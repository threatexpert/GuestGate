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
	"sync"
	"sync/atomic"
	"time"

	"github.com/xjasonlyu/tun2socks/v2/core"
	"github.com/xjasonlyu/tun2socks/v2/core/adapter"
	"github.com/xjasonlyu/tun2socks/v2/metadata"
	"github.com/xjasonlyu/tun2socks/v2/tunnel"
	"github.com/xjasonlyu/tun2socks/v2/tunnel/statistic"
	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"

	"guestgate/internal/capture"
	"guestgate/internal/dnsrelay"
	"guestgate/internal/upstream"
	"guestgate/internal/vmnet"
)

const proxyTCPTimeout = 26 * time.Second

type gatewayHandler struct {
	stack       *stack.Stack
	gateway     *gateway
	crlSlots    chan struct{}
	serveCRL    func(net.Conn)
	flows       sync.WaitGroup
	flowMu      sync.Mutex
	closing     bool
	intercepted int
	drainingCA  *capture.Recorder
	activity    *activityBatch
	isolated    bool
	*tunnel.DeferredTCPHandler

	localTCPError atomic.Pointer[string]
	dialer        *upstream.Client
	dns           *dnsrelay.Relay
	ctx           context.Context
}

// Identifies a virtual HTTP connection so its bytes bypass TLS capture.
type crlConnection struct{ net.Conn }

func (h *gatewayHandler) isGateway(raw []byte) bool {
	ip, ok := netip.AddrFromSlice(raw)
	return ok && h.gateway != nil && h.gateway.ip == ip.Unmap()
}

func (h *gatewayHandler) dialCRL(serve func(net.Conn)) (net.Conn, error) {
	select {
	case h.crlSlots <- struct{}{}:
	default:
		return nil, errors.New("网关 CRL 请求过多")
	}
	client, server := net.Pipe()
	if !h.launch(func() {
		defer func() { <-h.crlSlots }()
		stop := context.AfterFunc(h.ctx, func() { server.Close() })
		defer stop()
		serve(server)
	}) {
		<-h.crlSlots
		client.Close()
		server.Close()
		return nil, net.ErrClosed
	}
	return crlConnection{client}, nil
}

func (h *gatewayHandler) DialTCP(ctx context.Context, id stack.TransportEndpointID) (net.Conn, error) {
	// The deferred forwarder creates the guest endpoint only after this returns.
	// Both SOCKS5 and HTTP dialers wait for the upstream CONNECT reply.
	destination := net.JoinHostPort(id.LocalAddress.String(), strconv.Itoa(int(id.LocalPort)))
	if h.isGateway(id.LocalAddress.AsSlice()) {
		if id.LocalPort == 80 {
			if r := h.crlRecorder(); r != nil {
				return h.dialCRL(func(c net.Conn) {
					if r.ServeCRL(c) {
						h.activity.add("PKI", "已向客户机返回宿主机 CA 的签名吊销列表")
					}
				})
			}
			if h.serveCRL != nil {
				return h.dialCRL(h.serveCRL)
			}
		}
		return nil, errors.New("虚拟网关未开放此端口")
	}
	if h.isolated && hostDestination(id.LocalAddress.AsSlice()) {
		h.activity.add("阻断", "TCP "+destination+" · 隔离策略")
		err := errors.New("隔离策略阻断宿主机地址")
		h.gateway.recording().Failed(destination, false, err)
		return nil, err
	}
	dialCtx, cancel := context.WithTimeout(ctx, proxyTCPTimeout)
	defer cancel()
	h.activity.add("TCP", destination+" · 请求连接")
	source := net.JoinHostPort(id.RemoteAddress.String(), strconv.Itoa(int(id.RemotePort)))
	conn, err := h.dialer.DialGuestTCP(dialCtx, destination, source)
	if err != nil {
		detail := destination + " · " + err.Error()
		h.activity.add("错误", "TCP "+detail)
		if problem := localTCPDialProblem(err); problem != "" {
			h.localTCPError.Store(&problem)
		}
		h.gateway.recording().Failed(destination, false, err)
	} else {
		h.activity.add("TCP", destination+" · 上游代理已连接")
		h.localTCPError.Store(nil)
	}
	return conn, err
}

func (h *gatewayHandler) launch(f func()) bool {
	h.flowMu.Lock()
	defer h.flowMu.Unlock()
	if h.closing {
		return false
	}
	h.flows.Go(f)
	return true
}
func (h *gatewayHandler) stopFlows() {
	h.flowMu.Lock()
	h.closing = true
	h.flowMu.Unlock()
	h.flows.Wait()
}

// A TLS handshake already in flight may still need its issuer's CRL after
// recording stops. Keep that endpoint available until the captured flows drain.
func (h *gatewayHandler) crlRecorder() *capture.Recorder {
	h.flowMu.Lock()
	defer h.flowMu.Unlock()
	if r := h.gateway.recording(); r != nil {
		return r
	}
	return h.drainingCA
}

func (h *gatewayHandler) HandleTCPConnected(guest adapter.TCPConn, remote net.Conn) {
	if tracked, ok := remote.(*upstream.GuestTCP); ok {
		// Resolve the endpoint at handoff; later tuple reuse must never reset a different flow.
		if ep, ok := h.stack.FindTransportEndpoint(header.IPv4ProtocolNumber, tcp.ProtocolNumber, guest.ID(), 0).(*tcp.Endpoint); ok {
			tracked.BindAbort(ep.Abort)
		}
		remote = tracked.Conn
	}
	if _, local := remote.(crlConnection); local {
		h.DeferredTCPHandler.HandleTCPConnected(guest, remote)
		return
	}
	h.flowMu.Lock()
	recorder := h.gateway.recording()
	if recorder != nil {
		h.intercepted++
		h.drainingCA = recorder
	}
	h.flowMu.Unlock()
	if recorder == nil {
		h.DeferredTCPHandler.HandleTCPConnected(guest, remote)
		return
	}
	release := func() {
		h.flowMu.Lock()
		h.intercepted--
		if h.intercepted == 0 {
			h.drainingCA = nil
		}
		h.flowMu.Unlock()
	}
	id := guest.ID()
	dst := net.JoinHostPort(id.LocalAddress.String(), strconv.Itoa(int(id.LocalPort)))
	if !h.launch(func() {
		defer release()
		if err := recorder.Relay(h.ctx, guest, remote, dst, "http://"+h.gateway.ip.String()+recorder.CRLPath()); err != nil && h.ctx.Err() == nil {
			h.activity.add("录制", dst+" · "+err.Error())
		}
	}) {
		release()
		guest.Close()
		remote.Close()
	}
}

func (h *gatewayHandler) HandleUDP(c adapter.UDPConn) {
	id := c.ID()
	if h.isGateway(id.LocalAddress.AsSlice()) {
		c.Close()
		return
	}
	if h.isolated && hostDestination(id.LocalAddress.AsSlice()) {
		dst := net.JoinHostPort(id.LocalAddress.String(), strconv.Itoa(int(id.LocalPort)))
		h.activity.add("阻断", "UDP "+dst+" · 隔离策略")
		h.gateway.recording().Failed(dst, true, errors.New("隔离策略阻断宿主机地址"))
		c.Close()
		return
	}
	if id.LocalPort != 53 {
		h.DeferredTCPHandler.HandleUDP(c)
		return
	}
	if !h.launch(func() { h.serveDNS(c) }) {
		c.Close()
	}
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
	var tap *capture.Tap
	var recording *capture.Recorder
	defer func() { tap.Close("") }()
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
		if current := h.gateway.recording(); current != recording {
			tap.Close("")
			recording = current
			tap = current.Open(target.String(), "", "", false, true)
		}
		tap.Data(0, msg[:n])
		reply, err := h.dns.Exchange(ctx, target, msg[:n])
		cancel()
		if err != nil {
			h.activity.add("错误", "DNS "+query+" · "+err.Error())
			tap.Note("DNS 转发失败：" + err.Error())
			continue
		}
		tap.Data(1, reply)
		if _, err = c.WriteTo(reply, from); err != nil {
			return
		}
	}
}

type gateway struct {
	capture            *atomic.Pointer[capture.Recorder]
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

func (g *gateway) recording() *capture.Recorder {
	if g == nil || g.capture == nil {
		return nil
	}
	return g.capture.Load()
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
		if g.link == nil || !bytes.Equal(frame[:6], g.mac) || len(frame) < 34 {
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
	return g.transmitLink(ctx, g.link)
}
func (g *gateway) transmitLink(ctx context.Context, link *channel.Endpoint) error {
	for {
		pkt := link.ReadContext(ctx)
		if pkt == nil {
			return nil
		}
		if err := g.sendPacket(pkt); err != nil {
			return err
		}
	}
}
func (g *gateway) sendPacket(pkt *stack.PacketBuffer) error {
	defer pkt.DecRef()
	b := pkt.ToBuffer()
	defer b.Release()
	data := b.Flatten()
	if err := g.ethernet(data, 0x0800); err != nil {
		return err
	}
	g.downBytes.Add(uint64(len(data)))
	return nil
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
	gateway  *gateway
	client   *upstream.Client
	ctx      context.Context
	activity *activityBatch
}

func (p activityProxy) DialContext(ctx context.Context, m *metadata.Metadata) (net.Conn, error) {
	return p.client.DialContext(ctx, "tcp", m.DestinationAddress())
}

func (p activityProxy) DialUDP(m *metadata.Metadata) (net.PacketConn, error) {
	dst := m.DestinationAddress()
	p.activity.add("UDP", dst+" · 请求转发")
	conn, err := p.client.DialPacket(upstream.WithPurpose(p.ctx, upstream.UDPControl, dst))
	if err != nil {
		p.activity.add("错误", "UDP "+dst+" · "+err.Error())
		p.gateway.recording().Failed(dst, true, err)
		return nil, err
	}
	return p.gateway.recording().Open(dst, "", "", false, true).Packet(conn), nil
}

func (g *gateway) startStack(ctx context.Context, client *upstream.Client) (*gatewayHandler, func(), error) {
	return g.stackOn(ctx, client, g.link)
}
func (g *gateway) stackOn(ctx context.Context, client *upstream.Client, link *channel.Endpoint) (*gatewayHandler, func(), error) {
	child, cancel := context.WithCancel(ctx)
	t := tunnel.New(activityProxy{g, client, child, g.activity}, statistic.DefaultManager)
	t.ProcessAsync()

	h := &gatewayHandler{gateway: g, crlSlots: make(chan struct{}, 32), activity: g.activity, isolated: g.isolated, DeferredTCPHandler: tunnel.NewDeferredTCPHandler(child, t), dialer: client, ctx: child}
	h.dns = dnsrelay.New(child, client)
	s, e := core.CreateStack(&core.Config{LinkEndpoint: link, TransportHandler: h, RejectIPv6: true, DeferredTCP: &core.DeferredTCPConfig{Context: child}})
	if e != nil {
		cancel()
		<-h.dns.Done()
		h.Close()
		t.Close()
		return nil, nil, e
	}
	h.stack = s
	return h, func() {
		cancel()
		<-h.dns.Done()
		h.Close()
		s.Close()
		s.Wait()
		h.stopFlows()
		t.Close()
		link.Close()
	}, nil
}

func (m *manager) gatewayRun(ctx context.Context, v VM, dev string, client *upstream.Client, active *atomic.Pointer[capture.Recorder], p *setupProgress, session sessionControl) (result error) {
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
	g := gateway{capture: active, activity: p.activity, isolated: v.isolated, guest: guest, addresses: v.scope}
	child, cancel := context.WithCancel(ctx)
	defer cancel()
	route, e := g.newForwarding(child, client)
	if e != nil {
		return e
	}
	g.link = route.link
	defer func() { p.cleaning("正在关闭代理连接和协议栈"); route.close() }()
	drivers := []frameBackend{{"VMware 驱动", func() (vmnet.Port, error) { return vmnet.Open(v.Network) }}}
	if !v.isolated {
		drivers = append(drivers, frameBackend{"Npcap 回退", func() (vmnet.Port, error) { return vmnet.OpenNpcap(dev) }})
	}
	hub, e := m.networks.attach(child, v.Network, &g, drivers)
	if e != nil {
		return e
	}
	defer func() { p.cleaning("正在停止转发并释放虚拟网络端口"); m.networks.detach(v.Network, &g) }()
	p.activity.add("GuestGate", "本地转发网关使用的驱动："+hub.backend)
	p.step(openGateway, "done", "本地网关已就绪，虚拟机将使用 "+g.ip.String()+" 作为默认网关")
	p.step(setDHCP, "active", "正在更新该网卡的 DHCP 配置")
	since := time.Now()
	v.gatewayIP = g.ip
	if e = m.dhcp.change(v, true); e != nil {
		return e
	}
	dhcpInstalled = true
	p.step(setDHCP, "done", "网关 "+g.ip.String()+" · DNS "+v.dns.String())
	p.step(confirmGuest, "active", "正在重连虚拟网卡，等待本次租约或首个 TCP/UDP 包")
	route.transmit(&g)
	waitingSince := time.Now()
	var lease netip.Addr
	p.state.Stats.Server, p.state.Stats.DNS = client.Display(), v.dns.String()
	sample := trafficSample{at: since}
	var probeResult chan dnsrelay.Health
	startProbe := func() {
		probeResult = make(chan dnsrelay.Health, 1)
		p.state.Stats.Probing = true
		go func(f *forwarding, out chan<- dnsrelay.Health) { out <- f.handler.dns.Check(f.ctx, v.dns) }(route, probeResult)
	}
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
			<-route.sent
			return err
		case <-p.activity.flush:
			p.report(p.state)
		case cmd := <-session.commands:
			var res ControlResult
			if child.Err() != nil || p.state.Phase != "ready" {
				res.Error = "会话尚未就绪或已停止"
			} else {
				switch cmd.Action {
				case "connections":
					page := route.sockets.Page(cmd.Offset, cmd.Query, cmd.Kind)
					res.Page = &page
				case "disconnect-one":
					if err := route.sockets.Disconnect(cmd.ConnectionID); err != nil {
						res.Error = err.Error()
					}
				case "record":
					err := g.setRecording(v.Path, cmd.RecordingRoot, cmd.RecordTraffic, p)
					if err != nil {
						res.Error = err.Error()
						p.activity.add("错误", res.Error)
					}
				case "disconnect", "switch":
					var c *upstream.Client
					var err error
					if cmd.Action == "switch" {
						c, err = upstream.Parse(cmd.Proxy)
					} else {
						c, err = route.client.FreshTransport()
					}
					if err != nil {
						res.Error = err.Error()
						break
					}
					next, err := g.newForwarding(child, c)
					if err != nil {
						res.Error = err.Error()
						break
					}
					if err := g.switchForwarding(route, next); err != nil {
						next.close()
						cmd.reply(ControlResult{Error: err.Error()})
						return err
					}
					route = next
					if probeResult != nil {
						<-probeResult
						probeResult = nil
					}
					p.state.Stats.Server = c.Display()
					p.state.Stats.LocalTCPError = ""
					p.state.Stats.Health = dnsrelay.Health{}
					p.activity.add("上游", "已断开本虚拟机的原有连接，新连接使用 "+c.Display())
					startProbe()
				}
			}
			if cmd.Action != "connections" {
				p.state.Stats.TCPConnections, p.state.Stats.UDPControls = route.sockets.Counts()
				p.report(p.state)
			}
			cmd.reply(res)
		case <-session.probe:
			if probeResult != nil || p.state.Phase != "ready" || child.Err() != nil {
				continue
			}
			startProbe()
			p.report(p.state)
		case health := <-probeResult:
			probeResult = nil
			p.state.Stats.Probing = false
			p.state.Stats.Health = health
			for _, check := range []struct {
				name   string
				result dnsrelay.CheckResult
			}{
				{"上游代理服务", health.Service},
				{"TCP 转发探测", health.TCP},
				{"UDP 转发探测", health.UDP},
			} {
				if check.result.State == "error" || check.result.State == "unsupported" {
					p.activity.add("上游", check.name+" · "+check.result.Detail)
				}
			}
			p.report(p.state)
		case err := <-route.sent:
			return err
		case <-hub.done:
			cancel()
			<-route.sent
			return hub.err
		case linkErr = <-linkResult:
			if linkErr != nil {
				p.activity.add("错误", "虚拟网卡重连 · "+linkErr.Error())
			}
			linkResult = nil
			reconnected = nil // The reconnect command has returned; no wait during shutdown.
		case now := <-ticker.C:
			before := p.state
			p.state.Stats.TCPConnections, p.state.Stats.UDPControls = route.sockets.Counts()
			if recorder := active.Load(); recorder != nil && p.state.RecordingError == "" {
				if e := recorder.Status(); e != nil {
					active.Swap(nil).Close()
					p.state.Recording = false
					p.state.RecordingError = e.Error()
					p.activity.add("错误", e.Error())
				}
			}
			up := g.upBytes.Load()
			if up == 0 && !now.Before(nextLeaseRead) {
				if observed := currentLease(v, since, now); observed.IsValid() {
					lease = observed
				}
				nextLeaseRead = now.Add(3 * time.Second)
			}
			p.state.Stats.sample(&sample, now, up, g.downBytes.Load())
			p.state.Stats.LocalTCPError = ""
			if detail := route.handler.localTCPError.Load(); detail != nil {
				p.state.Stats.LocalTCPError = *detail
			}
			if p.state.Phase == "starting" && child.Err() == nil && (lease.IsValid() || up > 0) {
				evidence := "已收到虚拟机 TCP/UDP 流量"
				if lease.IsValid() {
					evidence = "已确认本次 DHCP 租约 " + lease.String()
				}
				startProbe()
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
