package gateway

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync"

	"guestgate/internal/vmnet"
)

type networkPool struct {
	mu   sync.Mutex
	hubs map[string]*networkHub
}

type networkHub struct {
	port    vmnet.Port
	backend string
	ip      netip.Addr
	subnet  netip.Prefix
	writes  sync.Mutex
	mu      sync.RWMutex
	guests  map[string]*gateway
	cancel  context.CancelFunc
	done    chan struct{}
	err     error // published by closing done
}

func (h *networkHub) write(frame []byte) error {
	h.writes.Lock()
	defer h.writes.Unlock()
	return h.port.WriteFrame(frame)
}

func (h *networkHub) run(ctx context.Context) {
	defer close(h.done)
	for ctx.Err() == nil {
		frame, err := h.port.ReadFrame()
		if err != nil {
			h.err = err
			return
		}
		if len(frame) < 14 {
			continue
		}
		h.mu.RLock()
		g := h.guests[string(frame[6:12])]
		if g != nil {
			err = g.accept(frame)
		}
		h.mu.RUnlock()
		if err != nil {
			h.err = err
			return
		}
	}
}

func gatewayMAC(ip netip.Addr) net.HardwareAddr {
	b := ip.As4()
	return net.HardwareAddr{2, 0x47, b[0], b[1], b[2], b[3]}
}

func (p *networkPool) attach(ctx context.Context, network string, g *gateway, drivers []frameBackend) (*networkHub, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if p.hubs == nil {
		p.hubs = make(map[string]*networkHub)
	}
	key := string(g.guest)
	h := p.hubs[network]
	if h == nil {
		port, name, err := selectPort(ctx, drivers, g.chooseAddress)
		if err != nil {
			return nil, err
		}
		lifetime, cancel := context.WithCancel(context.Background())
		h = &networkHub{port: port, backend: name, ip: g.ip, subnet: g.addresses.subnet, guests: make(map[string]*gateway), done: make(chan struct{}), cancel: cancel}
		g.hub = h
		h.guests[key] = g
		p.hubs[network] = h
		go h.run(lifetime)
		return h, nil
	}
	select {
	case <-h.done:
		return nil, fmt.Errorf("VMnet 已停止: %w", h.err)
	default:
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.subnet != g.addresses.subnet || !g.addresses.allows(h.ip) {
		return nil, errors.New("活动 VMnet 的网关与当前子网或地址配置冲突")
	}
	g.ip, g.mac = h.ip, gatewayMAC(h.ip)
	if string(g.mac) == key || h.guests[key] != nil {
		return nil, errors.New("VMnet 上的 MAC 地址冲突")
	}
	g.hub = h
	h.guests[key] = g
	return h, nil
}

func (p *networkPool) detach(network string, g *gateway) {
	p.mu.Lock()
	defer p.mu.Unlock()
	h := p.hubs[network]
	h.mu.Lock()
	delete(h.guests, string(g.guest))
	empty := len(h.guests) == 0
	h.mu.Unlock()
	if empty {
		h.cancel()
		<-h.done
		h.port.Close()
		delete(p.hubs, network)
	}
}
