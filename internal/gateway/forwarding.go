package gateway

import (
	"context"

	"guestgate/internal/upstream"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
)

// Each forwarding generation owns its stack, DNS state and upstream sockets.
// The VMware port, gateway address and DHCP lease belong to the longer VM session.
type forwarding struct {
	ctx          context.Context
	cancel       context.CancelFunc
	client       *upstream.Client
	sockets      *upstream.Connections
	link         *channel.Endpoint
	handler      *gatewayHandler
	closeStack   func()
	sent         chan error
	stopTransmit context.CancelFunc
}

func (g *gateway) newForwarding(parent context.Context, c *upstream.Client) (*forwarding, error) {
	ctx, cancel := context.WithCancel(parent)
	f := &forwarding{ctx: ctx, cancel: cancel, client: c, sockets: c.TrackConnections(), link: channel.New(512, 1500, "")}
	h, closeStack, err := g.stackOn(ctx, c, f.link)
	if err != nil {
		cancel()
		f.link.Close()
		return nil, err
	}
	f.handler, f.closeStack = h, closeStack
	return f, nil
}
func (f *forwarding) transmit(g *gateway) {
	ctx, cancel := context.WithCancel(f.ctx)
	f.stopTransmit = cancel
	f.sent = make(chan error, 1)
	go func() { defer close(f.sent); f.sent <- g.transmitLink(ctx, f.link) }()
}
func (f *forwarding) close() {
	f.cancel()
	f.sockets.Close()
	f.closeStack()
	if f.sent != nil {
		<-f.sent
	}
}
func (g *gateway) switchForwarding(old, next *forwarding) error {
	g.hub.mu.Lock()
	g.link = nil
	g.hub.mu.Unlock()
	// Keep the old stack and VMware port alive until its guest-facing resets
	// have actually been written. Only this guest's ingress is paused.
	old.stopTransmit()
	if err := <-old.sent; err != nil {
		return err
	}
	flush := func() error {
		for pkt := old.link.Read(); pkt != nil; pkt = old.link.Read() {
			if err := g.sendPacket(pkt); err != nil {
				return err
			}
		}
		return nil
	}
	if err := flush(); err != nil {
		return err
	}
	for _, endpoint := range old.handler.stack.RegisteredEndpoints() {
		if ep, ok := endpoint.(*tcp.Endpoint); ok {
			ep.Abort()
			if err := flush(); err != nil {
				return err
			}
		}
	}
	old.close()
	g.hub.mu.Lock()
	g.link = next.link
	g.hub.mu.Unlock()
	next.transmit(g)
	return nil
}
