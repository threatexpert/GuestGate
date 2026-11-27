package dnsrelay

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/xjasonlyu/tun2socks/v2/transport/socks5"
	"golang.org/x/net/proxy"
)

// Each guest owns one DNS relay. Only a probe can enable UDP forwarding.
type Relay struct {
	ctx    context.Context
	server string
	auth   *proxy.Auth
	tcp    proxy.ContextDialer
	demand chan struct{}
	first  sync.Once
	done   chan struct{}

	mu       sync.Mutex
	current  *dnsAssociation
	verified *dnsAssociation
	lastErr  error
	changed  chan struct{}
}

func New(ctx context.Context, server string, auth *proxy.Auth, tcp proxy.ContextDialer) *Relay {
	r := &Relay{ctx: ctx, server: server, auth: auth, tcp: tcp, demand: make(chan struct{}), done: make(chan struct{}), changed: make(chan struct{})}
	go r.run()
	return r
}

func (r *Relay) publish(a *dnsAssociation, err error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.current, r.lastErr, r.verified = a, err, nil
	close(r.changed)
	r.changed = make(chan struct{})
}

func (r *Relay) run() {
	defer close(r.done)
	select {
	case <-r.ctx.Done():
		return
	case <-r.demand:
	}

	const minDelay = 100 * time.Millisecond
	delay := minDelay
	for r.ctx.Err() == nil {
		a, err := openDNSAssociation(r.ctx, r.server, r.auth)
		r.publish(a, err)
		if errors.Is(err, errUDPUnsupported) {
			select {
			case <-r.ctx.Done():
				return
			case <-time.After(30 * time.Second):
				continue
			}
		}
		if err == nil {
			started := time.Now()
			a.serve(r.ctx)
			r.publish(nil, net.ErrClosed)
			if time.Since(started) >= 3*time.Second {
				delay = minDelay
			}
		}
		select {
		case <-r.ctx.Done():
			return
		case <-time.After(delay):
		}
		delay = min(delay*2, 3*time.Second)
	}
}

func (r *Relay) Done() <-chan struct{} { return r.done }

func (r *Relay) Exchange(ctx context.Context, target netip.AddrPort, query []byte) ([]byte, error) {
	if len(query) < 12 || len(query) > 65535 {
		return nil, errors.New("invalid DNS message length")
	}
	r.mu.Lock()
	a := r.verified
	r.mu.Unlock()
	if a == nil {
		return exchangeTCPDNS(ctx, r.tcp, target.String(), query)
	}
	udpCtx, cancel := context.WithTimeout(ctx, 12*time.Second)
	reply, udpErr := a.exchange(udpCtx, target, query)
	cancel()
	if udpErr == nil {
		return reply, nil
	}
	if ctx.Err() != nil || r.ctx.Err() != nil {
		return nil, udpErr
	}
	r.mu.Lock()
	if r.verified == a {
		r.verified = nil
	}
	r.mu.Unlock()
	reply, tcpErr := exchangeTCPDNS(ctx, r.tcp, target.String(), query)
	if tcpErr != nil {
		return nil, fmt.Errorf("UDP DNS 转发失败（%v），TCP DNS 重试失败：%w", udpErr, tcpErr)
	}
	return reply, nil
}

// ProbeUDP verifies a DNS round trip on the current association. A successful
// SOCKS5 handshake alone does not establish that UDP datagrams can get back.
func (r *Relay) ProbeUDP(ctx context.Context, target netip.AddrPort) error {
	r.first.Do(func() { close(r.demand) })
	for {
		r.mu.Lock()
		a, changed, err := r.current, r.changed, r.lastErr
		r.mu.Unlock()
		if err != nil {
			return err
		}
		if a != nil {
			_, err = a.exchange(ctx, target, rootNSQuery())
			r.mu.Lock()
			if r.current == a {
				if err == nil {
					r.verified = a
				} else {
					r.verified = nil
				}
			} else if err == nil {
				err = net.ErrClosed
			}
			r.mu.Unlock()
			return err
		}
		select {
		case <-r.ctx.Done():
			return r.ctx.Err()
		case <-ctx.Done():
			return ctx.Err()
		case <-changed:
		}
	}
}

type pendingDNS struct {
	target netip.AddrPort
	reply  chan []byte
}

type dnsAssociation struct {
	control, udp net.Conn
	done         chan struct{}
	mu           sync.Mutex
	pending      map[uint16]pendingDNS
}

func newDNSAssociation(control, udp net.Conn) *dnsAssociation {
	return &dnsAssociation{control: control, udp: udp, done: make(chan struct{}), pending: make(map[uint16]pendingDNS)}
}

func (a *dnsAssociation) serve(ctx context.Context) {
	// EOF on the control stream invalidates the relay even when UDP is idle.
	stop := context.AfterFunc(ctx, func() { a.control.Close() })
	defer stop()
	controlDone := make(chan struct{})
	go func() {
		defer close(controlDone)
		io.Copy(io.Discard, a.control)
		a.udp.Close()
	}()
	buf := make([]byte, 65535)
	for {
		n, err := a.udp.Read(buf)
		if err != nil {
			break
		}
		addr, msg, err := socks5.DecodeUDPPacket(buf[:n])
		if err != nil || len(msg) < 12 || msg[2]&0x80 == 0 {
			continue
		}
		id := binary.BigEndian.Uint16(msg)
		a.mu.Lock()
		p, ok := a.pending[id]
		a.mu.Unlock()
		if !ok || addr.String() != p.target.String() {
			continue
		}
		select {
		case p.reply <- bytes.Clone(msg):
		default:
		}
	}
	close(a.done)
	a.control.Close()
	<-controlDone
}

func (a *dnsAssociation) exchange(ctx context.Context, target netip.AddrPort, query []byte) ([]byte, error) {
	packet, err := socks5.EncodeUDPPacket(socks5.SerializeAddr("", target.Addr(), target.Port()), query)
	if err != nil {
		return nil, err
	}
	// Different guest sockets can use the same DNS ID against the same resolver.
	p := pendingDNS{target: target, reply: make(chan []byte, 1)}
	var seed [2]byte
	rand.Read(seed[:])
	id := binary.BigEndian.Uint16(seed[:])
	a.mu.Lock()
	if len(a.pending) == 1<<16 {
		a.mu.Unlock()
		return nil, errors.New("DNS relay transaction IDs exhausted")
	}
	for {
		if _, used := a.pending[id]; !used {
			break
		}
		id++
	}
	a.pending[id] = p
	a.mu.Unlock()
	defer func() {
		a.mu.Lock()
		delete(a.pending, id)
		a.mu.Unlock()
	}()
	binary.BigEndian.PutUint16(packet[len(packet)-len(query):], id)
	if _, err := a.udp.Write(packet); err != nil {
		return nil, err
	}
	select {
	case msg := <-p.reply:
		copy(msg[:2], query[:2])
		return msg, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-a.done:
		return nil, net.ErrClosed
	}
}
