package upstream

import (
	"context"
	"errors"
	"net"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

type ConnectionInfo struct {
	ID                         uint64
	Kind, Target, Local, Guest string
	Since                      int64
}
type ConnectionPage struct {
	Total, Controls, Matched, Offset int
	Items                            []ConnectionInfo
}

// IDs remain unique when a live VM switches upstreams or resets its stack.
var nextConnectionID atomic.Uint64

type guestKey struct{}
type guestFlow struct {
	mu           sync.Mutex
	source       string
	abort        func()
	disconnected bool
}

// GuestTCP carries the exact guest endpoint from the deferred handshake to
// the physical socket registry, even for wrapped SOCKS and HTTP connections.
type GuestTCP struct {
	net.Conn
	flow *guestFlow
}

func (c *Client) DialGuestTCP(ctx context.Context, target, source string) (net.Conn, error) {
	flow := &guestFlow{source: source}
	conn, err := c.DialContext(context.WithValue(ctx, guestKey{}, flow), "tcp", target)
	if err != nil {
		return nil, err
	}
	return &GuestTCP{conn, flow}, nil
}
func (c *GuestTCP) BindAbort(fn func()) {
	f := c.flow
	f.mu.Lock()
	already := f.disconnected
	if !already {
		f.abort = fn
	}
	f.mu.Unlock()
	if already {
		fn()
	}
}
func (f *guestFlow) disconnect() {
	f.mu.Lock()
	f.disconnected = true
	abort := f.abort
	f.abort = nil
	f.mu.Unlock()
	if abort != nil {
		abort()
	}
}

type purposeKey struct{}
type purpose struct{ kind, target string }

func WithPurpose(ctx context.Context, kind, target string) context.Context {
	return context.WithValue(ctx, purposeKey{}, purpose{kind, target})
}

type Connections struct {
	mu       sync.Mutex
	closed   bool
	ctx      context.Context
	cancel   context.CancelFunc
	active   map[*observedConn]ConnectionInfo
	controls int
}
type observedConn struct {
	net.Conn
	owner    *Connections
	guest    *guestFlow
	datagram net.Conn
	once     sync.Once
}

func (c *observedConn) Close() error {
	var err error
	c.once.Do(func() {
		err = c.Conn.Close()
		c.owner.mu.Lock()
		if info, ok := c.owner.active[c]; ok {
			if info.Kind == UDPControl || info.Kind == DNSControl {
				c.owner.controls--
			}
			delete(c.owner.active, c)
		}
		packet := c.datagram
		c.owner.mu.Unlock()
		if packet != nil {
			packet.Close()
		}
	})
	return err
}
func (c *observedConn) CloseWrite() error { return c.Conn.(*net.TCPConn).CloseWrite() }

const UDPControl = "UDP 控制"
const DNSControl = "DNS UDP 控制"

func (r *Connections) register(conn net.Conn, label purpose, guest *guestFlow) (net.Conn, error) {
	if r == nil {
		return conn, nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		conn.Close()
		return nil, net.ErrClosed
	}
	if r.active == nil {
		r.active = make(map[*observedConn]ConnectionInfo)
	}
	source := ""
	if guest != nil {
		source = guest.source
	}
	c := &observedConn{Conn: conn, owner: r, guest: guest}
	r.active[c] = ConnectionInfo{ID: nextConnectionID.Add(1), Kind: label.kind, Target: label.target, Local: conn.LocalAddr().String(), Guest: source, Since: time.Now().UnixMilli()}
	if label.kind == UDPControl || label.kind == DNSControl {
		r.controls++
	}
	return c, nil
}
func (r *Connections) Counts() (int, int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.active), r.controls
}
func (r *Connections) Page(offset int, query, kind string) ConnectionPage {
	query = strings.ToLower(strings.TrimSpace(query))
	r.mu.Lock()
	total := len(r.active)
	rows := make([]ConnectionInfo, 0, len(r.active))
	for _, info := range r.active {
		if kind != "" && kind != info.Kind {
			continue
		}
		if query != "" && !strings.Contains(strings.ToLower(info.Target+" "+info.Local+" "+info.Guest+" "+info.Kind), query) {
			continue
		}
		rows = append(rows, info)
	}
	controls := r.controls
	r.mu.Unlock()
	sort.Slice(rows, func(i, j int) bool { return rows[i].ID < rows[j].ID })
	const size = 50
	offset = max(0, min(offset, (max(len(rows)-1, 0)/size)*size))
	return ConnectionPage{Total: total, Controls: controls, Matched: len(rows), Offset: offset, Items: rows[offset:min(offset+size, len(rows))]}
}
func (r *Connections) Disconnect(id uint64) error {
	r.mu.Lock()
	var selected *observedConn
	for conn, info := range r.active {
		if info.ID == id {
			selected = conn
			break
		}
	}
	r.mu.Unlock()
	if selected == nil {
		return errors.New("该连接已结束，请刷新列表")
	}
	if selected.guest != nil {
		selected.guest.disconnect()
	}
	return selected.Close()
}

func (r *Connections) Close() {
	r.mu.Lock()
	r.closed = true
	r.cancel()
	sockets := make([]*observedConn, 0, len(r.active))
	for c := range r.active {
		sockets = append(sockets, c)
	}
	r.mu.Unlock()
	for _, c := range sockets {
		c.Close()
	}
}
func (c *Client) TrackConnections() *Connections {
	ctx, cancel := context.WithCancel(context.Background())
	r := &Connections{ctx: ctx, cancel: cancel}
	c.transport.connections = r
	return r
}
