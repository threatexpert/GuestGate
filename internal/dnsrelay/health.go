package dnsrelay

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"sync"
	"time"
)

type CheckResult struct {
	State, Detail string
}

type Health struct {
	Service, TCP, UDP CheckResult
	CheckedAt         int64
}

func rootNSQuery() []byte {
	return []byte{0, 0, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 2, 0, 1}
}

// Check verifies the SOCKS listener independently of either path to the guest's
// resolver. A UDP check must never succeed through the TCP DNS fallback.
func (r *Relay) Check(parent context.Context, dns netip.Addr) Health {
	ctx, cancel := context.WithTimeout(parent, 5*time.Second)
	service := r.checkService(ctx)
	cancel()
	h := Health{Service: service}
	if service.State == "ok" {
		ctx, cancel = context.WithTimeout(parent, 6*time.Second)
		defer cancel()
		target := netip.AddrPortFrom(dns, 53)
		// Root NS query. Any matching DNS response proves a round trip.
		query := rootNSQuery()
		var wg sync.WaitGroup
		var tcpErr error
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, tcpErr = exchangeTCPDNS(ctx, r.tcp, target.String(), query)
		}()
		udpErr := r.ProbeUDP(ctx, target)
		wg.Wait()
		h.TCP, h.UDP = pathResult(tcpErr), pathResult(udpErr)
		var timeout net.Error
		if errors.As(udpErr, &timeout) && timeout.Timeout() && tcpErr == nil {
			h.UDP.Detail = "UDP DNS 探测超时，TCP DNS 已验证可用"
		}
	} else {
		r.mu.Lock()
		r.verified = nil
		r.mu.Unlock()
		h.TCP, h.UDP = CheckResult{State: "blocked"}, CheckResult{State: "blocked"}
	}
	h.CheckedAt = time.Now().Unix()
	return h
}

func (r *Relay) checkService(ctx context.Context) CheckResult {
	var d net.Dialer
	c, err := d.DialContext(ctx, "tcp", r.server)
	if err != nil {
		return CheckResult{"error", "无法连接上游端口 · " + err.Error()}
	}
	defer c.Close()
	stop := context.AfterFunc(ctx, func() { c.Close() })
	defer stop()
	if deadline, ok := ctx.Deadline(); ok {
		c.SetDeadline(deadline)
	}
	if err := negotiate(c, r.auth); err != nil {
		return CheckResult{"error", "端口可达，SOCKS5 握手或认证失败 · " + err.Error()}
	}
	return CheckResult{"ok", "端口可达，SOCKS5 握手通过"}
}

func pathResult(err error) CheckResult {
	switch {
	case err == nil:
		return CheckResult{State: "ok"}
	case errors.Is(err, errUDPAssociateEOF):
		return CheckResult{"unsupported", "上游收到 UDP ASSOCIATE 后直接关闭连接（EOF），DNS 自动使用 TCP"}
	case errors.Is(err, errUDPUnsupported):
		return CheckResult{"unsupported", "上游不支持 UDP ASSOCIATE，DNS 自动使用 TCP"}
	default:
		return CheckResult{"error", err.Error()}
	}
}
