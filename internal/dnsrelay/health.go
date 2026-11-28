package dnsrelay

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"sync"
	"time"

	"guestgate/internal/upstream"
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
	if r.upstream.Scheme == "http" {
		return r.checkHTTP(parent, dns)
	}
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
			_, tcpErr = exchangeTCPDNS(ctx, r.upstream, target.String(), query)
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
	if err := r.upstream.CheckSOCKS(ctx); err != nil {
		return pathResult(err)
	}
	return CheckResult{"ok", "端口可达，SOCKS5 握手通过"}
}

func (r *Relay) checkHTTP(parent context.Context, dns netip.Addr) Health {
	ctx, cancel := context.WithTimeout(parent, 6*time.Second)
	defer cancel()
	h := Health{UDP: CheckResult{"unsupported", "HTTP CONNECT 仅支持 TCP，DNS 使用 TCP"}}
	conn, err := r.upstream.DialContext(ctx, "tcp", netip.AddrPortFrom(dns, 53).String())
	if err != nil {
		h.Service = pathResult(err)
		var status upstream.HTTPStatusError
		if errors.As(err, &status) && (status == 403 || status >= 500) {
			h.Service = CheckResult{"ok", "上游已响应 HTTP CONNECT 请求"}
		}
		h.TCP = pathResult(err)
	} else {
		defer conn.Close()
		h.Service = CheckResult{"ok", "HTTP CONNECT 隧道已建立"}
		_, err = queryDNSConn(ctx, conn, rootNSQuery())
		h.TCP = pathResult(err)
	}
	h.CheckedAt = time.Now().Unix()
	return h
}

func pathResult(err error) CheckResult {
	switch {
	case err == nil:
		return CheckResult{State: "ok"}
	case errors.Is(err, upstream.ErrUDPAssociateEOF):
		return CheckResult{"unsupported", "上游收到 UDP ASSOCIATE 后直接关闭连接（EOF），DNS 自动使用 TCP"}
	case errors.Is(err, upstream.ErrUDPUnsupported):
		return CheckResult{"unsupported", "上游不支持 UDP ASSOCIATE，DNS 自动使用 TCP"}
	default:
		return CheckResult{"error", err.Error()}
	}
}
