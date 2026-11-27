package gateway

import (
	"fmt"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"golang.org/x/net/dns/dnsmessage"
)

type ActivityEntry struct {
	Time          int64
	Kind, Message string
}

// Collect on the packet path, then drain into the existing worker status pipe.
// A burst must never hold up a guest connection on UI or pipe I/O.
const activityBatchLimit = 256

type activityBatch struct {
	mu      sync.Mutex
	entries []ActivityEntry
	skipped int
	flush   chan struct{}
}

func (b *activityBatch) add(kind, message string) {
	if b == nil {
		return
	}
	if len(message) > 768 {
		n := 768
		for !utf8.RuneStart(message[n]) {
			n--
		}
		message = message[:n] + "…"
	}
	entry := ActivityEntry{time.Now().UnixMilli(), kind, message}
	b.mu.Lock()
	defer b.mu.Unlock()
	if len(b.entries) == activityBatchLimit {
		b.skipped++
		return
	}
	b.entries = append(b.entries, entry)
	if len(b.entries) == 64 {
		select {
		case b.flush <- struct{}{}:
		default:
		}
	}
}

func (b *activityBatch) pending() bool {
	if b == nil {
		return false
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	return len(b.entries) > 0
}

func (b *activityBatch) drain() []ActivityEntry {
	b.mu.Lock()
	defer b.mu.Unlock()
	out := b.entries
	if b.skipped > 0 {
		out = append(out, ActivityEntry{time.Now().UnixMilli(), "GuestGate", fmt.Sprintf("活动过于频繁，本批省略 %d 条记录", b.skipped)})
	}
	b.entries = nil
	b.skipped = 0
	return out
}

func dnsQuestion(message []byte) string {
	var p dnsmessage.Parser
	if h, err := p.Start(message); err == nil && !h.Response {
		if q, err := p.Question(); err == nil {
			return q.Name.String() + " " + strings.TrimPrefix(q.Type.String(), "Type")
		}
	}
	return "DNS 查询"
}
