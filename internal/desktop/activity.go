package desktop

import (
	"sync"
	"time"

	"guestgate/internal/gateway"
)

const activityLimit = 1000

type ActivityLine struct {
	ID uint64
	VM string
	gateway.ActivityEntry
}

type activityHistory struct {
	mu          sync.Mutex
	lines       [activityLimit]ActivityLine
	last, count uint64
}

func (h *activityHistory) append(vm string, entries ...gateway.ActivityEntry) {
	h.mu.Lock()
	defer h.mu.Unlock()
	for _, entry := range entries {
		h.lines[h.last%activityLimit] = ActivityLine{h.last + 1, vm, entry}
		h.last++
		h.count = min(h.count+1, activityLimit)
	}
}

func (h *activityHistory) record(vm, kind, message string) {
	h.append(vm, gateway.ActivityEntry{Time: time.Now().UnixMilli(), Kind: kind, Message: message})
}

func (a *App) ActivitySince(after uint64) []ActivityLine {
	h := &a.activity
	h.mu.Lock()
	defer h.mu.Unlock()
	start := max(min(after, h.last), h.last-h.count)
	lines := make([]ActivityLine, 0, h.last-start)
	for i := start; i < h.last; i++ {
		lines = append(lines, h.lines[i%activityLimit])
	}
	return lines
}

func (a *App) ClearActivity() uint64 {
	h := &a.activity
	h.mu.Lock()
	defer h.mu.Unlock()
	clear(h.lines[:])
	h.count = 0
	return h.last
}
