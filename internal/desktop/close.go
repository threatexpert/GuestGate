package desktop

import (
	"context"

	"github.com/wailsapp/wails/v2/pkg/runtime"
)

type closeReport struct {
	Sessions     map[string]string
	Done, Failed bool
}

// Wails invokes this hook for both the X button and the final runtime.Quit.
func BeforeClose(ctx context.Context, a *App) bool {
	return a.beginClose(func(r closeReport) { runtime.EventsEmit(ctx, "guestgate:closing", r) }, func() { runtime.Quit(ctx) })
}

func (a *App) beginClose(notify func(closeReport), quit func()) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.closing {
		return !a.closeReady
	}
	a.closing = true
	for _, cancel := range a.checking {
		cancel()
	}
	if a.pipe == nil {
		a.closeReady = true
		return false
	}

	var keys []string
	for key, s := range a.states {
		if s.Running {
			keys = append(keys, key)
			if s.Phase != "stopping" {
				s.Phase, s.Status = "stopping", "正在停止代理"
				a.states[key] = s
			}
		}
	}
	pipe, done := a.pipe, a.done
	updates := make(chan struct{}, 1)
	a.closeUpdates = updates
	go func() {
		notify(a.closeSnapshot(keys, false))
		pipe.Close() // EOF cancels all sessions; continue reading worker progress.
		for {
			select {
			case <-updates:
				notify(a.closeSnapshot(keys, false))
			case <-done:
				last := a.closeSnapshot(keys, true)
				notify(last)
				if !last.Failed {
					quit()
				}
				return
			}
		}
	}()
	return true
}

func (a *App) closeSnapshot(keys []string, done bool) closeReport {
	a.mu.Lock()
	defer a.mu.Unlock()
	r := closeReport{Sessions: make(map[string]string, len(keys)), Done: done}
	for _, k := range keys {
		s := a.states[k]
		r.Sessions[k] = s.Status
		if s.Phase == "error" {
			r.Failed = true
		}
	}
	if done {
		a.closeReady = true
		a.closeUpdates = nil
	}
	return r
}
