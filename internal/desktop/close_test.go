package desktop

import (
	"errors"
	"io"
	"testing"
	"time"

	"guestgate/internal/gateway"
)

func TestCloseWhileWorkerIsCleaning(t *testing.T) {
	for _, fail := range []bool{false, true} {
		reader, writer := io.Pipe()
		a := &App{pipe: writer, done: make(chan struct{}), states: map[string]gateway.VMState{
			"one": gateway.InitialState(), "two": gateway.InitialState(),
		}}
		events := make(chan closeReport, 8)
		quit := make(chan struct{})
		closeWindow := func() bool {
			return a.beginClose(func(r closeReport) { events <- r }, func() { close(quit) })
		}
		next := func() closeReport {
			t.Helper()
			select {
			case e := <-events:
				return e
			case <-time.After(2 * time.Second):
				t.Fatal("missing close event")
				return closeReport{}
			}
		}
		if !closeWindow() || !closeWindow() {
			t.Fatal("window closed before worker exit")
		}
		if e := next(); len(e.Sessions) != 2 || e.Done {
			t.Fatal(e)
		}
		if _, err := reader.Read(make([]byte, 1)); err != io.EOF {
			t.Fatal("worker did not receive EOF", err)
		}
		reader.Close()
		a.mu.Lock()
		s := a.states["one"]
		s.Phase, s.Status = "stopping", "正在撤销 DHCP"
		a.states["one"] = s
		a.closeUpdates <- struct{}{}
		a.mu.Unlock()
		if e := next(); e.Sessions["one"] != s.Status || e.Done {
			t.Fatal(e)
		}
		a.mu.Lock()
		var err error
		if fail {
			err = errors.New("DHCP restart failed")
		}
		a.states["one"] = s.Finished(err, false)
		a.states["two"] = a.states["two"].Finished(nil, true)
		a.pipe = nil
		close(a.done)
		a.mu.Unlock()
		if e := next(); !e.Done || e.Failed != fail {
			t.Fatal(e)
		}
		if fail {
			select {
			case <-quit:
				t.Fatal("dismissed cleanup error")
			default:
			}
		} else {
			select {
			case <-quit:
			case <-time.After(2 * time.Second):
				t.Fatal("did not exit after cleanup")
			}
		}
		if closeWindow() {
			t.Fatal("final close was intercepted")
		}
	}
}

func TestIdleCloseDoesNotWait(t *testing.T) {
	a := new(App)
	if a.beginClose(nil, nil) || a.beginClose(nil, nil) {
		t.Fatal("idle close intercepted")
	}
}
