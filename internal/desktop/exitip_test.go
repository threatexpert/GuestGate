package desktop

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"guestgate/internal/profiles"
)

type commandBuffer struct{ bytes.Buffer }

func (*commandBuffer) Close() error { return nil }

func TestExitConfirmationGatesStart(t *testing.T) {
	t.Setenv("APPDATA", t.TempDir())
	for _, tc := range []struct {
		name                                  string
		skip, approve, lookupFails, wantStart bool
	}{
		{"approved", false, true, false, true}, {"cancelled", false, false, false, false}, {"offline", false, true, true, false}, {"disabled", true, false, true, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			vm := filepath.Join(t.TempDir(), "guest.vmx")
			if tc.skip {
				if err := profiles.Save(vm, profiles.Preferences{SkipExitConfirmation: true}); err != nil {
					t.Fatal(err)
				}
			}
			pipe := new(commandBuffer)
			a := &App{pipe: pipe}
			checked, asked := false, false
			a.lookup = func(context.Context, string) (exitInfo, error) {
				checked = true
				if tc.lookupFails {
					return exitInfo{}, errors.New("lookup failed")
				}
				return exitInfo{"8.8.8.8", "test region", "test provider"}, nil
			}
			a.exitChanged = func() {
				info := a.PendingExitConfirmation()
				if info == nil {
					return
				}
				asked = true
				if pipe.Len() != 0 || len(a.States()) != 0 || info.VM != vm || info.Server != "127.0.0.1:1080" || info.Location != "test region" {
					t.Fatal("premature start or incorrect prompt")
				}
				a.AnswerExitConfirmation(info.ID, tc.approve)
			}
			err := a.Start(vm, "socks5://user:secret@127.0.0.1:1080")
			if (err != nil) != (!tc.skip && tc.lookupFails) || (pipe.Len() != 0) != tc.wantStart || checked != !tc.skip || asked != (!tc.skip && !tc.lookupFails) || a.States()[strings.ToLower(vm)].Running != tc.wantStart {
				t.Fatalf("start=%v checked=%v asked=%v err=%v", pipe.Len() != 0, checked, asked, err)
			}
		})
	}
}

func TestExitIPAndLocationRequired(t *testing.T) {
	for _, tc := range []struct{ body, location string }{
		{`{"success":true,"ip":"8.8.8.8","country":"美国","region":"加州","city":"山景城"}`, "美国 · 加州 · 山景城"},
		{`{"ip":"8.8.4.4","country":"Japan","cc":"JP"}`, "Japan"},
		{`{"ip":"8.8.4.4","country":"United States","region_name":"Virginia","city":"Boydton"}`, "United States · Virginia · Boydton"},
		{`{"ip":"8.8.4.4","country":"MY","region":"Kuala Lumpur","city":"Kuala Lumpur"}`, "MY · Kuala Lumpur"},
		{`{"ip":"192.168.1.1","country":"美国"}`, ""},
		{`{"ip":"8.8.8.8","country":"Unknown","cc":"XX"}`, ""},
		{`{"success":false,"ip":"8.8.8.8","country":"US"}`, ""},
	} {
		s := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, tc.body) }))
		info, err := readExit(t.Context(), s.Client(), s.URL)
		s.Close()
		if (err != nil) != (tc.location == "") || info.Location != tc.location {
			t.Fatalf("%s: %+v %v", tc.body, info, err)
		}
	}
}

func TestClosingWindowCancelsPendingExitConfirmation(t *testing.T) {
	t.Setenv("APPDATA", t.TempDir())
	shown := make(chan struct{}, 2)
	a := &App{exitChanged: func() { shown <- struct{}{} }, lookup: func(context.Context, string) (exitInfo, error) { return exitInfo{"8.8.8.8", "test", "test"}, nil }}
	done := make(chan error, 1)
	go func() { done <- a.Start(filepath.Join(t.TempDir(), "guest.vmx"), "localhost:1080") }()
	select {
	case <-shown:
	case <-time.After(time.Second * 4):
		t.Fatal("no prompt")
	}
	id := a.PendingExitConfirmation().ID
	a.AnswerExitConfirmation("stale-id", true)
	if a.beginClose(nil, nil) {
		t.Fatal("expected no worker to stop")
	}
	a.AnswerExitConfirmation(id, true)
	select {
	case err := <-done:
		if err == nil || len(a.States()) != 0 || a.PendingExitConfirmation() != nil {
			t.Fatal("pending start survived close")
		}
	case <-time.After(time.Second * 4):
		t.Fatal("pending confirmation did not finish")
	}
}

func TestFirstValidExitCancelsSlowerLookup(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
	defer cancel()
	started, stopped, invalid := make(chan struct{}), make(chan struct{}), make(chan struct{})
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/slow":
			close(started)
			<-r.Context().Done()
			close(stopped)
		case "/invalid":
			io.WriteString(w, `{"ip":"127.0.0.1","country":"Unknown"}`)
			close(invalid)
		case "/valid":
			for _, signal := range []chan struct{}{started, invalid} {
				select {
				case <-signal:
				case <-r.Context().Done():
					return
				}
			}
			io.WriteString(w, `{"ip":"8.8.4.4","country":"Japan"}`)
		}
	}))
	defer s.Close()
	info, err := firstExit(ctx, s.Client(), []string{s.URL + "/slow", s.URL + "/invalid", s.URL + "/valid"})
	if err != nil || info.IP != "8.8.4.4" {
		t.Fatalf("result %+v, %v", info, err)
	}
	select {
	case <-stopped:
	case <-ctx.Done():
		t.Fatal("slow request not canceled")
	}
}

func TestAllExitLookupsUseSOCKS(t *testing.T) {
	l, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	targets := make(chan string, 4)
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			func() {
				defer c.Close()
				var h [5]byte
				if _, err = io.ReadFull(c, h[:2]); err != nil || h[0] != 5 {
					return
				}
				io.CopyN(io.Discard, c, int64(h[1]))
				c.Write([]byte{5, 0})
				if _, err = io.ReadFull(c, h[:]); err != nil || h[3] != 3 {
					return
				}
				dest := make([]byte, h[4])
				if _, err = io.ReadFull(c, dest); err != nil {
					return
				}
				targets <- string(dest)
				c.Write([]byte{5, 5, 0, 1, 0, 0, 0, 0, 0, 0})
			}()
		}
	}()
	_, err = lookupExit(t.Context(), "socks5://test:secret@"+l.Addr().String())
	if err == nil || strings.Contains(err.Error(), "secret") {
		t.Fatal("expected redacted lookup failure")
	}
	close(targets)
	counts := map[string]int{}
	for target := range targets {
		counts[target]++
	}
	for _, want := range []string{"ipwho.is", "api.myip.com", "ifconfig.co", "ipinfo.io"} {
		if counts[want] != 1 {
			t.Fatalf("expected one SOCKS request for %s, got %v", want, counts)
		}
	}
}
