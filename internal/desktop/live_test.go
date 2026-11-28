package desktop

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"

	"guestgate/internal/gateway"
)

func TestSessionRecordingDirectoryAfterStop(t *testing.T) {
	root := t.TempDir()
	latest := filepath.Join(root, "recording-2")
	if err := os.Mkdir(latest, 0700); err != nil {
		t.Fatal(err)
	}
	native := `\\?\` + latest
	a := &App{states: map[string]gateway.VMState{"win": {SessionID: "session", RecordingDirectory: native, Phase: "stopped"}}}
	got, err := a.sessionRecordingDirectory("WIN", "session", native)
	if err != nil || got != latest {
		t.Fatalf("open recording folder: got %q, %v", got, err)
	}
	for _, click := range [][2]string{{"previous", native}, {"session", root}, {"session", filepath.Join(root, "recording-1")}} {
		if _, err := a.sessionRecordingDirectory("WIN", click[0], click[1]); err == nil {
			t.Fatal("accepted stale recording link", click)
		}
	}
	if err := os.Remove(latest); err != nil {
		t.Fatal(err)
	}
	if _, err := a.sessionRecordingDirectory("WIN", "session", native); err == nil {
		t.Fatal("missing recording folder should return an error")
	}
}

func TestLiveSwitchConfirmationAndSessionIdentity(t *testing.T) {
	for _, test := range []struct {
		name                           string
		verify, approve, fail, replace bool
		wantCommand                    bool
	}{
		{"approved", true, true, false, false, true}, {"cancelled", true, false, false, false, false},
		{"lookup failed", true, false, true, false, false}, {"skipped", false, false, false, false, true},
		{"session replaced", true, true, false, true, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			r, w := io.Pipe()
			defer r.Close()
			defer w.Close()
			state := gateway.VMState{Running: true, Phase: "ready", SessionID: "original"}
			shown := make(chan struct{}, 3)
			a := &App{states: map[string]gateway.VMState{"guest": state}, pipe: w, done: make(chan struct{}), exitChanged: func() { shown <- struct{}{} }}
			const raw = "http://name:secret@localhost:1080"
			checked := false
			a.lookup = func(_ context.Context, candidate string) (exitInfo, error) {
				checked = true
				if candidate != raw {
					t.Error("wrong candidate for exit lookup")
				}
				if test.fail {
					return exitInfo{}, errors.New("offline")
				}
				return exitInfo{"192.0.2.42", "test", "fixture"}, nil
			}
			commands := make(chan gateway.WorkerCommand, 1)
			go func() {
				var cmd gateway.WorkerCommand
				if json.NewDecoder(r).Decode(&cmd) != nil {
					return
				}
				commands <- cmd
				a.mu.Lock()
				reply := a.replies[cmd.RequestID]
				a.mu.Unlock()
				reply <- gateway.ControlResult{}
			}()
			done := make(chan bool, 1)
			go func() { ok, err := a.SwitchUpstream("guest", "original", raw, test.verify); done <- ok && err == nil }()
			if test.verify && !test.fail {
				select {
				case <-shown:
				case <-time.After(time.Second):
					t.Fatal("no confirmation")
				}
				select {
				case <-commands:
					t.Fatal("old route changed before confirmation")
				default:
				}
				prompt := a.PendingExitConfirmation()
				if !prompt.Switching || prompt.Server != "http://localhost:1080" {
					t.Fatal("incorrect confirmation or leaked credentials")
				}
				if test.replace {
					a.mu.Lock()
					state.SessionID = "next"
					a.states["guest"] = state
					a.mu.Unlock()
				}
				a.AnswerExitConfirmation(prompt.ID, test.approve)
			}
			select {
			case ok := <-done:
				if ok != test.wantCommand {
					t.Errorf("result %v", ok)
				}
			case <-time.After(time.Second):
				t.Fatal("switch stuck")
			}
			if checked != test.verify {
				t.Fatal("unexpected exit lookup")
			}
			select {
			case cmd := <-commands:
				if !test.wantCommand || cmd.Action != "switch" || cmd.Proxy != raw || cmd.SessionID != "original" {
					t.Fatal("incorrect command")
				}
			default:
				if test.wantCommand {
					t.Fatal("missing switch")
				}
			}
		})
	}
}
