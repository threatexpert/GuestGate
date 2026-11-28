package profiles

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPreferencesSurviveRestartAndDuplicateNames(t *testing.T) {
	t.Setenv("APPDATA", t.TempDir())
	first := filepath.Join(t.TempDir(), "Win10.vmx")
	second := filepath.Join(t.TempDir(), "Win10.vmx")
	if p, err := Load(first); err != nil || p != nil {
		t.Fatal("new profile", err)
	}
	a := Preferences{Proxy: "socks5://alice:secret@127.0.0.1:1080", DNS: "8.8.8.8", RESTPassword: "rest-secret", AllowHostAccess: true, SkipExitConfirmation: true, RecordingRoot: t.TempDir()}
	b := Preferences{Proxy: "localhost:1081", DNS: "1.1.1.1"}
	if err := Save(first, a); err != nil {
		t.Fatal(err)
	}
	if err := Save(second, b); err != nil {
		t.Fatal(err)
	}
	path, _ := preferencePath(first)
	raw, err := os.ReadFile(path)
	if err != nil || bytes.Contains(raw, []byte("secret")) || bytes.Contains(raw, []byte(a.DNS)) {
		t.Fatal("file missing or plaintext")
	}
	a.DNS = "9.9.9.9"
	if err = Save(first, a); err != nil {
		t.Fatal(err)
	}
	for vm, want := range map[string]Preferences{strings.ToUpper(first): a, second: b} {
		got, err := Load(vm)
		if err != nil || got == nil || *got != want {
			t.Fatal("incorrect restored VM profile", err)
		}
	}
	if err = os.WriteFile(path, []byte("corrupt"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err = Load(first); err == nil {
		t.Fatal("damaged profile treated as new")
	}
}
