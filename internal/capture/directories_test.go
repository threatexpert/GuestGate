package capture

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRecordingLocations(t *testing.T) {
	base := t.TempDir()
	vm := filepath.Join(base, "一号", "实验.vmx")
	peer := filepath.Join(base, "二号", "实验.vmx")
	dir, err := RecordingDirectory(vm, "")
	if err != nil || dir != filepath.Join(base, "一号", "实验 录制") {
		t.Fatal(dir, err)
	}
	if _, err = os.Stat(dir); !os.IsNotExist(err) {
		t.Fatal("preview created the directory", err)
	}
	chosen := filepath.Join(base, "录制")
	custom, err := Recordings(vm, chosen)
	if err != nil || filepath.Dir(custom) != chosen || !strings.HasPrefix(filepath.Base(custom), "实验 [") {
		t.Fatal(custom, err)
	}
	other, err := Recordings(peer, chosen)
	if err != nil || strings.EqualFold(custom, other) {
		t.Fatal(other, err)
	}
	if _, err = Recordings(vm, "relative"); err == nil {
		t.Fatal("accepted relative root")
	}
	t.Setenv("LocalAppData", base)
	old := filepath.Join(base, "GuestGate", "analysis", recordingVMID(vm), "recordings")
	if found, err := LegacyRecordings(vm); err != nil || found != "" {
		t.Fatal(found, err)
	}
	if err = os.MkdirAll(old, 0700); err != nil {
		t.Fatal(err)
	}
	if found, err := LegacyRecordings(vm); err != nil || found != old {
		t.Fatal(found, err)
	}
}
