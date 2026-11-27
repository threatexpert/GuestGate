package workstation

import (
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/windows/registry"
)

func TestNonDefaultWorkstationInstall(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "虚拟机工具 Workstation")
	if err := os.Mkdir(dir, 0700); err != nil {
		t.Fatal(err)
	}
	want := filepath.Join(dir, "vmrun.exe")
	if err := os.WriteFile(want, nil, 0600); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name string
		view uint32
	}{
		{"64-bit registry", registry.WOW64_64KEY},
		{"32-bit registry", registry.WOW64_32KEY},
		{"registered service", 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dirs := workstationDirs(func(path, name string, view uint32) string {
				switch {
				case name == "InstallPath" && view == tc.view:
					return dir + `\`
				case name == "ImagePath" && tc.view == 0:
					return `"` + filepath.Join(dir, "vmware-authd.exe") + `" -s`
				default:
					return filepath.Join(dir, "obsolete")
				}
			})
			got, err := resolveVMRun(dirs)
			if err != nil || got != want {
				t.Fatalf("got %q, %v; want %q", got, err, want)
			}
		})
	}
	if _, err := resolveVMRun([]string{"", ".", filepath.Join(dir, "missing")}); err == nil {
		t.Fatal("missing installation accepted")
	}
}
