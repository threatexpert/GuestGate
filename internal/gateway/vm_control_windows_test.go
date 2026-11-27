package gateway

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/windows"
)

// Model a VM that is visible in both contexts, but whose running NIC is
// accessible only at the same elevation as the process hosting the guest.
func TestMain(m *testing.M) {
	if len(os.Args) > 1 && os.Args[1] == "-vp" {
		if len(os.Args) == 7 && os.Args[2] == fixturePassword && os.Args[3] == "readVariable" && filepath.Base(os.Args[4]) == "encrypted.vmx" {
			fmt.Println("custom")
			return
		}
		fmt.Fprintln(os.Stderr, "invalid VM password", os.Args[2])
		os.Exit(1)
	}
	if len(os.Args) == 5 && os.Args[1] == "readVariable" && os.Args[3] == "runtimeConfig" {
		if os.Args[2] == "ordinary.vmx" && windows.GetCurrentProcessToken().IsElevated() {
			fmt.Fprintln(os.Stderr, "The virtual machine is not powered on")
			os.Exit(1)
		}
		fmt.Println("custom")
		return
	}
	os.Exit(m.Run())
}

func TestVMControlContext(t *testing.T) {
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{"ordinary.vmx", "accessible.vmx"} {
		v := VM{Path: path, vmrun: exe, device: "ethernet0"}
		if err := v.selectControlContext(); err != nil {
			t.Fatal(err)
		}
		if v.controlShell != 0 {
			defer windows.CloseHandle(v.controlShell)
		}
		wantFallback := path == "ordinary.vmx" && windows.GetCurrentProcessToken().IsElevated()
		if (v.controlShell != 0) != wantFallback {
			t.Fatalf("%s: expected ordinary-user fallback=%v", path, wantFallback)
		}
		kind, err := v.vmCommand("readVariable", path, "runtimeConfig", "ethernet0.connectionType")
		if err != nil || kind != "custom" {
			t.Fatalf("%s: got %q, %v", path, kind, err)
		}
	}
}
