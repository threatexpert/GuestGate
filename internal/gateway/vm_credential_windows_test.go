package gateway

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"unsafe"

	"golang.org/x/sys/windows"
)

const fixturePassword = "测试 +/% & \" 加密"

func TestEncryptedVMControl(t *testing.T) {
	for _, legacy := range []bool{false, true} {
		t.Run(fmt.Sprintf("legacy=%t", legacy), func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "encrypted.vmx")
			guid, err := windows.GenerateGUID()
			if err != nil {
				t.Fatal(err)
			}
			vmx := fmt.Sprintf("vmx.encryptionType = \"partial\"\nencryptedVM.guid = %q\nencryption.data = %q\nethernet0.present = \"TRUE\"\nethernet0.generatedAddress = \"00:0c:29:01:02:03\"\n", guid.String(), strings.Repeat("x", 70000))
			if err := os.WriteFile(path, []byte(vmx), 0600); err != nil {
				t.Fatal(err)
			}
			v, err := readVM(path, nil)
			if err != nil || !v.Encrypted || v.Reason != "" {
				t.Fatalf("VMX detection: %v, reason %q", err, v.Reason)
			}
			target := "VMware Encrypted VM: " + path
			if legacy {
				target = guid.String()
			}
			saveTestCredential(t, target, fixturePassword)
			v.vmrun, err = os.Executable()
			if err != nil {
				t.Fatal(err)
			}
			if err := v.prepareControl(); err != nil {
				t.Fatal(err)
			}
			if v.controlShell != 0 {
				defer windows.CloseHandle(v.controlShell)
			}
			if got, err := v.vmCommand("readVariable", path, "runtimeConfig", "ethernet0.connectionType"); got != "custom" || err != nil {
				t.Fatal("authenticated runtime read failed")
			}
			if b, err := json.Marshal(v); err != nil || strings.Contains(string(b), "测试") || strings.Contains(string(b), guid.String()) {
				t.Fatal("private VM credential metadata in frontend payload")
			}
			v.vmPassword = "stale-password"
			if err := v.selectControlContext(); err == nil || strings.Contains(err.Error(), v.vmPassword) {
				t.Fatal("stale VM credential did not produce a safe error")
			}
		})
	}
}

func TestMissingVMCredential(t *testing.T) {
	v := VM{Path: filepath.Join(t.TempDir(), "chosen.vmx"), Encrypted: true, credentialGUID: "unrelated credential"}
	calls := 0
	_, err := v.savedPassword(func(target string) (string, error) {
		calls++
		if target != "VMware Encrypted VM: "+v.Path {
			t.Fatalf("unexpected credential lookup %q", target)
		}
		return "", windows.ERROR_NOT_FOUND
	})
	if calls != 1 || !errors.Is(err, windows.ERROR_NOT_FOUND) {
		t.Fatalf("lookups %d, error %v", calls, err)
	}
	if err := v.prepareControl(); err == nil || !strings.Contains(err.Error(), "记住密码") {
		t.Fatal("missing saved password should stop setup with recovery instructions")
	}
}

func saveTestCredential(t *testing.T, target, password string) {
	t.Helper()
	// Each test owns a random, session-only target and removes just that entry.
	name, err := windows.UTF16PtrFromString(target)
	if err != nil {
		t.Fatal(err)
	}
	raw := []byte(password)
	entry := struct {
		credentialData
		persist, attributeCount uint32
		attributes, alias, user uintptr
	}{credentialData: credentialData{kind: 1, target: name, size: uint32(len(raw)), blob: &raw[0]}, persist: 1}
	ok, _, err := credentialAPI.NewProc("CredWriteW").Call(uintptr(unsafe.Pointer(&entry)), 0)
	if ok == 0 {
		if errors.Is(err, windows.ERROR_NO_SUCH_LOGON_SESSION) {
			t.Skip("Windows credential vault unavailable in this logon session")
		}
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if ok, _, err := credentialAPI.NewProc("CredDeleteW").Call(uintptr(unsafe.Pointer(name)), 1, 0); ok == 0 {
			t.Error(err)
		}
	})
}

func TestEncryptedNICSwitch(t *testing.T) {
	v := VM{Path: "chosen.vmx", Network: "vmnet2", MAC: "00:0c:29:01:02:03", isolated: true, vmPassword: fixturePassword}
	reads, puts := 0, 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		user, pass, _ := req.BasicAuth()
		if user != "rest-user" || pass != "rest-password" {
			t.Error("REST account changed")
		}
		if req.URL.Path == "/api/vms" {
			if req.URL.RawQuery != "" {
				t.Error("VM credential sent to inventory")
			}
			fmt.Fprint(w, `[{"id":"chosen","path":"chosen.vmx"}]`)
			return
		}
		if req.URL.Query().Get("vmPassword") != base64.StdEncoding.EncodeToString([]byte(fixturePassword)) {
			t.Error("missing VM-specific credential on NIC request")
		}
		switch {
		case req.Method == "GET" && req.URL.Path == "/api/vms/chosen/nic":
			reads++
			kind, network := "nat", "vmnet8"
			if puts == 1 {
				kind, network = "custom", "vmnet2"
			}
			fmt.Fprintf(w, `{"nics":[{"index":0,"type":%q,"vmnet":%q,"macAddress":%q}]}`, kind, network, v.MAC)
		case req.Method == "PUT" && req.URL.Path == "/api/vms/chosen/nic/0":
			puts++
		default:
			t.Error("unexpected NIC request")
		}
	}))
	defer server.Close()
	r := vmREST{&http.Client{Transport: routeToTestServer{server}}, "rest-user", "rest-password"}
	if err := r.switchNIC(context.Background(), v); err != nil || reads != 2 || puts != 1 {
		t.Fatalf("switch: %v, reads=%d, updates=%d", err, reads, puts)
	}
}
