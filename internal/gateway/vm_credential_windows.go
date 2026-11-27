package gateway

import (
	"bytes"
	"errors"
	"fmt"
	"path/filepath"
	"runtime"
	"unicode/utf8"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	credentialAPI = windows.NewLazySystemDLL("advapi32.dll")
	credRead      = credentialAPI.NewProc("CredReadW")
	credFree      = credentialAPI.NewProc("CredFree")
)

// Prefix of Windows CREDENTIALW through CredentialBlob.
type credentialData struct {
	flags, kind     uint32
	target, comment *uint16
	written         windows.Filetime
	size            uint32
	blob            *byte
}

func readCredential(target string) (string, error) {
	name, err := windows.UTF16PtrFromString(target)
	if err != nil {
		return "", err
	}
	var data *credentialData
	ok, _, err := credRead.Call(uintptr(unsafe.Pointer(name)), 1 /* CRED_TYPE_GENERIC */, 0, uintptr(unsafe.Pointer(&data)))
	if ok == 0 {
		return "", err
	}
	defer credFree.Call(uintptr(unsafe.Pointer(data)))
	// Workstation stores UTF-8 bytes, including for non-ASCII passwords.
	if data.size == 0 || data.size > 2560 || data.blob == nil {
		return "", errors.New("VMware 保存的凭据为空或格式无效")
	}
	raw := bytes.TrimRight(unsafe.Slice(data.blob, data.size), "\x00")
	if len(raw) == 0 || bytes.IndexByte(raw, 0) >= 0 || !utf8.Valid(raw) {
		return "", errors.New("无法识别 VMware 保存的密码格式")
	}
	return string(raw), nil
}

func (v VM) savedPassword(read func(string) (string, error)) (string, error) {
	targets := []string{"VMware Encrypted VM: " + filepath.Clean(v.Path)}
	if guid, err := windows.GUIDFromString(v.credentialGUID); err == nil && len(v.credentialGUID) == 38 {
		targets = append(targets, guid.String())
	}
	for _, target := range targets {
		password, err := read(target)
		if !errors.Is(err, windows.ERROR_NOT_FOUND) {
			return password, err
		}
	}
	return "", windows.ERROR_NOT_FOUND
}

// The elevated manager and the ordinary Workstation UI can have distinct
// logon sessions. Use the verified desktop user's vault for the second lookup.
func (v VM) desktopPassword() (string, error) {
	shell, err := ordinaryDesktopShell()
	if err != nil {
		return "", err
	}
	defer windows.CloseHandle(shell)
	var primary, token windows.Token
	if err = windows.OpenProcessToken(shell, windows.TOKEN_DUPLICATE, &primary); err != nil {
		return "", err
	}
	defer primary.Close()
	if err = windows.DuplicateTokenEx(primary, windows.TOKEN_IMPERSONATE, nil, windows.SecurityImpersonation, windows.TokenImpersonation, &token); err != nil {
		return "", err
	}
	defer token.Close()
	var password string
	done := make(chan struct{})
	go func() {
		defer close(done)
		runtime.LockOSThread()
		if err = windows.SetThreadToken(nil, token); err != nil {
			runtime.UnlockOSThread()
			return
		}
		password, err = v.savedPassword(readCredential)
		if revert := windows.RevertToSelf(); revert != nil {
			// Exiting this goroutine retires the still-locked OS thread.
			password, err = "", revert
			return
		}
		runtime.UnlockOSThread()
	}()
	<-done
	return password, err
}

func (v *VM) prepareControl() error {
	if !v.Encrypted {
		return v.selectControlContext()
	}
	pass, err := v.savedPassword(readCredential)
	if (errors.Is(err, windows.ERROR_NOT_FOUND) || errors.Is(err, windows.ERROR_NO_SUCH_LOGON_SESSION)) && windows.GetCurrentProcessToken().IsElevated() {
		pass, err = v.desktopPassword()
	}
	if err != nil {
		return fmt.Errorf("无法读取这台加密虚拟机的已保存密码。请用启动 VMware 的 Windows 账户打开虚拟机，在 VMware 的解锁提示中勾选“记住密码”后重试（%w）", err)
	}
	v.vmPassword = pass
	if err := v.selectControlContext(); err != nil {
		return fmt.Errorf("已找到虚拟机凭据，但 VMware 未能读取运行时网卡。请确认 VMware 记住的是当前加密密码：%w", err)
	}
	return nil
}
