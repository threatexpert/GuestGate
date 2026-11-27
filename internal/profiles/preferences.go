package profiles

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

type Preferences struct {
	Proxy, DNS, RESTPassword string
	AllowHostAccess          bool
	SkipExitConfirmation     bool
}

// Key by the full VMX path. Display names and VMX basenames can both repeat.
func preferencePath(vm string) (string, error) {
	if !filepath.IsAbs(vm) {
		return "", errors.New("虚拟机配置文件路径无效")
	}
	dir, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	key := sha256.Sum256([]byte(strings.ToLower(filepath.Clean(vm))))
	return filepath.Join(dir, "GuestGate", "profiles", fmt.Sprintf("%x.dat", key)), nil
}

func protectPreferences(data []byte, encrypt bool) ([]byte, error) {
	if len(data) == 0 {
		return nil, errors.New("虚拟机配置文件为空")
	}
	in := windows.DataBlob{Size: uint32(len(data)), Data: &data[0]}
	var out windows.DataBlob
	var err error
	if encrypt {
		err = windows.CryptProtectData(&in, nil, nil, 0, nil, windows.CRYPTPROTECT_UI_FORBIDDEN, &out)
	} else {
		err = windows.CryptUnprotectData(&in, nil, nil, 0, nil, windows.CRYPTPROTECT_UI_FORBIDDEN, &out)
	}
	if err != nil {
		return nil, err
	}
	defer windows.LocalFree(windows.Handle(uintptr(unsafe.Pointer(out.Data))))
	return bytes.Clone(unsafe.Slice(out.Data, out.Size)), nil
}

// A missing profile is distinct from a saved draft with an empty field.
func Load(vm string) (*Preferences, error) {
	path, err := preferencePath(vm)
	if err != nil {
		return nil, err
	}
	raw, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	cleartext, err := protectPreferences(raw, false)
	if err != nil {
		return nil, err
	}
	var p Preferences
	if err = json.Unmarshal(cleartext, &p); err != nil {
		return nil, err
	}
	return &p, nil
}

func Save(vm string, p Preferences) error {
	path, err := preferencePath(vm)
	if err != nil {
		return err
	}
	raw, err := json.Marshal(p)
	if err != nil {
		return err
	}
	raw, err = protectPreferences(raw, true)
	if err != nil {
		return err
	}
	dir := filepath.Dir(path)
	if err = os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	f, err := os.CreateTemp(dir, "profile-*.tmp")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	_, err = f.Write(raw)
	if err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	src, err := windows.UTF16PtrFromString(f.Name())
	if err != nil {
		return err
	}
	dst, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return err
	}
	return windows.MoveFileEx(src, dst, windows.MOVEFILE_REPLACE_EXISTING|windows.MOVEFILE_WRITE_THROUGH)
}
