package profiles

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/windows"

	"guestgate/internal/usersecret"
)

type Preferences struct {
	Proxy, DNS, RESTPassword string
	AllowHostAccess          bool
	SkipExitConfirmation     bool
	RecordTraffic            bool
	RecordingRoot            string
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
	cleartext, err := usersecret.Protect(raw, false)
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
	raw, err = usersecret.Protect(raw, true)
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
