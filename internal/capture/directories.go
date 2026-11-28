package capture

import (
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// Keep the original VM identity in recording metadata and when locating older recordings.
func recordingVMID(vm string) string {
	id := sha256.Sum256([]byte(strings.ToLower(filepath.Clean(vm))))
	return fmt.Sprintf("%x", id[:16])
}

func RecordingDirectory(vm, root string) (string, error) {
	if !filepath.IsAbs(vm) || !strings.EqualFold(filepath.Ext(vm), ".vmx") {
		return "", fmt.Errorf("需要完整的 VMX 文件路径")
	}
	stem := strings.TrimSuffix(filepath.Base(vm), filepath.Ext(vm))
	if root == "" {
		return filepath.Join(filepath.Dir(vm), stem+" 录制"), nil
	}
	name := []rune(stem)
	if len(name) > 88 {
		name = name[:88]
	}
	if !filepath.IsAbs(root) {
		return "", fmt.Errorf("录制位置需要使用绝对路径")
	}
	// A shared base can contain guests with identical VMX filenames.
	return filepath.Join(root, string(name)+" ["+recordingVMID(vm)[:12]+"]"), nil
}

func Recordings(vm, root string) (string, error) {
	dir, err := RecordingDirectory(vm, root)
	if err != nil {
		return "", err
	}
	if err := os.MkdirAll(dir, 0700); err != nil {
		return "", fmt.Errorf("无法创建录制目录 %s：%w。请在解密与录制设置中更改位置", dir, err)
	}
	return dir, nil
}

func LegacyRecordings(vm string) (string, error) {
	if !filepath.IsAbs(vm) {
		return "", fmt.Errorf("需要完整的 VMX 文件路径")
	}
	root, err := os.UserCacheDir()
	if err != nil {
		return "", err
	}
	dir := filepath.Join(root, "GuestGate", "analysis", recordingVMID(vm), "recordings")
	info, err := os.Stat(dir)
	if os.IsNotExist(err) {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	if !info.IsDir() {
		return "", nil
	}
	return dir, nil
}
