package desktop

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/wailsapp/wails/v2/pkg/runtime"
	"guestgate/internal/capture"
)

func (*App) HostCANeedsUpgrade() (bool, error) { return capture.HostCANeedsUpgrade() }
func (*App) ExportHostCA(approveUpgrade bool) (string, error) {
	path, err := capture.ExportCA(approveUpgrade)
	if err != nil {
		return "", err
	}
	return path, openFolder(filepath.Dir(path))
}

type RecordingLocations struct {
	Directory string
	Legacy    string
}

func (*App) RecordingLocations(vm, root string) (RecordingLocations, error) {
	dir, err := capture.RecordingDirectory(vm, root)
	if err != nil {
		return RecordingLocations{}, err
	}
	legacy, err := capture.LegacyRecordings(vm)
	return RecordingLocations{dir, legacy}, err
}

func (a *App) ChooseRecordingRoot(vm, current string) (string, error) {
	a.mu.Lock()
	ctx := a.windowCtx
	a.mu.Unlock()
	if ctx == nil {
		return "", fmt.Errorf("窗口尚未就绪")
	}
	dir, err := capture.RecordingDirectory(vm, current)
	if err != nil {
		return "", err
	}
	start := filepath.Dir(dir)
	if info, err := os.Stat(start); err != nil || !info.IsDir() {
		start = ""
	}
	return runtime.OpenDirectoryDialog(ctx, runtime.OpenDialogOptions{Title: "选择录制存储位置", DefaultDirectory: start, CanCreateDirectories: true})
}

func (*App) OpenRecordings(vm, root string) error {
	dir, err := capture.Recordings(vm, root)
	if err != nil {
		return err
	}
	return openFolder(dir)
}

func (a *App) OpenSessionRecording(vm, session, directory string) error {
	path, err := a.sessionRecordingDirectory(vm, session, directory)
	if err != nil {
		return err
	}
	return openFolder(path)
}

func (a *App) sessionRecordingDirectory(vm, session, directory string) (string, error) {
	a.mu.Lock()
	state := a.states[strings.ToLower(vm)]
	a.mu.Unlock()
	if directory == "" || state.SessionID != session || state.RecordingDirectory != directory {
		return "", fmt.Errorf("录制会话已变更，请重新点击打开目录")
	}
	info, err := os.Stat(directory)
	if err != nil {
		return "", fmt.Errorf("无法打开本次录制目录：%w", err)
	}
	if !info.IsDir() {
		return "", fmt.Errorf("本次录制的位置不是文件夹")
	}
	// The native recorder returns extended-length paths. Explorer expects
	// ordinary drive or UNC paths when navigating to a folder.
	const extended = `\\?\`
	if path, ok := strings.CutPrefix(directory, extended); ok {
		switch {
		case strings.HasPrefix(strings.ToUpper(path), `UNC\`):
			return `\\` + path[4:], nil
		case len(path) >= 3 && path[1:3] == `:\`:
			return path, nil
		}
	}
	return directory, nil
}

func (*App) OpenLegacyRecordings(vm string) error {
	dir, err := capture.LegacyRecordings(vm)
	if err != nil {
		return err
	}
	if dir == "" {
		return fmt.Errorf("旧版录制目录已不存在")
	}
	return openFolder(dir)
}
func openFolder(path string) error {
	cmd := exec.Command(filepath.Join(os.Getenv("SystemRoot"), "explorer.exe"), path)
	if err := cmd.Start(); err != nil {
		return err
	}
	return cmd.Process.Release()
}
