package workstation

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

func machineRegistryString(path, name string, view uint32) string {
	key, err := registry.OpenKey(registry.LOCAL_MACHINE, path, registry.QUERY_VALUE|view)
	if err != nil {
		return ""
	}
	defer key.Close()
	value, kind, err := key.GetStringValue(name)
	if err != nil {
		return ""
	}
	if kind == registry.EXPAND_SZ {
		value, err = registry.ExpandString(value)
		if err != nil {
			return ""
		}
	}
	return strings.TrimSpace(value)
}

var authServiceImage = regexp.MustCompile(`(?i)^"?([^"]+\\vmware-authd\.exe)"?(?:\s|$)`)

func workstationDirs(read func(string, string, uint32) string) []string {
	var dirs []string
	for _, view := range []uint32{registry.WOW64_64KEY, registry.WOW64_32KEY} {
		dir := read(`SOFTWARE\VMware, Inc.\VMware Workstation`, "InstallPath", view)
		dirs = append(dirs, strings.Trim(dir, `"`))
	}
	image := read(`SYSTEM\CurrentControlSet\Services\VMAuthdService`, "ImagePath", 0)
	if match := authServiceImage.FindStringSubmatch(image); match != nil {
		dirs = append(dirs, filepath.Dir(match[1]))
	}
	for _, folder := range []*windows.KNOWNFOLDERID{windows.FOLDERID_ProgramFilesX86, windows.FOLDERID_ProgramFiles} {
		if dir, err := windows.KnownFolderPath(folder, 0); err == nil {
			dirs = append(dirs, filepath.Join(dir, "VMware", "VMware Workstation"))
		}
	}
	return dirs
}

func resolveVMRun(dirs []string) (string, error) {
	for _, dir := range dirs {
		if !filepath.IsAbs(dir) {
			continue
		}
		path := filepath.Join(dir, "vmrun.exe")
		if info, err := os.Stat(path); err == nil && info.Mode().IsRegular() {
			return path, nil
		}
	}
	return "", fmt.Errorf("找不到 vmrun.exe。请确认这台宿主机已安装 VMware Workstation，且安装目录中包含 vmrun.exe，然后刷新")
}

func VMRun() (string, error) { return resolveVMRun(workstationDirs(machineRegistryString)) }
