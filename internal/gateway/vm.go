package gateway

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/windows"
	"guestgate/internal/workstation"
)

type nicBinding struct{ network, mac string }

type VM struct {
	Encrypted                                        bool
	credentialGUID                                   string
	vmPassword                                       string
	GuestOSFamily                                    string
	IsOwnNetwork, RESTConfigured                     bool
	isolated                                         bool
	SharedReason                                     string
	dns, gatewayIP                                   netip.Addr
	scope                                            gatewayAddresses
	bindings                                         []nicBinding
	Path, Name, Network, CurrentNetwork, MAC, Reason string
	NeedsSwitch, NeedsRESTPassword                   bool
	subnet                                           netip.Prefix
	device                                           string
	vmrun                                            string
	controlShell                                     windows.Handle
}

func command(name string, args ...string) (string, error) {
	return commandWithParent(0, name, args...)
}

func (v VM) vmCommand(args ...string) (string, error) {
	if v.vmPassword != "" && len(args) >= 2 && args[1] == v.Path {
		args = append([]string{"-vp", v.vmPassword}, args...)
	}
	return commandWithParent(v.controlShell, v.vmrun, args...)
}

// Workstation can enumerate a user's VMs from an elevated process while only
// accepting runtime operations from the user's ordinary UAC session.
func (v *VM) selectControlContext() error {
	if !windows.GetCurrentProcessToken().IsElevated() && !v.Encrypted {
		return nil
	}
	args := []string{"readVariable", v.Path, "runtimeConfig", v.device + ".connectionType"}
	_, adminErr := v.vmCommand(args...)
	if adminErr == nil {
		return nil
	}
	if !windows.GetCurrentProcessToken().IsElevated() || !strings.Contains(strings.ToLower(adminErr.Error()), "not powered on") {
		if v.Encrypted {
			return adminErr
		}
		return nil
	}
	shell, err := ordinaryDesktopShell()
	if err != nil {
		return fmt.Errorf("管理员权限读取虚拟机失败：%w；无法取得同一账户的普通权限：%v", adminErr, err)
	}
	v.controlShell = shell
	if _, err := v.vmCommand(args...); err != nil {
		windows.CloseHandle(shell)
		v.controlShell = 0
		return fmt.Errorf("读取虚拟机运行时网卡失败。管理员权限：%w；普通权限：%v", adminErr, err)
	}
	return nil
}

// Starting a VMware tool with the ordinary desktop as parent inherits that
// desktop's token and logon session. Only use a non-elevated shell of this user.
func ordinaryDesktopShell() (windows.Handle, error) {
	var pid uint32
	if _, err := windows.GetWindowThreadProcessId(windows.GetShellWindow(), &pid); err != nil {
		return 0, err
	}
	shell, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION|windows.PROCESS_CREATE_PROCESS|windows.PROCESS_DUP_HANDLE, false, pid)
	if err != nil {
		return 0, err
	}
	if err := verifyOrdinaryShell(shell); err != nil {
		windows.CloseHandle(shell)
		return 0, err
	}
	return shell, nil
}

func verifyOrdinaryShell(shell windows.Handle) error {
	var token windows.Token
	if err := windows.OpenProcessToken(shell, windows.TOKEN_QUERY, &token); err != nil {
		return err
	}
	defer token.Close()
	current, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return err
	}
	desktop, err := token.GetTokenUser()
	if err != nil {
		return err
	}
	if !current.User.Sid.Equals(desktop.User.Sid) || token.IsElevated() {
		return errors.New("请用启动 VMware 的同一账户运行 GuestGate，并确保桌面以普通权限运行")
	}
	return nil
}

func commandWithParent(parent windows.Handle, name string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()
	c := exec.CommandContext(ctx, name, args...)
	c.SysProcAttr = vmProcessAttrs(parent)
	b, e := c.CombinedOutput()
	if e != nil {
		detail := strings.TrimSpace(string(b))
		if len(args) > 1 && args[0] == "-vp" {
			detail = strings.ReplaceAll(detail, args[1], "[已隐藏]")
		}
		return "", fmt.Errorf("%s: %w %s", filepath.Base(name), e, detail)
	}
	return strings.TrimSpace(string(b)), nil
}

func vmProcessAttrs(parent windows.Handle) *syscall.SysProcAttr {
	attrs := &syscall.SysProcAttr{HideWindow: true, ParentProcess: syscall.Handle(parent)}
	if parent != 0 {
		attrs.CreationFlags = windows.CREATE_NO_WINDOW
	}
	return attrs
}
func powershell(script string) (string, error) {
	return command(filepath.Join(os.Getenv("SystemRoot"), "System32", "WindowsPowerShell", "v1.0", "powershell.exe"), "-NoProfile", "-NonInteractive", "-Command", "$ErrorActionPreference='Stop';"+script)
}

// Reconnect only the selected NIC so an already running DHCP client can renew.
func renewLink(v VM) error {
	if _, err := v.vmCommand("disconnectNamedDevice", v.Path, v.device); err != nil {
		return err
	}
	time.Sleep(time.Second)
	var err error
	for attempt := 0; attempt < 3; attempt++ {
		if _, err = v.vmCommand("connectNamedDevice", v.Path, v.device); err == nil {
			return nil
		}
		time.Sleep(time.Second)
	}
	return err
}

func Machines() ([]VM, error) {
	vmrun, e := workstation.VMRun()
	if e != nil {
		return nil, e
	}
	nets, e := command(vmrun, "listHostNetworks")
	if e != nil {
		return nil, e
	}
	eligible := map[string]netip.Prefix{}
	for _, s := range strings.Split(nets, "\n") {
		f := strings.Fields(s)
		if len(f) != 6 || !strings.EqualFold(f[2], "hostOnly") || f[3] != "true" {
			continue
		}
		if prefix, ok := vmnetPrefix(f[4], f[5]); ok {
			eligible[strings.ToLower(f[1])] = prefix
		}
	}
	listing, e := command(vmrun, "list")
	if e != nil {
		return nil, e
	}
	restConfigured := needsRESTPassword()
	out := []VM{}
	for _, path := range strings.Split(listing, "\n") {
		path = strings.TrimSpace(path)
		if !strings.HasSuffix(strings.ToLower(path), ".vmx") {
			continue
		}
		v, err := readVM(path, eligible)
		if err != nil {
			return nil, err
		}
		v.vmrun = vmrun
		v.RESTConfigured = restConfigured
		v.IsOwnNetwork = isOwnVMnet(v)
		out = append(out, v)
	}
	owners := make(map[nicBinding]int)
	for _, v := range out {
		for _, nic := range v.bindings {
			owners[nic]++
		}
	}
	for i, v := range out {
		key := nicBinding{v.Network, strings.ToLower(v.MAC)}
		other := owners[key]
		if !v.NeedsSwitch {
			other--
		}
		if v.Reason == "" && other > 0 {
			out[i].SharedReason = "目标共享仅主机网络上已有相同 MAC 的虚拟网卡"
		}
	}
	return out, nil
}

func readVM(path string, eligible map[string]netip.Prefix) (VM, error) {
	v := VM{Path: path, Name: filepath.Base(path)}
	b, err := os.ReadFile(path)
	if err != nil {
		return v, err
	}
	fields := map[string]string{}
	for line := range strings.SplitSeq(string(b), "\n") {
		k, val, ok := strings.Cut(line, "=")
		if ok {
			fields[strings.ToLower(strings.TrimSpace(k))] = strings.Trim(strings.TrimSpace(val), "\"")
		}
	}
	v.credentialGUID = fields["encryptedvm.guid"]
	switch strings.ToLower(fields["vmx.encryptiontype"]) {
	case "partial", "full":
		v.Encrypted = true
	default:
		v.Encrypted = fields["encryption.keysafe"] != "" || fields["encryption.encryptedkey"] != "" || fields["encryption.data"] != "" || v.credentialGUID != ""
	}
	if name := fields["displayname"]; name != "" {
		v.Name = name
	}
	v.GuestOSFamily = guestOSFamily(fields["guestos"])
	count := 0
	for k, val := range fields {
		if !nicPresent.MatchString(k) || !strings.EqualFold(val, "true") {
			continue
		}
		count++
		p := strings.TrimSuffix(k, "present")
		v.device = strings.TrimSuffix(p, ".")
		v.CurrentNetwork = strings.ToLower(fields[p+"vnet"])
		switch strings.ToLower(fields[p+"connectiontype"]) {
		case "hostonly":
			v.CurrentNetwork = "vmnet1"
		case "custom":
		case "nat":
			v.CurrentNetwork = "NAT"
		case "bridged", "":
			v.CurrentNetwork = "桥接"
		default:
			v.Reason = "不支持的网卡连接类型：" + fields[p+"connectiontype"]
		}
		v.MAC = fields[p+"generatedaddress"]
		if strings.EqualFold(fields[p+"addresstype"], "static") {
			v.MAC = fields[p+"address"]
		}
		v.bindings = append(v.bindings, nicBinding{v.CurrentNetwork, strings.ToLower(v.MAC)})
	}
	v.Network = v.CurrentNetwork
	if !eligible[v.Network].IsValid() {
		v.Network = "vmnet1"
		v.NeedsSwitch = true
	}
	v.subnet = eligible[v.Network]
	switch {
	case count == 0 && v.Encrypted:
		v.Reason = "加密虚拟机的配置中未找到可核实的网络适配器，无法确认隔离条件"
	case count != 1:
		v.Reason = adapterCountError(count).Error()

	default:
		if m, err := net.ParseMAC(v.MAC); err != nil || len(m) != 6 {
			v.Reason = "无法读取虚拟网卡 MAC"
		}
	}
	if !v.subnet.IsValid() {
		v.SharedReason = "默认 VMnet1 不可用，需要启用 DHCP 的 IPv4 仅主机网络（Host-only）"
	}
	if v.NeedsSwitch {
		v.NeedsRESTPassword = needsRESTPassword()
	}
	return v, nil
}

var nicPresent = regexp.MustCompile(`^ethernet[0-9]+\.present$`)

func adapterCountError(count int) error {
	return fmt.Errorf("检测到 %d 个网络适配器。请在 VMware 设置中将网络适配器数量调整为 1，再刷新列表", count)
}

func (v VM) checkAdapter(current VM) error {
	if current.Reason != "" {
		return errors.New(current.Reason)
	}
	if current.device != v.device || !strings.EqualFold(current.MAC, v.MAC) || !strings.EqualFold(current.CurrentNetwork, v.Network) {
		return fmt.Errorf("网络适配器或连接的网络已变化，请刷新列表")
	}
	return nil
}

func (v VM) verifyConfiguredAdapter() error {
	current, err := readVM(v.Path, map[string]netip.Prefix{v.Network: v.subnet})
	if err != nil {
		return err
	}
	return v.checkAdapter(current)
}

func guestOSFamily(configured string) string {
	id := strings.ToLower(strings.TrimSpace(configured))
	if strings.HasPrefix(id, "win") || strings.HasPrefix(id, "longhorn") {
		return "windows"
	}
	if strings.Contains(id, "linux") {
		return "linux"
	}
	for _, prefix := range []string{"ubuntu", "debian", "fedora", "redhat", "rhel", "centos", "suse", "opensuse", "sles", "asianux", "photon", "mandrake", "mandriva", "coreos", "flatcar", "alpine", "vmware-photon"} {
		if strings.HasPrefix(id, prefix) {
			return "linux"
		}
	}
	return "other"
}

func captureDevice(v VM) (string, error) {
	// Resolve the VMware adapter by its driver description, including renamed interfaces.
	number := strings.TrimPrefix(v.Network, "vmnet")
	if ok, _ := regexp.MatchString(`^[0-9]+$`, number); !ok {
		return "", fmt.Errorf("VMnet 无效")
	}
	script := fmt.Sprintf(`$a=@(Get-NetAdapter | Where-Object { $_.InterfaceDescription -match 'VMnet%s$' });if($a.Count -ne 1){throw 'VMnet host adapter unavailable'}; $f=Get-NetIPInterface -InterfaceIndex $a[0].ifIndex;if(@($f|Where-Object Forwarding -eq Enabled).Count){throw 'Host forwarding must be disabled on this VMnet'}; $a[0].InterfaceGuid|ConvertTo-Json -Compress`, number)
	s, e := powershell(script)
	if e != nil {
		return "", e
	}
	var guid string
	if e = json.Unmarshal([]byte(s), &guid); e != nil {
		return "", e
	}
	return `\Device\NPF_{` + strings.Trim(guid, "{}") + "}", nil
}
