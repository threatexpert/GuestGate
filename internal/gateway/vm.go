package gateway

import (
	"bufio"
	"context"
	"encoding/json"
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

	"guestgate/internal/workstation"
)

type nicBinding struct{ network, mac string }

type VM struct {
	dns, gatewayIP                                   netip.Addr
	scope                                            gatewayAddresses
	bindings                                         []nicBinding
	Path, Name, Network, CurrentNetwork, MAC, Reason string
	NeedsSwitch, NeedsRESTPassword                   bool
	subnet                                           netip.Prefix
	device                                           string
	vmrun                                            string
}

func command(name string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()
	c := exec.CommandContext(ctx, name, args...)
	c.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	b, e := c.CombinedOutput()
	if e != nil {
		return "", fmt.Errorf("%s: %w %s", filepath.Base(name), e, strings.TrimSpace(string(b)))
	}
	return strings.TrimSpace(string(b)), nil
}
func powershell(script string) (string, error) {
	return command(filepath.Join(os.Getenv("SystemRoot"), "System32", "WindowsPowerShell", "v1.0", "powershell.exe"), "-NoProfile", "-NonInteractive", "-Command", "$ErrorActionPreference='Stop';"+script)
}

// Reconnect only the selected NIC so an already running DHCP client can renew.
func renewLink(v VM) error {
	if _, err := command(v.vmrun, "disconnectNamedDevice", v.Path, v.device); err != nil {
		return err
	}
	time.Sleep(time.Second)
	var err error
	for attempt := 0; attempt < 3; attempt++ {
		if _, err = command(v.vmrun, "connectNamedDevice", v.Path, v.device); err == nil {
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
			out[i].Reason = "目标 Host-only 网络上已有相同 MAC 的虚拟网卡"
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
	scan := bufio.NewScanner(strings.NewReader(string(b)))
	for scan.Scan() {
		k, val, ok := strings.Cut(scan.Text(), "=")
		if ok {
			fields[strings.ToLower(strings.TrimSpace(k))] = strings.Trim(strings.TrimSpace(val), "\"")
		}
	}
	if name := fields["displayname"]; name != "" {
		v.Name = name
	}
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
	if err := scan.Err(); err != nil {
		return v, err
	}
	v.Network = v.CurrentNetwork
	if !eligible[v.Network].IsValid() {
		v.Network = "vmnet1"
		v.NeedsSwitch = true
	}
	v.subnet = eligible[v.Network]
	switch {
	case count != 1:
		v.Reason = fmt.Sprintf("检测到 %d 张虚拟网卡，需要一张网卡以保证唯一出口", count)
	case !v.subnet.IsValid():
		v.Reason = "默认 VMnet1 不可用，需要启用 DHCP 且有可用主机地址的 IPv4 Host-only 网络"
	default:
		if m, err := net.ParseMAC(v.MAC); err != nil || len(m) != 6 {
			v.Reason = "无法读取虚拟网卡 MAC"
		}
	}
	if v.NeedsSwitch {
		v.NeedsRESTPassword = needsRESTPassword()
	}
	return v, nil
}

var nicPresent = regexp.MustCompile(`^ethernet[0-9]+\.present$`)

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
