package gateway

import (
	"bytes"
	"context"
	"crypto/sha256"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"golang.org/x/sys/windows/registry"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

//go:embed isolate.ps1
var provisionIsolated string

var numberedVMnet = regexp.MustCompile("^vmnet[0-9]+$")

func networkArray(names []string) string {
	values := []string{}
	for _, n := range names {
		n = strings.ToLower(n)
		if numberedVMnet.MatchString(n) {
			values = append(values, "'"+n+"'")
		}
	}
	return "@(" + strings.Join(values, ",") + ")"
}

const vmnetRegistry = `SOFTWARE\VMware, Inc.\VMnetLib\VMnetConfig\`

func ownerID(path string) string {
	return fmt.Sprintf("%x", sha256.Sum256([]byte(strings.ToLower(filepath.Clean(path)))))
}
func isOwnVMnet(v VM) bool {
	if !numberedVMnet.MatchString(v.CurrentNetwork) {
		return false
	}
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, vmnetRegistry+v.CurrentNetwork, registry.QUERY_VALUE|registry.WOW64_32KEY)
	if err != nil {
		return false
	}
	defer k.Close()
	value, _, err := k.GetStringValue("GuestGateOwner")
	return err == nil && value == ownerID(v.Path)
}

func (m *manager) isolatedNetwork(v *VM, all []VM, audit bool) error {
	m.dhcp.mu.Lock()
	defer m.dhcp.mu.Unlock()
	var occupied, listed []string
	for _, other := range all {
		if !strings.EqualFold(v.Path, other.Path) {
			for _, b := range other.bindings {
				occupied = append(occupied, b.network)
			}
		}
	}
	inventory, err := command(v.vmrun, "listHostNetworks")
	if err != nil {
		return err
	}
	for _, line := range strings.Split(inventory, "\n") {
		if f := strings.Fields(line); len(f) >= 3 {
			listed = append(listed, f[1])
		}
	}
	owner := ownerID(v.Path)
	script := fmt.Sprintf("$audit=$%t;$owner='%s';$occupied=%s;$listed=%s;\n", audit, owner, networkArray(occupied), networkArray(listed)) + provisionIsolated
	raw, err := powershell(script)
	if err != nil {
		return fmt.Errorf("隔离网络检查失败: %w", err)
	}
	var info struct{ Network, Subnet string }
	if err = json.Unmarshal([]byte(raw), &info); err != nil {
		return err
	}
	prefix, err := netip.ParsePrefix(info.Subnet + "/24")
	if err != nil || !prefix.Addr().Is4() || prefix != prefix.Masked() || !numberedVMnet.MatchString(info.Network) {
		return errors.New("隔离网络标识无效")
	}
	original, err := os.ReadFile(dhcpPath())
	if err != nil {
		return err
	}
	start := prefix.Addr().As4()
	lo, hi := start, start
	lo[3] = 128
	hi[3] = 200
	marker := "# GuestGate isolated " + owner
	block := fmt.Sprintf("%s\r\nsubnet %s netmask 255.255.255.0 {\r\n range %s %s;\r\n}\r\n", marker, prefix.Addr(), netip.AddrFrom4(lo), netip.AddrFrom4(hi))
	if !bytes.Contains(original, []byte(block)) {
		if audit {
			return errors.New("专用 DHCP 配置已变化")
		}
		if bytes.Contains(original, []byte(marker)) || bytes.Contains(original, []byte("subnet "+info.Subnet+" ")) {
			return errors.New("已有 DHCP 子网与隔离配置不一致")
		}
		updated := append(bytes.Clone(original), []byte("\r\n"+block)...)
		if err = replaceConf(updated); err != nil {
			return err
		}
	}
	if audit && (v.Network != info.Network || v.subnet != prefix) {
		return errors.New("专用网络配置已变化")
	}
	v.isolated = true
	v.Network = info.Network
	v.subnet = prefix
	return nil
}

func (m *manager) watchNetwork(ctx context.Context, v VM, failed chan<- error) {
	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
		if !v.isolated {
			if err := v.verifyConfiguredAdapter(); err != nil {
				failed <- fmt.Errorf("网络适配器复查失败：%w", err)
				return
			}
			continue
		}
		all, err := Machines()
		if err == nil {
			err = errors.New("找不到正在运行的虚拟机")
			for _, item := range all {
				if strings.EqualFold(item.Path, v.Path) {
					err = v.checkAdapter(item)
					break
				}
			}
		}
		if err == nil {
			var kind, name string
			kind, name, err = runtimeNIC(v)
			if err == nil && (!strings.EqualFold(kind, "custom") || !strings.EqualFold(name, v.Network)) {
				err = errors.New("运行中的网卡已离开专用隔离网络")
			}
		}
		if err == nil {
			err = m.isolatedNetwork(&v, all, true)
		}
		if err != nil && ctx.Err() == nil {
			_, disconnectErr := v.vmCommand("disconnectNamedDevice", v.Path, v.device)
			failed <- fmt.Errorf("隔离网络复查失败: %w", errors.Join(err, disconnectErr))
			return
		}
	}
}

func runtimeNIC(v VM) (string, string, error) {
	get := func(k string) (string, error) {
		field := v.device + "." + k
		value, err := v.vmCommand("readVariable", v.Path, "runtimeConfig", field)
		if err != nil {
			return "", fmt.Errorf("读取运行时网卡配置（readVariable runtimeConfig %s）: %w", field, err)
		}
		return value, nil
	}
	kind, err := get("connectionType")
	if err != nil {
		return "", "", err
	}
	name, err := get("vnet")
	return kind, name, err
}

// Workstation REST enumerates an adapterless VMnet only while its host adapter
// is registered. Disable that adapter before attaching the guest and remove it
// afterwards. VMware itself persists the live NIC change across power cycles.
func switchIsolated(ctx context.Context, v VM, password string) (result error) {
	kind, name, err := runtimeNIC(v)
	if err != nil {
		return err
	}
	if strings.EqualFold(kind, "custom") && strings.EqualFold(name, v.Network) && strings.EqualFold(v.CurrentNetwork, v.Network) {
		return nil
	}
	if err = ctx.Err(); err != nil {
		return err
	}
	if _, err = v.vmCommand("disconnectNamedDevice", v.Path, v.device); err != nil {
		return fmt.Errorf("断开网卡（disconnectNamedDevice %s）: %w", v.device, err)
	}
	ctl := filepath.Join(filepath.Dir(v.vmrun), "vnetlib64.exe")
	if _, err = os.Stat(ctl); err != nil {
		return err
	}
	// vnetlib returns operation-specific success codes. Check Windows' device
	// inventory after each call rather than treating a non-zero exit as failure.
	adapter := fmt.Sprintf("$a=@(Get-NetAdapter -IncludeHidden | Where-Object { $_.InterfaceDescription -match '(?i)\\b%s(?: #\\d+)?$' });", v.Network)
	remove := func() error {
		_, _ = command(ctl, "--", "remove", "adapter", v.Network)
		_, err := powershell(adapter + "if($a.Count){throw 'VMware host adapter was not removed'}")
		return err
	}
	stage, err := registry.OpenKey(registry.LOCAL_MACHINE, vmnetRegistry+v.Network, registry.SET_VALUE|registry.WOW64_32KEY)
	if err != nil {
		return err
	}
	defer stage.Close()
	if err = stage.SetDWordValue("GuestGateStaging", 1); err != nil {
		return err
	}
	defer func() {
		if err := remove(); err != nil {
			result = errors.Join(result, fmt.Errorf("清理隔离网络的临时宿主机网卡: %w", err))
		} else {
			result = errors.Join(result, stage.DeleteValue("GuestGateStaging"))
		}
	}()
	_, _ = command(ctl, "--", "add", "adapter", v.Network)
	_, err = powershell(adapter + "if($a.Count -ne 1){throw 'Expected one temporary VMware adapter'}; Disable-NetAdapter -InputObject $a[0] -Confirm:$false;" + adapter + "if($a.Count -ne 1 -or $a[0].Status -ne 'Disabled'){throw 'Temporary VMware adapter must be disabled'}")
	if err != nil {
		return err
	}
	if err = switchHostOnly(ctx, v, password); err != nil {
		return err
	}
	kind, name, err = runtimeNIC(v)
	if err != nil || !strings.EqualFold(kind, "custom") || !strings.EqualFold(name, v.Network) {
		return fmt.Errorf("VMware 未确认隔离网卡配置 (%s/%s): %v", kind, name, err)
	}
	return nil
}

func hostDestination(raw []byte) bool {
	dest, ok := netip.AddrFromSlice(raw)
	if !ok || !dest.Unmap().IsGlobalUnicast() {
		return true
	}
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return true
	}
	for _, n := range addrs {
		if a, ok := n.(*net.IPNet); ok && a.IP.Equal(raw) {
			return true
		}
	}
	return false
}
