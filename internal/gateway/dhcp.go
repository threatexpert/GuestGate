package gateway

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"golang.org/x/sys/windows"
)

const begin = "# GuestGate managed guest BEGIN"
const end = "# GuestGate managed guest END"

func dhcpPath() string { return filepath.Join(os.Getenv("ProgramData"), "VMware", "vmnetdhcp.conf") }

// VMware appends leases to a shared file. The last complete block for each
// address supersedes earlier owners, including after a DHCP service restart.
func sessionLease(r io.Reader, subnet netip.Prefix, mac string, since, now time.Time) netip.Addr {
	active := map[netip.Addr]time.Time{}
	var ip netip.Addr
	var start, end time.Time
	var owner string
	scan := bufio.NewScanner(r)
	for scan.Scan() {
		fields := strings.Fields(strings.TrimSuffix(strings.TrimSpace(scan.Text()), ";"))
		if len(fields) == 0 {
			continue
		}
		if len(fields) == 3 && fields[0] == "lease" && fields[2] == "{" {
			ip, _ = netip.ParseAddr(fields[1])
			owner, start, end = "", time.Time{}, time.Time{}
			continue
		}
		if !ip.IsValid() || !subnet.Contains(ip) {
			continue
		}
		switch fields[0] {
		case "hardware":
			if len(fields) == 3 && fields[1] == "ethernet" {
				owner = fields[2]
			}
		case "starts", "ends":
			if len(fields) == 4 {
				t, _ := time.Parse("2006/01/02 15:04:05", fields[2]+" "+fields[3])
				if fields[0] == "starts" {
					start = t
				} else {
					end = t
				}
			}
		case "}":
			delete(active, ip)
			if strings.EqualFold(owner, mac) && !start.Before(since.Truncate(time.Second)) && !start.After(now) && end.After(now) {
				active[ip] = start
			}
			ip = netip.Addr{}
		}
	}
	if scan.Err() != nil {
		return netip.Addr{}
	}
	var best netip.Addr
	for ip, start := range active {
		if !best.IsValid() || start.After(active[best]) {
			best = ip
		}
	}
	return best
}

func currentLease(v VM, since, now time.Time) netip.Addr {
	f, err := os.Open(filepath.Join(filepath.Dir(dhcpPath()), "vmnetdhcp.leases"))
	if err != nil {
		return netip.Addr{}
	}
	defer f.Close()
	return sessionLease(f, v.subnet, v.MAC, since, now)
}
func unmanaged(b []byte) ([]byte, error) {
	start := bytes.Index(b, []byte(begin))
	if start < 0 {
		return b, nil
	}
	// The marker includes its leading blank line, preserving the original bytes.
	if start < 2 || string(b[start-2:start]) != "\r\n" {
		return nil, fmt.Errorf("invalid GuestGate DHCP marker")
	}
	tail := bytes.Index(b[start:], []byte(end+"\r\n"))
	if tail < 0 {
		return nil, fmt.Errorf("incomplete GuestGate DHCP entry")
	}
	after := start + tail + len(end) + 2
	return append(append([]byte(nil), b[:start-2]...), b[after:]...), nil
}
func replaceConf(b []byte) error {
	path := dhcpPath()
	f, e := os.CreateTemp(filepath.Dir(path), "guestgate-*.tmp")
	if e != nil {
		return e
	}
	defer os.Remove(f.Name())
	_, e = f.Write(b)
	if e == nil {
		e = f.Sync()
	}
	ce := f.Close()
	if e != nil {
		return e
	}
	if ce != nil {
		return ce
	}
	a, _ := windows.UTF16PtrFromString(f.Name())
	z, _ := windows.UTF16PtrFromString(path)
	return windows.MoveFileEx(a, z, windows.MOVEFILE_REPLACE_EXISTING|windows.MOVEFILE_WRITE_THROUGH)
}

type dhcpTable struct {
	mu     sync.Mutex
	guests map[string]VM
}

func (d *dhcpTable) change(v VM, enable bool) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	next := make(map[string]VM, len(d.guests)+1)
	for k, guest := range d.guests {
		next[k] = guest
	}
	key := strings.ToLower(v.MAC)
	if enable {
		if _, ok := next[key]; ok {
			return fmt.Errorf("该网卡已启用")
		}
		next[key] = v
	} else {
		delete(next, key)
	}
	err := writeDHCP(next)
	if err == nil || !enable {
		d.guests = next
	}
	return err
}
func renderDHCP(original []byte, guests map[string]VM) ([]byte, error) {
	base, e := unmanaged(original)
	if e != nil {
		return nil, e
	}
	if len(guests) == 0 {
		return base, nil
	}
	keys := make([]string, 0, len(guests))
	for k := range guests {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var entries strings.Builder
	fmt.Fprintf(&entries, "\r\n%s\r\n", begin)
	for _, k := range keys {
		v := guests[k]
		gateway := v.gatewayIP
		mac, e := net.ParseMAC(v.MAC)
		if e != nil {
			return nil, e
		}
		if strings.Contains(strings.ToLower(string(base)), "hardware ethernet "+mac.String()) {
			return nil, fmt.Errorf("该 MAC 已有自定义 DHCP 保留项")
		}
		scope, err := readGatewayScope(base, v.subnet)
		if err != nil {
			return nil, err
		}
		if !scope.allows(gateway) {
			return nil, fmt.Errorf("网关地址 %s 与当前 DHCP 配置冲突", gateway)
		}
		fmt.Fprintf(&entries, "host GuestGate-%s {\r\n hardware ethernet %s;\r\n option routers %s;\r\n option domain-name-servers %s;\r\n}\r\n", strings.ReplaceAll(mac.String(), ":", ""), mac, gateway, v.dns)
	}
	fmt.Fprintf(&entries, "%s\r\n", end)
	return append(append([]byte(nil), base...), entries.String()...), nil
}
func writeDHCP(guests map[string]VM) error {
	original, e := os.ReadFile(dhcpPath())
	if e != nil {
		return e
	}
	updated, e := renderDHCP(original, guests)
	if e != nil {
		return e
	}
	if bytes.Equal(original, updated) {
		return nil
	}
	if e = replaceConf(updated); e != nil {
		return e
	}
	if _, e = powershell("Restart-Service -Name VMnetDHCP"); e != nil {
		if restore := replaceConf(original); restore != nil {
			return fmt.Errorf("%v; rollback: %w", e, restore)
		}
		_, restart := powershell("Restart-Service -Name VMnetDHCP")
		return fmt.Errorf("DHCP restart: %v (rollback: %v)", e, restart)
	}
	return nil
}
