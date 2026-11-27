package gateway

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"regexp"
	"strings"

	"guestgate/internal/vmnet"
)

type addressSpan struct{ first, last netip.Addr }
type gatewayAddresses struct {
	subnet   netip.Prefix
	excluded []addressSpan
}

func vmnetPrefix(ipText, maskText string) (netip.Prefix, bool) {
	ip, err := netip.ParseAddr(ipText)
	mask := net.ParseIP(maskText).To4()
	ones, bits := net.IPMask(mask).Size()
	if err != nil || !ip.Is4() || bits != 32 || ones == 0 || ones > 30 {
		return netip.Prefix{}, false
	}
	return netip.PrefixFrom(ip, ones).Masked(), true
}

var dhcpComment = regexp.MustCompile(`(?m)#[^\r\n]*`)
var dhcpStatements = regexp.MustCompile(`[^{};]*[{};]`)

// Read the VMware DHCP scope for this exact prefix. Ranges may be inside pools,
// while fixed-address declarations may also be outside the subnet block.
func readGatewayScope(base []byte, subnet netip.Prefix) (gatewayAddresses, error) {
	a := gatewayAddresses{subnet: subnet}
	depth, scopeDepth := 0, -1
	found, hasPool := false, false
	for _, raw := range dhcpStatements.FindAllString(string(dhcpComment.ReplaceAll(base, nil)), -1) {
		fields := strings.Fields(raw[:len(raw)-1])
		switch raw[len(raw)-1] {
		case '{':
			depth++
			if len(fields) == 4 && fields[0] == "subnet" && fields[2] == "netmask" {
				if p, ok := vmnetPrefix(fields[1], fields[3]); ok && p == subnet {
					if found {
						return a, errors.New("DHCP 中存在重复子网")
					}
					found, scopeDepth = true, depth
				}
			}
		case '}':
			if depth == scopeDepth {
				scopeDepth = -1
			}
			depth--
		case ';':
			if len(fields) < 1 {
				continue
			}
			switch fields[0] {
			case "fixed-address":
				for _, val := range strings.Split(strings.Join(fields[1:], " "), ",") {
					ip, err := netip.ParseAddr(strings.TrimSpace(val))
					if err != nil {
						return a, fmt.Errorf("无法确认 DHCP 保留地址 %q", val)
					}
					if subnet.Contains(ip) {
						a.excluded = append(a.excluded, addressSpan{ip, ip})
					}
				}
			case "range":
				if scopeDepth < 0 {
					continue
				}
				args := fields[1:]
				if len(args) > 0 && args[0] == "dynamic-bootp" {
					args = args[1:]
				}
				if len(args) < 1 || len(args) > 2 {
					return a, errors.New("无法确认 DHCP 地址池")
				}
				lo, e1 := netip.ParseAddr(args[0])
				hi, e2 := netip.ParseAddr(args[len(args)-1])
				if e1 != nil || e2 != nil || !subnet.Contains(lo) || !subnet.Contains(hi) || hi.Less(lo) {
					return a, errors.New("无效的 DHCP 地址池")
				}
				a.excluded = append(a.excluded, addressSpan{lo, hi})
				hasPool = true
			case "option":
				if (scopeDepth >= 0 || depth == 0) && len(fields) > 1 && fields[1] == "routers" {
					return a, errors.New("虚拟机所在网段已有其他网关")
				}
			}
		}
	}
	if !found || !hasPool {
		return a, fmt.Errorf("未找到 %s 的 DHCP 地址池", subnet)
	}
	return a, nil
}

func discoverGatewayAddresses(subnet netip.Prefix) (gatewayAddresses, error) {
	raw, err := os.ReadFile(dhcpPath())
	if err != nil {
		return gatewayAddresses{}, err
	}
	base, err := unmanaged(raw)
	if err != nil {
		return gatewayAddresses{}, err
	}
	a, err := readGatewayScope(base, subnet)
	if err != nil {
		return a, err
	}
	local, err := net.InterfaceAddrs()
	if err != nil {
		return a, err
	}
	for _, addr := range local {
		p, e := netip.ParsePrefix(addr.String())
		if e == nil && subnet.Contains(p.Addr().Unmap()) {
			ip := p.Addr().Unmap()
			a.excluded = append(a.excluded, addressSpan{ip, ip})
		}
	}
	return a, nil
}

// Walk free intervals instead of scanning every IP in a large DHCP pool.
func (a gatewayAddresses) nextFree(ip netip.Addr) netip.Addr {
	base := a.subnet.Masked().Addr().As4()
	n := binary.BigEndian.Uint32(base[:]) | (^uint32(0) >> a.subnet.Bits())
	var last [4]byte
	binary.BigEndian.PutUint32(last[:], n)
	broadcast := netip.AddrFrom4(last)
	for a.subnet.Contains(ip) && ip != a.subnet.Addr() && ip != broadcast {
		next := ip
		for _, r := range a.excluded {
			if !ip.Less(r.first) && !r.last.Less(ip) {
				if !r.last.Less(broadcast) {
					return netip.Addr{}
				}
				next = r.last.Next()
				break
			}
		}
		if next == ip {
			return ip
		}
		ip = next
	}
	return netip.Addr{}
}

func (a gatewayAddresses) allows(ip netip.Addr) bool {
	return ip.IsValid() && a.nextFree(ip) == ip
}

func (g *gateway) chooseAddress(ctx context.Context, port vmnet.Port) error {
	first := g.addresses.subnet.Addr().Next()
	// Prefer the traditional network+2. Consider network+1 last if it is free.
	for _, start := range []netip.Addr{first.Next(), first} {
		for ip := g.addresses.nextFree(start); ip.IsValid(); ip = g.addresses.nextFree(ip.Next()) {
			if start == first && ip != first {
				break
			}
			if err := ctx.Err(); err != nil {
				return err
			}
			g.ip, g.mac = ip, gatewayMAC(ip)
			if bytes.Equal(g.guest, g.mac) {
				continue
			}
			err := g.probeAddress(ctx, port)
			if !errors.Is(err, errGatewayInUse) {
				return err
			}
		}
	}
	return fmt.Errorf("%w：%s 没有可用的网关地址", errGatewayInUse, g.addresses.subnet)
}
