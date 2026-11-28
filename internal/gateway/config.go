package gateway

import (
	"fmt"
	"net/netip"
	"strings"
)

type Config struct {
	VM, Proxy, RESTPassword, DNS string
	AllowHostAccess              bool
	RecordTraffic                bool
	RecordingRoot                string
}

const DefaultDNS = "8.8.8.8"

func DNSAddress(raw string) (netip.Addr, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		raw = DefaultDNS
	}
	ip, err := netip.ParseAddr(raw)
	if err != nil || !ip.Is4() || ip.IsUnspecified() || ip.IsMulticast() || ip.IsLoopback() || ip == netip.AddrFrom4([4]byte{255, 255, 255, 255}) {
		return netip.Addr{}, fmt.Errorf("请输入有效的 IPv4 DNS 地址")
	}
	return ip, nil
}
