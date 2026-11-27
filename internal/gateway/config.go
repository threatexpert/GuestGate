package gateway

import (
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
)

type Config struct{ VM, Proxy, RESTPassword, DNS string }

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

func ParseProxy(raw string) (string, string, string, error) {
	raw = strings.TrimSpace(raw)
	if !strings.Contains(raw, "://") {
		raw = "socks5://" + raw
	}
	u, e := url.Parse(raw)
	if e != nil || u.Scheme != "socks5" || u.Hostname() == "" || u.Path != "" || u.RawQuery != "" || u.Fragment != "" {
		return "", "", "", fmt.Errorf("请输入 SOCKS5 地址和端口")
	}
	port, e := strconv.Atoi(u.Port())
	if e != nil || port < 1 || port > 65535 {
		return "", "", "", fmt.Errorf("SOCKS5 端口无效")
	}
	pass, _ := u.User.Password()
	return net.JoinHostPort(u.Hostname(), u.Port()), u.User.Username(), pass, nil
}
