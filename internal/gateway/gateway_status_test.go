package gateway

import (
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"testing"
	"time"
)

func TestSessionLeaseSelectsCurrentGuest(t *testing.T) {
	since := time.Date(2026, 11, 26, 15, 55, 11, 300, time.UTC)
	now := since.Add(2 * time.Minute)
	subnet := netip.MustParsePrefix("192.168.7.0/24")
	const mac = "00:0c:29:fb:b5:02"
	block := func(ip, mac, start, end string) string {
		return fmt.Sprintf("lease %s {\r\n starts 4 2026/11/26 %s;\r\n ends 4 2026/11/26 %s;\r\n hardware ethernet %s;\r\n}\r\n", ip, start, end, mac)
	}
	valid := block("192.168.7.131", mac, "15:55:11", "16:25:11")
	other := block("192.168.7.131", "00:0c:29:11:22:33", "15:55:42", "16:25:42")
	for _, tc := range []struct{ input, want string }{
		{valid, "192.168.7.131"},
		{valid + other, ""},
		{other + valid, "192.168.7.131"},
		{valid + strings.TrimSuffix(other, "}\r\n"), "192.168.7.131"},
		{block("192.168.8.131", mac, "15:55:11", "16:25:11"), ""},
		{block("192.168.7.131", mac, "15:55:10", "16:25:10"), ""},
		{block("192.168.7.131", mac, "15:55:11", "15:56:00"), ""},
	} {
		got := sessionLease(strings.NewReader(tc.input), subnet, mac, since, now)
		if tc.want == "" && got.IsValid() || tc.want != "" && got.String() != tc.want {
			t.Fatalf("lease = %v, want %q", got, tc.want)
		}
	}
}

func TestIdleGatewayWithLeaseDoesNotWaitForRenewal(t *testing.T) {
	g := gateway{ip: netip.MustParseAddr("192.168.7.2")}
	lease := netip.MustParseAddr("192.168.7.131")
	line := g.status(lease, 0, errors.New("reconnect failed"))
	for _, label := range []string{"DHCP 已分配 192.168.7.131", "网关 192.168.7.2 已就绪", "等待首个 TCP/UDP 包"} {
		if !strings.Contains(line, label) {
			t.Fatalf("missing %s in %s", label, line)
		}
	}
	if strings.Contains(line, "重连失败") || strings.Contains(line, "连接成功") {
		t.Fatal(line)
	}
	g.answeredARP.Store(true)
	if !strings.Contains(g.status(lease, 0, nil), "已应答") {
		t.Fatal("missing ARP status")
	}
	g.count.Add(1)
	if !strings.Contains(g.status(lease, 0, nil), "已收到代理流量") || !strings.Contains(g.status(lease, -1, nil), "连接失败") {
		t.Fatal("missing traffic status")
	}
}
