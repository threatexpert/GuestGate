package desktop

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"slices"
	"strings"
	"time"

	"github.com/wailsapp/wails/v2/pkg/runtime"

	"guestgate/internal/upstream"
)

type exitInfo struct{ IP, Location, Source string }

type ExitPrompt struct {
	ID, VM, Server, IP, Location, Source string
	Switching                            bool
}

type exitRequest struct {
	prompt ExitPrompt
	answer chan bool
}

func AttachWindow(a *App, ctx context.Context) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.windowCtx = ctx
	a.exitChanged = func() { runtime.EventsEmit(ctx, "guestgate:exit-confirmation") }
}

func (a *App) PendingExitConfirmation() *ExitPrompt {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.closing || len(a.exitRequests) == 0 {
		return nil
	}
	prompt := a.exitRequests[0].prompt
	return &prompt
}

func (a *App) AnswerExitConfirmation(id string, approved bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.closing || len(a.exitRequests) == 0 || a.exitRequests[0].prompt.ID != id {
		return
	}
	select {
	case a.exitRequests[0].answer <- approved:
	default:
	}
}

func (a *App) awaitExit(ctx context.Context, vm, server string, info exitInfo) (bool, error) {
	return a.confirmExit(ctx, vm, server, info, false)
}
func (a *App) confirmExit(ctx context.Context, vm, server string, info exitInfo, switching bool) (bool, error) {
	req := &exitRequest{
		prompt: ExitPrompt{rand.Text(), vm, server, info.IP, info.Location, info.Source, switching},
		answer: make(chan bool, 1),
	}
	a.mu.Lock()
	notify := a.exitChanged
	if notify == nil || a.closing || ctx.Err() != nil {
		a.mu.Unlock()
		return false, fmt.Errorf("无法显示出口 IP 确认窗口")
	}
	a.exitRequests = append(a.exitRequests, req)
	a.mu.Unlock()
	notify()
	defer func() {
		a.mu.Lock()
		i := slices.Index(a.exitRequests, req)
		a.exitRequests = slices.Delete(a.exitRequests, i, i+1)
		a.mu.Unlock()
		notify()
	}()
	select {
	case <-ctx.Done():
		return false, ctx.Err()
	case approved := <-req.answer:
		return approved, nil
	}
}

func lookupExit(ctx context.Context, raw string) (exitInfo, error) {
	up, err := upstream.Parse(raw)
	if err != nil {
		return exitInfo{}, err
	}
	transport := &http.Transport{DialContext: up.DialContext, DisableKeepAlives: true}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 7 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	return firstExit(ctx, client, []string{
		"https://ipwho.is/", "https://api.myip.com/",
		"https://ifconfig.co/json", "https://ipinfo.io/json",
	})
}

func firstExit(ctx context.Context, client *http.Client, sources []string) (exitInfo, error) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	type result struct {
		info exitInfo
		err  error
	}
	results := make(chan result, len(sources))
	for _, source := range sources {
		go func() {
			info, err := readExit(ctx, client, source)
			results <- result{info, err}
		}()
	}
	var failures error
	for range sources {
		select {
		case <-ctx.Done():
			return exitInfo{}, ctx.Err()
		case res := <-results:
			if res.err == nil {
				return res.info, nil
			}
			failures = errors.Join(failures, res.err)
		}
	}
	return exitInfo{}, fmt.Errorf("经上游代理查询出口 IP 和归属地失败：%w", failures)
}

func readExit(ctx context.Context, client *http.Client, source string) (exitInfo, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, source, nil)
	if err != nil {
		return exitInfo{}, err
	}
	req.Header.Set("Cache-Control", "no-cache")
	resp, err := client.Do(req)
	if err != nil {
		return exitInfo{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return exitInfo{}, fmt.Errorf("%s：HTTP %d", req.URL.Host, resp.StatusCode)
	}
	var data struct {
		IP, Country, Region, City, CC string
		RegionName                    string `json:"region_name"`
		Success                       *bool
	}
	if err = json.NewDecoder(io.LimitReader(resp.Body, 32<<10)).Decode(&data); err != nil {
		return exitInfo{}, fmt.Errorf("%s：响应格式无效", req.URL.Host)
	}
	ip, err := netip.ParseAddr(data.IP)
	if err != nil || !ip.Is4() || !ip.IsGlobalUnicast() || ip.IsPrivate() || netip.MustParsePrefix("100.64.0.0/10").Contains(ip) {
		return exitInfo{}, fmt.Errorf("%s：未返回公网 IPv4 地址", req.URL.Host)
	}
	country := strings.TrimSpace(data.Country)
	if (data.Success != nil && !*data.Success) || country == "" || strings.EqualFold(country, "unknown") || data.CC == "XX" {
		return exitInfo{}, fmt.Errorf("%s：未查到归属地", req.URL.Host)
	}
	location := []string{country}
	if data.Region == "" {
		data.Region = data.RegionName
	}
	for _, part := range []string{data.Region, data.City} {
		if p := strings.TrimSpace(part); p != "" && p != location[len(location)-1] {
			location = append(location, p)
		}
	}
	return exitInfo{ip.String(), strings.Join(location, " · "), req.URL.Host}, nil
}
