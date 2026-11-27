package gateway

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"

	"golang.org/x/sys/windows"
)

type manager struct {
	mu       sync.Mutex
	sessions map[string]context.CancelFunc
	lock     windows.Handle
	wg       sync.WaitGroup
	setup    sync.Mutex
	networks networkPool
	dhcp     dhcpTable
}

type WorkerCommand struct {
	Action string
	Config
}
type WorkerEvent struct {
	VM       string
	State    VMState
	Activity []ActivityEntry `json:",omitempty"`
}

func (m *manager) start(cfg Config, report func(VMState, []ActivityEntry)) {
	batch := &activityBatch{flush: make(chan struct{}, 1)}
	p := &setupProgress{state: InitialState(), activity: batch, report: func(s VMState) { report(s, batch.drain()) }}
	key := strings.ToLower(cfg.VM)
	m.mu.Lock()
	if m.sessions == nil {
		m.sessions = make(map[string]context.CancelFunc)
	}
	if _, ok := m.sessions[key]; ok {
		m.mu.Unlock()
		return
	}
	if len(m.sessions) == 0 {
		name, _ := windows.UTF16PtrFromString(`Global\GuestGate-VMware-DHCP`)
		lock, err := windows.CreateMutex(nil, false, name)
		if err != nil {
			if lock != 0 {
				windows.CloseHandle(lock)
			}
			m.mu.Unlock()
			message := "无法取得 VMware 配置锁：" + err.Error()
			if errors.Is(err, windows.ERROR_ALREADY_EXISTS) {
				message = "已有另一个 GuestGate 窗口正在管理网络，请在同一窗口启用多台虚拟机"
			}
			p.report(p.state.Finished(errors.New(message), false))
			return
		}
		m.lock = lock
	}
	ctx, cancel := context.WithCancel(context.Background())
	m.sessions[key] = cancel
	m.wg.Add(1)
	m.mu.Unlock()
	go func() {
		defer m.wg.Done()
		p.report(p.state)
		err := m.run(ctx, cfg, p)
		stopped := ctx.Err() != nil
		cancel()
		m.mu.Lock()
		delete(m.sessions, key)
		if len(m.sessions) == 0 {
			windows.CloseHandle(m.lock)
			m.lock = 0
		}
		p.report(p.state.Finished(err, stopped && p.cleanupErr == nil && (err == nil || errors.Is(err, context.Canceled))))
		m.mu.Unlock()
	}()
}

func (m *manager) stop(path string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if cancel := m.sessions[strings.ToLower(path)]; cancel != nil {
		cancel()
	}
}

func (m *manager) shutdown() {
	m.mu.Lock()
	for _, cancel := range m.sessions {
		cancel()
	}
	m.mu.Unlock()
	m.wg.Wait()
}

func (m *manager) prepare(ctx context.Context, cfg Config, p *setupProgress) (VM, string, error) {
	// vmrest uses one credential file for this Windows user during hot switching.
	m.setup.Lock()
	defer m.setup.Unlock()
	if err := ctx.Err(); err != nil {
		return VM{}, "", err
	}
	vms, err := Machines()
	if err != nil {
		return VM{}, "", err
	}
	for _, v := range vms {
		if !strings.EqualFold(v.Path, cfg.VM) {
			continue
		}
		if v.Reason != "" {
			return v, "", errors.New(v.Reason)
		}
		dns, err := DNSAddress(cfg.DNS)
		if err != nil {
			return v, "", err
		}
		var dev string
		if !cfg.AllowHostAccess {
			if hostDestination(dns.AsSlice()) {
				return v, "", errors.New("隔离模式无法使用宿主机 DNS")
			}
			if err = m.isolatedNetwork(&v, vms, false); err != nil {
				if v.IsOwnNetwork {
					_, disconnectErr := command(v.vmrun, "disconnectNamedDevice", v.Path, v.device)
					err = errors.Join(err, disconnectErr)
				}
				return v, "", err
			}
		} else {
			if v.SharedReason != "" {
				return v, "", errors.New(v.SharedReason)
			}
			dev, err = captureDevice(v)
			if err != nil {
				return v, "", fmt.Errorf("虚拟网络检查失败: %w", err)
			}
		}
		if v.subnet.Contains(dns) || dns.IsLinkLocalUnicast() {
			return v, "", errors.New("请选择可经代理网关路由的 DNS 地址，虚拟机会直接访问同网段地址和链路本地地址")
		}
		v.scope, err = discoverGatewayAddresses(v.subnet)
		if err != nil {
			return v, "", err
		}
		if !v.scope.nextFree(v.subnet.Addr().Next()).IsValid() {
			return v, "", fmt.Errorf("%s 没有 DHCP 地址池以外的可用网关地址", v.subnet)
		}
		v.dns = dns

		if err = ctx.Err(); err != nil {
			return v, "", err
		}
		p.step(checkVM, "done", v.Name+" · 已确认只配置 1 个网络适配器 · "+v.subnet.String())
		if v.isolated {
			p.step(selectNetwork, "active", "正在连接专用隔离网络 "+v.Network)
			if err = switchIsolated(ctx, v, cfg.RESTPassword); err != nil {
				return v, "", fmt.Errorf("隔离网络切换未完成: %w", err)
			}
			if err = m.isolatedNetwork(&v, vms, true); err != nil {
				_, disconnectErr := command(v.vmrun, "disconnectNamedDevice", v.Path, v.device)
				return v, "", errors.Join(err, disconnectErr)
			}
			p.step(selectNetwork, "done", "已接入隔离网络（"+strings.Replace(v.Network, "vmnet", "VMnet", 1)+"）。虚拟机无法访问宿主机端口，上网必须通过代理。")
			p.state.IsolatedNetwork = v.Network
		} else if v.NeedsSwitch {
			transition := v.CurrentNetwork + " → 共享仅主机网络（VMnet1）"
			p.step(selectNetwork, "active", transition)
			if err = switchHostOnly(ctx, v, cfg.RESTPassword); err != nil {
				return v, "", fmt.Errorf("未确认切换，原网络仍可能生效: %w", err)
			}
			p.step(selectNetwork, "done", transition+"，已核实网卡切换")
		} else {
			p.step(selectNetwork, "skipped", "已连接共享仅主机网络 "+v.Network+"，无需切换")
		}
		if err = v.verifyConfiguredAdapter(); err != nil {
			return v, "", err
		}
		return v, dev, nil
	}
	return VM{}, "", errors.New("找不到运行中的虚拟机")
}
func (m *manager) run(ctx context.Context, cfg Config, p *setupProgress) error {
	server, user, pass, err := ParseProxy(cfg.Proxy)
	if err != nil {
		return err
	}
	v, dev, err := m.prepare(ctx, cfg, p)
	if err != nil {
		return err
	}
	return m.gatewayRun(ctx, v, dev, server, user, pass, p)
}

func ServeManager(in io.Reader, out io.Writer) error {
	var m manager
	defer m.shutdown()
	var output sync.Mutex
	enc := json.NewEncoder(out)
	scan := bufio.NewScanner(in)
	for scan.Scan() {
		var cmd WorkerCommand
		if err := json.Unmarshal(scan.Bytes(), &cmd); err != nil {
			return err
		}
		switch cmd.Action {
		case "start":
			vm := cmd.VM
			m.start(cmd.Config, func(s VMState, activity []ActivityEntry) {
				output.Lock()
				defer output.Unlock()
				_ = enc.Encode(WorkerEvent{vm, s, activity})
			})
		case "stop":
			m.stop(cmd.VM)
		default:
			return errors.New("未知网关指令")
		}
	}
	return scan.Err()
}

// Keep the original single-session worker pipe available for existing callers.
func RunWorker() error {
	in := bufio.NewReader(os.Stdin)
	line, err := in.ReadBytes('\n')
	if err != nil {
		return err
	}
	var cfg Config
	if err = json.Unmarshal(line, &cfg); err != nil {
		return err
	}
	var m manager
	final := make(chan VMState, 1)
	m.start(cfg, func(s VMState, _ []ActivityEntry) {
		if s.Running {
			fmt.Println(s.Status)
		} else {
			final <- s
		}
	})
	go func() { io.Copy(io.Discard, in); m.stop(cfg.VM) }()
	s := <-final
	m.shutdown()
	if strings.HasPrefix(s.Status, "错误 · ") {
		return errors.New(strings.TrimPrefix(s.Status, "错误 · "))
	}
	return nil
}
