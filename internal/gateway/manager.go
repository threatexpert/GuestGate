package gateway

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"sync/atomic"

	"golang.org/x/sys/windows"

	"guestgate/internal/capture"
	"guestgate/internal/upstream"
)

type sessionControl struct {
	cancel   context.CancelFunc
	probe    chan struct{}
	id       string
	commands chan liveCommand
}

type manager struct {
	mu       sync.Mutex
	sessions map[string]sessionControl
	lock     windows.Handle
	wg       sync.WaitGroup
	setup    sync.Mutex
	networks networkPool
	dhcp     dhcpTable
}

type WorkerCommand struct {
	Action       string
	RequestID    uint64
	SessionID    string
	Offset       int
	Query, Kind  string
	ConnectionID uint64
	Config
}
type ControlResult struct {
	Error string
	Page  *upstream.ConnectionPage
}
type liveCommand struct {
	WorkerCommand
	reply func(ControlResult)
}
type WorkerEvent struct {
	RequestID uint64         `json:",omitempty"`
	Reply     *ControlResult `json:",omitempty"`
	VM        string
	State     VMState
	Activity  []ActivityEntry `json:",omitempty"`
}

func (m *manager) start(cfg Config, report func(VMState, []ActivityEntry)) {
	batch := &activityBatch{flush: make(chan struct{}, 1)}
	p := &setupProgress{state: InitialState(), activity: batch, report: func(s VMState) { report(s, batch.drain()) }}
	key := strings.ToLower(cfg.VM)
	m.mu.Lock()
	if m.sessions == nil {
		m.sessions = make(map[string]sessionControl)
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
	probe := make(chan struct{}, 1)
	session := sessionControl{cancel: cancel, probe: probe, id: rand.Text(), commands: make(chan liveCommand, 8)}
	p.state.SessionID = session.id
	m.sessions[key] = session
	m.wg.Add(1)
	m.mu.Unlock()
	go func() {
		defer m.wg.Done()
		p.report(p.state)
		err := m.run(ctx, cfg, p, session)
		stopped := ctx.Err() != nil
		cancel()
		m.mu.Lock()
		delete(m.sessions, key)
		close(session.commands)
		for cmd := range session.commands {
			cmd.reply(ControlResult{Error: "代理会话已结束"})
		}
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
	if session, ok := m.sessions[strings.ToLower(path)]; ok {
		session.cancel()
	}
}

func (m *manager) probe(path string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	select {
	case m.sessions[strings.ToLower(path)].probe <- struct{}{}:
	default:
	}
}

func (m *manager) shutdown() {
	m.mu.Lock()
	for _, session := range m.sessions {
		session.cancel()
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
		if err := v.prepareControl(); err != nil {
			return v, "", err
		}
		if v.Encrypted {
			p.activity.add("GuestGate", "已使用 Windows 保存的凭据验证加密虚拟机")
		}
		if v.controlShell != 0 {
			p.activity.add("GuestGate", "已使用当前用户的普通权限连接 VMware 虚拟机")
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
					_, disconnectErr := v.vmCommand("disconnectNamedDevice", v.Path, v.device)
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
			p.step(selectNetwork, "active", "正在将虚拟机网卡接入专用隔离网络（"+strings.Replace(v.Network, "vmnet", "VMnet", 1)+"）。")
			if err = switchIsolated(ctx, v, cfg.RESTPassword); err != nil {
				if strings.Contains(strings.ToLower(err.Error()), "not powered on") {
					listing, listErr := v.vmCommand("list")
					if listErr != nil {
						return v, "", fmt.Errorf("隔离网络切换未完成（%s）：%w；复查运行列表失败：%v", v.vmrun, err, listErr)
					}
					status := "运行列表中已找不到所选虚拟机"
					for _, path := range strings.Split(listing, "\n") {
						if strings.EqualFold(strings.TrimSpace(path), v.Path) {
							status = "运行列表中仍有该虚拟机，但 VMware 拒绝了运行时操作"
							break
						}
					}
					return v, "", fmt.Errorf("隔离网络切换未完成（%s）：%s。%w", v.vmrun, status, err)
				}
				return v, "", fmt.Errorf("隔离网络切换未完成: %w", err)
			}
			if err = m.isolatedNetwork(&v, vms, true); err != nil {
				_, disconnectErr := v.vmCommand("disconnectNamedDevice", v.Path, v.device)
				return v, "", errors.Join(err, disconnectErr)
			}
			p.step(selectNetwork, "done", "已接入隔离网络（"+strings.Replace(v.Network, "vmnet", "VMnet", 1)+"）。虚拟机无法访问宿主机端口，上网必须通过代理。")
			p.state.IsolatedNetwork = v.Network
		} else if v.NeedsSwitch {
			p.step(selectNetwork, "active", "正在将虚拟机网卡切换到共享仅主机网络（VMnet1）。")
			if err = switchHostOnly(ctx, v, cfg.RESTPassword); err != nil {
				return v, "", fmt.Errorf("未确认切换，原网络仍可能生效: %w", err)
			}
			p.step(selectNetwork, "done", "已确认虚拟机网卡接入共享仅主机网络（VMnet1）。")
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
func (m *manager) run(ctx context.Context, cfg Config, p *setupProgress, session sessionControl) (result error) {
	client, err := upstream.Parse(cfg.Proxy)
	if err != nil {
		return err
	}
	var active atomic.Pointer[capture.Recorder]
	defer func() {
		if r := active.Swap(nil); r != nil {
			p.cleaning("正在写入录制索引")
			if err := r.Close(); err != nil {
				p.state.RecordingError = err.Error()
				p.cleanupErr = errors.Join(p.cleanupErr, err)
				result = errors.Join(result, err)
			}
		}
	}()
	if cfg.RecordTraffic {
		recorder, err := capture.Start(cfg.VM, cfg.RecordingRoot)
		if err != nil {
			return err
		}
		p.state.RecordingDirectory = recorder.Directory
		p.activity.add("录制", "录制目录 · "+recorder.Directory)
		active.Store(recorder)
		p.state.Recording = true
	}
	v, dev, err := m.prepare(ctx, cfg, p)
	if v.controlShell != 0 {
		defer windows.CloseHandle(v.controlShell)
	}
	if err != nil {
		return err
	}
	return m.gatewayRun(ctx, v, dev, client, &active, p, session)
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
				_ = enc.Encode(WorkerEvent{VM: vm, State: s, Activity: activity})
			})
		case "connections", "disconnect-one", "disconnect", "switch", "record":
			command := cmd
			reply := func(res ControlResult) {
				output.Lock()
				defer output.Unlock()
				_ = enc.Encode(WorkerEvent{VM: command.VM, RequestID: command.RequestID, Reply: &res})
			}
			m.mu.Lock()
			session, ok := m.sessions[strings.ToLower(cmd.VM)]
			if !ok || session.id != cmd.SessionID {
				reply(ControlResult{Error: "原代理会话已结束"})
			} else {
				select {
				case session.commands <- liveCommand{cmd, reply}:
				default:
					reply(ControlResult{Error: "会话正忙，请重试"})
				}
			}
			m.mu.Unlock()
		case "stop":
			m.stop(cmd.VM)
		case "probe":
			m.probe(cmd.VM)
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
