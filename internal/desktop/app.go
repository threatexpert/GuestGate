package desktop

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"sync"
	"syscall"

	"guestgate/internal/gateway"
	"guestgate/internal/profiles"
	"guestgate/internal/upstream"
)

type App struct {
	nextRequest  uint64
	replies      map[uint64]chan gateway.ControlResult
	windowCtx    context.Context
	checking     map[string]context.CancelFunc
	exitRequests []*exitRequest
	exitChanged  func()
	lookup       func(context.Context, string) (exitInfo, error)
	activity     activityHistory
	mu           sync.Mutex
	pipe         io.WriteCloser
	done         chan struct{}
	states       map[string]gateway.VMState
	closing      bool
	closeReady   bool
	closeUpdates chan struct{}
}

func (a *App) Machines() ([]gateway.VM, error) {
	vms, err := gateway.Machines()
	if err != nil {
		a.activity.record("", "错误", "读取虚拟机列表 · "+err.Error())
	}
	return vms, err
}
func (a *App) States() map[string]gateway.VMState {
	a.mu.Lock()
	defer a.mu.Unlock()
	result := make(map[string]gateway.VMState, len(a.states))
	for k, v := range a.states {
		result[k] = v
	}
	return result
}
func (a *App) startManager() error {
	if a.pipe != nil {
		return nil
	}
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	cmd := exec.Command(exe, "--manager")
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	in, err := cmd.StdinPipe()
	if err != nil {
		return err
	}
	out, err := cmd.StdoutPipe()
	if err != nil {
		in.Close()
		return err
	}
	if err = cmd.Start(); err != nil {
		in.Close()
		out.Close()
		return err
	}
	a.pipe = in
	a.done = make(chan struct{})
	go func() {
		scan := bufio.NewScanner(out)
		scan.Buffer(make([]byte, 64*1024), 4*1024*1024)
		for scan.Scan() {
			var event gateway.WorkerEvent
			if json.Unmarshal(scan.Bytes(), &event) != nil {
				continue
			}
			a.mu.Lock()
			if event.Reply != nil {
				if reply := a.replies[event.RequestID]; reply != nil {
					reply <- *event.Reply
					delete(a.replies, event.RequestID)
				}
				a.mu.Unlock()
				continue
			}
			key := strings.ToLower(event.VM)
			a.activity.append(event.VM, event.Activity...)
			if !event.State.Running {
				kind := "GuestGate"
				if event.State.Phase == "error" {
					kind = "错误"
				}
				a.activity.record(event.VM, kind, event.State.Status)
			}
			if a.states[key].Phase == "stopping" && event.State.Running && event.State.Phase != "stopping" {
				event.State.Phase, event.State.Status = "stopping", "正在停止代理"
			}
			a.states[key] = event.State
			select {
			case a.closeUpdates <- struct{}{}:
			default:
			}
			a.mu.Unlock()
		}
		in.Close()
		cmd.Wait()
		a.mu.Lock()
		defer a.mu.Unlock()
		for k, s := range a.states {
			if s.Running {
				a.activity.record(k, "错误", "网关进程已退出")
				a.states[k] = s.Finished(fmt.Errorf("网关进程已退出"), false)
			}
		}
		a.pipe = nil
		close(a.done)
	}()
	return nil
}
func (a *App) Start(vm, proxy string) error { return a.StartVM(vm, proxy, gateway.DefaultDNS, "") }
func (a *App) StartWithCredentials(vm, proxy, restPassword string) error {
	return a.StartVM(vm, proxy, gateway.DefaultDNS, restPassword)
}
func (a *App) StartVM(vm, proxy, dns, restPassword string) error {
	return a.StartVMWithHostAccess(vm, proxy, dns, restPassword, false)
}
func (a *App) StartVMWithHostAccess(vm, proxy, dns, restPassword string, allowHostAccess bool) (result error) {
	defer func() {
		if result != nil {
			a.activity.record(vm, "错误", "启用代理 · "+result.Error())
		}
	}()
	client, err := upstream.Parse(proxy)
	if err != nil {
		return err
	}
	ip, err := gateway.DNSAddress(dns)
	if err != nil {
		return err
	}
	key := strings.ToLower(vm)
	pref, err := profiles.Load(vm)
	if err != nil {
		return err
	}
	a.mu.Lock()
	if a.closing {
		a.mu.Unlock()
		return fmt.Errorf("窗口正在关闭")
	}
	if a.checking[key] != nil || a.states[key].Running {
		a.mu.Unlock()
		return fmt.Errorf("该虚拟机正在启用或已启用代理")
	}
	ctx, cancel := context.WithCancel(context.Background())
	if a.checking == nil {
		a.checking = make(map[string]context.CancelFunc)
	}
	a.checking[key] = cancel
	a.mu.Unlock()
	defer func() { cancel(); a.mu.Lock(); delete(a.checking, key); a.mu.Unlock() }()
	if pref == nil || !pref.SkipExitConfirmation {
		lookup := a.lookup
		if lookup == nil {
			lookup = lookupExit
		}
		info, err := lookup(ctx, proxy)
		if err != nil {
			return err
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		ok, err := a.awaitExit(ctx, vm, client.Display(), info)
		if err != nil {
			return err
		}
		if !ok {
			a.activity.record(vm, "GuestGate", "已取消启用代理")
			return nil
		}
		a.activity.record(vm, "GuestGate", "已确认出口 "+info.IP+" · "+info.Location)
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.closing || ctx.Err() != nil {
		return fmt.Errorf("启动已取消")
	}
	if a.states == nil {
		a.states = make(map[string]gateway.VMState)
	}
	if err = a.startManager(); err != nil {
		return err
	}
	cfg := gateway.Config{VM: vm, Proxy: proxy, DNS: ip.String(), RESTPassword: restPassword, AllowHostAccess: allowHostAccess}
	if pref != nil {
		cfg.RecordTraffic = pref.RecordTraffic
		cfg.RecordingRoot = pref.RecordingRoot
	}
	if err = json.NewEncoder(a.pipe).Encode(gateway.WorkerCommand{Action: "start", Config: cfg}); err != nil {
		return err
	}
	a.states[key] = gateway.InitialState()
	a.activity.record(vm, "GuestGate", "正在启用代理")
	return nil
}
func (a *App) ProbeUpstream(vm string) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	state := a.states[strings.ToLower(vm)]
	if a.closing || a.pipe == nil || !state.Running || state.Phase != "ready" {
		return fmt.Errorf("虚拟机会话尚未就绪或已停止")
	}
	if state.Stats.Probing {
		return nil
	}
	return json.NewEncoder(a.pipe).Encode(gateway.WorkerCommand{Action: "probe", Config: gateway.Config{VM: vm}})
}

func (a *App) StopVM(vm string) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	key := strings.ToLower(vm)
	if cancel := a.checking[key]; cancel != nil {
		cancel()
	}
	if !a.states[key].Running || a.pipe == nil {
		return nil
	}
	if err := json.NewEncoder(a.pipe).Encode(gateway.WorkerCommand{Action: "stop", Config: gateway.Config{VM: vm}}); err != nil {
		a.activity.record(vm, "错误", "停止代理 · "+err.Error())
		return err
	}
	s := a.states[key]
	s.Phase, s.Status = "stopping", "正在停止代理"
	a.states[key] = s
	return nil
}
func (a *App) shutdown() {
	a.mu.Lock()
	a.closing = true
	for _, cancel := range a.checking {
		cancel()
	}
	if a.pipe == nil {
		a.mu.Unlock()
		return
	}
	done := a.done
	a.pipe.Close()
	a.mu.Unlock()
	<-done
}

func NewApp() (*App, func()) {
	a := new(App)
	a.activity.record("", "GuestGate", "GuestGate 已启动")
	return a, a.shutdown
}

func (a *App) LoadPreferences(vm string) (*profiles.Preferences, error) { return profiles.Load(vm) }
func (a *App) SavePreferences(vm string, p profiles.Preferences) error  { return profiles.Save(vm, p) }
