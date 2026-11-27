package desktop

import (
	"bufio"
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
)

type App struct {
	mu      sync.Mutex
	pipe    io.WriteCloser
	done    chan struct{}
	states  map[string]gateway.VMState
	closing bool
}

func (a *App) Machines() ([]gateway.VM, error) { return gateway.Machines() }
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
		for scan.Scan() {
			var event gateway.WorkerEvent
			if json.Unmarshal(scan.Bytes(), &event) != nil {
				continue
			}
			a.mu.Lock()
			key := strings.ToLower(event.VM)
			if a.states[key].Phase == "stopping" && event.State.Running {
				event.State.Phase, event.State.Status = "stopping", "正在停止代理"
			}
			a.states[key] = event.State
			a.mu.Unlock()
		}
		in.Close()
		cmd.Wait()
		a.mu.Lock()
		defer a.mu.Unlock()
		for k, s := range a.states {
			if s.Running {
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
	if _, _, _, err := gateway.ParseProxy(proxy); err != nil {
		return err
	}
	ip, err := gateway.DNSAddress(dns)
	if err != nil {
		return err
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	key := strings.ToLower(vm)
	if a.closing {
		return fmt.Errorf("窗口正在关闭")
	}
	if a.states[key].Running {
		return fmt.Errorf("该虚拟机已启用")
	}
	if a.states == nil {
		a.states = make(map[string]gateway.VMState)
	}
	if err = a.startManager(); err != nil {
		return err
	}
	cfg := gateway.Config{VM: vm, Proxy: proxy, DNS: ip.String(), RESTPassword: restPassword}
	if err = json.NewEncoder(a.pipe).Encode(gateway.WorkerCommand{Action: "start", Config: cfg}); err != nil {
		return err
	}
	a.states[key] = gateway.InitialState()
	return nil
}
func (a *App) StopVM(vm string) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	key := strings.ToLower(vm)
	if !a.states[key].Running || a.pipe == nil {
		return nil
	}
	if err := json.NewEncoder(a.pipe).Encode(gateway.WorkerCommand{Action: "stop", Config: gateway.Config{VM: vm}}); err != nil {
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
	return a, a.shutdown
}

func (a *App) LoadPreferences(vm string) (*profiles.Preferences, error) { return profiles.Load(vm) }
func (a *App) SavePreferences(vm string, p profiles.Preferences) error  { return profiles.Save(vm, p) }
