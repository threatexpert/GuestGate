package gateway

import (
	"time"

	"guestgate/internal/dnsrelay"
)

type SessionStats struct {
	Server, DNS, LastTCPError string
	Health                    dnsrelay.Health
	Probing                   bool
	UpBytes, DownBytes        uint64
	UpRate, DownRate          uint64
}

type trafficSample struct {
	at       time.Time
	up, down uint64
}

func (s *SessionStats) sample(previous *trafficSample, now time.Time, up, down uint64) {
	s.UpBytes, s.DownBytes = up, down
	if elapsed := now.Sub(previous.at).Seconds(); elapsed > 0 {
		s.UpRate = uint64(float64(up-previous.up) / elapsed)
		s.DownRate = uint64(float64(down-previous.down) / elapsed)
	}
	*previous = trafficSample{now, up, down}
}

type SetupStep struct {
	Title, State, Detail string
}

type VMState struct {
	IsolatedNetwork string
	Running         bool
	ShowGuestHelp   bool
	Phase, Status   string
	Steps           [5]SetupStep
	Stats           SessionStats
}

const (
	checkVM = iota
	selectNetwork
	openGateway
	setDHCP
	confirmGuest
)

func InitialState() VMState {
	s := VMState{Running: true, Phase: "starting", Status: "正在检查虚拟机"}
	for i, title := range []string{"检查虚拟机与网络", "准备虚拟机网络", "启动本地转发网关", "配置 DHCP 网关和 DNS", "等待虚拟机接入"} {
		s.Steps[i] = SetupStep{Title: title, State: "pending"}
	}
	s.Steps[checkVM].State = "active"
	return s
}

type setupProgress struct {
	activity   *activityBatch
	state      VMState
	report     func(VMState)
	cleanupErr error
}

func (p *setupProgress) cleaning(detail string) {
	p.activity.add("GuestGate", detail)
	p.state.Phase, p.state.Status = "stopping", detail
	p.report(p.state)
}

func (p *setupProgress) step(index int, state, detail string) {
	s := &p.state.Steps[index]
	p.activity.add("GuestGate", s.Title+" · "+detail)
	s.State, s.Detail = state, detail
	if state == "active" {
		p.state.Status = s.Title
	}
	if index == confirmGuest && state == "done" {
		p.state.ShowGuestHelp = false
		s.Title = "虚拟机已接入"
		p.state.Phase = "ready"
		p.state.Status = "代理运行中"
	}
	p.report(p.state)
}

func (s VMState) Finished(err error, stopped bool) VMState {
	s.Running = false
	s.ShowGuestHelp = false
	s.Phase, s.Status = "stopped", "已停止代理"
	for i := range s.Steps {
		if s.Steps[i].State == "active" {
			s.Steps[i].State = "cancelled"
			if err != nil && !stopped {
				s.Steps[i].State = "failed"
				s.Steps[i].Detail = err.Error()
			}
		}
	}
	if err != nil && !stopped {
		s.Phase, s.Status = "error", "错误 · "+err.Error()
	}
	return s
}
