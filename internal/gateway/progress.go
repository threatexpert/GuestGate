package gateway

type SetupStep struct {
	Title, State, Detail string
}

type VMState struct {
	Running       bool
	Phase, Status string
	Steps         [5]SetupStep
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
	for i, title := range []string{"检查虚拟机与网络", "准备仅主机网络", "启动透明代理网关", "配置 DHCP 网关和 DNS", "确认虚拟机已接入"} {
		s.Steps[i] = SetupStep{Title: title, State: "pending"}
	}
	s.Steps[checkVM].State = "active"
	return s
}

type setupProgress struct {
	state  VMState
	report func(VMState)
}

func (p *setupProgress) step(index int, state, detail string) {
	s := &p.state.Steps[index]
	s.State, s.Detail = state, detail
	if state == "active" {
		p.state.Status = s.Title
	}
	if index == confirmGuest && state == "done" {
		p.state.Phase = "ready"
		p.state.Status = "透明代理已启用"
	}
	p.report(p.state)
}

func (s VMState) Finished(err error, stopped bool) VMState {
	s.Running = false
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
