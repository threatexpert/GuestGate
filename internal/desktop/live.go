package desktop

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"guestgate/internal/gateway"
	"guestgate/internal/upstream"
)

func (a *App) liveCommand(cmd gateway.WorkerCommand) (gateway.ControlResult, error) {
	a.mu.Lock()
	state := a.states[strings.ToLower(cmd.VM)]
	if a.closing || a.pipe == nil || state.Phase != "ready" || state.SessionID != cmd.SessionID {
		a.mu.Unlock()
		return gateway.ControlResult{}, errors.New("原代理会话尚未就绪或已停止")
	}
	if a.replies == nil {
		a.replies = make(map[uint64]chan gateway.ControlResult)
	}
	a.nextRequest++
	cmd.RequestID = a.nextRequest
	reply := make(chan gateway.ControlResult, 1)
	a.replies[cmd.RequestID] = reply
	done := a.done
	err := json.NewEncoder(a.pipe).Encode(cmd)
	a.mu.Unlock()
	defer func() { a.mu.Lock(); delete(a.replies, cmd.RequestID); a.mu.Unlock() }()
	if err != nil {
		return gateway.ControlResult{}, err
	}
	select {
	case res := <-reply:
		if res.Error != "" {
			return res, errors.New(res.Error)
		}
		return res, nil
	case <-done:
		return gateway.ControlResult{}, errors.New("网关进程已退出")
	}
}
func (a *App) Connections(vm, session string, offset int, query, kind string) (*upstream.ConnectionPage, error) {
	res, err := a.liveCommand(gateway.WorkerCommand{Action: "connections", SessionID: session, Offset: offset, Query: query, Kind: kind, Config: gateway.Config{VM: vm}})
	return res.Page, err
}
func (a *App) DisconnectConnection(vm, session string, id uint64) error {
	_, err := a.liveCommand(gateway.WorkerCommand{Action: "disconnect-one", SessionID: session, ConnectionID: id, Config: gateway.Config{VM: vm}})
	return err
}
func (a *App) DisconnectConnections(vm, session string) error {
	_, err := a.liveCommand(gateway.WorkerCommand{Action: "disconnect", SessionID: session, Config: gateway.Config{VM: vm}})
	return err
}
func (a *App) SetRecording(vm, session, root string, on bool) error {
	_, err := a.liveCommand(gateway.WorkerCommand{Action: "record", SessionID: session, Config: gateway.Config{VM: vm, RecordingRoot: root, RecordTraffic: on}})
	return err
}
func (a *App) SwitchUpstream(vm, session, raw string, verify bool) (bool, error) {
	client, err := upstream.Parse(raw)
	if err != nil {
		return false, err
	}
	key := strings.ToLower(vm)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	a.mu.Lock()
	if a.closing || a.states[key].Phase != "ready" || a.states[key].SessionID != session || a.checking[key] != nil {
		a.mu.Unlock()
		return false, fmt.Errorf("会话已变更或有操作正在进行")
	}
	if a.checking == nil {
		a.checking = make(map[string]context.CancelFunc)
	}
	a.checking[key] = cancel
	a.mu.Unlock()
	defer func() { a.mu.Lock(); delete(a.checking, key); a.mu.Unlock() }()
	if verify {
		lookup := a.lookup
		if lookup == nil {
			lookup = lookupExit
		}
		info, err := lookup(ctx, raw)
		if err != nil {
			return false, fmt.Errorf("新上游出口 IP 查询失败：%w", err)
		}
		ok, err := a.confirmExit(ctx, vm, client.Display(), info, true)
		if err != nil || !ok {
			return false, err
		}
	}
	if err := ctx.Err(); err != nil {
		return false, err
	}
	_, err = a.liveCommand(gateway.WorkerCommand{Action: "switch", SessionID: session, Config: gateway.Config{VM: vm, Proxy: raw}})
	return err == nil, err
}
