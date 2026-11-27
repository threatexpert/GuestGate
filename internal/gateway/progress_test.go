package gateway

import (
	"errors"
	"testing"
)

func TestSetupProgressKeepsSteps(t *testing.T) {
	var snapshots []VMState
	p := setupProgress{state: InitialState(), report: func(s VMState) { snapshots = append(snapshots, s) }}
	p.step(checkVM, "done", "validated")
	p.step(selectNetwork, "skipped", "already host-only")
	p.step(openGateway, "active", "opening")
	failed := p.state.Finished(errors.New("driver failed"), false)
	if failed.Phase != "error" || failed.Running || failed.Steps[selectNetwork].State != "skipped" || failed.Steps[openGateway].State != "failed" || failed.Steps[setDHCP].State != "pending" {
		t.Fatal(failed)
	}
	cancelled := p.state.Finished(nil, true)
	if cancelled.Phase != "stopped" || cancelled.Steps[openGateway].State != "cancelled" {
		t.Fatal(cancelled)
	}
	p.step(openGateway, "done", "ready")
	p.step(setDHCP, "done", "published")
	p.step(confirmGuest, "active", "waiting")
	if p.state.Phase != "starting" || snapshots[0].Steps[confirmGuest].State != "pending" {
		t.Fatal("premature readiness or mutable snapshot")
	}
	p.step(confirmGuest, "done", "fresh lease")
	if p.state.Phase != "ready" || !p.state.Running || p.state.Steps[openGateway].Detail != "ready" {
		t.Fatal(p.state)
	}
}
