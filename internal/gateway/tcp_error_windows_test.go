package gateway

import (
	"context"
	"errors"
	"net"
	"os"
	"strings"
	"testing"

	"golang.org/x/sys/windows"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/stack"

	"guestgate/internal/upstream"
)

func TestGuestSOCKSFailureIsLoggedOnly(t *testing.T) {
	proxy := dnsListener(t)
	client, err := upstream.Parse(proxy.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	h := gatewayHandler{dialer: client, activity: new(activityBatch)}
	id := stack.TransportEndpointID{
		LocalAddress: tcpip.AddrFrom4([4]byte{192, 0, 2, 1}), LocalPort: 443,
		RemoteAddress: tcpip.AddrFrom4([4]byte{192, 0, 2, 11}), RemotePort: 12345,
	}
	done := make(chan error, 1)
	go func() {
		_, err := h.DialTCP(t.Context(), id)
		done <- err
	}()
	c := acceptDNSControl(t, proxy, 0)
	expectDNSCommand(t, c, 1, "192.0.2.1:443")
	dnsReplyCode(t, c, 1, 0)
	if err := <-done; err == nil || h.localTCPError.Load() != nil {
		t.Fatalf("SOCKS failure reached card or guest connected: %v", err)
	}
	entries := h.activity.drain()
	if len(entries) != 2 || entries[1].Kind != "错误" || !strings.Contains(entries[1].Message, "general SOCKS server failure") {
		t.Fatalf("missing upstream failure in activity log: %+v", entries)
	}
	if err := proxy.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := h.DialTCP(t.Context(), id); err == nil || h.localTCPError.Load() == nil {
		t.Fatalf("closed local proxy port did not reach status card: %v", err)
	}
}

func TestLocalTCPDialProblem(t *testing.T) {
	addr := &net.TCPAddr{IP: net.ParseIP("192.0.2.10"), Port: 1080}
	dialErr := func(err error) error {
		return &net.OpError{Op: "socks connect", Err: &net.OpError{Op: "dial", Net: "tcp", Addr: addr, Err: os.NewSyscallError("connectex", err)}}
	}
	for _, err := range []error{dialErr(windows.WSAECONNREFUSED), dialErr(windows.WSAETIMEDOUT), upstream.HTTPStatusError(502), context.DeadlineExceeded, net.ErrClosed, errors.New("general SOCKS server failure")} {
		if problem := localTCPDialProblem(err); problem != "" {
			t.Errorf("%v classified as %q", err, problem)
		}
	}
	for _, err := range []error{windows.WSAEACCES, windows.WSAENOBUFS, windows.WSAEADDRNOTAVAIL, windows.WSAENETDOWN} {
		if problem := localTCPDialProblem(dialErr(err)); !strings.Contains(problem, addr.String()) {
			t.Errorf("%v missing from local status: %q", err, problem)
		}
	}
}
