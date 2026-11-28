package upstream

import (
	"context"
	"io"
	"net"
	"os"
	"os/exec"
	"testing"
	"time"
)

// Set GUESTGATE_TEST_GONC to a local GONC executable to check wire compatibility.
func TestGONCInterop(t *testing.T) {
	bin := os.Getenv("GUESTGATE_TEST_GONC")
	if bin == "" {
		t.Skip("set GUESTGATE_TEST_GONC to test against a GONC binary")
	}
	listen := func() net.Listener {
		l, err := net.Listen("tcp4", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		return l
	}
	reservation := listen()
	endpoint := reservation.Addr().String()
	_, port, _ := net.SplitHostPort(endpoint)
	reservation.Close()
	ctx, cancel := context.WithTimeout(t.Context(), 18*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, bin, "-e", ":s5s -u -server-ip 127.0.0.1", "-psk", "interop-test", "-tls", "-k", "-l", "127.0.0.1", port)
	cmd.Dir = t.TempDir()
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { cmd.Process.Kill(); cmd.Wait() }()
	client, err := Parse("socks5s://" + endpoint + "?psk=interop-test")
	if err != nil {
		t.Fatal(err)
	}
	for until := time.Now().Add(7 * time.Second); ; {
		probe, stop := context.WithTimeout(ctx, 500*time.Millisecond)
		err = client.CheckSOCKS(probe)
		stop()
		if err == nil {
			break
		}
		if time.Now().After(until) {
			t.Fatal("GONC startup/handshake", err)
		}
		time.Sleep(80 * time.Millisecond)
	}
	wrong, err := Parse("socks5s://" + endpoint + "?psk=incorrect")
	if err != nil {
		t.Fatal(err)
	}
	if err := wrong.CheckSOCKS(ctx); err == nil {
		t.Fatal("GONC accepted an incorrect PSK")
	}
	listener := listen()
	defer listener.Close()
	go func() {
		c, err := listener.Accept()
		if err == nil {
			defer c.Close()
			io.Copy(c, c)
		}
	}()
	stream, err := client.DialContext(ctx, "tcp", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer stream.Close()
	stream.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err = io.WriteString(stream, "hello"); err != nil {
		t.Fatal(err)
	}
	data := make([]byte, 5)
	if _, err = io.ReadFull(stream, data); err != nil || string(data) != "hello" {
		t.Fatal("TCP round trip", string(data), err)
	}
	target, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer target.Close()
	go func() {
		var b [256]byte
		n, addr, err := target.ReadFrom(b[:])
		if err == nil {
			target.WriteTo(b[:n], addr)
		}
	}()
	packet, err := client.DialPacket(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer packet.Close()
	packet.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err = packet.WriteTo([]byte("gonc!"), target.LocalAddr()); err != nil {
		t.Fatal(err)
	}
	n, addr, err := packet.ReadFrom(data)
	if err != nil || string(data[:n]) != "gonc!" || addr.String() != target.LocalAddr().String() {
		t.Fatal("UDP round trip", string(data[:n]), addr, err)
	}
}
