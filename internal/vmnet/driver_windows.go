package vmnet

import (
	"encoding/binary"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"

	"golang.org/x/sys/windows"
)

// VMnetUserif ABI used by Workstation 17.0.2's vnetsniffer on Windows.
// A handle represents one switch port and is detached by CloseHandle.
const vmnetDevice = `\\.\Global\vmnetuserif`
const (
	vmnetAttach   = 0x81022044
	vmnetSetFlags = 0x81022010
)

type vmnetPort struct {
	handle windows.Handle
	buffer [1600]byte
}

func Open(network string) (Port, error) {
	suffix, ok := strings.CutPrefix(strings.ToLower(network), "vmnet")
	index, err := strconv.ParseUint(suffix, 10, 32)
	if !ok || err != nil {
		return nil, fmt.Errorf("invalid VMnet name %q", network)
	}
	path, err := windows.UTF16PtrFromString(vmnetDevice)
	if err != nil {
		return nil, err
	}
	h, err := windows.CreateFile(path, windows.GENERIC_READ|windows.GENERIC_WRITE, 0, nil, windows.OPEN_EXISTING, windows.FILE_ATTRIBUTE_NORMAL, 0)
	if err != nil {
		return nil, fmt.Errorf("open vmnetuserif: %w", err)
	}
	// The named-network request contains version, selector, VMnet number, then 32 zero bytes.
	var attach [44]byte
	binary.LittleEndian.PutUint32(attach[0:4], 1)
	binary.LittleEndian.PutUint32(attach[4:8], 1)
	binary.LittleEndian.PutUint32(attach[8:12], uint32(index))
	var n uint32
	if err = windows.DeviceIoControl(h, vmnetAttach, &attach[0], uint32(len(attach)), nil, 0, &n, nil); err != nil {
		windows.CloseHandle(h)
		return nil, fmt.Errorf("attach %s: %w", network, err)
	}
	flags := [4]byte{9}
	if err = windows.DeviceIoControl(h, vmnetSetFlags, &flags[0], 4, nil, 0, &n, nil); err != nil {
		windows.CloseHandle(h)
		return nil, fmt.Errorf("enable Ethernet reception: %w", err)
	}
	return &vmnetPort{handle: h}, nil
}
func (p *vmnetPort) ReadFrame() ([]byte, error) {
	var n uint32
	if err := windows.ReadFile(p.handle, p.buffer[:], &n, nil); err != nil {
		return nil, err
	}
	if n == 0 {
		time.Sleep(4 * time.Millisecond)
		return nil, nil
	}
	return append([]byte(nil), p.buffer[:n]...), nil
}
func (p *vmnetPort) WriteFrame(b []byte) error {
	var n uint32
	if err := windows.WriteFile(p.handle, b, &n, nil); err != nil {
		return err
	}
	if int(n) != len(b) {
		return io.ErrShortWrite
	}
	return nil
}
func (p *vmnetPort) Close() { windows.CloseHandle(p.handle) }
