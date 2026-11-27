package vmnet

import (
	"fmt"
	"path/filepath"
	"runtime"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Only resolve the small libpcap ABI we need when the VMware backend fails.
// Separate RX and TX handles keep capture and injection independent.
type npcapPort struct {
	dll                             windows.Handle
	rx, tx                          uintptr
	closeHandle, next, send, geterr uintptr
}

func OpenNpcap(device string) (Port, error) {
	system, err := windows.GetSystemDirectory()
	if err != nil {
		return nil, err
	}
	dll, err := windows.LoadLibraryEx(filepath.Join(system, "Npcap", "wpcap.dll"), 0, windows.LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR|windows.LOAD_LIBRARY_SEARCH_SYSTEM32)
	if err != nil {
		return nil, fmt.Errorf("加载 Npcap（可选安装）: %w", err)
	}
	p := &npcapPort{dll: dll}
	success := false
	defer func() {
		if !success {
			p.Close()
		}
	}()
	var open, nonblock, datalink uintptr
	for name, address := range map[string]*uintptr{"pcap_open_live": &open, "pcap_setnonblock": &nonblock, "pcap_close": &p.closeHandle, "pcap_next_ex": &p.next, "pcap_sendpacket": &p.send, "pcap_geterr": &p.geterr, "pcap_datalink": &datalink} {
		*address, err = windows.GetProcAddress(dll, name)
		if err != nil {
			return nil, err
		}
	}
	dev, err := windows.BytePtrFromString(device)
	if err != nil {
		return nil, err
	}
	var message [256]byte
	openPort := func(promisc uintptr) (uintptr, error) {
		handle, _, _ := syscall.SyscallN(open, uintptr(unsafe.Pointer(dev)), 65535, promisc, 60, uintptr(unsafe.Pointer(&message[0])))
		runtime.KeepAlive(dev)
		if handle == 0 {
			return 0, fmt.Errorf("pcap_open_live: %s", windows.ByteSliceToString(message[:]))
		}
		return handle, nil
	}
	if p.rx, err = openPort(1); err != nil {
		return nil, err
	}
	link, _, _ := syscall.SyscallN(datalink, p.rx)
	if int32(link) != 1 {
		return nil, fmt.Errorf("VMnet is not Ethernet (DLT %d)", link)
	}
	rc, _, _ := syscall.SyscallN(nonblock, p.rx, 1, uintptr(unsafe.Pointer(&message[0])))
	if int32(rc) != 0 {
		return nil, fmt.Errorf("pcap_setnonblock: %s", windows.ByteSliceToString(message[:]))
	}
	if p.tx, err = openPort(0); err != nil {
		return nil, err
	}
	success = true
	return p, nil
}
func (p *npcapPort) portError(handle uintptr) error {
	msg, _, _ := syscall.SyscallN(p.geterr, handle)
	if msg == 0 {
		return fmt.Errorf("Npcap I/O failure")
	}
	// pcap_geterr returns a borrowed C string valid until the next handle call.
	message := *(**byte)(unsafe.Pointer(&msg))
	return fmt.Errorf("Npcap: %s", windows.BytePtrToString(message))
}
func (p *npcapPort) ReadFrame() ([]byte, error) {
	// Windows timeval has two 32-bit longs on both x86 and x64.
	type header struct {
		sec, usec          int32
		captured, original uint32
	}
	var hdr *header
	var data *byte
	rc, _, _ := syscall.SyscallN(p.next, p.rx, uintptr(unsafe.Pointer(&hdr)), uintptr(unsafe.Pointer(&data)))
	switch int32(rc) {
	case 0:
		time.Sleep(4 * time.Millisecond)
		return nil, nil
	case 1:
		if hdr == nil || data == nil || hdr.captured > 65535 {
			return nil, fmt.Errorf("invalid Npcap frame")
		}
		return append([]byte(nil), unsafe.Slice(data, int(hdr.captured))...), nil
	default:
		return nil, p.portError(p.rx)
	}
}
func (p *npcapPort) WriteFrame(frame []byte) error {
	rc, _, _ := syscall.SyscallN(p.send, p.tx, uintptr(unsafe.Pointer(&frame[0])), uintptr(len(frame)))
	runtime.KeepAlive(frame)
	if int32(rc) != 0 {
		return p.portError(p.tx)
	}
	return nil
}
func (p *npcapPort) Close() {
	if p.tx != 0 {
		syscall.SyscallN(p.closeHandle, p.tx)
	}
	if p.rx != 0 {
		syscall.SyscallN(p.closeHandle, p.rx)
	}
	windows.FreeLibrary(p.dll)
}
