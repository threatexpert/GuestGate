package capture

import (
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"unicode/utf8"
	"unsafe"

	"golang.org/x/sys/windows"
)

type library struct {
	start, status, stop, open, event *windows.Proc
	roots                            *x509.CertPool
}

var loadLibrary = sync.OnceValues(func() (*library, error) {
	exe, err := os.Executable()
	if err != nil {
		return nil, err
	}
	return bindLibrary(filepath.Join(filepath.Dir(exe), "GuestGateRecorder.dll"))
})

func bindLibrary(path string) (*library, error) {
	handle, err := windows.LoadLibraryEx(path, 0, windows.LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR|windows.LOAD_LIBRARY_SEARCH_SYSTEM32)
	if err != nil {
		return nil, fmt.Errorf("加载 GuestGateRecorder.dll：%w", err)
	}
	d := &windows.DLL{Name: path, Handle: handle}
	l := &library{}
	for name, dest := range map[string]**windows.Proc{"gg_record_start": &l.start, "gg_record_status": &l.status, "gg_record_stop": &l.stop, "gg_tap_open": &l.open, "gg_tap_event": &l.event} {
		*dest, err = d.FindProc(name)
		if err != nil {
			d.Release()
			return nil, err
		}
	}
	rootsProc, err := d.FindProc("gg_roots")
	if err != nil {
		d.Release()
		return nil, err
	}
	n, _, _ := rootsProc.Call(0, 0)
	if n == 0 || n > 4<<20 {
		d.Release()
		return nil, errors.New("录制模块的 CA 列表无效")
	}
	der := make([]byte, n)
	rootsProc.Call(uintptr(unsafe.Pointer(&der[0])), n)
	certs, err := x509.ParseCertificates(der)
	if err != nil {
		d.Release()
		return nil, err
	}
	l.roots = x509.NewCertPool()
	for _, cert := range certs {
		l.roots.AddCert(cert)
	}
	return l, nil
}

type Recorder struct {
	ca        *authority
	lib       *library
	Directory string
	mu        sync.Mutex
	handle    uintptr
	next      uint64
	taps      map[*Tap]struct{}
	failure   error
}
type Tap struct {
	r        *Recorder
	handle   uintptr
	datagram bool
}

func Start(vm, root string) (*Recorder, error) {
	l, err := loadLibrary()
	if err != nil {
		return nil, err
	}
	ca, err := loadAuthority()
	if err != nil {
		return nil, err
	}
	return l.startVM(vm, root, ca)
}

func (l *library) startVM(vm, root string, ca *authority) (*Recorder, error) {
	dir, err := Recordings(vm, root)
	if err != nil {
		return nil, err
	}
	r, err := l.startRecording(ca, dir)
	if err != nil {
		return nil, err
	}
	meta, err := json.MarshalIndent(map[string]string{"application": "GuestGate", "vmx": filepath.Base(vm), "vm_id": recordingVMID(vm), "scope": "Guest gateway TCP and UDP; guest process identity unavailable; QUIC is recorded as UDP."}, "", "  ")
	if err == nil {
		err = os.WriteFile(filepath.Join(r.Directory, "guestgate.json"), meta, 0600)
	}
	if err != nil {
		return nil, errors.Join(err, r.Close())
	}
	return r, nil
}
func (l *library) startRecording(ca *authority, dir string) (*Recorder, error) {
	path, err := windows.BytePtrFromString(dir)
	if err != nil {
		return nil, err
	}
	out := make([]byte, 32768)
	h, _, _ := l.start.Call(uintptr(unsafe.Pointer(path)), uintptr(unsafe.Pointer(&out[0])), uintptr(len(out)))
	if h == 0 {
		return nil, fmt.Errorf("无法开始录制：%s", windows.ByteSliceToString(out))
	}
	return &Recorder{ca: ca, lib: l, Directory: windows.ByteSliceToString(out), handle: h, taps: make(map[*Tap]struct{})}, nil
}
func (r *Recorder) Status() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.failure != nil {
		return r.failure
	}
	if r.handle == 0 {
		return errors.New("录制已停止")
	}
	var out [1024]byte
	n, _, _ := r.lib.status.Call(r.handle, uintptr(unsafe.Pointer(&out[0])), uintptr(len(out)))
	if int32(n) < 0 {
		r.failure = errors.New("录制停止：" + windows.ByteSliceToString(out[:]))
	}
	return r.failure
}
func (r *Recorder) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.handle == 0 {
		return r.failure
	}
	for t := range r.taps {
		t.closeLocked("GuestGate 录制已停止")
	}
	var out [2048]byte
	n, _, _ := r.lib.stop.Call(r.handle, uintptr(unsafe.Pointer(&out[0])), uintptr(len(out)))
	r.handle = 0
	if int32(n) < 0 {
		return fmt.Errorf("完成录制失败：%s", windows.ByteSliceToString(out[:]))
	}
	return r.failure
}
func (r *Recorder) Open(destination, name, alpn string, decrypted, udp bool) *Tap {
	return r.open(destination, name, alpn, decrypted, udp, false)
}
func (r *Recorder) Failed(destination string, udp bool, err error) {
	if r != nil {
		r.open(destination, "", "", false, udp, true).Close(err.Error())
	}
}
func (r *Recorder) open(destination, name, alpn string, decrypted, udp, failed bool) *Tap {
	if r == nil {
		return nil
	}
	if strings.IndexByte(alpn, 0) >= 0 || !utf8.ValidString(alpn) {
		alpn = ""
	}
	_, port, _ := net.SplitHostPort(destination)
	portNumber, _ := strconv.Atoi(port)
	dst, e1 := windows.BytePtrFromString(destination)
	host, e2 := windows.BytePtrFromString(name)
	proto, e3 := windows.BytePtrFromString(alpn)
	if e1 != nil || e2 != nil || e3 != nil {
		return nil
	}
	mode := uintptr(0)
	if udp {
		mode = 2
	} else if decrypted {
		mode = 1
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.handle == 0 || r.failure != nil {
		return nil
	}
	if failed {
		mode |= 4
	}
	r.next++
	h, _, _ := r.lib.open.Call(r.handle, uintptr(r.next), uintptr(unsafe.Pointer(dst)), uintptr(unsafe.Pointer(host)), uintptr(unsafe.Pointer(proto)), uintptr(portNumber), mode)
	if h == 0 {
		r.failure = errors.New("录制器未能接收新连接，请检查磁盘空间及录制容量")
		return nil
	}
	t := &Tap{r, h, udp}
	r.taps[t] = struct{}{}
	return t
}
func (t *Tap) event(op, side uintptr, b []byte) {
	var p *byte
	if len(b) > 0 {
		p = &b[0]
	}
	n, _, _ := t.r.lib.event.Call(t.handle, op, side, uintptr(unsafe.Pointer(p)), uintptr(len(b)))
	if int32(n) < 0 {
		t.r.failure = errors.New("录制器未能写入网络事件")
	}
}
func (t *Tap) Data(side uintptr, b []byte) {
	if t == nil {
		return
	}
	t.r.mu.Lock()
	defer t.r.mu.Unlock()
	if t.handle == 0 {
		return
	}
	if t.datagram {
		t.event(1, side, b)
	} else {
		t.event(0, side, b)
	}
}
func (t *Tap) EOF(side uintptr) {
	if t == nil {
		return
	}
	t.r.mu.Lock()
	defer t.r.mu.Unlock()
	if t.handle != 0 {
		t.event(2, side, nil)
	}
}
func (t *Tap) Note(reason string) {
	if t == nil {
		return
	}
	t.r.mu.Lock()
	defer t.r.mu.Unlock()
	if t.handle != 0 {
		t.event(4, 0, []byte(reason))
	}
}

func (t *Tap) closeLocked(reason string) {
	if t.handle != 0 {
		t.event(3, 0, []byte(reason))
		delete(t.r.taps, t)
		t.handle = 0
	}
}
func (t *Tap) Close(reason string) {
	if t == nil {
		return
	}
	t.r.mu.Lock()
	defer t.r.mu.Unlock()
	t.closeLocked(reason)
}
