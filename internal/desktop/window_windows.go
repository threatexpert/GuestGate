package desktop

import (
	"context"
	"unsafe"

	"github.com/wailsapp/wails/v2/pkg/runtime"
	"golang.org/x/sys/windows"
)

var windowAPI = windows.NewLazySystemDLL("user32.dll")

func centeredWindow(work windows.Rect, dpi int32) windows.Rect {
	width, height := work.Right-work.Left, work.Bottom-work.Top
	// Work area and outer window size are in the same coordinate space.
	margin := 12 * dpi / 96
	w := min(980*dpi/96, max(1, width-2*margin))
	h := min(780*dpi/96, max(1, height-2*margin))
	x, y := work.Left+(width-w)/2, work.Top+(height-h)/2
	return windows.Rect{Left: x, Top: y, Right: x + w, Bottom: y + h}
}

func ShowStartupWindow(ctx context.Context, class string) {
	defer runtime.WindowShow(ctx)
	name, _ := windows.UTF16PtrFromString(class)
	hwnd, _, _ := windowAPI.NewProc("FindWindowW").Call(uintptr(unsafe.Pointer(name)), 0)
	if hwnd == 0 {
		return
	}
	// Wails sets ICON_SMALL from resource 3. Set ICON_BIG for the taskbar
	// and Alt+Tab using the same, shared Windows icon resource.
	var module windows.Handle
	if windows.GetModuleHandleEx(windows.GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT, nil, &module) == nil {
		icon, _, _ := windowAPI.NewProc("LoadIconW").Call(uintptr(module), 3)
		if icon != 0 {
			windowAPI.NewProc("SendMessageW").Call(hwnd, 0x0080, 1, icon) // WM_SETICON
		}
	}
	monitor, _, _ := windowAPI.NewProc("MonitorFromWindow").Call(hwnd, 2) // nearest monitor
	var info struct {
		Size          uint32
		Monitor, Work windows.Rect
		Flags         uint32
	}
	info.Size = uint32(unsafe.Sizeof(info))
	ok, _, _ := windowAPI.NewProc("GetMonitorInfoW").Call(monitor, uintptr(unsafe.Pointer(&info)))
	if ok == 0 {
		return
	}
	dpi := int32(96)
	if getDPI := windowAPI.NewProc("GetDpiForWindow"); getDPI.Find() == nil {
		if value, _, _ := getDPI.Call(hwnd); value != 0 {
			dpi = int32(value)
		}
	}
	r := centeredWindow(info.Work, dpi)
	const noZOrderOrActivate = 0x0004 | 0x0010
	windowAPI.NewProc("SetWindowPos").Call(hwnd, 0, uintptr(r.Left), uintptr(r.Top),
		uintptr(r.Right-r.Left), uintptr(r.Bottom-r.Top), noZOrderOrActivate)
}
