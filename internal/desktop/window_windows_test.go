package desktop

import (
	"testing"

	"golang.org/x/sys/windows"
)

func TestStartupWindowFitsMonitorWorkArea(t *testing.T) {
	for _, tc := range []struct {
		work windows.Rect
		dpi  int32
	}{
		{windows.Rect{Left: 0, Top: 40, Right: 800, Bottom: 600}, 96},
		{windows.Rect{Left: -1280, Top: -120, Right: 0, Bottom: 600}, 144},
		{windows.Rect{Left: 1920, Top: 0, Right: 2944, Bottom: 728}, 192},
		{windows.Rect{Left: 0, Top: 0, Right: 2560, Bottom: 1400}, 120},
	} {
		r := centeredWindow(tc.work, tc.dpi)
		l, tMargin := r.Left-tc.work.Left, r.Top-tc.work.Top
		right, bottom := tc.work.Right-r.Right, tc.work.Bottom-r.Bottom
		if l < 0 || tMargin < 0 || right-l < 0 || right-l > 1 || bottom-tMargin < 0 || bottom-tMargin > 1 {
			t.Fatalf("window %+v not centered inside %+v", r, tc.work)
		}
		if r.Right-r.Left != min(980*tc.dpi/96, tc.work.Right-tc.work.Left-2*(12*tc.dpi/96)) ||
			r.Bottom-r.Top != min(780*tc.dpi/96, tc.work.Bottom-tc.work.Top-2*(12*tc.dpi/96)) {
			t.Fatalf("incorrect size: %+v", r)
		}
	}
}
