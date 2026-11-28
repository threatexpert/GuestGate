package gateway

import "guestgate/internal/capture"

func (g *gateway) setRecording(vm, root string, enable bool, p *setupProgress) error {
	if enable == (g.recording() != nil) {
		return nil
	}
	if enable {
		r, err := capture.Start(vm, root)
		if err != nil {
			return err
		}
		g.capture.Store(r)
		p.state.RecordingDirectory = r.Directory
		p.state.RecordingError = ""
		p.state.Recording = true
		p.activity.add("录制", "已开始录制新连接 · "+r.Directory)
		return nil
	}
	r := g.capture.Swap(nil)
	p.state.Recording = false
	if err := r.Close(); err != nil {
		p.state.RecordingError = err.Error()
		return err
	}
	p.activity.add("录制", "已停止录制并写入索引 · "+r.Directory)
	return nil
}
