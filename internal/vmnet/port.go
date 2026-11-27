package vmnet

type Port interface {
	ReadFrame() ([]byte, error) // nil frame means idle; each call returns promptly.
	WriteFrame([]byte) error
	Close()
}
