package capture

import "net"

type recordedPacket struct {
	net.PacketConn
	tap *Tap
}

func (t *Tap) Packet(c net.PacketConn) net.PacketConn {
	if t == nil {
		return c
	}
	return &recordedPacket{c, t}
}
func (c *recordedPacket) WriteTo(b []byte, addr net.Addr) (int, error) {
	c.tap.Data(0, b)
	return c.PacketConn.WriteTo(b, addr)
}
func (c *recordedPacket) ReadFrom(b []byte) (int, net.Addr, error) {
	n, addr, err := c.PacketConn.ReadFrom(b)
	if err == nil {
		c.tap.Data(1, b[:n])
	}
	return n, addr, err
}
func (c *recordedPacket) Close() error { err := c.PacketConn.Close(); c.tap.Close(""); return err }
