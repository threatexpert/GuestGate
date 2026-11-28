package gateway

import (
	"errors"
	"net"
	"syscall"

	"golang.org/x/sys/windows"
)

// SOCKS wraps host dial failures and server replies in the same net.OpError.
// Only a native dial to the proxy can establish a local socket fault.
func localTCPDialProblem(err error) string {
	for ; err != nil; err = errors.Unwrap(err) {
		op, ok := err.(*net.OpError)
		if !ok || op.Op != "dial" {
			continue
		}
		addr, ok := op.Addr.(*net.TCPAddr)
		var code syscall.Errno
		if !ok || addr == nil || !errors.As(op.Err, &code) {
			continue
		}
		var message string
		switch code {
		case windows.WSAEACCES:
			message = "Windows 拒绝了本机的连接请求"
		case windows.WSAEADDRINUSE, windows.WSAEADDRNOTAVAIL:
			message = "本机无法分配连接所需的地址或端口"
		case windows.WSAENOBUFS, windows.WSAEMFILE:
			message = "本机套接字资源不足"
		case windows.WSAENETDOWN:
			message = "本机网络不可用"
		case windows.WSAECONNREFUSED:
			if !addr.IP.IsLoopback() {
				return ""
			}
			message = "本机代理端口拒绝连接"
		default:
			return ""
		}
		return message + " · " + addr.String()
	}
	return ""
}
