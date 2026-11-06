package dnsfwd

import (
	"net"
	"syscall"
	"time"
)

func upstreamDialer(up Upstream, timeout time.Duration) *net.Dialer {
	d := &net.Dialer{Timeout: timeout}
	if up.Mark != 0 || up.Iface != "" {
		d.Control = func(_, _ string, c syscall.RawConn) error {
			var sockErr error
			err := c.Control(func(fd uintptr) {
				if up.Iface != "" {
					sockErr = syscall.SetsockoptString(int(fd), syscall.SOL_SOCKET, syscall.SO_BINDTODEVICE, up.Iface)
					if sockErr != nil {
						return
					}
				}
				if up.Mark != 0 {
					sockErr = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_MARK, int(up.Mark))
				}
			})
			if err != nil {
				return err
			}
			return sockErr
		}
	}
	return d
}
