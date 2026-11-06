package dnsfwd

import (
	"net"
	"syscall"
	"time"
)

func upstreamDialer(mark uint32, timeout time.Duration) *net.Dialer {
	d := &net.Dialer{Timeout: timeout}
	if mark != 0 {
		d.Control = func(_, _ string, c syscall.RawConn) error {
			var sockErr error
			err := c.Control(func(fd uintptr) {
				sockErr = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_MARK, int(mark))
			})
			if err != nil {
				return err
			}
			return sockErr
		}
	}
	return d
}
