//go:build !linux

package dnsfwd

import (
	"errors"
	"net"
	"syscall"
	"time"
)

func upstreamDialer(mark uint32, timeout time.Duration) *net.Dialer {
	d := &net.Dialer{Timeout: timeout}
	if mark != 0 {
		d.Control = func(_, _ string, _ syscall.RawConn) error {
			return errors.New("marked DNS routing requires Linux")
		}
	}
	return d
}
