//go:build !linux

package dnsfwd

import (
	"errors"
	"net"
	"syscall"
	"time"
)

func upstreamDialer(up Upstream, timeout time.Duration) *net.Dialer {
	d := &net.Dialer{Timeout: timeout}
	if up.Mark != 0 || up.Iface != "" {
		d.Control = func(_, _ string, _ syscall.RawConn) error {
			return errors.New("marked DNS routing requires Linux")
		}
	}
	return d
}
