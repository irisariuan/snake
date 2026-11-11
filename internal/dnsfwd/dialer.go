package dnsfwd

import (
	"net"
	"time"
)

// Dialer returns a dialer whose sockets carry mark and, when iface is set,
// are bound to that interface, so they cannot leave by another one.
func Dialer(mark uint32, iface string, timeout time.Duration) *net.Dialer {
	return upstreamDialer(Upstream{Mark: mark, Iface: iface}, timeout)
}
