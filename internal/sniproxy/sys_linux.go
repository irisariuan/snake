package sniproxy

import (
	"encoding/binary"
	"errors"
	"net"
	"net/netip"
	"sync"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

// soOriginalDst is SO_ORIGINAL_DST (IPv4) and IP6T_SO_ORIGINAL_DST (IPv6):
// the destination a connection had before iptables REDIRECT.
const soOriginalDst = 80

// originalDst returns the pre-REDIRECT destination of an accepted
// connection.
func originalDst(c *net.TCPConn) (netip.AddrPort, error) {
	raw, err := c.SyscallConn()
	if err != nil {
		return netip.AddrPort{}, err
	}
	local, _ := c.LocalAddr().(*net.TCPAddr)
	v6 := local != nil && local.IP.To4() == nil
	var ap netip.AddrPort
	var serr error
	err = raw.Control(func(fd uintptr) {
		if v6 {
			// sockaddr_in6 (28 bytes) fits IPv6MTUInfo's leading field.
			var info *unix.IPv6MTUInfo
			info, serr = unix.GetsockoptIPv6MTUInfo(int(fd), unix.IPPROTO_IPV6, soOriginalDst)
			if serr == nil {
				var p [2]byte
				binary.NativeEndian.PutUint16(p[:], info.Addr.Port)
				ap = netip.AddrPortFrom(netip.AddrFrom16(info.Addr.Addr), binary.BigEndian.Uint16(p[:]))
			}
			return
		}
		// sockaddr_in (16 bytes) fits IPv6Mreq's 16-byte address field.
		var m *unix.IPv6Mreq
		m, serr = unix.GetsockoptIPv6Mreq(int(fd), unix.IPPROTO_IP, soOriginalDst)
		if serr == nil {
			a := m.Multiaddr
			ap = netip.AddrPortFrom(netip.AddrFrom4([4]byte{a[4], a[5], a[6], a[7]}), uint16(a[2])<<8|uint16(a[3]))
		}
	})
	if err == nil {
		err = serr
	}
	return ap, err
}

// markedDialer dials with SO_MARK set, so the router's policy ip rules
// pick the policy's routing table (tunnel, kill switch or WAN fallback).
func markedDialer(mark uint32, timeout time.Duration) *net.Dialer {
	d := &net.Dialer{Timeout: timeout}
	if mark == 0 {
		return d
	}
	d.Control = func(network, address string, c syscall.RawConn) error {
		var serr error
		err := c.Control(func(fd uintptr) {
			serr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_MARK, int(mark))
		})
		if err != nil {
			return err
		}
		return serr
	}
	return d
}

// neighbors maps LAN client addresses to MAC addresses from the kernel's
// neighbour table (ARP and NDP), for device-scoped policies.
type neighbors struct {
	mu      sync.Mutex
	byIP    map[netip.Addr]string
	fetched time.Time
	// dump returns the table (tests replace it).
	dump func() (map[netip.Addr]string, error)
}

const (
	neighMaxAge   = 30 * time.Second
	neighMinRetry = time.Second
)

// mac returns the client's MAC address, "" if unknown.
func (n *neighbors) mac(ip netip.Addr) string {
	ip = ip.Unmap()
	n.mu.Lock()
	defer n.mu.Unlock()
	m, ok := n.byIP[ip]
	age := time.Since(n.fetched)
	if (ok && age < neighMaxAge) || (!ok && age < neighMinRetry) {
		return m
	}
	dump := n.dump
	if dump == nil {
		dump = dumpNeighbors
	}
	if t, err := dump(); err == nil {
		n.byIP = t
	}
	n.fetched = time.Now()
	return n.byIP[ip]
}

// Neighbour message attributes (linux/neighbour.h).
const (
	ndaDst    = 1
	ndaLLAddr = 2
	ndMsgLen  = 12
)

func dumpNeighbors() (map[netip.Addr]string, error) {
	b, err := syscall.NetlinkRIB(syscall.RTM_GETNEIGH, syscall.AF_UNSPEC)
	if err != nil {
		return nil, err
	}
	msgs, err := syscall.ParseNetlinkMessage(b)
	if err != nil {
		return nil, err
	}
	out := map[netip.Addr]string{}
	for _, m := range msgs {
		if m.Header.Type != syscall.RTM_NEWNEIGH || len(m.Data) < ndMsgLen {
			continue
		}
		var ip netip.Addr
		var mac string
		attrs := m.Data[ndMsgLen:]
		for len(attrs) >= 4 {
			l := int(binary.NativeEndian.Uint16(attrs[0:2]))
			typ := binary.NativeEndian.Uint16(attrs[2:4])
			if l < 4 || l > len(attrs) {
				break
			}
			v := attrs[4:l]
			switch typ {
			case ndaDst:
				if a, ok := netip.AddrFromSlice(v); ok {
					ip = a.Unmap()
				}
			case ndaLLAddr:
				if len(v) == 6 {
					mac = net.HardwareAddr(v).String()
				}
			}
			adv := (l + 3) &^ 3
			if adv > len(attrs) {
				break
			}
			attrs = attrs[adv:]
		}
		if ip.IsValid() && mac != "" && mac != "00:00:00:00:00:00" {
			out[ip] = mac
		}
	}
	if len(out) == 0 && len(msgs) == 0 {
		return nil, errors.New("empty neighbour table")
	}
	return out, nil
}
