package netfilter

import (
	"errors"
	"fmt"
	"net"
	"sync/atomic"
	"syscall"

	"github.com/mdlayher/netlink"
	"golang.org/x/sys/unix"
)

// Kernel ipset netlink protocol (include/uapi/linux/netfilter/ipset/ip_set.h).
const (
	nfnlSubsysIPSet = 6
	ipsetProtocol   = 6

	ipsetCmdProtocol = 1
	ipsetCmdAdd      = 9
	ipsetCmdTest     = 11

	ipsetAttrProtocol = 1
	ipsetAttrSetname  = 2
	ipsetAttrData     = 7
	ipsetAttrIP       = 1
	ipsetAttrIPv4     = 1
	ipsetAttrIPv6     = 2

	ipsetErrExist = 4103 // test: element is not in the set
)

// NL adds and tests ipset entries over netlink, without spawning the ipset
// tool (milliseconds per call on a router; this is microseconds). It is safe
// for concurrent use.
type NL struct {
	c      *netlink.Conn
	broken atomic.Bool
}

// OpenNL connects to the kernel and checks that it speaks the ipset
// protocol snake uses.
func OpenNL() (*NL, error) {
	c, err := netlink.Dial(unix.NETLINK_NETFILTER, nil)
	if err != nil {
		return nil, err
	}
	n := &NL{c: c}
	ae := netlink.NewAttributeEncoder()
	ae.Uint8(ipsetAttrProtocol, ipsetProtocol)
	// The protocol command answers with a message of its own: no ACK.
	if _, err := n.execFlags(ipsetCmdProtocol, unix.AF_INET, ae, netlink.Request); err != nil {
		c.Close()
		return nil, fmt.Errorf("ipset netlink protocol: %w", err)
	}
	return n, nil
}

// Close releases the socket.
func (n *NL) Close() error { return n.c.Close() }

// Usable reports whether netlink calls should be tried.
func (n *NL) Usable() bool { return n != nil && !n.broken.Load() }

func (n *NL) exec(cmd uint16, family uint8, ae *netlink.AttributeEncoder) ([]netlink.Message, error) {
	// No NLM_F_EXCL: adding an existing entry succeeds and resets its
	// timeout, like `ipset -exist add`.
	return n.execFlags(cmd, family, ae, netlink.Request|netlink.Acknowledge)
}

func (n *NL) execFlags(cmd uint16, family uint8, ae *netlink.AttributeEncoder, flags netlink.HeaderFlags) ([]netlink.Message, error) {
	attrs, err := ae.Encode()
	if err != nil {
		return nil, err
	}
	// struct nfgenmsg { family, version, res_id (be16) }
	data := append([]byte{family, unix.NFNETLINK_V0, 0, 0}, attrs...)
	return n.c.Execute(netlink.Message{
		Header: netlink.Header{
			Type:  netlink.HeaderType(nfnlSubsysIPSet<<8 | cmd),
			Flags: flags,
		},
		Data: data,
	})
}

func adtMessage(set string, ip net.IP) (*netlink.AttributeEncoder, uint8) {
	family, typ, raw := uint8(unix.AF_INET), uint16(ipsetAttrIPv4), []byte(ip.To4())
	if raw == nil {
		family, typ, raw = unix.AF_INET6, ipsetAttrIPv6, []byte(ip.To16())
	}
	ae := netlink.NewAttributeEncoder()
	ae.Uint8(ipsetAttrProtocol, ipsetProtocol)
	ae.String(ipsetAttrSetname, set)
	ae.Nested(ipsetAttrData, func(d *netlink.AttributeEncoder) error {
		d.Nested(ipsetAttrIP, func(a *netlink.AttributeEncoder) error {
			a.Bytes(typ|netlink.NetByteOrder, raw)
			return nil
		})
		return nil
	})
	return ae, family
}

func errno(err error) syscall.Errno {
	var oe *netlink.OpError
	if errors.As(err, &oe) {
		var en syscall.Errno
		if errors.As(oe.Err, &en) {
			return en
		}
	}
	return 0
}

// Add adds addresses to a set (existing entries are refreshed).
func (n *NL) Add(set string, ips []net.IP) error {
	for _, ip := range ips {
		ae, fam := adtMessage(set, ip)
		if _, err := n.exec(ipsetCmdAdd, fam, ae); err != nil {
			return fmt.Errorf("ipset add %s %s: %w", set, ip, err)
		}
	}
	return nil
}

// Test reports whether ip is in the set.
func (n *NL) Test(set string, ip net.IP) (bool, error) {
	ae, fam := adtMessage(set, ip)
	_, err := n.exec(ipsetCmdTest, fam, ae)
	switch {
	case err == nil:
		return true, nil
	case errno(err) == ipsetErrExist:
		return false, nil
	}
	return false, err
}

// parseIPs returns the entries as plain addresses, or nil if any is not one
// (CIDRs and options go through the ipset tool).
func parseIPs(entries []string) []net.IP {
	out := make([]net.IP, 0, len(entries))
	for _, e := range entries {
		ip := net.ParseIP(e)
		if ip == nil {
			return nil
		}
		out = append(out, ip)
	}
	return out
}
