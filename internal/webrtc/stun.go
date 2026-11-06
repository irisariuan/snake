// Package webrtc implements session-affinity tracking for WebRTC traffic that
// belongs to a policy: while a client has a live session with a policy
// destination, STUN messages it sends (ICE connectivity checks, TURN
// allocations, binding requests) reveal the peers/relays its media will use.
// Those addresses are learned into a short-lived ipset so the media flows
// follow the tunnel, while WebRTC from unrelated apps is left on WAN.
package webrtc

import (
	"encoding/binary"
	"net"
)

const stunMagicCookie = 0x2112A442

// IsSTUN reports whether a UDP payload is a STUN message (RFC 5389).
func IsSTUN(p []byte) bool {
	if len(p) < 20 {
		return false
	}
	if p[0]&0xC0 != 0 { // top two bits must be zero
		return false
	}
	if binary.BigEndian.Uint32(p[4:8]) != stunMagicCookie {
		return false
	}
	msgLen := int(binary.BigEndian.Uint16(p[2:4]))
	if msgLen%4 != 0 || 20+msgLen > len(p) {
		return false
	}
	return true
}

// Packet is the subset of a queued packet we care about.
type Packet struct {
	Src, Dst net.IP
	DstPort  uint16
	UDP      bool
	Payload  []byte
}

// Parse extracts IP addresses and the UDP payload from a raw IPv4/IPv6 packet.
func Parse(b []byte) (Packet, bool) {
	var pk Packet
	if len(b) < 1 {
		return pk, false
	}
	var l4 []byte
	switch b[0] >> 4 {
	case 4:
		if len(b) < 20 {
			return pk, false
		}
		ihl := int(b[0]&0x0f) * 4
		if ihl < 20 || len(b) < ihl {
			return pk, false
		}
		// Fragments other than the first carry no UDP header.
		if binary.BigEndian.Uint16(b[6:8])&0x1fff != 0 {
			return pk, false
		}
		pk.Src = net.IP(append([]byte(nil), b[12:16]...))
		pk.Dst = net.IP(append([]byte(nil), b[16:20]...))
		pk.UDP = b[9] == 17
		l4 = b[ihl:]
	case 6:
		if len(b) < 40 {
			return pk, false
		}
		pk.Src = net.IP(append([]byte(nil), b[8:24]...))
		pk.Dst = net.IP(append([]byte(nil), b[24:40]...))
		next := b[6]
		off := 40
		// Skip common extension headers.
		for i := 0; i < 6 && (next == 0 || next == 43 || next == 60); i++ {
			if len(b) < off+8 {
				return pk, false
			}
			next = b[off]
			off += (int(b[off+1]) + 1) * 8
		}
		if off > len(b) {
			return pk, false
		}
		pk.UDP = next == 17
		l4 = b[off:]
	default:
		return pk, false
	}
	if pk.UDP {
		if len(l4) < 8 {
			return pk, false
		}
		pk.DstPort = binary.BigEndian.Uint16(l4[2:4])
		pk.Payload = l4[8:]
	}
	return pk, true
}
