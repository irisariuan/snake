// Package webrtc implements session-affinity tracking for WebRTC traffic that
// belongs to a policy: while a client has a live session with a policy
// destination, STUN messages it sends (ICE connectivity checks, TURN
// allocations, binding requests) reveal the peers/relays its media will use.
// Those addresses are learned into a short-lived ipset so the media flows
// follow the tunnel, while WebRTC from unrelated apps is left on WAN.
package webrtc

import (
	"encoding/binary"

	"github.com/irisariuan/snake/internal/packet"
)

// Parse is packet.Parse, kept for callers in this package.
var Parse = packet.Parse

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
