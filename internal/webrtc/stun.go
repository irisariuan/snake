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

// Target is what a STUN message's destination is.
type Target int

const (
	// TargetPeer is a media peer: ICE connectivity checks, responses and
	// indications. Peers are routed only inside a session window.
	TargetPeer Target = iota
	// TargetServer is a STUN or TURN server: plain binding requests (server
	// reflexive candidate gathering) and TURN requests. Servers are reused
	// across sessions, so they stay routed after the session ends.
	TargetServer
)

// STUN methods (RFC 5389, RFC 5766).
const (
	methodBinding          = 0x001
	methodAllocate         = 0x003
	methodRefresh          = 0x004
	methodSend             = 0x006
	methodCreatePermission = 0x008
	methodChannelBind      = 0x009
)

// Attributes that only ICE connectivity checks carry (RFC 8445).
var iceAttrs = map[uint16]bool{
	0x0006: true, // USERNAME
	0x0024: true, // PRIORITY
	0x0025: true, // USE-CANDIDATE
	0x8029: true, // ICE-CONTROLLED
	0x802A: true, // ICE-CONTROLLING
}

// Classify reports whether a STUN message (IsSTUN must be true) is sent to a
// server or to a peer. Anything ambiguous is a peer, which keeps it
// session-gated.
func Classify(p []byte) Target {
	t := binary.BigEndian.Uint16(p[0:2])
	method := t&0x000F | (t&0x00E0)>>1 | (t&0x3E00)>>2
	class := (t&0x0010)>>4 | (t&0x0100)>>7 // 0 request, 1 indication, 2/3 response
	switch method {
	case methodAllocate, methodRefresh, methodCreatePermission, methodChannelBind:
		if class == 0 {
			return TargetServer
		}
	case methodSend:
		if class == 1 {
			return TargetServer
		}
	case methodBinding:
		if class != 0 {
			return TargetPeer
		}
		end := 20 + int(binary.BigEndian.Uint16(p[2:4]))
		for off := 20; off+4 <= end; {
			typ := binary.BigEndian.Uint16(p[off : off+2])
			if iceAttrs[typ] {
				return TargetPeer
			}
			l := int(binary.BigEndian.Uint16(p[off+2 : off+4]))
			off += 4 + (l+3)&^3
		}
		return TargetServer
	}
	return TargetPeer
}
