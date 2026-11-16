// Package packet parses the IPv4/IPv6 + UDP/TCP headers of queued packets.
package packet

import (
	"encoding/binary"
	"net"
)

// Packet is the subset of a queued packet we care about.
type Packet struct {
	Src, Dst         net.IP
	SrcPort, DstPort uint16
	UDP              bool
	TCP              bool
	Seq              uint32 // TCP sequence number
	Flags            uint8  // TCP flags (FlagFIN, ...)
	Payload          []byte // UDP or TCP payload
}

// TCP flags.
const (
	FlagFIN = 0x01
	FlagSYN = 0x02
	FlagRST = 0x04
	FlagACK = 0x10
)

// Parse extracts IP addresses and the UDP or TCP payload from a raw
// IPv4/IPv6 packet.
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
		pk.TCP = b[9] == 6
		// Trailing bytes past the total length (padding) are not payload.
		if tot := int(binary.BigEndian.Uint16(b[2:4])); tot >= ihl && tot < len(b) {
			b = b[:tot]
		}
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
		pk.TCP = next == 6
		if pl := int(binary.BigEndian.Uint16(b[4:6])); pl > 0 && 40+pl >= off && 40+pl < len(b) {
			b = b[:40+pl]
		}
		l4 = b[off:]
	default:
		return pk, false
	}
	if pk.UDP {
		if len(l4) < 8 {
			return pk, false
		}
		pk.SrcPort = binary.BigEndian.Uint16(l4[0:2])
		pk.DstPort = binary.BigEndian.Uint16(l4[2:4])
		pk.Payload = l4[8:]
	}
	if pk.TCP {
		if len(l4) < 20 {
			return pk, false
		}
		hl := int(l4[12]>>4) * 4
		if hl < 20 || len(l4) < hl {
			return pk, false
		}
		pk.SrcPort = binary.BigEndian.Uint16(l4[0:2])
		pk.DstPort = binary.BigEndian.Uint16(l4[2:4])
		pk.Seq = binary.BigEndian.Uint32(l4[4:8])
		pk.Flags = l4[13]
		pk.Payload = l4[hl:]
	}
	return pk, true
}
