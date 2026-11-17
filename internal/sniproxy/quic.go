package sniproxy

// Reading the server name from QUIC (HTTP/3).
//
// A QUIC connection starts with Initial packets whose payload is encrypted,
// but with keys derived from the packet's own Destination Connection ID and
// a salt published in the QUIC specification (RFC 9001 section 5.2, RFC 9369
// for QUIC v2). Anyone on the path can derive them: they protect against
// tampering by off-path attackers, not against observers. The client's
// Initial packets carry the TLS ClientHello in CRYPTO frames, so once they
// are decrypted the server name is read exactly as for TCP.
//
// A ClientHello with post-quantum key shares no longer fits one packet, and
// browsers split (and shuffle) its CRYPTO frames across two or more Initial
// packets. cryptoStream reassembles them.

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"sort"
)

var errNotQUIC = errors.New("not a QUIC Initial packet")

// quicVersion holds what differs between the QUIC versions whose Initial
// packets can be read.
type quicVersion struct {
	salt        []byte
	key, iv, hp string // HKDF labels
	initialType byte   // long header packet type of Initial packets
	retryType   byte   // long header packet type of Retry packets (no Length field)
}

var (
	quicV1 = &quicVersion{
		salt: []byte{0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad, 0xcc, 0xbb, 0x7f, 0x0a},
		key:  "quic key", iv: "quic iv", hp: "quic hp", initialType: 0, retryType: 3,
	}
	quicV2 = &quicVersion{ // RFC 9369
		salt: []byte{0x0d, 0xed, 0xe3, 0xde, 0xf7, 0x00, 0xa6, 0xdb, 0x81, 0x93, 0x81, 0xbe, 0x6e, 0x26, 0x9d, 0xcb, 0xf9, 0xbd, 0x2e, 0xd9},
		key:  "quicv2 key", iv: "quicv2 iv", hp: "quicv2 hp", initialType: 1, retryType: 0,
	}
	quicDraft29 = &quicVersion{ // drafts 29-32, still sent by some older clients
		salt: []byte{0xaf, 0xbf, 0xec, 0x28, 0x99, 0x93, 0xd2, 0x4c, 0x9e, 0x97, 0x86, 0xf1, 0x9c, 0x61, 0x11, 0xe0, 0x43, 0x90, 0xa8, 0x99},
		key:  "quic key", iv: "quic iv", hp: "quic hp", initialType: 0, retryType: 3,
	}
)

func lookupVersion(v uint32) *quicVersion {
	switch {
	case v == 0x00000001:
		return quicV1
	case v == 0x6b3343cf:
		return quicV2
	case v >= 0xff00001d && v <= 0xff000020:
		return quicDraft29
	}
	return nil
}

// expandLabel is TLS 1.3's HKDF-Expand-Label with an empty context.
func expandLabel(secret []byte, label string, n int) []byte {
	full := "tls13 " + label
	info := make([]byte, 0, 4+len(full))
	info = append(info, byte(n>>8), byte(n), byte(len(full)))
	info = append(info, full...)
	info = append(info, 0)
	out, err := hkdf.Expand(sha256.New, secret, string(info), n)
	if err != nil {
		panic(err) // n is a fixed small length
	}
	return out
}

// initialKeys are the client's Initial packet protection keys.
type initialKeys struct {
	aead cipher.AEAD
	iv   []byte
	hp   cipher.Block
}

// clientInitialKeys derives the keys protecting the client's Initial
// packets of a connection with Destination Connection ID dcid.
func clientInitialKeys(v *quicVersion, dcid []byte) (initialKeys, error) {
	key, iv, hpKey, err := clientInitialSecrets(v, dcid)
	if err != nil {
		return initialKeys{}, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return initialKeys{}, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return initialKeys{}, err
	}
	hp, err := aes.NewCipher(hpKey)
	if err != nil {
		return initialKeys{}, err
	}
	return initialKeys{aead: aead, iv: iv, hp: hp}, nil
}

// clientInitialSecrets derives the client's Initial AEAD key, IV and
// header protection key (RFC 9001 section 5.2).
func clientInitialSecrets(v *quicVersion, dcid []byte) (key, iv, hp []byte, err error) {
	initial, err := hkdf.Extract(sha256.New, dcid, v.salt)
	if err != nil {
		return nil, nil, nil, err
	}
	secret := expandLabel(initial, "client in", 32)
	return expandLabel(secret, v.key, 16), expandLabel(secret, v.iv, 12), expandLabel(secret, v.hp, 16), nil
}

// varint reads a QUIC variable-length integer; n is 0 if b is too short.
func varint(b []byte) (v uint64, n int) {
	if len(b) == 0 {
		return 0, 0
	}
	n = 1 << (b[0] >> 6)
	if len(b) < n {
		return 0, 0
	}
	v = uint64(b[0] & 0x3f)
	for _, c := range b[1:n] {
		v = v<<8 | uint64(c)
	}
	return v, n
}

// cryptoFrag is the data of one CRYPTO frame.
type cryptoFrag struct {
	off  uint64
	data []byte
}

// initialPacket is a decrypted client Initial packet.
type initialPacket struct {
	version uint32
	dcid    []byte
	frags   []cryptoFrag
}

// parseDatagram decrypts the client Initial packets in a UDP datagram
// (several QUIC packets may be coalesced into one). Other long header
// packets (0-RTT) are skipped. It returns errNotQUIC when the datagram does
// not start with a client Initial packet of a known version.
func parseDatagram(b []byte) ([]initialPacket, error) {
	var out []initialPacket
	for len(b) > 0 {
		pkt, rest, ok, err := parseLongHeader(b)
		if err != nil {
			if len(out) > 0 {
				break // trailing garbage or padding after the Initial
			}
			return nil, err
		}
		if ok {
			out = append(out, pkt)
		} else if len(out) == 0 {
			return nil, errNotQUIC // must start with an Initial
		}
		b = rest
	}
	if len(out) == 0 {
		return nil, errNotQUIC
	}
	return out, nil
}

// parseLongHeader decrypts one Initial packet at the start of b. ok is
// false (with no error) for another long header packet, which is skipped.
func parseLongHeader(b []byte) (pkt initialPacket, rest []byte, ok bool, err error) {
	if len(b) < 7 || b[0]&0x80 == 0 {
		return pkt, nil, false, errNotQUIC
	}
	ver := binary.BigEndian.Uint32(b[1:5])
	v := lookupVersion(ver)
	if v == nil {
		return pkt, nil, false, errNotQUIC
	}
	typ := b[0] >> 4 & 3
	pos := 5
	dcil := int(b[pos])
	pos++
	if dcil > 20 || len(b) < pos+dcil+1 {
		return pkt, nil, false, errNotQUIC
	}
	dcid := b[pos : pos+dcil]
	pos += dcil
	scil := int(b[pos])
	pos++
	if scil > 20 || len(b) < pos+scil {
		return pkt, nil, false, errNotQUIC
	}
	pos += scil
	if typ == v.retryType {
		return pkt, nil, false, errNotQUIC // servers send Retry, clients do not
	}
	if typ == v.initialType {
		tl, n := varint(b[pos:])
		if n == 0 || uint64(len(b)-pos-n) < tl {
			return pkt, nil, false, errNotQUIC
		}
		pos += n + int(tl)
	}
	length, n := varint(b[pos:])
	if n == 0 || uint64(len(b)-pos-n) < length {
		return pkt, nil, false, errNotQUIC
	}
	pos += n
	end := pos + int(length)
	if typ != v.initialType {
		return pkt, b[end:], false, nil // 0-RTT or Handshake: skip
	}
	// Header protection: a 16-byte sample taken 4 bytes after the start of
	// the packet number masks its length bits and the packet number.
	pnOff := pos
	if pnOff+4+16 > end {
		return pkt, nil, false, errNotQUIC
	}
	keys, err := clientInitialKeys(v, dcid)
	if err != nil {
		return pkt, nil, false, err
	}
	var mask [16]byte
	keys.hp.Encrypt(mask[:], b[pnOff+4:pnOff+20])
	hdr := append([]byte(nil), b[:pnOff+4]...)
	hdr[0] ^= mask[0] & 0x0f
	pnLen := int(hdr[0]&3) + 1
	var pn uint64
	for i := 0; i < pnLen; i++ {
		hdr[pnOff+i] ^= mask[1+i]
		pn = pn<<8 | uint64(hdr[pnOff+i])
	}
	hdr = hdr[:pnOff+pnLen]
	// The packet number is truncated on the wire. A client's first
	// packets have small numbers, so the truncated value is the full one.
	nonce := append([]byte(nil), keys.iv...)
	for i := 0; i < 8; i++ {
		nonce[len(nonce)-1-i] ^= byte(pn >> (8 * i))
	}
	plain, err := keys.aead.Open(nil, nonce, b[pnOff+pnLen:end], hdr)
	if err != nil {
		return pkt, nil, false, errNotQUIC
	}
	frags, err := cryptoFrames(plain)
	if err != nil {
		return pkt, nil, false, err
	}
	return initialPacket{version: ver, dcid: append([]byte(nil), dcid...), frags: frags}, b[end:], true, nil
}

// cryptoFrames extracts the CRYPTO frames of a decrypted Initial payload.
// Only the frames allowed in Initial packets are understood.
func cryptoFrames(p []byte) ([]cryptoFrag, error) {
	var out []cryptoFrag
	next := func(n *int) uint64 {
		v, l := varint(p)
		if l == 0 {
			*n = -1
			return 0
		}
		p = p[l:]
		return v
	}
	for len(p) > 0 {
		typ := p[0]
		p = p[1:]
		ok := 0
		switch typ {
		case 0x00, 0x01: // PADDING, PING
		case 0x02, 0x03: // ACK (with ECN counts)
			next(&ok) // largest acknowledged
			next(&ok) // delay
			ranges := next(&ok)
			next(&ok) // first range
			if ranges > 256 {
				return out, errNotQUIC
			}
			for i := uint64(0); i < ranges && ok == 0; i++ {
				next(&ok)
				next(&ok)
			}
			if typ == 0x03 {
				next(&ok)
				next(&ok)
				next(&ok)
			}
		case 0x06: // CRYPTO
			off := next(&ok)
			n := next(&ok)
			if ok != 0 || n > uint64(len(p)) {
				return out, errNotQUIC
			}
			out = append(out, cryptoFrag{off: off, data: append([]byte(nil), p[:n]...)})
			p = p[n:]
		case 0x1c: // CONNECTION_CLOSE: nothing more to read
			return out, nil
		default:
			return out, errNotQUIC
		}
		if ok != 0 {
			return out, errNotQUIC
		}
	}
	return out, nil
}

// cryptoStream reassembles the CRYPTO frames of a connection's Initial
// packets, which may arrive split, shuffled, repeated or out of order.
type cryptoStream struct {
	frags []cryptoFrag
	size  int // bytes held
}

// add stores frames; it fails when they reach past what a ClientHello may
// use.
func (s *cryptoStream) add(frags []cryptoFrag) error {
	for _, f := range frags {
		if f.off > maxHello || f.off+uint64(len(f.data)) > maxHello {
			return errNotTLS
		}
		if len(f.data) == 0 {
			continue
		}
		s.size += len(f.data)
		if s.size > 2*maxHello {
			return errNotTLS
		}
		s.frags = append(s.frags, f)
	}
	return nil
}

// prefix returns the contiguous bytes from offset 0.
func (s *cryptoStream) prefix() []byte {
	sort.SliceStable(s.frags, func(a, b int) bool { return s.frags[a].off < s.frags[b].off })
	var out []byte
	for _, f := range s.frags {
		if f.off > uint64(len(out)) {
			break
		}
		if end := f.off + uint64(len(f.data)); end > uint64(len(out)) {
			out = append(out, f.data[uint64(len(out))-f.off:]...)
		}
	}
	return out
}

// hello parses the ClientHello once it is complete: errNeedMore while
// bytes are missing, errNotTLS if the stream is not a ClientHello.
func (s *cryptoStream) hello() (Hello, error) {
	b := s.prefix()
	if len(b) < 4 {
		return Hello{}, errNeedMore
	}
	if b[0] != 1 {
		return Hello{}, errNotTLS
	}
	l := int(b[1])<<16 | int(b[2])<<8 | int(b[3])
	if 4+l > maxHello {
		return Hello{}, errNotTLS
	}
	if len(b) < 4+l {
		return Hello{}, errNeedMore
	}
	return parseHelloBody(b[4 : 4+l])
}

// partialHello reads what it can from an incomplete ClientHello: the
// server name if its extension arrived (whether ECH is used may then be
// unknown).
func (s *cryptoStream) partialHello() Hello {
	b := s.prefix()
	if len(b) < 4 || b[0] != 1 {
		return Hello{}
	}
	return parsePartialHello(b[4:])
}
