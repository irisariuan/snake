package sniproxy

import (
	"errors"
	"strings"
)

// maxHello bounds how much of a connection's first bytes are buffered while
// looking for the ClientHello. A ClientHello with post-quantum key shares is
// about 2 KB; one record holds at most 16 KB, and a ClientHello may span a
// few records.
const maxHello = 64 << 10

var (
	errNeedMore = errors.New("need more data")
	errNotTLS   = errors.New("not a TLS ClientHello")
)

// Hello is what snake needs from a ClientHello.
type Hello struct {
	ServerName string // SNI host name, lowercase, no trailing dot ("" if absent)
	ECH        bool   // encrypted_client_hello present: ServerName is the outer (public) name
}

// TLS extension numbers.
const (
	extServerName = 0x0000
	extECH        = 0xfe0d
)

// parseHello parses the TLS records at the start of a connection. It
// returns errNeedMore while the ClientHello is incomplete and errNotTLS when
// the bytes are not a TLS handshake.
func parseHello(b []byte) (Hello, error) {
	msg, err := helloMessage(b)
	if err != nil {
		return Hello{}, err
	}
	return parseHelloBody(msg)
}

// helloMessage reassembles the ClientHello handshake message (without its
// 4-byte header) from one or more handshake records.
func helloMessage(b []byte) ([]byte, error) {
	var hs []byte
	for first := true; ; first = false {
		if len(b) < 5 {
			return nil, errNeedMore
		}
		// Content type handshake, record version 3.x.
		if b[0] != 0x16 || b[1] != 3 {
			return nil, errNotTLS
		}
		n := int(b[3])<<8 | int(b[4])
		if n == 0 || n > 1<<14+256 {
			return nil, errNotTLS
		}
		if len(b) < 5+n {
			if first && 5+n > maxHello {
				return nil, errNotTLS
			}
			return nil, errNeedMore
		}
		hs = append(hs, b[5:5+n]...)
		b = b[5+n:]
		if hs[0] != 1 { // ClientHello
			return nil, errNotTLS
		}
		if len(hs) >= 4 {
			l := int(hs[1])<<16 | int(hs[2])<<8 | int(hs[3])
			if 4+l > maxHello {
				return nil, errNotTLS
			}
			if len(hs) >= 4+l {
				return hs[4 : 4+l], nil
			}
		}
	}
}

// reader walks a byte slice; any read past the end marks it bad.
type reader struct {
	b   []byte
	bad bool
}

func (r *reader) bytes(n int) []byte {
	if r.bad || n < 0 || len(r.b) < n {
		r.bad = true
		return nil
	}
	v := r.b[:n]
	r.b = r.b[n:]
	return v
}

func (r *reader) u8() int {
	v := r.bytes(1)
	if v == nil {
		return 0
	}
	return int(v[0])
}

func (r *reader) u16() int {
	v := r.bytes(2)
	if v == nil {
		return 0
	}
	return int(v[0])<<8 | int(v[1])
}

func parseHelloBody(m []byte) (Hello, error) {
	var h Hello
	r := &reader{b: m}
	r.bytes(2)       // legacy_version
	r.bytes(32)      // random
	r.bytes(r.u8())  // session id
	r.bytes(r.u16()) // cipher suites
	r.bytes(r.u8())  // compression methods
	if r.bad {
		return h, errNotTLS
	}
	if len(r.b) == 0 {
		return h, nil // no extensions
	}
	ext := &reader{b: r.bytes(r.u16())}
	if r.bad {
		return h, errNotTLS
	}
	for len(ext.b) > 0 && !ext.bad {
		typ := ext.u16()
		data := ext.bytes(ext.u16())
		switch typ {
		case extECH:
			h.ECH = true
		case extServerName:
			list := &reader{b: data}
			names := &reader{b: list.bytes(list.u16())}
			for len(names.b) > 0 && !names.bad {
				kind := names.u8()
				name := names.bytes(names.u16())
				if kind == 0 && h.ServerName == "" && !names.bad {
					h.ServerName = strings.TrimSuffix(strings.ToLower(string(name)), ".")
				}
			}
		}
	}
	if ext.bad {
		return h, errNotTLS
	}
	if !validHost(h.ServerName) {
		h.ServerName = ""
	}
	return h, nil
}

// validHost accepts DNS host names only (no IP literals with ports, no
// control characters), so a crafted SNI cannot do anything odd in rule
// matching or logs.
func validHost(s string) bool {
	if s == "" || len(s) > 253 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' || c == '.' || c == '_') {
			return false
		}
	}
	return true
}
