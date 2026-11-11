// Package dnslookup sends one DNS query to a chosen resolver and returns
// every record of the answer, for the Diagnostics tab's DNS lookup.
package dnslookup

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

// Types are the record types a lookup can ask for.
var Types = map[string]dnsmessage.Type{
	"A": dnsmessage.TypeA, "AAAA": dnsmessage.TypeAAAA, "CNAME": dnsmessage.TypeCNAME,
	"MX": dnsmessage.TypeMX, "TXT": dnsmessage.TypeTXT, "NS": dnsmessage.TypeNS,
	"SOA": dnsmessage.TypeSOA, "PTR": dnsmessage.TypePTR, "SRV": dnsmessage.TypeSRV,
	"HTTPS": dnsmessage.Type(65), "CAA": dnsmessage.Type(257),
}

// Record is one resource record of the answer.
type Record struct {
	Section string `json:"section"` // answer, authority
	Name    string `json:"name"`
	Type    string `json:"type"`
	TTL     uint32 `json:"ttl"`
	Data    string `json:"data"`
}

// Result is the outcome of a lookup.
type Result struct {
	Name   string `json:"name"`
	Type   string `json:"type"`
	Server string `json:"server"`
	Via    string `json:"via,omitempty"`
	Rcode  string `json:"rcode,omitempty"`
	// TookMs is how long the lookup took, including a TCP retry, or
	// until it failed.
	TookMs  float64  `json:"took_ms"`
	TCP     bool     `json:"tcp,omitempty"` // the UDP answer was truncated
	Records []Record `json:"records"`
	Error   string   `json:"error,omitempty"`
}

// Dialer opens a connection to the resolver ("udp" or "tcp").
type Dialer func(ctx context.Context, network, addr string) (net.Conn, error)

// Server normalizes a resolver address: host or host:port, port 53 by
// default; IPv6 with or without brackets.
func Server(s string) (string, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return "", errors.New("resolver required")
	}
	if ap, err := netip.ParseAddrPort(s); err == nil && ap.Port() != 0 {
		return ap.String(), nil
	}
	if a, err := netip.ParseAddr(strings.Trim(s, "[]")); err == nil {
		return netip.AddrPortFrom(a, 53).String(), nil
	}
	host, port, err := net.SplitHostPort(s)
	if err != nil {
		host, port = s, "53"
	}
	if p, err := strconv.Atoi(port); err != nil || p < 1 || p > 65535 {
		return "", fmt.Errorf("bad resolver port %q", port)
	}
	if host == "" || strings.ContainsAny(host, " /") {
		return "", fmt.Errorf("bad resolver %q", s)
	}
	return net.JoinHostPort(host, port), nil
}

// QueryName is the name to ask for: an IP address becomes its reverse
// (in-addr.arpa / ip6.arpa) name, and the type PTR.
func QueryName(name, typ string) (string, string) {
	name = strings.TrimSuffix(strings.TrimSpace(name), ".")
	a, err := netip.ParseAddr(name)
	if err != nil {
		return strings.ToLower(name), typ
	}
	a = a.Unmap()
	var b strings.Builder
	if a.Is4() {
		v := a.As4()
		fmt.Fprintf(&b, "%d.%d.%d.%d.in-addr.arpa", v[3], v[2], v[1], v[0])
	} else {
		v := a.As16()
		for i := 15; i >= 0; i-- {
			fmt.Fprintf(&b, "%x.%x.", v[i]&0xf, v[i]>>4)
		}
		b.WriteString("ip6.arpa")
	}
	return b.String(), "PTR"
}

// Lookup asks server for records of the given type of name, over UDP and
// again over TCP when the answer is truncated.
func Lookup(dial Dialer, server, name, typ string, timeout time.Duration) Result {
	typ = strings.ToUpper(strings.TrimSpace(typ))
	if typ == "" {
		typ = "A"
	}
	name, typ = QueryName(name, typ)
	res := Result{Name: name, Type: typ, Server: server, Records: []Record{}}
	t, ok := Types[typ]
	if !ok {
		res.Error = "unsupported record type " + typ
		return res
	}
	qn, err := dnsmessage.NewName(name + ".")
	if err != nil || name == "" {
		res.Error = "bad name"
		return res
	}
	q := dnsmessage.Message{
		Header:    dnsmessage.Header{ID: uint16(time.Now().UnixNano()), RecursionDesired: true},
		Questions: []dnsmessage.Question{{Name: qn, Type: t, Class: dnsmessage.ClassINET}},
	}
	// EDNS0 for answers over 512 bytes.
	var opt dnsmessage.ResourceHeader
	_ = opt.SetEDNS0(1232, dnsmessage.RCodeSuccess, false)
	q.Additionals = []dnsmessage.Resource{{Header: opt, Body: &dnsmessage.OPTResource{}}}
	buf, err := q.Pack()
	if err != nil {
		res.Error = err.Error()
		return res
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	start := time.Now()
	resp, err := exchange(ctx, dial, "udp", server, buf, q.ID)
	if err == nil && resp.Truncated {
		res.TCP = true
		resp, err = exchange(ctx, dial, "tcp", server, buf, q.ID)
	}
	res.TookMs = float64(time.Since(start).Microseconds()) / 1000
	if err != nil {
		res.Error = err.Error()
		return res
	}
	res.Rcode = rcode(resp.RCode)
	add := func(sec string, rs []dnsmessage.Resource) {
		for _, r := range rs {
			if r.Header.Type == dnsmessage.TypeOPT {
				continue
			}
			res.Records = append(res.Records, Record{Section: sec, Name: strings.TrimSuffix(r.Header.Name.String(), "."),
				Type: typeName(r.Header.Type), TTL: r.Header.TTL, Data: data(r.Body)})
		}
	}
	add("answer", resp.Answers)
	add("authority", resp.Authorities)
	return res
}

func exchange(ctx context.Context, dial Dialer, network, server string, buf []byte, id uint16) (*dnsmessage.Message, error) {
	c, err := dial(ctx, network, server)
	if err != nil {
		return nil, err
	}
	defer c.Close()
	if d, ok := ctx.Deadline(); ok {
		_ = c.SetDeadline(d)
	}
	if network == "tcp" {
		b := make([]byte, 2+len(buf))
		binary.BigEndian.PutUint16(b, uint16(len(buf)))
		copy(b[2:], buf)
		if _, err := c.Write(b); err != nil {
			return nil, err
		}
		var l [2]byte
		if _, err := io.ReadFull(c, l[:]); err != nil {
			return nil, err
		}
		resp := make([]byte, binary.BigEndian.Uint16(l[:]))
		if _, err := io.ReadFull(c, resp); err != nil {
			return nil, err
		}
		return parse(resp, id)
	}
	if _, err := c.Write(buf); err != nil {
		return nil, err
	}
	resp := make([]byte, 65535)
	for {
		n, err := c.Read(resp)
		if err != nil {
			return nil, err
		}
		if m, err := parse(resp[:n], id); err == nil {
			return m, nil
		} // else a stray or mangled datagram: wait for ours
	}
}

func parse(b []byte, id uint16) (*dnsmessage.Message, error) {
	var m dnsmessage.Message
	if err := m.Unpack(b); err != nil {
		return nil, err
	}
	if m.ID != id || !m.Response {
		return nil, errors.New("unexpected DNS message")
	}
	return &m, nil
}

func typeName(t dnsmessage.Type) string {
	for k, v := range Types {
		if v == t {
			return k
		}
	}
	return strings.TrimPrefix(t.String(), "Type")
}

func rcode(r dnsmessage.RCode) string {
	switch r {
	case dnsmessage.RCodeSuccess:
		return "NOERROR"
	case dnsmessage.RCodeFormatError:
		return "FORMERR"
	case dnsmessage.RCodeServerFailure:
		return "SERVFAIL"
	case dnsmessage.RCodeNameError:
		return "NXDOMAIN"
	case dnsmessage.RCodeNotImplemented:
		return "NOTIMP"
	case dnsmessage.RCodeRefused:
		return "REFUSED"
	}
	return "RCODE" + strconv.Itoa(int(r))
}

func host(n dnsmessage.Name) string { return strings.TrimSuffix(n.String(), ".") }

func data(b dnsmessage.ResourceBody) string {
	switch r := b.(type) {
	case *dnsmessage.AResource:
		return netip.AddrFrom4(r.A).String()
	case *dnsmessage.AAAAResource:
		return netip.AddrFrom16(r.AAAA).String()
	case *dnsmessage.CNAMEResource:
		return host(r.CNAME)
	case *dnsmessage.NSResource:
		return host(r.NS)
	case *dnsmessage.PTRResource:
		return host(r.PTR)
	case *dnsmessage.MXResource:
		return fmt.Sprintf("%d %s", r.Pref, host(r.MX))
	case *dnsmessage.SRVResource:
		return fmt.Sprintf("%d %d %d %s", r.Priority, r.Weight, r.Port, host(r.Target))
	case *dnsmessage.TXTResource:
		q := make([]string, len(r.TXT))
		for i, s := range r.TXT {
			q[i] = strconv.Quote(s)
		}
		return strings.Join(q, " ")
	case *dnsmessage.SOAResource:
		return fmt.Sprintf("%s %s %d %d %d %d %d", host(r.NS), host(r.MBox), r.Serial, r.Refresh, r.Retry, r.Expire, r.MinTTL)
	case *dnsmessage.UnknownResource:
		return fmt.Sprintf("\\# %d %x", len(r.Data), r.Data)
	}
	return ""
}
