package dnslookup

import (
	"context"
	"net"
	"strings"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

// serve answers one query per datagram with handler's message.
func serve(t *testing.T, handler func(q dnsmessage.Message) dnsmessage.Message) (string, func() int) {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", pc.LocalAddr().String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { pc.Close(); ln.Close() })
	tcp := 0
	go func() {
		b := make([]byte, 4096)
		for {
			n, a, err := pc.ReadFrom(b)
			if err != nil {
				return
			}
			var q dnsmessage.Message
			_ = q.Unpack(b[:n])
			r := handler(q)
			out, _ := r.Pack()
			_, _ = pc.WriteTo(out, a)
		}
	}()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			tcp++
			var l [2]byte
			_, _ = c.Read(l[:])
			b := make([]byte, int(l[0])<<8|int(l[1]))
			_, _ = c.Read(b)
			var q dnsmessage.Message
			_ = q.Unpack(b)
			r := handler(q)
			r.Truncated = false
			out, _ := r.Pack()
			_, _ = c.Write(append([]byte{byte(len(out) >> 8), byte(len(out))}, out...))
			c.Close()
		}
	}()
	return pc.LocalAddr().String(), func() int { return tcp }
}

func dialer(ctx context.Context, network, addr string) (net.Conn, error) {
	var d net.Dialer
	return d.DialContext(ctx, network, addr)
}

func TestLookup(t *testing.T) {
	cn := dnsmessage.MustNewName("edge.example.net.")
	srv, _ := serve(t, func(q dnsmessage.Message) dnsmessage.Message {
		h := dnsmessage.ResourceHeader{Name: q.Questions[0].Name, Class: dnsmessage.ClassINET, TTL: 60}
		m := dnsmessage.Message{Header: dnsmessage.Header{ID: q.ID, Response: true}, Questions: q.Questions}
		switch q.Questions[0].Type {
		case dnsmessage.TypeA:
			h.Type = dnsmessage.TypeCNAME
			h2 := dnsmessage.ResourceHeader{Name: cn, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET, TTL: 30}
			m.Answers = []dnsmessage.Resource{{Header: h, Body: &dnsmessage.CNAMEResource{CNAME: cn}}, {Header: h2, Body: &dnsmessage.AResource{A: [4]byte{192, 0, 2, 7}}}}
		case dnsmessage.TypeMX:
			h.Type = dnsmessage.TypeMX
			m.Answers = []dnsmessage.Resource{{Header: h, Body: &dnsmessage.MXResource{Pref: 10, MX: cn}}}
		default:
			m.RCode = dnsmessage.RCodeNameError
		}
		return m
	})
	r := Lookup(dialer, srv, "WWW.Example.com.", "a", 2*time.Second)
	if r.Error != "" || r.Rcode != "NOERROR" || len(r.Records) != 2 {
		t.Fatalf("%+v", r)
	}
	if r.Records[0].Type != "CNAME" || r.Records[0].Data != "edge.example.net" || r.Records[1].Data != "192.0.2.7" || r.Records[1].TTL != 30 || r.Name != "www.example.com" {
		t.Fatalf("records %+v", r.Records)
	}
	if r := Lookup(dialer, srv, "example.com", "MX", 2*time.Second); len(r.Records) != 1 || r.Records[0].Data != "10 edge.example.net" {
		t.Fatalf("MX %+v", r)
	}
	if r := Lookup(dialer, srv, "192.0.2.7", "A", 2*time.Second); r.Rcode != "NXDOMAIN" || r.Type != "PTR" || r.Name != "7.2.0.192.in-addr.arpa" {
		t.Fatalf("PTR %+v", r)
	}
	if r := Lookup(dialer, srv, "example.com", "BOGUS", time.Second); !strings.Contains(r.Error, "unsupported") {
		t.Fatalf("bad type: %+v", r)
	}
}

func TestLookupTruncatedRetriesTCP(t *testing.T) {
	srv, tcp := serve(t, func(q dnsmessage.Message) dnsmessage.Message {
		h := dnsmessage.ResourceHeader{Name: q.Questions[0].Name, Type: dnsmessage.TypeTXT, Class: dnsmessage.ClassINET, TTL: 5}
		return dnsmessage.Message{Header: dnsmessage.Header{ID: q.ID, Response: true, Truncated: true}, Questions: q.Questions,
			Answers: []dnsmessage.Resource{{Header: h, Body: &dnsmessage.TXTResource{TXT: []string{"v=spf1 -all"}}}}}
	})
	r := Lookup(dialer, srv, "example.com", "TXT", 2*time.Second)
	if r.Error != "" || !r.TCP || tcp() != 1 || len(r.Records) != 1 || r.Records[0].Data != `"v=spf1 -all"` {
		t.Fatalf("%+v tcp=%d", r, tcp())
	}
}

func TestServerAndReverse(t *testing.T) {
	for in, want := range map[string]string{"9.9.9.9": "9.9.9.9:53", "1.1.1.1:5353": "1.1.1.1:5353", "2606:4700::1111": "[2606:4700::1111]:53",
		"[2606:4700::1111]:853": "[2606:4700::1111]:853", "dns.example": "dns.example:53"} {
		if got, err := Server(in); err != nil || got != want {
			t.Errorf("Server(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	for _, bad := range []string{"", "1.1.1.1:0", "a b"} {
		if _, err := Server(bad); err == nil {
			t.Errorf("Server(%q) accepted", bad)
		}
	}
	if n, ty := QueryName("2001:db8::1", "A"); ty != "PTR" || !strings.HasPrefix(n, "1.0.0.0.") || !strings.HasSuffix(n, ".8.b.d.0.1.0.0.2.ip6.arpa") {
		t.Fatalf("%s %s", n, ty)
	}
}
