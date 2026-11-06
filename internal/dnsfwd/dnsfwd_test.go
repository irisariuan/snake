package dnsfwd

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

// answer replies to q with name -> 192.0.2.7.
func answer(t *testing.T, q []byte) []byte {
	var p dnsmessage.Parser
	h, err := p.Start(q)
	if err != nil {
		t.Errorf("bad query: %v", err)
		return nil
	}
	qs, _ := p.AllQuestions()
	h.Response, h.RecursionAvailable = true, true
	b := dnsmessage.NewBuilder(nil, h)
	_ = b.StartQuestions()
	for _, x := range qs {
		_ = b.Question(x)
	}
	_ = b.StartAnswers()
	for _, x := range qs {
		_ = b.AResource(dnsmessage.ResourceHeader{Name: x.Name, Class: dnsmessage.ClassINET, TTL: 60}, dnsmessage.AResource{A: [4]byte{192, 0, 2, 7}})
	}
	out, _ := b.Finish()
	return out
}

func query(id uint16, name string) []byte {
	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: id, RecursionDesired: true})
	_ = b.StartQuestions()
	_ = b.Question(dnsmessage.Question{Name: dnsmessage.MustNewName(name), Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET})
	out, _ := b.Finish()
	return out
}

func checkAnswer(t *testing.T, resp []byte, id uint16) {
	t.Helper()
	var p dnsmessage.Parser
	h, err := p.Start(resp)
	if err != nil {
		t.Fatalf("bad answer: %v", err)
	}
	if h.ID != id || h.RCode != dnsmessage.RCodeSuccess {
		t.Fatalf("answer id %d rcode %v, want id %d success", h.ID, h.RCode, id)
	}
	_ = p.SkipAllQuestions()
	a, err := p.AnswerHeader()
	if err != nil || a.Type != dnsmessage.TypeA {
		t.Fatalf("no A answer: %v", err)
	}
	r, _ := p.AResource()
	if r.A != [4]byte{192, 0, 2, 7} {
		t.Fatalf("got %v", r.A)
	}
}

// tlsCert is the httptest certificate (valid for example.com and 127.0.0.1).
func testTLS(t *testing.T) (*tls.Config, *x509.CertPool) {
	srv := httptest.NewTLSServer(http.NotFoundHandler())
	t.Cleanup(srv.Close)
	pool := x509.NewCertPool()
	pool.AddCert(srv.Certificate())
	return srv.TLS, pool
}

func freeAddr(t *testing.T) string {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return l.Addr().String()
}

func exchangeUDP(t *testing.T, addr string, q []byte) []byte {
	t.Helper()
	c, err := net.Dial("udp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := c.Write(q); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 4096)
	n, err := c.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	return buf[:n]
}

func exchangeTCP(t *testing.T, addr string, q []byte) []byte {
	t.Helper()
	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	msg := make([]byte, 2+len(q))
	binary.BigEndian.PutUint16(msg, uint16(len(q)))
	copy(msg[2:], q)
	if _, err := c.Write(msg); err != nil {
		t.Fatal(err)
	}
	resp, err := readMsg(c)
	if err != nil {
		t.Fatal(err)
	}
	return resp
}

func hostPort(t *testing.T, addr string) (string, int) {
	h, p, _ := net.SplitHostPort(addr)
	n, _ := strconv.Atoi(p)
	return h, n
}

func TestDoT(t *testing.T) {
	cfg, pool := testTLS(t)
	l, err := tls.Listen("tcp", "127.0.0.1:0", cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	var conns atomic.Int32
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			conns.Add(1)
			go func(c net.Conn) {
				defer c.Close()
				for {
					q, err := readMsg(c)
					if err != nil {
						return
					}
					a := answer(t, q)
					out := make([]byte, 2+len(a))
					binary.BigEndian.PutUint16(out, uint16(len(a)))
					copy(out[2:], a)
					_, _ = c.Write(out)
				}
			}(c)
		}
	}()
	ip, port := hostPort(t, l.Addr().String())
	listen := freeAddr(t)
	var m Manager
	if err := m.Configure([]Spec{{ID: 1, Listen: listen, Up: Upstream{Proto: DoT, IP: ip, Port: port, TLSName: "example.com", RootCAs: pool}}}); err != nil {
		t.Fatal(err)
	}
	defer m.Stop()
	checkAnswer(t, exchangeUDP(t, listen, query(4242, "www.example.com.")), 4242)
	checkAnswer(t, exchangeUDP(t, listen, query(7, "a.example.com.")), 7)
	checkAnswer(t, exchangeTCP(t, listen, query(99, "b.example.com.")), 99)
	if n := conns.Load(); n != 1 {
		t.Errorf("sequential queries used %d TLS connections, want 1 (reuse)", n)
	}
	st := m.Stats()[1]
	if st.Queries != 3 || st.Errors != 0 {
		t.Fatalf("stats %+v", st)
	}
	// Several stale idle entries must not consume both attempts: after
	// the first failure, the query must succeed on a fresh connection.
	d := m.srvs[1].ex.(*dot)
	for len(d.pool) > 0 {
		old := <-d.pool
		old.Close()
	}
	for i := 0; i < 3; i++ {
		client, peer := net.Pipe()
		stale := tls.Client(client, tlsConfig(d.up))
		client.Close()
		peer.Close()
		d.pool <- stale
	}
	checkAnswer(t, exchangeUDP(t, listen, query(100, "after-idle.example.com.")), 100)
	if n := conns.Load(); n != 2 {
		t.Errorf("stale pool recovery used %d connections, want 2 total", n)
	}
}

func TestDoH(t *testing.T) {
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/dns-query" || r.Header.Get("Content-Type") != "application/dns-message" || r.Host != "example.com" {
			http.Error(w, "bad request "+r.Host+r.URL.Path, 400)
			return
		}
		q, _ := io.ReadAll(r.Body)
		if q[0] != 0 || q[1] != 0 {
			http.Error(w, "id must be 0", 400)
			return
		}
		w.Header().Set("Content-Type", "application/dns-message")
		_, _ = w.Write(answer(t, q))
	}))
	srv.EnableHTTP2 = true
	srv.StartTLS()
	defer srv.Close()
	pool := x509.NewCertPool()
	pool.AddCert(srv.Certificate())
	ip, port := hostPort(t, srv.Listener.Addr().String())
	listen := freeAddr(t)
	var m Manager
	if err := m.Configure([]Spec{{ID: 2, Listen: listen, Up: Upstream{Proto: DoH, IP: ip, Port: port, TLSName: "example.com", Path: "/dns-query", RootCAs: pool}}}); err != nil {
		t.Fatal(err)
	}
	defer m.Stop()
	checkAnswer(t, exchangeUDP(t, listen, query(1234, "www.example.com.")), 1234)
	checkAnswer(t, exchangeTCP(t, listen, query(55, "c.example.com.")), 55)
}

func TestFailureIsServfail(t *testing.T) {
	// Wrong certificate name: the TLS handshake fails, the client gets
	// SERVFAIL at once (never a plain-DNS fallback).
	cfg, pool := testTLS(t)
	l, _ := tls.Listen("tcp", "127.0.0.1:0", cfg)
	defer l.Close()
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go func() { _ = c.(*tls.Conn).Handshake(); c.Close() }()
		}
	}()
	ip, port := hostPort(t, l.Addr().String())
	listen := freeAddr(t)
	var m Manager
	if err := m.Configure([]Spec{{ID: 3, Listen: listen, Up: Upstream{Proto: DoT, IP: ip, Port: port, TLSName: "wrong.name", RootCAs: pool}}}); err != nil {
		t.Fatal(err)
	}
	defer m.Stop()
	resp := exchangeUDP(t, listen, query(77, "x.example.com."))
	var p dnsmessage.Parser
	h, err := p.Start(resp)
	if err != nil {
		t.Fatal(err)
	}
	if h.ID != 77 || h.RCode != dnsmessage.RCodeServerFailure || !h.Response {
		t.Fatalf("got %+v", h)
	}
	if st := m.Stats()[3]; st.Errors != 1 || st.LastError == "" {
		t.Fatalf("stats %+v", st)
	}
}

func TestReconfigure(t *testing.T) {
	var m Manager
	a := Spec{ID: 1, Listen: freeAddr(t), Up: Upstream{Proto: DoT, IP: "127.0.0.1", TLSName: "x"}}
	if err := m.Configure([]Spec{a}); err != nil {
		t.Fatal(err)
	}
	s1 := m.srvs[1]
	_ = m.Configure([]Spec{a})
	if m.srvs[1] != s1 {
		t.Fatal("unchanged spec restarted the forwarder")
	}
	a.Up.TLSName = "y"
	_ = m.Configure([]Spec{a})
	if m.srvs[1] == s1 {
		t.Fatal("changed spec kept the old forwarder")
	}
	m.Stop()
	if len(m.srvs) != 0 {
		t.Fatal("stop left forwarders")
	}
}

func TestOccupiedPortsAndSharedResolver(t *testing.T) {
	for _, transport := range []string{"udp", "tcp"} {
		t.Run(transport, func(t *testing.T) {
			var addr string
			if transport == "udp" {
				l, err := net.ListenPacket("udp", "127.0.0.1:0")
				if err != nil {
					t.Fatal(err)
				}
				defer l.Close()
				addr = l.LocalAddr().String()
			} else {
				l, err := net.Listen("tcp", "127.0.0.1:0")
				if err != nil {
					t.Fatal(err)
				}
				defer l.Close()
				addr = l.Addr().String()
			}
			var m Manager
			defer m.Stop()
			up := Upstream{Proto: DoT, IP: "9.9.9.9", TLSName: "dns.quad9.net", Disabled: true}
			if err := m.Configure([]Spec{{ID: 1, Listen: addr, Up: up}, {ID: 2, Listen: addr, Up: up}}); err != nil {
				t.Fatal(err)
			}
			st := m.Stats()
			if st[1].Listen == addr || st[2].Listen == addr || st[1].Listen == st[2].Listen {
				t.Fatalf("listeners collided: %v", st)
			}
			for _, s := range st {
				for _, response := range [][]byte{exchangeUDP(t, s.Listen, query(55, "test.example.")), exchangeTCP(t, s.Listen, query(55, "test.example."))} {
					var p dnsmessage.Parser
					h, err := p.Start(response)
					if err != nil || h.RCode != dnsmessage.RCodeServerFailure {
						t.Fatalf("disabled tunnel did not fail closed: %v %v", h, err)
					}
				}
			}
			first := m.srvs[1]
			if err := m.Configure([]Spec{{ID: 1, Listen: addr, Up: up}, {ID: 2, Listen: addr, Up: up}}); err != nil {
				t.Fatal(err)
			}
			if m.srvs[1] != first {
				t.Fatal("allocated listener changed on an unchanged apply")
			}
		})
	}
}

func TestMDNSReservedAndPartialFailure(t *testing.T) {
	var m Manager
	defer m.Stop()
	up := Upstream{Proto: DoT, IP: "9.9.9.9", TLSName: "dns.quad9.net", Disabled: true}
	err := m.Configure([]Spec{{ID: 3, Listen: "127.0.0.1:5353", Up: up}, {ID: 4, Listen: "not-an-address", Up: up}})
	if err == nil {
		t.Fatal("invalid listener unexpectedly succeeded")
	}
	ready := m.Endpoints()
	if ready[3] == "" || ready[3] == "127.0.0.1#5353" || ready[4] != "" {
		t.Fatalf("unsafe readiness map: %v", ready)
	}
}
