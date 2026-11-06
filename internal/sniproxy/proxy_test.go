package sniproxy

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/irisariuan/snake/internal/match"
)

// realHello captures the ClientHello crypto/tls sends for serverName.
func realHello(t *testing.T, serverName string) []byte {
	t.Helper()
	a, b := net.Pipe()
	go func() {
		c := tls.Client(a, &tls.Config{ServerName: serverName, InsecureSkipVerify: true})
		_ = c.Handshake()
	}()
	var buf []byte
	tmp := make([]byte, 4096)
	_ = b.SetReadDeadline(time.Now().Add(2 * time.Second))
	for {
		n, err := b.Read(tmp)
		buf = append(buf, tmp[:n]...)
		if _, perr := parseHello(buf); perr != errNeedMore || err != nil {
			break
		}
	}
	a.Close()
	b.Close()
	return buf
}

// buildHello builds a single-record ClientHello with the given extensions.
func buildHello(exts ...[]byte) []byte {
	var body bytes.Buffer
	body.Write([]byte{3, 3})
	body.Write(make([]byte, 32))
	body.WriteByte(0)                 // session id
	body.Write([]byte{0, 2, 0x13, 1}) // one cipher suite
	body.Write([]byte{1, 0})          // compression: null
	var ext bytes.Buffer
	for _, e := range exts {
		ext.Write(e)
	}
	body.Write([]byte{byte(ext.Len() >> 8), byte(ext.Len())})
	body.Write(ext.Bytes())
	hs := append([]byte{1, 0, byte(body.Len() >> 8), byte(body.Len())}, body.Bytes()...)
	return append([]byte{0x16, 3, 1, byte(len(hs) >> 8), byte(len(hs))}, hs...)
}

func sniExt(name string) []byte {
	n := len(name)
	list := append([]byte{0, byte(n >> 8), byte(n)}, name...)
	data := append([]byte{byte(len(list) >> 8), byte(len(list))}, list...)
	return append([]byte{0, 0, byte(len(data) >> 8), byte(len(data))}, data...)
}

func TestParseRealHello(t *testing.T) {
	b := realHello(t, "WWW.Netflix.com")
	h, err := parseHello(b)
	if err != nil {
		t.Fatal(err)
	}
	if h.ServerName != "www.netflix.com" || h.ECH {
		t.Fatalf("got %+v", h)
	}
	// Every strict prefix asks for more data.
	for i := 0; i < len(b); i += 7 {
		if _, err := parseHello(b[:i]); err != errNeedMore {
			t.Fatalf("prefix %d: %v", i, err)
		}
	}
}

func TestParseFragmentedHello(t *testing.T) {
	one := buildHello(sniExt("api.example.com"))
	hs := one[5:]
	// Split the handshake message over three records.
	var b []byte
	for _, part := range [][]byte{hs[:3], hs[3:20], hs[20:]} {
		b = append(b, 0x16, 3, 1, byte(len(part)>>8), byte(len(part)))
		b = append(b, part...)
	}
	h, err := parseHello(b)
	if err != nil || h.ServerName != "api.example.com" {
		t.Fatalf("got %+v %v", h, err)
	}
}

func TestParseHelloVariants(t *testing.T) {
	ech := []byte{0xfe, 0x0d, 0, 1, 0}
	h, err := parseHello(buildHello(sniExt("cloudflare-ech.com"), ech))
	if err != nil || !h.ECH || h.ServerName != "cloudflare-ech.com" {
		t.Fatalf("ech: %+v %v", h, err)
	}
	h, err = parseHello(buildHello())
	if err != nil || h.ServerName != "" {
		t.Fatalf("no sni: %+v %v", h, err)
	}
	if h, _ := parseHello(buildHello(sniExt("bad name\n.com"))); h.ServerName != "" {
		t.Fatalf("invalid name accepted: %q", h.ServerName)
	}
	for _, b := range [][]byte{[]byte("GET / HTTP/1.1\r\n"), {0x16, 3, 1, 0, 4, 2, 0, 0, 0}, {0x17, 3, 3, 0, 1, 0}} {
		if _, err := parseHello(b); err != errNotTLS {
			t.Errorf("%q: %v, want not TLS", b, err)
		}
	}
	// Truncated extensions are rejected, not read out of bounds.
	b := buildHello(sniExt("example.com"))
	b[len(b)-len(sniExt("example.com"))+2] = 0xff // extension length past the end
	if _, err := parseHello(b); err != errNotTLS {
		t.Errorf("corrupt extension: %v", err)
	}
}

type fakeSets struct {
	mu  sync.Mutex
	add map[string][]string
}

func (f *fakeSets) AddMany(name string, entries []string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.add == nil {
		f.add = map[string][]string{}
	}
	f.add[name] = append(f.add[name], entries...)
	return nil
}

func (f *fakeSets) get(name string) []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.add[name]...)
}

// harness runs a proxy whose "original destination" is an echo server on
// loopback and records the mark of each upstream dial.
type harness struct {
	p     *Proxy
	sets  *fakeSets
	marks chan uint32
	up    net.Listener
}

func newHarness(t *testing.T, pols []Policy, setup ...func(*harness)) *harness {
	t.Helper()
	up, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		for {
			c, err := up.Accept()
			if err != nil {
				return
			}
			go func() { _, _ = io.Copy(c, c); c.Close() }()
		}
	}()
	h := &harness{sets: &fakeSets{}, marks: make(chan uint32, 10), up: up}
	upAddr := up.Addr().(*net.TCPAddr).AddrPort()
	h.p = &Proxy{Sets: h.sets,
		origDst: func(*net.TCPConn) (netip.AddrPort, error) { return upAddr, nil },
		dial: func(ctx context.Context, mark uint32, addr string) (net.Conn, error) {
			h.marks <- mark
			if addr != upAddr.String() {
				return nil, errors.New("wrong destination " + addr)
			}
			var d net.Dialer
			return d.DialContext(ctx, "tcp", addr)
		},
	}
	for _, f := range setup {
		f(h) // before the listener starts
	}
	if err := h.p.Configure(Config{Port: 0, Policies: pols}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { h.p.Stop(); up.Close() })
	return h
}

// send writes payload through the proxy and returns what came back.
func (h *harness) send(t *testing.T, payload []byte) ([]byte, error) {
	t.Helper()
	c, err := net.Dial("tcp4", h.p.Addr())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if _, err := c.Write(payload); err != nil {
		return nil, err
	}
	_ = c.(*net.TCPConn).CloseWrite()
	_ = c.SetReadDeadline(time.Now().Add(3 * time.Second))
	return io.ReadAll(c)
}

func (h *harness) mark(t *testing.T) uint32 {
	t.Helper()
	select {
	case m := <-h.marks:
		return m
	case <-time.After(3 * time.Second):
		t.Fatal("no upstream dial")
		return 0
	}
}

func netflix() Policy {
	return Policy{ID: 1, Name: "nf", Set: match.MustCompile([]string{"netflix.com", "drop:ads.netflix.com", "!skip.netflix.com"}),
		Mark: 0x10000, Set4: "SNK_1_d4", DropSet4: "SNK_1_x4", Session4: "SNK_1_s4"}
}

func TestProxyRoutesBySNI(t *testing.T) {
	other := Policy{ID: 2, Name: "other", Set: match.MustCompile([]string{"skip.netflix.com"}), Mark: 0x20000, Set4: "SNK_2_d4"}
	h := newHarness(t, []Policy{netflix(), other})

	hello := buildHello(sniExt("www.netflix.com"))
	got, err := h.send(t, append(hello, "data"...))
	if err != nil || !bytes.Equal(got, append(hello, "data"...)) {
		t.Fatalf("relay: %v, got %d bytes", err, len(got))
	}
	if m := h.mark(t); m != 0x10000 {
		t.Fatalf("mark %#x, want policy 1", m)
	}
	if s := h.sets.get("SNK_1_d4"); len(s) != 1 || s[0] != "127.0.0.1" {
		t.Fatalf("destination not learned: %v", s)
	}
	if s := h.sets.get("SNK_1_s4"); len(s) != 1 {
		t.Fatalf("session not opened: %v", s)
	}

	// An exclusion in policy 1 lets the next policy match.
	if _, err := h.send(t, buildHello(sniExt("skip.netflix.com"))); err != nil {
		t.Fatal(err)
	}
	if m := h.mark(t); m != 0x20000 {
		t.Fatalf("excluded name: mark %#x, want policy 2", m)
	}

	// Unmatched and non-TLS traffic leaves unmarked (WAN).
	for _, payload := range [][]byte{buildHello(sniExt("example.org")), []byte("SSH-2.0-x\r\n")} {
		got, err := h.send(t, payload)
		if err != nil || !bytes.Equal(got, payload) {
			t.Fatalf("passthrough: %v %q", err, got)
		}
		if m := h.mark(t); m != 0 {
			t.Fatalf("unmatched mark %#x", m)
		}
	}
	st := h.p.Stats()
	if st.Matched != 2 || st.NoSNI != 1 || st.ByPolicy[1] != 1 || st.ByPolicy[2] != 1 {
		t.Fatalf("stats %+v", st)
	}
}

func TestProxyRefusesDrop(t *testing.T) {
	h := newHarness(t, []Policy{netflix()})
	got, _ := h.send(t, buildHello(sniExt("ads.netflix.com")))
	if len(got) != 0 {
		t.Errorf("relayed %d bytes", len(got))
	}
	select {
	case m := <-h.marks:
		t.Fatalf("refused connection dialled upstream (mark %#x)", m)
	case <-time.After(100 * time.Millisecond):
	}
	if s := h.sets.get("SNK_1_x4"); len(s) != 1 {
		t.Fatalf("drop destination not learned: %v", s)
	}
	if st := h.p.Stats(); st.Dropped != 1 || st.Matched != 0 {
		t.Fatalf("stats %+v", st)
	}
}

func TestProxyRoutesECHByOuterName(t *testing.T) {
	ech := Policy{ID: 2, Name: "ech", Set: match.MustCompile([]string{"cloudflare-ech.com"}), Mark: 0x20000}
	h := newHarness(t, []Policy{netflix(), ech})
	ext := []byte{0xfe, 0x0d, 0, 1, 0}
	// The outer name decides: a rule for it routes the connection.
	payload := buildHello(sniExt("cloudflare-ech.com"), ext)
	if got, err := h.send(t, payload); err != nil || !bytes.Equal(got, payload) {
		t.Fatalf("relay: %v", err)
	}
	if m := h.mark(t); m != 0x20000 {
		t.Fatalf("ECH by outer name: mark %#x", m)
	}
	// Without a rule for the outer name it goes via WAN, not dropped.
	payload = buildHello(sniExt("public.example.net"), ext)
	if got, err := h.send(t, payload); err != nil || !bytes.Equal(got, payload) {
		t.Fatalf("relay: %v", err)
	}
	if m := h.mark(t); m != 0 {
		t.Fatalf("unmatched ECH: mark %#x", m)
	}
	if st := h.p.Stats(); st.ECH != 2 || st.Matched != 1 {
		t.Fatalf("stats %+v", st)
	}
}

func TestProxyServerFirstProtocol(t *testing.T) {
	old := helloTimeout
	helloTimeout = 100 * time.Millisecond
	defer func() { helloTimeout = old }()
	h := newHarness(t, []Policy{netflix()})
	c, err := net.Dial("tcp4", h.p.Addr())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	// Say nothing: after the timeout the proxy connects via WAN anyway.
	if m := h.mark(t); m != 0 {
		t.Fatalf("mark %#x", m)
	}
	_, _ = c.Write([]byte("hi"))
	buf := make([]byte, 2)
	_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := io.ReadFull(c, buf); err != nil || string(buf) != "hi" {
		t.Fatalf("%v %q", err, buf)
	}
}

func TestProxyDeviceScope(t *testing.T) {
	pol := netflix()
	pol.MACs = map[string]bool{"aa:bb:cc:dd:ee:ff": true}
	var mac atomic.Value
	mac.Store("11:22:33:44:55:66")
	h := newHarness(t, []Policy{pol}, func(h *harness) {
		h.p.neigh.dump = func() (map[netip.Addr]string, error) {
			return map[netip.Addr]string{netip.MustParseAddr("127.0.0.1"): mac.Load().(string)}, nil
		}
	})
	if _, err := h.send(t, buildHello(sniExt("www.netflix.com"))); err != nil {
		t.Fatal(err)
	}
	if m := h.mark(t); m != 0 {
		t.Fatalf("other device routed: mark %#x", m)
	}
	mac.Store("aa:bb:cc:dd:ee:ff")
	h.p.neigh.mu.Lock()
	h.p.neigh.fetched = time.Time{}
	h.p.neigh.mu.Unlock()
	if _, err := h.send(t, buildHello(sniExt("www.netflix.com"))); err != nil {
		t.Fatal(err)
	}
	if m := h.mark(t); m != 0x10000 {
		t.Fatalf("policy device not routed: mark %#x", m)
	}
}

func TestProxyRefusesDirectConnections(t *testing.T) {
	// The original destination of a connection nobody redirected is the
	// proxy itself.
	h := newHarness(t, []Policy{netflix()}, func(h *harness) {
		h.p.origDst = func(c *net.TCPConn) (netip.AddrPort, error) {
			return c.LocalAddr().(*net.TCPAddr).AddrPort(), nil
		}
	})
	got, _ := h.send(t, buildHello(sniExt("www.netflix.com")))
	if len(got) != 0 || h.p.Stats().Refused != 1 {
		t.Fatalf("direct connection served: %q %+v", got, h.p.Stats())
	}
}

func TestProxyDialFailureResets(t *testing.T) {
	h := newHarness(t, []Policy{netflix()}, func(h *harness) {
		h.p.dial = func(context.Context, uint32, string) (net.Conn, error) {
			return nil, errors.New("network is unreachable")
		}
	})
	got, _ := h.send(t, buildHello(sniExt("www.netflix.com")))
	st := h.p.Stats()
	if len(got) != 0 || st.Errors != 1 || !strings.Contains(st.LastError, "policy nf") {
		t.Fatalf("got %q, stats %+v", got, st)
	}
}

func TestConfigureKeepsListener(t *testing.T) {
	h := newHarness(t, []Policy{netflix()})
	addr := h.p.Addr()
	if err := h.p.Configure(Config{Port: 0, Policies: []Policy{netflix()}}); err != nil {
		t.Fatal(err)
	}
	if h.p.Addr() != addr {
		t.Fatalf("listener restarted: %s -> %s", addr, h.p.Addr())
	}
	h.p.Stop()
	if h.p.Running() {
		t.Fatal("still running")
	}
}

func TestOriginalDstWithoutRedirect(t *testing.T) {
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		c, err := net.Dial("tcp4", ln.Addr().String())
		if err == nil {
			time.Sleep(200 * time.Millisecond)
			c.Close()
		}
	}()
	c, err := ln.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	// Without REDIRECT the kernel either reports the local address (as
	// conntrack saw it) or fails; both are refused by handle.
	ap, err := originalDst(c.(*net.TCPConn))
	if err == nil && ap != c.LocalAddr().(*net.TCPAddr).AddrPort() {
		t.Fatalf("original dst %v, local %v", ap, c.LocalAddr())
	}
}

func TestProxyRefuseECH(t *testing.T) {
	strict := netflix()
	strict.RefuseECH = true
	strict.MACs = map[string]bool{"aa:bb:cc:dd:ee:ff": true}
	open := Policy{ID: 2, Name: "ech", Set: match.MustCompile([]string{"cloudflare-ech.com"}), Mark: 0x20000}
	var mac atomic.Value
	mac.Store("aa:bb:cc:dd:ee:ff")
	h := newHarness(t, []Policy{strict, open}, func(h *harness) {
		h.p.neigh.dump = func() (map[netip.Addr]string, error) {
			return map[netip.Addr]string{netip.MustParseAddr("127.0.0.1"): mac.Load().(string)}, nil
		}
	})
	ext := []byte{0xfe, 0x0d, 0, 1, 0}
	echHello := buildHello(sniExt("cloudflare-ech.com"), ext)

	// The strict policy's device: refused, even though a later policy
	// would route the public name.
	if got, _ := h.send(t, echHello); len(got) != 0 {
		t.Fatalf("relayed %d bytes", len(got))
	}
	select {
	case m := <-h.marks:
		t.Fatalf("refused connection dialled upstream (mark %#x)", m)
	case <-time.After(100 * time.Millisecond):
	}
	// Without ECH the same device is routed as usual.
	if _, err := h.send(t, buildHello(sniExt("www.netflix.com"))); err != nil {
		t.Fatal(err)
	}
	if m := h.mark(t); m != 0x10000 {
		t.Fatalf("plain hello: mark %#x", m)
	}

	// Another device: the strict policy does not apply, ECH is routed.
	mac.Store("11:22:33:44:55:66")
	h.p.neigh.mu.Lock()
	h.p.neigh.fetched = time.Time{}
	h.p.neigh.mu.Unlock()
	if got, err := h.send(t, echHello); err != nil || !bytes.Equal(got, echHello) {
		t.Fatalf("relay: %v", err)
	}
	if m := h.mark(t); m != 0x20000 {
		t.Fatalf("other device: mark %#x", m)
	}
	if st := h.p.Stats(); st.ECH != 2 || st.ECHRefused != 1 {
		t.Fatalf("stats %+v", st)
	}
}
