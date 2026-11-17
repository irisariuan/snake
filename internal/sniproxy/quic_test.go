package sniproxy

import (
	"bufio"
	"context"
	"crypto/aes"
	"crypto/tls"
	"encoding/binary"
	"encoding/hex"
	"math/rand"
	"net"
	"net/netip"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/irisariuan/snake/internal/match"
)

func unhex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(strings.ReplaceAll(s, " ", ""))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// RFC 9001 appendix A and RFC 9369 appendix A.
func TestQUICInitialSecrets(t *testing.T) {
	dcid := unhex(t, "8394c8f03e515708")
	for _, c := range []struct {
		v           *quicVersion
		key, iv, hp string
	}{
		{quicV1, "1f369613dd76d5467730efcbe3b1a22d", "fa044b2f42a3fd3b46fb255c", "9f50449e04a0e810283a1e9933adedd2"},
		{quicV2, "8b1a0bc121284290a29e0971b5cd045d", "91f73e2351d8fa91660e909f", "45b95e15235d6f45a6b19cbcb0294ba9"},
	} {
		key, iv, hp, err := clientInitialSecrets(c.v, dcid)
		if err != nil || hex.EncodeToString(key) != c.key || hex.EncodeToString(iv) != c.iv || hex.EncodeToString(hp) != c.hp {
			t.Errorf("%s: key %x iv %x hp %x %v", c.v.key, key, iv, hp, err)
		}
	}
	// Header protection mask of the RFC 9001 A.2 client Initial.
	block, _ := aes.NewCipher(unhex(t, "9f50449e04a0e810283a1e9933adedd2"))
	var mask [16]byte
	block.Encrypt(mask[:], unhex(t, "d1b1c98dd7689fb8ec11d242b123dc9b"))
	if hex.EncodeToString(mask[:5]) != "437b9aec36" {
		t.Errorf("mask %x", mask[:5])
	}
}

func TestVarint(t *testing.T) {
	for _, c := range []struct {
		in   string
		v    uint64
		n    int
		fail bool
	}{
		{"25", 37, 1, false}, {"7bbd", 15293, 2, false}, {"9d7f3e7d", 494878333, 4, false},
		{"c2197c5eff14e88c", 151288809941952652, 8, false}, {"7b", 0, 0, true},
	} {
		v, n := varint(unhex(t, c.in))
		if v != c.v || n != c.n {
			t.Errorf("%s: %d %d", c.in, v, n)
		}
	}
}

// realInitials are client Initial datagrams of a real QUIC stack.
func realInitials(t *testing.T) map[string][]byte {
	t.Helper()
	f, err := os.Open("testdata/quic_initials.txt")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	out := map[string][]byte{}
	sc := bufio.NewScanner(f)
	sc.Buffer(nil, 1<<20)
	for sc.Scan() {
		fs := strings.Fields(sc.Text())
		if len(fs) != 4 || strings.HasPrefix(fs[0], "#") {
			continue
		}
		out[fs[0]+" "+fs[1]] = unhex(t, fs[3])
	}
	return out
}

func TestQUICRealInitials(t *testing.T) {
	got := 0
	for k, d := range realInitials(t) {
		pkts, err := parseDatagram(d)
		if err != nil {
			t.Fatalf("%s: %v", k, err)
		}
		var s cryptoStream
		for _, p := range pkts {
			if err := s.add(p.frags); err != nil {
				t.Fatal(err)
			}
		}
		h, err := s.hello()
		if want := strings.Fields(k)[1]; err != nil || h.ServerName != want || h.ECH {
			t.Errorf("%s: %+v %v", k, h, err)
		}
		got++
		// Any change to the protected packet is detected. (aioquic pads
		// the datagram after the packet, so change a byte inside it.)
		bad := append([]byte(nil), d...)
		bad[300] ^= 1
		if _, err := parseDatagram(bad); err == nil {
			t.Errorf("%s: corrupted packet accepted", k)
		}
	}
	if got != 2 {
		t.Fatalf("%d fixtures", got)
	}
}

// quicHello returns the ClientHello crypto/tls sends over QUIC (handshake
// message, no record header). With its post-quantum key share it is too
// big for one packet, like a browser's.
func quicHello(t *testing.T, name string) []byte {
	t.Helper()
	c := tls.QUICClient(&tls.QUICConfig{TLSConfig: &tls.Config{ServerName: name, MinVersion: tls.VersionTLS13, NextProtos: []string{"h3"}}})
	c.SetTransportParameters([]byte{0x04, 0x04, 0x80, 0x10, 0x00, 0x00})
	if err := c.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	for {
		ev := c.NextEvent()
		switch ev.Kind {
		case tls.QUICNoEvent:
			t.Fatal("no ClientHello")
		case tls.QUICWriteData:
			if ev.Level == tls.QUICEncryptionLevelInitial {
				return append([]byte(nil), ev.Data...)
			}
		}
	}
}

// helloMsg strips the record header from buildHello's output.
func helloMsg(rec []byte) []byte { return rec[5:] }

func appendVarint(b []byte, v uint64) []byte {
	switch {
	case v < 1<<6:
		return append(b, byte(v))
	case v < 1<<14:
		return append(b, byte(v>>8)|0x40, byte(v))
	default:
		return append(b, byte(v>>24)|0x80, byte(v>>16), byte(v>>8), byte(v))
	}
}

func cryptoFrame(off int, data []byte) []byte {
	f := appendVarint([]byte{0x06}, uint64(off))
	f = appendVarint(f, uint64(len(data)))
	return append(f, data...)
}

// sealInitial builds a protected client Initial packet carrying frames,
// padded to the 1200 bytes clients must send.
func sealInitial(t *testing.T, v *quicVersion, ver uint32, dcid []byte, pn uint32, frames []byte) []byte {
	t.Helper()
	keys, err := clientInitialKeys(v, dcid)
	if err != nil {
		t.Fatal(err)
	}
	hdrLen := 1 + 4 + 1 + len(dcid) + 1 + 0 + 1 + 2 + 2 // no SCID, empty token, 2-byte length, 2-byte pn
	if pad := 1200 - hdrLen - len(frames) - 16; pad > 0 {
		frames = append(frames, make([]byte, pad)...) // PADDING frames
	}
	hdr := []byte{0xc0 | v.initialType<<4 | 1}
	hdr = binary.BigEndian.AppendUint32(hdr, ver)
	hdr = append(hdr, byte(len(dcid)))
	hdr = append(hdr, dcid...)
	hdr = append(hdr, 0) // SCID length
	hdr = append(hdr, 0) // token length
	l := 2 + len(frames) + 16
	hdr = append(hdr, byte(l>>8)|0x40, byte(l))
	pnOff := len(hdr)
	hdr = append(hdr, byte(pn>>8), byte(pn))
	nonce := append([]byte(nil), keys.iv...)
	for i := 0; i < 8; i++ {
		nonce[len(nonce)-1-i] ^= byte(uint64(pn) >> (8 * i))
	}
	pkt := keys.aead.Seal(append([]byte(nil), hdr...), nonce, frames, hdr)
	var mask [16]byte
	keys.hp.Encrypt(mask[:], pkt[pnOff+4:pnOff+20])
	pkt[0] ^= mask[0] & 0x0f
	pkt[pnOff] ^= mask[1]
	pkt[pnOff+1] ^= mask[2]
	return pkt
}

// splitInitials spreads a ClientHello over packets the way browsers do:
// CRYPTO frames cut at random points, shuffled within each packet, mixed
// with PING frames.
func splitInitials(t *testing.T, v *quicVersion, ver uint32, dcid, hello []byte, per int, rnd *rand.Rand) [][]byte {
	t.Helper()
	var out [][]byte
	pn := uint32(0)
	for start := 0; start < len(hello); start += per {
		end := min(start+per, len(hello))
		var frames [][]byte
		for off := start; off < end; {
			n := min(1+rnd.Intn(300), end-off)
			frames = append(frames, cryptoFrame(off, hello[off:off+n]))
			off += n
		}
		rnd.Shuffle(len(frames), func(a, b int) { frames[a], frames[b] = frames[b], frames[a] })
		payload := []byte{0x01} // PING
		for _, f := range frames {
			payload = append(payload, f...)
		}
		out = append(out, sealInitial(t, v, ver, dcid, pn, payload))
		pn++
	}
	return out
}

func TestQUICSplitHello(t *testing.T) {
	hello := quicHello(t, "Play.Example.TV")
	if len(hello) < 1200 {
		t.Logf("ClientHello is %d bytes (no post-quantum key share?)", len(hello))
	}
	rnd := rand.New(rand.NewSource(1))
	for _, c := range []struct {
		v   *quicVersion
		ver uint32
	}{{quicV1, 1}, {quicV2, 0x6b3343cf}, {quicDraft29, 0xff00001d}} {
		dcid := []byte{1, 2, 3, 4, 5, 6, 7, 8}
		pkts := splitInitials(t, c.v, c.ver, dcid, hello, 700, rnd)
		if len(pkts) < 2 {
			t.Fatalf("%d packets", len(pkts))
		}
		// Delivered in reverse order: the stream is complete only with all.
		var s cryptoStream
		for i := len(pkts) - 1; i >= 0; i-- {
			ps, err := parseDatagram(pkts[i])
			if err != nil {
				t.Fatalf("%x packet %d: %v", c.ver, i, err)
			}
			for _, p := range ps {
				_ = s.add(p.frags)
			}
			h, err := s.hello()
			if i > 0 && err != errNeedMore {
				t.Fatalf("%x: complete after packet %d: %+v %v", c.ver, i, h, err)
			}
			if i == 0 && (err != nil || h.ServerName != "play.example.tv") {
				t.Fatalf("%x: %+v %v", c.ver, h, err)
			}
		}
	}
}

func TestQUICPartialHello(t *testing.T) {
	// SNI first, then a big extension that is cut off.
	big := append([]byte{0x00, 0x15, 0x05, 0x00}, make([]byte, 0x500)...)
	msg := helloMsg(buildHello(sniExt("a.example.com"), big))
	var s cryptoStream
	_ = s.add([]cryptoFrag{{0, msg[:200]}})
	if _, err := s.hello(); err != errNeedMore {
		t.Fatal(err)
	}
	if h := s.partialHello(); h.ServerName != "a.example.com" {
		t.Fatalf("%+v", h)
	}
	// Server name extension itself cut off: nothing.
	var s2 cryptoStream
	_ = s2.add([]cryptoFrag{{0, msg[:50]}})
	if h := s2.partialHello(); h.ServerName != "" {
		t.Fatalf("%+v", h)
	}
}

func TestQUICNotInitial(t *testing.T) {
	d := realInitials(t)["v1 www.netflix.com"]
	unknown := append([]byte(nil), d...)
	binary.BigEndian.PutUint32(unknown[1:5], 0x1a2a3a4a) // reserved (greased) version
	for name, b := range map[string][]byte{
		"short header":    {0x40, 1, 2, 3, 4, 5, 6, 7, 8},
		"unknown version": unknown,
		"too short":       d[:30],
		"empty":           nil,
		"dns":             make([]byte, 40),
	} {
		if _, err := parseDatagram(b); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
	// Frames that may not appear in a client Initial.
	if _, err := cryptoFrames([]byte{0x06, 0, 2, 'h', 'i', 0x08, 0}); err == nil {
		t.Error("STREAM frame accepted")
	}
	if fs, err := cryptoFrames([]byte{0x02, 5, 0, 1, 0, 1, 1, 0x00, 0x06, 0x02, 1, 'x'}); err != nil || len(fs) != 1 || fs[0].off != 2 {
		t.Errorf("ACK + CRYPTO: %+v %v", fs, err)
	}
	// A CRYPTO frame past what a ClientHello may use.
	var s cryptoStream
	if err := s.add([]cryptoFrag{{maxHello, []byte{1}}}); err == nil {
		t.Error("offset past maxHello accepted")
	}
}

// --- queue logic ---

type verdict struct {
	id   uint32
	kind string // accept, mark, drop
	mark uint32
}

type recVerdicts struct {
	mu  sync.Mutex
	got []verdict
}

func (r *recVerdicts) add(v verdict) error {
	r.mu.Lock()
	r.got = append(r.got, v)
	r.mu.Unlock()
	return nil
}
func (r *recVerdicts) Accept(id uint32) error { return r.add(verdict{id, "accept", 0}) }
func (r *recVerdicts) Drop(id uint32) error   { return r.add(verdict{id, "drop", 0}) }
func (r *recVerdicts) AcceptMark(id, mark uint32) error {
	return r.add(verdict{id, "mark", mark})
}

// wait returns the verdicts once there are n.
func (r *recVerdicts) wait(t *testing.T, n int) []verdict {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for {
		r.mu.Lock()
		got := append([]verdict(nil), r.got...)
		r.mu.Unlock()
		if len(got) >= n {
			return got
		}
		if time.Now().After(deadline) {
			t.Fatalf("verdicts %+v, want %d", got, n)
		}
		time.Sleep(time.Millisecond)
	}
}

// udp4 wraps a datagram in IPv4/UDP headers from the client to dst:443.
func udp4(src string, sport uint16, dst string, payload []byte) []byte {
	h := make([]byte, 28)
	h[0] = 0x45
	binary.BigEndian.PutUint16(h[2:4], uint16(28+len(payload)))
	h[9] = 17
	copy(h[12:16], net.ParseIP(src).To4())
	copy(h[16:20], net.ParseIP(dst).To4())
	binary.BigEndian.PutUint16(h[20:22], sport)
	binary.BigEndian.PutUint16(h[22:24], 443)
	binary.BigEndian.PutUint16(h[24:26], uint16(8+len(payload)))
	return append(h, payload...)
}

func quicProxy(pols ...Policy) (*Proxy, *quicState, *fakeSets) {
	sets := &fakeSets{}
	p := &Proxy{Sets: sets}
	p.pol.Store(&pols)
	return p, newQUICState(4455, 0x00ff0000), sets
}

func quicPolicy() Policy {
	return Policy{ID: 2, Name: "tv", Set: match.MustCompile([]string{"example.tv", "drop:ads.example.tv"}), Mark: 0x20000,
		Set4: "SNK_2_d4", DropSet4: "SNK_2_x4", Session4: "SNK_2_s4"}
}

func TestQUICQueueRoutesSplitHello(t *testing.T) {
	p, q, sets := quicProxy(quicPolicy())
	r := &recVerdicts{}
	pkts := splitInitials(t, quicV1, 1, []byte{9, 9, 9, 9}, quicHello(t, "play.example.tv"), 700, rand.New(rand.NewSource(2)))
	for i, d := range pkts {
		p.quicPacket(q, r, uint32(10+i), 0x1, udp4("192.168.50.20", 50000, "203.0.113.80", d))
		if i < len(pkts)-1 {
			if len(r.got) != 0 {
				t.Fatalf("released before the ClientHello was complete: %+v", r.got)
			}
		}
	}
	got := r.wait(t, len(pkts))
	for i, v := range got {
		// Released in arrival order, unmarked: the policy's set routes them.
		if v.id != uint32(10+i) || v.kind != "accept" {
			t.Fatalf("verdicts %+v", got)
		}
	}
	if a := sets.get("SNK_2_d4"); len(a) != 1 || a[0] != "203.0.113.80" {
		t.Errorf("destination not learned before release: %v", a)
	}
	if a := sets.get("SNK_2_s4"); len(a) != 1 || a[0] != "192.168.50.20" {
		t.Errorf("session window not opened: %v", a)
	}
	// A retransmission of the decided flow is released at once.
	p.quicPacket(q, r, 99, 0, udp4("192.168.50.20", 50000, "203.0.113.80", pkts[0]))
	if got := r.wait(t, len(pkts)+1); got[len(pkts)] != (verdict{99, "accept", 0}) {
		t.Errorf("retransmission: %+v", got[len(pkts)])
	}
	if st := p.Stats(); st.QUIC != 1 || st.Matched != 1 || st.ByPolicy[2] != 1 {
		t.Errorf("stats %+v", st)
	}
}

func TestQUICQueueUnmatchedAndOther(t *testing.T) {
	p, q, sets := quicProxy(quicPolicy())
	r := &recVerdicts{}
	d := realInitials(t)["v1 www.netflix.com"]
	p.quicPacket(q, r, 1, 0, udp4("192.168.50.20", 50001, "198.51.100.1", d))
	// Not QUIC, a short header packet, not UDP: on at once.
	p.quicPacket(q, r, 2, 0, udp4("192.168.50.20", 50002, "198.51.100.1", []byte("hello")))
	p.quicPacket(q, r, 3, 0, udp4("192.168.50.20", 50003, "198.51.100.1", append([]byte{0x41}, make([]byte, 40)...)))
	p.quicPacket(q, r, 4, 0, []byte{0x45, 0, 0, 20})
	got := r.wait(t, 4)
	for _, v := range got {
		if v.kind != "accept" {
			t.Fatalf("%+v", got)
		}
	}
	if len(sets.get("SNK_2_d4")) != 0 {
		t.Error("unmatched destination learned")
	}
}

func TestQUICQueueDropAndECH(t *testing.T) {
	ech := []byte{0xfe, 0x0d, 0, 1, 0}
	one := func(t *testing.T, p *Proxy, q *quicState, msg []byte, dst string) verdict {
		t.Helper()
		r := &recVerdicts{}
		d := sealInitial(t, quicV1, 1, []byte{7, 7, 7, 7}, 0, cryptoFrame(0, msg))
		p.quicPacket(q, r, 5, 0, udp4("192.168.50.20", 50010, dst, d))
		return r.wait(t, 1)[0]
	}
	t.Run("drop rule", func(t *testing.T) {
		p, q, sets := quicProxy(quicPolicy())
		// Released into the drop set: the router rejects it.
		if v := one(t, p, q, helloMsg(buildHello(sniExt("ads.example.tv"))), "203.0.113.66"); v.kind != "accept" {
			t.Errorf("%+v", v)
		}
		if a := sets.get("SNK_2_x4"); len(a) != 1 || a[0] != "203.0.113.66" {
			t.Errorf("drop set %v", a)
		}
		// Without a drop set to reject it, the packets are dropped.
		pol := quicPolicy()
		pol.DropSet4 = ""
		p, q, _ = quicProxy(pol)
		if v := one(t, p, q, helloMsg(buildHello(sniExt("ads.example.tv"))), "203.0.113.66"); v.kind != "drop" {
			t.Errorf("%+v", v)
		}
	})
	t.Run("ech drop", func(t *testing.T) {
		pol := quicPolicy()
		pol.ECH = ECHDrop
		p, q, _ := quicProxy(pol)
		if v := one(t, p, q, helloMsg(buildHello(sniExt("cloudflare-ech.com"), ech)), "203.0.113.70"); v.kind != "drop" {
			t.Errorf("%+v", v)
		}
	})
	t.Run("ech route", func(t *testing.T) {
		pol := quicPolicy()
		pol.ECH = ECHRoute
		p, q, sets := quicProxy(pol)
		// Marked, and the shared CDN address is not learned.
		if v := one(t, p, q, helloMsg(buildHello(sniExt("cloudflare-ech.com"), ech)), "203.0.113.70"); v.kind != "mark" || v.mark != 0x20000 {
			t.Errorf("%+v", v)
		}
		if len(sets.get("SNK_2_d4")) != 0 {
			t.Error("ECH CDN address learned")
		}
	})
	t.Run("ipv6 off", func(t *testing.T) {
		// Set6 "": the policy leaves IPv6 alone, so nothing is learned or marked.
		p, q, _ := quicProxy(quicPolicy())
		r := &recVerdicts{}
		d := sealInitial(t, quicV1, 1, []byte{7}, 0, cryptoFrame(0, helloMsg(buildHello(sniExt("example.tv")))))
		p.quicPacket(q, r, 6, 0, udp6("2001:db8::20", 50020, "2001:db8:1::80", d))
		if v := r.wait(t, 1)[0]; v.kind != "accept" {
			t.Errorf("%+v", v)
		}
	})
}

func udp6(src string, sport uint16, dst string, payload []byte) []byte {
	h := make([]byte, 48)
	h[0] = 0x60
	binary.BigEndian.PutUint16(h[4:6], uint16(8+len(payload)))
	h[6] = 17
	copy(h[8:24], net.ParseIP(src))
	copy(h[24:40], net.ParseIP(dst))
	binary.BigEndian.PutUint16(h[40:42], sport)
	binary.BigEndian.PutUint16(h[42:44], 443)
	binary.BigEndian.PutUint16(h[44:46], uint16(8+len(payload)))
	return append(h, payload...)
}

func TestQUICQueueMarkWhenSetFails(t *testing.T) {
	p, q, _ := quicProxy(quicPolicy())
	p.Sets = failSets{}
	r := &recVerdicts{}
	d := sealInitial(t, quicV1, 1, []byte{3}, 0, cryptoFrame(0, helloMsg(buildHello(sniExt("example.tv")))))
	// QoS direction bits and old snake bits are cleared, the rest kept.
	p.quicPacket(q, r, 7, 0xc0ff0001, udp4("192.168.50.20", 50030, "203.0.113.81", d))
	if v := r.wait(t, 1)[0]; v.kind != "mark" || v.mark != 0x20001 {
		t.Errorf("%+v", v)
	}
}

type failSets struct{}

func (failSets) AddMany(string, []string) error { return os.ErrPermission }

func TestQUICQueueTimeoutUsesPartialHello(t *testing.T) {
	old := quicHelloWait
	quicHelloWait = 20 * time.Millisecond
	defer func() { quicHelloWait = old }()
	p, q, sets := quicProxy(quicPolicy())
	r := &recVerdicts{}
	big := append([]byte{0x00, 0x15, 0x05, 0x00}, make([]byte, 0x500)...)
	msg := helloMsg(buildHello(sniExt("x.example.tv"), big))
	// Only the first packet arrives; the second was lost.
	d := sealInitial(t, quicV1, 1, []byte{4}, 0, cryptoFrame(0, msg[:600]))
	p.quicPacket(q, r, 8, 0, udp4("192.168.50.20", 50040, "203.0.113.82", d))
	if v := r.wait(t, 1)[0]; v.kind != "accept" {
		t.Errorf("%+v", v)
	}
	if a := sets.get("SNK_2_d4"); len(a) != 1 {
		t.Errorf("server name from the partial ClientHello not used: %v", a)
	}
}

func TestQUICQueueDeviceScope(t *testing.T) {
	pol := quicPolicy()
	pol.Nets = []netip.Prefix{netip.MustParsePrefix("192.168.50.99/32")}
	p, q, sets := quicProxy(pol)
	r := &recVerdicts{}
	d := sealInitial(t, quicV1, 1, []byte{5}, 0, cryptoFrame(0, helloMsg(buildHello(sniExt("example.tv")))))
	p.quicPacket(q, r, 9, 0, udp4("192.168.50.20", 50050, "203.0.113.83", d))
	if v := r.wait(t, 1)[0]; v.kind != "accept" || len(sets.get("SNK_2_d4")) != 0 {
		t.Errorf("another device's connection routed: %+v %v", v, sets.get("SNK_2_d4"))
	}
}

// blockSets holds AddMany until released.
type blockSets struct {
	fakeSets
	gate chan struct{}
}

func (b *blockSets) AddMany(name string, entries []string) error {
	<-b.gate
	return b.fakeSets.AddMany(name, entries)
}

func TestQUICQueueHoldsWhileDeciding(t *testing.T) {
	p, q, _ := quicProxy(quicPolicy())
	bs := &blockSets{gate: make(chan struct{})}
	p.Sets = bs
	r := &recVerdicts{}
	d := sealInitial(t, quicV1, 1, []byte{6}, 0, cryptoFrame(0, helloMsg(buildHello(sniExt("example.tv")))))
	p.quicPacket(q, r, 1, 0, udp4("192.168.50.20", 50060, "203.0.113.84", d))
	// While the destination is being added, a later packet of the flow
	// (here a short header one) must wait too.
	time.Sleep(10 * time.Millisecond)
	p.quicPacket(q, r, 2, 0, udp4("192.168.50.20", 50060, "203.0.113.84", append([]byte{0x41}, make([]byte, 40)...)))
	time.Sleep(10 * time.Millisecond)
	r.mu.Lock()
	early := len(r.got)
	r.mu.Unlock()
	if early != 0 {
		t.Fatalf("released before the destination was added: %+v", r.got)
	}
	close(bs.gate)
	got := r.wait(t, 2)
	if got[0].id != 1 || got[1].id != 2 || got[0].kind != "accept" || got[1].kind != "accept" {
		t.Errorf("%+v", got)
	}
	if a := bs.get("SNK_2_d4"); len(a) != 1 {
		t.Errorf("%v", a)
	}
}
