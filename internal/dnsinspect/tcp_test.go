package dnsinspect

import (
	"encoding/binary"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/irisariuan/snake/internal/match"
	"github.com/irisariuan/snake/internal/netfilter"
	"github.com/irisariuan/snake/internal/packet"
	"github.com/irisariuan/snake/internal/system"
)

const isn = 0xfffffff0 // close to wrapping, to exercise sequence arithmetic

// tcpSeg builds an IPv4 or IPv6 TCP segment from the resolver (port 53) to
// the client.
func tcpSeg(v6 bool, seq uint32, flags byte, payload []byte) []byte {
	th := make([]byte, 20)
	binary.BigEndian.PutUint16(th[0:2], 53)
	binary.BigEndian.PutUint16(th[2:4], 40000)
	binary.BigEndian.PutUint32(th[4:8], seq)
	th[12] = 5 << 4
	th[13] = flags
	l4 := append(th, payload...)
	if v6 {
		h := make([]byte, 40)
		h[0] = 0x60
		binary.BigEndian.PutUint16(h[4:6], uint16(len(l4)))
		h[6] = 6
		copy(h[8:24], net.ParseIP("2001:db8::1"))
		copy(h[24:40], net.ParseIP("2001:db8::10"))
		return append(h, l4...)
	}
	h := make([]byte, 20)
	h[0] = 0x45
	binary.BigEndian.PutUint16(h[2:4], uint16(20+len(l4)))
	h[9] = 6
	copy(h[12:16], []byte{192, 168, 50, 1})
	copy(h[16:20], []byte{192, 168, 50, 10})
	return append(h, l4...)
}

// framed prefixes each message with its 2-byte length.
func framed(msgs ...[]byte) []byte {
	var out []byte
	for _, m := range msgs {
		out = binary.BigEndian.AppendUint16(out, uint16(len(m)))
		out = append(out, m...)
	}
	return out
}

func tcpInspector() (*Inspector, *system.Recorder) {
	rec := &system.Recorder{}
	i := &Inspector{IPSet: netfilter.IPSet{R: rec}}
	i.SetRules([]Rules{{ID: 1, Name: "nf", Set: match.MustCompile([]string{"netflix.com"}), Set4: "SNK_1_d4", Set6: "SNK_1_d6"}})
	return i, rec
}

func run(w func()) bool {
	if w == nil {
		return false
	}
	w()
	return true
}

func TestParseTCP(t *testing.T) {
	for _, v6 := range []bool{false, true} {
		raw := tcpSeg(v6, 1234, packet.FlagACK|packet.FlagFIN, []byte("abc"))
		raw = append(raw, 0, 0) // link-layer padding is not payload
		pk, ok := packet.Parse(raw)
		if !ok || !pk.TCP || pk.UDP || pk.SrcPort != 53 || pk.DstPort != 40000 || pk.Seq != 1234 ||
			pk.Flags != packet.FlagACK|packet.FlagFIN || string(pk.Payload) != "abc" {
			t.Errorf("v6=%v: %+v %v", v6, pk, ok)
		}
	}
}

func TestTCPAnswerOneSegment(t *testing.T) {
	for _, v6 := range []bool{false, true} {
		i, rec := tcpInspector()
		if run(i.handle(tcpSeg(v6, isn, packet.FlagSYN|packet.FlagACK, nil))) {
			t.Fatal("work for a SYN-ACK")
		}
		msg := BuildAnswer(t, "www.netflix.com", nil, "203.0.113.1")
		if !run(i.handle(tcpSeg(v6, isn+1, packet.FlagACK, framed(msg)))) {
			t.Fatalf("v6=%v: answer not held", v6)
		}
		if !strings.Contains(strings.Join(rec.Commands, "\n"), "SNK_1_d4 203.0.113.1") {
			t.Errorf("v6=%v: not added: %v", v6, rec.Commands)
		}
		if st := i.Stats(); st.TCP != 1 || st.Answers != 1 || st.Matched != 1 {
			t.Errorf("stats %+v", st)
		}
		i.handle(tcpSeg(v6, isn+1+uint32(len(msg)+2), packet.FlagACK|packet.FlagFIN, nil))
		if n := i.tcp.len(); n != 0 {
			t.Errorf("%d flows left after FIN", n)
		}
	}
}

func TestTCPAnswerSplitAndShared(t *testing.T) {
	i, rec := tcpInspector()
	i.handle(tcpSeg(false, isn, packet.FlagSYN|packet.FlagACK, nil))
	m1 := BuildAnswer(t, "a.netflix.com", nil, "203.0.113.1")
	m2 := BuildAnswer(t, "b.netflix.com", []string{"c.example"}, "203.0.113.2", "2001:db8::2")
	m3 := BuildAnswer(t, "c.netflix.com", nil, "203.0.113.3")
	stream := framed(m1, m2, m3)
	// Cuts: inside m1's length prefix, inside m1, at m1's end + part of
	// m2 (the segment completing m1 must be held), the rest of m2 and all
	// of m3 in one segment (two answers, one hold).
	cuts := []int{1, 10, len(m1) + 2 + 5, len(stream)}
	seq, prev := uint32(isn+1), 0
	held := []bool{}
	for _, c := range cuts {
		held = append(held, run(i.handle(tcpSeg(false, seq, packet.FlagACK, stream[prev:c]))))
		seq += uint32(c - prev)
		prev = c
	}
	if want := []bool{false, false, true, true}; !equalBools(held, want) {
		t.Errorf("held = %v, want %v", held, want)
	}
	calls := strings.Join(rec.Commands, "\n")
	for _, s := range []string{"SNK_1_d4 203.0.113.1", "SNK_1_d4 203.0.113.2", "SNK_1_d6 2001:db8::2", "SNK_1_d4 203.0.113.3"} {
		if !strings.Contains(calls, s) {
			t.Errorf("%s not added: %v", s, rec.Commands)
		}
	}
	if st := i.Stats(); st.TCP != 3 {
		t.Errorf("tcp answers = %d", st.TCP)
	}
}

func TestTCPRetransmitOverlapAndGap(t *testing.T) {
	i, _ := tcpInspector()
	i.handle(tcpSeg(false, isn, packet.FlagSYN|packet.FlagACK, nil))
	m1 := BuildAnswer(t, "a.netflix.com", nil, "203.0.113.1")
	m2 := BuildAnswer(t, "b.netflix.com", nil, "203.0.113.2")
	s := framed(m1, m2)
	base := uint32(isn + 1)
	half := len(m1)/2 + 2
	i.handle(tcpSeg(false, base, packet.FlagACK, s[:half]))
	// Retransmission of the first half: nothing new.
	if run(i.handle(tcpSeg(false, base, packet.FlagACK, s[:half]))) {
		t.Error("work for a retransmission")
	}
	// Overlapping segment completing m1.
	if !run(i.handle(tcpSeg(false, base+4, packet.FlagACK, s[4:len(m1)+2]))) {
		t.Error("overlapping segment completing m1 not held")
	}
	if st := i.Stats(); st.TCP != 1 {
		t.Fatalf("tcp answers = %d", st.TCP)
	}
	// A gap: tracking stops and later segments pass through.
	off := uint32(len(m1) + 2)
	if run(i.handle(tcpSeg(false, base+off+3, packet.FlagACK, s[off+3:]))) || i.tcp.len() != 0 {
		t.Error("gap not handled")
	}
	if run(i.handle(tcpSeg(false, base+off, packet.FlagACK, s[off:]))) {
		t.Error("untracked connection inspected")
	}
}

func TestTCPUntrackedAndLimits(t *testing.T) {
	i, _ := tcpInspector()
	// No SYN-ACK seen (connection older than the daemon): passed through.
	msg := BuildAnswer(t, "a.netflix.com", nil, "203.0.113.1")
	if run(i.handle(tcpSeg(false, 100, packet.FlagACK, framed(msg)))) {
		t.Error("connection without SYN-ACK inspected")
	}
	// The table is bounded; idle connections make room.
	now := time.Unix(1000, 0)
	tr := &tcpTracker{now: func() time.Time { return now }}
	pk := packet.Packet{Src: net.IPv4(192, 168, 50, 1), Dst: net.IPv4(192, 168, 50, 10), SrcPort: 53, TCP: true, Flags: packet.FlagSYN | packet.FlagACK}
	for p := 0; p < maxTCPFlows+10; p++ {
		pk.DstPort = uint16(p)
		tr.feed(pk)
	}
	if n := tr.len(); n != maxTCPFlows {
		t.Fatalf("flows = %d", n)
	}
	now = now.Add(tcpIdle + time.Second)
	pk.DstPort = 60000
	tr.feed(pk)
	if n := tr.len(); n != 1 {
		t.Errorf("flows after sweep = %d", n)
	}
	// RST drops the state.
	pk.Flags = packet.FlagRST
	tr.feed(pk)
	if n := tr.len(); n != 0 {
		t.Errorf("flows after RST = %d", n)
	}
}

func TestQueryTCP(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	answer := BuildAnswer(t, "x.example", []string{"y.example"}, "203.0.113.9")
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			var l [2]byte
			if _, err := c.Read(l[:]); err == nil {
				q := make([]byte, binary.BigEndian.Uint16(l[:]))
				_, _ = c.Read(q)
				// Answer in two writes to split the frame.
				f := framed(answer)
				_, _ = c.Write(f[:3])
				time.Sleep(5 * time.Millisecond)
				_, _ = c.Write(f[3:])
			}
			c.Close()
		}
	}()
	a, err := QueryTCP(ln.Addr().String(), "x.example", 2*time.Second)
	if err != nil || len(a.IPs) != 2 || len(a.Chain) != 1 || a.Chain[0] != "y.example" {
		t.Errorf("QueryTCP = %+v %v", a, err)
	}
}

func equalBools(a, b []bool) bool {
	if len(a) != len(b) {
		return false
	}
	for k := range a {
		if a[k] != b[k] {
			return false
		}
	}
	return true
}
