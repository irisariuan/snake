package webrtc

import (
	"encoding/binary"
	"testing"
)

func stunBinding() []byte {
	b := make([]byte, 20)
	binary.BigEndian.PutUint16(b[0:2], 0x0001) // binding request
	binary.BigEndian.PutUint16(b[2:4], 0)
	binary.BigEndian.PutUint32(b[4:8], stunMagicCookie)
	return b
}

func ipv4UDP(payload []byte) []byte {
	h := make([]byte, 28)
	h[0] = 0x45
	h[9] = 17
	copy(h[12:16], []byte{192, 168, 50, 10})
	copy(h[16:20], []byte{203, 0, 113, 7})
	binary.BigEndian.PutUint16(h[20:22], 50000)
	binary.BigEndian.PutUint16(h[22:24], 3478)
	return append(h, payload...)
}

func TestSTUN(t *testing.T) {
	if !IsSTUN(stunBinding()) {
		t.Fatal("binding request not detected")
	}
	dtls := append([]byte{0x16, 0xfe, 0xfd}, make([]byte, 30)...)
	if IsSTUN(dtls) {
		t.Fatal("DTLS detected as STUN")
	}
	bad := stunBinding()
	binary.BigEndian.PutUint16(bad[2:4], 8) // claims attributes that are not there
	if IsSTUN(bad) {
		t.Fatal("truncated message accepted")
	}
}

func TestParse(t *testing.T) {
	pk, ok := Parse(ipv4UDP(stunBinding()))
	if !ok || !pk.UDP || pk.Dst.String() != "203.0.113.7" || pk.DstPort != 3478 || !IsSTUN(pk.Payload) {
		t.Fatalf("parse v4: %+v %v", pk, ok)
	}
	v6 := make([]byte, 48)
	v6[0] = 0x60
	v6[6] = 17
	v6[24], v6[25] = 0x20, 0x01
	v6[39] = 1
	binary.BigEndian.PutUint16(v6[42:44], 19302)
	v6 = append(v6, stunBinding()...)
	pk, ok = Parse(v6)
	if !ok || pk.Dst.String() != "2001::1" || pk.DstPort != 19302 || !IsSTUN(pk.Payload) {
		t.Fatalf("parse v6: %+v %v", pk, ok)
	}
}

func TestParseConntrack(t *testing.T) {
	line := "ipv4     2 tcp      6 7438 ESTABLISHED src=192.168.50.10 dst=52.1.2.3 sport=51234 dport=443 src=52.1.2.3 dst=10.2.0.2 sport=443 dport=51234 [ASSURED] mark=196608 use=1"
	c, ok := ParseConntrack(line, 0xff0000, 16)
	if !ok || c.ID != 3 || c.Src != "192.168.50.10" || c.Dst != "52.1.2.3" || c.V6 {
		t.Fatalf("got %+v %v", c, ok)
	}
	if _, ok := ParseConntrack("ipv4 2 tcp 6 10 TIME_WAIT src=1.1.1.1 dst=2.2.2.2 mark=196608 use=1", 0xff0000, 16); ok {
		t.Fatal("TIME_WAIT counted")
	}
	if _, ok := ParseConntrack("ipv4 2 udp 17 10 src=1.1.1.1 dst=2.2.2.2 mark=0 use=1", 0xff0000, 16); ok {
		t.Fatal("unmarked counted")
	}
	// procfs prints IPv6 in full form; ipset prints it compressed.
	c, ok = ParseConntrack("ipv6 10 udp 17 170 src=2001:0db8:0000:0000:0000:0000:0000:0010 dst=2001:0db8:0000:0000:0000:0000:0000:0001 sport=50000 dport=3478 mark=65536 use=1", 0xff0000, 16)
	if !ok || !c.V6 || c.Src != "2001:db8::10" || c.Dst != "2001:db8::1" {
		t.Fatalf("v6: %+v %v", c, ok)
	}
}

// stunMsg builds a STUN message of the given type with the given attribute
// types (each with a 4-byte value).
func stunMsg(typ uint16, attrs ...uint16) []byte {
	b := make([]byte, 20, 20+8*len(attrs))
	binary.BigEndian.PutUint16(b[0:2], typ)
	binary.BigEndian.PutUint16(b[2:4], uint16(8*len(attrs)))
	binary.BigEndian.PutUint32(b[4:8], stunMagicCookie)
	for _, a := range attrs {
		b = binary.BigEndian.AppendUint16(b, a)
		b = binary.BigEndian.AppendUint16(b, 4)
		b = append(b, 0, 0, 0, 0)
	}
	return b
}

func TestClassify(t *testing.T) {
	cases := []struct {
		name string
		msg  []byte
		want Target
	}{
		{"server binding request", stunMsg(0x0001), TargetServer},
		{"binding request with SOFTWARE+FINGERPRINT", stunMsg(0x0001, 0x8022, 0x8028), TargetServer},
		{"ICE check (PRIORITY, ICE-CONTROLLING)", stunMsg(0x0001, 0x0006, 0x0024, 0x802A), TargetPeer},
		{"ICE check, USERNAME after other attrs", stunMsg(0x0001, 0x8022, 0x0006), TargetPeer},
		{"ICE-CONTROLLED only", stunMsg(0x0001, 0x8029), TargetPeer},
		{"binding success response", stunMsg(0x0101), TargetPeer},
		{"binding indication (consent)", stunMsg(0x0011), TargetPeer},
		{"TURN allocate", stunMsg(0x0003, 0x0019), TargetServer},
		{"TURN refresh", stunMsg(0x0004), TargetServer},
		{"TURN create permission", stunMsg(0x0008), TargetServer},
		{"TURN channel bind", stunMsg(0x0009), TargetServer},
		{"TURN send indication", stunMsg(0x0016), TargetServer},
		{"allocate error response", stunMsg(0x0113), TargetPeer},
	}
	for _, c := range cases {
		if !IsSTUN(c.msg) {
			t.Fatalf("%s: not STUN", c.name)
		}
		if got := Classify(c.msg); got != c.want {
			t.Errorf("%s: got %v want %v", c.name, got, c.want)
		}
	}
}
