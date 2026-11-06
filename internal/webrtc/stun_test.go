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
	id, src, v6, ok := ParseConntrack(line, 0xff0000, 16)
	if !ok || id != 3 || src != "192.168.50.10" || v6 {
		t.Fatalf("got %d %s %v %v", id, src, v6, ok)
	}
	if _, _, _, ok := ParseConntrack("ipv4 2 tcp 6 10 TIME_WAIT src=1.1.1.1 dst=2.2.2.2 mark=196608 use=1", 0xff0000, 16); ok {
		t.Fatal("TIME_WAIT counted")
	}
	if _, _, _, ok := ParseConntrack("ipv4 2 udp 17 10 src=1.1.1.1 dst=2.2.2.2 mark=0 use=1", 0xff0000, 16); ok {
		t.Fatal("unmarked counted")
	}
}
