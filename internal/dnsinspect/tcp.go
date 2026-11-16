package dnsinspect

import (
	"encoding/binary"
	"io"
	"net"
	"sync"
	"time"

	"github.com/irisariuan/snake/internal/packet"
)

// DNS over TCP (RFC 7766): every message is preceded by a 2-byte length
// and may be split over several segments, or share one with others. The
// tracker follows dnsmasq's side of each connection from its SYN-ACK,
// collects the bytes in order and hands out the complete messages. The
// segment that completes a message is the one held until the addresses
// are in the sets: the client cannot read the answer without it.
//
// Anything unexpected (a gap, a connection first seen mid-stream, a full
// table) stops tracking that connection and lets it through unchanged,
// like the rest of the queue.

const (
	// maxTCPFlows bounds the connections tracked at once.
	maxTCPFlows = 4096
	// tcpIdle drops a connection's state after this long without a segment.
	tcpIdle = 2 * time.Minute
	// maxTCPBuf bounds the bytes buffered for one connection: one length
	// prefix and the largest possible message.
	maxTCPBuf = 2 + 0xffff
)

type flowKey struct {
	src, dst         [16]byte
	srcPort, dstPort uint16
}

func keyOf(pk packet.Packet) flowKey {
	var k flowKey
	copy(k.src[:], pk.Src.To16())
	copy(k.dst[:], pk.Dst.To16())
	k.srcPort, k.dstPort = pk.SrcPort, pk.DstPort
	return k
}

type tcpFlow struct {
	next uint32 // sequence number of the next byte expected
	buf  []byte // bytes of the message being collected
	seen time.Time
}

// tcpTracker reassembles the DNS messages of TCP connections.
type tcpTracker struct {
	mu    sync.Mutex
	flows map[flowKey]*tcpFlow
	now   func() time.Time // for tests
}

// seqLess reports whether a comes before b in sequence space.
func seqLess(a, b uint32) bool { return int32(a-b) < 0 }

// feed takes one segment of a server-to-client stream and returns the DNS
// messages it completes, in order.
func (t *tcpTracker) feed(pk packet.Packet) [][]byte {
	now := time.Now
	if t.now != nil {
		now = t.now
	}
	k := keyOf(pk)
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.flows == nil {
		t.flows = map[flowKey]*tcpFlow{}
	}
	f := t.flows[k]
	if pk.Flags&packet.FlagSYN != 0 {
		// SYN-ACK: the stream starts at the next byte. A repeated SYN-ACK
		// (retransmitted) restarts the same state.
		if f == nil && len(t.flows) >= maxTCPFlows {
			t.sweep(now())
			if len(t.flows) >= maxTCPFlows {
				return nil
			}
		}
		t.flows[k] = &tcpFlow{next: pk.Seq + 1, seen: now()}
		return nil
	}
	if f == nil {
		return nil
	}
	f.seen = now()
	var msgs [][]byte
	if data := pk.Payload; len(data) > 0 {
		end := pk.Seq + uint32(len(data))
		switch {
		case !seqLess(f.next, end):
			// Retransmission of bytes already seen.
			data = nil
		case seqLess(f.next, pk.Seq):
			// A gap: the stream can no longer be followed.
			delete(t.flows, k)
			return nil
		default:
			data = data[f.next-pk.Seq:]
		}
		if len(data) > 0 {
			f.next = end
			f.buf = append(f.buf, data...)
			for len(f.buf) >= 2 {
				n := int(binary.BigEndian.Uint16(f.buf))
				if len(f.buf) < 2+n {
					break
				}
				if n > 0 {
					msgs = append(msgs, append([]byte(nil), f.buf[2:2+n]...))
				}
				f.buf = f.buf[2+n:]
			}
			if len(f.buf) == 0 {
				f.buf = nil
			} else if len(f.buf) > maxTCPBuf {
				delete(t.flows, k)
				return msgs
			}
		}
	}
	if pk.Flags&(packet.FlagFIN|packet.FlagRST) != 0 {
		delete(t.flows, k)
	}
	return msgs
}

// sweep drops idle connections; t.mu must be held.
func (t *tcpTracker) sweep(now time.Time) {
	for k, f := range t.flows {
		if now.Sub(f.seen) > tcpIdle {
			delete(t.flows, k)
		}
	}
}

// len returns the number of tracked connections.
func (t *tcpTracker) len() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return len(t.flows)
}

// handleTCP inspects one segment of a DNS-over-TCP answer stream.
func (i *Inspector) handleTCP(pk packet.Packet) func() {
	var works []func()
	for _, msg := range i.tcp.feed(pk) {
		if w := i.handleMsg(pk.Dst, msg, true); w != nil {
			works = append(works, w)
		}
	}
	switch len(works) {
	case 0:
		return nil
	case 1:
		return works[0]
	}
	return func() {
		for _, w := range works {
			w()
		}
	}
}

// queryTCP sends one DNS message over TCP and returns the answer.
func queryTCP(server string, msg []byte, timeout time.Duration) ([]byte, error) {
	c, err := net.DialTimeout("tcp", server, timeout)
	if err != nil {
		return nil, err
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(timeout))
	out := make([]byte, 2+len(msg))
	binary.BigEndian.PutUint16(out, uint16(len(msg)))
	copy(out[2:], msg)
	if _, err := c.Write(out); err != nil {
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
	return resp, nil
}
