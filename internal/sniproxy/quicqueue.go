package sniproxy

// QUIC (HTTP/3) routing by server name.
//
// iptables queues UDP 443 packets of the sniffing policies' clients from
// the raw table, before connection tracking: only packets of flows that
// have not had a reply recently (SNK_QF4/6) are queued, which in practice
// means a new connection's first packets. Holding them before conntrack
// matters: a ClientHello split over two Initial packets is complete only
// once the second arrives, and if the first had already created a
// conntrack entry, the second would create a clashing one that the kernel
// drops.
//
// Once the ClientHello is complete, the decision is the TCP proxy's, but
// carried out by the kernel: the destination is added to the matching
// policy's domain set (or a session is started) before the packets are
// released, so the policy's own rules route the connection from its first
// packet, keep policy order and leave connections other policies claimed
// alone. Only an ech: route connection, whose CDN address is not learned,
// is released with the policy's mark. Refused connections are dropped;
// those matching drop: rules are released into the drop set, so the
// router rejects them and the browser falls back to TCP at once.
//
// Anything that is not a readable QUIC Initial goes on unchanged (via WAN
// unless a policy claims it), as non-TLS TCP does.

import (
	"context"
	"fmt"
	"net/netip"
	"sync"
	"time"

	nfqueue "github.com/florianl/go-nfqueue/v2"

	"github.com/irisariuan/snake/internal/logx"
	"github.com/irisariuan/snake/internal/packet"
)

// Tunables (variables so tests can shorten them).
var (
	// quicHelloWait is how long a flow's packets are held for the rest of
	// its ClientHello. A lost Initial packet is resent by the client after
	// its probe timeout; until then the earlier ones wait.
	quicHelloWait = time.Second
	// quicDoneTTL remembers decided flows, for their retransmitted
	// packets that arrive before the server's reply.
	quicDoneTTL = 30 * time.Second
)

const (
	maxQUICFlows = 1024 // flows held at once
	maxQUICHeld  = 16   // packets held per flow
	quicWorkers  = 16   // concurrent decisions
	// qosDirMask is config.QoSDirMask (Adaptive QoS direction bits).
	qosDirMask = 0xc0000000
)

// Flow verdicts.
const (
	verdictAccept = iota
	verdictDrop
)

type quicKey struct {
	src, dst netip.AddrPort
}

// quicHeld is a packet waiting for its flow's decision.
type quicHeld struct {
	id   uint32
	mark uint32 // its mark when queued
}

// quicFlow is a connection whose ClientHello is being collected.
type quicFlow struct {
	key    quicKey
	crypto cryptoStream
	held   []quicHeld
	timer  *time.Timer
	// deciding: the ClientHello is complete (or timed out) and a worker
	// is deciding. Packets arriving meanwhile are held too: released
	// early, one would create the flow's conntrack entry before its
	// destination is in the policy's set.
	deciding bool
}

// quicDone is a decided flow.
type quicDone struct {
	at      time.Time
	verdict int
	mark    uint32 // 0: keep the packet's mark
}

// quicState is the running QUIC queue.
type quicState struct {
	nf       *nfqueue.Nfqueue
	cancel   context.CancelFunc
	queue    uint16
	markMask uint32
	sem      chan struct{}

	mu    sync.Mutex
	flows map[quicKey]*quicFlow
	done  map[quicKey]quicDone
	swept time.Time
}

// verdicter sets packet verdicts (the queue; a recorder in tests).
type verdicter interface {
	Accept(id uint32) error
	AcceptMark(id, mark uint32) error
	Drop(id uint32) error
}

type nfVerdicter struct{ nf *nfqueue.Nfqueue }

func (v nfVerdicter) Accept(id uint32) error { return v.nf.SetVerdict(id, nfqueue.NfAccept) }
func (v nfVerdicter) Drop(id uint32) error   { return v.nf.SetVerdict(id, nfqueue.NfDrop) }
func (v nfVerdicter) AcceptMark(id, mark uint32) error {
	return v.nf.SetVerdictWithOption(id, nfqueue.NfAccept, nfqueue.WithMark(mark))
}

// QUICRunning reports whether the QUIC queue is open.
func (p *Proxy) QUICRunning() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.quic != nil && p.quic.nf != nil
}

// configureQUICLocked opens, keeps or closes the queue; p.mu must be held.
func (p *Proxy) configureQUICLocked(queue uint16, markMask uint32) error {
	if p.quic != nil && (queue == 0 || p.quic.queue != queue) {
		p.stopQUICLocked()
	}
	if queue == 0 {
		return nil
	}
	if p.quic != nil {
		p.quic.mu.Lock()
		p.quic.markMask = markMask
		p.quic.mu.Unlock()
		return nil
	}
	q := newQUICState(queue, markMask)
	cfg := nfqueue.Config{
		NfQueue:      queue,
		MaxPacketLen: 0xffff,
		MaxQueueLen:  1024,
		Copymode:     nfqueue.NfQnlCopyPacket,
		WriteTimeout: 100 * time.Millisecond,
		Flags:        nfqueue.NfQaCfgFlagFailOpen,
	}
	nf, err := nfqueue.Open(&cfg)
	if err != nil {
		return fmt.Errorf("quic nfqueue %d: %w", queue, err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	fn := func(a nfqueue.Attribute) int {
		if a.PacketID == nil {
			return 0
		}
		var mark uint32
		if a.Mark != nil {
			mark = *a.Mark
		}
		var payload []byte
		if a.Payload != nil {
			payload = *a.Payload
		}
		p.quicPacket(q, nfVerdicter{nf}, *a.PacketID, mark, payload)
		return 0
	}
	errFn := func(e error) int {
		if ctx.Err() != nil {
			return 1
		}
		logx.Debugf("quic nfqueue: %v", e)
		return 0
	}
	if err := nf.RegisterWithErrorFunc(ctx, fn, errFn); err != nil {
		cancel()
		nf.Close()
		return fmt.Errorf("quic nfqueue %d register: %w", queue, err)
	}
	q.nf, q.cancel = nf, cancel
	p.quic = q
	logx.Infof("sni proxy: reading QUIC server names on nfqueue %d", queue)
	return nil
}

func newQUICState(queue uint16, markMask uint32) *quicState {
	return &quicState{queue: queue, markMask: markMask, sem: make(chan struct{}, quicWorkers),
		flows: map[quicKey]*quicFlow{}, done: map[quicKey]quicDone{}}
}

func (p *Proxy) stopQUICLocked() {
	q := p.quic
	p.quic = nil
	if q == nil {
		return
	}
	if q.cancel != nil {
		q.cancel()
	}
	if q.nf != nil {
		_ = q.nf.Close() // the kernel drops held packets; clients resend them
	}
	logx.Infof("sni proxy: QUIC queue closed")
}

// quicPacket handles one queued packet. It runs on the queue's reader
// goroutine, so it never blocks: decisions run on workers.
func (p *Proxy) quicPacket(q *quicState, v verdicter, id, mark uint32, raw []byte) {
	pk, ok := packet.Parse(raw)
	if !ok || !pk.UDP {
		_ = v.Accept(id)
		return
	}
	src, _ := netip.AddrFromSlice(pk.Src)
	dst, _ := netip.AddrFromSlice(pk.Dst)
	key := quicKey{netip.AddrPortFrom(src.Unmap(), pk.SrcPort), netip.AddrPortFrom(dst.Unmap(), pk.DstPort)}
	now := time.Now()

	q.mu.Lock()
	q.sweepLocked(now)
	if d, ok := q.done[key]; ok {
		q.mu.Unlock()
		q.apply(v, quicHeld{id: id, mark: mark}, d)
		return
	}
	f := q.flows[key]
	if f != nil && f.deciding {
		f.held = append(f.held, quicHeld{id: id, mark: mark})
		q.mu.Unlock()
		return
	}
	pkts, perr := parseDatagram(pk.Payload)
	if f == nil {
		if perr != nil || len(q.flows) >= maxQUICFlows {
			// Not the start of a QUIC connection snake can read (a
			// later packet of a long flow, another protocol, an
			// unknown version): on unchanged.
			q.mu.Unlock()
			if perr != nil && len(pk.Payload) > 0 && pk.Payload[0]&0x80 != 0 {
				p.quicUndecoded.Add(1)
			}
			_ = v.Accept(id)
			return
		}
		f = &quicFlow{key: key}
		q.flows[key] = f
		p.quicConns.Add(1)
		f.timer = time.AfterFunc(quicHelloWait, func() { p.quicTimeout(q, v, f) })
	}
	f.held = append(f.held, quicHeld{id: id, mark: mark})
	bad := false
	for _, ip := range pkts {
		if f.crypto.add(ip.frags) != nil {
			bad = true
		}
	}
	var hello Hello
	herr := errNotTLS
	if !bad {
		hello, herr = f.crypto.hello()
	}
	if herr == errNeedMore && len(f.held) < maxQUICHeld {
		q.mu.Unlock()
		return // wait for the rest of the ClientHello
	}
	f.deciding = true
	f.timer.Stop()
	q.mu.Unlock()
	if herr == errNeedMore {
		hello = f.crypto.partialHello()
	} else if herr != nil {
		hello = Hello{}
	}
	p.quicDecideAsync(q, v, f, hello)
}

// quicTimeout decides a flow whose ClientHello did not complete in time,
// with what arrived of it.
func (p *Proxy) quicTimeout(q *quicState, v verdicter, f *quicFlow) {
	q.mu.Lock()
	if q.flows[f.key] != f || f.deciding {
		q.mu.Unlock()
		return
	}
	f.deciding = true
	hello := f.crypto.partialHello()
	q.mu.Unlock()
	p.quicDecideAsync(q, v, f, hello)
}

func (p *Proxy) quicDecideAsync(q *quicState, v verdicter, f *quicFlow, hello Hello) {
	select {
	case q.sem <- struct{}{}:
		go func() {
			defer func() { <-q.sem }()
			p.quicDecide(q, v, f, hello)
		}()
	default: // all workers busy: decide here
		p.quicDecide(q, v, f, hello)
	}
}

// quicDecide routes a flow by its ClientHello and releases its packets.
func (p *Proxy) quicDecide(q *quicState, v verdicter, f *quicFlow, hello Hello) {
	done := quicDone{at: time.Now(), verdict: verdictAccept}
	defer func() {
		if r := recover(); r != nil {
			logx.Errorf("sni proxy: quic panic: %v", r)
			done = quicDone{at: time.Now(), verdict: verdictAccept}
		}
		// From here on, the flow's packets get the verdict at once.
		q.mu.Lock()
		q.done[f.key] = done
		delete(q.flows, f.key)
		held := f.held
		q.mu.Unlock()
		for _, h := range held {
			q.apply(v, h, done)
		}
	}()
	client, dst := f.key.src.Addr(), f.key.dst
	d := p.decide(client, dst, hello, "sni proxy (quic)")
	switch {
	case d.reset && !d.res.Drop:
		done.verdict = verdictDrop // ech: drop
	case d.reset:
		// A drop: rule: the destination is in the drop set now (or a drop
		// session started), so the router rejects the connection. If it
		// could not be added, drop the packets instead.
		if !d.dropKernel {
			done.verdict = verdictDrop
		}
	case d.routed:
		if p.commit(client, dst.Addr(), hello, d, true) {
			break // the policy's rules route it now
		}
		if dst.Addr().Is6() && d.pol.Set6 == "" && !d.echAll {
			break // the policy leaves IPv6 alone
		}
		done.mark = d.pol.Mark
	}
}

// apply releases or drops one held packet.
func (q *quicState) apply(v verdicter, h quicHeld, d quicDone) {
	switch {
	case d.verdict == verdictDrop:
		_ = v.Drop(h.id)
	case d.mark != 0:
		q.mu.Lock()
		mask := q.markMask
		q.mu.Unlock()
		// Clear snake's bits and the QoS direction bits: SNAKE saves a
		// policy mark only from a packet without them.
		m := h.mark&^(mask|qosDirMask) | d.mark
		_ = v.AcceptMark(h.id, m)
	default:
		_ = v.Accept(h.id)
	}
}

// sweepLocked forgets old decided flows; q.mu must be held.
func (q *quicState) sweepLocked(now time.Time) {
	if now.Sub(q.swept) < quicDoneTTL/4 && len(q.done) < 8192 {
		return
	}
	q.swept = now
	for k, d := range q.done {
		if now.Sub(d.at) >= quicDoneTTL {
			delete(q.done, k)
		}
	}
	if len(q.done) >= 8192 {
		q.done = map[quicKey]quicDone{}
	}
}
