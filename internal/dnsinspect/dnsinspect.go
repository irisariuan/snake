// Package dnsinspect matches DNS answers that dnsmasq sends to LAN clients
// against snake's domain rules (wildcards, regexes, keywords, exclusions,
// CNAME chains) and adds the answered addresses to the policy ipsets.
//
// Answers are taken from an NFQUEUE on the router's OUTPUT path and released
// only after the addresses are in the set, so the client's first connection
// already follows the policy. The queue is fail-open: when the daemon is not
// running, answers pass straight through.
package dnsinspect

import (
	"context"
	"fmt"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	nfqueue "github.com/florianl/go-nfqueue/v2"
	"golang.org/x/net/dns/dnsmessage"

	"github.com/irisariuan/snake/internal/logx"
	"github.com/irisariuan/snake/internal/match"
	"github.com/irisariuan/snake/internal/netfilter"
	"github.com/irisariuan/snake/internal/packet"
)

// Rules are one policy's compiled domain rules, in policy order.
type Rules struct {
	ID          int
	Name        string
	Set         *match.Set
	FollowCNAME bool
	Set4, Set6  string // target ipsets ("" to skip a family)
}

// Answer is the relevant content of a DNS response.
type Answer struct {
	Question string   `json:"question"`
	Chain    []string `json:"chain,omitempty"` // CNAME targets in order
	IPs      []net.IP `json:"ips"`
}

// ParseAnswer extracts the question, CNAME chain and A/AAAA addresses.
func ParseAnswer(msg []byte) (Answer, bool) {
	var a Answer
	var p dnsmessage.Parser
	h, err := p.Start(msg)
	if err != nil || !h.Response || h.RCode != dnsmessage.RCodeSuccess {
		return a, false
	}
	q, err := p.Question()
	if err != nil {
		return a, false
	}
	a.Question = clean(q.Name.String())
	if err := p.SkipAllQuestions(); err != nil {
		return a, false
	}
	for {
		rh, err := p.AnswerHeader()
		if err == dnsmessage.ErrSectionDone {
			break
		}
		if err != nil {
			return a, len(a.IPs) > 0
		}
		switch rh.Type {
		case dnsmessage.TypeA:
			r, err := p.AResource()
			if err != nil {
				return a, len(a.IPs) > 0
			}
			a.IPs = append(a.IPs, net.IP(r.A[:]))
		case dnsmessage.TypeAAAA:
			r, err := p.AAAAResource()
			if err != nil {
				return a, len(a.IPs) > 0
			}
			a.IPs = append(a.IPs, net.IP(r.AAAA[:]))
		case dnsmessage.TypeCNAME:
			r, err := p.CNAMEResource()
			if err != nil {
				return a, len(a.IPs) > 0
			}
			a.Chain = append(a.Chain, clean(r.CNAME.String()))
		default:
			if err := p.SkipAnswer(); err != nil {
				return a, len(a.IPs) > 0
			}
		}
	}
	return a, a.Question != ""
}

func clean(n string) string { return strings.TrimSuffix(strings.ToLower(n), ".") }

// Decide returns the first policy whose rules match the answer.
func Decide(rules []Rules, a Answer) (Rules, match.Result, bool) {
	all := append([]string{a.Question}, a.Chain...)
	for _, r := range rules {
		names := all
		if !r.FollowCNAME {
			names = all[:1]
		}
		res := r.Set.MatchAny(names...)
		if res.Matched {
			return r, res, true
		}
	}
	return Rules{}, match.Result{}, false
}

// Stats are counters for the UI.
type Stats struct {
	Answers uint64 `json:"answers"`
	Matched uint64 `json:"matched"`
	Added   uint64 `json:"added"`
	Errors  uint64 `json:"errors"`
}

// Inspector runs the queue.
type Inspector struct {
	IPSet netfilter.IPSet
	// CacheTTL skips re-adding an address seen recently (0 = always add).
	CacheTTL time.Duration

	mu     sync.Mutex
	rules  []Rules
	nf     *nfqueue.Nfqueue
	cancel context.CancelFunc
	cache  map[string]time.Time
	names  map[string]string // address -> name it was answered for (matched answers only)
	stats  Stats
	queue  uint16
}

// Stats returns a copy of the counters.
func (i *Inspector) Stats() Stats {
	return Stats{atomic.LoadUint64(&i.stats.Answers), atomic.LoadUint64(&i.stats.Matched), atomic.LoadUint64(&i.stats.Added), atomic.LoadUint64(&i.stats.Errors)}
}

// NameOf returns the policy domain an address was last answered for, or "".
func (i *Inspector) NameOf(addr string) string {
	i.mu.Lock()
	defer i.mu.Unlock()
	return i.names[addr]
}

// Running reports whether the queue is open.
func (i *Inspector) Running() bool {
	i.mu.Lock()
	defer i.mu.Unlock()
	return i.nf != nil
}

// SetRules swaps the rule list without reopening the queue.
func (i *Inspector) SetRules(r []Rules) {
	i.mu.Lock()
	i.rules = r
	i.cache = map[string]time.Time{}
	i.mu.Unlock()
}

// Start opens the queue (no-op if already open on the same number).
func (i *Inspector) Start(queue uint16) error {
	i.mu.Lock()
	if i.nf != nil && i.queue == queue {
		i.mu.Unlock()
		return nil
	}
	i.mu.Unlock()
	i.Stop()
	cfg := nfqueue.Config{
		NfQueue:      queue,
		MaxPacketLen: 0xffff,
		MaxQueueLen:  2048,
		Copymode:     nfqueue.NfQnlCopyPacket,
		WriteTimeout: 100 * time.Millisecond,
		Flags:        nfqueue.NfQaCfgFlagFailOpen,
	}
	nf, err := nfqueue.Open(&cfg)
	if err != nil {
		return fmt.Errorf("dns nfqueue %d: %w", queue, err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	fn := func(a nfqueue.Attribute) int {
		if a.PacketID == nil {
			return 0
		}
		if a.Payload != nil {
			i.handle(*a.Payload)
		}
		_ = nf.SetVerdict(*a.PacketID, nfqueue.NfAccept)
		return 0
	}
	errFn := func(e error) int {
		if ctx.Err() != nil {
			return 1
		}
		logx.Debugf("dns nfqueue: %v", e)
		return 0
	}
	if err := nf.RegisterWithErrorFunc(ctx, fn, errFn); err != nil {
		cancel()
		nf.Close()
		return fmt.Errorf("dns nfqueue %d register: %w", queue, err)
	}
	i.mu.Lock()
	i.nf, i.cancel, i.queue = nf, cancel, queue
	if i.cache == nil {
		i.cache = map[string]time.Time{}
	}
	i.mu.Unlock()
	logx.Infof("dns inspector listening on nfqueue %d", queue)
	return nil
}

func (i *Inspector) handle(raw []byte) {
	pk, ok := packet.Parse(raw)
	if !ok || !pk.UDP {
		return
	}
	ans, ok := ParseAnswer(pk.Payload)
	if !ok || len(ans.IPs) == 0 {
		return
	}
	atomic.AddUint64(&i.stats.Answers, 1)
	i.mu.Lock()
	rules := i.rules
	i.mu.Unlock()
	r, res, ok := Decide(rules, ans)
	if !ok {
		return
	}
	atomic.AddUint64(&i.stats.Matched, 1)
	logx.Debugf("dns: %s matched %q (%s) -> policy %s", ans.Question, res.Rule, res.Name, r.Name)
	add := map[string][]string{}
	now := time.Now()
	i.mu.Lock()
	if i.names == nil || len(i.names) > 50000 {
		i.names = map[string]string{}
	}
	for _, ip := range ans.IPs {
		i.names[ip.String()] = ans.Question
	}
	for _, ip := range ans.IPs {
		set := r.Set4
		if ip.To4() == nil {
			set = r.Set6
		}
		if set == "" {
			continue
		}
		key := set + " " + ip.String()
		if i.CacheTTL > 0 && now.Before(i.cache[key]) {
			continue
		}
		i.cache[key] = now.Add(i.CacheTTL)
		add[set] = append(add[set], ip.String())
	}
	if len(i.cache) > 50000 {
		i.cache = map[string]time.Time{}
	}
	i.mu.Unlock()
	for set, ips := range add {
		if err := i.IPSet.AddMany(set, ips); err != nil {
			atomic.AddUint64(&i.stats.Errors, 1)
			logx.Warnf("dns inspector: add to %s: %v", set, err)
			continue
		}
		atomic.AddUint64(&i.stats.Added, uint64(len(ips)))
	}
}

// Stop closes the queue.
func (i *Inspector) Stop() {
	i.mu.Lock()
	nf, cancel := i.nf, i.cancel
	i.nf, i.cancel = nil, nil
	i.mu.Unlock()
	if cancel != nil {
		cancel()
	}
	if nf != nil {
		nf.Close()
	}
}

// Query asks a resolver for A and AAAA records of name and returns the
// combined answer, including the CNAME chain (used by the domain tester).
func Query(server, name string, timeout time.Duration) (Answer, error) {
	out := Answer{Question: clean(name)}
	fqdn, err := dnsmessage.NewName(strings.TrimSuffix(name, ".") + ".")
	if err != nil {
		return out, err
	}
	var lastErr error
	got := false
	for i, t := range []dnsmessage.Type{dnsmessage.TypeA, dnsmessage.TypeAAAA} {
		m := dnsmessage.Message{
			Header:    dnsmessage.Header{ID: uint16(time.Now().UnixNano()) + uint16(i), RecursionDesired: true},
			Questions: []dnsmessage.Question{{Name: fqdn, Type: t, Class: dnsmessage.ClassINET}},
		}
		buf, err := m.Pack()
		if err != nil {
			return out, err
		}
		c, err := net.DialTimeout("udp", server, timeout)
		if err != nil {
			return out, err
		}
		_ = c.SetDeadline(time.Now().Add(timeout))
		if _, err := c.Write(buf); err != nil {
			c.Close()
			lastErr = err
			continue
		}
		resp := make([]byte, 4096)
		n, err := c.Read(resp)
		c.Close()
		if err != nil {
			lastErr = err
			continue
		}
		a, ok := ParseAnswer(resp[:n])
		if !ok {
			continue
		}
		got = true
		for _, cn := range a.Chain {
			dup := false
			for _, x := range out.Chain {
				dup = dup || x == cn
			}
			if !dup {
				out.Chain = append(out.Chain, cn)
			}
		}
		out.IPs = append(out.IPs, a.IPs...)
	}
	if !got && lastErr != nil {
		return out, lastErr
	}
	if !got {
		return out, fmt.Errorf("no answer for %s", name)
	}
	return out, nil
}
