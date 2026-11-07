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
	"sort"
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
	// DropSet4/6 receive the addresses of answers matching drop: rules.
	DropSet4, DropSet6 string
	// Session starts sessions for answers matching session: rules: the
	// addresses are routed for the device that asked only, not added to
	// the sets. nil: session: rules are treated as plain rules.
	Session func(client string, addrs []string, rule, name string, opts match.Opts) error
	// Route handles answers matching route/drop session rules (if:,
	// route: and drop[...]: rules, applied top to bottom; an if: rule's
	// branch is picked by the device's condition). It reports what the
	// device's sessions now do with the addresses (match.ActRoute,
	// match.ActDrop or ""). matched is the name the rules matched (the
	// question or a CNAME). nil: such rules are not routed.
	Route func(client string, addrs []string, rule, name, matched string) (string, error)
	// Cond receives the addresses of answers matching if: atoms (which are
	// routed like plain rules too).
	Cond func(addrs []string, hits []match.CondHit)
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
	Answers  uint64 `json:"answers"`
	Matched  uint64 `json:"matched"`
	Dropped  uint64 `json:"dropped"`  // matched a drop: rule
	Sessions uint64 `json:"sessions"` // matched a session: rule (routed for the asking device)
	Added    uint64 `json:"added"`
	Errors   uint64 `json:"errors"`
}

// inspectorWorkers bounds concurrent set updates for held answers.
const inspectorWorkers = 16

// Inspector runs the queue.
type Inspector struct {
	IPSet netfilter.IPSet
	// CacheTTL skips re-adding an address seen recently (0 = always add).
	CacheTTL time.Duration

	mu      sync.Mutex
	rules   []Rules
	nf      *nfqueue.Nfqueue
	cancel  context.CancelFunc
	cache   map[string]time.Time
	names   map[string]string // address -> name it was answered for (matched answers only)
	recs    map[string]*Record
	pending map[string]chan struct{} // set+addr being added right now
	stats   Stats
	queue   uint16
}

// Stats returns a copy of the counters.
func (i *Inspector) Stats() Stats {
	return Stats{Answers: atomic.LoadUint64(&i.stats.Answers), Matched: atomic.LoadUint64(&i.stats.Matched), Dropped: atomic.LoadUint64(&i.stats.Dropped), Sessions: atomic.LoadUint64(&i.stats.Sessions),
		Added: atomic.LoadUint64(&i.stats.Added), Errors: atomic.LoadUint64(&i.stats.Errors)}
}

// Record describes how an address got into a policy's domain set.
type Record struct {
	Set       string    `json:"set"`
	Addr      string    `json:"addr"`
	Name      string    `json:"name"`              // query name
	Matched   string    `json:"matched,omitempty"` // name in the CNAME chain that matched
	Rule      string    `json:"rule"`              // rule that matched
	Client    string    `json:"client,omitempty"`  // device the answer went to ("router" for the router itself)
	FirstSeen time.Time `json:"first_seen"`
	LastSeen  time.Time `json:"last_seen"`
	Hits      int       `json:"hits"`
}

// MaxRecords bounds the address records kept in memory.
const MaxRecords = 100000

func recKey(set, addr string) string { return set + " " + addr }

// record stores an answer; i.mu must be held.
func (i *Inspector) record(r Record) {
	if i.recs == nil {
		i.recs = map[string]*Record{}
	}
	k := recKey(r.Set, r.Addr)
	if old := i.recs[k]; old != nil {
		r.FirstSeen, r.Hits = old.FirstSeen, old.Hits
	} else {
		r.FirstSeen = r.LastSeen
		if len(i.recs) >= MaxRecords {
			i.pruneLocked(MaxRecords / 10)
		}
	}
	r.Hits++
	i.recs[k] = &r
}

// pruneLocked drops the n least recently seen records.
func (i *Inspector) pruneLocked(n int) {
	all := make([]*Record, 0, len(i.recs))
	for _, r := range i.recs {
		all = append(all, r)
	}
	sort.Slice(all, func(a, b int) bool { return all[a].LastSeen.Before(all[b].LastSeen) })
	for _, r := range all[:min(n, len(all))] {
		delete(i.recs, recKey(r.Set, r.Addr))
	}
}

// Records returns copies of the records of the given sets, by address.
func (i *Inspector) Records(sets ...string) map[string]*Record {
	want := map[string]bool{}
	for _, s := range sets {
		want[s] = true
	}
	i.mu.Lock()
	defer i.mu.Unlock()
	out := map[string]*Record{}
	for _, r := range i.recs {
		if want[r.Set] {
			c := *r
			out[r.Addr] = &c
		}
	}
	return out
}

// AllRecords returns copies of every record (for saving).
func (i *Inspector) AllRecords() []Record {
	i.mu.Lock()
	defer i.mu.Unlock()
	out := make([]Record, 0, len(i.recs))
	for _, r := range i.recs {
		out = append(out, *r)
	}
	sort.Slice(out, func(a, b int) bool { return recKey(out[a].Set, out[a].Addr) < recKey(out[b].Set, out[b].Addr) })
	return out
}

// LoadRecords restores saved records (existing ones win).
func (i *Inspector) LoadRecords(rs []Record) {
	i.mu.Lock()
	defer i.mu.Unlock()
	if i.recs == nil {
		i.recs = map[string]*Record{}
	}
	for _, r := range rs {
		k := recKey(r.Set, r.Addr)
		if i.recs[k] == nil && len(i.recs) < MaxRecords {
			r := r
			i.recs[k] = &r
		}
	}
}

// Forget drops records (and the re-add cache) for addresses of a set, so a
// later answer adds them again. nil addrs forgets the whole set.
func (i *Inspector) Forget(set string, addrs []string) {
	i.mu.Lock()
	defer i.mu.Unlock()
	if addrs == nil {
		for k, r := range i.recs {
			if r.Set == set {
				delete(i.recs, k)
			}
		}
		for k := range i.cache {
			if strings.HasPrefix(k, set+" ") {
				delete(i.cache, k)
			}
		}
		return
	}
	for _, a := range addrs {
		delete(i.recs, recKey(set, a))
		delete(i.cache, recKey(set, a))
	}
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
	// Answers that need no set change are released at once; the others
	// are released by workers once their addresses are in the sets, so a
	// slow add never holds up unrelated lookups.
	sem := make(chan struct{}, inspectorWorkers)
	fn := func(a nfqueue.Attribute) int {
		if a.PacketID == nil {
			return 0
		}
		id := *a.PacketID
		var work func()
		if a.Payload != nil {
			work = i.handle(*a.Payload)
		}
		if work == nil {
			_ = nf.SetVerdict(id, nfqueue.NfAccept)
			return 0
		}
		select {
		case sem <- struct{}{}:
			go func() {
				defer func() { <-sem }()
				work()
				_ = nf.SetVerdict(id, nfqueue.NfAccept)
			}()
		default: // all workers busy: do it here
			work()
			_ = nf.SetVerdict(id, nfqueue.NfAccept)
		}
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

// handle inspects one DNS answer. It returns nil when the answer can be
// released right away (not a policy answer, or its addresses are already
// in the sets); otherwise it returns the work that must finish first.
func (i *Inspector) handle(raw []byte) func() {
	pk, ok := packet.Parse(raw)
	if !ok || !pk.UDP {
		return nil
	}
	ans, ok := ParseAnswer(pk.Payload)
	if !ok || len(ans.IPs) == 0 {
		return nil
	}
	atomic.AddUint64(&i.stats.Answers, 1)
	i.mu.Lock()
	rules := i.rules
	i.mu.Unlock()
	// Addresses of route: rules' if: atoms count for their conditions,
	// whatever routes the answer (negated atoms are not routed at all).
	recordConds(rules, ans)
	r, res, ok := Decide(rules, ans)
	if !ok {
		return nil
	}
	if res.Route {
		// Route or drop sessions for the asking device, by its condition;
		// never the sets.
		if r.Route == nil || pk.Dst.IsLoopback() {
			return nil
		}
		client := pk.Dst.String()
		addrs := make([]string, 0, len(ans.IPs))
		for _, ip := range ans.IPs {
			addrs = append(addrs, ip.String())
		}
		return func() {
			act, err := r.Route(client, addrs, res.Rule, ans.Question, res.Name)
			if err != nil {
				atomic.AddUint64(&i.stats.Errors, 1)
				logx.Warnf("dns inspector: conditional rule: %v", err)
			}
			switch act {
			case match.ActRoute:
				atomic.AddUint64(&i.stats.Matched, 1)
				atomic.AddUint64(&i.stats.Sessions, 1)
			case match.ActDrop:
				atomic.AddUint64(&i.stats.Matched, 1)
				atomic.AddUint64(&i.stats.Dropped, 1)
			}
		}
	}
	if res.Session && r.Session != nil {
		// Routed for the asking device only: no sets, no records. The
		// router's own lookups (pre-resolving) start no session.
		if pk.Dst.IsLoopback() {
			return nil
		}
		atomic.AddUint64(&i.stats.Matched, 1)
		atomic.AddUint64(&i.stats.Sessions, 1)
		client := pk.Dst.String()
		addrs := make([]string, 0, len(ans.IPs))
		for _, ip := range ans.IPs {
			addrs = append(addrs, ip.String())
		}
		logx.Debugf("dns: %s matched %q -> session of %s in policy %s", ans.Question, res.Rule, client, r.Name)
		return func() {
			if err := r.Session(client, addrs, res.Rule, ans.Question, res.Opts); err != nil {
				atomic.AddUint64(&i.stats.Errors, 1)
				logx.Warnf("dns inspector: session: %v", err)
			}
		}
	}
	if res.Drop {
		// Blocked: the addresses go to the drop sets instead.
		r.Set4, r.Set6 = r.DropSet4, r.DropSet6
		atomic.AddUint64(&i.stats.Dropped, 1)
	}
	atomic.AddUint64(&i.stats.Matched, 1)
	logx.Debugf("dns: %s matched %q (%s) -> policy %s", ans.Question, res.Rule, res.Name, r.Name)
	add := map[string][]string{}
	var keys []string
	var waits []chan struct{}
	now := time.Now()
	client := pk.Dst.String()
	if pk.Dst.IsLoopback() {
		client = "router"
	}
	i.mu.Lock()
	if i.pending == nil {
		i.pending = map[string]chan struct{}{}
	}
	for _, ip := range ans.IPs {
		set := r.Set4
		if ip.To4() == nil {
			set = r.Set6
		}
		if set != "" {
			i.record(Record{Set: set, Addr: ip.String(), Name: ans.Question, Matched: res.Name, Rule: res.Rule, Client: client, LastSeen: now})
		}
	}
	if i.names == nil || len(i.names) > 50000 {
		i.names = map[string]string{}
	}
	for _, ip := range ans.IPs {
		i.names[ip.String()] = ans.Question
	}
	done := make(chan struct{})
	for _, ip := range ans.IPs {
		set := r.Set4
		if ip.To4() == nil {
			set = r.Set6
		}
		if set == "" {
			continue
		}
		key := set + " " + ip.String()
		if ch, ok := i.pending[key]; ok {
			// Another answer is adding it right now: release after it.
			waits = append(waits, ch)
			continue
		}
		if i.CacheTTL > 0 && now.Before(i.cache[key]) {
			continue
		}
		i.cache[key] = now.Add(i.CacheTTL)
		i.pending[key] = done
		keys = append(keys, key)
		add[set] = append(add[set], ip.String())
	}
	if len(i.cache) > 50000 {
		i.cache = map[string]time.Time{}
	}
	i.mu.Unlock()
	if len(add) == 0 && len(waits) == 0 {
		return nil
	}
	return func() {
		var failed []string
		for set, ips := range add {
			if err := i.IPSet.AddMany(set, ips); err != nil {
				atomic.AddUint64(&i.stats.Errors, 1)
				logx.Warnf("dns inspector: add to %s: %v", set, err)
				for _, ip := range ips {
					failed = append(failed, set+" "+ip)
				}
				continue
			}
			atomic.AddUint64(&i.stats.Added, uint64(len(ips)))
		}
		i.mu.Lock()
		for _, k := range keys {
			delete(i.pending, k)
		}
		for _, k := range failed {
			delete(i.cache, k) // retry on the next answer
		}
		i.mu.Unlock()
		close(done)
		for _, ch := range waits {
			select {
			case <-ch:
			case <-time.After(time.Second):
			}
		}
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

// recordConds hands the answer's addresses to every policy whose route:
// rules' if: atoms match its names.
func recordConds(rules []Rules, ans Answer) {
	var addrs []string
	for _, r := range rules {
		if r.Cond == nil || !r.Set.HasConds() {
			continue
		}
		names := []string{ans.Question}
		if r.FollowCNAME {
			names = append(names, ans.Chain...)
		}
		hits := r.Set.CondHits(names...)
		if len(hits) == 0 {
			continue
		}
		if addrs == nil {
			for _, ip := range ans.IPs {
				addrs = append(addrs, ip.String())
			}
		}
		r.Cond(addrs, hits)
	}
}
