package engine

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/irisariuan/snake/internal/config"
	"github.com/irisariuan/snake/internal/dnsinspect"
	"github.com/irisariuan/snake/internal/logx"
	"github.com/irisariuan/snake/internal/netfilter"
	"github.com/irisariuan/snake/internal/system"
)

// Kinds of policy-learned addresses.
const (
	LearnedDNS  = "dns"     // answers to policy domain rules (SNK_<id>_d)
	LearnedPeer = "peer"    // WebRTC peers: sessions learned from STUN
	LearnedSess = "session" // sessions started by session: rules
	LearnedDrop = "drop"    // answers to drop: domain rules (SNK_<id>_x)
)

func learnedKind(kind string) (string, error) {
	switch kind {
	case "", LearnedDNS:
		return netfilter.KindDomain, nil
	case LearnedPeer, LearnedSess:
		return kind, nil // sessions, not a set
	case LearnedDrop:
		return netfilter.KindDrop, nil
	}
	return "", fmt.Errorf("kind must be %q, %q, %q or %q", LearnedDNS, LearnedDrop, LearnedSess, LearnedPeer)
}

// LearnedAddr is one address a policy learned, with what is known about it.
type LearnedAddr struct {
	Addr      string     `json:"addr"`
	Expires   int        `json:"expires,omitempty"` // seconds left in the kernel set; 0 = no timeout
	Name      string     `json:"name,omitempty"`    // DNS query name
	Matched   string     `json:"matched,omitempty"` // CNAME that matched, when not the query name
	Rule      string     `json:"rule,omitempty"`
	Source    string     `json:"source,omitempty"` // "policy" or "list: <name>"
	Client    string     `json:"client,omitempty"`
	Device    string     `json:"device,omitempty"`
	FirstSeen *time.Time `json:"first_seen,omitempty"`
	LastSeen  *time.Time `json:"last_seen,omitempty"`
	Hits      int        `json:"hits,omitempty"`
}

// RuleCount summarises addresses per rule.
type RuleCount struct {
	Rule   string `json:"rule"`
	Source string `json:"source"`
	Count  int    `json:"count"`
}

// LearnedView is the answer to LearnedAddrs.
type LearnedView struct {
	PolicyID  int           `json:"policy_id"`
	Policy    string        `json:"policy"`
	Kind      string        `json:"kind"`
	Inspector bool          `json:"inspector"` // DNS details are being recorded
	Total     int           `json:"total"`     // entries in the kernel sets
	Matching  int           `json:"matching"`  // entries matching the filter
	Unknown   int           `json:"unknown"`   // DNS entries without a record (dnsmasq-added or older)
	Rules     []RuleCount   `json:"rules,omitempty"`
	Addrs     []LearnedAddr `json:"addrs"`
}

func (e *Engine) policyByRef(ref string) (config.Policy, error) {
	cfg := e.rtCfg()
	if cfg == nil {
		return config.Policy{}, errors.New("no configuration loaded")
	}
	id, _ := strconv.Atoi(ref)
	for _, p := range cfg.Policies {
		if p.ID == id || strings.EqualFold(p.Name, ref) {
			return p, nil
		}
	}
	return config.Policy{}, fmt.Errorf("no policy %q", ref)
}

// ruleSources maps each domain rule of a policy to where it comes from.
func (e *Engine) ruleSources(id int) map[string]string {
	e.mu.Lock()
	cfg := e.cfg
	e.mu.Unlock()
	out := map[string]string{}
	if cfg == nil {
		return out
	}
	for _, p := range cfg.Policies {
		if p.ID != id {
			continue
		}
		for _, n := range p.Lists {
			if l, ok := cfg.List(n); ok {
				for _, d := range l.Domains {
					out[strings.TrimSpace(d)] = "list: " + l.Name
				}
			}
		}
		for _, d := range p.Domains {
			out[strings.TrimSpace(d)] = "policy"
		}
	}
	return out
}

// LearnedAddrs lists a policy's learned addresses of one kind. q filters on
// any field; limit caps the returned rows (0 = 1000).
func (e *Engine) LearnedAddrs(ref, kind, q string, limit int) (LearnedView, error) {
	p, err := e.policyByRef(ref)
	if err != nil {
		return LearnedView{}, err
	}
	k, err := learnedKind(kind)
	if err != nil {
		return LearnedView{}, err
	}
	if limit <= 0 {
		limit = 1000
	}
	if k == LearnedPeer || k == LearnedSess {
		return e.sessionView(p, k, q, limit), nil
	}
	v := LearnedView{PolicyID: p.ID, Policy: p.Name, Kind: kind, Addrs: []LearnedAddr{}}
	if v.Kind == "" {
		v.Kind = LearnedDNS
	}
	v.Inspector = isDNSKind(k) && e.dns.Running()
	ips := e.ipset()
	sets := []string{netfilter.SetName(p.ID, k, false), netfilter.SetName(p.ID, k, true)}
	var recs map[string]*dnsinspect.Record
	var sources map[string]string
	if isDNSKind(k) {
		recs = e.dns.Records(sets...)
		sources = e.ruleSources(p.ID)
	}
	devices := map[string]string{}
	if !e.DryRun {
		for _, c := range Clients() {
			devices[c.IP] = c.Name
		}
	}
	// Lightweight rows; full LearnedAddr values are built only for the rows
	// returned (sets can hold 100k+ entries).
	type row struct {
		addr string
		exp  int
		rec  *dnsinspect.Record
		last int64
	}
	rules := map[string]*RuleCount{}
	q = strings.ToLower(strings.TrimSpace(q))
	has := func(f string) bool { return f != "" && strings.Contains(strings.ToLower(f), q) }
	var rows []row
	for _, set := range sets {
		for _, m := range ips.Members(set, 0) {
			r := row{addr: m}
			if i := strings.IndexByte(m, ' '); i > 0 {
				r.addr = m[:i]
				if j := strings.Index(m, " timeout "); j >= 0 {
					t := m[j+9:]
					if k := strings.IndexByte(t, ' '); k >= 0 {
						t = t[:k]
					}
					r.exp, _ = strconv.Atoi(t)
				}
			}
			v.Total++
			rule, source := "", ""
			if rc, ok := recs[r.addr]; ok {
				r.rec = rc
				r.last = rc.LastSeen.UnixNano()
				rule = rc.Rule
				source = sources[strings.TrimSpace(rule)]
				if source == "" {
					source = "removed rule"
				}
			} else if isDNSKind(k) {
				v.Unknown++
			}
			if rules[rule] == nil {
				rules[rule] = &RuleCount{Rule: rule, Source: source}
			}
			rules[rule].Count++
			if q != "" && !strings.Contains(r.addr, q) && (r.rec == nil ||
				!(has(r.rec.Name) || has(r.rec.Matched) || has(r.rec.Rule) || has(source) || has(r.rec.Client) || has(devices[r.rec.Client]))) {
				continue
			}
			rows = append(rows, r)
		}
	}
	v.Matching = len(rows)
	order := make([]int32, len(rows))
	for i := range order {
		order[i] = int32(i)
	}
	sort.Slice(order, func(i, j int) bool {
		a, b := &rows[order[i]], &rows[order[j]]
		if a.last != b.last {
			return a.last > b.last // newest first; no record (0) last
		}
		return a.addr < b.addr
	})
	if len(order) > limit {
		order = order[:limit]
	}
	for _, i := range order {
		r := rows[i]
		a := LearnedAddr{Addr: r.addr, Expires: r.exp}
		if rc := r.rec; rc != nil {
			first, last := rc.FirstSeen, rc.LastSeen
			a.Name, a.Rule, a.Client, a.Hits, a.FirstSeen, a.LastSeen = rc.Name, rc.Rule, rc.Client, rc.Hits, &first, &last
			if rc.Matched != rc.Name {
				a.Matched = rc.Matched
			}
			a.Source = rules[rc.Rule].Source
			a.Device = devices[rc.Client]
		}
		v.Addrs = append(v.Addrs, a)
	}
	if isDNSKind(k) {
		for _, r := range rules {
			v.Rules = append(v.Rules, *r)
		}
		sort.Slice(v.Rules, func(i, j int) bool {
			if v.Rules[i].Count != v.Rules[j].Count {
				return v.Rules[i].Count > v.Rules[j].Count
			}
			return v.Rules[i].Rule < v.Rules[j].Rule
		})
	}
	return v, nil
}

// ForgetRequest selects learned addresses to remove from a policy.
type ForgetRequest struct {
	Kind  string   `json:"kind"`
	Addrs []string `json:"addrs"`
	Rule  *string  `json:"rule"` // every DNS address learned by this rule ("" = no record)
	All   bool     `json:"all"`
}

// ForgetLearned removes learned addresses from a policy's sets. They come
// back when the policy learns them again (next DNS answer / STUN check).
func (e *Engine) ForgetLearned(ref string, req ForgetRequest) (int, error) {
	p, err := e.policyByRef(ref)
	if err != nil {
		return 0, err
	}
	k, err := learnedKind(req.Kind)
	if err != nil {
		return 0, err
	}
	if k == LearnedPeer || k == LearnedSess {
		if k == LearnedPeer && req.Rule != nil {
			return 0, errors.New("rule selection does not apply to WebRTC peers")
		}
		return e.forgetSessions(p.ID, k, req), nil
	}
	ips := e.ipset()
	s4, s6 := netfilter.SetName(p.ID, k, false), netfilter.SetName(p.ID, k, true)
	if req.All {
		n := max(ips.Count(s4), 0) + max(ips.Count(s6), 0)
		_ = ips.Flush(s4)
		_ = ips.Flush(s6)
		if isDNSKind(k) {
			e.dns.Forget(s4, nil)
			e.dns.Forget(s6, nil)
		}
		return n, nil
	}
	addrs := req.Addrs
	if req.Rule != nil {
		if !isDNSKind(k) {
			return 0, errors.New("rule selection only applies to DNS addresses")
		}
		v, err := e.LearnedAddrs(strconv.Itoa(p.ID), req.Kind, "", 1<<30)
		if err != nil {
			return 0, err
		}
		addrs = nil
		for _, a := range v.Addrs {
			if a.Rule == *req.Rule {
				addrs = append(addrs, a.Addr)
			}
		}
	}
	if len(addrs) == 0 {
		return 0, nil
	}
	v4, v6 := netfilter.SplitFamilies(addrs)
	if err := ips.Del(s4, v4); err != nil {
		return 0, err
	}
	if len(v6) > 0 {
		_ = ips.Del(s6, v6)
	}
	if isDNSKind(k) {
		e.dns.Forget(s4, v4)
		e.dns.Forget(s6, v6)
	}
	return len(v4) + len(v6), nil
}

func (e *Engine) dnsLearnPath() string { return filepath.Join(e.P.Base, "dnslearn.json") }

// LoadDNSRecords restores the DNS inspector's address records.
func (e *Engine) LoadDNSRecords() {
	b, err := os.ReadFile(e.dnsLearnPath())
	if err != nil {
		return
	}
	var rs []dnsinspect.Record
	if err := json.Unmarshal(b, &rs); err != nil {
		logx.Warnf("dns records: %v", err)
		return
	}
	e.dns.LoadRecords(rs)
}

// saveDNSRecords persists the DNS inspector's address records.
func (e *Engine) saveDNSRecords() {
	if e.DryRun {
		return
	}
	b, err := json.Marshal(e.dns.AllRecords())
	if err != nil {
		return
	}
	if _, err := system.WriteIfChanged(e.dnsLearnPath(), b, 0o600); err != nil {
		logx.Warnf("save dns records: %v", err)
	}
}

// isDNSKind reports whether a set kind is filled from DNS answers (and so
// has inspector records).
func isDNSKind(k string) bool { return k == netfilter.KindDomain || k == netfilter.KindDrop }

// sessionView lists a policy's sessions (session: rules or WebRTC peers)
// like learned addresses: one row per device + address.
func (e *Engine) sessionView(p config.Policy, kind, q string, limit int) LearnedView {
	src := SessionRule
	if kind == LearnedPeer {
		src = SessionWebRTC
	}
	v := LearnedView{PolicyID: p.ID, Policy: p.Name, Kind: kind, Addrs: []LearnedAddr{}}
	devices := map[string]string{}
	if !e.DryRun {
		for _, c := range Clients() {
			devices[c.IP] = c.Name
		}
	}
	q = strings.ToLower(strings.TrimSpace(q))
	rules := map[string]*RuleCount{}
	now := time.Now()
	for _, s := range e.Sessions(p.ID) {
		if s.Source != src {
			continue
		}
		v.Total++
		if rules[s.Rule] == nil {
			rules[s.Rule] = &RuleCount{Rule: s.Rule}
		}
		rules[s.Rule].Count++
		if q != "" && !strings.Contains(strings.ToLower(s.Addr+" "+s.Client+" "+s.Name+" "+s.Rule+" "+devices[s.Client]), q) {
			continue
		}
		v.Matching++
		if len(v.Addrs) >= limit {
			continue
		}
		created, seen := s.Created, s.Seen
		exp := int(s.Expires.Sub(now).Seconds())
		if s.Permanent {
			exp = 0 // never
		}
		v.Addrs = append(v.Addrs, LearnedAddr{Addr: s.Addr, Expires: exp, Name: s.Name, Rule: s.Rule,
			Client: s.Client, Device: devices[s.Client], FirstSeen: &created, LastSeen: &seen})
	}
	for _, rc := range rules {
		v.Rules = append(v.Rules, *rc)
	}
	sort.Slice(v.Rules, func(i, j int) bool { return v.Rules[i].Count > v.Rules[j].Count })
	return v
}

// forgetSessions ends sessions of a policy: all of one source, those of a
// rule, or those to the given addresses.
func (e *Engine) forgetSessions(policy int, kind string, req ForgetRequest) int {
	src := SessionRule
	if kind == LearnedPeer {
		src = SessionWebRTC
	}
	addrs := map[string]bool{}
	for _, a := range req.Addrs {
		if ip := net.ParseIP(strings.TrimSpace(a)); ip != nil {
			addrs[ip.String()] = true
		}
	}
	n := 0
	s := &e.sess
	s.mu.Lock()
	for k, se := range s.m {
		if k.Policy != policy || se.Source != src {
			continue
		}
		if req.All || (req.Rule != nil && se.Rule == *req.Rule) || addrs[k.Addr] {
			delete(s.m, k)
			n++
		}
	}
	s.mu.Unlock()
	if n > 0 {
		_ = e.writeSessionChains(policy)
	}
	return n
}
