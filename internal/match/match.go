// Package match implements snake's domain rule format.
//
// One rule per line (or list entry). Blank lines and text after " #" are ignored.
//
//	example.com          domain and all its subdomains (fast path: handled by dnsmasq too)
//	.example.com         subdomains only, not example.com itself
//	=example.com         exactly example.com
//	*.example.com        glob: * matches within one label  -> a.example.com, not a.b.example.com
//	**.example.com       glob: ** matches across labels   -> a.example.com, a.b.example.com
//	api-?.example.com    glob: ? matches one character (not a dot)
//	~nflx                keyword: name contains "nflx"
//	/^ipv4-c\d+-.*\.oca\.nflxvideo\.net$/   regular expression (RE2, case-insensitive)
//	re:^ipv4-c\d+\.example\.com$            same, alternative syntax
//	!ads.example.com     exclusion: any rule above prefixed with ! removes matches
//	drop:ads.example.com drop: block connections to what the rule matches (any
//	                     domain rule after drop:); beats include rules, but !
//	                     still exempts a name
//	drop:asn:1234        drop: block an autonomous system's prefixes
//	drop:cidr:1.2.3.0/24 drop: block an address range or single IP (drop:ip: too)
//	session:example.com  session: route what the rule matches only for the
//	                     device that looked it up (any domain rule after
//	                     session:); the addresses are not added to the
//	                     policy's sets. Beats include rules; drop: and !
//	                     beat it. Options: session[ttl=10m;onlookup=1]:
//	if:C;then:route:E    conditional rules (then:/else:/finally:), see route.go
//
// Names are compared lowercase without the trailing dot. With CNAME following
// (the default) a rule also matches when any name in the answer's CNAME chain
// matches, so e.g. "**.akamaized.net" catches services that CNAME into Akamai.
package match

import (
	"fmt"
	"net"
	"regexp"
	"regexp/syntax"
	"strconv"
	"strings"
	"sync"
)

// Kind of pattern.
type Kind string

const (
	Suffix     Kind = "suffix"     // example.com
	Subdomains Kind = "subdomains" // .example.com
	Exact      Kind = "exact"      // =example.com
	Glob       Kind = "glob"       // *.example.com
	Keyword    Kind = "keyword"    // ~word
	Regex      Kind = "regex"      // /re/ or re:re
	ASN        Kind = "asn"        // drop:asn:1234 (addresses, not names)
	CIDR       Kind = "cidr"       // drop:cidr:1.2.3.0/24
)

// DropPrefix marks a rule whose matches are blocked instead of routed.
const DropPrefix = "drop:"

// SessionPrefix marks a rule whose matches are routed only for the device
// that looked the name up, for a while after its last connection, instead
// of being added to the policy's sets.
const SessionPrefix = "session:"

// Pattern is one parsed rule.
type Pattern struct {
	Raw     string `json:"raw"`
	Kind    Kind   `json:"kind"`
	Negate  bool   `json:"negate"`
	Drop    bool   `json:"drop,omitempty"`
	Session bool   `json:"session,omitempty"`
	Opts    Opts   `json:"opts,omitempty"` // session[...] options
	Value   string `json:"value"`
	// Base is a literal domain suffix every match must end with ("" if none
	// can be derived). It steers DNS resolution through the tunnel and is
	// used for pre-resolving.
	Base string `json:"base,omitempty"`
	re   *regexp.Regexp
}

var labelRe = regexp.MustCompile(`^([a-z0-9_]([a-z0-9_\-]{0,61}[a-z0-9_])?)$`)

func validDomain(d string) bool {
	if d == "" || len(d) > 253 || strings.HasPrefix(d, ".") || strings.HasSuffix(d, ".") {
		return false
	}
	for _, l := range strings.Split(d, ".") {
		if !labelRe.MatchString(l) {
			return false
		}
	}
	return true
}

// StripComment removes a trailing " # comment" and surrounding space.
func StripComment(s string) string {
	s = strings.TrimSpace(s)
	if strings.HasPrefix(s, "#") {
		return ""
	}
	// Regexes may legitimately contain '#'; only strip " #" outside them.
	if !strings.HasPrefix(strings.TrimPrefix(s, "!"), "/") && !strings.HasPrefix(strings.TrimPrefix(s, "!"), "re:") {
		if i := strings.Index(s, " #"); i >= 0 {
			s = strings.TrimSpace(s[:i])
		}
	}
	return s
}

// Normalize canonicalises a rule's text (lowercase, scheme/path stripped for
// plain domains). Regexes are left as written.
func Normalize(s string) string {
	if IsRoute(s) {
		return normalizeRoute(s)
	}
	s = StripComment(s)
	if s == "" {
		return ""
	}
	neg := ""
	if strings.HasPrefix(s, "!") {
		neg, s = "!", strings.TrimSpace(s[1:])
	}
	if opts, has, rest, ok := splitCmd(s, "drop"); ok && has {
		// drop[options]: a drop session (domain rules only).
		if o, err := parseOpts(opts); err == nil {
			return neg + cmdPrefix("drop", o) + Normalize(strings.TrimSpace(rest))
		}
		return neg + "drop[" + opts + "]:" + Normalize(strings.TrimSpace(rest))
	}
	if len(s) >= len(DropPrefix) && strings.EqualFold(s[:len(DropPrefix)], DropPrefix) {
		inner := strings.TrimSpace(s[len(DropPrefix):])
		lo := strings.ToLower(inner)
		for _, k := range []string{"asn:", "cidr:", "ip:"} {
			if strings.HasPrefix(lo, k) {
				v := strings.ToLower(strings.TrimSpace(inner[len(k):]))
				if k == "asn:" {
					v = strings.TrimPrefix(v, "as")
				}
				return neg + DropPrefix + k + v
			}
		}
		return neg + DropPrefix + Normalize(inner)
	}
	if opts, has, rest, ok := splitCmd(s, "session"); ok {
		o, err := parseOpts(opts)
		if err != nil || !has {
			// Kept as written so Parse reports the bad option.
			if err != nil {
				return neg + "session[" + opts + "]:" + Normalize(strings.TrimSpace(rest))
			}
		}
		return neg + cmdPrefix("session", o) + Normalize(strings.TrimSpace(rest))
	}
	if strings.HasPrefix(s, "/") || strings.HasPrefix(s, "re:") {
		return neg + s
	}
	s = strings.ToLower(s)
	if strings.HasPrefix(s, "~") {
		return neg + s
	}
	prefix := ""
	if strings.HasPrefix(s, "=") {
		prefix, s = "=", s[1:]
	}
	s = strings.TrimPrefix(s, "https://")
	s = strings.TrimPrefix(s, "http://")
	if i := strings.IndexAny(s, "/:"); i >= 0 {
		s = s[:i]
	}
	s = strings.TrimSuffix(s, ".")
	return neg + prefix + s
}

// Parse parses one rule.
func Parse(raw string) (Pattern, error) {
	s := Normalize(raw)
	p := Pattern{Raw: s}
	if s == "" {
		return p, fmt.Errorf("empty rule")
	}
	if strings.HasPrefix(s, "!") {
		p.Negate = true
		s = s[1:]
	}
	if strings.HasPrefix(s, DropPrefix) || strings.HasPrefix(s, "drop[") {
		if p.Negate {
			return p, fmt.Errorf("! and drop: cannot be combined; write !name to exempt a name from drop rules")
		}
		return parseDrop(s)
	}
	if _, _, _, ok := splitCmd(s, "session"); ok {
		if p.Negate {
			return p, fmt.Errorf("! and session: cannot be combined; write !name to exempt a name")
		}
		return parseSession(s)
	}
	if IsRoute(s) {
		return p, fmt.Errorf("if: and route: rules are compiled with the rule list (if:...;then:...)")
	}
	switch {
	case strings.HasPrefix(s, "re:") || strings.HasPrefix(s, "/"):
		expr := strings.TrimPrefix(s, "re:")
		if strings.HasPrefix(s, "/") {
			if len(s) < 3 || !strings.HasSuffix(s, "/") {
				return p, fmt.Errorf("regex must be written /.../")
			}
			expr = s[1 : len(s)-1]
		}
		if _, err := syntax.Parse(expr, syntax.Perl); err != nil {
			return p, fmt.Errorf("bad regex: %v", err)
		}
		re, err := regexp.Compile("(?i)" + expr)
		if err != nil {
			return p, fmt.Errorf("bad regex: %v", err)
		}
		p.Kind, p.Value, p.re = Regex, expr, re
		p.Base = regexBase(expr)
	case strings.HasPrefix(s, "~"):
		kw := s[1:]
		if kw == "" || strings.ContainsAny(kw, " \t") {
			return p, fmt.Errorf("keyword must be non-empty and contain no spaces")
		}
		p.Kind, p.Value = Keyword, kw
	case strings.HasPrefix(s, "="):
		d := s[1:]
		if !validDomain(d) {
			return p, fmt.Errorf("invalid domain %q", d)
		}
		p.Kind, p.Value, p.Base = Exact, d, d
	case strings.ContainsAny(s, "*?"):
		if strings.Contains(s, "***") {
			return p, fmt.Errorf("use * (one label) or ** (any labels)")
		}
		re, err := regexp.Compile(globToRegex(s))
		if err != nil {
			return p, fmt.Errorf("bad wildcard: %v", err)
		}
		p.Kind, p.Value, p.re = Glob, s, re
		p.Base = globBase(s)
	case strings.HasPrefix(s, "."):
		d := s[1:]
		if !validDomain(d) {
			return p, fmt.Errorf("invalid domain %q", d)
		}
		if !strings.Contains(d, ".") {
			return p, fmt.Errorf("%q would match a whole top-level domain; use **.%s if you really mean it", s, d)
		}
		p.Kind, p.Value, p.Base = Subdomains, d, d
	default:
		if !validDomain(s) {
			return p, fmt.Errorf("invalid domain %q", s)
		}
		if !strings.Contains(s, ".") {
			return p, fmt.Errorf("%q would match a whole top-level domain; use **.%s if you really mean it", s, s)
		}
		p.Kind, p.Value, p.Base = Suffix, s, s
	}
	if p.Base != "" && !strings.Contains(p.Base, ".") {
		p.Base = "" // a bare TLD is too broad to steer DNS for
	}
	return p, nil
}

// parseDrop parses "drop:<rule>", "drop:asn:N" or "drop:cidr:X".
// "drop[options]:<domain rule>" is a drop session: the answered addresses
// are blocked for the asking device (and share= devices) only.
func parseDrop(s string) (Pattern, error) {
	if opts, has, rest, ok := splitCmd(s, "drop"); ok && has {
		o, err := parseOpts(opts)
		if err != nil {
			return Pattern{Raw: s, Drop: true}, fmt.Errorf("drop[...]: %v", err)
		}
		lo := strings.ToLower(rest)
		if strings.HasPrefix(lo, "asn:") || strings.HasPrefix(lo, "cidr:") || strings.HasPrefix(lo, "ip:") {
			return Pattern{Raw: s, Drop: true}, fmt.Errorf("drop[...] options need a domain rule (a drop session starts with a DNS lookup); drop:asn:/cidr: block for every device")
		}
		q, err := parseDrop(DropPrefix + rest)
		if err != nil {
			return q, err
		}
		q.Raw, q.Opts = s, o
		return q, nil
	}
	inner := s[len(DropPrefix):]
	p := Pattern{Raw: s, Drop: true}
	switch {
	case strings.HasPrefix(inner, "asn:"):
		v := strings.TrimPrefix(strings.TrimSpace(inner[4:]), "as")
		n, err := strconv.ParseUint(v, 10, 32)
		if err != nil || n == 0 {
			return p, fmt.Errorf("invalid ASN %q", inner[4:])
		}
		p.Kind, p.Value = ASN, strconv.FormatUint(n, 10)
	case strings.HasPrefix(inner, "cidr:") || strings.HasPrefix(inner, "ip:"):
		_, v, _ := strings.Cut(inner, ":")
		v = strings.TrimSpace(v)
		if _, n, err := net.ParseCIDR(v); err == nil {
			v = n.String()
		} else if ip := net.ParseIP(v); ip != nil {
			v = ip.String()
		} else {
			return p, fmt.Errorf("invalid CIDR/IP %q", v)
		}
		p.Kind, p.Value = CIDR, v
	case inner == "":
		return p, fmt.Errorf("drop: needs a rule, e.g. drop:ads.example.com")
	default:
		q, err := Parse(inner)
		if err != nil {
			return p, err
		}
		if q.Negate || q.Drop || q.Session {
			return p, fmt.Errorf("drop: must be followed by a domain rule, asn: or cidr:")
		}
		q.Raw, q.Drop = s, true
		return q, nil
	}
	return p, nil
}

// parseSession parses "session:<domain rule>" or "session[opts]:<rule>".
func parseSession(s string) (Pattern, error) {
	opts, _, inner, _ := splitCmd(s, "session")
	p := Pattern{Raw: s, Session: true}
	o, err := parseOpts(opts)
	if err != nil {
		return p, fmt.Errorf("session[...]: %v", err)
	}
	if inner == "" {
		return p, fmt.Errorf("session: needs a domain rule, e.g. session:example.com")
	}
	q, err := Parse(inner)
	if err != nil {
		return p, err
	}
	if q.Negate || q.Drop || q.Session || q.Kind == ASN || q.Kind == CIDR {
		return p, fmt.Errorf("session: must be followed by a domain rule (a session starts with a DNS lookup)")
	}
	if o.Permanent() {
		return p, fmt.Errorf("session[...]: a negative ttl and set= are for route and drop actions")
	}
	q.Raw, q.Session, q.Opts = s, true, o
	return q, nil
}

func globToRegex(g string) string {
	var b strings.Builder
	b.WriteString("^")
	for i := 0; i < len(g); i++ {
		switch c := g[i]; c {
		case '*':
			if i+1 < len(g) && g[i+1] == '*' {
				b.WriteString(`.+`)
				i++
			} else {
				b.WriteString(`[^.]*`)
			}
		case '?':
			b.WriteString(`[^.]`)
		default:
			b.WriteString(regexp.QuoteMeta(string(c)))
		}
	}
	b.WriteString("$")
	return b.String()
}

// globBase returns the labels after the last label containing a wildcard.
func globBase(g string) string {
	labels := strings.Split(g, ".")
	last := -1
	for i, l := range labels {
		if strings.ContainsAny(l, "*?") {
			last = i
		}
	}
	base := strings.Join(labels[last+1:], ".")
	if !validDomain(base) {
		return ""
	}
	return base
}

// regexBase derives a literal domain suffix from a regex that ends with one,
// e.g. `^ipv4-.*\.oca\.nflxvideo\.net$` -> "oca.nflxvideo.net".
func regexBase(expr string) string {
	re, err := syntax.Parse(expr, syntax.Perl)
	if err != nil {
		return ""
	}
	re = re.Simplify()
	if re.Op != syntax.OpConcat || len(re.Sub) < 2 {
		return ""
	}
	subs := re.Sub
	end := subs[len(subs)-1]
	if end.Op != syntax.OpEndText && end.Op != syntax.OpEndLine {
		return "" // unanchored: anything may follow
	}
	lit := subs[len(subs)-2]
	if lit.Op != syntax.OpLiteral {
		return ""
	}
	s := strings.ToLower(string(lit.Rune))
	if i := strings.Index(s, "."); i >= 0 {
		s = s[i+1:]
	} else {
		return ""
	}
	if !validDomain(s) {
		return ""
	}
	return s
}

// Match reports whether name matches the pattern (ignoring Negate).
func (p Pattern) Match(name string) bool {
	switch p.Kind {
	case Suffix:
		return name == p.Value || strings.HasSuffix(name, "."+p.Value)
	case Subdomains:
		return strings.HasSuffix(name, "."+p.Value)
	case Exact:
		return name == p.Value
	case Keyword:
		return strings.Contains(name, p.Value)
	case Glob, Regex:
		return p.re != nil && p.re.MatchString(name)
	}
	return false // ASN, CIDR: addresses, not names
}

// Native reports whether dnsmasq's ipset= can implement the rule exactly.
func (p Pattern) Native() bool { return p.Kind == Suffix && !p.Negate }

// Set is a compiled rule list. Do not modify Include/Exclude after the
// first MatchAny: the lookup index is built once.
type Set struct {
	once               sync.Once
	inc, exc, drp, ses index
	plainDrop          []Pattern // drop: rules without options (blocked for everyone)
	Include            []Pattern
	Exclude            []Pattern
	Drop               []Pattern // drop: domain rules
	Session            []Pattern // session: domain rules
	Routes             []*Route  // if:...;then:... and route: rules
	// Steps are the rules that start route or drop sessions (if:/route:
	// rules and drop[...]: rules), in the order written: a lookup
	// matching several applies them all, top to bottom.
	Steps     []Step
	DropASNs  []int    // drop:asn:
	DropCIDRs []string // drop:cidr:
}

// LineError is a parse error for one rule.
type LineError struct {
	Index int    `json:"index"`
	Rule  string `json:"rule"`
	Error string `json:"error"`
}

// Compile parses rules, skipping blanks/comments and reporting bad lines.
// A route: rule may span several entries (see Group).
func Compile(rules []string) (*Set, []LineError) {
	s := &Set{}
	var errs []LineError
	for _, lg := range Group(rules) {
		i, r := lg.First, lg.Text
		if StripComment(r) == "" && !IsRoute(r) {
			continue
		}
		if IsRoute(r) {
			rt, err := ParseRoute(r)
			if err != nil {
				errs = append(errs, LineError{Index: i, Rule: r, Error: err.Error()})
				continue
			}
			s.Routes = append(s.Routes, rt)
			s.Steps = append(s.Steps, Step{Line: i, Route: rt})
			continue
		}
		p, err := Parse(r)
		if err != nil {
			errs = append(errs, LineError{Index: i, Rule: r, Error: err.Error()})
			continue
		}
		switch {
		case p.Negate:
			s.Exclude = append(s.Exclude, p)
		case p.Kind == ASN:
			n, _ := strconv.Atoi(p.Value)
			s.DropASNs = append(s.DropASNs, n)
		case p.Kind == CIDR:
			s.DropCIDRs = append(s.DropCIDRs, p.Value)
		case p.Drop:
			s.Drop = append(s.Drop, p)
			if !p.Opts.IsZero() {
				q := p
				s.Steps = append(s.Steps, Step{Line: i, Drop: &q})
			}
		case p.Session:
			s.Session = append(s.Session, p)
		default:
			s.Include = append(s.Include, p)
		}
	}
	return s, errs
}

// Step is a rule that starts route or drop sessions: an if:/route: rule
// or a drop[...]: rule.
type Step struct {
	Line  int      `json:"line"`
	Route *Route   `json:"route,omitempty"`
	Drop  *Pattern `json:"drop,omitempty"`
}

// Raw is the rule's text.
func (st Step) Raw() string {
	if st.Route != nil {
		return st.Route.Raw
	}
	return st.Drop.Raw
}

// Match reports whether the rule has the name (in any branch).
func (st Step) Match(name string) bool {
	if st.Route != nil {
		return st.Route.MatchName(name)
	}
	return st.Drop.Match(name)
}

// StepsFor lists the steps any of the names matches, top to bottom.
func (s *Set) StepsFor(names ...string) []Step {
	var out []Step
	for _, st := range s.Steps {
		for _, n := range names {
			if n != "" && st.Match(n) {
				out = append(out, st)
				break
			}
		}
	}
	return out
}

// firstStep returns the first step a name matches (drop[...] rules only
// with dropOnly) and that name.
func (s *Set) firstStep(names []string, dropOnly bool) (Step, string, bool) {
	for _, st := range s.Steps {
		if dropOnly && st.Drop == nil {
			continue
		}
		for _, n := range names {
			if st.Match(n) {
				return st, n, true
			}
		}
	}
	return Step{}, "", false
}

// MustCompile compiles rules already validated, dropping bad ones.
func MustCompile(rules []string) *Set {
	s, _ := Compile(rules)
	return s
}

// Result explains a match decision.
type Result struct {
	Matched bool   `json:"matched"`
	Name    string `json:"name,omitempty"`    // the name in the chain that matched
	Rule    string `json:"rule,omitempty"`    // the include (or drop) rule that matched
	Drop    bool   `json:"drop,omitempty"`    // a drop: rule matched: block, do not route
	Session bool   `json:"session,omitempty"` // a session: rule matched: route for the asking device only
	// Route: route/drop session rules matched (Set.StepsFor lists them; the
	// device's conditions pick their actions); Rule is the first.
	Route bool `json:"route,omitempty"`
	Opts  Opts `json:"opts,omitempty"` // options of the session: rule
	// Cond lists the if: atoms the names matched: the answer is routed
	// like a plain rule, and its addresses count for those conditions.
	Cond     []CondHit `json:"cond,omitempty"`
	Excluded string    `json:"excluded,omitempty"` // the exclusion that vetoed it
}

// MatchAny tests every name (query name first, then the CNAME chain).
// A name matching an exclusion vetoes the whole answer; otherwise a name
// matching a drop rule blocks it, then session rules, then include rules
// are considered.
// Among the rules matching the first matching name, the earliest is
// reported.
func (s *Set) MatchAny(names ...string) Result {
	s.once.Do(s.build)
	for _, n := range names {
		if i := s.exc.first(n); i >= 0 {
			return Result{Excluded: s.Exclude[i].Raw, Name: n}
		}
	}
	for _, n := range names {
		if i := s.drp.first(n); i >= 0 {
			return Result{Matched: true, Drop: true, Name: n, Rule: s.plainDrop[i].Raw}
		}
	}
	// drop[...] rules: they and every other route/drop rule matching
	// apply, top to bottom.
	if st, n, ok := s.firstStep(names, true); ok {
		return Result{Matched: true, Route: true, Name: n, Rule: st.Raw()}
	}
	for _, n := range names {
		if i := s.ses.first(n); i >= 0 {
			return Result{Matched: true, Session: true, Name: n, Rule: s.Session[i].Raw, Opts: s.Session[i].Opts}
		}
	}
	// if: atoms: always routed; the addresses count for their conditions.
	var hits []CondHit
	first, firstRule := "", ""
	for _, r := range s.Routes {
		if r.If == nil {
			continue
		}
		for _, a := range r.If.Positive() {
			for _, n := range names {
				if a.Atom.Match(n) {
					hits = append(hits, CondHit{Rule: r.Raw, Atom: a.ID})
					if first == "" {
						first, firstRule = n, r.Raw
					}
					break
				}
			}
		}
	}
	if len(hits) > 0 {
		return Result{Matched: true, Name: first, Rule: firstRule, Cond: hits}
	}
	if st, n, ok := s.firstStep(names, false); ok {
		// The device's conditions pick the branches (see Route.Pick).
		return Result{Matched: true, Route: true, Name: n, Rule: st.Raw()}
	}
	for _, n := range names {
		if i := s.inc.first(n); i >= 0 {
			return Result{Matched: true, Name: n, Rule: s.Include[i].Raw}
		}
	}
	return Result{}
}

// index answers "earliest matching pattern" without scanning plain domain
// rules: suffix/subdomain/exact rules are looked up by the name and each of
// its parent domains; only globs, keywords and regexes are scanned.
type index struct {
	whole map[string]int // name == value: Suffix, Exact
	sub   map[string]int // name ends in "."+value: Suffix, Subdomains
	slow  []int          // pattern indexes that need Match
	pats  []Pattern
}

func newIndex(pats []Pattern) index {
	x := index{whole: map[string]int{}, sub: map[string]int{}, pats: pats}
	keep := func(m map[string]int, k string, i int) {
		if j, ok := m[k]; !ok || i < j {
			m[k] = i
		}
	}
	for i, p := range pats {
		switch p.Kind {
		case Suffix:
			keep(x.whole, p.Value, i)
			keep(x.sub, p.Value, i)
		case Exact:
			keep(x.whole, p.Value, i)
		case Subdomains:
			keep(x.sub, p.Value, i)
		default:
			x.slow = append(x.slow, i)
		}
	}
	return x
}

// first returns the index of the earliest pattern matching name, or -1.
func (x *index) first(name string) int {
	best := -1
	better := func(i int) {
		if best < 0 || i < best {
			best = i
		}
	}
	if i, ok := x.whole[name]; ok {
		better(i)
	}
	for rest := name; ; {
		dot := strings.IndexByte(rest, '.')
		if dot < 0 {
			break
		}
		rest = rest[dot+1:]
		if i, ok := x.sub[rest]; ok {
			better(i)
		}
	}
	for _, i := range x.slow {
		if best >= 0 && i > best {
			break
		}
		if x.pats[i].Match(name) {
			better(i)
			break
		}
	}
	return best
}

func (s *Set) build() {
	for _, p := range s.Drop {
		if p.Opts.IsZero() {
			s.plainDrop = append(s.plainDrop, p)
		}
	}
	s.inc, s.exc, s.drp, s.ses = newIndex(s.Include), newIndex(s.Exclude), newIndex(s.plainDrop), newIndex(s.Session)
}

// Empty reports whether the set has no include rules (session: rules count).
func (s *Set) Empty() bool { return s == nil || len(s.Include)+len(s.Session)+len(s.Routes) == 0 }

// HasSessions reports whether the set has session: or route: rules.
func (s *Set) HasSessions() bool { return s != nil && len(s.Session)+len(s.Routes) > 0 }

// HasConds reports whether some route: rule has an if: part.
func (s *Set) HasConds() bool {
	for _, r := range s.Routes {
		if r.If != nil {
			return true
		}
	}
	return false
}

// CondHits lists the if: atoms (negated ones too) any of the names
// matches: the addresses of such an answer count for those conditions,
// whatever routes it.
func (s *Set) CondHits(names ...string) []CondHit {
	var hits []CondHit
	for _, r := range s.Routes {
		if r.If == nil {
			continue
		}
		for _, a := range r.If.All() {
			for _, n := range names {
				if a.Atom.Match(n) {
					hits = append(hits, CondHit{Rule: r.Raw, Atom: a.ID})
					break
				}
			}
		}
	}
	return hits
}

// Route returns the route: rule with this text.
func (s *Set) Route(raw string) *Route {
	for _, r := range s.Routes {
		if r.Raw == raw {
			return r
		}
	}
	return nil
}

// HasDrops reports whether the set has any drop: rule.
func (s *Set) HasDrops() bool {
	return s != nil && len(s.Drop)+len(s.DropASNs)+len(s.DropCIDRs) > 0
}

// DropSuffixes returns the plain drop: suffix rules dnsmasq can add to the
// drop set by itself. With exclusions there are none unless degraded (no
// DNS inspector), since dnsmasq cannot honour them. Extra drop entries are
// safe otherwise: a drop beats include rules anyway.
func (s *Set) DropSuffixes(degraded bool) []string {
	if len(s.Exclude) > 0 && !degraded {
		return nil
	}
	var out []string
	for _, p := range s.Drop {
		if p.Kind == Suffix && p.Opts.IsZero() { // drop sessions are per device
			out = append(out, p.Value)
		}
	}
	return out
}

// HasDropSessions reports whether some drop: rules have options (drop
// sessions, blocked per device).
func (s *Set) HasDropSessions() bool {
	for _, r := range s.Routes {
		if r.HasDrop() {
			return true
		}
	}
	for _, p := range s.Drop {
		if !p.Opts.IsZero() {
			return true
		}
	}
	return false
}

// NativeSuffixes returns rules dnsmasq can handle by itself. When the set has
// exclusions none are native, since dnsmasq cannot honour them.
func (s *Set) NativeSuffixes() []string {
	if len(s.Exclude) > 0 {
		return nil
	}
	var out []string
	for _, p := range s.Include {
		if p.Native() {
			out = append(out, p.Value)
		}
	}
	return out
}

// PlainSuffixes returns the include rules dnsmasq can match, ignoring
// exclusions (degraded mode when the DNS inspector is unavailable).
func (s *Set) PlainSuffixes() []string {
	var out []string
	for _, p := range s.Include {
		if p.Native() {
			out = append(out, p.Value)
		}
	}
	return out
}

// NeedsInspector reports whether some rules need DNS answer inspection.
// session: rules always do: only the inspector knows which device asked.
func (s *Set) NeedsInspector() bool {
	if len(s.Session)+len(s.Routes) > 0 {
		return true
	}
	if len(s.Exclude) > 0 {
		return len(s.Include)+len(s.Drop) > 0
	}
	for _, p := range s.Include {
		if !p.Native() {
			return true
		}
	}
	for _, p := range s.Drop {
		if p.Kind != Suffix || !p.Opts.IsZero() {
			return true
		}
	}
	return false
}

// Bases returns literal domain suffixes covering the include rules (used to
// send their DNS through the tunnel and for pre-resolving). Rules without a
// derivable suffix (keywords, unanchored regexes) contribute nothing.
func (s *Set) Bases() []string {
	seen := map[string]bool{}
	var out []string
	pats := append(append([]Pattern(nil), s.Include...), s.Session...)
	for _, r := range s.Routes {
		xs := []*Expr{r.If}
		for _, a := range r.Branches() {
			if a.Kind == ActRoute {
				xs = append(xs, a.Expr)
			}
		}
		for _, x := range xs {
			if x != nil {
				for _, a := range x.Positive() {
					pats = append(pats, *a.Atom)
				}
			}
		}
	}
	for _, p := range pats {
		if p.Base != "" && !seen[p.Base] {
			seen[p.Base] = true
			out = append(out, p.Base)
		}
	}
	return out
}
