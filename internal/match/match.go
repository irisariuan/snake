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
//
// Names are compared lowercase without the trailing dot. With CNAME following
// (the default) a rule also matches when any name in the answer's CNAME chain
// matches, so e.g. "**.akamaized.net" catches services that CNAME into Akamai.
package match

import (
	"fmt"
	"regexp"
	"regexp/syntax"
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
)

// Pattern is one parsed rule.
type Pattern struct {
	Raw    string `json:"raw"`
	Kind   Kind   `json:"kind"`
	Negate bool   `json:"negate"`
	Value  string `json:"value"`
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
	s = StripComment(s)
	if s == "" {
		return ""
	}
	neg := ""
	if strings.HasPrefix(s, "!") {
		neg, s = "!", strings.TrimSpace(s[1:])
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
	return false
}

// Native reports whether dnsmasq's ipset= can implement the rule exactly.
func (p Pattern) Native() bool { return p.Kind == Suffix && !p.Negate }

// Set is a compiled rule list. Do not modify Include/Exclude after the
// first MatchAny: the lookup index is built once.
type Set struct {
	once     sync.Once
	inc, exc index
	Include  []Pattern
	Exclude  []Pattern
}

// LineError is a parse error for one rule.
type LineError struct {
	Index int    `json:"index"`
	Rule  string `json:"rule"`
	Error string `json:"error"`
}

// Compile parses rules, skipping blanks/comments and reporting bad lines.
func Compile(rules []string) (*Set, []LineError) {
	s := &Set{}
	var errs []LineError
	for i, r := range rules {
		if StripComment(r) == "" {
			continue
		}
		p, err := Parse(r)
		if err != nil {
			errs = append(errs, LineError{Index: i, Rule: r, Error: err.Error()})
			continue
		}
		if p.Negate {
			s.Exclude = append(s.Exclude, p)
		} else {
			s.Include = append(s.Include, p)
		}
	}
	return s, errs
}

// MustCompile compiles rules already validated, dropping bad ones.
func MustCompile(rules []string) *Set {
	s, _ := Compile(rules)
	return s
}

// Result explains a match decision.
type Result struct {
	Matched  bool   `json:"matched"`
	Name     string `json:"name,omitempty"`     // the name in the chain that matched
	Rule     string `json:"rule,omitempty"`     // the include rule that matched
	Excluded string `json:"excluded,omitempty"` // the exclusion that vetoed it
}

// MatchAny tests every name (query name first, then the CNAME chain).
// A name matching an exclusion vetoes the whole answer. Among the rules
// matching the first matching name, the earliest rule is reported.
func (s *Set) MatchAny(names ...string) Result {
	s.once.Do(s.build)
	for _, n := range names {
		if i := s.exc.first(n); i >= 0 {
			return Result{Excluded: s.Exclude[i].Raw, Name: n}
		}
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
	s.inc, s.exc = newIndex(s.Include), newIndex(s.Exclude)
}

// Empty reports whether the set has no include rules.
func (s *Set) Empty() bool { return s == nil || len(s.Include) == 0 }

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
func (s *Set) NeedsInspector() bool {
	if len(s.Exclude) > 0 {
		return len(s.Include) > 0
	}
	for _, p := range s.Include {
		if !p.Native() {
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
	for _, p := range s.Include {
		if p.Base != "" && !seen[p.Base] {
			seen[p.Base] = true
			out = append(out, p.Base)
		}
	}
	return out
}
