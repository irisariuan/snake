package match

import (
	"fmt"
	"strings"
)

// Conditional rules:
//
//	if:COND;then:ACTION;else:ACTION;finally:ACTION
//
// else: and finally: are optional. ACTION is route[options]:EXPR (the
// names' answers start sessions through the tunnel for the device) or
// drop[options]:EXPR (they start drop sessions, blocking the addresses for
// the device); options as for session[...]: (ttl, onlookup, share).
//
// The if: part's names are routed like plain rules, for every device; the
// addresses they resolve to are remembered per atom. When a device looks
// up a name of a branch, the condition is evaluated for that device: it
// holds while the device has a live connection to an address of the
// condition's atoms (not: negates). If it holds, then: names get then:'s
// action, otherwise else: names get else:'s action; finally: names get
// finally:'s action either way, unless the branch taken also has the name.
//
// A plain route[options]:EXPR (no if:) always starts sessions (like
// session:, with expressions). The old form route[options]:EXPR;if:COND is
// read as if:COND;then:route[options]:EXPR.
//
// EXPR and COND are a domain rule (suffix, .sub, =exact, glob, ~keyword,
// /regex/), or a modifier: not:EXPR, and:(EXPR, EXPR, ...),
// or:(EXPR, EXPR, ...), or (EXPR) / (EXPR, EXPR, ...) for and:. A rule may
// span lines: it continues after a line ending in ";", before a line
// starting with ";" or then:/else:/finally:, and while parentheses are open.

// RoutePrefix starts an unconditional session rule with expressions.
const RoutePrefix = "route:"

// IfPrefix starts a conditional rule.
const IfPrefix = "if:"

// Branch actions.
const (
	ActRoute = "route"
	ActDrop  = "drop"
)

// Expr is a parsed condition or name expression.
type Expr struct {
	Op   string   `json:"op"` // atom, not, and, or
	Atom *Pattern `json:"atom,omitempty"`
	ID   int      `json:"id,omitempty"` // atom number within its expression (1-based)
	Kids []*Expr  `json:"kids,omitempty"`
}

// MatchName evaluates the expression against one name.
func (x *Expr) MatchName(name string) bool {
	return x.Eval(func(a *Expr) bool { return a.Atom.Match(name) })
}

// Eval evaluates the expression with atom truth values from f.
func (x *Expr) Eval(f func(atom *Expr) bool) bool {
	switch x.Op {
	case "atom":
		return f(x)
	case "not":
		return !x.Kids[0].Eval(f)
	case "and":
		for _, k := range x.Kids {
			if !k.Eval(f) {
				return false
			}
		}
		return true
	case "or":
		for _, k := range x.Kids {
			if k.Eval(f) {
				return true
			}
		}
	}
	return false
}

// Positive lists the atoms not under a not: (an odd number of them).
func (x *Expr) Positive() []*Expr {
	var out []*Expr
	var walk func(e *Expr, neg bool)
	walk = func(e *Expr, neg bool) {
		switch e.Op {
		case "atom":
			if !neg {
				out = append(out, e)
			}
		case "not":
			walk(e.Kids[0], !neg)
		default:
			for _, k := range e.Kids {
				walk(k, neg)
			}
		}
	}
	walk(x, false)
	return out
}

// All lists every atom.
func (x *Expr) All() []*Expr {
	var out []*Expr
	var walk func(e *Expr)
	walk = func(e *Expr) {
		if e.Op == "atom" {
			out = append(out, e)
		}
		for _, k := range e.Kids {
			walk(k)
		}
	}
	walk(x)
	return out
}

// Action is one branch of a conditional rule.
type Action struct {
	Kind string `json:"kind"` // route or drop
	Opts Opts   `json:"opts,omitempty"`
	Expr *Expr  `json:"expr"`
}

// Match reports whether the branch has the name.
func (a *Action) Match(name string) bool { return a != nil && a.Expr.MatchName(name) }

// Route is a parsed conditional rule (or a plain route: rule: no If, the
// action in Then).
type Route struct {
	Raw     string  `json:"raw"`
	If      *Expr   `json:"if,omitempty"` // nil: always
	Then    *Action `json:"then"`
	Else    *Action `json:"else,omitempty"`
	Finally *Action `json:"finally,omitempty"`
}

// Branches lists the rule's actions.
func (r *Route) Branches() []*Action {
	var out []*Action
	for _, a := range []*Action{r.Then, r.Else, r.Finally} {
		if a != nil {
			out = append(out, a)
		}
	}
	return out
}

// MatchName reports whether a branch has the name.
func (r *Route) MatchName(name string) bool {
	for _, a := range r.Branches() {
		if a.Match(name) {
			return true
		}
	}
	return false
}

// Pick returns the action for a name when the condition is (not) met:
// then: (or else:) first, then finally:. Nil: nothing to do.
func (r *Route) Pick(cond bool, names ...string) *Action {
	branch := r.Then
	if !cond {
		branch = r.Else
	}
	for _, a := range []*Action{branch, r.Finally} {
		for _, n := range names {
			if n != "" && a.Match(n) {
				return a
			}
		}
	}
	return nil
}

// HasDrop reports whether a branch drops.
func (r *Route) HasDrop() bool {
	for _, a := range r.Branches() {
		if a.Kind == ActDrop {
			return true
		}
	}
	return false
}

// CondHit says an address belongs to atom Atom of the if: part of Rule.
type CondHit struct {
	Rule string `json:"rule"`
	Atom int    `json:"atom"`
}

// IsRoute reports whether a rule (or its first line) is a conditional
// (if:) or route: rule.
func IsRoute(s string) bool {
	t := strings.TrimSpace(s)
	if len(t) > 3 && strings.EqualFold(t[:3], IfPrefix) {
		return true
	}
	return len(t) > 5 && strings.EqualFold(t[:5], "route") && (t[5] == ':' || t[5] == '[')
}

// normalizeRoute keeps a rule's text as written (atoms are normalized when
// parsed), without comments and trailing spaces; the old route:...;if:...
// form is rewritten as if:...;then:route:....
func normalizeRoute(s string) string {
	var out []string
	for _, l := range strings.Split(s, "\n") {
		lead := l[:len(l)-len(strings.TrimLeft(l, " \t"))]
		l = StripComment(l)
		if l == "" {
			continue
		}
		if len(out) == 0 {
			// Canonical command prefix: route: or route[options]:
			if opts, _, rest, ok := splitCmd(l, "route"); ok {
				if o, err := parseOpts(opts); err == nil {
					l = cmdPrefix("route", o) + rest
				}
			}
			out = append(out, l)
			continue
		}
		out = append(out, lead+l)
	}
	text := strings.Join(out, "\n")
	if conv, ok := convertLegacy(text); ok {
		return conv
	}
	return text
}

func joinLines(text string) string {
	var b strings.Builder
	for _, l := range strings.Split(text, "\n") {
		l = strings.TrimSpace(StripComment(l))
		// A line starting a branch needs no ";" before it.
		if startsBranch(l) && b.Len() > 0 && !strings.HasSuffix(b.String(), ";") {
			b.WriteString(";")
		}
		b.WriteString(l)
	}
	return b.String()
}

// IsLegacyRoute reports whether text is the old route:EXPR;if:COND form.
func IsLegacyRoute(text string) bool {
	_, ok := convertLegacy(text)
	return ok
}

// ConvertLegacy rewrites the old route[options]:EXPR;if:COND form as
// if:COND;then:route[options]:EXPR.
func ConvertLegacy(text string) (string, bool) { return convertLegacy(text) }

func convertLegacy(text string) (string, bool) {
	joined := joinLines(text)
	opts, _, rest, ok := splitCmd(joined, "route")
	if !ok {
		return "", false
	}
	o, err := parseOpts(opts)
	if err != nil {
		return "", false
	}
	p := &exprParser{s: rest}
	if _, err := p.expr(); err != nil {
		return "", false
	}
	exprText := strings.TrimSpace(rest[:p.i])
	if !p.eat(";") || !p.eat(IfPrefix) {
		return "", false
	}
	condText := strings.TrimSpace(rest[p.i:])
	if _, err := (&exprParser{s: condText}).expr(); err != nil {
		return "", false
	}
	sep := ";"
	if strings.Contains(strings.TrimSpace(text), "\n") {
		sep = ";\n"
	}
	return IfPrefix + condText + sep + "then:" + cmdPrefix(ActRoute, o) + exprText, true
}

// ParseRoute parses a conditional or route: rule (possibly spanning lines).
func ParseRoute(text string) (*Route, error) {
	norm := normalizeRoute(text)
	s := joinLines(norm)
	r := &Route{Raw: norm}
	if len(s) >= 3 && strings.EqualFold(s[:3], IfPrefix) {
		p := &exprParser{s: s[3:]}
		var err error
		if r.If, err = p.expr(); err != nil {
			return nil, fmt.Errorf("if: %v", err)
		}
		if !p.eat(";") || !p.eat("then:") {
			return nil, fmt.Errorf("expected ;then:ACTION after the if: condition (if:COND;then:route:EXPR)")
		}
		if r.Then, err = p.action("then"); err != nil {
			return nil, err
		}
		for _, br := range []string{"else", "finally"} {
			save := p.i
			if !p.eat(";") {
				break
			}
			if !p.eat(br + ":") {
				p.i = save
				continue
			}
			a, err := p.action(br)
			if err != nil {
				return nil, err
			}
			if br == "else" {
				r.Else = a
			} else {
				r.Finally = a
			}
		}
		p.eat(";")
		if p.i < len(p.s) {
			rest := p.s[p.i:]
			lo := strings.ToLower(strings.TrimLeft(rest, " \t;"))
			for _, kw := range []string{"then:", "else:", "finally:", "if:"} {
				if strings.HasPrefix(lo, kw) {
					return nil, fmt.Errorf("unexpected %q: the parts go in the order if:, then:, else:, finally:, each once", rest)
				}
			}
			return nil, fmt.Errorf("unexpected %q at the end", rest)
		}
		number(r.If)
		if len(r.If.Positive()) == 0 {
			return nil, fmt.Errorf("if: needs at least one condition that is not negated")
		}
		for _, a := range r.Branches() {
			number(a.Expr)
		}
		return r, nil
	}
	opts, _, rest, ok := splitCmd(s, "route")
	if !ok {
		return nil, fmt.Errorf("a conditional rule starts with if: (if:COND;then:route:EXPR) or route:")
	}
	o, err := parseOpts(opts)
	if err != nil {
		return nil, fmt.Errorf("route[...]: %v", err)
	}
	p := &exprParser{s: rest}
	r.Then = &Action{Kind: ActRoute, Opts: o}
	if r.Then.Expr, err = p.expr(); err != nil {
		return nil, fmt.Errorf("route: %v", err)
	}
	p.eat(";")
	if p.i < len(p.s) {
		return nil, fmt.Errorf("unexpected %q at the end", p.s[p.i:])
	}
	number(r.Then.Expr)
	return r, nil
}

// action parses route[options]:EXPR or drop[options]:EXPR.
func (p *exprParser) action(part string) (*Action, error) {
	p.skip()
	rest := p.s[p.i:]
	for _, kind := range []string{ActRoute, ActDrop} {
		opts, _, after, ok := splitCmd(rest, kind)
		if !ok {
			continue
		}
		o, err := parseOpts(opts)
		if err != nil {
			return nil, fmt.Errorf("%s: %s[...]: %v", part, kind, err)
		}
		p.i = len(p.s) - len(after)
		x, err := p.expr()
		if err != nil {
			return nil, fmt.Errorf("%s: %s: %v", part, kind, err)
		}
		return &Action{Kind: kind, Opts: o, Expr: x}, nil
	}
	return nil, fmt.Errorf("%s: needs an action: route[options]:EXPR or drop[options]:EXPR", part)
}

func number(x *Expr) {
	n := 0
	var walk func(e *Expr)
	walk = func(e *Expr) {
		if e.Op == "atom" {
			n++
			e.ID = n
		}
		for _, k := range e.Kids {
			walk(k)
		}
	}
	walk(x)
}

type exprParser struct {
	s string
	i int
}

func (p *exprParser) skip() {
	for p.i < len(p.s) && (p.s[p.i] == ' ' || p.s[p.i] == '\t') {
		p.i++
	}
}

func (p *exprParser) eat(tok string) bool {
	p.skip()
	if len(p.s)-p.i >= len(tok) && strings.EqualFold(p.s[p.i:p.i+len(tok)], tok) {
		p.i += len(tok)
		return true
	}
	return false
}

func (p *exprParser) expr() (*Expr, error) {
	switch {
	case p.eat("not:"):
		k, err := p.expr()
		if err != nil {
			return nil, err
		}
		return &Expr{Op: "not", Kids: []*Expr{k}}, nil
	case p.eat("and:"):
		return p.list("and")
	case p.eat("or:"):
		return p.list("or")
	case p.eat("("):
		// (x) groups; (x, y, ...) is and:(x, y, ...).
		x := &Expr{Op: "and"}
		for {
			k, err := p.expr()
			if err != nil {
				return nil, err
			}
			x.Kids = append(x.Kids, k)
			if p.eat(",") {
				continue
			}
			if p.eat(")") {
				break
			}
			return nil, fmt.Errorf("expected , or )")
		}
		if len(x.Kids) == 1 {
			return x.Kids[0], nil
		}
		return x, nil
	}
	return p.atom()
}

func (p *exprParser) list(op string) (*Expr, error) {
	if !p.eat("(") {
		return nil, fmt.Errorf("%s: needs ( ... ), e.g. %s:(a.com, b.com)", op, op)
	}
	x := &Expr{Op: op}
	for {
		k, err := p.expr()
		if err != nil {
			return nil, err
		}
		x.Kids = append(x.Kids, k)
		if p.eat(",") {
			continue
		}
		if p.eat(")") {
			break
		}
		return nil, fmt.Errorf("expected , or ) in %s:( ... )", op)
	}
	return x, nil
}

func (p *exprParser) atom() (*Expr, error) {
	p.skip()
	start := p.i
	if p.i < len(p.s) && p.s[p.i] == '/' {
		// /regex/: up to the next unescaped slash.
		p.i++
		for p.i < len(p.s) && p.s[p.i] != '/' {
			if p.s[p.i] == '\\' {
				p.i++
			}
			p.i++
		}
		if p.i >= len(p.s) {
			return nil, fmt.Errorf("unterminated /regex/")
		}
		p.i++
	} else {
		for p.i < len(p.s) && !strings.ContainsRune(",();", rune(p.s[p.i])) && p.s[p.i] != ' ' && p.s[p.i] != '\t' {
			p.i++
		}
	}
	text := p.s[start:p.i]
	if text == "" {
		if p.i < len(p.s) {
			return nil, fmt.Errorf("expected a domain rule at %q", p.s[p.i:])
		}
		return nil, fmt.Errorf("expected a domain rule")
	}
	lo := strings.ToLower(text)
	for _, bad := range []string{"re:", "drop:", "drop[", "session:", "session[", "route:", "route[", "if:", "then:", "else:", "finally:", "asn:", "cidr:", "ip:", "!"} {
		if strings.HasPrefix(lo, bad) {
			return nil, fmt.Errorf("%q: only domain rules (and not:, and:, or:) go in an expression; write regexes as /.../", text)
		}
	}
	pat, err := Parse(text)
	if err != nil {
		return nil, fmt.Errorf("%q: %v", text, err)
	}
	return &Expr{Op: "atom", Atom: &pat}, nil
}

// Logical is one rule built from one or more lines.
type Logical struct {
	First int    // index of its first line
	Text  string // its lines, joined with newlines
}

// Group joins the lines of multi-line if:/route: rules: a rule continues
// after a line ending in ";", before a line starting with ";", then:, else:
// or finally:, and while its
// parentheses (outside /regexes/) are open. Other lines stay as they are.
func Group(lines []string) []Logical {
	var out []Logical
	for i := 0; i < len(lines); i++ {
		if !IsRoute(StripComment(lines[i])) {
			out = append(out, Logical{First: i, Text: lines[i]})
			continue
		}
		parts := []string{lines[i]}
		j := i
		for j+1 < len(lines) {
			cur := strings.Join(parts, "\n")
			next := strings.TrimSpace(StripComment(lines[j+1]))
			if next == "" {
				if open(cur) {
					j++
					parts = append(parts, lines[j])
					continue
				}
				break
			}
			if open(cur) || strings.HasSuffix(strings.TrimSpace(StripComment(lastLine(cur))), ";") || strings.HasPrefix(next, ";") || startsBranch(next) {
				j++
				parts = append(parts, lines[j])
				continue
			}
			break
		}
		out = append(out, Logical{First: i, Text: strings.Join(parts, "\n")})
		i = j
	}
	return out
}

func startsBranch(s string) bool {
	lo := strings.ToLower(s)
	return strings.HasPrefix(lo, "then:") || strings.HasPrefix(lo, "else:") || strings.HasPrefix(lo, "finally:")
}

func lastLine(s string) string {
	if k := strings.LastIndexByte(s, '\n'); k >= 0 {
		return s[k+1:]
	}
	return s
}

// open reports whether text has unclosed parentheses outside /regexes/.
func open(text string) bool {
	depth := 0
	for _, l := range strings.Split(text, "\n") {
		l = StripComment(l)
		inRe := false
		prev := byte(0)
		for k := 0; k < len(l); k++ {
			c := l[k]
			switch {
			case inRe:
				if c == '/' && prev != '\\' {
					inRe = false
				}
			case c == '/' && (prev == 0 || strings.ContainsRune("(,: \t", rune(prev))):
				inRe = true
			case c == '(':
				depth++
			case c == ')':
				depth--
			}
			if c != ' ' && c != '\t' {
				prev = c
			}
		}
	}
	return depth > 0
}

// Lines groups lines and returns the logical rules' text.
func Lines(lines []string) []string {
	g := Group(lines)
	out := make([]string, len(g))
	for i, l := range g {
		out[i] = l.Text
	}
	return out
}
