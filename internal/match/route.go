package match

import (
	"fmt"
	"strings"
)

// Conditional rules:
//
//	route:EXPR;if:EXPR
//
// The if: part's names are routed like plain rules, for every device; the
// addresses they resolve to are remembered per atom. The route: part is
// routed as device sessions: when a device looks up a name it matches, the
// answer starts sessions for that device only if the if: condition holds
// for it (the device has a live connection to an address of the
// condition's atoms; not: negates). Without ;if: the route: part always
// starts sessions (like session:, with expressions).
//
// EXPR is a domain rule (suffix, .sub, =exact, glob, ~keyword, /regex/), or
// a modifier: not:EXPR, and:(EXPR, EXPR, ...), or:(EXPR, EXPR, ...), or
// (EXPR). A rule may span lines: it continues after a line ending in ";",
// before a line starting with ";", and while parentheses are open.

// RoutePrefix starts a conditional rule.
const RoutePrefix = "route:"

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

// Route is a parsed conditional rule.
type Route struct {
	Raw   string `json:"raw"`
	Opts  Opts   `json:"opts,omitempty"` // route[...] options for its sessions
	Route *Expr  `json:"route"`
	If    *Expr  `json:"if,omitempty"` // nil: always
}

// CondHit says an address belongs to atom Atom of the if: part of Rule.
type CondHit struct {
	Rule string `json:"rule"`
	Atom int    `json:"atom"`
}

// IsRoute reports whether a rule (or its first line) is a route: rule.
func IsRoute(s string) bool {
	t := strings.TrimSpace(s)
	return len(t) > 5 && strings.EqualFold(t[:5], "route") && (t[5] == ':' || t[5] == '[')
}

// normalizeRoute keeps a route: rule's text as written (atoms are
// normalized when parsed), without comments and trailing spaces.
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
	return strings.Join(out, "\n")
}

// ParseRoute parses a route: rule (possibly spanning lines).
func ParseRoute(text string) (*Route, error) {
	norm := normalizeRoute(text)
	var b strings.Builder
	for _, l := range strings.Split(norm, "\n") {
		b.WriteString(strings.TrimSpace(l))
	}
	opts, _, rest, ok := splitCmd(b.String(), "route")
	if !ok {
		return nil, fmt.Errorf("a conditional rule starts with route: or route[options]:")
	}
	o, err := parseOpts(opts)
	if err != nil {
		return nil, fmt.Errorf("route[...]: %v", err)
	}
	p := &exprParser{s: rest}
	r := &Route{Raw: norm, Opts: o}
	if r.Route, err = p.expr(); err != nil {
		return nil, fmt.Errorf("route: %v", err)
	}
	if p.eat(";") {
		if !p.eat("if:") {
			return nil, fmt.Errorf("expected if: after ; (route:...;if:...)")
		}
		if r.If, err = p.expr(); err != nil {
			return nil, fmt.Errorf("if: %v", err)
		}
	}
	if p.i < len(p.s) {
		return nil, fmt.Errorf("unexpected %q at the end", p.s[p.i:])
	}
	number(r.Route)
	if r.If != nil {
		number(r.If)
		if len(r.If.Positive()) == 0 {
			return nil, fmt.Errorf("if: needs at least one condition that is not negated")
		}
	}
	return r, nil
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
	for _, bad := range []string{"re:", "drop:", "session:", "route:", "if:", "asn:", "cidr:", "ip:", "!"} {
		if strings.HasPrefix(lo, bad) {
			return nil, fmt.Errorf("%q: only domain rules (and not:, and:, or:) go in a route: or if: expression; write regexes as /.../", text)
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

// Group joins the lines of multi-line route: rules: a rule continues after
// a line ending in ";", before a line starting with ";", and while its
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
			if open(cur) || strings.HasSuffix(strings.TrimSpace(StripComment(lastLine(cur))), ";") || strings.HasPrefix(next, ";") {
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
