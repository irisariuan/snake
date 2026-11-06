package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"os"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/irisariuan/snake/internal/config"
	"github.com/irisariuan/snake/internal/engine"
	"github.com/irisariuan/snake/internal/learn"
)

const learnUsage = `usage:
  snake learn list [--json]                  learning groups (STUN/TURN servers)
  snake learn show <id> [--json]             one group: servers and discovery sessions
  snake learn new <name> [--route P|off] [ADDR...]
  snake learn set <id> [--name N] [--notes T] [--route P|off] [--enable|--disable]
                       [--pin|--unpin] [--ttl SECONDS|default]
  snake learn add <id> ADDR...               add servers by hand (never expire)
  snake learn rm <id> ADDR...                remove servers
  snake learn move <id> <to-id> ADDR...      move servers to another group
  snake learn merge <id> <into-id>           merge a group into another
  snake learn delete <id>

  snake learn addrs <policy> [--kind dns|peer] [--filter Q] [--limit N] [--json]
                                             addresses a policy learned (DNS answers,
                                             WebRTC peers)
  snake learn forget <policy> [--kind dns|peer] (ADDR... | --rule RULE | --all)
                                             remove learned addresses

P and <policy> are a policy name or id.`

// learnAPI is the daemon call used by learn commands (replaced in tests).
var learnAPI = func(method, path string, body any) ([]byte, error) {
	var r io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return nil, err
		}
		r = bytes.NewReader(b)
	}
	return call(method, path, r)
}

// learnConfig loads the configuration for policy name lookups (replaced in tests).
var learnConfig = func() (*config.Config, error) { return loadNormalized(paths().Config) }

// loadNormalized loads the configuration the way the daemon sees it (policy
// ids assigned).
func loadNormalized(path string) (*config.Config, error) {
	c, err := config.Load(path)
	if err != nil {
		return nil, err
	}
	c.ApplyDefaults()
	c.Normalize()
	return c, nil
}

// valueFlags take an argument.
var learnValueFlags = map[string]bool{"--name": true, "--notes": true, "--route": true, "--ttl": true, "--kind": true, "--filter": true, "--limit": true, "--rule": true}

// positional returns the arguments that are not flags or flag values.
func positional(args []string) []string {
	var out []string
	for i := 0; i < len(args); i++ {
		a := args[i]
		if strings.HasPrefix(a, "--") {
			if learnValueFlags[a] {
				i++
			}
			continue
		}
		out = append(out, a)
	}
	return out
}

func hasValueFlag(args []string, f string) bool {
	for _, a := range args {
		if a == f || strings.HasPrefix(a, f+"=") {
			return true
		}
	}
	return false
}

func learnCmd(args []string) error { return runLearn(args, os.Stdout) }

func runLearn(args []string, w io.Writer) error {
	if len(args) == 0 {
		return fmt.Errorf("%s", learnUsage)
	}
	sub, rest := args[0], args[1:]
	pos := positional(rest)
	need := func(n int) error {
		if len(pos) < n {
			return fmt.Errorf("%s", learnUsage)
		}
		if n > 0 && sub != "new" && sub != "addrs" && sub != "forget" {
			if id, err := strconv.Atoi(pos[0]); err != nil || id <= 0 {
				return fmt.Errorf("bad group id %q (see snake learn list)", pos[0])
			}
		}
		return nil
	}
	switch sub {
	case "list", "ls":
		return learnList(w, hasFlag(rest, "--json"))
	case "show":
		if err := need(1); err != nil {
			return err
		}
		return learnShow(w, pos[0], hasFlag(rest, "--json"))
	case "new":
		if err := need(1); err != nil {
			return err
		}
		body := map[string]any{"name": pos[0], "servers": pos[1:]}
		if hasValueFlag(rest, "--route") {
			id, err := routeID(flagValue(rest, "--route"))
			if err != nil {
				return err
			}
			body["route_via"] = id
		}
		return learnEdit(w, "POST", "/api/learnings", body, "created group %q", pos[0])
	case "set":
		if err := need(1); err != nil {
			return err
		}
		p, err := learnPatch(rest)
		if err != nil {
			return err
		}
		return learnEdit(w, "PUT", "/api/learnings/"+pos[0], p, "updated group %s", pos[0])
	case "add", "rm":
		if err := need(2); err != nil {
			return err
		}
		key := map[string]string{"add": "add", "rm": "remove"}[sub]
		return learnEdit(w, "POST", "/api/learnings/"+pos[0]+"/servers", map[string]any{key: pos[1:]}, "%s: %d server(s) in group %s", sub, len(pos)-1, pos[0])
	case "move", "mv":
		if err := need(3); err != nil {
			return err
		}
		to, err := strconv.Atoi(pos[1])
		if err != nil {
			return fmt.Errorf("bad target group %q", pos[1])
		}
		return learnEdit(w, "POST", "/api/learnings/"+pos[0]+"/move", map[string]any{"servers": pos[2:], "to": to}, "moved %d server(s) to group %d", len(pos)-2, to)
	case "merge":
		if err := need(2); err != nil {
			return err
		}
		into, err := strconv.Atoi(pos[1])
		if err != nil {
			return fmt.Errorf("bad target group %q", pos[1])
		}
		return learnEdit(w, "POST", "/api/learnings/"+pos[0]+"/merge", map[string]any{"into": into}, "merged group %s into %d", pos[0], into)
	case "delete", "del":
		if err := need(1); err != nil {
			return err
		}
		return learnEdit(w, "DELETE", "/api/learnings/"+pos[0], nil, "deleted group %s", pos[0])
	case "addrs":
		if err := need(1); err != nil {
			return err
		}
		return learnAddrs(w, pos[0], rest)
	case "forget":
		if err := need(1); err != nil {
			return err
		}
		req := engine.ForgetRequest{Kind: flagValue(rest, "--kind"), Addrs: pos[1:], All: hasFlag(rest, "--all")}
		if hasValueFlag(rest, "--rule") {
			r := flagValue(rest, "--rule")
			req.Rule = &r
		}
		if !req.All && req.Rule == nil && len(req.Addrs) == 0 {
			return fmt.Errorf("forget needs addresses, --rule RULE or --all")
		}
		b, err := learnAPI("POST", "/api/learned/"+url.PathEscape(pos[0])+"/forget", req)
		if err != nil {
			return err
		}
		var r struct{ Removed int }
		_ = json.Unmarshal(b, &r)
		fmt.Fprintf(w, "removed %d address(es); they come back when the policy learns them again\n", r.Removed)
		return nil
	}
	return fmt.Errorf("%s", learnUsage)
}

func routeID(v string) (int, error) {
	if v == "off" || v == "0" || v == "wan" {
		return 0, nil
	}
	cfg, err := learnConfig()
	if err != nil {
		return 0, err
	}
	id, _ := strconv.Atoi(v)
	for _, p := range cfg.Policies {
		if p.ID == id || strings.EqualFold(p.Name, v) {
			return p.ID, nil
		}
	}
	return 0, fmt.Errorf("no policy %q", v)
}

func learnPatch(args []string) (learn.Patch, error) {
	var p learn.Patch
	str := func(f string) *string {
		if !hasValueFlag(args, f) {
			return nil
		}
		v := flagValue(args, f)
		return &v
	}
	p.Name, p.Notes = str("--name"), str("--notes")
	if hasValueFlag(args, "--route") {
		id, err := routeID(flagValue(args, "--route"))
		if err != nil {
			return p, err
		}
		p.RouteVia = &id
	}
	boolFlag := func(on, off string) *bool {
		switch {
		case hasFlag(args, on):
			t := true
			return &t
		case hasFlag(args, off):
			f := false
			return &f
		}
		return nil
	}
	p.Enabled, p.Pinned = boolFlag("--enable", "--disable"), boolFlag("--pin", "--unpin")
	if hasValueFlag(args, "--ttl") {
		v := flagValue(args, "--ttl")
		n := 0
		if v != "default" {
			d, err := time.ParseDuration(v)
			if err == nil {
				n = int(d.Seconds())
			} else if n, err = strconv.Atoi(v); err != nil {
				return p, fmt.Errorf("bad --ttl %q (seconds, a duration like 12h, or default)", v)
			}
		}
		p.TTL = &n
	}
	if p == (learn.Patch{}) {
		return p, fmt.Errorf("nothing to change\n%s", learnUsage)
	}
	return p, nil
}

type learningsList struct {
	Groups     []learn.Group `json:"groups"`
	DefaultTTL int           `json:"default_ttl"`
}

func fetchLearnings() (learningsList, []byte, error) {
	var l learningsList
	b, err := learnAPI("GET", "/api/learnings", nil)
	if err != nil {
		return l, nil, err
	}
	err = json.Unmarshal(b, &l)
	return l, b, err
}

func learnEdit(w io.Writer, method, path string, body any, format string, a ...any) error {
	if _, err := learnAPI(method, path, body); err != nil {
		return err
	}
	fmt.Fprintf(w, format+"\n", a...)
	return nil
}

func policyNames() map[int]string {
	out := map[int]string{0: "off (WAN)"}
	if cfg, err := learnConfig(); err == nil {
		for _, p := range cfg.Policies {
			out[p.ID] = p.Name
		}
	}
	return out
}

func since(t time.Time) string {
	if t.IsZero() {
		return "never"
	}
	d := time.Since(t)
	switch {
	case d < 90*time.Second:
		return fmt.Sprintf("%ds ago", int(d.Seconds()))
	case d < 90*time.Minute:
		return fmt.Sprintf("%dm ago", int(d.Minutes()))
	case d < 48*time.Hour:
		return fmt.Sprintf("%dh ago", int(d.Hours()))
	}
	return fmt.Sprintf("%dd ago", int(d.Hours()/24))
}

func until(t *time.Time) string {
	if t == nil {
		return "never"
	}
	d := time.Until(*t)
	switch {
	case d <= 0:
		return "now"
	case d < 90*time.Minute:
		return fmt.Sprintf("in %dm", int(d.Minutes()))
	case d < 48*time.Hour:
		return fmt.Sprintf("in %dh", int(d.Hours()))
	}
	return fmt.Sprintf("in %dd", int(d.Hours()/24))
}

func lastActivity(g learn.Group) time.Time {
	var t time.Time
	for _, s := range g.Servers {
		for _, x := range []time.Time{s.LastSeen, s.LastActive} {
			if x.After(t) {
				t = x
			}
		}
	}
	return t
}

func learnList(w io.Writer, asJSON bool) error {
	l, raw, err := fetchLearnings()
	if err != nil {
		return err
	}
	if asJSON {
		_, err := w.Write(raw)
		return err
	}
	names := policyNames()
	tw := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "ID\tNAME\tROUTE VIA\tSTATE\tSERVERS\tTTL\tLAST ACTIVE")
	for _, g := range l.Groups {
		state := "on"
		if !g.Enabled {
			state = "off"
		}
		if g.Pinned {
			state += ",pinned"
		}
		ttl := "default"
		if g.TTL > 0 {
			ttl = (time.Duration(g.TTL) * time.Second).String()
		}
		fmt.Fprintf(tw, "%d\t%s\t%s\t%s\t%d\t%s\t%s\n", g.ID, g.Name, names[g.RouteVia], state, len(g.Servers), ttl, since(lastActivity(g)))
	}
	if len(l.Groups) == 0 {
		fmt.Fprintln(tw, "(no learning groups)")
	}
	fmt.Fprintf(tw, "\ndefault idle TTL %s\n", time.Duration(l.DefaultTTL)*time.Second)
	return tw.Flush()
}

func learnShow(w io.Writer, ref string, asJSON bool) error {
	l, _, err := fetchLearnings()
	if err != nil {
		return err
	}
	id, _ := strconv.Atoi(ref)
	for _, g := range l.Groups {
		if g.ID != id {
			continue
		}
		if asJSON {
			b, _ := json.MarshalIndent(g, "", "  ")
			fmt.Fprintln(w, string(b))
			return nil
		}
		names := policyNames()
		fmt.Fprintf(w, "#%d %s\n", g.ID, g.Name)
		fmt.Fprintf(w, "route via: %s   enabled: %v   pinned: %v   ttl: ", names[g.RouteVia], g.Enabled, g.Pinned)
		if g.TTL > 0 {
			fmt.Fprintln(w, time.Duration(g.TTL)*time.Second)
		} else {
			fmt.Fprintf(w, "default (%s)\n", time.Duration(l.DefaultTTL)*time.Second)
		}
		fmt.Fprintf(w, "created: %s\n", g.Created.Local().Format(time.RFC3339))
		if g.Notes != "" {
			fmt.Fprintf(w, "notes: %s\n", g.Notes)
		}
		tw := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
		fmt.Fprintln(tw, "\nSERVER\tFIRST SEEN\tLAST REQUEST\tLAST CONNECTION\tEXPIRES")
		for _, s := range g.Servers {
			addr := s.Addr
			if s.Manual {
				addr += " (by hand)"
			}
			fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n", addr, since(s.FirstSeen), since(s.LastSeen), since(s.LastActive), until(s.ExpiresAt))
		}
		fmt.Fprintln(tw, "\nDISCOVERED\tPOLICY SESSION\tTUNNEL\tDEVICE\tCONNECTED TO")
		for _, o := range g.Origins {
			pol := o.Policy
			if o.Trigger {
				pol += " *"
			}
			dev := strings.Join(nonEmpty(o.Device, o.ClientIP, o.MAC), " ")
			fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n", o.Time.Local().Format("2006-01-02 15:04"), pol, o.Tunnel, dev, strings.Join(o.Destinations, ", "))
		}
		if len(g.Origins) == 0 {
			fmt.Fprintln(tw, "(created by hand or imported)")
		} else {
			fmt.Fprintln(tw, "* = session where the STUN/TURN request was seen")
		}
		return tw.Flush()
	}
	return fmt.Errorf("no learning group %s", ref)
}

func nonEmpty(s ...string) []string {
	var out []string
	for _, x := range s {
		if x != "" {
			out = append(out, x)
		}
	}
	return out
}

func learnAddrs(w io.Writer, policy string, args []string) error {
	q := url.Values{"kind": {flagValue(args, "--kind")}, "q": {flagValue(args, "--filter")}, "limit": {flagValue(args, "--limit")}}
	b, err := learnAPI("GET", "/api/learned/"+url.PathEscape(policy)+"?"+q.Encode(), nil)
	if err != nil {
		return err
	}
	if hasFlag(args, "--json") {
		_, err := w.Write(b)
		return err
	}
	var v engine.LearnedView
	if err := json.Unmarshal(b, &v); err != nil {
		return err
	}
	fmt.Fprintf(w, "%s (#%d) %s addresses: %d in kernel", v.Policy, v.PolicyID, v.Kind, v.Total)
	if v.Matching != v.Total {
		fmt.Fprintf(w, ", %d matching", v.Matching)
	}
	if v.Kind == engine.LearnedDNS {
		if v.Unknown > 0 {
			fmt.Fprintf(w, ", %d without DNS details", v.Unknown)
		}
		if !v.Inspector {
			fmt.Fprint(w, " (DNS inspector off: no new details are recorded)")
		}
	}
	fmt.Fprintln(w)
	tw := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
	if v.Kind == engine.LearnedDNS {
		fmt.Fprintln(tw, "ADDRESS\tNAME\tRULE\tSOURCE\tDEVICE\tLAST SEEN\tEXPIRES")
	} else {
		fmt.Fprintln(tw, "ADDRESS\tEXPIRES")
	}
	for _, a := range v.Addrs {
		exp := "never"
		if a.Expires > 0 {
			exp = (time.Duration(a.Expires) * time.Second).String()
		}
		if v.Kind != engine.LearnedDNS {
			fmt.Fprintf(tw, "%s\t%s\n", a.Addr, exp)
			continue
		}
		name := a.Name
		if a.Matched != "" {
			name += " -> " + a.Matched
		}
		last := "?"
		if a.LastSeen != nil {
			last = since(*a.LastSeen)
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\t%s\n", a.Addr, orDash(name), orDash(a.Rule), orDash(a.Source), orDash(strings.Join(nonEmpty(a.Device, a.Client), " ")), last, exp)
	}
	if len(v.Addrs) < v.Matching {
		fmt.Fprintf(tw, "... %d more (use --limit or --filter)\n", v.Matching-len(v.Addrs))
	}
	return tw.Flush()
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}
