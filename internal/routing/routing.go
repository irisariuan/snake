// Package routing manages snake's ip rules and per-policy routing tables.
package routing

import (
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/irisariuan/snake/internal/config"
	"github.com/irisariuan/snake/internal/netfilter"
	"github.com/irisariuan/snake/internal/system"
)

// Manager wraps `ip`.
type Manager struct {
	R system.Runner
}

func fam(v6 bool) []string {
	if v6 {
		return []string{"-6"}
	}
	return []string{"-4"}
}

func (m Manager) ip(v6 bool, args ...string) (string, error) {
	return m.R.Run("ip", append(fam(v6), args...)...)
}

// PolicyRoute describes the desired route state of one policy table.
type PolicyRoute struct {
	ID        int
	Iface     string // active tunnel interface, "" if none
	Kill      bool   // install unreachable default when Iface == ""
	V6        bool   // also manage the IPv6 table
	V6Route   bool   // IPv6 goes via Iface (otherwise unreachable)
	DNSServer string // plain resolver selected by dnsmasq's bound interface
	DNSTunnel string // oif selector; encrypted queries use a socket mark instead
}

// ProbeRoute is a table used by health probes to reach the internet through a tunnel.
type ProbeRoute struct {
	Tunnel string
	Iface  string
	Up     bool
}

// Sync reconciles rules and tables in place: missing rules are added before
// stale ones are removed and default routes are swapped with "replace", so
// marked traffic never falls through to WAN during an update.
func (m Manager) Sync(s config.Settings, routes []PolicyRoute, probes []ProbeRoute, ipv6 bool) error {
	var errs []string
	fams := []bool{false}
	if ipv6 {
		fams = append(fams, true)
	}
	mask := fmt.Sprintf("0x%x", s.RouteMask())
	want := map[bool][]rule{}
	used := map[int]bool{}
	for _, r := range routes {
		table := netfilter.PolicyTableBase + r.ID
		used[table] = true
		mark := fmt.Sprintf("0x%x/%s", s.PolicyMark(r.ID), mask)
		for _, v6 := range fams {
			if v6 && !r.V6 {
				continue
			}
			want[v6] = append(want[v6], rule{pref: netfilter.PolicyPrefBase + r.ID, spec: []string{"fwmark", mark}, table: table})
			iface := r.Iface
			if v6 && !r.V6Route {
				iface = ""
			}
			if err := m.setDefault(v6, strconv.Itoa(table), iface, r.Kill || (v6 && r.Iface != "")); err != nil {
				errs = append(errs, err.Error())
			}
		}
		if r.DNSServer != "" && r.DNSTunnel != "" {
			// SO_BINDTODEVICE from dnsmasq's @interface identifies the
			// tunnel even when several policies share one resolver IP.
			// Probe tables always fail closed when an interface goes down.
			want[false] = append(want[false], rule{pref: netfilter.DNSRulePrefBase + r.ID,
				spec:  []string{"iif", "lo", "oif", config.TunnelInterface(r.DNSTunnel), "to", r.DNSServer + "/32"},
				table: netfilter.ProbeTableBase + config.TunnelIndex(r.DNSTunnel)})
		}
	}
	for _, p := range probes {
		idx := config.TunnelIndex(p.Tunnel)
		table := netfilter.ProbeTableBase + idx
		used[table] = true
		mark := fmt.Sprintf("0x%x/%s", s.ProbeMark(p.Tunnel), mask)
		for _, v6 := range fams {
			want[v6] = append(want[v6], rule{pref: netfilter.ProbePrefBase + idx, spec: []string{"fwmark", mark}, table: table})
			iface := ""
			if p.Up {
				iface = p.Iface
			}
			// Probes must never fall back to WAN, or a dead tunnel would look healthy.
			if err := m.setDefault(v6, strconv.Itoa(table), iface, true); err != nil && !v6 {
				errs = append(errs, err.Error())
			}
		}
	}
	for _, v6 := range fams {
		if err := m.reconcileRules(v6, want[v6]); err != nil {
			errs = append(errs, err.Error())
		}
	}
	for t := netfilter.PolicyTableBase; t <= netfilter.ProbeTableBase+len(config.TunnelNames); t++ {
		if used[t] {
			continue
		}
		for _, v6 := range fams {
			_, _ = m.ip(v6, "route", "flush", "table", strconv.Itoa(t))
		}
	}
	if len(errs) > 0 {
		return fmt.Errorf("routing: %s", strings.Join(errs, "; "))
	}
	return nil
}

type rule struct {
	pref  int
	spec  []string
	table int
}

func (r rule) key() string {
	return fmt.Sprintf("%d %s lookup %d", r.pref, strings.Join(r.spec, " "), r.table)
}

// existingRule is a rule in snake's priority range as printed by `ip rule show`.
type existingRule struct {
	pref int
	text string // everything after "pref:", e.g. "from all fwmark 0x10000/0xff0000 lookup 1001"
}

func (m Manager) listRules(v6 bool) []existingRule {
	out, err := m.ip(v6, "rule", "show")
	if err != nil {
		return nil
	}
	var rs []existingRule
	for _, l := range strings.Split(out, "\n") {
		i := strings.IndexByte(l, ':')
		if i <= 0 {
			continue
		}
		pref, err := strconv.Atoi(strings.TrimSpace(l[:i]))
		if err != nil || pref < netfilter.PrefMin || pref > netfilter.PrefMax {
			continue
		}
		rs = append(rs, existingRule{pref: pref, text: strings.Join(strings.Fields(l[i+1:]), " ")})
	}
	return rs
}

// matches compares a desired rule with `ip rule show` output.
func (r rule) matches(e existingRule) bool {
	if e.pref != r.pref || !strings.HasSuffix(e.text, "lookup "+strconv.Itoa(r.table)) {
		return false
	}
	for i := 0; i+1 < len(r.spec); i += 2 {
		k, v := r.spec[i], r.spec[i+1]
		if k == "to" {
			v = strings.TrimSuffix(v, "/32")
		}
		if !strings.Contains(e.text, k+" "+v) {
			return false
		}
	}
	return true
}

func (m Manager) reconcileRules(v6 bool, want []rule) error {
	existing := m.listRules(v6)
	var errs []string
	keep := make([]bool, len(existing))
	for _, w := range want {
		found := false
		for i, e := range existing {
			if !keep[i] && w.matches(e) {
				keep[i], found = true, true
				break
			}
		}
		if found {
			continue
		}
		args := append([]string{"rule", "add", "pref", strconv.Itoa(w.pref)}, w.spec...)
		args = append(args, "lookup", strconv.Itoa(w.table))
		if _, err := m.ip(v6, args...); err != nil {
			errs = append(errs, err.Error())
		}
	}
	for i, e := range existing {
		if keep[i] {
			continue
		}
		args := append([]string{"rule", "del", "pref", strconv.Itoa(e.pref)}, strings.Fields(e.text)...)
		if _, err := m.ip(v6, args...); err != nil {
			_, _ = m.ip(v6, "rule", "del", "pref", strconv.Itoa(e.pref))
		}
	}
	if len(errs) > 0 {
		return fmt.Errorf("%s", strings.Join(errs, "; "))
	}
	return nil
}

// setDefault points the table's default route at iface, or makes it
// unreachable (kill) / absent (fall through to main), without a gap.
func (m Manager) setDefault(v6 bool, table, iface string, kill bool) error {
	switch {
	case iface != "":
		_, err := m.ip(v6, "route", "replace", "default", "dev", iface, "table", table)
		return err
	case kill:
		_, err := m.ip(v6, "route", "replace", "unreachable", "default", "table", table)
		return err
	}
	_, _ = m.ip(v6, "route", "flush", "table", table)
	return nil
}

func (m Manager) deleteRules(v6 bool) {
	for _, e := range m.listRules(v6) {
		_, _ = m.ip(v6, "rule", "del", "pref", strconv.Itoa(e.pref))
	}
}

// Teardown removes all snake rules and tables.
func (m Manager) Teardown(ipv6 bool) {
	fams := []bool{false}
	if ipv6 {
		fams = append(fams, true)
	}
	for _, v6 := range fams {
		m.deleteRules(v6)
		for t := netfilter.PolicyTableBase; t <= netfilter.ProbeTableBase+len(config.TunnelNames); t++ {
			_, _ = m.ip(v6, "route", "flush", "table", strconv.Itoa(t))
		}
	}
}

// LooseRPFilter sets rp_filter=2 on an interface so asymmetric replies from
// policy-routed connections are not dropped.
func LooseRPFilter(iface string) {
	p := "/proc/sys/net/ipv4/conf/" + iface + "/rp_filter"
	if b, err := os.ReadFile(p); err == nil && strings.TrimSpace(string(b)) == "1" {
		_ = os.WriteFile(p, []byte("2"), 0o644)
	}
}
