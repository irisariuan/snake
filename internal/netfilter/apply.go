package netfilter

import (
	"bufio"
	"fmt"
	"strconv"
	"strings"

	"github.com/irisariuan/snake/internal/system"
)

// Applier pushes a Plan into the kernel.
type Applier struct {
	R system.Runner
}

func bin(v6 bool, base string) string {
	if v6 {
		return "ip6" + base
	}
	return "ip" + base
}

// ExistingChains lists snake-owned chains currently present.
func (a Applier) ExistingChains(v6 bool) map[string][]string {
	out := map[string][]string{}
	fam := "4"
	if v6 {
		fam = "6"
	}
	for _, t := range []string{"mangle", "nat", "filter"} {
		s, err := a.R.Run(bin(v6, "tables"), "-t", t, "-S")
		if err != nil {
			continue
		}
		sc := bufio.NewScanner(strings.NewReader(s))
		for sc.Scan() {
			f := strings.Fields(sc.Text())
			if len(f) == 2 && f[0] == "-N" && strings.HasPrefix(f[1], ChainMain) {
				out[fam+"/"+t] = append(out[fam+"/"+t], f[1])
			}
		}
	}
	return out
}

// Apply loads the plan atomically per table and installs hooks.
func (a Applier) Apply(p Plan) error {
	var errs []string
	for _, key := range Tables {
		payload, ok := p.Restore[key]
		if !ok {
			continue
		}
		v6 := strings.HasPrefix(key, "6/")
		if _, err := a.R.RunInput(payload, bin(v6, "tables-restore"), "--noflush"); err != nil {
			errs = append(errs, fmt.Sprintf("%s: %v", key, err))
		}
	}
	for _, h := range p.Hooks {
		if err := a.ensureHook(h); err != nil {
			errs = append(errs, err.Error())
		}
	}
	if len(errs) > 0 {
		return fmt.Errorf("netfilter: %s", strings.Join(errs, "; "))
	}
	return nil
}

func (a Applier) ensureHook(h Hook) error {
	b := bin(h.V6, "tables")
	args := append([]string{"-t", h.Table, "-C", h.Chain}, h.Args...)
	if _, err := a.R.Run(b, args...); err == nil {
		return nil
	}
	args = append([]string{"-t", h.Table, "-I", h.Chain, "1"}, h.Args...)
	_, err := a.R.Run(b, args...)
	return err
}

// HooksPresent reports whether every hook is installed (used to detect a
// firewall restart that wiped our jumps).
func (a Applier) HooksPresent(hooks []Hook) bool {
	for _, h := range hooks {
		args := append([]string{"-t", h.Table, "-C", h.Chain}, h.Args...)
		if _, err := a.R.Run(bin(h.V6, "tables"), args...); err != nil {
			return false
		}
	}
	return true
}

// Teardown removes every hook and chain snake owns.
func (a Applier) Teardown(ipv6 bool, lan string) {
	fams := []bool{false}
	if ipv6 {
		fams = append(fams, true)
	}
	for _, v6 := range fams {
		hooks := []Hook{
			{V6: v6, Table: "mangle", Chain: "PREROUTING", Args: []string{"-i", lan, "-j", ChainMain}},
			{V6: v6, Table: "mangle", Chain: "FORWARD", Args: []string{"-j", ChainMSS}},
			{V6: v6, Table: "filter", Chain: "FORWARD", Args: []string{"-j", ChainFwd}},
			{V6: v6, Table: "nat", Chain: "PREROUTING", Args: []string{"-i", lan, "-j", ChainDNS}},
			{V6: v6, Table: "nat", Chain: "POSTROUTING", Args: []string{"-j", ChainNAT}},
		}
		for _, h := range hooks {
			for i := 0; i < 10; i++ {
				args := append([]string{"-t", h.Table, "-D", h.Chain}, h.Args...)
				if _, err := a.R.Run(bin(v6, "tables"), args...); err != nil {
					break
				}
			}
		}
		ex := a.ExistingChains(v6)
		fam := "4"
		if v6 {
			fam = "6"
		}
		for _, t := range []string{"mangle", "nat", "filter"} {
			chains := ex[fam+"/"+t]
			if len(chains) == 0 {
				continue
			}
			var b strings.Builder
			b.WriteString("*" + t + "\n")
			for _, c := range chains {
				b.WriteString(":" + c + " - [0:0]\n")
			}
			for _, c := range chains {
				b.WriteString("-X " + c + "\n")
			}
			b.WriteString("COMMIT\n")
			_, _ = a.R.RunInput(b.String(), bin(v6, "tables-restore"), "--noflush")
		}
	}
}

// Counters returns packets/bytes for the mark chain jump of each policy
// (how much traffic each policy has captured since the rules were loaded).
func (a Applier) Counters(v6 bool) map[string][2]uint64 {
	out := map[string][2]uint64{}
	s, err := a.R.Run(bin(v6, "tables"), "-t", "mangle", "-L", "-vnx")
	if err != nil {
		return out
	}
	sc := bufio.NewScanner(strings.NewReader(s))
	var cur string
	for sc.Scan() {
		line := sc.Text()
		if strings.HasPrefix(line, "Chain ") {
			cur = strings.Fields(line)[1]
			continue
		}
		if !strings.HasPrefix(cur, chainMark) {
			continue
		}
		f := strings.Fields(line)
		if len(f) >= 3 && f[2] == "MARK" {
			pk, _ := strconv.ParseUint(f[0], 10, 64)
			by, _ := strconv.ParseUint(f[1], 10, 64)
			out[cur] = [2]uint64{pk, by}
		}
	}
	return out
}
