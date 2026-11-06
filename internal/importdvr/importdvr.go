// Package importdvr migrates Ranger802004's Domain VPN Routing configuration.
package importdvr

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/irisariuan/snake/internal/config"
)

// DefaultDir is where domain_vpn_routing keeps its configuration.
const DefaultDir = "/jffs/configs/domain_vpn_routing"

// Result reports what was imported.
type Result struct {
	Policies []config.Policy `json:"policies"`
	Warnings []string        `json:"warnings"`
}

// Read parses domain_vpn_routing.conf and asn.conf in dir.
//
// Policy line: NAME|DOMAINLIST|DOMAINTOIP|INTERFACE|VERBOSE|PRIVATEIPS|ADDCNAMES
// ASN line:    AS1234|INTERFACE
func Read(dir string) (Result, error) {
	var res Result
	lines, err := readLines(filepath.Join(dir, "domain_vpn_routing.conf"))
	if err != nil {
		return res, err
	}
	byIface := map[string]int{}
	for _, l := range lines {
		f := strings.Split(l, "|")
		if len(f) < 4 {
			res.Warnings = append(res.Warnings, fmt.Sprintf("skipped malformed line %q", l))
			continue
		}
		name, list, iface := f[0], f[1], strings.ToLower(f[3])
		if config.TunnelIndex(iface) == 0 {
			res.Warnings = append(res.Warnings, fmt.Sprintf("policy %s uses interface %s: snake only routes through VPN clients, skipped", name, iface))
			continue
		}
		if !filepath.IsAbs(list) {
			list = filepath.Join(dir, list)
		}
		domains, err := readLines(list)
		if err != nil {
			res.Warnings = append(res.Warnings, fmt.Sprintf("policy %s: %v", name, err))
		}
		p := newPolicy(name, iface)
		for _, d := range domains {
			if d = config.NormalizeDomain(d); d != "" {
				p.Domains = append(p.Domains, d)
			}
		}
		byIface[iface] = len(res.Policies)
		res.Policies = append(res.Policies, p)
	}
	asnLines, err := readLines(filepath.Join(dir, "asn.conf"))
	if err == nil {
		for _, l := range asnLines {
			f := strings.Split(l, "|")
			if len(f) < 2 {
				continue
			}
			n, err := config.ParseASN(f[0])
			iface := strings.ToLower(f[1])
			if err != nil || config.TunnelIndex(iface) == 0 {
				res.Warnings = append(res.Warnings, fmt.Sprintf("skipped ASN line %q", l))
				continue
			}
			i, ok := byIface[iface]
			if !ok {
				res.Policies = append(res.Policies, newPolicy("ASN-"+iface, iface))
				i = len(res.Policies) - 1
				byIface[iface] = i
			}
			res.Policies[i].ASNs = append(res.Policies[i].ASNs, n)
		}
	}
	if len(res.Policies) == 0 {
		res.Warnings = append(res.Warnings, "nothing to import")
	}
	return res, nil
}

func newPolicy(name, iface string) config.Policy {
	clean := strings.Map(func(r rune) rune {
		if r == '|' {
			return -1
		}
		return r
	}, name)
	if len(clean) > 40 {
		clean = clean[:40]
	}
	return config.Policy{
		Name:       clean,
		Enabled:    true,
		Tunnels:    []string{iface},
		KillSwitch: false,
		Leak:       config.DefaultLeak(),
	}
}

// Merge appends imported policies, renaming on conflict.
func Merge(c *config.Config, imported []config.Policy) {
	names := map[string]bool{}
	for _, p := range c.Policies {
		names[p.Name] = true
	}
	for _, p := range imported {
		base, n := p.Name, 2
		for names[p.Name] {
			p.Name = fmt.Sprintf("%s-%d", base, n)
			n++
		}
		names[p.Name] = true
		p.ID = 0
		c.Policies = append(c.Policies, p)
	}
	c.Normalize()
}

func readLines(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var out []string
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	for sc.Scan() {
		l := strings.TrimSpace(sc.Text())
		if l != "" && !strings.HasPrefix(l, "#") {
			out = append(out, l)
		}
	}
	return out, sc.Err()
}
