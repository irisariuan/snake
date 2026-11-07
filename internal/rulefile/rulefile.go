// Package rulefile reads and writes snake rule files (.rules).
//
// A rule file is UTF-8 text, one entry per line:
//
//	# snake rules v1                     comment
//	@name Netflix                        directive: list name
//	@description Netflix streaming       directive: free text
//	@source https://example.com/x.rules  directive: where updates come from
//	netflix.com                          domain rule (see package match)
//	**.nflxvideo.net
//	/^ipv4-c\d+-.*\.oca\.nflxvideo\.net$/
//	!=ads.netflix.com
//	asn:2906                             autonomous system (AS prefix optional)
//	cidr:23.246.0.0/18                   address range or single IP (ip: also accepted)
//
// On import, lines from common list formats are converted: AdBlock/AdGuard
// "||example.com^", hosts files "0.0.0.0 example.com", and dnsmasq
// "server=/a/b/..." / "ipset=/a/b/..." / "address=/a/..." lines.
package rulefile

import (
	"fmt"
	"net"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/irisariuan/snake/internal/match"
)

// Header is the first line written on export.
const Header = "# snake rules v1"

// File is a parsed rule file.
type File struct {
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Source      string   `json:"source"`
	Domains     []string `json:"domains"` // domain rules and comment lines, in order
	ASNs        []int    `json:"asns"`
	CIDRs       []string `json:"cidrs"`
}

// Issue is a problem on one line (1-based).
type Issue struct {
	Line    int    `json:"line"`
	Text    string `json:"text"`
	Message string `json:"message"`
}

// Result is the outcome of parsing.
type Result struct {
	File      File    `json:"file"`
	Errors    []Issue `json:"errors"`
	Warnings  []Issue `json:"warnings"`
	Converted int     `json:"converted"` // lines converted from other formats
}

var (
	hostsRe   = regexp.MustCompile(`^(0\.0\.0\.0|127\.0\.0\.1|::1?)\s+(\S+)`)
	abpRe     = regexp.MustCompile(`^\|\|([a-z0-9.\-_*]+)\^(\$.*)?$`)
	dnsmasqRe = regexp.MustCompile(`^(server|ipset|nftset|address|local)=/(.+)/`)
)

// Parse reads rule-file text. With convert, foreign list formats are
// translated; otherwise they are reported as errors.
func Parse(text string, convert bool) Result {
	var r Result
	r.File.Domains = []string{}
	r.File.ASNs = []int{}
	r.File.CIDRs = []string{}
	seenASN := map[int]bool{}
	text = strings.TrimPrefix(text, "\uFEFF")
	// Multi-line route: rules are one entry (their lines joined with "\n").
	for _, lg := range match.Group(strings.Split(strings.ReplaceAll(text, "\r\n", "\n"), "\n")) {
		n, raw := lg.First+1, lg.Text
		line := strings.TrimSpace(raw)
		if line == "" {
			continue
		}
		if match.IsRoute(line) {
			if _, err := match.ParseRoute(line); err != nil {
				r.Errors = append(r.Errors, Issue{Line: n, Text: raw, Message: err.Error()})
				continue
			}
			r.File.Domains = append(r.File.Domains, match.Normalize(line))
			continue
		}
		issue := func(msg string) Issue { return Issue{Line: n, Text: raw, Message: msg} }
		switch {
		case strings.HasPrefix(line, "#"):
			if line != Header {
				r.File.Domains = append(r.File.Domains, line)
			}
		case strings.HasPrefix(line, "@"):
			key, val, _ := strings.Cut(line[1:], " ")
			val = strings.TrimSpace(val)
			switch strings.ToLower(key) {
			case "name":
				r.File.Name = val
			case "description":
				r.File.Description = val
			case "source":
				r.File.Source = val
			default:
				r.Warnings = append(r.Warnings, issue("unknown directive @"+key+" (ignored)"))
			}
		case hasPrefixFold(line, "asn:"):
			v := strings.TrimSpace(line[4:])
			a, err := parseASN(v)
			if err != nil {
				r.Errors = append(r.Errors, issue(err.Error()))
				continue
			}
			if !seenASN[a] {
				seenASN[a] = true
				r.File.ASNs = append(r.File.ASNs, a)
			}
		case hasPrefixFold(line, "cidr:") || hasPrefixFold(line, "ip:"):
			_, v, _ := strings.Cut(line, ":")
			v = strings.TrimSpace(stripComment(v))
			if _, _, err := net.ParseCIDR(v); err != nil && net.ParseIP(v) == nil {
				r.Errors = append(r.Errors, issue(fmt.Sprintf("invalid CIDR/IP %q", v)))
				continue
			}
			r.File.CIDRs = append(r.File.CIDRs, v)
		case convert && strings.HasPrefix(line, "!") && !strings.HasPrefix(strings.TrimSpace(line[1:]), "/") &&
			strings.ContainsAny(strings.TrimSpace(line[1:]), " \t"):
			r.Converted++ // AdBlock comment ("! Title: ...")
		default:
			if convert {
				if conv, ok := convertLine(line); ok {
					r.Converted++
					for _, d := range conv {
						if _, err := match.Parse(d); err == nil {
							r.File.Domains = append(r.File.Domains, d)
						} else {
							r.Errors = append(r.Errors, issue(err.Error()))
						}
					}
					continue
				}
			}
			if _, err := match.Parse(line); err != nil {
				if convert && strings.HasPrefix(line, "!") {
					r.Converted++ // AdBlock comment ("! Title: ...")
					continue
				}
				r.Errors = append(r.Errors, issue(err.Error()))
				continue
			}
			r.File.Domains = append(r.File.Domains, match.Normalize(line))
		}
	}
	r.File.Domains = dedupKeepComments(r.File.Domains)
	r.File.CIDRs = dedup(r.File.CIDRs)
	return r
}

func hasPrefixFold(s, p string) bool {
	return len(s) >= len(p) && strings.EqualFold(s[:len(p)], p)
}

func stripComment(s string) string {
	if i := strings.Index(s, "#"); i >= 0 {
		return s[:i]
	}
	return s
}

func parseASN(v string) (int, error) {
	v = strings.TrimSpace(stripComment(v))
	n, err := strconv.ParseUint(strings.TrimPrefix(strings.ToUpper(v), "AS"), 10, 32)
	if err != nil || n == 0 || uint64(int(n)) != n {
		return 0, fmt.Errorf("invalid ASN %q", v)
	}
	return int(n), nil
}

// convertLine translates one line from a foreign list format.
func convertLine(line string) ([]string, bool) {
	l := strings.ToLower(line)
	if m := abpRe.FindStringSubmatch(l); m != nil {
		return []string{m[1]}, true
	}
	if m := hostsRe.FindStringSubmatch(l); m != nil {
		var out []string
		for _, h := range strings.Fields(l)[1:] {
			if strings.HasPrefix(h, "#") {
				break
			}
			if h == "localhost" || h == "localhost.localdomain" || h == "broadcasthost" || h == "local" {
				continue
			}
			out = append(out, "="+h)
		}
		return out, true
	}
	if m := dnsmasqRe.FindStringSubmatch(l); m != nil {
		var out []string
		for _, d := range strings.Split(m[2], "/") {
			if d = strings.TrimSpace(d); d != "" && d != "#" {
				out = append(out, d)
			}
		}
		return out, true
	}
	return nil, false
}

// Format renders a file in canonical form.
func Format(f File) string {
	var b strings.Builder
	b.WriteString(Header + "\n")
	if f.Name != "" {
		b.WriteString("@name " + oneLine(f.Name) + "\n")
	}
	if f.Description != "" {
		b.WriteString("@description " + oneLine(f.Description) + "\n")
	}
	if f.Source != "" {
		b.WriteString("@source " + oneLine(f.Source) + "\n")
	}
	if len(f.Domains) > 0 {
		b.WriteString("\n")
		for _, d := range f.Domains {
			b.WriteString(d + "\n")
		}
	}
	if len(f.ASNs) > 0 {
		b.WriteString("\n")
		asns := append([]int(nil), f.ASNs...)
		sort.Ints(asns)
		for _, a := range asns {
			b.WriteString("asn:" + strconv.Itoa(a) + "\n")
		}
	}
	if len(f.CIDRs) > 0 {
		b.WriteString("\n")
		for _, c := range f.CIDRs {
			b.WriteString("cidr:" + c + "\n")
		}
	}
	return b.String()
}

func oneLine(s string) string { return strings.Join(strings.Fields(s), " ") }

func dedup(in []string) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(in))
	for _, s := range in {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}

func dedupKeepComments(in []string) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(in))
	for _, s := range in {
		if strings.HasPrefix(s, "#") || !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}
