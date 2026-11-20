package config

import (
	"net/netip"
	"regexp"
	"strings"
)

// The DoH block lists (Settings.DoHDomains, DoHAddresses, CanaryDomains)
// start as the presets below and are edited in Settings → DNS. One entry
// per line; a line starting with # is a comment or a switched-off entry,
// so a preset can be turned off without losing it.

// DefaultDoHDomains are well-known DNS-over-HTTPS hostnames. When DoH is
// blocked for the whole LAN, dnsmasq answers them with NXDOMAIN.
var DefaultDoHDomains = []string{
	"# Google",
	"dns.google", "dns.google.com", "8888.google",
	"# Cloudflare",
	"cloudflare-dns.com", "mozilla.cloudflare-dns.com", "chrome.cloudflare-dns.com", "one.one.one.one",
	"1dot1dot1dot1.cloudflare-dns.com", "security.cloudflare-dns.com", "family.cloudflare-dns.com",
	"# Quad9",
	"dns.quad9.net", "dns9.quad9.net", "dns10.quad9.net", "dns11.quad9.net",
	"# OpenDNS",
	"doh.opendns.com", "doh.familyshield.opendns.com",
	"# AdGuard",
	"dns.adguard.com", "dns.adguard-dns.com", "dns-family.adguard.com", "unfiltered.adguard-dns.com",
	"# NextDNS, CleanBrowsing, DNS.SB, Control D, Mullvad",
	"dns.nextdns.io", "doh.cleanbrowsing.org", "doh.dns.sb", "dns.controld.com", "freedns.controld.com",
	"doh.mullvad.net", "dns.mullvad.net",
	"# Alibaba, DNSPod, 360",
	"dns.alidns.com", "doh.pub", "doh.360.cn",
	"# Others",
	"doh.libredns.gr", "dns.digitale-gesellschaft.ch", "dns.switch.ch", "doh.applied-privacy.net",
	"dns.brahma.world", "ordns.he.net",
}

// DefaultDoHAddresses are resolver addresses (IPv4 and IPv6, single
// addresses or CIDRs) that answer DoH directly by IP. Connections to them
// on port 443 are rejected for devices with DoH blocked.
var DefaultDoHAddresses = []string{
	"# Cloudflare",
	"1.1.1.1", "1.0.0.1", "1.1.1.2", "1.0.0.2", "1.1.1.3", "1.0.0.3",
	"2606:4700:4700::1111", "2606:4700:4700::1001", "2606:4700:4700::1112", "2606:4700:4700::1002",
	"# Google",
	"8.8.8.8", "8.8.4.4",
	"2001:4860:4860::8888", "2001:4860:4860::8844",
	"# Quad9",
	"9.9.9.9", "149.112.112.112", "9.9.9.10", "149.112.112.10", "9.9.9.11", "149.112.112.11",
	"2620:fe::fe", "2620:fe::9", "2620:fe::11",
	"# AdGuard",
	"94.140.14.14", "94.140.15.15", "94.140.14.140", "94.140.14.141",
	"2a10:50c0::ad1:ff", "2a10:50c0::ad2:ff",
	"# OpenDNS",
	"208.67.222.222", "208.67.220.220",
	"2620:119:35::35", "2620:119:53::53",
	"# NextDNS",
	"45.90.28.0/24", "45.90.30.0/24",
	"2a07:a8c0::/32", "2a07:a8c1::/32",
	"# CleanBrowsing",
	"185.228.168.168", "185.228.169.168",
	"# Control D",
	"76.76.2.0/24", "76.76.10.0/24",
	"# Mullvad",
	"194.242.2.2",
	"2a07:e340::2",
	"# DNS.SB servers",
	"185.222.222.222", "45.11.45.11",
	"2a0d:2a00:1::",
}

// DefaultCanaryDomains make browsers and operating systems turn off their
// built-in encrypted DNS or relays when answered with NXDOMAIN: Firefox
// turns off its DoH, Apple devices turn off iCloud Private Relay.
var DefaultCanaryDomains = []string{
	"# Firefox DoH",
	"use-application-dns.net",
	"# iCloud Private Relay",
	"mask.icloud.com", "mask-h2.icloud.com", "mask-api.icloud.com",
}

// Active returns the entries of a block list that are in force: comment
// and switched-off (#) lines are left out.
func Active(list []string) []string {
	var out []string
	for _, s := range list {
		if s = strings.TrimSpace(s); s != "" && !strings.HasPrefix(s, "#") {
			out = append(out, s)
		}
	}
	return out
}

var hostRe = regexp.MustCompile(`^([a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9_])?\.)*[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)

// normalizeHostList cleans a hostname block list, keeping comments.
func normalizeHostList(in []string) []string {
	return dedupKeepComments(mapStr(in, func(s string) string {
		if s = strings.TrimSpace(s); strings.HasPrefix(s, "#") {
			return s
		}
		return NormalizeDomain(s)
	}))
}

// normalizeAddrList cleans an address block list, keeping comments.
func normalizeAddrList(in []string) []string {
	return dedupKeepComments(mapStr(in, func(s string) string {
		s = strings.TrimSpace(s)
		if strings.HasPrefix(s, "#") {
			return s
		}
		if p, err := netip.ParsePrefix(s); err == nil {
			return p.Masked().String()
		}
		if a, err := netip.ParseAddr(s); err == nil {
			return a.String()
		}
		return s
	}))
}

func validateHostList(name string, list []string, add func(string, ...any)) {
	for _, h := range Active(list) {
		if len(h) > 253 || !hostRe.MatchString(h) {
			add("%s: %q is not a hostname", name, h)
		}
	}
}

func validateAddrList(name string, list []string, add func(string, ...any)) {
	for _, a := range Active(list) {
		if _, err := netip.ParsePrefix(a); err == nil {
			continue
		}
		if ip, err := netip.ParseAddr(a); err == nil && ip.Zone() == "" {
			continue
		}
		add("%s: %q is not an IP address or CIDR", name, a)
	}
}

// DoHPresets are the default block lists, for "restore defaults".
type DoHPresets struct {
	DoHDomains    []string `json:"doh_domains"`
	DoHAddresses  []string `json:"doh_addresses"`
	CanaryDomains []string `json:"canary_domains"`
}

// DefaultDoHPresets returns copies of the default block lists.
func DefaultDoHPresets() DoHPresets {
	cp := func(s []string) []string { return append([]string(nil), s...) }
	return DoHPresets{cp(DefaultDoHDomains), cp(DefaultDoHAddresses), cp(DefaultCanaryDomains)}
}
