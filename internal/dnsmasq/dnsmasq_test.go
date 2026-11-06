package dnsmasq

import (
	"fmt"
	"strings"
	"testing"

	"github.com/irisariuan/snake/internal/config"
)

func TestGenerate(t *testing.T) {
	c := config.Default()
	var many []string
	for i := 0; i < 30; i++ {
		many = append(many, fmt.Sprintf("d%d.example.com", i))
	}
	c.Policies = []config.Policy{
		{ID: 1, Name: "nf", Enabled: true, Domains: []string{"netflix.com", "nflxvideo.net"}, Leak: config.Leak{DNSViaTunnel: true, DNSServer: "9.9.9.9", BlockDoH: true}},
		{ID: 2, Name: "big", Enabled: true, Domains: many},
		{ID: 3, Name: "off", Enabled: false, Domains: []string{"x.com"}},
	}
	out := Generate(c, true)
	for _, s := range []string{
		"ipset=/netflix.com/nflxvideo.net/SNK_1_d4,SNK_1_d6",
		"server=/netflix.com/nflxvideo.net/9.9.9.9",
		"SNK_DOH4,SNK_DOH6",
		"local=/use-application-dns.net/",
	} {
		if !strings.Contains(out, s) {
			t.Errorf("missing %q", s)
		}
	}
	if strings.Contains(out, "/x.com/") || strings.Contains(out, "policy 3") {
		t.Error("disabled policy rendered")
	}
}

func TestChunking(t *testing.T) {
	c := config.Default()
	var many []string
	for i := 0; i < 30; i++ {
		many = append(many, fmt.Sprintf("d%d.example.com", i))
	}
	c.Policies = []config.Policy{{ID: 2, Name: "big", Enabled: true, Domains: many}}
	if n := strings.Count(Generate(c, true), "SNK_2_d4"); n != 3 {
		t.Errorf("30 domains should split into 3 lines, got %d", n)
	}
}

func TestGenerateRuleKinds(t *testing.T) {
	c := config.Default()
	c.Policies = []config.Policy{
		{ID: 1, Name: "mixed", Enabled: true, Domains: []string{"netflix.com", "**.nflxvideo.net", `/^x\d\.edge\.example\.org$/`, "~keyword"},
			Leak: config.Leak{DNSViaTunnel: true, DNSServer: "9.9.9.9"}},
		{ID: 2, Name: "excl", Enabled: true, Domains: []string{"disneyplus.com", "!=ads.disneyplus.com"}},
	}
	out := Generate(c, true)
	for _, s := range []string{
		"ipset=/netflix.com/SNK_1_d4,SNK_1_d6",                       // only the plain rule is native
		"server=/netflix.com/nflxvideo.net/edge.example.org/9.9.9.9", // bases of every rule kind
	} {
		if !strings.Contains(out, s) {
			t.Errorf("missing %q in\n%s", s, out)
		}
	}
	if strings.Contains(out, "SNK_2_d4") {
		t.Error("policy with exclusions must not use dnsmasq ipset while the inspector runs")
	}
	if !strings.Contains(Generate(c, false), "ipset=/disneyplus.com/SNK_2_d4") {
		t.Error("degraded mode should fall back to plain rules")
	}
}

func TestGenerateDrop(t *testing.T) {
	c := config.Default()
	c.Policies = []config.Policy{
		{ID: 1, Name: "nf", Enabled: true, Domains: []string{"netflix.com", "drop:ads.netflix.com", "drop:**.tracker.example", "drop:asn:1234"},
			Leak: config.Leak{DNSViaTunnel: true, DNSServer: "9.9.9.9"}},
		{ID: 2, Name: "block", Enabled: true, Devices: []string{"aa:bb:cc:00:00:01"}, Domains: []string{"drop:games.example"}},
		{ID: 3, Name: "excl", Enabled: true, Domains: []string{"x.example", "drop:ads.x.example", "!=ok.ads.x.example"}},
	}
	out := Generate(c, true)
	for _, s := range []string{
		"ipset=/netflix.com/SNK_1_d4,SNK_1_d6",
		"ipset=/ads.netflix.com/SNK_1_x4,SNK_1_x6",
		"ipset=/games.example/SNK_2_x4,SNK_2_x6",
		"server=/netflix.com/9.9.9.9",
	} {
		if !strings.Contains(out, s) {
			t.Errorf("missing %q in\n%s", s, out)
		}
	}
	for _, s := range []string{"tracker.example", "ads.netflix.com/9.9.9.9", "SNK_2_d4", "ads.x.example/SNK_3_x4"} {
		if strings.Contains(out, s) {
			t.Errorf("unexpected %q in\n%s", s, out)
		}
	}
	// degraded (no inspector): plain drops even with exclusions
	if out := Generate(c, false); !strings.Contains(out, "ipset=/ads.x.example/SNK_3_x4,SNK_3_x6") {
		t.Errorf("degraded:\n%s", out)
	}
}
