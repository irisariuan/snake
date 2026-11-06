package importdvr

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/irisariuan/snake/internal/config"
)

func TestRead(t *testing.T) {
	d := t.TempDir()
	write := func(n, s string) {
		if err := os.WriteFile(filepath.Join(d, n), []byte(s), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("policy_nf_domainlist", "netflix.com\n*.nflxvideo.net\n\n")
	write("domain_vpn_routing.conf", "nf|"+filepath.Join(d, "policy_nf_domainlist")+"|x|wgc1|0|0|0\nbank|x|y|wan|0|0|0\n")
	write("asn.conf", "AS2906|wgc1\nAS13335|ovpnc3\n")
	res, err := Read(d)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Policies) != 2 {
		t.Fatalf("policies = %+v", res.Policies)
	}
	nf := res.Policies[0]
	if nf.Name != "nf" || len(nf.Domains) != 2 || nf.Domains[1] != "nflxvideo.net" || len(nf.ASNs) != 1 || nf.ASNs[0] != 2906 {
		t.Fatalf("nf = %+v", nf)
	}
	if res.Policies[1].Tunnels[0] != "ovpnc3" || res.Policies[1].ASNs[0] != 13335 {
		t.Fatalf("asn policy = %+v", res.Policies[1])
	}
	if len(res.Warnings) != 1 {
		t.Fatalf("warnings = %v", res.Warnings)
	}
	c := config.Default()
	c.Policies = []config.Policy{{ID: 1, Name: "nf", Enabled: true, Tunnels: []string{"wgc2"}, Domains: []string{"a.com"}, Leak: config.DefaultLeak()}}
	Merge(c, res.Policies)
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
	if c.Policies[1].Name != "nf-2" || c.Policies[1].ID == 1 {
		t.Fatalf("merge = %+v", c.Policies[1])
	}
}
