package api

import (
	"strings"
	"testing"

	"github.com/irisariuan/snake/internal/config"
)

func TestSaveList(t *testing.T) {
	c := config.Default()
	c.Policies = []config.Policy{{ID: 1, Name: "p", Lists: []string{"Old"}}}
	c.RuleLists = []config.RuleList{{Name: "Old", Domains: []string{"a.com"}}, {Name: "Other"}}

	// rename via @name updates policy references
	if _, err := SaveList(c, "Old", "@name New\nb.com\nasn:2906\n", false); err != nil {
		t.Fatal(err)
	}
	if c.RuleLists[0].Name != "New" || c.RuleLists[0].Domains[0] != "b.com" || c.Policies[0].Lists[0] != "New" {
		t.Fatalf("after rename: %+v %+v", c.RuleLists[0], c.Policies[0].Lists)
	}
	// new list without @name needs a name
	if _, err := SaveList(c, "", "x.com\n", false); err == nil {
		t.Fatal("expected name error")
	}
	// name clash
	if _, err := SaveList(c, "", "@name Other\nx.com\n", false); err == nil || !strings.Contains(err.Error(), "already exists") {
		t.Fatalf("err = %v", err)
	}
	// errors carry line numbers
	_, err := SaveList(c, "New", "@name New\nok.com\nbad domain\n", false)
	if err == nil || !strings.Contains(err.Error(), "line 3") {
		t.Fatalf("err = %v", err)
	}
	// import with conversion
	if _, err := SaveList(c, "", "@name Ads\n||ads.example.com^\n", true); err != nil {
		t.Fatal(err)
	}
	l, _ := c.List("Ads")
	if len(l.Domains) != 1 || l.Domains[0] != "ads.example.com" {
		t.Fatalf("converted: %+v", l)
	}
	// export round-trips
	if out := ExportList(l); !strings.Contains(out, "@name Ads\n") || !strings.Contains(out, "\nads.example.com\n") {
		t.Fatalf("export:\n%s", out)
	}
	if FileName("Disney+ UK") != "Disney__UK.rules" {
		t.Fatal(FileName("Disney+ UK"))
	}
}
