package main

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/irisariuan/snake/internal/api"
	"github.com/irisariuan/snake/internal/config"
	"github.com/irisariuan/snake/internal/engine"
	"github.com/irisariuan/snake/internal/system"
)

// learnHarness points the learn commands at an in-process API.
func learnHarness(t *testing.T) *system.Recorder {
	t.Helper()
	dir := t.TempDir()
	b, err := os.ReadFile("../../testdata/config.json")
	if err != nil {
		t.Fatal(err)
	}
	cfgPath := filepath.Join(dir, "config.json")
	_ = os.WriteFile(cfgPath, b, 0o600)
	rec := &system.Recorder{Responses: map[string]string{
		"ipset list SNK_1_d4": "Name: SNK_1_d4\nMembers:\n203.0.113.99 timeout 300\n",
	}}
	e := engine.New(engine.DefaultPaths(dir), rec)
	if err := e.Load(); err != nil {
		t.Fatal(err)
	}
	h := (&api.Server{E: e}).Handler()
	oldAPI, oldCfg := learnAPI, learnConfig
	t.Cleanup(func() { learnAPI, learnConfig = oldAPI, oldCfg })
	learnConfig = func() (*config.Config, error) { return loadNormalized(cfgPath) }
	learnAPI = func(method, path string, body any) ([]byte, error) {
		var r io.Reader
		if body != nil {
			j, _ := json.Marshal(body)
			r = bytes.NewReader(j)
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, httptest.NewRequest(method, path, r))
		if w.Code >= 400 {
			var e struct{ Error string }
			_ = json.Unmarshal(w.Body.Bytes(), &e)
			return nil, &cliErr{e.Error}
		}
		return w.Body.Bytes(), nil
	}
	return rec
}

type cliErr struct{ s string }

func (e *cliErr) Error() string { return e.s }

func run(t *testing.T, args ...string) string {
	t.Helper()
	var out bytes.Buffer
	if err := runLearn(args, &out); err != nil {
		t.Fatalf("snake learn %s: %v", strings.Join(args, " "), err)
	}
	return out.String()
}

func TestLearnCLI(t *testing.T) {
	learnHarness(t)
	if out := run(t, "list"); !strings.Contains(out, "(no learning groups)") {
		t.Fatalf("empty list:\n%s", out)
	}
	run(t, "new", "Discord", "--route", "Netflix US", "203.0.113.10", "203.0.113.11")
	run(t, "new", "Other")
	out := run(t, "list")
	if !strings.Contains(out, "Discord") || !strings.Contains(out, "Netflix US") || !strings.Contains(out, "off (WAN)") {
		t.Fatalf("list:\n%s", out)
	}
	run(t, "set", "1", "--ttl", "12h", "--pin", "--notes", "voice", "--disable")
	run(t, "move", "1", "2", "203.0.113.11")
	run(t, "add", "2", "198.51.100.5")
	run(t, "rm", "2", "198.51.100.5")
	out = run(t, "show", "1")
	for _, want := range []string{"#1 Discord", "enabled: false", "pinned: true", "ttl: 12h0m0s", "notes: voice", "203.0.113.10 (by hand)"} {
		if !strings.Contains(out, want) {
			t.Errorf("show missing %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "203.0.113.11") {
		t.Error("moved server still shown in group 1")
	}
	run(t, "merge", "2", "1")
	run(t, "set", "1", "--route", "off", "--ttl", "default", "--enable")
	out = run(t, "show", "1", "--json")
	if !strings.Contains(out, `"203.0.113.11"`) || !strings.Contains(out, `"route_via": 0`) || strings.Contains(out, `"ttl"`) {
		t.Fatalf("after merge:\n%s", out)
	}
	run(t, "delete", "1")
	if out := run(t, "list"); !strings.Contains(out, "(no learning groups)") {
		t.Fatalf("after delete:\n%s", out)
	}

	var buf bytes.Buffer
	for _, bad := range [][]string{{"set", "1"}, {"set", "x", "--pin"}, {"new", "y", "--route", "nope"}, {"forget", "1"}, {"show", "99"}, {"add", "5", "10.0.0.1"}} {
		if err := runLearn(bad, &buf); err == nil {
			t.Errorf("snake learn %v: no error", bad)
		}
	}
}

func TestLearnAddrsCLI(t *testing.T) {
	rec := learnHarness(t)
	out := run(t, "addrs", "Netflix US")
	if !strings.Contains(out, "Netflix US (#1) dns addresses: 1 in kernel, 1 without DNS details") || !strings.Contains(out, "203.0.113.99") || !strings.Contains(out, "5m0s") {
		t.Fatalf("addrs:\n%s", out)
	}
	if out := run(t, "forget", "1", "203.0.113.99"); !strings.Contains(out, "removed 1 address") {
		t.Fatalf("forget:\n%s", out)
	}
	if last := rec.Commands[len(rec.Commands)-1]; !strings.Contains(last, "del SNK_1_d4 203.0.113.99") {
		t.Fatalf("ipset: %s", last)
	}
	run(t, "forget", "Disney UK TV", "--kind", "peer", "--all")
	found := false
	for _, c := range rec.Commands {
		found = found || c == "ipset flush SNK_2_r4"
	}
	if !found {
		t.Fatal("peer flush not run")
	}
}
