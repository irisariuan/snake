package webui

import (
	"os"
	"strings"
	"testing"
	"testing/fstest"
)

func TestInline(t *testing.T) {
	fsys := fstest.MapFS{
		"s/index.html":    {Data: []byte(`<html><head><script data-snake-ctx>window.SNAKE_CTX={}</script><style>#snake{}</style><link rel="stylesheet" href="/_astro/b.css"></head><body><div id="snake"></div><script type="module" src="/_astro/app.js"></script></body></html>`)},
		"s/_astro/app.js": {Data: []byte(`const x = "</script>"; boot();`)},
		"s/_astro/b.css":  {Data: []byte(`.b{}`)},
	}
	s := inline(fsys, "s")
	if s.Err != nil {
		t.Fatal(s.Err)
	}
	if s.CSS != "#snake{}.b{}" || !strings.Contains(s.JS, `const x = "<\/script>"; boot();`) || strings.Contains(s.JS, "SNAKE_CTX") {
		t.Fatalf("css %q js %q", s.CSS, s.JS)
	}
	if strings.Contains(s.HTML, "/_astro/") || strings.Count(s.HTML, "</script>") != 2 {
		t.Fatalf("not inlined:\n%s", s.HTML)
	}
	delete(fsys, "s/_astro/b.css")
	if s := inline(fsys, "s"); s.Err == nil {
		t.Fatal("missing asset not reported")
	}
	if s := inline(fsys, "nowhere"); s.Err == nil || !strings.Contains(s.Err.Error(), "make web") {
		t.Fatalf("err = %v", s.Err)
	}
}

// TestBuiltSite checks the page built by `make web`. It is skipped when the
// UI was not built, unless SNAKE_REQUIRE_UI is set (make test, CI).
func TestBuiltSite(t *testing.T) {
	s := Built()
	if s.Err != nil {
		if os.Getenv("SNAKE_REQUIRE_UI") != "" {
			t.Fatal(s.Err)
		}
		t.Skip(s.Err)
	}
	asp := string(ASP(8444))
	for _, c := range []struct{ name, text string }{{"standalone", s.HTML}, {"asp", asp}} {
		if strings.Contains(c.text, "/_astro/") {
			t.Errorf("%s page references an external asset", c.name)
		}
	}
	// The firmware's state.js and general.js use jQuery's $; without it
	// the menu fails ("$ is not defined", then "bandName" errors).
	if j, st := strings.Index(asp, `src="/js/jquery.js"`), strings.Index(asp, `src="/state.js"`); j < 0 || j > st {
		t.Error("asp page must load /js/jquery.js before /state.js")
	}
	// Merlin's web server runs <% ... %> in .asp pages as server code.
	if strings.Contains(s.JS+s.CSS, "<%") || strings.Contains(s.JS+s.CSS, "%>") {
		t.Error("inlined UI contains <% or %>, which the router's web server would execute")
	}
	if strings.Contains(strings.ReplaceAll(asp, "{{PAGE}}", ""), "{{") || !strings.Contains(asp, "window.SNAKE_CTX = (function") || strings.Contains(asp, "mode: 'standalone'") {
		t.Error("asp template not filled correctly")
	}
	if !strings.Contains(s.HTML, "mode: 'standalone'") || !strings.Contains(s.CSS, "#snake .card") || !strings.Contains(s.JS, "snake_token") {
		t.Error("standalone page incomplete")
	}
}
