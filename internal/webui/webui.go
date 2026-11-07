// Package webui embeds the web interface: a Merlin Addons page and a
// standalone page served by the API.
//
// The interface is an Astro + Tailwind project in web/. `make web` builds
// it into build/site, which is embedded here; its stylesheet and script are
// inlined into both pages, so each is a single self-contained file (the
// router's Addons page must be).
package webui

import (
	"embed"
	"fmt"
	"io/fs"
	"regexp"
	"strconv"
	"strings"
	"sync"
)

//go:embed all:build
var build embed.FS

//go:embed assets/page.asp
var pageASP string

//go:embed assets/mount.sh
var mountSH string

//go:embed assets/unmount.sh
var unmountSH string

// Site is the built page, its assets inlined.
type Site struct {
	HTML string // standalone page
	CSS  string // its stylesheets
	JS   string // its module scripts (the app)
	Err  error  // why there is no built page
}

var (
	styleRE  = regexp.MustCompile(`(?s)<style>(.*?)</style>`)
	moduleRE = regexp.MustCompile(`(?s)<script type="module">(.*?)</script>`)
	srcRE    = regexp.MustCompile(`<script type="module" src="/([^"]+)"></script>`)
	linkRE   = regexp.MustCompile(`<link rel="stylesheet" href="/([^"]+)"\s*/?>`)
)

var loadSite = sync.OnceValue(func() Site { return inline(build, "build/site") })

// Built returns the embedded page.
func Built() Site { return loadSite() }

// inline reads dir/index.html and replaces references to its scripts and
// stylesheets with their contents.
func inline(fsys fs.FS, dir string) Site {
	b, err := fs.ReadFile(fsys, dir+"/index.html")
	if err != nil {
		return Site{Err: fmt.Errorf("the web UI was not built into this binary (run make web, then rebuild)")}
	}
	var ferr error
	asset := func(p string) string {
		data, err := fs.ReadFile(fsys, dir+"/"+p)
		if err != nil {
			ferr = fmt.Errorf("web UI asset %s missing", p)
		}
		return string(data)
	}
	html := srcRE.ReplaceAllStringFunc(string(b), func(m string) string {
		return `<script type="module">` + escapeScript(asset(srcRE.FindStringSubmatch(m)[1])) + `</script>`
	})
	html = linkRE.ReplaceAllStringFunc(html, func(m string) string {
		return "<style>" + asset(linkRE.FindStringSubmatch(m)[1]) + "</style>"
	})
	if ferr != nil {
		return Site{Err: ferr}
	}
	s := Site{HTML: html}
	for _, m := range styleRE.FindAllStringSubmatch(html, -1) {
		s.CSS += m[1]
	}
	for _, m := range moduleRE.FindAllStringSubmatch(html, -1) {
		s.JS += m[1] + "\n"
	}
	if s.CSS == "" || s.JS == "" {
		return Site{Err: fmt.Errorf("web UI build has no stylesheet or script")}
	}
	return s
}

// escapeScript keeps inlined code from closing its <script> element. Valid
// JavaScript only has "</script" inside strings, templates, regular
// expressions and comments, where "<\/script" means the same.
func escapeScript(js string) string {
	return strings.ReplaceAll(js, "</script", `<\/script`)
}

// notBuilt is served when the binary has no web UI (built without
// `make web`): the API and CLI still work.
func notBuilt(err error) string {
	return `<p style="font:14px sans-serif;color:#e8eef0;background:#6d2323;padding:12px">snake: ` + err.Error() +
		`. The daemon, CLI and API work without it.</p>`
}

// ASP renders the Addons page; {{PAGE}} is filled in by the mount script.
func ASP(apiPort int) []byte {
	s := Built()
	css, js := s.CSS, s.JS
	if s.Err != nil {
		css, js = "", "document.getElementById('snake').innerHTML = "+strconv.Quote(notBuilt(s.Err))+";"
	}
	r := strings.NewReplacer("{{CSS}}", css, "{{PORT}}", strconv.Itoa(apiPort))
	out := r.Replace(pageASP)
	// JS last so nothing inside it is substituted.
	return []byte(strings.Replace(out, "{{JS}}", js, 1))
}

// Standalone renders the page served at the API root.
func Standalone() []byte {
	s := Built()
	if s.Err != nil {
		return []byte("<!doctype html><title>snake</title>" + notBuilt(s.Err))
	}
	return []byte(s.HTML)
}

// MountScript installs the Addons page.
func MountScript() string { return mountSH }

// UnmountScript removes the Addons page.
func UnmountScript() string { return unmountSH }
