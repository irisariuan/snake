// Package webui embeds the web interface: a Merlin Addons page and a
// standalone page served by the API.
package webui

import (
	_ "embed"
	"strconv"
	"strings"
)

//go:embed assets/app.js
var appJS string

//go:embed assets/app.css
var appCSS string

//go:embed assets/page.asp
var pageASP string

//go:embed assets/index.html
var indexHTML string

//go:embed assets/mount.sh
var mountSH string

//go:embed assets/unmount.sh
var unmountSH string

// ASP renders the Addons page; {{PAGE}} is filled in by the mount script.
func ASP(apiPort int) []byte {
	r := strings.NewReplacer("{{CSS}}", appCSS, "{{PORT}}", strconv.Itoa(apiPort))
	out := r.Replace(pageASP)
	// JS last so nothing inside it is substituted.
	return []byte(strings.Replace(out, "{{JS}}", appJS, 1))
}

// Standalone renders the page served at the API root.
func Standalone() []byte {
	out := strings.Replace(indexHTML, "{{CSS}}", appCSS, 1)
	return []byte(strings.Replace(out, "{{JS}}", appJS, 1))
}

// MountScript installs the Addons page.
func MountScript() string { return mountSH }

// UnmountScript removes the Addons page.
func UnmountScript() string { return unmountSH }
