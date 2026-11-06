// Package update checks GitHub releases for a newer snake, installs it and
// rolls back to the previous binary.
//
// Release layout (built by .github/workflows/release.yml): a tag vX.Y.Z with
// assets snake-arm64, snake-armv7 and SHA256SUMS.
package update

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"
)

// DefaultRepo is where releases are published.
const DefaultRepo = "irisariuan/snake"

// SumsAsset is the checksum file published with every release.
const SumsAsset = "SHA256SUMS"

// Info is the result of an update check.
type Info struct {
	Current    string    `json:"current"`
	Latest     string    `json:"latest,omitempty"`
	Available  bool      `json:"available"`  // Latest is newer than Current
	Comparable bool      `json:"comparable"` // Current is a release version (not a dev build)
	Notes      string    `json:"notes,omitempty"`
	URL        string    `json:"url,omitempty"`
	Published  time.Time `json:"published,omitempty"`
	Asset      string    `json:"asset"`
	CheckedAt  time.Time `json:"checked_at,omitempty"`
	Error      string    `json:"error,omitempty"`
	Previous   string    `json:"previous,omitempty"` // version a rollback would restore
	Busy       bool      `json:"busy"`
}

type release struct {
	TagName     string    `json:"tag_name"`
	Body        string    `json:"body"`
	HTMLURL     string    `json:"html_url"`
	PublishedAt time.Time `json:"published_at"`
	Draft       bool      `json:"draft"`
	Prerelease  bool      `json:"prerelease"`
	Assets      []struct {
		Name string `json:"name"`
		URL  string `json:"browser_download_url"`
	} `json:"assets"`
}

// Updater manages the installed binary at Bin; Bin+".prev" is the rollback
// copy.
type Updater struct {
	Bin     string        // installed binary, e.g. /jffs/addons/snake/snake
	Current string        // running version
	Repo    func() string // owner/name, read at check time (config can change)
	APIBase string        // default https://api.github.com
	Client  *http.Client

	mu   sync.Mutex // serialises install/rollback
	imu  sync.Mutex
	info Info
	rel  *release
	busy bool
}

// Asset is the release asset name for this build's CPU.
func Asset() string {
	if runtime.GOARCH == "arm" {
		return "snake-armv7"
	}
	return "snake-" + runtime.GOARCH
}

func (u *Updater) prev() string { return u.Bin + ".prev" }

func (u *Updater) repo() string {
	if u.Repo != nil {
		if r := strings.Trim(strings.TrimSpace(u.Repo()), "/"); r != "" {
			return r
		}
	}
	return DefaultRepo
}

func (u *Updater) client() *http.Client {
	if u.Client != nil {
		return u.Client
	}
	return &http.Client{Timeout: 2 * time.Minute}
}

// Info returns the last check result with the current rollback state.
func (u *Updater) Info() Info {
	u.imu.Lock()
	in := u.info
	in.Busy = u.busy
	u.imu.Unlock()
	in.Current = u.Current
	in.Asset = Asset()
	_, in.Comparable = parseVersion(u.Current)
	in.Previous = u.PreviousVersion()
	return in
}

// Check asks GitHub for the latest release.
func (u *Updater) Check(ctx context.Context) (Info, error) {
	rel, err := u.latest(ctx)
	u.imu.Lock()
	u.info.CheckedAt = time.Now()
	if err != nil {
		u.info.Error = err.Error()
	} else {
		u.rel = rel
		u.info.Error = ""
		u.info.Latest = rel.TagName
		u.info.Notes = rel.Body
		u.info.URL = rel.HTMLURL
		u.info.Published = rel.PublishedAt
		u.info.Available = Newer(rel.TagName, u.Current)
	}
	u.imu.Unlock()
	return u.Info(), err
}

func (u *Updater) latest(ctx context.Context) (*release, error) {
	base := u.APIBase
	if base == "" {
		base = "https://api.github.com"
	}
	req, err := http.NewRequestWithContext(ctx, "GET", base+"/repos/"+u.repo()+"/releases/latest", nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("User-Agent", "snake-updater")
	resp, err := u.client().Do(req)
	if err != nil {
		return nil, fmt.Errorf("check for updates: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return nil, fmt.Errorf("no releases published in %s", u.repo())
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("check for updates: GitHub returned %s", resp.Status)
	}
	var rel release
	if err := json.NewDecoder(io.LimitReader(resp.Body, 4<<20)).Decode(&rel); err != nil {
		return nil, fmt.Errorf("check for updates: %w", err)
	}
	if rel.TagName == "" {
		return nil, errors.New("check for updates: release has no tag")
	}
	return &rel, nil
}

func (u *Updater) setBusy(b bool) bool {
	u.imu.Lock()
	defer u.imu.Unlock()
	if b && u.busy {
		return false
	}
	u.busy = b
	return true
}

// Install downloads the latest release, verifies its checksum and that it
// runs, keeps the current binary as the rollback copy and puts the new one
// in place. The caller restarts the daemon. Returns the installed version.
func (u *Updater) Install(ctx context.Context) (string, error) {
	if !u.setBusy(true) {
		return "", errors.New("an update is already in progress")
	}
	defer u.setBusy(false)
	u.mu.Lock()
	defer u.mu.Unlock()

	if _, err := u.Check(ctx); err != nil {
		return "", err
	}
	u.imu.Lock()
	rel := u.rel
	u.imu.Unlock()
	var binURL, sumsURL string
	for _, a := range rel.Assets {
		switch a.Name {
		case Asset():
			binURL = a.URL
		case SumsAsset:
			sumsURL = a.URL
		}
	}
	if binURL == "" {
		return "", fmt.Errorf("release %s has no %s asset", rel.TagName, Asset())
	}
	if sumsURL == "" {
		return "", fmt.Errorf("release %s has no %s asset", rel.TagName, SumsAsset)
	}
	sums, err := u.download(ctx, sumsURL, 1<<20)
	if err != nil {
		return "", err
	}
	want := checksumFor(string(sums), Asset())
	if want == "" {
		return "", fmt.Errorf("%s has no checksum for %s", SumsAsset, Asset())
	}
	bin, err := u.download(ctx, binURL, 100<<20)
	if err != nil {
		return "", err
	}
	got := sha256.Sum256(bin)
	if hex.EncodeToString(got[:]) != want {
		return "", fmt.Errorf("checksum mismatch for %s: download corrupted", Asset())
	}

	tmp := u.Bin + ".new"
	if err := os.WriteFile(tmp, bin, 0o755); err != nil {
		return "", err
	}
	v, err := BinaryVersion(tmp)
	if err != nil {
		os.Remove(tmp)
		return "", fmt.Errorf("downloaded binary does not run on this router: %w", err)
	}
	if err := u.swapIn(tmp); err != nil {
		os.Remove(tmp)
		return "", err
	}
	return v, nil
}

// swapIn makes path the installed binary and keeps the old one as .prev.
func (u *Updater) swapIn(path string) error {
	if _, err := os.Stat(u.Bin); err == nil {
		_ = os.Remove(u.prev())
		if err := os.Rename(u.Bin, u.prev()); err != nil {
			return fmt.Errorf("keep previous binary: %w", err)
		}
	}
	if err := os.Rename(path, u.Bin); err != nil {
		// Put the old binary back.
		_ = os.Rename(u.prev(), u.Bin)
		return err
	}
	return nil
}

// CanRollback reports whether a previous binary is kept.
func (u *Updater) CanRollback() bool {
	_, err := os.Stat(u.prev())
	return err == nil
}

// PreviousVersion is the version of the rollback copy ("" if none).
func (u *Updater) PreviousVersion() string {
	if !u.CanRollback() {
		return ""
	}
	v, err := BinaryVersion(u.prev())
	if err != nil {
		return "unknown"
	}
	return v
}

// Rollback swaps the installed binary with the previous one (so a second
// rollback undoes the first). The caller restarts the daemon. Returns the
// version now installed.
func (u *Updater) Rollback() (string, error) {
	if !u.setBusy(true) {
		return "", errors.New("an update is already in progress")
	}
	defer u.setBusy(false)
	u.mu.Lock()
	defer u.mu.Unlock()
	if !u.CanRollback() {
		return "", errors.New("no previous version to roll back to")
	}
	v, _ := BinaryVersion(u.prev())
	tmp := u.Bin + ".rollback"
	if err := os.Rename(u.prev(), tmp); err != nil {
		return "", err
	}
	if err := u.swapIn(tmp); err != nil {
		_ = os.Rename(tmp, u.prev())
		return "", err
	}
	return v, nil
}

func (u *Updater) download(ctx context.Context, url string, max int64) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "snake-updater")
	resp, err := u.client().Do(req)
	if err != nil {
		return nil, fmt.Errorf("download: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("download %s: %s", url, resp.Status)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, max+1))
	if err != nil {
		return nil, fmt.Errorf("download: %w", err)
	}
	if int64(len(b)) > max {
		return nil, fmt.Errorf("download %s: too large", url)
	}
	return b, nil
}

// checksumFor finds name in sha256sum output ("<hex>  <name>").
func checksumFor(sums, name string) string {
	sc := bufio.NewScanner(strings.NewReader(sums))
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) == 2 && strings.TrimPrefix(f[1], "*") == name {
			return strings.ToLower(f[0])
		}
	}
	return ""
}

// BinaryVersion runs "<path> version" and returns the version it prints.
func BinaryVersion(path string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, path, "version").Output()
	if err != nil {
		return "", err
	}
	f := strings.Fields(string(out))
	if len(f) < 2 || f[0] != "snake" {
		return "", fmt.Errorf("unexpected version output %q", strings.TrimSpace(string(out)))
	}
	return f[1], nil
}

// vX.Y.Z, optionally followed by git describe's -N-gHASH and/or -dirty.
var (
	verRE      = regexp.MustCompile(`^v?(\d+)\.(\d+)\.(\d+)(-.*)?$`)
	describeRE = regexp.MustCompile(`^-\d+-g[0-9a-f]+`)
)

type version struct {
	n     [3]int
	ahead bool // git describe suffix: built from commits after the tag
	pre   bool // pre-release (-rc1, -beta...)
}

func parseVersion(s string) (version, bool) {
	m := verRE.FindStringSubmatch(strings.TrimSpace(s))
	if m == nil {
		return version{}, false
	}
	var v version
	for i := 0; i < 3; i++ {
		v.n[i], _ = strconv.Atoi(m[i+1])
	}
	if suf := m[4]; suf != "" {
		if describeRE.MatchString(suf) {
			v.ahead = true
		} else if suf != "-dirty" {
			v.pre = true
		}
	}
	return v, true
}

// Newer reports whether latest is a newer release than current. Dev builds
// (current not a version) are never offered automatic updates.
func Newer(latest, current string) bool {
	l, ok1 := parseVersion(latest)
	c, ok2 := parseVersion(current)
	if !ok1 || !ok2 {
		return false
	}
	for i := 0; i < 3; i++ {
		if l.n[i] != c.n[i] {
			return l.n[i] > c.n[i]
		}
	}
	// Same X.Y.Z: a final release beats its pre-release; a build ahead of
	// the tag is already newer.
	return c.pre && !l.pre && !c.ahead
}
