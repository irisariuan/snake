// Command snake is a split-tunnelling daemon, CLI and web UI for Asuswrt-Merlin.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"text/tabwriter"
	"time"

	"github.com/irisariuan/snake/internal/api"
	"github.com/irisariuan/snake/internal/config"
	"github.com/irisariuan/snake/internal/dnsmasq"
	"github.com/irisariuan/snake/internal/engine"
	"github.com/irisariuan/snake/internal/importdvr"
	"github.com/irisariuan/snake/internal/logx"
	"github.com/irisariuan/snake/internal/netfilter"
	"github.com/irisariuan/snake/internal/routing"
	"github.com/irisariuan/snake/internal/system"
	"github.com/irisariuan/snake/internal/webui"
)

const (
	baseDir        = "/jffs/addons/snake"
	binPath        = baseDir + "/snake"
	tokenPath      = baseDir + "/token"
	aspPath        = baseDir + "/snake.asp"
	customSettings = "/jffs/addons/custom_settings.txt"
	lockPath       = "/var/lock/snake.lock"
	hookTag        = "# snake"
)

func usage() {
	fmt.Fprint(os.Stderr, `snake: split tunnelling for Asuswrt-Merlin

Usage: snake <command> [args]

  install                 install hooks, web UI page and start the daemon
  uninstall [--purge]     remove everything (--purge also deletes config)
  start | stop | restart  control the daemon (stop --flush also removes rules)
  disable | enable        emergency switch: remove all rules (traffic uses WAN,
                          kill switches off) and stop applying / turn back on
  status                  show tunnels and policies
  update [--check] [--yes] [--force]
                          install the latest GitHub release (restarts the daemon)
  update --list           list published releases
  update --version V [--yes]
                          install release V, older or newer (restarts the daemon)
  rollback [--yes]        go back to the version before the last update
  apply [--dry-run]       re-apply rules (dry run prints the generated commands)
  reload                  reload config.json from disk and apply
  policy list             list policies
  test <domain>           show how a domain is routed
  rules list|check|import|export
                          manage rule lists / .rules files (snake rules for help)
  learn list|show|new|set|add|rm|move|merge|delete|addrs|forget
                          learning groups and learned addresses (snake learn for help)
  import-dvr [--dir D] [--yes]
                          import Domain VPN Routing policies
  token [--rotate]        print the API token for the standalone UI
  webui-mount             (re)install the Addons page
  daemon                  run in the foreground
  version
`)
}

func main() {
	fixCACerts()
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	cmd, args := os.Args[1], os.Args[2:]
	var err error
	switch cmd {
	case "daemon":
		err = runDaemon()
	case "start":
		err = start()
	case "stop":
		err = stop(hasFlag(args, "--flush"))
	case "restart":
		_ = stop(false)
		time.Sleep(time.Second)
		err = start()
	case "disable":
		err = disableCmd()
	case "enable":
		err = enableCmd()
	case "status":
		err = status()
	case "update":
		err = updateCmd(args)
	case "rollback":
		err = rollbackCmd(args)
	case "apply":
		if hasFlag(args, "--dry-run") {
			err = dryRun()
		} else {
			err = applyCmd("manual")
		}
	case "reload":
		err = callOrLocal("POST", "/api/reload", "reload")
	case "policy":
		err = policyList()
	case "test":
		if len(args) < 1 {
			err = fmt.Errorf("usage: snake test <domain>")
			break
		}
		err = printCall("GET", "/api/test?domain="+args[0])
	case "rules":
		err = rulesCmd(args)
	case "learn", "learnings":
		err = learnCmd(args)
	case "import-dvr":
		err = importCmd(args)
	case "token":
		err = tokenCmd(hasFlag(args, "--rotate"))
	case "install":
		err = install()
	case "uninstall":
		err = uninstall(hasFlag(args, "--purge"))
	case "webui-mount":
		err = webuiMount()
	case "hook":
		err = hook(args)
	case "version", "--version", "-v":
		fmt.Println("snake", engine.Version)
	case "help", "-h", "--help":
		usage()
	default:
		usage()
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "snake:", err)
		os.Exit(1)
	}
}

func hasFlag(args []string, f string) bool {
	for _, a := range args {
		if a == f {
			return true
		}
	}
	return false
}

func flagValue(args []string, f string) string {
	for i, a := range args {
		if a == f && i+1 < len(args) {
			return args[i+1]
		}
		if strings.HasPrefix(a, f+"=") {
			return strings.TrimPrefix(a, f+"=")
		}
	}
	return ""
}

// fixCACerts points Go at Merlin's CA bundle when the standard paths are missing.
func fixCACerts() {
	if os.Getenv("SSL_CERT_FILE") != "" {
		return
	}
	for _, p := range []string{"/etc/ssl/certs/ca-certificates.crt", "/etc/ssl/cert.pem"} {
		if _, err := os.Stat(p); err == nil {
			return
		}
	}
	for _, p := range []string{"/rom/etc/ssl/certs/ca-certificates.crt", "/rom/etc/ssl/cert.pem", "/opt/etc/ssl/certs/ca-certificates.crt", "/rom/ca-bundle.crt"} {
		if _, err := os.Stat(p); err == nil {
			os.Setenv("SSL_CERT_FILE", p)
			return
		}
	}
}

func paths() engine.Paths { return engine.DefaultPaths(baseDir) }

// ---------- daemon ----------

func runDaemon() error {
	isTTY := false
	if fi, err := os.Stdout.Stat(); err == nil && fi.Mode()&os.ModeCharDevice != 0 {
		isTTY = true
	}
	logx.Init("snake", !isTTY, os.Getenv("SNAKE_DEBUG") != "")
	p := paths()
	if pidAlive() {
		return fmt.Errorf("daemon already running")
	}
	_ = os.MkdirAll(p.Base, 0o755)
	_ = os.WriteFile(p.PID, []byte(strconv.Itoa(os.Getpid())), 0o644)
	defer os.Remove(p.PID)

	e := engine.New(p, system.Exec{})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	tok, err := api.LoadToken(tokenPath, false)
	if err != nil {
		return err
	}
	if err := api.PublishToken(customSettings, tok); err != nil {
		logx.Warnf("publish token: %v", err)
	}
	cfg, err := config.Load(p.Config)
	if err != nil {
		return err
	}
	lanIP := system.NVRAM{R: system.Exec{}}.Get("lan_ipaddr")
	u := newUpdater(func() string { return e.Config().Settings.UpdateRepo })
	srv := &api.Server{E: e, Token: tok, U: u, Restart: restartVerified}
	go autoUpdate(ctx, e, u)
	go func() {
		if err := srv.Serve(ctx, p.Socket, lanIP, cfg.Settings.APIPort); err != nil {
			logx.Errorf("api: %v", err)
		}
	}()

	sig := make(chan os.Signal, 2)
	signal.Notify(sig, syscall.SIGTERM, syscall.SIGINT, syscall.SIGHUP)
	go func() {
		for s := range sig {
			if s == syscall.SIGHUP {
				if err := e.Load(); err != nil {
					logx.Errorf("reload: %v", err)
					continue
				}
				_ = e.Apply("SIGHUP")
				continue
			}
			cancel()
			return
		}
	}()
	logx.Infof("snake %s starting", engine.Version)
	return e.Run(ctx)
}

func pidAlive() bool {
	b, err := os.ReadFile(paths().PID)
	if err != nil {
		return false
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(b)))
	if err != nil || pid <= 1 || pid == os.Getpid() {
		return false
	}
	if syscall.Kill(pid, 0) != nil {
		return false
	}
	cmdline, _ := os.ReadFile(fmt.Sprintf("/proc/%d/cmdline", pid))
	return strings.Contains(string(cmdline), "snake")
}

func start() error {
	if pidAlive() {
		fmt.Println("snake daemon already running")
		return nil
	}
	// The installed binary, so a start from another copy (the rollback
	// helper, an installer in /tmp) runs the current version.
	self := binPath
	if _, err := os.Stat(self); err != nil {
		if self, err = os.Executable(); err != nil {
			return err
		}
	}
	devnull, _ := os.OpenFile(os.DevNull, os.O_RDWR, 0)
	cmd := exec.Command(self, "daemon")
	cmd.Stdin, cmd.Stdout, cmd.Stderr = devnull, devnull, devnull
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	if err := cmd.Start(); err != nil {
		return err
	}
	fmt.Println("snake daemon started, pid", cmd.Process.Pid)
	return cmd.Process.Release()
}

func stop(flush bool) error {
	b, err := os.ReadFile(paths().PID)
	if err == nil && pidAlive() {
		pid, _ := strconv.Atoi(strings.TrimSpace(string(b)))
		_ = syscall.Kill(pid, syscall.SIGTERM)
		for i := 0; i < 50 && pidAlive(); i++ {
			time.Sleep(100 * time.Millisecond)
		}
		fmt.Println("snake daemon stopped")
	} else {
		fmt.Println("snake daemon not running")
	}
	if flush {
		teardown()
		fmt.Println("rules, routes and sets removed")
	}
	return nil
}

// disableCmd is the emergency switch. Without a daemon it removes the rules
// itself and leaves the flag file, which keeps a later start disabled.
func disableCmd() error {
	if pidAlive() {
		if _, err := call("POST", "/api/disable?reason=cli", nil); err != nil {
			return err
		}
	} else {
		if err := os.WriteFile(paths().Disabled, []byte(time.Now().Format(time.RFC3339)+" cli\n"), 0o644); err != nil {
			return err
		}
		teardown()
	}
	fmt.Println("snake DISABLED: rules, routes and sets removed; all traffic uses WAN. Turn back on with: snake enable")
	return nil
}

func enableCmd() error {
	if pidAlive() {
		if _, err := call("POST", "/api/enable?reason=cli", nil); err != nil {
			return err
		}
		fmt.Println("snake enabled")
		return nil
	}
	if err := os.Remove(paths().Disabled); err != nil && !os.IsNotExist(err) {
		return err
	}
	fmt.Println("snake enabled; daemon not running, start it with: snake start")
	return nil
}

func teardown() {
	r := system.Exec{}
	ipv6 := system.Exists("ip6tables-restore")
	cfg, _ := config.Load(paths().Config)
	lan := "br+"
	if cfg != nil {
		lan = cfg.Settings.LANInterfaces
	}
	netfilter.Applier{R: r}.Teardown(ipv6, lan)
	routing.Manager{R: r}.Teardown(ipv6)
	ips := netfilter.IPSet{R: r}
	for _, n := range ips.Names() {
		_ = ips.Destroy(n)
	}
	_ = os.Remove(paths().DNSMasq)
	_, _ = r.Run("service", "restart_dnsmasq")
}

// ---------- client ----------

func client() *http.Client {
	return &http.Client{
		Timeout: 60 * time.Second,
		Transport: &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "unix", paths().Socket)
		}},
	}
}

func call(method, path string, body io.Reader) ([]byte, error) {
	req, err := http.NewRequest(method, "http://snake"+path, body)
	if err != nil {
		return nil, err
	}
	resp, err := client().Do(req)
	if err != nil {
		return nil, fmt.Errorf("daemon not reachable (%w); start it with: snake start", err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 400 {
		var e struct{ Error string }
		_ = json.Unmarshal(b, &e)
		return nil, fmt.Errorf("%s", e.Error)
	}
	return b, nil
}

func printCall(method, path string) error {
	b, err := call(method, path, nil)
	if err != nil {
		return err
	}
	var v any
	_ = json.Unmarshal(b, &v)
	out, _ := json.MarshalIndent(v, "", "  ")
	fmt.Println(string(out))
	return nil
}

// callOrLocal asks the daemon; when it is not running, applies directly.
func callOrLocal(method, path, reason string) error {
	if pidAlive() {
		_, err := call(method, path, nil)
		if err == nil {
			fmt.Println("ok")
		}
		return err
	}
	return applyLocal(reason)
}

func applyCmd(reason string) error { return callOrLocal("POST", "/api/apply", reason) }

func applyLocal(reason string) error {
	unlock, err := lock()
	if err != nil {
		return err
	}
	defer unlock()
	logx.Init("snake", true, false)
	e := engine.New(paths(), system.Exec{})
	return e.ApplyOnce(reason)
}

func lock() (func(), error) {
	f, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return func() {}, nil // no /var/lock: run unlocked
	}
	deadline := time.Now().Add(60 * time.Second)
	for {
		if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err == nil {
			return func() { _ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN); f.Close() }, nil
		}
		if time.Now().After(deadline) {
			f.Close()
			return nil, fmt.Errorf("timed out waiting for %s", lockPath)
		}
		time.Sleep(200 * time.Millisecond)
	}
}

func status() error {
	b, err := call("GET", "/api/status", nil)
	if err != nil {
		return err
	}
	var st engine.Status
	if err := json.Unmarshal(b, &st); err != nil {
		return err
	}
	fmt.Printf("snake %s, up %s, WAN %s, last apply %s\n", st.Version, st.Uptime, st.WANIP, st.LastApply.Format(time.RFC3339))
	if st.Disabled {
		fmt.Println("*** DISABLED (emergency switch): no rules installed, all traffic uses WAN. Turn back on with: snake enable")
	}
	fmt.Printf("caps: ipv6=%v ipv6nat=%v nfqueue=%v conntrack=%v\n", st.Caps.IPv6, st.Caps.IPv6NAT, st.Caps.NFQueue, st.Caps.Conntrack)
	if st.LastError != "" {
		fmt.Println("LAST ERROR:", st.LastError)
	}
	tw := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "\nTUNNEL\tIFACE\tHEALTHY\tEXIT\tCOUNTRY\tRTT\tAVG\tLOSS\tMBIT/S\tREASON")
	var names []string
	for n := range st.Tunnels {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		t := st.Tunnels[n]
		avg, mbps := "", ""
		if t.RTTMs > 0 {
			avg = fmt.Sprintf("%.0fms", t.RTTMs)
		}
		if t.ThroughputMbps > 0 {
			mbps = fmt.Sprintf("%.1f", t.ThroughputMbps)
		}
		fmt.Fprintf(tw, "%s\t%s\t%v\t%s\t%s\t%s\t%s\t%.0f%%\t%s\t%s\n", n, t.Iface, t.Healthy, t.ExitIP, t.Country, t.ProbeRTT, avg, t.Loss*100, mbps, t.Reason)
	}
	fmt.Fprintln(tw, "\nPOLICY\tSCOPE\tROUTE\tIPV6\tWEBRTC\tTRAFFIC\tSETS")
	for _, p := range st.Policies {
		route := p.Active
		switch {
		case !p.Enabled:
			route = "disabled"
		case p.KillEngaged:
			route = "BLOCKED (kill switch)"
		case p.Leaking:
			route = "WAN (no tunnel)"
		}
		var sets []string
		for k, v := range p.Sets {
			sets = append(sets, fmt.Sprintf("%s=%d", strings.TrimPrefix(k, fmt.Sprintf("SNK_%d_", p.ID)), v))
		}
		sort.Strings(sets)
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%dB\t%s\n", p.Name, p.Scope, route, p.IPv6Mode, p.WebRTCMode, p.Bytes, strings.Join(sets, " "))
	}
	return tw.Flush()
}

func devicesSummary(p config.Policy) string {
	if len(p.ExcludeDevices) == 0 {
		return strconv.Itoa(len(p.Devices))
	}
	return fmt.Sprintf("%d (-%d)", len(p.Devices), len(p.ExcludeDevices))
}

func policyList() error {
	cfg, err := config.Load(paths().Config)
	if err != nil {
		return err
	}
	tw := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "ID\tNAME\tENABLED\tTUNNELS\tKILL\tSCOPE\tDOMAINS\tASNS\tCIDRS\tDEVICES")
	for _, p := range cfg.Policies {
		fmt.Fprintf(tw, "%d\t%s\t%v\t%s\t%v\t%s\t%d\t%d\t%d\t%s\n", p.ID, p.Name, p.Enabled, strings.Join(p.Tunnels, ">"), p.KillSwitch, p.Scope(), len(p.Domains), len(p.ASNs), len(p.CIDRs), devicesSummary(p))
	}
	return tw.Flush()
}

// dryRun prints every command an apply would run, without touching the system.
func dryRun() error {
	rec := &system.Recorder{Responses: map[string]string{"nvram get ipv6_service": "native"}}
	e := engine.New(paths(), rec)
	e.DryRun = true
	if p := os.Getenv("SNAKE_CONFIG"); p != "" {
		e.P.Config = p
	}
	if err := e.Load(); err != nil {
		return err
	}
	e.DetectCaps()
	e.SeedHealth()
	_ = e.Apply("dry run")
	fmt.Println(rec.Joined())
	fmt.Println("\n# dnsmasq fragment")
	fmt.Print(dnsmasq.Generate(e.Config().Runtime(), e.Caps().NFQueue))
	return nil
}

func importCmd(args []string) error {
	dir := flagValue(args, "--dir")
	if dir == "" {
		dir = importdvr.DefaultDir
	}
	res, err := importdvr.Read(dir)
	if err != nil {
		return err
	}
	for _, w := range res.Warnings {
		fmt.Println("warning:", w)
	}
	for _, p := range res.Policies {
		fmt.Printf("  %s via %s: %d domains, %d ASNs\n", p.Name, strings.Join(p.Tunnels, ","), len(p.Domains), len(p.ASNs))
	}
	if !hasFlag(args, "--yes") {
		fmt.Println("preview only; re-run with --yes to import")
		return nil
	}
	if pidAlive() {
		_, err := call("POST", "/api/import-dvr?apply=1&dir="+dir, nil)
		if err == nil {
			fmt.Println("imported")
		}
		return err
	}
	cfg, err := config.Load(paths().Config)
	if err != nil {
		return err
	}
	importdvr.Merge(cfg, res.Policies)
	if err := cfg.Validate(); err != nil {
		return err
	}
	if err := config.Save(paths().Config, cfg); err != nil {
		return err
	}
	fmt.Println("imported; run: snake apply")
	return nil
}

func tokenCmd(rotate bool) error {
	tok, err := api.LoadToken(tokenPath, rotate)
	if err != nil {
		return err
	}
	if rotate {
		_ = api.PublishToken(customSettings, tok)
		fmt.Fprintln(os.Stderr, "token rotated; restart the daemon: snake restart")
	}
	fmt.Println(tok)
	return nil
}

// ---------- hooks ----------

func hook(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("hook name required")
	}
	switch args[0] {
	case "services-start":
		_ = webuiMount()
		_, _ = system.Exec{}.Run("cru", "a", "snake_watchdog", "*/5 * * * * "+binPath+" start >/dev/null 2>&1")
		return start()
	case "services-stop":
		return stop(false)
	case "restart-verify":
		return hookRestartVerify()
	case "firewall":
		// firewall-start and nat-start: rules were wiped, put them back now.
		return applyCmd("firewall hook")
	case "dnsmasq":
		if len(args) < 2 {
			return fmt.Errorf("usage: hook dnsmasq <config>")
		}
		if _, err := os.Stat(paths().DNSMasq); err != nil {
			return nil
		}
		return dnsmasq.PostConf(args[1], paths().DNSMasq)
	case "tunnel":
		if pidAlive() {
			_, err := call("POST", "/api/recheck", nil)
			return err
		}
		return applyLocal("tunnel event")
	}
	return fmt.Errorf("unknown hook %q", args[0])
}

type hookFile struct {
	name string
	line string
}

func hookFiles() []hookFile {
	return []hookFile{
		{"services-start", binPath + " hook services-start & " + hookTag},
		{"services-stop", binPath + " hook services-stop " + hookTag},
		{"firewall-start", binPath + " hook firewall " + hookTag},
		{"nat-start", binPath + " hook firewall " + hookTag},
		{"dnsmasq.postconf", binPath + " hook dnsmasq \"$1\" " + hookTag},
		{"wgclient-start", binPath + " hook tunnel & " + hookTag},
		{"wgclient-stop", binPath + " hook tunnel & " + hookTag},
		{"openvpn-event", binPath + " hook tunnel & " + hookTag},
	}
}

func writeHook(h hookFile) error {
	p := filepath.Join("/jffs/scripts", h.name)
	b, err := os.ReadFile(p)
	content := string(b)
	if err != nil || strings.TrimSpace(content) == "" {
		content = "#!/bin/sh\n"
	}
	var keep []string
	for _, l := range strings.Split(strings.TrimRight(content, "\n"), "\n") {
		if !strings.HasSuffix(strings.TrimSpace(l), hookTag) {
			keep = append(keep, l)
		}
	}
	keep = append(keep, h.line)
	if err := os.WriteFile(p, []byte(strings.Join(keep, "\n")+"\n"), 0o755); err != nil {
		return err
	}
	return os.Chmod(p, 0o755)
}

func removeHook(h hookFile) {
	p := filepath.Join("/jffs/scripts", h.name)
	b, err := os.ReadFile(p)
	if err != nil {
		return
	}
	var keep []string
	for _, l := range strings.Split(strings.TrimRight(string(b), "\n"), "\n") {
		if !strings.HasSuffix(strings.TrimSpace(l), hookTag) {
			keep = append(keep, l)
		}
	}
	if len(keep) == 1 && strings.HasPrefix(keep[0], "#!") {
		_ = os.Remove(p)
		return
	}
	_ = os.WriteFile(p, []byte(strings.Join(keep, "\n")+"\n"), 0o755)
}

func webuiMount() error {
	cfg, err := config.Load(paths().Config)
	if err != nil {
		cfg = config.Default()
	}
	if err := os.WriteFile(aspPath, webui.ASP(cfg.Settings.APIPort), 0o644); err != nil {
		return err
	}
	out, err := system.Exec{}.RunInput(webui.MountScript(), "sh", "-s", aspPath)
	if err != nil {
		return err
	}
	fmt.Println("web UI page:", strings.TrimSpace(out))
	return nil
}

func install() error {
	nv := system.NVRAM{R: system.Exec{}}
	if nv.Get("buildno") == "" {
		return fmt.Errorf("this does not look like an Asuswrt-Merlin router")
	}
	if err := os.MkdirAll(baseDir, 0o755); err != nil {
		return err
	}
	if err := os.MkdirAll("/jffs/scripts", 0o755); err != nil {
		return err
	}
	self, err := os.Executable()
	if err != nil {
		return err
	}
	if self, _ = filepath.EvalSymlinks(self); self != binPath {
		b, err := os.ReadFile(self)
		if err != nil {
			return err
		}
		if err := os.WriteFile(binPath+".new", b, 0o755); err != nil {
			return err
		}
		if err := os.Rename(binPath+".new", binPath); err != nil {
			return err
		}
		fmt.Println("installed binary to", binPath)
	}
	if nv.Get("jffs2_scripts") != "1" {
		_, _ = system.Exec{}.Run("nvram", "set", "jffs2_scripts=1")
		_, _ = system.Exec{}.Run("nvram", "commit")
		fmt.Println("enabled custom JFFS scripts")
	}
	for _, h := range hookFiles() {
		if err := writeHook(h); err != nil {
			return err
		}
	}
	if _, err := os.Stat(paths().Config); err != nil {
		if err := config.Save(paths().Config, config.Default()); err != nil {
			return err
		}
	}
	if _, err := api.LoadToken(tokenPath, false); err != nil {
		return err
	}
	_ = os.Symlink(binPath, "/opt/bin/snake") // convenience when Entware exists
	if err := webuiMount(); err != nil {
		fmt.Println("warning: web UI page:", err)
	}
	_, _ = system.Exec{}.Run("cru", "a", "snake_watchdog", "*/5 * * * * "+binPath+" start >/dev/null 2>&1")
	if pidAlive() {
		_ = stop(false)
	}
	cmd := exec.Command(binPath, "start")
	cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
	if err := cmd.Run(); err != nil {
		return err
	}
	fmt.Println("done. Open the router WebUI → Addons → snake, or run: snake status")
	fmt.Println("tip: set each VPN client's \"Redirect Internet traffic through tunnel\" to \"VPN Director\" (with no rules) so only snake decides what uses it.")
	return nil
}

func uninstall(purge bool) error {
	_ = stop(true)
	engine.NewWireGuard(system.Exec{}).RemoveAll() // snake's own tunnels
	engine.NewOpenVPN(system.Exec{}).StopAll()
	for _, h := range hookFiles() {
		removeHook(h)
	}
	_, _ = system.Exec{}.Run("cru", "d", "snake_watchdog")
	_, _ = system.Exec{}.RunInput(webui.UnmountScript(), "sh", "-s")
	if b, err := os.ReadFile(customSettings); err == nil {
		var keep []string
		for _, l := range strings.Split(string(b), "\n") {
			if l != "" && !strings.HasPrefix(l, "snake_") {
				keep = append(keep, l)
			}
		}
		_ = os.WriteFile(customSettings, []byte(strings.Join(keep, "\n")+"\n"), 0o644)
	}
	_ = os.Remove("/opt/bin/snake")
	_ = os.Remove(paths().Disabled) // a reinstall starts enabled
	if purge {
		_ = os.RemoveAll(baseDir)
		fmt.Println("removed", baseDir)
	} else {
		fmt.Println("config kept in", baseDir, "(use --purge to delete)")
	}
	fmt.Println("snake uninstalled")
	return nil
}
