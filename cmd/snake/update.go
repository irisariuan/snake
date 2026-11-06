package main

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/irisariuan/snake/internal/config"
	"github.com/irisariuan/snake/internal/engine"
	"github.com/irisariuan/snake/internal/logx"
	"github.com/irisariuan/snake/internal/update"
)

// newUpdater manages the installed binary. repo is read on every check.
func newUpdater(repo func() string) *update.Updater {
	return &update.Updater{Bin: binPath, Current: engine.Version, Repo: repo}
}

func repoFromConfig() string {
	if c, err := config.Load(paths().Config); err == nil {
		return c.Settings.UpdateRepo
	}
	return ""
}

// installedSelf reports whether this process runs the installed binary
// (not a copy in /tmp or a dev build).
func installedSelf() bool {
	self, err := os.Executable()
	if err != nil {
		return false
	}
	self, _ = filepath.EvalSymlinks(self)
	return self == binPath
}

// restartVerified restarts the daemon from a detached helper process (which
// survives the daemon stopping) and rolls back if the new binary does not
// come up. The helper is the previous binary when there is one: it is the
// one known to work.
func restartVerified() error {
	helper := binPath + ".prev"
	if _, err := os.Stat(helper); err != nil {
		helper = binPath
	}
	devnull, _ := os.OpenFile(os.DevNull, os.O_RDWR, 0)
	cmd := exec.Command(helper, "hook", "restart-verify")
	cmd.Stdin, cmd.Stdout, cmd.Stderr = devnull, devnull, devnull
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	if err := cmd.Start(); err != nil {
		return err
	}
	return cmd.Process.Release()
}

// daemonHealthy waits for the daemon to answer on its socket, then checks it
// is still running a little later (a crash loop fails the second check).
func daemonHealthy(wait time.Duration) bool {
	deadline := time.Now().Add(wait)
	for {
		if pidAlive() {
			if _, err := call("GET", "/api/status", nil); err == nil {
				break
			}
		}
		if time.Now().After(deadline) {
			return false
		}
		time.Sleep(time.Second)
	}
	time.Sleep(15 * time.Second)
	if !pidAlive() {
		return false
	}
	_, err := call("GET", "/api/status", nil)
	return err == nil
}

// hookRestartVerify runs detached after an update or rollback.
func hookRestartVerify() error {
	logx.Init("snake", true, false)
	time.Sleep(2 * time.Second) // let the API response reach the browser
	_ = stop(false)
	time.Sleep(time.Second)
	if err := start(); err == nil && daemonHealthy(60*time.Second) {
		v, _ := update.BinaryVersion(binPath)
		logx.Infof("update: daemon %s is running", v)
		return nil
	}
	u := newUpdater(repoFromConfig)
	bad, _ := update.BinaryVersion(binPath)
	if !u.CanRollback() {
		logx.Errorf("update: daemon %s did not start and there is no previous version", bad)
		return fmt.Errorf("daemon did not start")
	}
	v, err := u.Rollback()
	if err != nil {
		logx.Errorf("update: daemon %s did not start; rollback failed: %v", bad, err)
		return err
	}
	logx.Errorf("update: daemon %s did not start, rolled back to %s", bad, v)
	_ = stop(false)
	time.Sleep(time.Second)
	return start()
}

// autoUpdate checks for releases a few minutes after start and then twice
// a day; with auto_update on it installs them and restarts.
func autoUpdate(ctx context.Context, e *engine.Engine, u *update.Updater) {
	t := time.NewTimer(3 * time.Minute)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		t.Reset(12 * time.Hour)
		cctx, cancel := context.WithTimeout(ctx, time.Minute)
		in, err := u.Check(cctx)
		cancel()
		if err != nil {
			logx.Warnf("update check: %v", err)
			continue
		}
		if !in.Available {
			continue
		}
		if !e.Config().Settings.AutoUpdate || !installedSelf() {
			logx.Infof("update available: %s (running %s)", in.Latest, in.Current)
			continue
		}
		ictx, cancel := context.WithTimeout(ctx, 5*time.Minute)
		v, err := u.Install(ictx)
		cancel()
		if err != nil {
			logx.Errorf("auto-update to %s: %v", in.Latest, err)
			continue
		}
		logx.Infof("auto-update: installed %s (was %s), restarting", v, in.Current)
		if err := restartVerified(); err != nil {
			logx.Errorf("auto-update: restart: %v", err)
		}
		return
	}
}

// ---------- CLI ----------

func updateCmd(args []string) error {
	u := newUpdater(repoFromConfig)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	in, err := u.Check(ctx)
	if err != nil {
		return err
	}
	fmt.Printf("running %s, latest release %s (%s)\n", in.Current, in.Latest, in.URL)
	if !in.Comparable {
		fmt.Println("this is a development build: it cannot be compared with releases")
	}
	if hasFlag(args, "--check") {
		if in.Available {
			fmt.Println("update available: snake update")
		} else {
			fmt.Println("no update available")
		}
		return nil
	}
	if !in.Available && !hasFlag(args, "--force") {
		fmt.Println("already up to date (--force reinstalls the latest release)")
		return nil
	}
	if !hasFlag(args, "--yes") && !confirm(fmt.Sprintf("Install %s?", in.Latest)) {
		return nil
	}
	v, err := u.Install(ctx)
	if err != nil {
		return err
	}
	fmt.Printf("installed %s; previous version kept for: snake rollback\n", v)
	return restartAfterSwap()
}

func rollbackCmd(args []string) error {
	u := newUpdater(repoFromConfig)
	prev := u.PreviousVersion()
	if prev == "" {
		return fmt.Errorf("no previous version to roll back to")
	}
	if !hasFlag(args, "--yes") && !confirm(fmt.Sprintf("Roll back to %s?", prev)) {
		return nil
	}
	v, err := u.Rollback()
	if err != nil {
		return err
	}
	fmt.Printf("rolled back to %s (run snake rollback again to undo)\n", v)
	return restartAfterSwap()
}

func restartAfterSwap() error {
	if !pidAlive() {
		fmt.Println("daemon not running; start it with: snake start")
		return nil
	}
	if err := restartVerified(); err != nil {
		return err
	}
	fmt.Println("daemon restarting (rolls back automatically if it does not come up)")
	return nil
}

func confirm(q string) bool {
	fmt.Print(q + " [y/N] ")
	l, _ := bufio.NewReader(os.Stdin).ReadString('\n')
	l = strings.ToLower(strings.TrimSpace(l))
	return l == "y" || l == "yes"
}
