package netfilter

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"

	"github.com/irisariuan/snake/internal/system"
)

// IPSet manages ipsets through the ipset CLI.
type IPSet struct {
	R system.Runner
}

// SetSpec describes a set to create.
type SetSpec struct {
	Name    string
	Type    string // hash:net, hash:ip
	V6      bool
	Timeout int
	MaxElem int
}

func (s SetSpec) createArgs(name string) []string {
	fam := "inet"
	if s.V6 {
		fam = "inet6"
	}
	args := []string{"create", name, s.Type, "family", fam}
	if s.MaxElem > 0 {
		args = append(args, "maxelem", strconv.Itoa(s.MaxElem))
	}
	if s.Timeout > 0 {
		args = append(args, "timeout", strconv.Itoa(s.Timeout))
	}
	return args
}

// Ensure creates the set if missing. If a set with the same name but
// different parameters exists, it is recreated when unreferenced.
func (x IPSet) Ensure(s SetSpec) error {
	args := append([]string{"-exist"}, s.createArgs(s.Name)...)
	if _, err := x.R.Run("ipset", args...); err == nil {
		return nil
	}
	// Parameters changed: swap in a fresh set, keeping members where possible.
	tmp := tmpName(s.Name)
	_, _ = x.R.Run("ipset", "destroy", tmp)
	if _, err := x.R.Run("ipset", s.createArgs(tmp)...); err != nil {
		return err
	}
	if _, err := x.R.Run("ipset", "swap", tmp, s.Name); err != nil {
		_, _ = x.R.Run("ipset", "destroy", tmp)
		return fmt.Errorf("ipset %s has incompatible parameters and cannot be swapped: %w", s.Name, err)
	}
	_, _ = x.R.Run("ipset", "destroy", tmp)
	return nil
}

func tmpName(n string) string {
	t := n + "_t"
	if len(t) > 31 {
		t = t[:31]
	}
	return t
}

// Replace atomically replaces the members of a set.
func (x IPSet) Replace(s SetSpec, members []string) error {
	if err := x.Ensure(s); err != nil {
		return err
	}
	tmp := tmpName(s.Name)
	var b strings.Builder
	b.WriteString(strings.Join(s.createArgs(tmp), " ") + "\n")
	b.WriteString("flush " + tmp + "\n")
	for _, m := range members {
		b.WriteString("add " + tmp + " " + m + "\n")
	}
	if _, err := x.R.RunInput(b.String(), "ipset", "-exist", "restore"); err != nil {
		_, _ = x.R.Run("ipset", "destroy", tmp)
		return err
	}
	if _, err := x.R.Run("ipset", "swap", tmp, s.Name); err != nil {
		return err
	}
	_, err := x.R.Run("ipset", "destroy", tmp)
	return err
}

// AddMany adds entries (with -exist) in one call.
func (x IPSet) AddMany(name string, entries []string) error {
	if len(entries) == 0 {
		return nil
	}
	var b strings.Builder
	for _, e := range entries {
		b.WriteString("add " + name + " " + e + "\n")
	}
	_, err := x.R.RunInput(b.String(), "ipset", "-exist", "restore")
	return err
}

// Del removes entries (missing ones are ignored) in one call.
func (x IPSet) Del(name string, entries []string) error {
	if len(entries) == 0 {
		return nil
	}
	var b strings.Builder
	for _, e := range entries {
		b.WriteString("del " + name + " " + e + "\n")
	}
	_, err := x.R.RunInput(b.String(), "ipset", "-exist", "restore")
	return err
}

// Flush empties a set.
func (x IPSet) Flush(name string) error {
	_, err := x.R.Run("ipset", "flush", name)
	return err
}

// Test reports whether ip is in the set.
func (x IPSet) Test(name, ip string) bool {
	_, err := x.R.Run("ipset", "test", name, ip)
	return err == nil
}

// Names lists sets with the snake prefix.
func (x IPSet) Names() []string {
	out, err := x.R.Run("ipset", "list", "-n")
	if err != nil {
		return nil
	}
	var names []string
	for _, l := range strings.Split(out, "\n") {
		l = strings.TrimSpace(l)
		if strings.HasPrefix(l, SetPrefix) {
			names = append(names, l)
		}
	}
	return names
}

// Count returns the number of entries in a set (-1 if missing).
func (x IPSet) Count(name string) int {
	out, err := x.R.Run("ipset", "list", name, "-t")
	if err != nil {
		return -1
	}
	for _, l := range strings.Split(out, "\n") {
		if strings.HasPrefix(l, "Number of entries:") {
			n, _ := strconv.Atoi(strings.TrimSpace(strings.TrimPrefix(l, "Number of entries:")))
			return n
		}
	}
	return 0
}

// Members lists up to limit members.
func (x IPSet) Members(name string, limit int) []string {
	out, err := x.R.Run("ipset", "list", name)
	if err != nil {
		return nil
	}
	var m []string
	in := false
	sc := bufio.NewScanner(strings.NewReader(out))
	for sc.Scan() {
		l := strings.TrimSpace(sc.Text())
		if l == "Members:" {
			in = true
			continue
		}
		if in && l != "" {
			m = append(m, l)
			if limit > 0 && len(m) >= limit {
				break
			}
		}
	}
	return m
}

// Destroy removes a set (fails silently when still referenced).
func (x IPSet) Destroy(name string) error {
	_, err := x.R.Run("ipset", "destroy", name)
	return err
}

// Save writes the named sets to path in ipset restore format.
func (x IPSet) Save(path string, names []string) error {
	var b strings.Builder
	for _, n := range names {
		out, err := x.R.Run("ipset", "save", n)
		if err != nil {
			continue
		}
		b.WriteString(out + "\n")
	}
	_, err := system.WriteIfChanged(path, []byte(b.String()), 0o600)
	return err
}

// RestoreFile loads a saved file, ignoring existing entries.
func (x IPSet) RestoreFile(path string) error {
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	if len(strings.TrimSpace(string(b))) == 0 {
		return nil
	}
	_, err = x.R.RunInput(string(b), "ipset", "-exist", "restore")
	return err
}

// SplitFamilies separates CIDRs/IPs into IPv4 and IPv6 lists.
func SplitFamilies(entries []string) (v4, v6 []string) {
	for _, e := range entries {
		ipStr := e
		if i := strings.IndexByte(e, '/'); i >= 0 {
			ipStr = e[:i]
		}
		ip := net.ParseIP(ipStr)
		if ip == nil {
			continue
		}
		if ip.To4() != nil {
			v4 = append(v4, e)
		} else {
			v6 = append(v6, e)
		}
	}
	return
}
