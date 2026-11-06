package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"text/tabwriter"

	"github.com/irisariuan/snake/internal/api"
	"github.com/irisariuan/snake/internal/config"
	"github.com/irisariuan/snake/internal/rulefile"
)

const rulesUsage = `usage:
  snake rules list
  snake rules check <file>
  snake rules import <file|url> [--name NAME] [--no-convert]
  snake rules export <list> [-o FILE]
  snake rules export --policy <name|id> [--expand] [-o FILE]`

func rulesCmd(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("%s", rulesUsage)
	}
	switch args[0] {
	case "list":
		return rulesList()
	case "check":
		if len(args) < 2 {
			return fmt.Errorf("%s", rulesUsage)
		}
		return rulesCheck(args[1])
	case "import":
		if len(args) < 2 {
			return fmt.Errorf("%s", rulesUsage)
		}
		return rulesImport(args[1], flagValue(args, "--name"), !hasFlag(args, "--no-convert"))
	case "export":
		return rulesExport(args[1:])
	}
	return fmt.Errorf("%s", rulesUsage)
}

func rulesList() error {
	cfg, err := config.Load(paths().Config)
	if err != nil {
		return err
	}
	tw := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "LIST\tDOMAIN RULES\tASNS\tCIDRS\tUSED BY\tSOURCE")
	for _, l := range cfg.RuleLists {
		var users []string
		for _, p := range cfg.Policies {
			for _, n := range p.Lists {
				if n == l.Name {
					users = append(users, p.Name)
				}
			}
		}
		n := 0
		for _, d := range l.Domains {
			if !strings.HasPrefix(d, "#") {
				n++
			}
		}
		fmt.Fprintf(tw, "%s\t%d\t%d\t%d\t%s\t%s\n", l.Name, n, len(l.ASNs), len(l.CIDRs), strings.Join(users, ","), l.Source)
	}
	return tw.Flush()
}

func readSource(src string) (string, error) {
	if strings.HasPrefix(src, "http://") || strings.HasPrefix(src, "https://") {
		return api.FetchRules(src)
	}
	b, err := os.ReadFile(src)
	return string(b), err
}

func rulesCheck(path string) error {
	text, err := readSource(path)
	if err != nil {
		return err
	}
	res := rulefile.Parse(text, false)
	for _, e := range res.Errors {
		fmt.Printf("%s:%d: error: %s\n    %s\n", path, e.Line, e.Message, strings.TrimSpace(e.Text))
	}
	for _, w := range res.Warnings {
		fmt.Printf("%s:%d: warning: %s\n", path, w.Line, w.Message)
	}
	f := res.File
	fmt.Printf("%s: %d domain rules, %d ASNs, %d CIDRs\n", path, len(f.Domains), len(f.ASNs), len(f.CIDRs))
	if len(res.Errors) > 0 {
		return fmt.Errorf("%d error(s)", len(res.Errors))
	}
	return nil
}

func rulesImport(src, name string, convert bool) error {
	text, err := readSource(src)
	if err != nil {
		return err
	}
	res := rulefile.Parse(text, convert)
	for _, e := range res.Errors {
		fmt.Printf("line %d: skipped: %s\n", e.Line, e.Message)
	}
	f := res.File
	if name != "" {
		f.Name = name
	}
	if f.Name == "" {
		f.Name = strings.TrimSuffix(filepath.Base(src), filepath.Ext(src))
	}
	if f.Source == "" && (strings.HasPrefix(src, "http://") || strings.HasPrefix(src, "https://")) {
		f.Source = src
	}
	if res.Converted > 0 {
		fmt.Printf("converted %d line(s) from other list formats\n", res.Converted)
	}
	clean := rulefile.Format(f)
	if pidAlive() {
		body, _ := json.Marshal(map[string]any{"text": clean})
		if _, err := call("PUT", "/api/lists/"+urlPath(f.Name), bytes.NewReader(body)); err != nil {
			return err
		}
	} else {
		cfg, err := config.Load(paths().Config)
		if err != nil {
			return err
		}
		if _, err := api.SaveList(cfg, f.Name, clean, false); err != nil {
			return err
		}
		cfg.Normalize()
		if err := cfg.Validate(); err != nil {
			return err
		}
		if err := config.Save(paths().Config, cfg); err != nil {
			return err
		}
	}
	fmt.Printf("rule list %q saved: %d domain rules, %d ASNs, %d CIDRs\n", f.Name, len(f.Domains), len(f.ASNs), len(f.CIDRs))
	fmt.Println("attach it to a policy in the web UI (Policies → Edit → Rule lists)")
	return nil
}

func urlPath(s string) string {
	return strings.ReplaceAll(strings.ReplaceAll(s, "%", "%25"), " ", "%20")
}

func rulesExport(args []string) error {
	cfg, err := config.Load(paths().Config)
	if err != nil {
		return err
	}
	var text string
	if p := flagValue(args, "--policy"); p != "" {
		found := false
		for _, pol := range cfg.Policies {
			if pol.Name == p || fmt.Sprint(pol.ID) == p {
				text, found = api.ExportPolicy(cfg, pol, hasFlag(args, "--expand")), true
			}
		}
		if !found {
			return fmt.Errorf("no policy %q", p)
		}
	} else {
		if len(args) == 0 || strings.HasPrefix(args[0], "-") {
			return fmt.Errorf("%s", rulesUsage)
		}
		l, ok := cfg.List(args[0])
		if !ok {
			return fmt.Errorf("no rule list %q", args[0])
		}
		text = api.ExportList(l)
	}
	if out := flagValue(args, "-o"); out != "" {
		return os.WriteFile(out, []byte(text), 0o644)
	}
	fmt.Print(text)
	return nil
}
