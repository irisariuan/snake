package api

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/irisariuan/snake/internal/config"
	"github.com/irisariuan/snake/internal/match"
	"github.com/irisariuan/snake/internal/rulefile"
)

const maxRuleFile = 4 << 20

func (s *Server) ruleRoutes(mux *http.ServeMux) {
	mux.HandleFunc("POST /api/rulefile/parse", s.parseRuleFile)
	mux.HandleFunc("POST /api/rulefile/fetch", s.fetchRuleFile)
	mux.HandleFunc("GET /api/rulefile/export", s.exportRuleFile)
	mux.HandleFunc("PUT /api/lists/{name}", s.putList)
	mux.HandleFunc("DELETE /api/lists/{name}", s.deleteList)
	mux.HandleFunc("POST /api/lists/{name}/refresh", s.refreshList)
}

type parseReq struct {
	Text    string `json:"text"`
	Convert bool   `json:"convert"`
	Name    string `json:"name"` // optional: test this name against the rules
}

// parseRuleFile validates rule-file text for the editor: per-line errors,
// counts, the canonical form and an optional match test.
func (s *Server) parseRuleFile(w http.ResponseWriter, r *http.Request) {
	var req parseReq
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxRuleFile)).Decode(&req); err != nil {
		writeErr(w, 400, err)
		return
	}
	res := rulefile.Parse(req.Text, req.Convert)
	set := match.MustCompile(res.File.Domains)
	kinds := map[string]int{}
	for _, d := range res.File.Domains {
		if match.IsRoute(d) {
			if rt, err := match.ParseRoute(d); err == nil && rt.If != nil {
				kinds["conditional"]++
			} else {
				kinds["route"]++
			}
			continue
		}
		if p, err := match.Parse(d); err == nil && match.StripComment(d) != "" {
			k := string(p.Kind)
			if p.Negate {
				k = "!" + k
			}
			if p.Drop {
				k = "drop " + k
			}
			if p.Session {
				k = "session " + k
			}
			kinds[k]++
		}
	}
	out := map[string]any{
		"file": res.File, "errors": res.Errors, "warnings": res.Warnings, "converted": res.Converted,
		"kinds": kinds, "inspector": set.NeedsInspector(),
	}
	if len(res.Errors) == 0 {
		out["formatted"] = rulefile.Format(res.File)
	}
	if req.Name != "" {
		out["result"] = set.MatchAny(match.Normalize(req.Name))
	}
	writeJSON(w, out)
}

// fetchRuleFile downloads a rule list through the router.
func (s *Server) fetchRuleFile(w http.ResponseWriter, r *http.Request) {
	var req struct {
		URL string `json:"url"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&req); err != nil {
		writeErr(w, 400, err)
		return
	}
	text, err := FetchRules(req.URL)
	if err != nil {
		writeErr(w, 400, err)
		return
	}
	writeJSON(w, map[string]string{"text": text})
}

// FetchRules downloads a rule file over HTTP(S).
func FetchRules(raw string) (string, error) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return "", errors.New("URL must be http:// or https://")
	}
	cl := &http.Client{Timeout: 30 * time.Second}
	req, _ := http.NewRequest("GET", u.String(), nil)
	req.Header.Set("User-Agent", "snake-router/1")
	resp, err := cl.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return "", fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, maxRuleFile+1))
	if err != nil {
		return "", err
	}
	if len(b) > maxRuleFile {
		return "", errors.New("file larger than 4 MB")
	}
	return string(b), nil
}

// ExportList renders a rule list.
func ExportList(l config.RuleList) string {
	return rulefile.Format(rulefile.File{Name: l.Name, Description: l.Description, Source: l.Source, Domains: l.Domains, ASNs: l.ASNs, CIDRs: l.CIDRs})
}

// ExportPolicy renders a policy's rules; expand also inlines its rule lists.
func ExportPolicy(c *config.Config, p config.Policy, expand bool) string {
	if expand {
		p = c.Expand(p)
	}
	f := rulefile.File{Name: p.Name, Domains: p.Domains, ASNs: p.ASNs, CIDRs: p.CIDRs}
	out := rulefile.Format(f)
	if !expand && len(p.Lists) > 0 {
		out += "\n# also uses rule lists: " + strings.Join(p.Lists, ", ") + "\n"
	}
	return out
}

func (s *Server) exportRuleFile(w http.ResponseWriter, r *http.Request) {
	c := s.E.Config()
	q := r.URL.Query()
	var text, name string
	switch {
	case q.Get("list") != "":
		l, ok := c.List(q.Get("list"))
		if !ok {
			writeErr(w, 404, errors.New("no such rule list"))
			return
		}
		text, name = ExportList(l), l.Name
	case q.Get("policy") != "":
		id, _ := strconv.Atoi(q.Get("policy"))
		found := false
		for _, p := range c.Policies {
			if p.ID == id || p.Name == q.Get("policy") {
				text, name, found = ExportPolicy(c, p, q.Get("expand") == "1"), p.Name, true
				break
			}
		}
		if !found {
			writeErr(w, 404, errors.New("no such policy"))
			return
		}
	default:
		writeErr(w, 400, errors.New("list or policy required"))
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", FileName(name)))
	_, _ = io.WriteString(w, text)
}

// FileName turns a list name into a safe file name.
func FileName(name string) string {
	f := strings.Map(func(r rune) rune {
		if r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-' || r == '_' || r == '.' {
			return r
		}
		return '_'
	}, name)
	if f == "" {
		f = "rules"
	}
	return f + ".rules"
}

// SaveList parses text and creates or replaces the rule list called orig
// (renaming it, and every policy reference, when the text's @name differs).
func SaveList(c *config.Config, orig, text string, convert bool) (rulefile.Result, error) {
	res := rulefile.Parse(text, convert)
	if len(res.Errors) > 0 {
		var msgs []string
		for _, e := range res.Errors {
			msgs = append(msgs, fmt.Sprintf("line %d: %s", e.Line, e.Message))
		}
		return res, errors.New(strings.Join(msgs, "; "))
	}
	f := res.File
	if f.Name == "" {
		f.Name = orig
	}
	if f.Name == "" {
		return res, errors.New("the list needs a name (@name ...)")
	}
	nl := config.RuleList{Name: f.Name, Description: f.Description, Source: f.Source, Domains: f.Domains, ASNs: f.ASNs, CIDRs: f.CIDRs}
	replaced := false
	for i, l := range c.RuleLists {
		if l.Name == orig && orig != "" {
			c.RuleLists[i] = nl
			replaced = true
		} else if l.Name == f.Name {
			return res, fmt.Errorf("a rule list named %q already exists", f.Name)
		}
	}
	if !replaced {
		c.RuleLists = append(c.RuleLists, nl)
	}
	if orig != "" && orig != f.Name {
		for i := range c.Policies {
			for j, n := range c.Policies[i].Lists {
				if n == orig {
					c.Policies[i].Lists[j] = f.Name
				}
			}
		}
	}
	return res, nil
}

func (s *Server) putList(w http.ResponseWriter, r *http.Request) {
	var req parseReq
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxRuleFile)).Decode(&req); err != nil {
		writeErr(w, 400, err)
		return
	}
	orig := r.PathValue("name")
	if r.URL.Query().Get("new") == "1" {
		orig = ""
	}
	var res rulefile.Result
	c, err := s.E.UpdateConfig(func(c *config.Config) error {
		var err error
		res, err = SaveList(c, orig, req.Text, req.Convert)
		return err
	})
	if err != nil {
		writeErr(w, 400, err)
		return
	}
	writeJSON(w, map[string]any{"config": c, "warnings": res.Warnings, "converted": res.Converted})
}

func (s *Server) deleteList(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	c, err := s.E.UpdateConfig(func(c *config.Config) error {
		var users []string
		for _, p := range c.Policies {
			for _, n := range p.Lists {
				if n == name {
					users = append(users, p.Name)
				}
			}
		}
		if len(users) > 0 {
			return fmt.Errorf("rule list %q is used by: %s", name, strings.Join(users, ", "))
		}
		out := c.RuleLists[:0]
		for _, l := range c.RuleLists {
			if l.Name != name {
				out = append(out, l)
			}
		}
		c.RuleLists = out
		return nil
	})
	if err != nil {
		writeErr(w, 400, err)
		return
	}
	writeJSON(w, map[string]any{"config": c})
}

// refreshList re-downloads a list from its @source.
func (s *Server) refreshList(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	l, ok := s.E.Config().List(name)
	if !ok || l.Source == "" {
		writeErr(w, 400, errors.New("list not found or has no @source"))
		return
	}
	text, err := FetchRules(l.Source)
	if err != nil {
		writeErr(w, 400, err)
		return
	}
	var res rulefile.Result
	c, err := s.E.UpdateConfig(func(c *config.Config) error {
		res = rulefile.Parse(text, true)
		// Keep our name and source even if the remote file says otherwise.
		f := res.File
		f.Name, f.Source = name, l.Source
		if f.Description == "" {
			f.Description = l.Description
		}
		var err error
		res, err = SaveList(c, name, rulefile.Format(f), false)
		return err
	})
	if err != nil {
		writeErr(w, 400, err)
		return
	}
	writeJSON(w, map[string]any{"config": c, "warnings": res.Warnings})
}
