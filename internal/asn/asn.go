// Package asn resolves autonomous system numbers to announced prefixes.
package asn

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"time"
)

// Cache stores prefixes per ASN on disk.
type Cache struct {
	Dir    string
	MaxAge time.Duration
	Client *http.Client
	// URL is a format string taking the ASN number.
	URL string
}

type entry struct {
	Fetched  time.Time `json:"fetched"`
	Prefixes []string  `json:"prefixes"`
}

// DefaultURL is RIPEstat's announced-prefixes endpoint.
const DefaultURL = "https://stat.ripe.net/data/announced-prefixes/data.json?resource=AS%d&sourceapp=snake-router"

func (c *Cache) path(n int) string { return filepath.Join(c.Dir, "AS"+strconv.Itoa(n)+".json") }

// Prefixes returns prefixes for an ASN, using the cache when fresh. On fetch
// failure a stale cache is returned with the error.
func (c *Cache) Prefixes(n int, force bool) ([]string, error) {
	var cached entry
	if b, err := os.ReadFile(c.path(n)); err == nil {
		_ = json.Unmarshal(b, &cached)
	}
	if !force && len(cached.Prefixes) > 0 && time.Since(cached.Fetched) < c.MaxAge {
		return cached.Prefixes, nil
	}
	p, err := c.fetch(n)
	if err != nil {
		if len(cached.Prefixes) > 0 {
			return cached.Prefixes, fmt.Errorf("AS%d refresh failed, using cache: %w", n, err)
		}
		return nil, fmt.Errorf("AS%d: %w", n, err)
	}
	_ = os.MkdirAll(c.Dir, 0o755)
	b, _ := json.Marshal(entry{Fetched: time.Now(), Prefixes: p})
	_ = os.WriteFile(c.path(n), b, 0o644)
	return p, nil
}

// Stale reports whether an ASN needs refreshing.
func (c *Cache) Stale(n int) bool {
	st, err := os.Stat(c.path(n))
	return err != nil || time.Since(st.ModTime()) > c.MaxAge
}

func (c *Cache) fetch(n int) ([]string, error) {
	cl := c.Client
	if cl == nil {
		cl = &http.Client{Timeout: 60 * time.Second}
	}
	u := c.URL
	if u == "" {
		u = DefaultURL
	}
	resp, err := cl.Get(fmt.Sprintf(u, n))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	return parseRIPE(io.LimitReader(resp.Body, 32<<20))
}

func parseRIPE(r io.Reader) ([]string, error) {
	var doc struct {
		Data struct {
			Prefixes []struct {
				Prefix string `json:"prefix"`
			} `json:"prefixes"`
		} `json:"data"`
	}
	if err := json.NewDecoder(r).Decode(&doc); err != nil {
		return nil, err
	}
	out := make([]string, 0, len(doc.Data.Prefixes))
	for _, p := range doc.Data.Prefixes {
		if p.Prefix != "" {
			out = append(out, p.Prefix)
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("no prefixes announced")
	}
	return out, nil
}
