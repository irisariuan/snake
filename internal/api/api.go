// Package api serves snake's JSON API and the standalone web UI.
package api

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/irisariuan/snake/internal/config"
	"github.com/irisariuan/snake/internal/engine"
	"github.com/irisariuan/snake/internal/importdvr"
	"github.com/irisariuan/snake/internal/logx"
	"github.com/irisariuan/snake/internal/webui"
)

// Server is the API server.
type Server struct {
	E     *engine.Engine
	Token string
}

// LoadToken reads or creates the API token.
func LoadToken(path string, rotate bool) (string, error) {
	if !rotate {
		if b, err := os.ReadFile(path); err == nil && len(strings.TrimSpace(string(b))) >= 32 {
			return strings.TrimSpace(string(b)), nil
		}
	}
	buf := make([]byte, 24)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	tok := hex.EncodeToString(buf)
	if err := os.WriteFile(path, []byte(tok+"\n"), 0o600); err != nil {
		return "", err
	}
	return tok, nil
}

// PublishToken writes the token into Merlin's custom_settings.txt so the
// Addons page (served behind the router login) can read it.
func PublishToken(customSettings, token string) error {
	b, _ := os.ReadFile(customSettings)
	var lines []string
	for _, l := range strings.Split(string(b), "\n") {
		if l == "" || strings.HasPrefix(l, "snake_token ") {
			continue
		}
		lines = append(lines, l)
	}
	lines = append(lines, "snake_token "+token)
	return os.WriteFile(customSettings, []byte(strings.Join(lines, "\n")+"\n"), 0o644)
}

func (s *Server) routes(authed bool) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/status", func(w http.ResponseWriter, r *http.Request) { writeJSON(w, s.E.Status()) })
	mux.HandleFunc("GET /api/config", func(w http.ResponseWriter, r *http.Request) { writeJSON(w, s.E.Config()) })
	mux.HandleFunc("PUT /api/config", s.putConfig)
	mux.HandleFunc("POST /api/apply", func(w http.ResponseWriter, r *http.Request) {
		if err := s.E.Apply("manual"); err != nil {
			writeErr(w, 500, err)
			return
		}
		writeJSON(w, map[string]string{"result": "applied"})
	})
	mux.HandleFunc("POST /api/reload", func(w http.ResponseWriter, r *http.Request) {
		if err := s.E.Load(); err != nil {
			writeErr(w, 400, err)
			return
		}
		s.E.Kick()
		if err := s.E.Apply("reload"); err != nil {
			writeErr(w, 500, err)
			return
		}
		writeJSON(w, map[string]string{"result": "reloaded"})
	})
	mux.HandleFunc("POST /api/recheck", func(w http.ResponseWriter, r *http.Request) {
		s.E.Kick()
		writeJSON(w, map[string]string{"result": "scheduled"})
	})
	mux.HandleFunc("GET /api/test", func(w http.ResponseWriter, r *http.Request) {
		d := r.URL.Query().Get("domain")
		if d == "" {
			writeErr(w, 400, errors.New("domain required"))
			return
		}
		writeJSON(w, s.E.TestDomain(d))
	})
	mux.HandleFunc("GET /api/set", func(w http.ResponseWriter, r *http.Request) {
		limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
		if limit <= 0 || limit > 5000 {
			limit = 500
		}
		m, err := s.E.SetMembers(r.URL.Query().Get("name"), limit)
		if err != nil {
			writeErr(w, 400, err)
			return
		}
		writeJSON(w, map[string]any{"members": m})
	})
	mux.HandleFunc("POST /api/policies/{id}/flush", func(w http.ResponseWriter, r *http.Request) {
		id, err := strconv.Atoi(r.PathValue("id"))
		if err != nil {
			writeErr(w, 400, err)
			return
		}
		s.E.FlushLearned(id)
		writeJSON(w, map[string]string{"result": "flushed"})
	})
	mux.HandleFunc("GET /api/clients", func(w http.ResponseWriter, r *http.Request) { writeJSON(w, engine.Clients()) })
	mux.HandleFunc("GET /api/leaks", func(w http.ResponseWriter, r *http.Request) { writeJSON(w, s.E.LeakChecks()) })
	mux.HandleFunc("GET /api/logs", func(w http.ResponseWriter, r *http.Request) { writeJSON(w, logx.Recent()) })
	s.ruleRoutes(mux)
	mux.HandleFunc("GET /api/plan", func(w http.ResponseWriter, r *http.Request) { writeJSON(w, s.E.Plan()) })
	mux.HandleFunc("POST /api/import-dvr", s.importDVR)
	mux.HandleFunc("GET /", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		_, _ = w.Write(webui.Standalone())
	})
	if !authed {
		return mux
	}
	return s.auth(mux)
}

func (s *Server) auth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "SAMEORIGIN")
		if o := r.Header.Get("Origin"); o != "" && sameHost(o, r.Host) {
			w.Header().Set("Access-Control-Allow-Origin", o)
			w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type")
			w.Header().Set("Access-Control-Allow-Methods", "GET, PUT, POST, OPTIONS")
			w.Header().Set("Access-Control-Max-Age", "600")
			w.Header().Set("Vary", "Origin")
		}
		if r.Method == http.MethodOptions {
			w.WriteHeader(204)
			return
		}
		if r.URL.Path == "/" {
			next.ServeHTTP(w, r)
			return
		}
		tok := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		if subtle.ConstantTimeCompare([]byte(tok), []byte(s.Token)) != 1 {
			writeErr(w, 401, errors.New("unauthorized"))
			return
		}
		next.ServeHTTP(w, r)
	})
}

func sameHost(origin, host string) bool {
	u, err := url.Parse(origin)
	if err != nil {
		return false
	}
	h := host
	if hh, _, err := net.SplitHostPort(host); err == nil {
		h = hh
	}
	return strings.EqualFold(u.Hostname(), h)
}

func (s *Server) putConfig(w http.ResponseWriter, r *http.Request) {
	var c config.Config
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4<<20))
	if err := dec.Decode(&c); err != nil {
		writeErr(w, 400, err)
		return
	}
	if err := s.E.SetConfig(&c); err != nil {
		writeErr(w, 400, err)
		return
	}
	writeJSON(w, s.E.Config())
}

func (s *Server) importDVR(w http.ResponseWriter, r *http.Request) {
	dir := r.URL.Query().Get("dir")
	if dir == "" {
		dir = importdvr.DefaultDir
	}
	res, err := importdvr.Read(dir)
	if err != nil {
		writeErr(w, 400, err)
		return
	}
	if r.URL.Query().Get("apply") != "1" {
		writeJSON(w, res)
		return
	}
	c := s.E.Config()
	importdvr.Merge(c, res.Policies)
	if err := s.E.SetConfig(c); err != nil {
		writeErr(w, 400, err)
		return
	}
	writeJSON(w, res)
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, code int, err error) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
}

// Serve runs the unix socket (CLI, no auth; root-only) and the LAN listeners.
func (s *Server) Serve(ctx context.Context, socket, lanIP string, port int) error {
	_ = os.Remove(socket)
	ul, err := net.Listen("unix", socket)
	if err != nil {
		return err
	}
	_ = os.Chmod(socket, 0o600)
	servers := []*http.Server{{Handler: s.routes(false), ReadHeaderTimeout: 10 * time.Second}}
	go func() { _ = servers[0].Serve(ul) }()

	if lanIP == "" {
		lanIP = "127.0.0.1"
	}
	addr := net.JoinHostPort(lanIP, strconv.Itoa(port))
	hs := &http.Server{Addr: addr, Handler: s.routes(true), ReadHeaderTimeout: 10 * time.Second}
	servers = append(servers, hs)
	go func() {
		if err := hs.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			logx.Errorf("api http %s: %v", addr, err)
		}
	}()
	logx.Infof("api listening on http://%s", addr)

	// HTTPS with the router's own certificate, for WebUIs served over HTTPS
	// (browsers block mixed content).
	cert, key := "/etc/cert.pem", "/etc/key.pem"
	if _, err := os.Stat(cert); err == nil {
		taddr := net.JoinHostPort(lanIP, strconv.Itoa(port+1))
		ts := &http.Server{Addr: taddr, Handler: s.routes(true), ReadHeaderTimeout: 10 * time.Second,
			TLSConfig: &tls.Config{MinVersion: tls.VersionTLS12}}
		servers = append(servers, ts)
		go func() {
			if err := ts.ListenAndServeTLS(cert, key); err != nil && !errors.Is(err, http.ErrServerClosed) {
				logx.Errorf("api https %s: %v", taddr, err)
			}
		}()
		logx.Infof("api listening on https://%s", taddr)
	}
	<-ctx.Done()
	sctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	for _, srv := range servers {
		_ = srv.Shutdown(sctx)
	}
	_ = os.Remove(socket)
	return nil
}
