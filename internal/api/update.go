package api

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/irisariuan/snake/internal/logx"
	"github.com/irisariuan/snake/internal/update"
)

func (s *Server) updateRoutes(mux *http.ServeMux) {
	// GET: cached check result; ?refresh=1 (or no check yet) asks GitHub.
	mux.HandleFunc("GET /api/update", func(w http.ResponseWriter, r *http.Request) {
		if s.U == nil {
			writeErr(w, 501, errors.New("updates are not available"))
			return
		}
		in := s.U.Info()
		if r.URL.Query().Get("refresh") == "1" || in.CheckedAt.IsZero() {
			ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
			defer cancel()
			in, _ = s.U.Check(ctx) // the error is in in.Error
		}
		writeJSON(w, in)
	})
	// Published releases, to install a chosen version.
	mux.HandleFunc("GET /api/update/releases", func(w http.ResponseWriter, r *http.Request) {
		if s.U == nil {
			writeErr(w, 501, errors.New("updates are not available"))
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
		defer cancel()
		rels, err := s.U.Releases(ctx)
		if err != nil {
			writeErr(w, 502, err)
			return
		}
		writeJSON(w, rels)
	})
	// Install the latest release, or ?version=vX.Y.Z.
	mux.HandleFunc("POST /api/update", func(w http.ResponseWriter, r *http.Request) {
		if s.U == nil {
			writeErr(w, 501, errors.New("updates are not available"))
			return
		}
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
		defer cancel()
		from := s.U.Current
		want := r.URL.Query().Get("version")
		var v string
		var err error
		if want != "" {
			v, err = s.U.InstallVersion(ctx, want)
		} else {
			v, err = s.U.Install(ctx)
		}
		if err != nil {
			writeErr(w, 500, err)
			return
		}
		logx.Infof("update: installed %s (was %s), restarting", v, from)
		s.pinVersion(v)
		s.restart(w, "updated", v)
	})
	mux.HandleFunc("POST /api/rollback", func(w http.ResponseWriter, r *http.Request) {
		if s.U == nil {
			writeErr(w, 501, errors.New("updates are not available"))
			return
		}
		v, err := s.U.Rollback()
		if err != nil {
			writeErr(w, 400, err)
			return
		}
		logx.Infof("rollback: installed %s (was %s), restarting", v, s.U.Current)
		s.pinVersion(v)
		s.restart(w, "rolled back", v)
	})
}

// pinVersion turns automatic updates off after an older version was
// installed on purpose: the next check would install the latest again.
func (s *Server) pinVersion(installed string) {
	if !update.Newer(s.U.Current, installed) {
		return
	}
	c := s.E.Config()
	if !c.Settings.AutoUpdate {
		return
	}
	c.Settings.AutoUpdate = false
	if err := s.E.SetConfig(c); err != nil {
		logx.Warnf("update: could not turn off automatic updates: %v", err)
		return
	}
	logx.Infof("update: automatic updates turned off (%s is older than %s)", installed, s.U.Current)
}

func (s *Server) restart(w http.ResponseWriter, result, version string) {
	if s.Restart != nil {
		if err := s.Restart(); err != nil {
			writeErr(w, 500, errors.New(result+" to "+version+", but restart failed: "+err.Error()+"; run: snake restart"))
			return
		}
	}
	writeJSON(w, map[string]string{"result": result, "version": version, "restart": "the daemon restarts in a few seconds"})
}
