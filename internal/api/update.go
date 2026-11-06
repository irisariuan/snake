package api

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/irisariuan/snake/internal/logx"
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
	mux.HandleFunc("POST /api/update", func(w http.ResponseWriter, r *http.Request) {
		if s.U == nil {
			writeErr(w, 501, errors.New("updates are not available"))
			return
		}
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
		defer cancel()
		from := s.U.Current
		v, err := s.U.Install(ctx)
		if err != nil {
			writeErr(w, 500, err)
			return
		}
		logx.Infof("update: installed %s (was %s), restarting", v, from)
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
		s.restart(w, "rolled back", v)
	})
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
