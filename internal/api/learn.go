package api

import (
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"time"

	"github.com/irisariuan/snake/internal/learn"
)

func (s *Server) learnRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/learnings", s.listLearnings)
	mux.HandleFunc("POST /api/learnings", s.createLearning)
	mux.HandleFunc("PUT /api/learnings/{id}", s.updateLearning)
	mux.HandleFunc("DELETE /api/learnings/{id}", s.deleteLearning)
	mux.HandleFunc("POST /api/learnings/{id}/servers", s.editLearningServers)
	mux.HandleFunc("POST /api/learnings/{id}/move", s.moveLearningServers)
	mux.HandleFunc("POST /api/learnings/{id}/merge", s.mergeLearning)
}

type learningsResp struct {
	Groups     []learn.Group `json:"groups"`
	DefaultTTL int           `json:"default_ttl"`
}

func (s *Server) learnings(w http.ResponseWriter) {
	g, ttl := s.E.Learnings()
	writeJSON(w, learningsResp{Groups: g, DefaultTTL: ttl})
}

func (s *Server) listLearnings(w http.ResponseWriter, r *http.Request) { s.learnings(w) }

func decode(w http.ResponseWriter, r *http.Request, v any) bool {
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(v); err != nil {
		writeErr(w, 400, err)
		return false
	}
	return true
}

func groupID(w http.ResponseWriter, r *http.Request) (int, bool) {
	id, err := strconv.Atoi(r.PathValue("id"))
	if err != nil || id <= 0 {
		writeErr(w, 400, errors.New("bad group id"))
		return 0, false
	}
	return id, true
}

// edit runs fn and answers with the full list (404 for unknown groups).
func (s *Server) edit(w http.ResponseWriter, fn func(st *learn.Store) error) {
	if err := s.E.EditLearnings(fn); err != nil {
		code := 400
		if errors.Is(err, learn.ErrNotFound) {
			code = 404
		}
		writeErr(w, code, err)
		return
	}
	s.learnings(w)
}

func (s *Server) checkRoute(w http.ResponseWriter, p learn.Patch) bool {
	if p.RouteVia != nil && !s.E.ValidRouteVia(*p.RouteVia) {
		writeErr(w, 400, errors.New("route_via must be 0 (off) or an existing policy id"))
		return false
	}
	return true
}

type createReq struct {
	learn.Patch
	Servers []string `json:"servers"`
}

func (s *Server) createLearning(w http.ResponseWriter, r *http.Request) {
	var req createReq
	if !decode(w, r, &req) || !s.checkRoute(w, req.Patch) {
		return
	}
	s.edit(w, func(st *learn.Store) error {
		_, err := st.New(req.Patch, req.Servers, time.Now())
		return err
	})
}

func (s *Server) updateLearning(w http.ResponseWriter, r *http.Request) {
	id, ok := groupID(w, r)
	var p learn.Patch
	if !ok || !decode(w, r, &p) || !s.checkRoute(w, p) {
		return
	}
	s.edit(w, func(st *learn.Store) error { return st.Update(id, p) })
}

func (s *Server) deleteLearning(w http.ResponseWriter, r *http.Request) {
	id, ok := groupID(w, r)
	if !ok {
		return
	}
	s.edit(w, func(st *learn.Store) error { return st.Delete(id) })
}

type serversReq struct {
	Add    []string `json:"add"`
	Remove []string `json:"remove"`
}

func (s *Server) editLearningServers(w http.ResponseWriter, r *http.Request) {
	id, ok := groupID(w, r)
	var req serversReq
	if !ok || !decode(w, r, &req) {
		return
	}
	s.edit(w, func(st *learn.Store) error {
		if len(req.Remove) > 0 {
			if err := st.RemoveServers(id, req.Remove); err != nil {
				return err
			}
		}
		if len(req.Add) > 0 {
			return st.AddServers(id, req.Add, time.Now())
		}
		return nil
	})
}

type moveReq struct {
	Servers []string `json:"servers"`
	To      int      `json:"to"`
}

func (s *Server) moveLearningServers(w http.ResponseWriter, r *http.Request) {
	id, ok := groupID(w, r)
	var req moveReq
	if !ok || !decode(w, r, &req) {
		return
	}
	s.edit(w, func(st *learn.Store) error { return st.Move(id, req.Servers, req.To) })
}

type mergeReq struct {
	Into int `json:"into"`
}

func (s *Server) mergeLearning(w http.ResponseWriter, r *http.Request) {
	id, ok := groupID(w, r)
	var req mergeReq
	if !ok || !decode(w, r, &req) {
		return
	}
	s.edit(w, func(st *learn.Store) error { return st.Merge(id, req.Into) })
}
