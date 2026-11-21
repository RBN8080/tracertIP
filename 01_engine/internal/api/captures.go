package api

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/rbn8080/tracertip/01_engine/internal/ipdb"
)

type captureInfo struct {
	ID      string    `json:"id"`
	SavedAt time.Time `json:"saved_at"`
	Note    string    `json:"note,omitempty"`
	Node    string    `json:"node,omitempty"`
	Public  bool      `json:"public"`
	historyQuery
	Rounds int `json:"rounds"`
	Events int `json:"events"`
}

type capture struct {
	captureInfo
	History historyView `json:"history"`
}

var captureID = regexp.MustCompile(`^[A-Z2-7]{26,64}$`)

func (s *Server) createCapture(w http.ResponseWriter, r *http.Request) {
	if !sameOrigin(w, r, true) {
		return
	}
	var q struct {
		historyQuery
		Note string `json:"note"`
	}
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 8<<10))
	if err := dec.Decode(&q); err != nil || dec.Decode(new(any)) != io.EOF {
		fail(w, http.StatusBadRequest, "send one JSON object with target, from and to")
		return
	}
	q.Note = strings.TrimSpace(q.Note)
	if utf8.RuneCountInString(q.Note) > 300 {
		fail(w, http.StatusBadRequest, "note must be 300 characters or shorter")
		return
	}
	if public(r) && q.Note != "" {
		fail(w, http.StatusBadRequest, "notes are available in private captures")
		return
	}
	view, ok := s.loadHistory(w, r, q.historyQuery)
	if !ok {
		return
	}
	if len(view.Rounds)+len(view.Events) == 0 {
		fail(w, http.StatusUnprocessableEntity, "there are no measurements or events in this interval")
		return
	}
	info := captureInfo{
		ID: rand.Text(), SavedAt: time.Now().UTC(), Note: q.Note, Node: view.Node, Public: view.Public,
		historyQuery: view.historyQuery, Rounds: len(view.Rounds), Events: len(view.Events),
	}
	if err := saveCapture(r.Context(), s.cfg.Store.CapturesDir(), capture{captureInfo: info, History: view}); err != nil {
		fail(w, http.StatusServiceUnavailable, "could not store the capture")
		return
	}
	w.Header().Set("Location", "/v1/captures/"+info.ID)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(info)
}

func saveCapture(ctx context.Context, dir string, c capture) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	f, err := os.CreateTemp(dir, ".capture-*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	defer f.Close()
	enc := json.NewEncoder(f)
	if err := enc.Encode(c.captureInfo); err != nil {
		return err
	}
	if err := enc.Encode(c.History); err != nil {
		return err
	}
	if err := errors.Join(f.Sync(), f.Close(), ctx.Err()); err != nil {
		return err
	}
	if err := ipdb.SyncDir(filepath.Dir(dir)); err != nil {
		return err
	}
	if err := os.Rename(f.Name(), filepath.Join(dir, c.ID+".capture")); err != nil {
		return err
	}
	return ipdb.SyncDir(dir)
}

func captureFile(dir, id string, withHistory, pub bool) (capture, error) {
	if !captureID.MatchString(id) {
		return capture{}, fs.ErrNotExist
	}
	f, err := os.Open(filepath.Join(dir, id+".capture"))
	if err != nil {
		return capture{}, err
	}
	defer f.Close()
	var c capture
	dec := json.NewDecoder(f)
	if err := dec.Decode(&c.captureInfo); err != nil {
		return capture{}, err
	}
	if c.ID != id || pub && !c.Public {
		return capture{}, fs.ErrNotExist
	}
	if withHistory {
		if err := dec.Decode(&c.History); err != nil {
			return capture{}, err
		}
	}
	return c, nil
}

func (s *Server) captures(w http.ResponseWriter, r *http.Request) {
	dir := s.cfg.Store.CapturesDir()
	files, err := os.ReadDir(dir)
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		fail(w, http.StatusServiceUnavailable, "could not list captures")
		return
	}
	var infos []captureInfo
	for _, f := range files {
		id, ok := strings.CutSuffix(f.Name(), ".capture")
		if !ok || !f.Type().IsRegular() {
			continue
		}
		c, err := captureFile(dir, id, false, public(r))
		switch {
		case err == nil:
			infos = append(infos, c.captureInfo)
		case !errors.Is(err, fs.ErrNotExist):
			fail(w, http.StatusServiceUnavailable, "could not read a saved capture")
			return
		}
	}
	slices.SortFunc(infos, func(a, b captureInfo) int { return b.SavedAt.Compare(a.SavedAt) })
	writeJSON(w, list(infos))
}

func (s *Server) requestedCapture(w http.ResponseWriter, r *http.Request) (capture, bool) {
	c, err := captureFile(s.cfg.Store.CapturesDir(), r.PathValue("id"), true, public(r))
	switch {
	case errors.Is(err, fs.ErrNotExist):
		fail(w, http.StatusNotFound, "no saved capture with that ID")
	case err != nil:
		fail(w, http.StatusServiceUnavailable, "could not read the capture")
	}
	return c, err == nil
}

func (s *Server) getCapture(w http.ResponseWriter, r *http.Request) {
	if c, ok := s.requestedCapture(w, r); ok {
		writeJSON(w, c)
	}
}
