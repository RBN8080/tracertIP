package api

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"slices"
	"time"

	"github.com/rbn8080/tracertip/01_engine/internal/live"
)

const maxHistoryRange = time.Hour

type historyQuery struct {
	Target string    `json:"target"`
	From   time.Time `json:"from"`
	To     time.Time `json:"to"`
}

type historyView struct {
	historyQuery
	Node   string           `json:"node,omitempty"`
	Public bool             `json:"public"`
	Rounds []roundView      `json:"rounds"`
	Events []routeEventView `json:"events"`
}

func (q historyQuery) validate() (netip.Addr, error) {
	a, err := netip.ParseAddr(q.Target)
	if err != nil || a.Zone() != "" {
		return netip.Addr{}, errors.New("target must be an IPv4 or IPv6 address")
	}
	if q.From.IsZero() || !q.To.After(q.From) || q.To.Sub(q.From) > maxHistoryRange {
		return netip.Addr{}, errors.New("select an interval of more than zero and at most 60 minutes")
	}
	return a.Unmap(), nil
}

func (s *Server) historyTargets(w http.ResponseWriter, r *http.Request) {
	targets, err := s.cfg.Store.HistoryTargets()
	if err == nil && public(r) && s.cfg.ResolveHistory != nil {
		_, err = s.cfg.ResolveHistory(r.Context(), targets)
	}
	if err != nil {
		fail(w, http.StatusServiceUnavailable, "could not list history")
		return
	}
	var addresses []string
	for _, target := range targets {
		if a := s.addr(target, public(r)); a != "" {
			addresses = append(addresses, a)
		}
	}
	writeJSON(w, list(addresses))
}

func (s *Server) history(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	from, e1 := time.Parse(time.RFC3339Nano, q.Get("from"))
	to, e2 := time.Parse(time.RFC3339Nano, q.Get("to"))
	if e1 != nil || e2 != nil {
		fail(w, http.StatusBadRequest, "from and to must be timestamps with a time zone")
		return
	}
	if view, ok := s.loadHistory(w, r, historyQuery{Target: q.Get("target"), From: from, To: to}); ok {
		writeJSON(w, view)
	}
}

func (s *Server) loadHistory(w http.ResponseWriter, r *http.Request, q historyQuery) (historyView, bool) {
	target, err := q.validate()
	if err != nil {
		fail(w, http.StatusBadRequest, err.Error())
		return historyView{}, false
	}
	select {
	case s.historyReads <- struct{}{}:
		defer func() { <-s.historyReads }()
	default:
		fail(w, http.StatusTooManyRequests, "history is busy; retry in a few seconds")
		return historyView{}, false
	}

	q.Target, q.From, q.To = target.String(), q.From.UTC(), q.To.UTC()
	pub := public(r)
	if pub && s.cfg.ResolveHistory != nil {
		if _, err = s.cfg.ResolveHistory(r.Context(), []netip.Addr{target}); err != nil {
			fail(w, http.StatusServiceUnavailable, "could not prepare public history")
			return historyView{}, false
		}
	}
	if s.addr(target, pub) == "" {
		fail(w, http.StatusNotFound, "history unavailable for this target")
		return historyView{}, false
	}
	data, err := s.cfg.Store.ReadHistory(r.Context(), target, q.From, q.To)
	if err == nil && pub {
		err = s.resolveHistoryHops(r.Context(), data.Rounds)
	}
	if err != nil {
		fail(w, http.StatusServiceUnavailable, "could not read history")
		return historyView{}, false
	}

	out := historyView{
		historyQuery: q, Public: pub,
		Rounds: make([]roundView, 0, len(data.Rounds)), Events: make([]routeEventView, 0, len(data.Events)),
	}
	if !pub {
		out.Node = s.cfg.NodeName
	}
	for _, round := range data.Rounds {
		out.Rounds = append(out.Rounds, s.roundView(round, pub))
	}
	for _, event := range data.Events {
		event.Target = q.Target
		out.Events = append(out.Events, s.eventView(event, pub))
	}
	return out, true
}

func (s *Server) resolveHistoryHops(ctx context.Context, rounds []live.Round) error {
	if s.cfg.ResolveHistory == nil {
		return nil
	}
	seen := make(map[netip.Addr]bool)
	for _, r := range rounds {
		for _, hop := range r.Samples {
			if hop.From.IsValid() {
				seen[hop.From] = true
			}
		}
	}
	addrs := make([]netip.Addr, 0, len(seen))
	for a := range seen {
		addrs = append(addrs, a)
	}
	slices.SortFunc(addrs, netip.Addr.Compare)
	if _, err := s.cfg.ResolveHistory(ctx, addrs); err != nil {
		return fmt.Errorf("resolve historical hops: %w", err)
	}
	return nil
}
