package live

import (
	"context"
	"log/slog"
	"net/netip"
	"sync/atomic"
	"time"

	"github.com/rbn8080/tracertip/01_engine/internal/route"
)

// AnalyzerQueue is how many rounds may wait for the analyzer: one hour. A
// lookup in the AS bases takes about a second on the node and only happens
// for addresses not seen before, so the queue only fills if the bases hang.
const AnalyzerQueue = RingRounds

// Resolver gives the AS of each address (0: unknown or special-purpose).
type Resolver func(context.Context, []netip.Addr) (map[netip.Addr]int, error)

// Analyzer turns one monitor's rounds into route events, apart from the
// probing so a slow lookup never delays a probe.
type Analyzer struct {
	m       *Monitor
	det     *route.Detector
	in      chan Round
	resolve Resolver
	asn     map[netip.Addr]int
	events  *route.Log
	store   *Store
	log     *slog.Logger
	dropped atomic.Int64 // rounds lost because the queue was full
	path    atomic.Value // []int: the established path, for other goroutines
}

// NewAnalyzer follows m's target; its events go to the store and to events.
func NewAnalyzer(m *Monitor, resolve Resolver, events *route.Log, store *Store, log *slog.Logger) *Analyzer {
	return &Analyzer{m: m, det: route.NewDetector(m.Target, route.ConfirmRounds), in: make(chan Round, AnalyzerQueue),
		resolve: resolve, asn: map[netip.Addr]int{}, events: events, store: store, log: log}
}

// Feed queues a round without ever blocking the monitor.
func (a *Analyzer) Feed(r Round) {
	select {
	case a.in <- r:
	default:
		a.dropped.Add(1)
	}
}

// Dropped is how many rounds the analyzer never saw.
func (a *Analyzer) Dropped() int64 { return a.dropped.Load() }

// Run analyzes rounds until ctx ends. Bases that cannot be read stop it:
// events from a broken lookup would be false (P5).
func (a *Analyzer) Run(ctx context.Context) error {
	for {
		select {
		case <-ctx.Done():
			return nil
		case r := <-a.in:
			if err := a.round(ctx, r); err != nil {
				return err
			}
		}
	}
}

func (a *Analyzer) round(ctx context.Context, r Round) error {
	var fresh []netip.Addr
	for _, s := range r.Samples {
		if _, ok := a.asn[s.From]; s.From.IsValid() && !ok {
			fresh = append(fresh, s.From)
		}
	}
	if len(fresh) > 0 {
		got, err := a.resolve(ctx, fresh)
		if err != nil {
			return err
		}
		for _, addr := range fresh {
			a.asn[addr] = got[addr]
		}
	}
	steps := make([]route.Step, len(r.Samples))
	for i, s := range r.Samples {
		steps[i] = route.Step{TTL: s.TTL, Addr: s.From, ASN: a.asn[s.From], RTTms: s.RTTms, Target: s.From == r.Target}
	}
	evs := a.det.Round(r.N, r.Start, steps)
	a.path.Store(a.det.Path())
	if len(evs) == 0 {
		return nil
	}
	a.events.Add(evs...)
	recs := make([]any, len(evs))
	for i, e := range evs {
		recs[i] = e
		a.log.Info("route change", "target", e.Target, "state", e.State, "ttl", e.TTL, "before", e.Before, "after", e.After)
	}
	return a.store.Write(r.Target, time.Now(), a.m.Header, recs...) // each event keeps its round's time
}

// Path is the target's established AS path as of the last analyzed round.
func (a *Analyzer) Path() []int {
	p, _ := a.path.Load().([]int)
	return p
}
