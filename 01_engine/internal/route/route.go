// Package route follows a target's AS path round by round and reports when
// it changes (00_IDEA 4, C1 and C2; Paxson, SIGCOMM 1996). A round that only
// lacks or adds an AS is a hop that did or did not answer, not a change
// (rule R5): with the flow fixed, none of the 28 370 rounds of the second
// study rehearsal differed otherwise from its trace (evidence 2_115).
package route

import (
	"net/netip"
	"slices"
	"sync"
	"time"

	"github.com/rbn8080/tracertip/01_engine/internal/model"
)

// ConfirmRounds is how many rounds in a row must show a new path before the
// change is confirmed: 6 s at one round every 2 s. No single round of the
// rehearsal faked a change, so this is margin, not a measured need.
const ConfirmRounds = 3

// RTTWindow is how many rounds the RTT before a change summarises: one
// minute, the window of trace -watch.
const RTTWindow = 30

// Step is one probe of a round with the AS of its replier; ASN 0 means
// unknown, unrouted or special-purpose, and is left out of the path.
type Step struct {
	TTL    int
	Addr   netip.Addr // invalid: no reply
	ASN    int
	RTTms  float64 // negative: no reply
	Target bool    // the target itself answered
}

// PathOf is a round's AS path: known ASes in TTL order, repeats collapsed.
func PathOf(steps []Step) []int {
	var p []int
	for _, s := range steps {
		if s.ASN != 0 && (len(p) == 0 || p[len(p)-1] != s.ASN) {
			p = append(p, s.ASN)
		}
	}
	return p
}

// Same says whether two paths are the same route: equal, or one holding
// every AS of the other (a hop that did not answer, or answered this time).
func Same(a, b []int) bool {
	return within(a, b) || within(b, a)
}

func within(a, b []int) bool {
	for _, x := range a {
		if !slices.Contains(b, x) {
			return false
		}
	}
	return true
}

// Detector follows one target. It is not safe for concurrent use.
type Detector struct {
	target  netip.Addr
	path    []int     // the established path; nil until the first is confirmed
	rtts    []float64 // the target's RTT in the last RTTWindow rounds; negative: none
	cand    *candidate
	confirm int
}

type candidate struct {
	path   []int
	id     int64
	rounds int
	ttl    int
	before *float64
	after  *float64
}

// NewDetector follows target; confirm rounds in a row confirm a change.
func NewDetector(target netip.Addr, confirm int) *Detector {
	return &Detector{target: target, confirm: max(1, confirm)}
}

// Path is the established path.
func (d *Detector) Path() []int { return slices.Clone(d.path) }

// Round takes the next round and returns the events it causes. The first
// path is established silently once it has held for confirm rounds.
func (d *Detector) Round(n int, at time.Time, steps []Step) []model.Event {
	rtt := targetRTT(steps)
	defer func() {
		d.rtts = append(d.rtts, rtt)
		if len(d.rtts) > RTTWindow {
			d.rtts = d.rtts[1:]
		}
	}()
	p := PathOf(steps)
	if len(p) == 0 {
		return nil // nothing public answered: nothing to say about the route
	}
	var out []model.Event
	switch {
	case d.path != nil && Same(p, d.path):
		if len(p) > len(d.path) && within(d.path, p) {
			d.path = p // a fuller view of the same route
		}
		if c := d.cand; c != nil {
			d.cand = nil
			out = append(out, d.event(c, model.StateDropped, n, at))
		}
		return out
	case d.cand != nil && Same(p, d.cand.path):
		c := d.cand
		c.rounds++
		if len(p) > len(c.path) {
			c.path = p
		}
		c.after = minPtr(c.after, rtt)
	default:
		if c := d.cand; c != nil && d.path != nil {
			out = append(out, d.event(c, model.StateDropped, n, at))
		}
		d.cand = &candidate{path: p, id: at.UnixNano(), rounds: 1, ttl: firstNew(steps, d.path),
			before: minOf(d.rtts), after: minPtr(nil, rtt)}
		if d.path != nil {
			out = append(out, d.event(d.cand, model.StateProvisional, n, at))
		}
	}
	if c := d.cand; c.rounds >= d.confirm {
		if d.path != nil {
			out = append(out, d.event(c, model.StateConfirmed, n, at))
		}
		d.path, d.cand = c.path, nil
	}
	return out
}

func (d *Detector) event(c *candidate, state string, n int, at time.Time) model.Event {
	return model.Event{V: model.SchemaVersion, Type: model.TypeEvent, Time: at.UTC(), Target: d.target.String(),
		Kind: model.EventRouteChange, State: state, ID: c.id, Round: n, TTL: c.ttl,
		Before: slices.Clone(d.path), After: slices.Clone(c.path), RTTBeforeMS: c.before, RTTAfterMS: c.after}
}

// firstNew is the TTL of the first replier whose AS is not on the old path.
func firstNew(steps []Step, old []int) int {
	for _, s := range steps {
		if s.ASN != 0 && !slices.Contains(old, s.ASN) {
			return s.TTL
		}
	}
	return 0
}

func targetRTT(steps []Step) float64 {
	best := -1.0
	for _, s := range steps {
		if s.Target && s.RTTms >= 0 && (best < 0 || s.RTTms < best) {
			best = s.RTTms
		}
	}
	return best
}

func minOf(xs []float64) *float64 {
	var m *float64
	for _, x := range xs {
		m = minPtr(m, x)
	}
	return m
}

// minPtr keeps the smaller RTT; a negative one was not measured.
func minPtr(m *float64, x float64) *float64 {
	if x < 0 || (m != nil && *m <= x) {
		return m
	}
	return &x
}

// Log keeps the newest events in fixed memory, for every target.
type Log struct {
	mu  sync.Mutex
	buf []model.Event
	max int
}

// NewLog keeps up to n events.
func NewLog(n int) *Log { return &Log{max: n} }

// Add appends events, dropping the oldest beyond the limit.
func (l *Log) Add(evs ...model.Event) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.buf = append(l.buf, evs...)
	if over := len(l.buf) - l.max; over > 0 {
		l.buf = slices.Delete(l.buf, 0, over)
	}
}

// Last returns up to n of the newest events, oldest first.
func (l *Log) Last(n int) []model.Event {
	l.mu.Lock()
	defer l.mu.Unlock()
	return slices.Clone(l.buf[max(0, len(l.buf)-n):])
}
