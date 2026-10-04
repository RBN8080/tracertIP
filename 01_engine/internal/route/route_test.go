package route

import (
	"net/netip"
	"slices"
	"testing"
	"time"

	"github.com/rbn8080/tracertip/01_engine/internal/model"
)

var target = netip.MustParseAddr("192.0.2.99")

// round builds the steps of a round from the AS of each TTL (0: no reply),
// with the target answering last at rtt (negative: it did not answer).
func round(asns []int, rtt float64) []Step {
	var s []Step
	for i, a := range asns {
		st := Step{TTL: i + 1, ASN: a, RTTms: -1}
		if a != 0 {
			st.Addr, st.RTTms = netip.AddrFrom4([4]byte{192, 0, 2, byte(i + 1)}), float64(i+1)
		}
		s = append(s, st)
	}
	if rtt >= 0 {
		s = append(s, Step{TTL: len(asns) + 1, Addr: target, ASN: asns[len(asns)-1], RTTms: rtt, Target: true})
	}
	return s
}

type feed struct {
	asns []int
	rtt  float64
}

func run(d *Detector, rounds []feed) []model.Event {
	var out []model.Event
	at := time.Date(2026, 10, 4, 12, 0, 0, 0, time.UTC)
	for n, r := range rounds {
		out = append(out, d.Round(n, at.Add(time.Duration(n)*2*time.Second), round(r.asns, r.rtt))...)
	}
	return out
}

func states(evs []model.Event) []string {
	var s []string
	for _, e := range evs {
		s = append(s, e.State)
	}
	return s
}

var (
	pathA = []int{64496, 64497, 64500, 64510} // transit 64500
	pathB = []int{64496, 64497, 64501, 64510} // transit 64501
)

func TestDetector(t *testing.T) {
	a, b := feed{pathA, 97}, feed{pathB, 100}
	mute := feed{[]int{64496, 0, 64500, 64510}, 97} // 64497 did not answer
	for _, tc := range []struct {
		name   string
		rounds []feed
		want   []string
	}{
		{"the first path is set silently", []feed{a, a, a, a}, nil},
		{"a hop that does not answer is no change", []feed{a, a, a, mute, mute, a}, nil},
		{"a new transit is provisional, then confirmed", []feed{a, a, a, b, b, b, b}, []string{"provisional", "confirmed"}},
		{"one round of a new path is dropped", []feed{a, a, a, b, a, a}, []string{"provisional", "dropped"}},
		{"a new path while another is pending replaces it", []feed{a, a, a, b, {[]int{64496, 64502, 64510}, 99}, a},
			[]string{"provisional", "dropped", "provisional", "dropped"}},
		{"nothing public answered: no verdict", []feed{a, a, a, {[]int{0, 0}, -1}, a}, nil},
		{"a change before the first path is set is no event", []feed{a, b, b, b, b}, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := states(run(NewDetector(target, ConfirmRounds), tc.rounds))
			if !slices.Equal(got, tc.want) {
				t.Errorf("events %v, want %v", got, tc.want)
			}
		})
	}
}

// The records of one change share an id and carry where it happened, both
// paths, and the target's RTT before and after.
func TestConfirmedEvent(t *testing.T) {
	d := NewDetector(target, ConfirmRounds)
	evs := run(d, []feed{{pathA, 97.4}, {pathA, 96.9}, {pathA, 97.1}, {pathB, 100.2}, {pathB, 99.8}, {pathB, 100.5}})
	if len(evs) != 2 {
		t.Fatalf("events %+v", evs)
	}
	p, c := evs[0], evs[1]
	if p.ID != c.ID || p.ID == 0 || c.Round != 5 || p.Round != 3 || c.Target != target.String() {
		t.Errorf("provisional %+v confirmed %+v", p, c)
	}
	if !slices.Equal(c.Before, pathA) || !slices.Equal(c.After, pathB) || c.TTL != 3 {
		t.Errorf("confirmed before %v after %v at TTL %d, want %v, %v at TTL 3", c.Before, c.After, c.TTL, pathA, pathB)
	}
	if c.RTTBeforeMS == nil || *c.RTTBeforeMS != 96.9 || c.RTTAfterMS == nil || *c.RTTAfterMS != 99.8 {
		t.Errorf("RTT before %v after %v, want 96.9 and 99.8", c.RTTBeforeMS, c.RTTAfterMS)
	}
	if !slices.Equal(d.Path(), pathB) {
		t.Errorf("established path %v, want %v", d.Path(), pathB)
	}
}

// A target that never answered has no RTT: nil, never 0 (P5).
func TestEventWithoutTargetRTT(t *testing.T) {
	evs := run(NewDetector(target, 1), []feed{{pathA, -1}, {pathB, -1}})
	if len(evs) != 2 || evs[1].RTTBeforeMS != nil || evs[1].RTTAfterMS != nil {
		t.Errorf("events %+v", evs)
	}
}

func TestLogKeepsNewest(t *testing.T) {
	l := NewLog(2)
	l.Add(model.Event{ID: 1}, model.Event{ID: 2})
	l.Add(model.Event{ID: 3})
	got := l.Last(5)
	if len(got) != 2 || got[0].ID != 2 || got[1].ID != 3 {
		t.Errorf("log %+v", got)
	}
}
