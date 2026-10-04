package batch

import (
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/rbn8080/tracertip/01_engine/internal/targets"
)

func TestSlot(t *testing.T) {
	every := 30 * time.Minute
	a, fa := Slot(time.Date(2026, 9, 29, 9, 12, 0, 0, time.UTC), every)
	b, fb := Slot(time.Date(2026, 9, 29, 9, 44, 0, 0, time.UTC), every)
	if !a.Equal(time.Date(2026, 9, 29, 9, 0, 0, 0, time.UTC)) || !b.Equal(a.Add(every)) {
		t.Errorf("slots %s, %s", a, b)
	}
	if fa == fb {
		t.Errorf("consecutive slots share family %s", fa)
	}
	if _, fc := Slot(a.Add(2*every), every); fc != fa {
		t.Error("families do not alternate")
	}
}

// Four slots: one valid, one run without NTP time, one cut short, one gap.
func TestReport(t *testing.T) {
	dir := t.TempDir()
	every := 30 * time.Minute
	s0 := time.Date(2026, 9, 29, 0, 0, 0, 0, time.UTC)
	write := func(slot time.Time, fam string, synced, finish bool) {
		r, err := CreateRun(filepath.Join(dir, "runs"), slot, fam)
		if err != nil {
			t.Fatal(err)
		}
		r.Write(map[string]any{"v": 1, "type": "run", "slot": slot, "engine": "e1", "clock_synced": synced,
			"temp_c": 81.5, "disk_free_mb": 900, "targets": 2})
		if !finish {
			r.Abort()
			return
		}
		r.Write(map[string]any{"v": 1, "type": "run_end", "traced": 2, "unmeasured": 1})
		r.Close()
	}
	write(s0, V4, true, true)
	write(s0.Add(every), V6, false, true)
	write(s0.Add(2*every), V4, true, false)
	sum, err := Report(dir, every, s0.Add(3*every))
	if err != nil {
		t.Fatal(err)
	}
	if len(sum.Days) != 1 {
		t.Fatalf("days %+v", sum.Days)
	}
	d := sum.Days[0]
	if d.Slots != 4 || d.Complete != 1 || d.NoClock != 1 || d.Incomplete != 1 || d.Gaps != 1 || d.Hot != 3 || d.MinDiskMB != 900 || d.Unmeasured != 2 || d.Dark != 2 {
		t.Errorf("day %+v", d)
	}
	if len(sum.Engines) != 1 || sum.Engines[0] != "e1" {
		t.Errorf("engines %v", sum.Engines)
	}
}

func entry(id int, cont, role string) targets.Target {
	return targets.Target{Anchor: targets.Anchor{ID: id, IPv4: netip.MustParseAddr("192.0.2.1"), IPv6: netip.MustParseAddr("2001:db8::1")},
		Continent: cont, Role: role, Checks: []targets.Check{{Name: "all", OK: true}}}
}

func TestReplacement(t *testing.T) {
	failed := entry(4, "EU", targets.RoleStudy)
	failed.Checks = append(failed.Checks, targets.Check{Name: "reach-v6", OK: false})
	s, err := NewState([]targets.Target{entry(1, "EU", targets.RoleStudy), entry(2, "EU", targets.RoleReserve),
		failed, {Role: targets.RoleFixed, Anchor: targets.Anchor{IPv4: netip.MustParseAddr("198.51.100.1")}}})
	if err != nil {
		t.Fatal(err)
	}
	if len(s.Active) != 2 || len(s.Reserve["EU"]) != 1 {
		t.Fatalf("active %d, reserve %d: a failed candidate got in", len(s.Active), len(s.Reserve["EU"]))
	}
	now := time.Now()
	for i := range s.FailLimit - 1 {
		if r := s.Result(0, V6, false, now); r != nil {
			t.Fatalf("replaced after %d misses", i+1)
		}
	}
	s.Result(0, V4, true, now) // the other family does not reset the count
	r := s.Result(0, V6, false, now)
	if r == nil || r.In == nil || r.In.ID != 2 || s.Active[0].ID != 2 || s.Active[0].Role != targets.RoleStudy {
		t.Fatalf("replacement %+v, active %+v", r, s.Active[0])
	}
	for range s.FailLimit {
		s.Result(0, V4, false, now)
	}
	if len(s.Active) != 1 || s.Active[0].Role != targets.RoleFixed {
		t.Errorf("with the reserve spent, the target leaves: %+v", s.Active)
	}
	for range 2 * s.FailLimit {
		if s.Result(0, V4, false, now) != nil {
			t.Fatal("a fixed target was replaced")
		}
	}
}

func TestRunFileAndState(t *testing.T) {
	dir := t.TempDir()
	slot := time.Date(2026, 9, 29, 9, 30, 0, 0, time.UTC)
	r, err := CreateRun(dir, slot, V6)
	if err != nil {
		t.Fatal(err)
	}
	if err := r.Write(map[string]int{"v": 1}); err != nil {
		t.Fatal(err)
	}
	final := filepath.Join(dir, "2026-09-29", "0930Z-v6.jsonl")
	if _, err := os.Stat(final + ".partial"); err != nil {
		t.Fatal("no partial file while running")
	}
	if err := r.Abort(); err != nil { // a restart in the middle of the run
		t.Fatal(err)
	}
	if r, err = CreateRun(dir, slot, V6); err != nil {
		t.Fatal(err)
	}
	if err := r.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(final); err != nil {
		t.Fatal("no final file after closing")
	}
	if cut, _ := filepath.Glob(final + ".aborted-*"); len(cut) != 1 {
		t.Errorf("the cut run was not kept apart: %v", cut)
	}

	s := &State{Active: []Entry{{ID: 7, Role: targets.RoleStudy}}, Fails: map[string]int{"7/v4": 2}, Runs: 3}
	path := filepath.Join(dir, "state.json")
	if err := s.Save(path); err != nil {
		t.Fatal(err)
	}
	got, err := LoadState(path)
	if err != nil || got.Runs != 3 || got.Fails["7/v4"] != 2 || got.Active[0].ID != 7 {
		t.Errorf("state back: %+v, %v", got, err)
	}
	if none, err := LoadState(filepath.Join(dir, "missing.json")); none != nil || err != nil {
		t.Errorf("missing state: %v, %v", none, err)
	}
}

// An outage on the node's side makes most targets miss: those misses do not
// count, so it never replaces the whole list.
func TestSettleIgnoresOwnOutage(t *testing.T) {
	list := []targets.Target{entry(9, "EU", targets.RoleReserve)}
	for id := 1; id <= 4; id++ {
		list = append(list, entry(id, "EU", targets.RoleStudy))
	}
	s, err := NewState(list)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	for range 3 * s.FailLimit {
		if r := s.Settle(V6, map[int]bool{0: false, 1: false, 2: false, 3: true}, now); r != nil {
			t.Fatalf("replaced during an outage: %+v", r)
		}
	}
	if len(s.Fails) != 0 || len(s.Reserve["EU"]) != 1 {
		t.Fatalf("an outage counted as misses: %v", s.Fails)
	}
	// One target of four missing is the target's own: it leaves at the limit.
	var out []*Replacement
	for range s.FailLimit {
		out = s.Settle(V6, map[int]bool{0: true, 1: false, 2: true, 3: true}, now)
	}
	if len(out) != 1 || out[0].Out.ID != 2 || s.Active[1].ID != 9 {
		t.Errorf("replacement %+v, active %+v", out, s.Active)
	}
	// A target left out of the verdicts (not measured) keeps its count.
	s.Settle(V6, map[int]bool{0: false, 2: true, 3: true}, now)
	s.Settle(V6, map[int]bool{2: true, 3: true}, now)
	if s.Fails[s.Active[0].key(V6)] != 1 {
		t.Errorf("an unmeasured target changed its count: %v", s.Fails)
	}
}

// One failed routing check is not enough: the data service can be wrong.
func TestRoutingNeedsTwoChecks(t *testing.T) {
	s, err := NewState([]targets.Target{entry(1, "EU", targets.RoleStudy), entry(2, "EU", targets.RoleReserve)})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	if s.Routing(0, V6, false, "day 1", now) != nil {
		t.Fatal("replaced on the first failed check")
	}
	if s.Routing(0, V6, true, "", now) != nil || len(s.BGPFails) != 0 {
		t.Fatalf("a good check did not clear the count: %v", s.BGPFails)
	}
	s.Routing(0, V6, false, "day 3", now)
	if r := s.Routing(0, V6, false, "day 4", now); r == nil || s.Active[0].ID != 2 || len(s.BGPFails) != 0 {
		t.Errorf("after two failed checks in a row: %+v, active %+v", r, s.Active)
	}
}

func TestVmRSSMB(t *testing.T) {
	for in, want := range map[string]int64{
		"Name:\ttracertip\nVmHWM:\t   98304 kB\nVmRSS:\t   21568 kB\n": 21,
		"VmRSS:\n": 0, "Name:\tx\n": 0, "VmRSS:\t abc kB\n": 0,
	} {
		if got := vmRSSMB(in); got != want {
			t.Errorf("vmRSSMB(%q) = %d, want %d", in, got, want)
		}
	}
}
