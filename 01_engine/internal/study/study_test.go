package study

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
	for i := range FailLimit - 1 {
		if r := s.Result(0, V6, false, now); r != nil {
			t.Fatalf("replaced after %d misses", i+1)
		}
	}
	s.Result(0, V4, true, now) // the other family does not reset the count
	r := s.Result(0, V6, false, now)
	if r == nil || r.In == nil || r.In.ID != 2 || s.Active[0].ID != 2 || s.Active[0].Role != targets.RoleStudy {
		t.Fatalf("replacement %+v, active %+v", r, s.Active[0])
	}
	for range FailLimit {
		s.Result(0, V4, false, now)
	}
	if len(s.Active) != 1 || s.Active[0].Role != targets.RoleFixed {
		t.Errorf("with the reserve spent, the target leaves: %+v", s.Active)
	}
	for range 2 * FailLimit {
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
