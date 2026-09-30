package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/rbn8080/tracertip/01_engine/internal/batch"
	"github.com/rbn8080/tracertip/01_engine/internal/enrich"
	"github.com/rbn8080/tracertip/01_engine/internal/probe"
	"github.com/rbn8080/tracertip/01_engine/internal/targets"
)

func runFrame(t *testing.T, path string) (h runHeader, e runEnd) {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	for line := range strings.Lines(string(b)) {
		switch {
		case strings.Contains(line, `"type":"run_end"`):
			json.Unmarshal([]byte(line), &e)
		case strings.Contains(line, `"type":"run"`):
			json.Unmarshal([]byte(line), &h)
		}
	}
	return h, e
}

// fakePath stands for the network in batch tests: a target answers, stays
// silent, or cannot even be probed.
type fakePath struct {
	target  netip.Addr
	mode    string // "up", "silent", "senderr"
	replies chan []byte
}

func (f *fakePath) Send(dst netip.Addr, ttl int, icmp []byte) error {
	switch f.mode {
	case "senderr":
		return errors.New("network is unreachable")
	case "up":
		pkt := make([]byte, 20, 20+len(icmp))
		pkt[0], pkt[8], pkt[9] = 0x45, 57, 1
		src := f.target.As4()
		copy(pkt[12:], src[:])
		pkt = append(pkt, icmp...)
		pkt[20] = 0 // Echo Reply
		f.replies <- pkt
	}
	return nil
}

func (f *fakePath) Recv(buf []byte, deadline time.Time) (int, probe.Meta, error) {
	select {
	case b := <-f.replies:
		return copy(buf, b), probe.Meta{}, nil
	case <-time.After(time.Until(deadline)):
		return 0, probe.Meta{}, os.ErrDeadlineExceeded
	}
}

func (f *fakePath) Close() error { return nil }

// A target that never answers is replaced by the reserve after FailLimit
// runs. What the node could not measure (no socket, probes not sent) is no
// verdict on any target, and one failed routing check is not enough.
func TestBatchReplacesUnreachable(t *testing.T) {
	defer func(o func(netip.Addr) (probe.Conn, error), d probe.Config) { open, probe.Defaults = o, d }(open, probe.Defaults)
	probe.Defaults.TTLMax, probe.Defaults.Timeout = 3, 30*time.Millisecond
	probe.Defaults.RoundInterval, probe.Defaults.Spacing = 40*time.Millisecond, time.Millisecond
	mode := map[string]string{"192.0.2.1": "silent"}
	open = func(a netip.Addr) (probe.Conn, error) {
		m := mode["*"] // an outage hits every target
		if own := mode[a.String()]; m == "up" && own != "" {
			m = own
		}
		if m == "nosocket" {
			return nil, errors.New("no socket in tests")
		}
		return &fakePath{target: a, mode: m, replies: make(chan []byte, 64)}, nil
	}
	mode["*"] = "up"

	ok := []targets.Check{{Name: "all", OK: true}}
	anchor := func(id int, v4 string) targets.Anchor {
		return targets.Anchor{ID: id, IPv4: netip.MustParseAddr(v4), IPv6: netip.MustParseAddr("2001:db8::1")}
	}
	list := targetList{V: 1, Targets: []targets.Target{
		{Anchor: anchor(1, "192.0.2.1"), Continent: "EU", Role: targets.RoleStudy, Checks: ok},
		{Anchor: anchor(2, "192.0.2.2"), Continent: "EU", Role: targets.RoleReserve, Checks: ok},
		{Anchor: anchor(3, "192.0.2.3"), Continent: "EU", Role: targets.RoleStudy, Checks: ok},
		{Anchor: anchor(4, "192.0.2.4"), Continent: "EU", Role: targets.RoleStudy, Checks: ok},
	}}
	dir := t.TempDir()
	b, _ := json.Marshal(list)
	file := filepath.Join(dir, "list.json")
	os.WriteFile(file, b, 0o644)
	state := filepath.Join(dir, "study")
	st, err := openState(state, file, batch.FailLimit)
	if err != nil {
		t.Fatal(err)
	}
	o := &observer{dir: state, st: st, rounds: 1, log: io.Discard, known: map[netip.Addr]enrich.Info{}}
	o.opts.NoDNS, o.opts.NoCity = true, true
	slot := time.Date(2026, 9, 29, 0, 0, 0, 0, time.UTC)
	runFile := func(s time.Time) string {
		return filepath.Join(state, "runs", s.Format("2006-01-02"), s.Format("1504Z")+"-v4.jsonl")
	}

	// The node's own outages come first: they must leave no trace in the counts.
	for i, m := range []string{"nosocket", "senderr", "silent"} {
		mode["*"] = m
		s := slot.Add(-time.Duration(i+1) * time.Hour)
		for range 2 * batch.FailLimit {
			if err := o.run(context.Background(), s, batch.V4); err != nil {
				t.Fatal(err)
			}
		}
		_, end := runFrame(t, runFile(s))
		if m == "silent" {
			if end.Traced != 3 || end.Reached != 0 || end.Unmeasured != 0 {
				t.Errorf("%s: run end %+v", m, end)
			}
		} else if end.Traced != 0 || end.Unmeasured != 3 {
			t.Errorf("%s: run end %+v, want 3 unmeasured", m, end)
		}
		if len(st.Fails) != 0 || st.Active[0].ID != 1 {
			t.Fatalf("%s: an outage on the node's side counted against the targets: fails %v, active %+v", m, st.Fails, st.Active)
		}
	}
	mode["*"] = "up"
	runs := st.Runs

	for i := range batch.FailLimit {
		if err := o.run(context.Background(), slot.Add(time.Duration(i)*time.Hour), batch.V4); err != nil {
			t.Fatal(err)
		}
	}
	if st.Active[0].ID != 2 || st.Runs != runs+batch.FailLimit {
		t.Errorf("active %+v after %d runs", st.Active, st.Runs)
	}
	log, err := os.ReadFile(filepath.Join(state, "replacements.jsonl"))
	if err != nil || strings.Count(string(log), "\n") != 1 {
		t.Errorf("replacement log %q, %v", log, err)
	}
	if _, end := runFrame(t, runFile(slot)); end.Traced != 3 || end.Reached != 2 {
		t.Errorf("run end %+v", end)
	}
	again, err := openState(state, "", batch.FailLimit)
	if err != nil || again.Active[0].ID != 2 {
		t.Errorf("state not resumed: %+v, %v", again, err)
	}

	// A run that would overflow its slot skips the targets it cannot finish
	// and never counts them as failures.
	o.every = time.Hour
	late := time.Now().UTC().Add(-time.Hour + 20*time.Millisecond) // less left than a 1-round trace takes
	if err := o.run(context.Background(), late, batch.V4); err != nil {
		t.Fatal(err)
	}
	if head, end := runFrame(t, runFile(late)); end.Skipped != 3 || end.Traced != 0 || head.Targets != 3 {
		t.Errorf("late run: %+v / %+v", head, end)
	}
	if len(st.Fails) != 0 {
		t.Errorf("a skipped target counted as a failure: %v", st.Fails)
	}
	o.every = 0

	// The daily check finds a second origin (MOAS). Once a day, and only the
	// second day in a row do the targets leave.
	asked := 0
	o.bgp = func(context.Context, netip.Addr) (targets.Routing, error) {
		asked++
		return targets.Routing{Prefix: "192.0.2.0/24", Announced: true, Origins: []int{64500, 64501}}, nil
	}
	o.revalidate(context.Background(), "2026-09-30")
	o.revalidate(context.Background(), "2026-09-30")
	if len(st.Active) != 3 || asked != 6 || st.Checked != "2026-09-30" {
		t.Errorf("after the first daily check: active %+v, %d questions, checked %q", st.Active, asked, st.Checked)
	}
	o.revalidate(context.Background(), "2026-10-01")
	if len(st.Active) != 0 {
		t.Errorf("after two failed daily checks: active %+v", st.Active)
	}
	if _, err := os.Stat(filepath.Join(state, "bgp", "2026-09-30.jsonl")); err != nil {
		t.Error("daily BGP answers not kept")
	}
}
