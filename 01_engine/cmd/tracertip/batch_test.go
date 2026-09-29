package main

import (
	"bufio"
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

// A target that never answers is replaced by the reserve after FailLimit
// runs; every run leaves a whole file and the replacement is logged.
func TestBatchReplacesUnreachable(t *testing.T) {
	defer func(o func(netip.Addr) (probe.Conn, error)) { open = o }(open)
	open = func(netip.Addr) (probe.Conn, error) { return nil, errors.New("no socket in tests") }

	ok := []targets.Check{{Name: "all", OK: true}}
	anchor := func(id int, v4 string) targets.Anchor {
		return targets.Anchor{ID: id, IPv4: netip.MustParseAddr(v4), IPv6: netip.MustParseAddr("2001:db8::1")}
	}
	list := targetList{V: 1, Targets: []targets.Target{
		{Anchor: anchor(1, "192.0.2.1"), Continent: "EU", Role: targets.RoleStudy, Checks: ok},
		{Anchor: anchor(2, "192.0.2.2"), Continent: "EU", Role: targets.RoleReserve, Checks: ok},
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
	slot := time.Date(2026, 9, 29, 0, 0, 0, 0, time.UTC)
	for i := range batch.FailLimit {
		if err := o.run(context.Background(), slot.Add(time.Duration(i)*time.Hour), batch.V4); err != nil {
			t.Fatal(err)
		}
	}
	if st.Active[0].ID != 2 || st.Runs != batch.FailLimit {
		t.Errorf("active %+v after %d runs", st.Active, st.Runs)
	}
	log, err := os.ReadFile(filepath.Join(state, "replacements.jsonl"))
	if err != nil || strings.Count(string(log), "\n") != 1 {
		t.Errorf("replacement log %q, %v", log, err)
	}
	f, err := os.Open(filepath.Join(state, "runs", "2026-09-29", "0000Z-v4.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	var types []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		var r struct{ Type string }
		json.Unmarshal(sc.Bytes(), &r)
		types = append(types, r.Type)
	}
	if strings.Join(types, ",") != "run,error,run_end" {
		t.Errorf("run file records %v", types)
	}
	again, err := openState(state, "", batch.FailLimit)
	if err != nil || again.Active[0].ID != 2 {
		t.Errorf("state not resumed: %+v, %v", again, err)
	}

	// A run that would overflow its slot skips the targets it cannot finish
	// and never counts them as failures.
	o.every = time.Hour
	late := time.Now().UTC().Add(-time.Hour + 2*time.Second) // 2 s left; a 1-round trace takes 4 s
	if err := o.run(context.Background(), late, batch.V4); err != nil {
		t.Fatal(err)
	}
	if head, end := runFrame(t, filepath.Join(state, "runs", late.Format("2006-01-02"), late.Format("1504Z")+"-v4.jsonl")); end.Skipped != 1 || end.Traced != 0 || head.Targets != 1 {
		t.Errorf("late run: %+v / %+v", head, end)
	}
	if len(st.Fails) != 0 {
		t.Errorf("a skipped target counted as a failure: %v", st.Fails)
	}
	o.every = 0

	// The daily check finds a second origin (MOAS): the target leaves, once a day.
	asked := 0
	o.bgp = func(context.Context, netip.Addr) (targets.Routing, error) {
		asked++
		return targets.Routing{Prefix: "192.0.2.0/24", Announced: true, Origins: []int{64500, 64501}}, nil
	}
	o.revalidate(context.Background(), "2026-09-30")
	o.revalidate(context.Background(), "2026-09-30")
	if len(st.Active) != 0 || asked != 1 || st.Checked != "2026-09-30" {
		t.Errorf("after the daily check: active %+v, %d questions, checked %q", st.Active, asked, st.Checked)
	}
	if _, err := os.Stat(filepath.Join(state, "bgp", "2026-09-30.jsonl")); err != nil {
		t.Error("daily BGP answers not kept")
	}
}
