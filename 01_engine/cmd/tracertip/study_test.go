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

	"github.com/rbn8080/tracertip/01_engine/internal/enrich"
	"github.com/rbn8080/tracertip/01_engine/internal/probe"
	"github.com/rbn8080/tracertip/01_engine/internal/study"
	"github.com/rbn8080/tracertip/01_engine/internal/targets"
)

// A target that never answers is replaced by the reserve after FailLimit
// runs; every run leaves a whole file and the replacement is logged.
func TestStudyReplacesUnreachable(t *testing.T) {
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
	st, err := openState(state, file)
	if err != nil {
		t.Fatal(err)
	}
	o := &observer{dir: state, st: st, rounds: 1, log: io.Discard, known: map[netip.Addr]enrich.Info{}}
	slot := time.Date(2026, 9, 29, 0, 0, 0, 0, time.UTC)
	for i := range study.FailLimit {
		if err := o.run(context.Background(), slot.Add(time.Duration(i)*time.Hour), study.V4); err != nil {
			t.Fatal(err)
		}
	}
	if st.Active[0].ID != 2 || st.Runs != study.FailLimit {
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
	again, err := openState(state, "")
	if err != nil || again.Active[0].ID != 2 {
		t.Errorf("state not resumed: %+v, %v", again, err)
	}

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
