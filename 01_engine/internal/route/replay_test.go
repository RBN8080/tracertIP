package route

import (
	"bufio"
	"context"
	"encoding/json"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/rbn8080/tracertip/01_engine/internal/enrich"
	"github.com/rbn8080/tracertip/01_engine/internal/model"
)

// TestReplayStudy runs the detector over a batch-mode study, round by round,
// with the study's own frozen bases. The data is private: set
// TRACERTIP_REPLAY to the study's state folder (runs/ and bases/ inside).
// The second rehearsal must show the three transit changes shared by the
// IPv4 targets (14:00, 18:00 and 20:00 UTC on 2026-09-30, evidence O5_114).
func TestReplayStudy(t *testing.T) {
	dir := os.Getenv("TRACERTIP_REPLAY")
	if dir == "" {
		t.Skip("TRACERTIP_REPLAY not set")
	}
	files, _ := filepath.Glob(filepath.Join(dir, "runs", "*", "*Z-v*.jsonl"))
	sort.Strings(files)
	type trace struct {
		target netip.Addr
		rounds map[int][]model.Probe
	}
	var traces []trace
	addrs := map[netip.Addr]bool{}
	for _, f := range files {
		fh, err := os.Open(f)
		if err != nil {
			t.Fatal(err)
		}
		sc := bufio.NewScanner(fh)
		sc.Buffer(make([]byte, 1<<20), 1<<24)
		var cur *trace
		for sc.Scan() {
			var head struct{ Type, Target, Slot string }
			json.Unmarshal(sc.Bytes(), &head)
			if head.Type == "run" && (head.Slot < "2026-09-30T12:00:00Z" || head.Slot > "2026-10-01T11:30:00Z") {
				break // outside the rehearsal's 48 slots
			}
			switch head.Type {
			case "start":
				traces = append(traces, trace{target: netip.MustParseAddr(head.Target), rounds: map[int][]model.Probe{}})
				cur = &traces[len(traces)-1]
			case "probe":
				var p model.Probe
				json.Unmarshal(sc.Bytes(), &p)
				cur.rounds[p.Round] = append(cur.rounds[p.Round], p)
				for _, r := range p.Replies {
					if a, err := netip.ParseAddr(r.From); err == nil && !r.Late {
						addrs[a] = true
					}
				}
			}
		}
		fh.Close()
		if err := sc.Err(); err != nil {
			t.Fatal(err)
		}
	}
	var list []netip.Addr
	for a := range addrs {
		list = append(list, a)
	}
	info, err := enrich.Enrich(context.Background(), list, enrich.Options{Dir: filepath.Join(dir, "bases"), NoDNS: true, NoIPmap: true, NoCity: true})
	if err != nil {
		t.Fatal(err)
	}
	asn := func(a netip.Addr) int {
		for _, x := range info[a].AS {
			if x.Source == "iptoasn" {
				return x.ASN
			}
		}
		return 0
	}

	dets := map[netip.Addr]*Detector{}
	n := map[netip.Addr]int{}
	confirmed := map[string]int{} // "hour family" -> targets
	var all []model.Event
	for _, tr := range traces {
		d := dets[tr.target]
		if d == nil {
			d = NewDetector(tr.target, ConfirmRounds)
			dets[tr.target] = d
		}
		keys := make([]int, 0, len(tr.rounds))
		for k := range tr.rounds {
			keys = append(keys, k)
		}
		slices.Sort(keys)
		for _, k := range keys {
			probes := tr.rounds[k]
			var steps []Step
			for _, p := range probes {
				s := Step{TTL: p.TTL, RTTms: -1}
				for _, r := range p.Replies {
					if a, err := netip.ParseAddr(r.From); err == nil && !r.Late {
						s.Addr, s.ASN, s.RTTms = a, asn(a), float64(r.RTTNS)/1e6
						s.Target = a == tr.target && (r.ICMPType == 0 || r.ICMPType == 129)
						break
					}
				}
				steps = append(steps, s)
			}
			for _, e := range d.Round(n[tr.target], probes[0].SendWall, steps) {
				all = append(all, e)
				if e.State == model.StateConfirmed {
					fam := "v4"
					if tr.target.Is6() {
						fam = "v6"
					}
					confirmed[e.Time.Format("01-02T15")+" "+fam]++
				}
			}
			n[tr.target]++
		}
	}
	count := map[string]int{}
	for _, e := range all {
		count[e.State]++
	}
	var keys []string
	for k := range confirmed {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var lines []string
	for _, k := range keys {
		lines = append(lines, k+": "+strconv.Itoa(confirmed[k]))
	}
	t.Logf("traces %d, targets %d, events %v", len(traces), len(dets), count)
	t.Logf("confirmed by hour and family:\n%s", strings.Join(lines, "\n"))
	for _, h := range []string{"09-30T14 v4", "09-30T18 v4", "09-30T20 v4"} {
		if confirmed[h] < 8 {
			t.Errorf("%s: %d targets confirmed a change, want the shared transit change in 8 or more", h, confirmed[h])
		}
	}
}
