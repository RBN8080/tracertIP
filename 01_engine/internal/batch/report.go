package batch

import (
	"bufio"
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"
)

// hotC: the Pi starts throttling at 80 °C (Raspberry Pi documentation).
const hotC = 80

// Day sums up one UTC day of runs. It states facts; judging them is up to
// whoever runs the batch.
type Day struct {
	Day        string
	Slots      int // expected so far
	Complete   int // whole file, NTP time, every expected target traced
	Incomplete int // cut short: .partial or .aborted
	NoClock    int // whole, but without NTP time
	Short      int // whole, but fewer targets traced than expected
	Gaps       int // slots without any run
	MaxLateS   float64
	MaxRunMin  float64 // longest whole run
	Skipped    int     // targets left for lack of time
	Hot        int     // runs started at 80 °C or more
	MaxTempC   float64
	MinDiskMB  int64
	Replaced   int
}

// Summary is the whole batch so far.
type Summary struct {
	Days    []Day
	Engines []string // engine versions seen in the run headers
	Bases   []string // SHA-256 of the bases' lists seen in the run headers
}

type runLine struct {
	Type        string    `json:"type"`
	Slot        time.Time `json:"slot"`
	LateS       float64   `json:"late_s"`
	Engine      string    `json:"engine"`
	ClockSynced bool      `json:"clock_synced"`
	TempC       float64   `json:"temp_c"`
	DiskFreeMB  int64     `json:"disk_free_mb"`
	BasesSHA256 string    `json:"bases_sha256"`
	Targets     int       `json:"targets"`
	Traced      int       `json:"traced"`
	Skipped     int       `json:"skipped"`
	Start       time.Time `json:"start"`
	Time        time.Time `json:"time"`
}

// Report reads a batch folder: run files by day, and the replacement log.
func Report(dir string, every time.Duration, now time.Time) (Summary, error) {
	var sum Summary
	files, err := filepath.Glob(filepath.Join(dir, "runs", "*", "*Z-v?.jsonl*"))
	if err != nil {
		return sum, err
	}
	days := map[string]*Day{}
	seen := map[time.Time]bool{}
	var first time.Time
	for _, f := range files {
		head, end, err := frame(f)
		if err != nil || head == nil {
			continue
		}
		s := head.Slot.UTC()
		if first.IsZero() || s.Before(first) {
			first = s
		}
		seen[s] = true
		d := day(days, s)
		if head.TempC > d.MaxTempC {
			d.MaxTempC = head.TempC
		}
		if head.DiskFreeMB > 0 && (d.MinDiskMB == 0 || head.DiskFreeMB < d.MinDiskMB) {
			d.MinDiskMB = head.DiskFreeMB
		}
		if head.TempC >= hotC {
			d.Hot++
		}
		if !slices.Contains(sum.Engines, head.Engine) {
			sum.Engines = append(sum.Engines, head.Engine)
		}
		if head.BasesSHA256 != "" && !slices.Contains(sum.Bases, head.BasesSHA256) {
			sum.Bases = append(sum.Bases, head.BasesSHA256)
		}
		d.MaxLateS = max(d.MaxLateS, head.LateS)
		if end != nil {
			d.Skipped += end.Skipped
			if !head.Start.IsZero() && !end.Time.IsZero() {
				d.MaxRunMin = max(d.MaxRunMin, end.Time.Sub(head.Start).Minutes())
			}
		}
		switch {
		case !strings.HasSuffix(f, ".jsonl") || end == nil:
			d.Incomplete++
		case !head.ClockSynced:
			d.NoClock++
		case end.Traced < head.Targets:
			d.Short++
		default:
			d.Complete++
		}
	}
	if !first.IsZero() {
		for s := first; !s.After(now); s = s.Add(every) {
			d := day(days, s)
			d.Slots++
			if !seen[s] {
				d.Gaps++
			}
		}
	}
	if b, err := os.ReadFile(filepath.Join(dir, "replacements.jsonl")); err == nil {
		for line := range bytes.Lines(b) {
			var r Replacement
			if json.Unmarshal(line, &r) == nil && !r.Time.IsZero() {
				day(days, r.Time).Replaced++
			}
		}
	}
	for _, d := range days {
		sum.Days = append(sum.Days, *d)
	}
	slices.SortFunc(sum.Days, func(a, b Day) int { return strings.Compare(a.Day, b.Day) })
	return sum, nil
}

func day(days map[string]*Day, t time.Time) *Day {
	k := t.UTC().Format("2006-01-02")
	if days[k] == nil {
		days[k] = &Day{Day: k}
	}
	return days[k]
}

// frame reads a run file's header and end, skipping the trace records.
func frame(path string) (head, end *runLine, err error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, nil, err
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 16<<20)
	for sc.Scan() {
		b := sc.Bytes()
		if !bytes.Contains(b, []byte(`"type":"run`)) { // trace records are skipped undecoded
			continue
		}
		var r runLine
		if json.Unmarshal(b, &r) != nil {
			continue
		}
		switch r.Type {
		case "run":
			if head == nil {
				head = &r
			}
		case "run_end":
			end = &r
		}
	}
	return head, end, sc.Err()
}
