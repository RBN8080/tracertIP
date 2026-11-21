package live

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/rbn8080/tracertip/01_engine/internal/model"
)

// History is the recorded rounds and route events in a requested interval.
type History struct {
	Rounds []Round
	Events []model.Event
}

// HistoryTargets includes destinations with data on disk, even after tracing stops.
func (s *Store) HistoryTargets() ([]netip.Addr, error) {
	dirs, err := os.ReadDir(s.dir)
	if err != nil {
		return nil, err
	}
	var targets []netip.Addr
	for _, dir := range dirs {
		a, err := netip.ParseAddr(strings.ReplaceAll(dir.Name(), "-", ":"))
		if !dir.IsDir() || err != nil || dir.Name() != TargetDir(a) {
			continue
		}
		files, err := os.ReadDir(filepath.Join(s.dir, dir.Name()))
		if err != nil {
			return nil, err
		}
		for _, f := range files {
			day, hasExtension := strings.CutSuffix(strings.TrimSuffix(f.Name(), ".gz"), ".jsonl")
			if _, err := time.Parse(time.DateOnly, day); hasExtension && err == nil && !f.IsDir() {
				targets = append(targets, a)
				break
			}
		}
	}
	slices.SortFunc(targets, netip.Addr.Compare)
	return targets, nil
}

// ReadHistory returns rounds by their first send, with an inclusive start
// and exclusive end. The original logs keep every reply for each probe.
func (s *Store) ReadHistory(ctx context.Context, target netip.Addr, from, to time.Time) (History, error) {
	var history History
	var probes []model.Probe
	var first time.Time
	flush := func() {
		if len(probes) != 0 && !first.Before(from) && first.Before(to) {
			history.Rounds = append(history.Rounds, Summarize(target, probes[0].Round, probes))
		}
		probes, first = probes[:0], time.Time{}
	}
	const roundMargin = 5 * time.Second
	earliest, latest := from.Add(-roundMargin), to.Add(roundMargin)
	// A probe may finish after midnight, and an event may wait for the analyzer.
	// The analyzer's queue holds up to an hour of scheduled rounds.
	day := earliest.UTC().Truncate(24 * time.Hour)
	end := to.UTC().Add(time.Hour)
	for ; day.Before(end); day = day.AddDate(0, 0, 1) {
		name := filepath.Join(s.dir, TargetDir(target), day.Format(time.DateOnly)+".jsonl")
		firstRecord := true
		err := readHistoryDay(ctx, name, func(line []byte) error {
			var rec struct {
				Type string    `json:"type"`
				Time time.Time `json:"time"`
				Sent time.Time `json:"t_send_wall"`
			}
			if err := json.Unmarshal(line, &rec); err != nil {
				return err
			}
			if rec.Type == model.TypeStart && !firstRecord {
				flush() // a new session, as opposed to the daily file header
			}
			firstRecord = false
			switch rec.Type {
			case model.TypeProbe:
				if rec.Sent.Before(earliest) || !rec.Sent.Before(latest) {
					return nil
				}
				var p model.Probe
				if err := json.Unmarshal(line, &p); err != nil {
					return err
				}
				if len(probes) > 0 && (p.Round != probes[0].Round || p.SendWall.Sub(first) > roundMargin) {
					flush()
				}
				if first.IsZero() || p.SendWall.Before(first) {
					first = p.SendWall
				}
				probes = append(probes, p)
			case model.TypeEvent:
				if rec.Time.Before(from) || !rec.Time.Before(to) {
					return nil
				}
				var event model.Event
				if err := json.Unmarshal(line, &event); err != nil {
					return err
				}
				history.Events = append(history.Events, event)
			}
			return nil
		})
		if err != nil {
			return History{}, fmt.Errorf("history for %s: %w", day.Format(time.DateOnly), err)
		}
	}
	flush()
	slices.SortStableFunc(history.Events, func(a, b model.Event) int { return a.Time.Compare(b.Time) })
	slices.SortStableFunc(history.Rounds, func(a, b Round) int { return a.Start.Compare(b.Start) })
	return history, nil
}

func readHistoryDay(ctx context.Context, name string, visit func([]byte) error) error {
	// Compression publishes the gzip before unlinking the original.
	f, err := os.Open(name)
	zipped := errors.Is(err, os.ErrNotExist)
	if zipped {
		f, err = os.Open(name + ".gz")
	}
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	defer f.Close()
	var input io.Reader = f
	if zipped {
		gz, err := gzip.NewReader(f)
		if err != nil {
			return err
		}
		defer gz.Close()
		input = gz
	}
	scanner := bufio.NewScanner(input)
	scanner.Buffer(make([]byte, 16<<10), 4<<20)
	scanner.Split(completeHistoryLine)
	for scanner.Scan() {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := visit(scanner.Bytes()); err != nil {
			return err
		}
	}
	return scanner.Err()
}

// A power cut can leave the last line torn. Completed lines remain usable.
func completeHistoryLine(data []byte, atEOF bool) (int, []byte, error) {
	if i := bytes.IndexByte(data, '\n'); i >= 0 {
		return i + 1, data[:i], nil
	}
	if atEOF {
		return len(data), nil, nil
	}
	return 0, nil, nil
}
