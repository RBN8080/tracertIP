package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/netip"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/rbn8080/tracertip/01_engine/internal/enrich"
	"github.com/rbn8080/tracertip/01_engine/internal/ipdb"
	"github.com/rbn8080/tracertip/01_engine/internal/model"
	"github.com/rbn8080/tracertip/01_engine/internal/probe"
	"github.com/rbn8080/tracertip/01_engine/internal/study"
	"github.com/rbn8080/tracertip/01_engine/internal/targets"
)

// runHeader and runEnd frame each run file.
type runHeader struct {
	V           int       `json:"v"`
	Type        string    `json:"type"` // "run"
	Slot        time.Time `json:"slot"`
	Family      string    `json:"family"`
	Start       time.Time `json:"start"`
	LateS       float64   `json:"late_s"` // start after the slot began
	Engine      string    `json:"engine"`
	ClockSynced bool      `json:"clock_synced"` // false: the run is invalid (D7)
	TempC       float64   `json:"temp_c,omitempty"`
	DiskFreeMB  int64     `json:"disk_free_mb,omitempty"`
	BasesSHA256 string    `json:"bases_sha256,omitempty"` // of the frozen copy's SHA256SUMS
	Targets     int       `json:"targets"`                // active, with an address in the family
}

type runEnd struct {
	V       int       `json:"v"`
	Type    string    `json:"type"` // "run_end"
	Time    time.Time `json:"time"`
	Traced  int       `json:"traced"`
	Reached int       `json:"reached"`
}

type traceError struct {
	V      int       `json:"v"`
	Type   string    `json:"type"` // "error"
	Time   time.Time `json:"time"`
	Target string    `json:"target"`
	Error  string    `json:"error"`
}

// observer runs the study: one run per slot over the active targets in the
// slot's family, one target at a time (frontier 1.bis), and short traces of
// the fixed targets between them.
type observer struct {
	dir    string // state and data
	st     *study.State
	cfg    config
	opts   enrich.Options
	known  map[netip.Addr]enrich.Info
	day    string
	rounds int
	short  time.Duration
	last   time.Time // last short trace
	log    io.Writer
	bgp    func(context.Context, netip.Addr) (targets.Routing, error) // nil: no daily check
}

func runStudy(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("study", flag.ContinueOnError)
	fs.SetOutput(stderr)
	list := fs.String("targets", "", "target list from tracertip targets (read once, when the state is new)")
	dir := fs.String("state", "", "folder for the study's state and data")
	every := fs.Duration("every", 30*time.Minute, "run slot; runs alternate IPv4 and IPv6")
	rounds := fs.Int("rounds", 10, "rounds per trace")
	short := fs.Duration("short", 5*time.Minute, "fixed targets: a 2-round trace this often (0 = off)")
	once := fs.Bool("once", false, "run the current slot and stop")
	report := fs.Bool("report", false, "check the runs so far against the validity rules and stop")
	cfgPath := fs.String("config", defaultConfigPath(), "configuration file (origin, access ISP, resolver, bases)")
	bases := fs.String("dir", "", "folder with the bases, fixed for the study (default: config)")
	fs.Usage = func() {
		fmt.Fprintln(stderr, "usage: tracertip study -state <dir> [-targets <file>] [flags]")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil || fs.NArg() != 0 || *dir == "" || *every < time.Minute || *rounds < 1 || *rounds > 100 || *short < 0 {
		if err == nil {
			fs.Usage()
		}
		return exitUsage
	}
	if *report {
		return studyReport(*dir, *every, stdout, stderr)
	}
	explicit := false
	fs.Visit(func(f *flag.Flag) { explicit = explicit || f.Name == "config" })
	cfg, err := loadConfig(*cfgPath, explicit)
	if err != nil {
		fmt.Fprintln(stderr, "tracertip:", err)
		return exitUsage
	}
	if cfg.Origin == nil {
		fmt.Fprintln(stderr, "tracertip: the study needs the origin in the configuration")
		return exitUsage
	}
	st, err := openState(*dir, *list)
	if err != nil {
		fmt.Fprintln(stderr, "tracertip:", err)
		return exitFail
	}
	o := &observer{dir: *dir, st: st, cfg: cfg, rounds: *rounds, short: *short, log: stderr,
		opts: enrichOptions(cfg, *bases, "", false, false), known: map[netip.Addr]enrich.Info{}}
	o.opts.NoCity = true
	o.opts.IPmapCache = filepath.Join(*dir, "ipmap-cache.json")
	client, ua := ipdb.NewClient(time.Minute), "tracertip/"+version()+" (+https://github.com/RBN8080/tracertIP)"
	o.bgp = func(ctx context.Context, a netip.Addr) (targets.Routing, error) {
		return targets.PrefixOverview(ctx, client, a, ua)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	for {
		slot, fam := study.Slot(time.Now(), *every)
		if st.LastRun.Before(slot) {
			if err := o.run(ctx, slot, fam); err != nil {
				if ctx.Err() != nil {
					return exitOK // stopped: the run stays .partial
				}
				fmt.Fprintln(stderr, "tracertip:", err)
				return exitFail
			}
			if *once {
				return exitOK
			}
			continue
		}
		if err := o.idle(ctx, slot.Add(*every)); err != nil {
			return exitOK
		}
	}
}

// openState resumes the study, or starts it from the target list and keeps
// a copy of the list with the data.
func openState(dir, list string) (*study.State, error) {
	path := filepath.Join(dir, "state.json")
	st, err := study.LoadState(path)
	if err != nil || st != nil {
		return st, err
	}
	if list == "" {
		return nil, errors.New("no state yet: give the target list with -targets")
	}
	b, err := os.ReadFile(list)
	if err != nil {
		return nil, err
	}
	var l targetList
	if err := json.Unmarshal(b, &l); err != nil {
		return nil, fmt.Errorf("%s: %w", list, err)
	}
	if st, err = study.NewState(l.Targets); err != nil {
		return nil, err
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, err
	}
	if err := ipdb.WriteAtomic(filepath.Join(dir, "targets.json"), b, 0o644); err != nil {
		return nil, err
	}
	return st, st.Save(path)
}

// bgpCheck is one daily RIPEstat answer about a target's prefix.
type bgpCheck struct {
	V         int       `json:"v"`
	Type      string    `json:"type"` // "bgp"
	Time      time.Time `json:"time"`
	Target    string    `json:"target"`
	Declared  int       `json:"declared_as,omitempty"`
	Prefix    string    `json:"prefix,omitempty"`
	Announced bool      `json:"announced"`
	Origins   []int     `json:"origins,omitempty"`
	Error     string    `json:"error,omitempty"`
}

// revalidate asks RIPEstat, once a UTC day, whether each target's prefixes
// are still announced by one AS, the declared one; a study target that fails
// is replaced (D7). The answers are kept per day: they are also the BGP side
// of T1.
func (o *observer) revalidate(ctx context.Context, day string) error {
	if o.bgp == nil || o.st.Checked == day {
		return nil
	}
	var recs []any
	answered := 0
	for i := 0; i < len(o.st.Active); i++ {
		e := o.st.Active[i]
		for _, fam := range []string{study.V4, study.V6} {
			a := e.Addr(fam)
			if !a.IsValid() {
				continue
			}
			r, err := o.bgp(ctx, a)
			c := bgpCheck{V: 1, Type: "bgp", Time: time.Now().UTC(), Target: a.String(), Declared: e.AS(fam),
				Prefix: r.Prefix, Announced: r.Announced, Origins: r.Origins}
			if err != nil {
				c.Error = err.Error()
				recs = append(recs, c)
				continue // no answer, no verdict
			}
			answered++
			recs = append(recs, c)
			if r.Announced && len(r.Origins) == 1 && (e.AS(fam) == 0 || r.Origins[0] == e.AS(fam)) {
				continue
			}
			rep := o.st.Replace(i, fmt.Sprintf("%s prefix %s: announced=%t, origins %v, declared AS%d", fam, r.Prefix, r.Announced, r.Origins, e.AS(fam)), time.Now())
			if rep == nil {
				continue // fixed targets stay
			}
			recs = append(recs, rep)
			if err := study.Append(filepath.Join(o.dir, "replacements.jsonl"), rep); err != nil {
				return err
			}
			if rep.In == nil {
				i--
			}
			break
		}
	}
	if err := study.Append(filepath.Join(o.dir, "bgp", day+".jsonl"), recs...); err != nil {
		return err
	}
	if answered == 0 {
		return nil // RIPEstat unreachable: try again at the next run
	}
	o.st.Checked = day
	return o.st.Save(filepath.Join(o.dir, "state.json"))
}

// run traces every active target with an address in fam, in order.
func (o *observer) run(ctx context.Context, slot time.Time, fam string) error {
	o.newDay(slot)
	if err := o.revalidate(ctx, o.day); err != nil {
		return err
	}
	rf, err := study.CreateRun(filepath.Join(o.dir, "runs"), slot, fam)
	if err != nil {
		return err
	}
	now := time.Now().UTC()
	temp, free := study.Health(o.dir)
	want := 0
	for _, e := range o.st.Active {
		if e.Addr(fam).IsValid() {
			want++
		}
	}
	h := runHeader{V: 1, Type: "run", Slot: slot, Family: fam, Start: now, LateS: now.Sub(slot).Seconds(),
		Engine: version(), ClockSynced: study.ClockSynced(), TempC: temp, DiskFreeMB: free, Targets: want}
	if b, err := os.ReadFile(filepath.Join(o.opts.Dir, "SHA256SUMS")); err == nil {
		sum := sha256.Sum256(b)
		h.BasesSHA256 = hex.EncodeToString(sum[:])
	}
	if err := rf.Write(h); err != nil {
		rf.Abort()
		return err
	}
	end := runEnd{V: 1, Type: "run_end"}
	for i := 0; i < len(o.st.Active); i++ {
		a := o.st.Active[i].Addr(fam)
		if !a.IsValid() {
			continue
		}
		if err := o.shortTraces(ctx); err != nil {
			rf.Abort()
			return err
		}
		reached, err := o.trace(ctx, a, o.rounds, rf.Write)
		if ctx.Err() != nil {
			rf.Abort()
			return ctx.Err()
		}
		if err != nil {
			rf.Write(traceError{V: 1, Type: "error", Time: time.Now().UTC(), Target: a.String(), Error: err.Error()})
		}
		end.Traced++
		if reached {
			end.Reached++
		}
		if r := o.st.Result(i, fam, reached, time.Now()); r != nil {
			fmt.Fprintf(o.log, "tracertip: %s replaced: %s\n", a, r.Reason)
			rf.Write(r)
			if err := study.Append(filepath.Join(o.dir, "replacements.jsonl"), r); err != nil {
				rf.Abort()
				return err
			}
			if r.In == nil {
				i-- // the target left and the list shrank
			}
		}
		if err := rf.Sync(); err != nil {
			rf.Abort()
			return err
		}
		if err := o.st.Save(filepath.Join(o.dir, "state.json")); err != nil {
			rf.Abort()
			return err
		}
	}
	end.Time = time.Now().UTC()
	if err := rf.Write(end); err != nil {
		rf.Abort()
		return err
	}
	if err := rf.Close(); err != nil {
		return err
	}
	o.st.Runs++
	o.st.LastRun = slot
	o.keepIPmap(slot)
	return o.st.Save(filepath.Join(o.dir, "state.json"))
}

// trace probes one target and writes its records: start, probes, hops, end.
func (o *observer) trace(ctx context.Context, a netip.Addr, rounds int, write func(...any) error) (bool, error) {
	s := &session{cfg: o.cfg, opts: o.opts, known: o.known, target: a}
	s.startCity()
	pc := probe.Defaults
	pc.Rounds, pc.Target, pc.ICMPID, pc.FlowID = rounds, a, random16(), random16()
	var err error
	if a.Is6() {
		if pc.Source, err = probe.SourceFor(a); err != nil {
			return false, fmt.Errorf("no IPv6 route: %w", err)
		}
	}
	conn, err := open(a)
	if err != nil {
		return false, err
	}
	defer conn.Close()
	begin := time.Now()
	if err := write(startRecord(begin, a, pc, o.opts.Dir)); err != nil {
		return false, err
	}
	sum, recs, err := s.once(ctx, conn, pc, func(p model.Probe) error { return write(p) })
	if err != nil {
		return false, err
	}
	for _, r := range recs {
		if err := write(r); err != nil {
			return false, err
		}
	}
	return sum.Reached, write(model.End{V: model.SchemaVersion, Type: model.TypeEnd, Time: time.Now().UTC(),
		Reached: sum.Reached, Hops: sum.TargetTTL, Probes: sum.Probes, NoReply: sum.NoReply,
		DurationMS: time.Since(begin).Milliseconds()})
}

// shortTraces gives each fixed target a 2-round trace when one is due: the
// near and far ends of every link on its path, often enough to follow the
// time of day (TSLP; Dhamdhere et al., SIGCOMM 2018).
func (o *observer) shortTraces(ctx context.Context) error {
	if o.short == 0 || time.Since(o.last) < o.short {
		return nil
	}
	o.last = time.Now()
	for _, e := range o.st.Active {
		if e.Role != targets.RoleFixed {
			continue
		}
		for _, fam := range []string{study.V4, study.V6} {
			a := e.Addr(fam)
			if !a.IsValid() {
				continue
			}
			var recs []any
			_, err := o.trace(ctx, a, 2, func(v ...any) error { recs = append(recs, v...); return nil })
			if ctx.Err() != nil {
				return ctx.Err()
			}
			if err != nil {
				recs = append(recs, traceError{V: 1, Type: "error", Time: time.Now().UTC(), Target: a.String(), Error: err.Error()})
			}
			day := time.Now().UTC().Format("2006-01-02")
			if err := study.Append(filepath.Join(o.dir, "short", day+".jsonl"), recs...); err != nil {
				return err
			}
		}
	}
	return nil
}

// idle waits for the next slot, running the short traces meanwhile.
func (o *observer) idle(ctx context.Context, next time.Time) error {
	for {
		if err := o.shortTraces(ctx); err != nil {
			return err
		}
		wait := time.Until(next)
		if o.short > 0 {
			wait = min(wait, time.Until(o.last.Add(o.short)))
		}
		if wait <= 0 && !time.Now().Before(next) {
			return nil
		}
		t := time.NewTimer(max(wait, time.Second))
		select {
		case <-ctx.Done():
			t.Stop()
			return ctx.Err()
		case <-t.C:
		}
		if !time.Now().Before(next) {
			return nil
		}
	}
}

// newDay forgets the enrichment each UTC day, so names and IPmap answers are
// asked again and each day's data carries its own (T3).
func (o *observer) newDay(slot time.Time) {
	if d := slot.UTC().Format("2006-01-02"); d != o.day {
		o.day, o.known = d, map[netip.Addr]enrich.Info{}
	}
}

// keepIPmap copies the IPmap answers, with their dates, next to the day's runs.
func (o *observer) keepIPmap(slot time.Time) {
	b, err := os.ReadFile(o.opts.IPmapCache)
	if err != nil {
		return
	}
	day := filepath.Join(o.dir, "runs", slot.UTC().Format("2006-01-02"))
	if err := ipdb.WriteAtomic(filepath.Join(day, "ipmap-cache.json"), b, 0o644); err != nil {
		fmt.Fprintln(o.log, "tracertip: keeping the IPmap answers:", err)
	}
}

// studyReport prints each day against the validity rules and the verdict:
// exit 0 to go on, 1 when the study must be repeated (V6).
func studyReport(dir string, every time.Duration, stdout, stderr io.Writer) int {
	sum, err := study.Report(dir, every, time.Now())
	if err != nil {
		fmt.Fprintln(stderr, "tracertip:", err)
		return exitFail
	}
	fmt.Fprintf(stdout, "%-10s %5s %5s %10s %8s %4s %5s %4s %3s %6s %8s %8s  %s\n",
		"day", "slots", "valid", "incomplete", "no-clock", "late", "short", "gaps", "hot", "max°C", "min-disk", "replaced", "status")
	for _, d := range sum.Days {
		status := "ok"
		if d.Invalid() {
			status = "INVALID"
		}
		fmt.Fprintf(stdout, "%-10s %5d %5d %10d %8d %4d %5d %4d %3d %6.1f %6dMB %8d  %s\n",
			d.Day, d.Slots, d.Valid, d.Incomplete, d.NoClock, d.Late, d.Short, d.Gaps, d.Hot, d.MaxTempC, d.MinDiskMB, d.Replaced, status)
	}
	fmt.Fprintf(stdout, "engine: %s; frozen bases seen: %d\n", strings.Join(sum.Engines, ", "), len(sum.Bases))
	if sum.LowDisk {
		fmt.Fprintln(stdout, "alert: less than 1 GB free")
	}
	if again, why := sum.Repeat(); again {
		fmt.Fprintln(stdout, "verdict: REPEAT the study:", why)
		return exitFail
	}
	fmt.Fprintln(stdout, "verdict: go on")
	return exitOK
}
