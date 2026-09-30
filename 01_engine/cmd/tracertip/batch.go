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

	"github.com/rbn8080/tracertip/01_engine/internal/batch"
	"github.com/rbn8080/tracertip/01_engine/internal/enrich"
	"github.com/rbn8080/tracertip/01_engine/internal/ipdb"
	"github.com/rbn8080/tracertip/01_engine/internal/model"
	"github.com/rbn8080/tracertip/01_engine/internal/probe"
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
	ClockSynced bool      `json:"clock_synced"` // false: wall times cannot be trusted
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
	Skipped int       `json:"skipped,omitempty"` // left for lack of time before the next slot
	// Unmeasured traces failed on the node's side (no route, no socket,
	// probes not sent): they say nothing about the target.
	Unmeasured int `json:"unmeasured,omitempty"`
	Reached    int `json:"reached"`
}

type traceError struct {
	V      int       `json:"v"`
	Type   string    `json:"type"` // "error"
	Time   time.Time `json:"time"`
	Target string    `json:"target"`
	Error  string    `json:"error"`
}

// observer runs batch mode: one run per slot over the active targets in the
// slot's family, one target at a time (frontier 1.bis), and short traces of
// the fixed targets between them.
type observer struct {
	dir    string // state and data
	st     *batch.State
	cfg    config
	opts   enrich.Options
	known  map[netip.Addr]enrich.Info
	day    string
	rounds int
	every  time.Duration
	short  time.Duration
	last   time.Time // last short trace
	log    io.Writer
	bgp    func(context.Context, netip.Addr) (targets.Routing, error) // nil: no daily check
}

func runBatch(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("batch", flag.ContinueOnError)
	fs.SetOutput(stderr)
	list := fs.String("targets", "", "target list from tracertip targets (read once, when the state is new)")
	dir := fs.String("state", "", "folder for the state and the data")
	every := fs.Duration("every", 30*time.Minute, "run slot; runs alternate IPv4 and IPv6")
	rounds := fs.Int("rounds", 10, "rounds per trace")
	short := fs.Duration("short", 5*time.Minute, "fixed targets: a 2-round trace this often (0 = off)")
	once := fs.Bool("once", false, "run the current slot and stop")
	failLimit := fs.Int("fail-limit", batch.FailLimit, "runs of one family in a row a target may miss before the reserve replaces it (new state only)")
	report := fs.Bool("report", false, "sum up the runs so far by day and stop")
	cfgPath := fs.String("config", defaultConfigPath(), "configuration file (origin, access ISP, resolver, bases)")
	bases := fs.String("dir", "", "folder with the bases (default: config)")
	fs.Usage = func() {
		fmt.Fprintln(stderr, "usage: tracertip batch -state <dir> [-targets <file>] [flags]")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil || fs.NArg() != 0 || *dir == "" || *every < time.Minute || *rounds < 1 || *rounds > 100 || *short < 0 || *failLimit < 1 {
		if err == nil {
			fs.Usage()
		}
		return exitUsage
	}
	if *report {
		return batchReport(*dir, *every, stdout, stderr)
	}
	explicit := false
	fs.Visit(func(f *flag.Flag) { explicit = explicit || f.Name == "config" })
	cfg, err := loadConfig(*cfgPath, explicit)
	if err != nil {
		fmt.Fprintln(stderr, "tracertip:", err)
		return exitUsage
	}
	if cfg.Origin == nil {
		fmt.Fprintln(stderr, "tracertip: batch mode needs the origin in the configuration")
		return exitUsage
	}
	st, err := openState(*dir, *list, *failLimit)
	if err != nil {
		fmt.Fprintln(stderr, "tracertip:", err)
		return exitFail
	}
	o := &observer{dir: *dir, st: st, cfg: cfg, rounds: *rounds, every: *every, short: *short, log: stderr,
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
		slot, fam := batch.Slot(time.Now(), *every)
		if st.LastRun.Before(slot) {
			if err := o.run(ctx, slot, fam); err != nil {
				if ctx.Err() != nil {
					return exitOK // stopped: the run stays .partial
				}
				fmt.Fprintln(stderr, "tracertip:", err)
				return exitFail
			}
			// The daily BGP check uses the gap before the next slot, never a run's time.
			rctx, cancel := context.WithDeadline(ctx, slot.Add(*every))
			err := o.revalidate(rctx, o.day)
			cancel()
			if err != nil && ctx.Err() == nil {
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

// openState resumes the batch, or starts it from the target list and keeps
// a copy of the list with the data.
func openState(dir, list string, failLimit int) (*batch.State, error) {
	path := filepath.Join(dir, "state.json")
	st, err := batch.LoadState(path)
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
	if st, err = batch.NewState(l.Targets); err != nil {
		return nil, err
	}
	st.FailLimit = failLimit
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
// is replaced. The answers are kept per day, as the BGP side of the paths.
func (o *observer) revalidate(ctx context.Context, day string) error {
	if o.bgp == nil || o.st.Checked == day {
		return nil
	}
	var recs []any
	answered := 0
	for i := 0; i < len(o.st.Active); i++ {
		e := o.st.Active[i]
		for _, fam := range []string{batch.V4, batch.V6} {
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
			ok := r.Announced && len(r.Origins) == 1 && (e.AS(fam) == 0 || r.Origins[0] == e.AS(fam))
			reason := fmt.Sprintf("%s prefix %s: announced=%t, origins %v, declared AS%d, on %d daily checks in a row",
				fam, r.Prefix, r.Announced, r.Origins, e.AS(fam), batch.BGPFailLimit)
			rep := o.st.Routing(i, fam, ok, reason, time.Now())
			if rep == nil {
				if !ok {
					fmt.Fprintf(o.log, "tracertip: %s failed its routing check: announced=%t, origins %v\n", a, r.Announced, r.Origins)
				}
				continue // fixed targets stay; a first failure waits for the next day
			}
			fmt.Fprintf(o.log, "tracertip: %s replaced: %s\n", a, rep.Reason)
			recs = append(recs, rep)
			if err := batch.Append(filepath.Join(o.dir, "replacements.jsonl"), rep); err != nil {
				return err
			}
			if rep.In == nil {
				i--
			}
			break
		}
	}
	if err := batch.Append(filepath.Join(o.dir, "bgp", day+".jsonl"), recs...); err != nil {
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
	rf, err := batch.CreateRun(filepath.Join(o.dir, "runs"), slot, fam)
	if err != nil {
		return err
	}
	now := time.Now().UTC()
	temp, free := batch.Health(o.dir)
	want := 0
	for _, e := range o.st.Active {
		if e.Addr(fam).IsValid() {
			want++
		}
	}
	h := runHeader{V: 1, Type: "run", Slot: slot, Family: fam, Start: now, LateS: now.Sub(slot).Seconds(),
		Engine: version(), ClockSynced: batch.ClockSynced(), TempC: temp, DiskFreeMB: free, Targets: want}
	if b, err := os.ReadFile(filepath.Join(o.opts.Dir, "SHA256SUMS")); err == nil {
		sum := sha256.Sum256(b)
		h.BasesSHA256 = hex.EncodeToString(sum[:])
	}
	if err := rf.Write(h); err != nil {
		rf.Abort()
		return err
	}
	end := runEnd{V: 1, Type: "run_end"}
	// A trace takes rounds x interval plus the last timeout (measured: 22 s
	// for 10 rounds). One that cannot end before the next slot is skipped,
	// so a slow run never delays the next one.
	per := time.Duration(o.rounds)*probe.Defaults.RoundInterval + probe.Defaults.Timeout
	deadline := slot.Add(o.every)
	verdict := map[int]bool{} // index in Active: did the target answer
	for i := 0; i < len(o.st.Active); i++ {
		a := o.st.Active[i].Addr(fam)
		if !a.IsValid() {
			continue
		}
		if o.every > 0 && time.Now().Add(per).After(deadline) {
			end.Skipped++
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
			// The node did not measure: no verdict on the target.
			rf.Write(traceError{V: 1, Type: "error", Time: time.Now().UTC(), Target: a.String(), Error: err.Error()})
			end.Unmeasured++
		} else {
			end.Traced++
			if reached {
				end.Reached++
			}
			verdict[i] = reached
		}
		if err := rf.Sync(); err != nil {
			rf.Abort()
			return err
		}
	}
	// Misses are judged with the whole run in view, so an outage on the
	// node's side never empties the target list.
	for _, r := range o.st.Settle(fam, verdict, time.Now()) {
		fmt.Fprintf(o.log, "tracertip: %s replaced: %s\n", r.Out.Addr(fam), r.Reason)
		rf.Write(r)
		if err := batch.Append(filepath.Join(o.dir, "replacements.jsonl"), r); err != nil {
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

// enrichWait bounds the network answers (names, IPmap) after each trace;
// what is missing is asked again at the next trace.
const enrichWait = 8 * time.Second

// trace probes one target and writes its records: start, probes, hops, end.
func (o *observer) trace(ctx context.Context, a netip.Addr, rounds int, write func(...any) error) (bool, error) {
	s := &session{cfg: o.cfg, opts: o.opts, known: o.known, target: a, enrichWait: enrichWait}
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
	if err := write(model.End{V: model.SchemaVersion, Type: model.TypeEnd, Time: time.Now().UTC(),
		Reached: sum.Reached, Hops: sum.TargetTTL, Probes: sum.Probes, NoReply: sum.NoReply,
		DurationMS: time.Since(begin).Milliseconds()}); err != nil {
		return false, err
	}
	if !sum.Reached && sum.SendErrors > 0 {
		return false, fmt.Errorf("%d of %d probes not sent", sum.SendErrors, sum.Probes)
	}
	return sum.Reached, nil
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
		for _, fam := range []string{batch.V4, batch.V6} {
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
			if err := batch.Append(filepath.Join(o.dir, "short", day+".jsonl"), recs...); err != nil {
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
// asked again and each day's data carries its own.
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

// batchReport prints the runs so far by day. It states facts; the rules
// that judge them belong to whoever runs the batch.
func batchReport(dir string, every time.Duration, stdout, stderr io.Writer) int {
	sum, err := batch.Report(dir, every, time.Now())
	if err != nil {
		fmt.Fprintln(stderr, "tracertip:", err)
		return exitFail
	}
	fmt.Fprintf(stdout, "%-10s %5s %8s %10s %8s %5s %4s %7s %7s %7s %10s %4s %3s %6s %8s %8s\n",
		"day", "slots", "complete", "incomplete", "no-clock", "short", "gaps", "late-s", "run-min", "skipped", "unmeasured", "dark", "hot", "max°C", "min-disk", "replaced")
	for _, d := range sum.Days {
		fmt.Fprintf(stdout, "%-10s %5d %8d %10d %8d %5d %4d %7.0f %7.1f %7d %10d %4d %3d %6.1f %6dMB %8d\n",
			d.Day, d.Slots, d.Complete, d.Incomplete, d.NoClock, d.Short, d.Gaps, d.MaxLateS, d.MaxRunMin, d.Skipped, d.Unmeasured, d.Dark,
			d.Hot, d.MaxTempC, d.MinDiskMB, d.Replaced)
	}
	fmt.Fprintf(stdout, "engine: %s\nbases lists seen: %d\n", strings.Join(sum.Engines, ", "), len(sum.Bases))
	return exitOK
}
