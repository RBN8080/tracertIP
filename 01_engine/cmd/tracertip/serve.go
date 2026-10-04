package main

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net/netip"
	"os"
	"os/signal"
	"slices"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/rbn8080/tracertip/01_engine/internal/batch"
	"github.com/rbn8080/tracertip/01_engine/internal/live"
	"github.com/rbn8080/tracertip/01_engine/internal/probe"
)

func runServe(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("serve", flag.ContinueOnError)
	fs.SetOutput(stderr)
	list := fs.String("targets", "", "file with the targets, one IP per line, # for comments (at most 5)")
	dir := fs.String("state", "", "folder for the history")
	capGB := fs.Float64("cap-gb", float64(live.DefaultCap)/(1<<30), "disk the history may use, in GiB")
	every := fs.Duration("status", time.Minute, "how often to log the health")
	limit := fs.Duration("for", 0, "stop after this long (0 = until stopped)")
	cfgPath := fs.String("config", defaultConfigPath(), "configuration file (origin, access ISP, resolver, bases)")
	bases := fs.String("dir", "", "folder with the bases (default: config, then the user cache)")
	fs.Usage = func() {
		fmt.Fprintln(stderr, "usage: tracertip serve -targets <file> -state <dir> [flags]")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil || fs.NArg() != 0 || *list == "" || *dir == "" || *capGB <= 0 || *every <= 0 || *limit < 0 {
		if err == nil {
			fs.Usage()
		}
		return exitUsage
	}
	targetList, err := readTargets(*list)
	if err != nil {
		fmt.Fprintln(stderr, "tracertip:", err)
		return exitUsage
	}
	explicit := false
	fs.Visit(func(f *flag.Flag) { explicit = explicit || f.Name == "config" })
	cfg, err := loadConfig(*cfgPath, explicit)
	if err != nil {
		fmt.Fprintln(stderr, "tracertip:", err)
		return exitUsage
	}
	basesDir := enrichOptions(cfg, *bases, "", true, true).Dir

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if *limit > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, *limit)
		defer cancel()
	}
	log := slog.New(slog.NewTextHandler(stderr, nil))
	store, err := live.OpenStore(*dir, int64(*capGB*(1<<30)), time.Now())
	if err != nil {
		fmt.Fprintln(stderr, "tracertip:", err)
		return exitFail
	}
	mcfg := live.Config{
		Probe: probe.Defaults, Open: open, Source: probe.SourceFor, Store: store, Log: log,
		Header: func(a netip.Addr, pc probe.Config) any { return startRecord(time.Now(), a, pc, basesDir) },
	}
	monitors := make([]*live.Monitor, len(targetList))
	for i, a := range targetList {
		monitors[i] = live.NewMonitor(a, mcfg, random16(), random16())
	}
	fmt.Fprintf(stdout, "tracertip serve: %d targets, one round every %s each; history in %s (cap %.1f GiB); Ctrl-C stops\n",
		len(monitors), probe.Defaults.RoundInterval, *dir, *capGB)

	err = serve(ctx, monitors, probe.Defaults.RoundInterval, *every, *dir, log)
	if cerr := store.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		fmt.Fprintln(stderr, "tracertip:", err)
		return exitFail
	}
	return exitOK
}

// serve runs the monitors with their rounds staggered evenly over the round
// interval, so the targets' probes do not leave together (00_IDEA 5), and
// logs their health every so often. The first monitor that cannot write its
// history stops them all.
func serve(ctx context.Context, monitors []*live.Monitor, interval, every time.Duration, dir string, log *slog.Logger) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	var (
		wg   sync.WaitGroup
		mu   sync.Mutex
		errs []error
	)
	for i, m := range monitors {
		wg.Go(func() {
			if !wait(ctx, interval*time.Duration(i)/time.Duration(len(monitors))) {
				return
			}
			if err := m.Run(ctx); err != nil {
				mu.Lock()
				errs = append(errs, fmt.Errorf("%s: %w", m.Target, err))
				mu.Unlock()
				cancel()
			}
		})
	}
	t := time.NewTicker(every)
	defer t.Stop()
	for ctx.Err() == nil {
		select {
		case <-ctx.Done():
		case <-t.C:
			logHealth(log, monitors, dir)
		}
	}
	wg.Wait()
	return errors.Join(errs...)
}

func logHealth(log *slog.Logger, monitors []*live.Monitor, dir string) {
	tempC, freeMB := batch.Health(dir)
	log.Info("node", "clock_synced", batch.ClockSynced(), "temp_c", tempC, "disk_free_mb", freeMB)
	for _, m := range monitors {
		h := m.Health()
		log.Info("target", "target", h.Target, "state", h.State, "rounds", h.Rounds, "replied", h.Replied,
			"no_reply", h.NoReply, "send_errors", h.SendErrors, "sessions", h.Sessions,
			"lag_ms", fmt.Sprintf("%.0f", h.LagMS), "max_lag_ms", fmt.Sprintf("%.0f", h.MaxLagMS), "err", h.Error)
	}
}

func wait(ctx context.Context, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}

// readTargets reads the declared targets: IP addresses only, no names or
// ranges, at most live.MaxTargets (00_IDEA 1.bis: it measures paths, it
// does not scan).
func readTargets(path string) ([]netip.Addr, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var out []netip.Addr
	sc := bufio.NewScanner(f)
	for n := 1; sc.Scan(); n++ {
		line, _, _ := strings.Cut(sc.Text(), "#")
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		a, err := netip.ParseAddr(line)
		if err != nil {
			return nil, fmt.Errorf("%s:%d: %q is not an IP address", path, n, line)
		}
		a = a.Unmap()
		if a.IsUnspecified() || a.IsLoopback() || a.IsMulticast() || a.IsLinkLocalUnicast() {
			return nil, fmt.Errorf("%s:%d: %s cannot be a target", path, n, a)
		}
		if slices.Contains(out, a) {
			return nil, fmt.Errorf("%s:%d: %s is listed twice", path, n, a)
		}
		out = append(out, a)
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	switch {
	case len(out) == 0:
		return nil, fmt.Errorf("%s: no targets", path)
	case len(out) > live.MaxTargets:
		return nil, fmt.Errorf("%s: %d targets; the frontier allows %d at once", path, len(out), live.MaxTargets)
	}
	return out, nil
}
