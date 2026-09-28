package main

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/netip"
	"os"
	"os/signal"
	"sort"
	"strings"
	"time"

	"github.com/rbn8080/tracertip/01_engine/internal/model"
	"github.com/rbn8080/tracertip/01_engine/internal/probe"
)

// open is swapped in tests.
var open = probe.Open

func runTrace(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("trace", flag.ContinueOnError)
	fs.SetOutput(stderr)
	jsonOut := fs.Bool("json", false, "write JSON Lines records (schema v1) instead of a table")
	rounds := fs.Int("rounds", probe.Defaults.Rounds, "rounds of probes (1-100)")
	ttlMax := fs.Int("ttl-max", probe.Defaults.TTLMax, "highest TTL (1-40, frontier)")
	fs.Usage = func() {
		fmt.Fprintln(stderr, "usage: tracertip trace [flags] <ipv4>")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return exitUsage
	}
	if fs.NArg() != 1 {
		fs.Usage()
		return exitUsage
	}
	target, err := netip.ParseAddr(fs.Arg(0))
	if err != nil || !target.Is4() {
		fmt.Fprintf(stderr, "tracertip: %q is not an IPv4 address\n", fs.Arg(0))
		return exitUsage
	}
	if *rounds < 1 || *rounds > 100 || *ttlMax < 1 || *ttlMax > probe.Defaults.TTLMax {
		fmt.Fprintln(stderr, "tracertip: rounds must be 1-100 and ttl-max 1-40")
		return exitUsage
	}

	cfg := probe.Defaults
	cfg.Target, cfg.Rounds, cfg.TTLMax = target, *rounds, *ttlMax
	cfg.ICMPID, cfg.FlowID = random16(), random16()

	conn, err := open()
	if err != nil {
		fmt.Fprintln(stderr, "tracertip:", err)
		return exitFail
	}
	defer conn.Close()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	enc := json.NewEncoder(stdout)
	begin := time.Now()
	start := model.Start{
		V: model.SchemaVersion, Type: model.TypeStart, Tool: "tracertip", Version: version(),
		Time: begin.UTC(), Target: target.String(), Method: "icmp-paris",
		Params: model.Params{
			TTLMax: cfg.TTLMax, TimeoutMS: int(cfg.Timeout.Milliseconds()),
			RoundIntervalMS: int(cfg.RoundInterval.Milliseconds()), ProbeSpacingMS: int(cfg.Spacing.Milliseconds()),
			Rounds: cfg.Rounds, ICMPID: int(cfg.ICMPID), FlowID: int(cfg.FlowID),
		},
	}
	var probes []model.Probe
	emit := func(p model.Probe) error {
		if *jsonOut {
			return enc.Encode(p)
		}
		probes = append(probes, p)
		return nil
	}
	if *jsonOut {
		if err := enc.Encode(start); err != nil {
			fmt.Fprintln(stderr, "tracertip:", err)
			return exitFail
		}
	}
	sum, err := probe.Trace(ctx, conn, cfg, emit)
	if err != nil {
		fmt.Fprintln(stderr, "tracertip:", err)
		return exitFail
	}
	end := model.End{
		V: model.SchemaVersion, Type: model.TypeEnd, Time: time.Now().UTC(), Reached: sum.Reached,
		Hops: sum.TargetTTL, Probes: sum.Probes, NoReply: sum.NoReply, DurationMS: time.Since(begin).Milliseconds(),
	}
	if *jsonOut {
		if err := enc.Encode(end); err != nil {
			fmt.Fprintln(stderr, "tracertip:", err)
			return exitFail
		}
		return exitOK
	}
	writeHops(stdout, probes, end)
	return exitOK
}

// writeHops prints one line per TTL: addresses seen, minimum RTT and replies.
// '*' marks a TTL with no reply: a gap, never 0 ms.
func writeHops(w io.Writer, probes []model.Probe, end model.End) {
	type hop struct {
		addrs   map[string]bool
		min     int64
		replied int
		sent    int
	}
	hops := map[int]*hop{}
	for _, p := range probes {
		h := hops[p.TTL]
		if h == nil {
			h = &hop{addrs: map[string]bool{}, min: -1}
			hops[p.TTL] = h
		}
		h.sent++
		if p.Status == model.StatusReply {
			h.replied++
		}
		for _, r := range p.Replies {
			if r.Late {
				continue
			}
			h.addrs[r.From] = true
			if h.min < 0 || r.RTTNS < h.min {
				h.min = r.RTTNS
			}
		}
	}
	ttls := make([]int, 0, len(hops))
	for t := range hops {
		ttls = append(ttls, t)
	}
	sort.Ints(ttls)
	for _, t := range ttls {
		if end.Reached && t > end.Hops {
			break
		}
		h := hops[t]
		if h.min < 0 {
			fmt.Fprintf(w, "%2d  *\n", t)
			continue
		}
		addrs := make([]string, 0, len(h.addrs))
		for a := range h.addrs {
			addrs = append(addrs, a)
		}
		sort.Strings(addrs)
		fmt.Fprintf(w, "%2d  %-40s %8.1f ms  %d/%d\n", t, strings.Join(addrs, " "), float64(h.min)/1e6, h.replied, h.sent)
	}
	fmt.Fprintf(w, "reached=%t probes=%d no_reply=%d %d ms\n", end.Reached, end.Probes, end.NoReply, end.DurationMS)
}

func random16() uint16 {
	var b [2]byte
	if _, err := rand.Read(b[:]); err != nil || binary.BigEndian.Uint16(b[:]) == 0 {
		return 0x7472 // "tr": fixed fallback, never zero
	}
	return binary.BigEndian.Uint16(b[:])
}
