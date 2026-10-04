package main

import (
	"context"
	"maps"
	"net/netip"
	"sync"

	"github.com/rbn8080/tracertip/01_engine/internal/enrich"
	"github.com/rbn8080/tracertip/01_engine/internal/judge"
	"github.com/rbn8080/tracertip/01_engine/internal/live"
	"github.com/rbn8080/tracertip/01_engine/internal/model"
	"github.com/rbn8080/tracertip/01_engine/internal/output"
)

// asnCache holds the AS lookups the analyzers and the API share.
type asnCache struct {
	mu      sync.Mutex
	known   map[netip.Addr]int
	resolve live.Resolver
}

func newASNCache(resolve live.Resolver) *asnCache {
	return &asnCache{known: map[netip.Addr]int{}, resolve: resolve}
}

// Resolve answers from the cache and looks up only what it lacks.
func (c *asnCache) Resolve(ctx context.Context, addrs []netip.Addr) (map[netip.Addr]int, error) {
	c.mu.Lock()
	var fresh []netip.Addr
	for _, a := range addrs {
		if _, ok := c.known[a]; !ok {
			fresh = append(fresh, a)
		}
	}
	c.mu.Unlock()
	var got map[netip.Addr]int
	if len(fresh) > 0 {
		var err error
		if got, err = c.resolve(ctx, fresh); err != nil {
			return nil, err
		}
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, a := range fresh {
		c.known[a] = got[a]
	}
	out := make(map[netip.Addr]int, len(addrs))
	for _, a := range addrs {
		out[a] = c.known[a]
	}
	return out, nil
}

// home is the public-output rule: special-purpose addresses, the access
// ISP's, and any address not looked up yet (fail-safe: Saltzer and
// Schroeder, 1975) stay hidden.
func (c *asnCache) home(accessASN int) func(netip.Addr) bool {
	return func(a netip.Addr) bool {
		if class, _ := enrich.Classify(a); class != enrich.ClassPublic {
			return true
		}
		c.mu.Lock()
		asn, ok := c.known[a]
		c.mu.Unlock()
		return !ok || accessASN != 0 && asn == accessASN
	}
}

// hopJudge judges a target's recent rounds as trace does, enriching each
// address once.
type hopJudge struct {
	mu    sync.Mutex
	cfg   config
	opts  enrich.Options
	known map[netip.Addr]enrich.Info
}

func (j *hopJudge) hops(ctx context.Context, target netip.Addr, rounds []live.Round, public bool) (any, error) {
	probes := roundProbes(target, rounds)
	hops := judge.Hops(probes, target)
	j.mu.Lock()
	defer j.mu.Unlock()
	var fresh []netip.Addr
	for _, h := range hops {
		for _, a := range h.Addrs {
			if _, ok := j.known[a]; !ok {
				fresh = append(fresh, a)
			}
		}
	}
	if len(fresh) > 0 {
		ectx, cancel := context.WithTimeout(ctx, enrichWait)
		defer cancel()
		info, err := enrich.Enrich(ectx, fresh, j.opts)
		if err != nil {
			return nil, err
		}
		maps.Copy(j.known, info)
	}
	return output.Records(hops, judge.Judge(hops, j.known, j.cfg.Origin), j.known, j.cfg.AccessASN, public), nil
}

// roundProbes gives rounds back the shape of probe records, enough for the
// judge: who answered each TTL, how fast, and whether it was the target.
func roundProbes(target netip.Addr, rounds []live.Round) []model.Probe {
	echo := 0
	if target.Is6() {
		echo = 129
	}
	var out []model.Probe
	for i, r := range rounds {
		for _, s := range r.Samples {
			p := model.Probe{Round: i, TTL: s.TTL, Status: s.Status}
			if s.From.IsValid() {
				typ := 11 // Time Exceeded; only the target's Echo Reply matters to the judge
				if s.From == target {
					typ = echo
				}
				p.Replies = []model.Reply{{From: s.From.String(), RTTNS: int64(s.RTTms * 1e6), ICMPType: typ}}
			}
			out = append(out, p)
		}
	}
	return out
}
