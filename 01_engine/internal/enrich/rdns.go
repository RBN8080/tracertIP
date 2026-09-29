package enrich

import (
	"context"
	"net"
	"net/netip"
	"strings"
	"sync"
	"time"
)

// PTR lookups: bounded time and concurrency, so names never push a trace past
// its budget.
const (
	ptrTimeout     = 2 * time.Second
	ptrConcurrency = 8
)

// newResolver uses the system resolver, or server ("host:port") if given. Some
// resolvers answer a PTR query with the query name itself; those answers are
// dropped (measured on the node's LAN resolver, 2026-09-28).
func newResolver(server string) *net.Resolver {
	if server == "" {
		return net.DefaultResolver
	}
	return &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, network, server)
	}}
}

func lookupNames(ctx context.Context, r *net.Resolver, addrs []netip.Addr) map[netip.Addr]string {
	var (
		mu  sync.Mutex
		wg  sync.WaitGroup
		out = map[netip.Addr]string{}
		sem = make(chan struct{}, ptrConcurrency)
	)
	for _, a := range addrs {
		wg.Add(1)
		sem <- struct{}{}
		go func() {
			defer wg.Done()
			defer func() { <-sem }()
			c, cancel := context.WithTimeout(ctx, ptrTimeout)
			defer cancel()
			names, err := r.LookupAddr(c, a.String())
			if err != nil || len(names) == 0 || bogusPTR(names[0]) {
				return
			}
			mu.Lock()
			out[a] = strings.TrimSuffix(names[0], ".")
			mu.Unlock()
		}()
	}
	wg.Wait()
	return out
}

func bogusPTR(name string) bool {
	return strings.HasSuffix(strings.TrimSuffix(strings.ToLower(name), "."), ".in-addr.arpa")
}
