package probe

import (
	"context"
	"encoding/binary"
	"errors"
	"net/netip"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/rbn8080/tracertip/01_engine/internal/model"
)

// fakeNet answers probes like a path: router i at TTL i, silent TTLs, and an
// Echo Reply once the TTL reaches the target's distance.
type fakeNet struct {
	target  netip.Addr
	dist    int
	silent  map[int]bool
	delay   time.Duration
	replies chan delivery
	src     netip.Addr // IPv6: the node's address, covered by the checksum

	mu    sync.Mutex
	flows map[[2]uint16]int // (id, checksum) seen on the wire
	sent  int
}

func newFakeNet(target netip.Addr, dist int) *fakeNet {
	return &fakeNet{target: target, dist: dist, silent: map[int]bool{}, delay: 3 * time.Millisecond,
		replies: make(chan delivery, 1024), flows: map[[2]uint16]int{}}
}

type delivery struct {
	b []byte
	m Meta
}

func (f *fakeNet) Send(dst netip.Addr, ttl int, icmp []byte) error {
	f.mu.Lock()
	f.flows[[2]uint16{binary.BigEndian.Uint16(icmp[4:]), binary.BigEndian.Uint16(icmp[2:])}]++
	f.sent++
	f.mu.Unlock()
	if f.target.Is6() {
		return f.send6(dst, ttl, icmp)
	}
	if !checksumOK(icmp) {
		panic("probe with a bad checksum")
	}
	var pkt []byte
	switch {
	case ttl >= f.dist:
		pkt = ipv4(f.target, 57, ttl, echoReply(icmp))
	case f.silent[ttl]:
		return nil
	default:
		pkt = ipv4(netip.AddrFrom4([4]byte{192, 0, 2, byte(ttl)}), 255-ttl, ttl, timeExceeded(dst, icmp))
	}
	time.AfterFunc(f.delay, func() { f.replies <- delivery{b: pkt} })
	return nil
}

func (f *fakeNet) send6(dst netip.Addr, ttl int, icmp []byte) error {
	if !checksum6OK(f.src, dst, icmp) {
		panic("ICMPv6 probe with a bad checksum")
	}
	var d delivery
	switch {
	case ttl >= f.dist:
		m := append([]byte(nil), icmp...)
		m[0] = icmp6EchoReply
		d = delivery{b: m, m: Meta{From: f.target, HopLimit: 57}}
	case f.silent[ttl]:
		return nil
	default:
		q := make([]byte, ipv6Header)
		q[0], q[6], q[7] = 0x60, protoICMPv6, 1
		t := dst.As16()
		copy(q[24:], t[:])
		m := append([]byte{icmp6TimeExceed, 0, 0, 0, 0, 0, 0, 0}, q...)
		m = append(m, icmp[:8]...)
		router := netip.MustParseAddr("2001:db8::")
		for i := 0; i < ttl; i++ {
			router = router.Next()
		}
		d = delivery{b: m, m: Meta{From: router, HopLimit: 64 - ttl}}
	}
	time.AfterFunc(f.delay, func() { f.replies <- d })
	return nil
}

func (f *fakeNet) Recv(buf []byte, deadline time.Time) (int, Meta, error) {
	t := time.NewTimer(time.Until(deadline))
	defer t.Stop()
	select {
	case d := <-f.replies:
		return copy(buf, d.b), d.m, nil
	case <-t.C:
		return 0, Meta{}, os.ErrDeadlineExceeded
	}
}

func (f *fakeNet) Close() error { return nil }

func TestTrace(t *testing.T) {
	target := netip.MustParseAddr("198.51.100.7")
	net := newFakeNet(target, 4)
	net.silent[2] = true
	cfg := Config{Target: target, TTLMax: 10, Rounds: 3, Timeout: 50 * time.Millisecond,
		RoundInterval: 60 * time.Millisecond, Spacing: time.Millisecond, ICMPID: 0x1234, FlowID: 0xbeef}

	var recs []model.Probe
	sum, err := Trace(context.Background(), net, cfg, func(p model.Probe) error {
		recs = append(recs, p)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if !sum.Reached || sum.TargetTTL != 4 {
		t.Errorf("summary %+v, want target reached at TTL 4", sum)
	}
	if len(net.flows) != 1 || net.flows[[2]uint16{0x1234, 0xbeef}] != net.sent {
		t.Errorf("flows on the wire %v: want one flow for all %d probes", net.flows, net.sent)
	}
	if sum.Probes != len(recs) || sum.Probes != net.sent {
		t.Errorf("summary %d probes, %d records, %d sent", sum.Probes, len(recs), net.sent)
	}
	for _, r := range recs {
		want := model.StatusReply
		if r.TTL == 2 {
			want = model.StatusNoReply
		}
		if r.Status != want {
			t.Errorf("round %d TTL %d: status %q, want %q", r.Round, r.TTL, r.Status, want)
		}
		if r.Round > 0 && r.TTL > 4+beyondTarget {
			t.Errorf("round %d probed TTL %d beyond the target cap", r.Round, r.TTL)
		}
		for _, rep := range r.Replies {
			if rep.RTTNS <= 0 || len(rep.Raw) == 0 {
				t.Errorf("TTL %d: reply without RTT or raw bytes: %+v", r.TTL, rep)
			}
			if r.TTL < 4 && (rep.ICMPType != icmpTimeExceed || rep.QTTL != 1) {
				t.Errorf("TTL %d: %+v, want Time Exceeded quoting TTL 1", r.TTL, rep)
			}
		}
	}
	seen := map[[2]int]bool{}
	for i, r := range recs {
		if i > 0 && recs[i-1].Round > r.Round {
			t.Fatalf("rounds interleaved: round %d after round %d", r.Round, recs[i-1].Round)
		}
		if k := [2]int{r.Round, r.TTL}; seen[k] {
			t.Fatalf("round %d TTL %d emitted twice", r.Round, r.TTL)
		} else {
			seen[k] = true
		}
	}
}

// A reply goes out at once: it does not wait for its probe's timeout, nor
// for a silent TTL before it in the same round. The silent one goes out when
// its time is up, and no probe of the next round overtakes it.
func TestTraceEmitsRepliesAtOnce(t *testing.T) {
	target := netip.MustParseAddr("198.51.100.7")
	net := newFakeNet(target, 4)
	net.silent[2] = true
	cfg := Config{Target: target, TTLMax: 6, Rounds: 2, Timeout: 300 * time.Millisecond,
		RoundInterval: 100 * time.Millisecond, Spacing: time.Millisecond, ICMPID: 1, FlowID: 2}
	type out struct {
		p   model.Probe
		lag time.Duration
	}
	var got []out
	_, err := Trace(context.Background(), net, cfg, func(p model.Probe) error {
		got = append(got, out{p, time.Since(p.SendWall)})
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	silentSeen := map[int]bool{}
	for _, o := range got {
		switch {
		case o.p.TTL == 2:
			if o.lag < cfg.Timeout-5*time.Millisecond { // SendWall is wall time (UTC strips the monotonic reading)
				t.Errorf("round %d: the silent TTL went out after %s, before its timeout", o.p.Round, o.lag)
			}
			silentSeen[o.p.Round] = true
		case o.p.Round == 0 && o.lag > cfg.Timeout/2:
			t.Errorf("round 0 TTL %d: reply went out %s after sending, want well before the %s timeout", o.p.TTL, o.lag, cfg.Timeout)
		case o.p.Round == 1 && !silentSeen[0]:
			t.Errorf("round 1 TTL %d went out before round 0's silent TTL", o.p.TTL)
		}
	}
}

// Watch mode: rounds go on, past the sequence wrap, until ctx ends.
func TestTraceContinuous(t *testing.T) {
	target := netip.MustParseAddr("198.51.100.7")
	net := newFakeNet(target, 2)
	// The timeout leaves the fake network's 3 ms reply room under -race on a busy machine.
	cfg := Config{Target: target, TTLMax: 10, Rounds: 0, Timeout: 50 * time.Millisecond,
		RoundInterval: time.Millisecond, Spacing: 0, ICMPID: 1, FlowID: 2}
	ctx, cancel := context.WithCancel(context.Background())
	last := -1
	_, err := Trace(ctx, net, cfg, func(p model.Probe) error {
		if p.Status != model.StatusReply {
			t.Errorf("round %d TTL %d: %s", p.Round, p.TTL, p.Status)
		}
		if last = p.Round; last >= maxRoundSeq+5 {
			cancel()
		}
		return nil
	})
	if !errors.Is(err, context.Canceled) || last < maxRoundSeq+5 {
		t.Errorf("err %v after round %d", err, last)
	}
}

func TestTraceIPv6(t *testing.T) {
	target := netip.MustParseAddr("2001:db8:ffff::7")
	net := newFakeNet(target, 3)
	net.src = netip.MustParseAddr("2001:db8:aaaa::1")
	cfg := Config{Target: target, Source: net.src, TTLMax: 8, Rounds: 2, Timeout: 50 * time.Millisecond,
		RoundInterval: 60 * time.Millisecond, Spacing: time.Millisecond, ICMPID: 0x4242, FlowID: 0x1111}
	var recs []model.Probe
	sum, err := Trace(context.Background(), net, cfg, func(p model.Probe) error { recs = append(recs, p); return nil })
	if err != nil {
		t.Fatal(err)
	}
	if !sum.Reached || sum.TargetTTL != 3 || len(net.flows) != 1 {
		t.Errorf("summary %+v, flows %v", sum, net.flows)
	}
	for _, r := range recs {
		for _, rep := range r.Replies {
			if r.TTL < 3 && (rep.ICMPType != icmp6TimeExceed || rep.QTTL != 1 || rep.IPTTL != 64-r.TTL) {
				t.Errorf("TTL %d: %+v, want Time Exceeded quoting hop limit 1", r.TTL, rep)
			}
			if r.TTL >= 3 && (rep.ICMPType != icmp6EchoReply || rep.From != target.String()) {
				t.Errorf("TTL %d: %+v, want an Echo Reply from the target", r.TTL, rep)
			}
		}
	}
	cfg.Source = netip.Addr{}
	if _, err := Trace(context.Background(), net, cfg, nil); err == nil {
		t.Error("IPv6 trace without a source address accepted")
	}
}

// Paris for ICMPv6: the checksum (which covers both addresses) stays constant.
func TestEchoRequest6ConstantFlow(t *testing.T) {
	src, dst := netip.MustParseAddr("2001:db8:aaaa::1"), netip.MustParseAddr("2001:db8:ffff::7")
	for ttl := 1; ttl <= 40; ttl++ {
		b := echoRequest6(src, dst, 0x4242, seqFor(3, ttl), 0x1111)
		if binary.BigEndian.Uint16(b[2:]) != 0x1111 || !checksum6OK(src, dst, b) || b[0] != icmp6Echo {
			t.Fatalf("TTL %d: % x", ttl, b[:8])
		}
	}
}

func FuzzParseReply6(f *testing.F) {
	f.Add([]byte{icmp6EchoReply, 0, 0, 0, 1, 2, 3, 4})
	f.Add(append([]byte{icmp6TimeExceed, 0, 0, 0, 0, 0, 0, 0, 0x60}, make([]byte, 60)...))
	f.Fuzz(func(t *testing.T, b []byte) {
		r, err := parseReply6(b, Meta{})
		if err == nil && len(r.icmp) != len(b) {
			t.Fatal("ICMPv6 length changed")
		}
	})
}
