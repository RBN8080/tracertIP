package probe

import (
	"context"
	"encoding/binary"
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
	replies chan []byte

	mu    sync.Mutex
	flows map[[2]uint16]int // (id, checksum) seen on the wire
	sent  int
}

func newFakeNet(target netip.Addr, dist int) *fakeNet {
	return &fakeNet{target: target, dist: dist, silent: map[int]bool{}, delay: 3 * time.Millisecond,
		replies: make(chan []byte, 1024), flows: map[[2]uint16]int{}}
}

func (f *fakeNet) Send(dst netip.Addr, ttl int, icmp []byte) error {
	f.mu.Lock()
	f.flows[[2]uint16{binary.BigEndian.Uint16(icmp[4:]), binary.BigEndian.Uint16(icmp[2:])}]++
	f.sent++
	f.mu.Unlock()
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
	time.AfterFunc(f.delay, func() { f.replies <- pkt })
	return nil
}

func (f *fakeNet) Recv(buf []byte, deadline time.Time) (int, error) {
	t := time.NewTimer(time.Until(deadline))
	defer t.Stop()
	select {
	case p := <-f.replies:
		return copy(buf, p), nil
	case <-t.C:
		return 0, os.ErrDeadlineExceeded
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
	for i := 1; i < len(recs); i++ {
		a, b := recs[i-1], recs[i]
		if a.Round > b.Round || (a.Round == b.Round && a.TTL >= b.TTL) {
			t.Fatalf("records out of order: (%d,%d) then (%d,%d)", a.Round, a.TTL, b.Round, b.TTL)
		}
	}
}

func TestTraceRejectsIPv6(t *testing.T) {
	cfg := Defaults
	cfg.Target = netip.MustParseAddr("2001:db8::1")
	if _, err := Trace(context.Background(), newFakeNet(cfg.Target, 1), cfg, nil); err == nil {
		t.Error("IPv6 target accepted")
	}
}
