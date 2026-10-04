// Package probe sends Paris-style ICMP Echo probes with increasing TTL to one
// target and records every reply. It only measures; enrichment and judgement
// happen elsewhere.
package probe

import (
	"context"
	"errors"
	"net/netip"
	"os"
	"sort"
	"sync"
	"time"

	"github.com/rbn8080/tracertip/01_engine/internal/model"
)

// Conn sends ICMP messages with a given TTL (IPv6: hop limit). For IPv4, Recv
// returns whole packets; for IPv6 the kernel strips the header, so the sender
// and hop limit come in Meta (RFC 3542).
type Conn interface {
	Send(dst netip.Addr, ttl int, icmp []byte) error
	Recv(buf []byte, deadline time.Time) (int, Meta, error)
	Close() error
}

// Meta is what an IPv6 receive reports outside the ICMPv6 message.
type Meta struct {
	From     netip.Addr
	HopLimit int
}

// Config holds the probing parameters (00_IDEA 1.bis frontier).
type Config struct {
	Target        netip.Addr
	Source        netip.Addr    // IPv6 only: the checksum covers it (RFC 8200 8.1)
	TTLMax        int           // 40: longest Phase 0 path was 31 hops
	Rounds        int           // rounds of TTL 1..cap; 0 = until ctx ends (watch)
	Timeout       time.Duration // 2000 ms per probe; worst Phase 0 RTT was 842 ms
	RoundInterval time.Duration // one round every 2 s per target
	Spacing       time.Duration // between TTLs of a round, against ICMP rate limits
	ICMPID        uint16
	FlowID        uint16 // constant checksum = the flow load balancers hash
}

// Defaults are the frontier values (00_IDEA 1.bis; RFC 1812 4.3.2.8;
// Ravaioli et al., ICC 2015: stagger probes instead of bursting).
var Defaults = Config{
	TTLMax:        40,
	Rounds:        10,
	Timeout:       2000 * time.Millisecond,
	RoundInterval: 2000 * time.Millisecond,
	Spacing:       40 * time.Millisecond,
}

// beyondTarget is how many TTLs past the target's distance keep being probed.
const beyondTarget = 2

// Summary describes a finished trace.
type Summary struct {
	Reached    bool
	TargetTTL  int // TTL of the first Echo Reply from the target; 0 if never
	Probes     int
	NoReply    int
	SendErrors int // probes the node could not send
	LateLost   int // replies that came after their probe was already written
}

type pending struct {
	rec  model.Probe
	sent time.Time // monotonic
}

// Trace probes cfg.Target and calls emit for each probe as soon as it has an
// on-time reply, or once it can no longer get one. Rounds never interleave:
// no probe of a round comes out before every probe of the rounds before it,
// but within a round a reply may overtake a TTL still waiting for its own.
// In the second study rehearsal no probe drew more than one reply (613 514
// probes, evidence 2_119), so emitting at the first loses nothing measured;
// a later reply is counted in LateLost.
func Trace(ctx context.Context, c Conn, cfg Config, emit func(model.Probe) error) (Summary, error) {
	v6 := cfg.Target.Is6() && !cfg.Target.Is4In6()
	if v6 && !cfg.Source.Is6() {
		return Summary{}, errors.New("probe: an IPv6 target needs the IPv6 source address")
	}
	start := time.Now()
	var (
		mu       sync.Mutex
		inflight = map[uint16]*pending{}
		sum      Summary
		capTTL   = cfg.TTLMax
	)

	recvDone := make(chan struct{})
	stop := make(chan struct{})
	wake := make(chan struct{}, 1) // an on-time reply came in: its probe can go out
	go func() {
		defer close(recvDone)
		buf := make([]byte, 65535)
		for {
			select {
			case <-stop:
				return
			default:
			}
			n, meta, err := c.Recv(buf, time.Now().Add(100*time.Millisecond))
			if err != nil {
				if errors.Is(err, os.ErrDeadlineExceeded) {
					continue
				}
				return
			}
			now := time.Now()
			var r reply
			if v6 {
				r, err = parseReply6(buf[:n], meta)
			} else {
				r, err = parseReply(buf[:n])
			}
			if err != nil || r.id != cfg.ICMPID || r.dst != cfg.Target {
				continue
			}
			mu.Lock()
			p, ok := inflight[r.seq]
			if !ok {
				sum.LateLost++
			} else {
				rtt := now.Sub(p.sent)
				late := rtt > cfg.Timeout
				p.rec.Replies = append(p.rec.Replies, model.Reply{
					RecvWall: now.UTC(), RTTNS: rtt.Nanoseconds(), Late: late,
					From: r.from.String(), ICMPType: r.icmpType, ICMPCode: r.icmpCode,
					IPTTL: r.ipTTL, IPID: r.ipID, IPLen: r.ipLen,
					QTTL: r.qTTL, QIPID: r.qIPID, QLen: r.qLen,
					Raw: append([]byte(nil), r.icmp...),
				})
				if !late {
					select {
					case wake <- struct{}{}:
					default:
					}
				}
				if r.echo && r.from == cfg.Target && !late {
					_, ttl := splitSeq(r.seq)
					if !sum.Reached || ttl < sum.TargetTTL {
						sum.Reached, sum.TargetTTL = true, ttl
					}
					capTTL = min(cfg.TTLMax, sum.TargetTTL+beyondTarget)
				}
			}
			mu.Unlock()
		}
	}()
	var once sync.Once
	stopRecv := func() {
		once.Do(func() {
			close(stop)
			<-recvDone
		})
	}
	defer stopRecv()
	result := func(err error) (Summary, error) {
		stopRecv()
		mu.Lock()
		defer mu.Unlock()
		return sum, err
	}

	sendErr := func(rec *model.Probe, err error) {
		rec.Status, rec.Error = model.StatusSendError, err.Error()
	}
	var order []uint16
	// done: the probe has an on-time reply or its time is up. Call with mu held.
	done := func(p *pending, until time.Time, all bool) bool {
		if all || p.sent.Add(cfg.Timeout).Before(until) {
			return true
		}
		for _, r := range p.rec.Replies {
			if !r.Late {
				return true
			}
		}
		return false
	}
	flush := func(until time.Time, all bool) error {
		mu.Lock()
		block := -1 // the oldest round with a probe still waiting: later rounds wait for it
		for _, s := range order {
			if p := inflight[s]; !done(p, until, all) && (block < 0 || p.rec.Round < block) {
				block = p.rec.Round
			}
		}
		var ready []*pending
		keep := order[:0]
		for _, s := range order {
			p := inflight[s]
			if done(p, until, all) && (block < 0 || p.rec.Round <= block) {
				ready = append(ready, p)
				delete(inflight, s)
			} else {
				keep = append(keep, s)
			}
		}
		order = keep
		mu.Unlock()
		sort.SliceStable(ready, func(i, j int) bool {
			a, b := ready[i].rec, ready[j].rec
			return a.Round < b.Round || a.Round == b.Round && a.SendMonoNS < b.SendMonoNS
		})
		for _, p := range ready {
			mu.Lock()
			rec := p.rec
			rec.Replies = append([]model.Reply(nil), p.rec.Replies...)
			mu.Unlock()
			if rec.Status == "" {
				rec.Status = model.StatusNoReply
				for _, r := range rec.Replies {
					if !r.Late {
						rec.Status = model.StatusReply
						break
					}
				}
			}
			mu.Lock()
			sum.Probes++
			switch rec.Status {
			case model.StatusNoReply:
				sum.NoReply++
			case model.StatusSendError:
				sum.SendErrors++
			}
			mu.Unlock()
			if err := emit(rec); err != nil {
				return err
			}
		}
		return nil
	}

	// pause waits d, handing on every probe that gets its reply or runs out of
	// time meanwhile, the moment it does.
	pause := func(d time.Duration) error {
		end := time.Now().Add(d)
		for {
			wait := time.Until(end)
			mu.Lock()
			for _, s := range order {
				wait = min(wait, time.Until(inflight[s].sent.Add(cfg.Timeout)))
			}
			mu.Unlock()
			t := time.NewTimer(max(wait, 0))
			select {
			case <-ctx.Done():
				t.Stop()
				return ctx.Err()
			case <-wake:
			case <-t.C:
			}
			t.Stop()
			if err := flush(time.Now(), false); err != nil {
				return err
			}
			if !time.Now().Before(end) {
				return nil
			}
		}
	}

	for round := 0; cfg.Rounds == 0 || round < cfg.Rounds; round++ {
		roundStart := time.Now()
		for ttl := 1; ; ttl++ {
			mu.Lock()
			last := capTTL
			mu.Unlock()
			if ttl > last {
				break
			}
			seq := seqFor(round, ttl)
			now := time.Now()
			p := &pending{sent: now, rec: model.Probe{
				V: model.SchemaVersion, Type: model.TypeProbe,
				Round: round, TTL: ttl, ICMPID: int(cfg.ICMPID), Seq: int(seq), FlowID: int(cfg.FlowID),
				SendWall: now.UTC(), SendMonoNS: now.Sub(start).Nanoseconds(),
			}}
			mu.Lock()
			inflight[seq] = p
			order = append(order, seq)
			mu.Unlock()
			msg := echoRequest(cfg.ICMPID, seq, cfg.FlowID)
			if v6 {
				msg = echoRequest6(cfg.Source, cfg.Target, cfg.ICMPID, seq, cfg.FlowID)
			}
			if err := c.Send(cfg.Target, ttl, msg); err != nil {
				mu.Lock()
				sendErr(&p.rec, err)
				mu.Unlock()
			}
			if err := pause(cfg.Spacing); err != nil {
				return result(err)
			}
		}
		if cfg.Rounds == 0 || round < cfg.Rounds-1 {
			if err := pause(time.Until(roundStart.Add(cfg.RoundInterval))); err != nil {
				return result(err)
			}
		}
	}
	// Wait for the last probes' timeout; late replies may still arrive.
	if err := pause(cfg.Timeout); err != nil {
		return result(err)
	}
	return result(flush(time.Now(), true))
}
