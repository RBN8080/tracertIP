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
	Reached   bool
	TargetTTL int // TTL of the first Echo Reply from the target; 0 if never
	Probes    int
	NoReply   int
	LateLost  int // replies that came after their probe was already written
}

type pending struct {
	rec  model.Probe
	sent time.Time // monotonic
}

// Trace probes cfg.Target and calls emit for each probe once it can no longer
// get an on-time reply, in (round, TTL) order within each round.
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
	flush := func(until time.Time, all bool) error {
		mu.Lock()
		var ready []*pending
		keep := order[:0]
		for _, s := range order {
			p := inflight[s]
			if all || p.sent.Add(cfg.Timeout).Before(until) {
				ready = append(ready, p)
				delete(inflight, s)
			} else {
				keep = append(keep, s)
			}
		}
		order = keep
		mu.Unlock()
		sort.SliceStable(ready, func(i, j int) bool { return ready[i].rec.SendMonoNS < ready[j].rec.SendMonoNS })
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
			if rec.Status == model.StatusNoReply {
				sum.NoReply++
			}
			mu.Unlock()
			if err := emit(rec); err != nil {
				return err
			}
		}
		return nil
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
			if err := sleep(ctx, cfg.Spacing); err != nil {
				return result(err)
			}
			if err := flush(time.Now(), false); err != nil {
				return result(err)
			}
		}
		if cfg.Rounds == 0 || round < cfg.Rounds-1 {
			if err := sleep(ctx, time.Until(roundStart.Add(cfg.RoundInterval))); err != nil {
				return result(err)
			}
			if err := flush(time.Now(), false); err != nil {
				return result(err)
			}
		}
	}
	// Wait for the last probes' timeout; late replies may still arrive.
	if err := sleep(ctx, cfg.Timeout); err != nil {
		return result(err)
	}
	return result(flush(time.Now(), true))
}

func sleep(ctx context.Context, d time.Duration) error {
	if d <= 0 {
		return ctx.Err()
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}
