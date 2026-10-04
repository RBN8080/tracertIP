package live

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"sync"
	"time"

	"github.com/rbn8080/tracertip/01_engine/internal/model"
	"github.com/rbn8080/tracertip/01_engine/internal/probe"
)

// MaxTargets is the frontier's limit on targets probed at once (00_IDEA 1.bis).
const MaxTargets = 5

// RingRounds is the memory each target keeps: one hour at one round every 2 s,
// the longest window the live views draw. Older rounds are on disk.
const RingRounds = 1800

// DarkRounds is how many rounds in a row with no probe sent end a session:
// the node lost its route (an IPv6 default route that expired, RFC 4861) and
// the source address must be looked up again.
const DarkRounds = 5

// RestartWait is the pause before a new session after the node could not
// measure, so a long outage costs a log line every few seconds, not a loop.
const RestartWait = 10 * time.Second

var restartWait = RestartWait // shortened in tests

// State values of a monitor.
const (
	StateMeasuring = "measuring"
	StateNoRoute   = "no route"  // no source address for the target's family
	StateNoSocket  = "no socket" // raw socket refused (CAP_NET_RAW)
	StateDark      = "dark"      // probes not sent: the node's own outage
)

// Config is what every monitor shares.
type Config struct {
	Probe  probe.Config // TTLMax, Timeout, RoundInterval and Spacing
	Open   func(netip.Addr) (probe.Conn, error)
	Source func(netip.Addr) (netip.Addr, error)
	Store  *Store
	// Header gives the record that opens each session and each day's file.
	Header  func(target netip.Addr, pc probe.Config) any
	OnRound func(Round) // optional; runs on the monitor's goroutine
	Log     *slog.Logger
}

// Health is what a monitor reports about itself: "the network lost" against
// "I did not measure" (00_IDEA 4, block F).
type Health struct {
	Target     string    `json:"target"`
	State      string    `json:"state"`
	Error      string    `json:"error,omitempty"`
	Rounds     int64     `json:"rounds"`
	Probes     int64     `json:"probes"`
	Replied    int64     `json:"replied"`
	NoReply    int64     `json:"no_reply"`
	SendErrors int64     `json:"send_errors"`
	Sessions   int64     `json:"sessions"`
	LastRound  time.Time `json:"last_round,omitzero"`
	// LagMS is how late the last round started against the schedule.
	LagMS    float64 `json:"lag_ms"`
	MaxLagMS float64 `json:"max_lag_ms"`
}

// Monitor probes one target until its context ends.
type Monitor struct {
	Target netip.Addr
	Ring   *Ring
	cfg    Config
	pc     probe.Config // with this target's identifier and flow

	mu sync.Mutex
	h  Health
	n  int // rounds so far
}

// NewMonitor gives the target its own ICMP identifier and a flow that stays
// the same for the monitor's life, so a new path is a new route and not load
// balancing (Augustin et al., IMC 2006).
func NewMonitor(target netip.Addr, cfg Config, icmpID, flowID uint16) *Monitor {
	pc := cfg.Probe
	pc.Target, pc.Rounds, pc.ICMPID, pc.FlowID = target, 0, icmpID, flowID
	return &Monitor{Target: target, Ring: NewRing(RingRounds), cfg: cfg, pc: pc,
		h: Health{Target: target.String(), State: StateMeasuring}}
}

// Header is the record that opens the target's files.
func (m *Monitor) Header() any { return m.cfg.Header(m.Target, m.pc) }

// Health returns a copy of the monitor's health.
func (m *Monitor) Health() Health {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.h
}

// countLocked adds one probe to the health; false if it was never sent.
func (m *Monitor) countLocked(status string) bool {
	m.h.Probes++
	switch status {
	case model.StatusReply:
		m.h.Replied++
	case model.StatusNoReply:
		m.h.NoReply++
	case model.StatusSendError:
		m.h.SendErrors++
		return false
	}
	return true
}

func (m *Monitor) count(status string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.countLocked(status)
}

// Run measures in sessions until ctx ends. A session ends when the node
// cannot measure; the next one starts after RestartWait.
func (m *Monitor) Run(ctx context.Context) error {
	for {
		err := m.session(ctx)
		if ctx.Err() != nil {
			return nil
		}
		if _, ok := errors.AsType[*storeError](err); ok {
			return err // the history cannot be written: fail loudly (P5)
		}
		m.cfg.Log.Warn("session ended", "target", m.Target, "state", m.Health().State, "err", err)
		t := time.NewTimer(restartWait)
		select {
		case <-ctx.Done():
			t.Stop()
			return nil
		case <-t.C:
		}
	}
}

type storeError struct{ err error }

func (e *storeError) Error() string { return "history: " + e.err.Error() }
func (e *storeError) Unwrap() error { return e.err }

func (m *Monitor) setState(state string, err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.h.State, m.h.Error = state, ""
	if err != nil {
		m.h.Error = err.Error()
	}
}

func (m *Monitor) session(ctx context.Context) error {
	pc := m.pc
	if pc.Target.Is6() {
		src, err := m.cfg.Source(pc.Target)
		if err != nil {
			m.setState(StateNoRoute, err)
			return err
		}
		pc.Source = src
	}
	conn, err := m.cfg.Open(pc.Target)
	if err != nil {
		m.setState(StateNoSocket, err)
		return err
	}
	defer conn.Close()
	m.mu.Lock()
	m.h.Sessions++
	m.mu.Unlock()
	m.setState(StateMeasuring, nil)
	header := func() any { return m.cfg.Header(pc.Target, pc) }
	if err := m.cfg.Store.Write(pc.Target, time.Now(), nil, header()); err != nil {
		return &storeError{err}
	}

	sctx, cancel := context.WithCancel(ctx)
	defer cancel()
	var (
		round  []model.Probe
		cur    = -1
		last   int  // highest TTL of the previous round: the round is complete when it arrives
		closed bool // cur was finished early; a straggler goes to disk only
		dark   int
		failed error
		prev   time.Time // start of the previous round
	)
	finish := func() {
		if len(round) == 0 {
			return
		}
		r := Summarize(pc.Target, m.n, round)
		m.n++
		sent := 0
		m.mu.Lock()
		m.h.Rounds++
		for _, s := range r.Samples {
			if m.countLocked(s.Status) {
				sent++
			}
		}
		m.h.LastRound = r.Start
		if !prev.IsZero() {
			m.h.LagMS = max(0, float64(r.Start.Sub(prev)-pc.RoundInterval)/1e6)
			m.h.MaxLagMS = max(m.h.MaxLagMS, m.h.LagMS)
		}
		m.mu.Unlock()
		prev = r.Start
		m.Ring.Add(r)
		if m.cfg.OnRound != nil {
			m.cfg.OnRound(r)
		}
		if sent == 0 {
			dark++
		} else {
			dark = 0
		}
		if dark >= DarkRounds {
			m.setState(StateDark, fmt.Errorf("%d rounds in a row with no probe sent", dark))
			cancel()
		}
		last = 0
		for _, p := range round {
			last = max(last, p.TTL)
		}
		round = round[:0]
	}
	_, err = probe.Trace(sctx, conn, pc, func(p model.Probe) error {
		if p.Round != cur {
			finish()
			cur, closed = p.Round, false
		}
		if err := m.cfg.Store.Write(pc.Target, time.Now(), header, p); err != nil {
			failed = &storeError{err}
			return failed
		}
		if closed { // the path grew longer than last round's: rare, and the next round has it
			m.count(p.Status)
			return nil
		}
		round = append(round, p)
		if last > 0 && p.TTL >= last {
			finish() // without waiting a round interval for the next round's first probe
			closed = true
		}
		return nil
	})
	finish()
	if failed != nil {
		return failed
	}
	if m.Health().State == StateDark {
		return errors.New("node could not send probes")
	}
	return err
}
