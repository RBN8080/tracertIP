package live

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"math/rand/v2"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"time"

	"github.com/rbn8080/tracertip/01_engine/internal/ipdb"
	"github.com/rbn8080/tracertip/01_engine/internal/model"
	"github.com/rbn8080/tracertip/01_engine/internal/route"
)

// Fleet errors.
var (
	ErrFull    = fmt.Errorf("the frontier allows %d targets at once: remove one first", MaxTargets)
	ErrExists  = errors.New("already a target")
	ErrUnknown = errors.New("not a target")
	ErrInvalid = errors.New("not a target address: an IPv4 or IPv6 unicast address is needed")
)

// CheckTarget accepts IP addresses only, no names or ranges (00_IDEA 1.bis:
// it measures paths, it does not scan).
func CheckTarget(a netip.Addr) error {
	if !a.IsValid() || a.IsUnspecified() || a.IsLoopback() || a.IsMulticast() || a.IsLinkLocalUnicast() || a.IsInterfaceLocalMulticast() {
		return ErrInvalid
	}
	return nil
}

// Member is one target of the fleet with what follows it.
type Member struct {
	Monitor  *Monitor
	Analyzer *Analyzer
	Added    time.Time
	cancel   context.CancelFunc
	done     chan struct{}
}

// FleetConfig is what every member shares.
type FleetConfig struct {
	Monitor Config // OnRound is set per member
	Resolve Resolver
	Events  *route.Log
	Store   *Store
	Log     *slog.Logger
	// State is the folder of the saved list (targets.json) and its audit log
	// (targets-log.jsonl).
	State string
	// OnRound sees every finished round of every member, after its analyzer.
	OnRound func(Round)
	// OnChange sees the list after every addition or removal.
	OnChange func([]netip.Addr)
	// Fail stops the service: a member could not write its history or read
	// the bases (P5).
	Fail func(error)
}

// Fleet is the set of targets probed at once, at most MaxTargets. Targets
// are added and removed while it runs; the list survives restarts.
type Fleet struct {
	cfg FleetConfig
	ctx context.Context

	mu      sync.Mutex
	members map[netip.Addr]*Member
	order   []netip.Addr
}

// NewFleet loads the saved list (nil: none saved yet); Start begins probing.
func NewFleet(cfg FleetConfig) (*Fleet, []netip.Addr, error) {
	f := &Fleet{cfg: cfg, members: map[netip.Addr]*Member{}}
	saved, err := f.load()
	return f, saved, err
}

type savedList struct {
	V       int      `json:"v"`
	Targets []string `json:"targets"`
}

func (f *Fleet) listPath() string { return filepath.Join(f.cfg.State, "targets.json") }

func (f *Fleet) load() ([]netip.Addr, error) {
	b, err := os.ReadFile(f.listPath())
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var s savedList
	if err := json.Unmarshal(b, &s); err != nil {
		return nil, fmt.Errorf("%s: %w", f.listPath(), err)
	}
	out := []netip.Addr{} // a saved empty list is not "nothing saved"
	for _, t := range s.Targets {
		a, err := netip.ParseAddr(t)
		if err != nil || CheckTarget(a) != nil {
			return nil, fmt.Errorf("%s: %q is not a target address", f.listPath(), t)
		}
		out = append(out, a)
	}
	return out, nil
}

// Start probes targets until ctx ends.
func (f *Fleet) Start(ctx context.Context, targets []netip.Addr) error {
	f.ctx = ctx
	for _, a := range targets {
		if err := f.Add(a, "start"); err != nil {
			return fmt.Errorf("%s: %w", a, err)
		}
	}
	return nil
}

// Add starts following a; who is noted in the audit log.
func (f *Fleet) Add(a netip.Addr, who string) error {
	a = a.Unmap()
	if err := CheckTarget(a); err != nil {
		return err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if _, ok := f.members[a]; ok {
		return ErrExists
	}
	if len(f.members) >= MaxTargets {
		return ErrFull
	}
	mcfg := f.cfg.Monitor
	var an *Analyzer
	mcfg.OnRound = func(r Round) {
		an.Feed(r)
		if f.cfg.OnRound != nil {
			f.cfg.OnRound(r)
		}
	}
	m := NewMonitor(a, mcfg, uint16(rand.N(65535)+1), uint16(rand.N(65535)+1))
	an = NewAnalyzer(m, f.cfg.Resolve, f.cfg.Events, f.cfg.Store, f.cfg.Log)
	ctx, cancel := context.WithCancel(f.ctx)
	mem := &Member{Monitor: m, Analyzer: an, Added: time.Now(), cancel: cancel, done: make(chan struct{})}
	f.members[a] = mem
	f.order = append(f.order, a)
	if err := f.saveLocked(); err != nil {
		delete(f.members, a)
		f.order = f.order[:len(f.order)-1]
		cancel()
		return err
	}
	f.audit("add", a, who)
	go f.run(ctx, mem)
	f.changedLocked()
	return nil
}

// run follows one member. Its first round waits a random part of the round
// interval, so the targets' probes do not leave together (00_IDEA 5).
func (f *Fleet) run(ctx context.Context, mem *Member) {
	defer close(mem.done)
	var wg sync.WaitGroup
	fail := func(err error) {
		if err != nil && ctx.Err() == nil && f.cfg.Fail != nil {
			f.cfg.Fail(fmt.Errorf("%s: %w", mem.Monitor.Target, err))
		}
	}
	wg.Go(func() { fail(mem.Analyzer.Run(ctx)) })
	wg.Go(func() {
		jitter := time.Duration(rand.Int64N(int64(max(f.cfg.Monitor.Probe.RoundInterval, time.Millisecond))))
		t := time.NewTimer(jitter)
		select {
		case <-ctx.Done():
			t.Stop()
			return
		case <-t.C:
		}
		fail(mem.Monitor.Run(ctx))
	})
	wg.Wait()
}

// Remove stops following a and waits for it; its history stays on disk.
func (f *Fleet) Remove(a netip.Addr, who string) error {
	a = a.Unmap()
	f.mu.Lock()
	mem, ok := f.members[a]
	if !ok {
		f.mu.Unlock()
		return ErrUnknown
	}
	delete(f.members, a)
	f.order = slices.DeleteFunc(f.order, func(x netip.Addr) bool { return x == a })
	err := f.saveLocked()
	f.audit("remove", a, who)
	f.changedLocked()
	f.mu.Unlock()
	mem.cancel()
	<-mem.done
	return errors.Join(err, f.cfg.Store.CloseTarget(a))
}

// Members returns the targets in the order they were added.
func (f *Fleet) Members() []*Member {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]*Member, 0, len(f.order))
	for _, a := range f.order {
		out = append(out, f.members[a])
	}
	return out
}

// Get returns a's member.
func (f *Fleet) Get(a netip.Addr) (*Member, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	m, ok := f.members[a.Unmap()]
	return m, ok
}

// Wait waits for every member after the fleet's context ended.
func (f *Fleet) Wait() {
	for _, m := range f.Members() {
		<-m.done
	}
}

func (f *Fleet) saveLocked() error {
	s := savedList{V: 1, Targets: []string{}}
	for _, a := range f.order {
		s.Targets = append(s.Targets, a.String())
	}
	b, err := json.Marshal(s)
	if err != nil {
		return err
	}
	return ipdb.WriteAtomic(f.listPath(), append(b, '\n'), 0o644)
}

func (f *Fleet) changedLocked() {
	if f.cfg.OnChange != nil {
		f.cfg.OnChange(slices.Clone(f.order))
	}
}

// targetChange is one line of the audit log.
type targetChange struct {
	V      int       `json:"v"`
	Type   string    `json:"type"` // "target"
	Time   time.Time `json:"time"`
	Action string    `json:"action"` // "add" or "remove"
	Target string    `json:"target"`
	By     string    `json:"by"` // "start" or the client's address
}

func (f *Fleet) audit(action string, a netip.Addr, who string) {
	rec := targetChange{V: model.SchemaVersion, Type: "target", Time: time.Now().UTC(), Action: action, Target: a.String(), By: who}
	b, _ := json.Marshal(rec)
	fh, err := os.OpenFile(filepath.Join(f.cfg.State, "targets-log.jsonl"), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err == nil {
		_, err = fh.Write(append(b, '\n'))
		err = errors.Join(err, fh.Sync(), fh.Close())
	}
	if err != nil {
		f.cfg.Log.Error("audit log", "err", err)
	}
	f.cfg.Log.Info("target "+action, "target", a, "by", who)
}
