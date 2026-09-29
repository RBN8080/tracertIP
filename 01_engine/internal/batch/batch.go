// Package batch keeps the state of batch mode: runs over a target list on
// fixed UTC slots that alternate the address family, and the replacement of
// a failing target by the reserve of its continent. Everything it writes
// survives a power cut.
package batch

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"time"

	"github.com/rbn8080/tracertip/01_engine/internal/ipdb"
	"github.com/rbn8080/tracertip/01_engine/internal/targets"
)

// Families.
const (
	V4 = "v4"
	V6 = "v6"
)

// FailLimit is the default number of runs of one family in a row a target
// may miss before the reserve replaces it.
const FailLimit = 4

// Entry is one target of the batch.
type Entry struct {
	ID        int        `json:"id,omitempty"` // anchor; 0 for a fixed target
	Continent string     `json:"continent,omitempty"`
	Country   string     `json:"country,omitempty"`
	Role      string     `json:"role"`
	IPv4      netip.Addr `json:"ip_v4,omitzero"`
	IPv6      netip.Addr `json:"ip_v6,omitzero"`
	ASv4      int        `json:"as_v4,omitempty"` // declared, checked daily
	ASv6      int        `json:"as_v6,omitempty"`
}

// AS is the entry's declared AS in a family.
func (e Entry) AS(fam string) int {
	if fam == V6 {
		return e.ASv6
	}
	return e.ASv4
}

// Addr is the entry's address in a family; invalid if it has none.
func (e Entry) Addr(fam string) netip.Addr {
	if fam == V6 {
		return e.IPv6
	}
	return e.IPv4
}

func (e Entry) key(fam string) string {
	if e.ID != 0 {
		return fmt.Sprintf("%d/%s", e.ID, fam)
	}
	return e.Addr(fam).String()
}

// Replacement records a target leaving the batch.
type Replacement struct {
	V      int       `json:"v"`
	Type   string    `json:"type"` // "replacement"
	Time   time.Time `json:"time"`
	Out    Entry     `json:"out"`
	In     *Entry    `json:"in"` // nil: the continent's reserve ran out
	Reason string    `json:"reason"`
}

// State is what the batch remembers between runs and restarts.
type State struct {
	FailLimit int                `json:"fail_limit"`
	Active    []Entry            `json:"active"`
	Reserve   map[string][]Entry `json:"reserve"` // by continent, in rank order
	Fails     map[string]int     `json:"fails"`   // runs missed in a row, by target and family
	Runs      int                `json:"runs"`
	LastRun   time.Time          `json:"last_run,omitzero"` // slot of the last run
	Checked   string             `json:"checked,omitempty"` // UTC day of the last revalidation
}

// NewState takes the validator's list: study and fixed targets that passed
// every check become active; the reserve keeps its rank order.
func NewState(list []targets.Target) (*State, error) {
	s := &State{FailLimit: FailLimit, Reserve: map[string][]Entry{}, Fails: map[string]int{}}
	for _, t := range list {
		if !t.Passed() {
			continue
		}
		e := Entry{ID: t.ID, Continent: t.Continent, Country: t.Country, Role: t.Role,
			IPv4: t.IPv4, IPv6: t.IPv6, ASv4: t.ASv4, ASv6: t.ASv6}
		switch t.Role {
		case targets.RoleStudy, targets.RoleFixed:
			s.Active = append(s.Active, e)
		case targets.RoleReserve:
			s.Reserve[t.Continent] = append(s.Reserve[t.Continent], e)
		}
	}
	if len(s.Active) == 0 {
		return nil, fmt.Errorf("no target passed its checks")
	}
	return s, nil
}

// Result records one trace. After s.FailLimit misses in a row, a study
// target is swapped, in place, for the next reserve of its continent; fixed
// targets are never replaced.
func (s *State) Result(i int, fam string, reached bool, now time.Time) *Replacement {
	e := s.Active[i]
	k := e.key(fam)
	if reached {
		delete(s.Fails, k)
		return nil
	}
	s.Fails[k]++
	if s.Fails[k] < s.FailLimit {
		return nil
	}
	return s.Replace(i, fmt.Sprintf("no echo reply over %s in %d runs in a row", fam, s.FailLimit), now)
}

// Replace swaps a study target, in place, for the next reserve of its
// continent, or drops it when the reserve is spent. Fixed targets stay.
func (s *State) Replace(i int, reason string, now time.Time) *Replacement {
	e := s.Active[i]
	if e.Role != targets.RoleStudy {
		return nil
	}
	delete(s.Fails, e.key(V4))
	delete(s.Fails, e.key(V6))
	r := &Replacement{V: 1, Type: "replacement", Time: now.UTC(), Out: e, Reason: reason}
	if q := s.Reserve[e.Continent]; len(q) > 0 {
		in := q[0]
		in.Role = targets.RoleStudy
		s.Reserve[e.Continent] = q[1:]
		s.Active[i] = in
		r.In = &in
	} else {
		s.Active = append(s.Active[:i], s.Active[i+1:]...)
	}
	return r
}

// Slot is the start of the slot holding t, with its family: slots are
// aligned to every in UTC and alternate IPv4 and IPv6.
func Slot(t time.Time, every time.Duration) (time.Time, string) {
	start := t.UTC().Truncate(every)
	if (start.UnixNano()/int64(every))%2 == 0 {
		return start, V4
	}
	return start, V6
}

// LoadState reads path; a missing file is no state yet.
func LoadState(path string) (*State, error) {
	b, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var s State
	if err := json.Unmarshal(b, &s); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return &s, nil
}

// Save replaces path atomically.
func (s *State) Save(path string) error {
	b, err := json.MarshalIndent(s, "", " ")
	if err != nil {
		return err
	}
	return ipdb.WriteAtomic(path, append(b, '\n'), 0o644)
}

// RunFile is one run's JSON Lines file. It is written as name.partial and
// synced after each trace, then renamed: a power cut leaves a partial file
// whose traces up to the last sync are whole.
type RunFile struct {
	f     *os.File
	enc   *json.Encoder
	final string
}

// CreateRun opens dir/YYYY-MM-DD/HHMMZ-<family>.jsonl.partial.
func CreateRun(dir string, slot time.Time, fam string) (*RunFile, error) {
	day := filepath.Join(dir, slot.UTC().Format("2006-01-02"))
	if err := os.MkdirAll(day, 0o755); err != nil {
		return nil, err
	}
	final := filepath.Join(day, slot.UTC().Format("1504Z")+"-"+fam+".jsonl")
	if _, err := os.Stat(final + ".partial"); err == nil {
		// A restart cut this slot's run: keep it apart, whole up to its last sync.
		if err := os.Rename(final+".partial", fmt.Sprintf("%s.aborted-%d", final, time.Now().Unix())); err != nil {
			return nil, err
		}
	}
	f, err := os.OpenFile(final+".partial", os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return nil, err
	}
	if err := ipdb.SyncDir(day); err != nil {
		f.Close()
		return nil, err
	}
	return &RunFile{f: f, enc: json.NewEncoder(f), final: final}, nil
}

// Write adds records; each is one write of one line.
func (r *RunFile) Write(recs ...any) error {
	for _, v := range recs {
		if err := r.enc.Encode(v); err != nil {
			return err
		}
	}
	return nil
}

// Sync makes what was written survive a power cut.
func (r *RunFile) Sync() error { return r.f.Sync() }

// Close syncs, closes and gives the file its final name.
func (r *RunFile) Close() error {
	err := r.f.Sync()
	if cerr := r.f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return err
	}
	return ipdb.Rename(r.f.Name(), r.final)
}

// Abort syncs and closes, keeping the .partial name: the run was cut short.
func (r *RunFile) Abort() error {
	err := r.f.Sync()
	if cerr := r.f.Close(); err == nil {
		err = cerr
	}
	return err
}

// ClockSynced says whether systemd-timesyncd has synchronized the clock;
// without it, wall times in the run cannot be trusted.
func ClockSynced() bool {
	_, err := os.Stat("/run/systemd/timesync/synchronized")
	return err == nil
}

// Append adds JSON lines to path and syncs them.
func Append(path string, recs ...any) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	_, statErr := os.Stat(path)
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return err
	}
	if os.IsNotExist(statErr) {
		err = ipdb.SyncDir(filepath.Dir(path))
	}
	enc := json.NewEncoder(f)
	for _, v := range recs {
		if err == nil {
			err = enc.Encode(v)
		}
	}
	if err == nil {
		err = f.Sync()
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	return err
}
