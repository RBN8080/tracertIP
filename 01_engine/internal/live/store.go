package live

import (
	"compress/gzip"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/rbn8080/tracertip/01_engine/internal/ipdb"
)

// SyncEvery bounds what a power cut can take: at most this much of the newest
// records (Pillai et al., OSDI 2014). Syncing every round, 2.5 times a second
// with five targets, would cost the SSD for no gain in the analysis.
const SyncEvery = 10 * time.Second

// DefaultCap is the disk the history may use: about 57 days at the measured
// 0.30 GB a day with five targets (evidence 2_115), a fifth of the node's
// free disk (00_IDEA 5.bis).
const DefaultCap = 16 << 30

// Store writes each target's records as JSON Lines, one file per target and
// UTC day: dir/<target>/YYYY-MM-DD.jsonl. A day is gzipped once it closes,
// and the oldest days are removed while the history passes its cap. Each
// record is one write of one line, so a cut leaves at most a torn last line.
type Store struct {
	dir string
	cap int64

	mu       sync.Mutex
	files    map[netip.Addr]*dayFile
	lastSync time.Time
	bgErr    error          // a compression or trim that failed, reported by the next Write
	wg       sync.WaitGroup // compressions in flight
}

type dayFile struct {
	day string
	f   *os.File
}

// OpenStore prepares dir and compresses days a crash left uncompressed.
func OpenStore(dir string, capBytes int64, now time.Time) (*Store, error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, err
	}
	s := &Store{dir: dir, cap: capBytes, files: map[netip.Addr]*dayFile{}, lastSync: now}
	today := now.UTC().Format(time.DateOnly)
	err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		switch {
		case err != nil:
			return err
		case strings.HasSuffix(path, ".gz.tmp"):
			return os.Remove(path) // a compression the crash cut short; the .jsonl is still there
		case strings.HasSuffix(path, ".jsonl") && strings.TrimSuffix(d.Name(), ".jsonl") != today:
			return compress(path)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return s, s.trim()
}

// TargetDir names a target's folder; IPv6 colons are not valid on every
// file system.
func TargetDir(a netip.Addr) string { return strings.ReplaceAll(a.String(), ":", "-") }

// Write appends recs to target's file for now's UTC day. header gives the
// record that opens each new file.
func (s *Store) Write(target netip.Addr, now time.Time, header func() any, recs ...any) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.bgErr; err != nil {
		s.bgErr = nil
		return err
	}
	day := now.UTC().Format(time.DateOnly)
	df := s.files[target]
	if df != nil && df.day != day {
		if err := s.closeDay(target, df); err != nil {
			return err
		}
		df = nil
	}
	if df == nil {
		var err error
		if df, err = s.openDay(target, day); err != nil {
			return err
		}
		if header != nil {
			recs = append([]any{header()}, recs...)
		}
	}
	for _, r := range recs {
		b, err := json.Marshal(r)
		if err != nil {
			return err
		}
		if _, err := df.f.Write(append(b, '\n')); err != nil {
			return err
		}
	}
	if now.Sub(s.lastSync) >= SyncEvery {
		s.lastSync = now
		for _, f := range s.files {
			if err := f.f.Sync(); err != nil {
				return err
			}
		}
	}
	return nil
}

// Close syncs and closes every file and waits for compressions.
func (s *Store) Close() error {
	s.mu.Lock()
	var errs []error
	for _, df := range s.files {
		errs = append(errs, df.f.Sync(), df.f.Close())
	}
	s.files = map[netip.Addr]*dayFile{}
	s.mu.Unlock()
	s.wg.Wait()
	s.mu.Lock()
	defer s.mu.Unlock()
	return errors.Join(append(errs, s.bgErr)...)
}

func (s *Store) openDay(target netip.Addr, day string) (*dayFile, error) {
	dir := filepath.Join(s.dir, TargetDir(target))
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, err
	}
	path := filepath.Join(dir, day+".jsonl")
	_, statErr := os.Stat(path)
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return nil, err
	}
	if errors.Is(statErr, os.ErrNotExist) {
		if err := ipdb.SyncDir(dir); err != nil {
			f.Close()
			return nil, err
		}
	}
	df := &dayFile{day: day, f: f}
	s.files[target] = df
	return df, nil
}

// closeDay closes a finished day; compression and trimming run apart, so
// probing never waits for them.
func (s *Store) closeDay(target netip.Addr, df *dayFile) error {
	delete(s.files, target)
	if err := errors.Join(df.f.Sync(), df.f.Close()); err != nil {
		return err
	}
	path := df.f.Name()
	s.wg.Go(func() {
		err := compress(path)
		s.mu.Lock()
		defer s.mu.Unlock()
		if err == nil {
			err = s.trim()
		}
		s.bgErr = errors.Join(s.bgErr, err)
	})
	return nil
}

// compress replaces path with path.gz, safely: the original goes only once
// the compressed copy is synced under its final name.
func compress(path string) error {
	in, err := os.Open(path)
	if err != nil {
		return err
	}
	defer in.Close()
	tmp := path + ".gz.tmp"
	out, err := os.Create(tmp)
	if err != nil {
		return err
	}
	zw := gzip.NewWriter(out)
	_, err = io.Copy(zw, in)
	err = errors.Join(err, zw.Close(), out.Sync(), out.Close())
	if err == nil {
		err = os.Rename(tmp, path+".gz")
	}
	if err != nil {
		os.Remove(tmp)
		return err
	}
	in.Close()
	if err := os.Remove(path); err != nil {
		return err
	}
	return ipdb.SyncDir(filepath.Dir(path))
}

// trim removes the oldest compressed days while the history passes its cap.
// Open days are counted but never removed.
func (s *Store) trim() error {
	type file struct {
		path, day string
		size      int64
	}
	var files []file
	var total int64
	err := filepath.WalkDir(s.dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		total += info.Size()
		if day, ok := strings.CutSuffix(d.Name(), ".jsonl.gz"); ok {
			files = append(files, file{path, day, info.Size()})
		}
		return nil
	})
	if err != nil {
		return err
	}
	slices.SortFunc(files, func(a, b file) int { return strings.Compare(a.day+a.path, b.day+b.path) })
	for _, f := range files {
		if total <= s.cap {
			break
		}
		if err := os.Remove(f.path); err != nil {
			return err
		}
		total -= f.size
	}
	return nil
}
