package stats

import (
	"math"
	"math/rand/v2"
	"slices"
	"testing"
)

func exact(xs []float64, q float64) float64 {
	s := slices.Clone(xs)
	slices.Sort(s)
	return s[max(0, int(math.Ceil(q*float64(len(s))))-1)]
}

// A histogram percentile is the exact nearest-rank one or at most 1 % above.
func TestHistogramWithinOnePercent(t *testing.T) {
	r := rand.New(rand.NewPCG(1, 2))
	for _, tc := range []struct {
		name string
		gen  func() float64
	}{
		{"steady path", func() float64 { return 97 + r.ExpFloat64()*0.5 }},
		{"long tail", func() float64 { return 180 + r.ExpFloat64()*40 }},
		{"home router", func() float64 { return 0.4 + r.Float64()*0.2 }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var h Histogram
			xs := make([]float64, 1800)
			for i := range xs {
				xs[i] = tc.gen()
				h.Add(xs[i])
			}
			for _, q := range []float64{0.5, 0.95, 0.99} {
				got, ok := h.Quantile(q)
				want := exact(xs, q)
				if !ok || got < want || got > want*(1+histRelErr)+1e-9 {
					t.Errorf("p%.0f = %v (%t), exact %v", 100*q, got, ok, want)
				}
			}
		})
	}
}

// Merging histograms gives the percentiles of the union: windows combine
// without averaging percentiles.
func TestMergeIsUnion(t *testing.T) {
	var a, b, all Histogram
	for i := range 600 {
		v := 50 + float64(i%97)
		all.Add(v)
		if i%3 == 0 {
			a.Add(v)
		} else {
			b.Add(v)
		}
	}
	a.Merge(&b)
	for _, q := range []float64{0.5, 0.95, 0.99} {
		x, _ := a.Quantile(q)
		y, _ := all.Quantile(q)
		if x != y {
			t.Errorf("p%.0f merged %v, all %v", 100*q, x, y)
		}
	}
}

// Wilks: the median needs 5 samples, p95 59 and p99 299; with fewer, the
// percentile is absent.
func TestMinSamples(t *testing.T) {
	for q, want := range map[float64]uint64{0.5: 5, 0.95: 59, 0.99: 299} {
		if got := MinSamples(q); got != want {
			t.Errorf("MinSamples(%v) = %d, want %d", q, got, want)
		}
	}
	var h Histogram
	for range 58 {
		h.Add(100)
	}
	if _, ok := h.Quantile(0.95); ok {
		t.Error("p95 from 58 samples")
	}
	h.Add(100)
	if _, ok := h.Quantile(0.95); !ok {
		t.Error("no p95 from 59 samples")
	}
}

func TestSummarize(t *testing.T) {
	s := Summarize([]float64{10, -1, -1, 12, 11, -1, 13})
	if s.Sent != 7 || s.Replied != 4 || s.MaxBurst != 2 || *s.LossPct != 300.0/7 {
		t.Errorf("counts %+v loss %v", s, *s.LossPct)
	}
	if *s.MinMS != 10 || *s.MaxMS != 13 || s.P50MS != nil || s.P95MS != nil {
		t.Errorf("min %v max %v p50 %v p95 %v: want 10, 13 and no percentiles from 4 RTTs", *s.MinMS, *s.MaxMS, s.P50MS, s.P95MS)
	}
	// RFC 3550: J += (|D| - J)/16 over 10→12, 12→11, 11→13.
	j := 0.0
	for _, d := range []float64{2, 1, 2} {
		j += (d - j) / 16
	}
	if math.Abs(*s.JitterMS-j) > 1e-12 {
		t.Errorf("jitter %v, want %v", *s.JitterMS, j)
	}
	none := Summarize([]float64{-1, -1})
	if none.MinMS != nil || none.JitterMS != nil || *none.LossPct != 100 {
		t.Errorf("no replies: %+v", none)
	}
	if empty := Summarize(nil); empty.LossPct != nil {
		t.Errorf("no probes, loss %v: want absent", *empty.LossPct)
	}
}

// The last bucket reaches the largest RTT the histogram promises.
func TestBucketsCoverRange(t *testing.T) {
	if upper(histBuckets-1) < histMaxMS || upper(histBuckets-2) >= histMaxMS {
		t.Errorf("last bucket ends at %v, before it %v; want it to be the first to reach %v",
			upper(histBuckets-1), upper(histBuckets-2), float64(histMaxMS))
	}
}
