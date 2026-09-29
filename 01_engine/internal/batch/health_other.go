//go:build !linux

package batch

// Health is unknown off Linux: batch mode only runs there.
func Health(string) (float64, int64) { return 0, 0 }
