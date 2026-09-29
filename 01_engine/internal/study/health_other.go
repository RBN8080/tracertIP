//go:build !linux

package study

// Health is unknown off Linux: the study only runs on the node.
func Health(string) (float64, int64) { return 0, 0 }
