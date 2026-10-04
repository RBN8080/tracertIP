package batch

import (
	"strconv"
	"strings"
)

// vmRSSMB reads VmRSS from a /proc/<pid>/status text, in MB; zero if absent.
func vmRSSMB(status string) int64 {
	for line := range strings.Lines(status) {
		v, ok := strings.CutPrefix(line, "VmRSS:")
		if !ok {
			continue
		}
		if f := strings.Fields(v); len(f) > 0 {
			if kb, err := strconv.ParseInt(f[0], 10, 64); err == nil {
				return kb >> 10
			}
		}
	}
	return 0
}
