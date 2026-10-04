package batch

import (
	"os"
	"strconv"
	"strings"
	"syscall"
)

// Health reads the node's temperature (°C) and the free space under dir
// (MB); zero means unknown.
func Health(dir string) (tempC float64, freeMB int64) {
	if b, err := os.ReadFile("/sys/class/thermal/thermal_zone0/temp"); err == nil {
		if m, err := strconv.Atoi(strings.TrimSpace(string(b))); err == nil {
			tempC = float64(m) / 1000
		}
	}
	var s syscall.Statfs_t
	if syscall.Statfs(dir, &s) == nil {
		freeMB = int64(s.Bavail) * int64(s.Bsize) >> 20
	}
	return tempC, freeMB
}

// RSSMB is this process's resident memory (MB), from /proc; zero if unknown.
func RSSMB() int64 {
	b, err := os.ReadFile("/proc/self/status")
	if err != nil {
		return 0
	}
	return vmRSSMB(string(b))
}
