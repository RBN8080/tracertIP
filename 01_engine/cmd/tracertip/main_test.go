package main

import (
	"bytes"
	"errors"
	"net/netip"
	"strings"
	"testing"

	"github.com/rbn8080/tracertip/01_engine/internal/probe"
)

func TestRunExitCodes(t *testing.T) {
	for _, tc := range []struct {
		args   []string
		code   int
		stdout string
		stderr string
	}{
		{nil, exitUsage, "", "usage:"},
		{[]string{"version"}, exitOK, "tracertip", ""},
		{[]string{"help"}, exitOK, "usage:", ""},
		{[]string{"nope"}, exitUsage, "", `unknown command "nope"`},
		{[]string{"trace"}, exitUsage, "", "usage: tracertip trace"},
		{[]string{"trace", "not-an-ip"}, exitUsage, "", "not an IP address"},
		{[]string{"trace", "-ttl-max", "41", "192.0.2.1"}, exitUsage, "", "ttl-max 1-40"},
		{[]string{"trace", "-rounds", "0", "192.0.2.1"}, exitUsage, "", "rounds must be"},
		{[]string{"trace", "192.0.2.1"}, exitFail, "", "no socket in tests"},
	} {
		open = func(netip.Addr) (probe.Conn, error) { return nil, errors.New("no socket in tests") }
		var out, errb bytes.Buffer
		if got := run(tc.args, &out, &errb); got != tc.code {
			t.Errorf("%v: exit %d, want %d", tc.args, got, tc.code)
		}
		if !strings.Contains(out.String(), tc.stdout) || !strings.Contains(errb.String(), tc.stderr) {
			t.Errorf("%v: stdout %q, stderr %q", tc.args, out.String(), errb.String())
		}
	}
}
