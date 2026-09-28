package main

import (
	"bytes"
	"strings"
	"testing"
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
	} {
		var out, errb bytes.Buffer
		if got := run(tc.args, &out, &errb); got != tc.code {
			t.Errorf("%v: exit %d, want %d", tc.args, got, tc.code)
		}
		if !strings.Contains(out.String(), tc.stdout) || !strings.Contains(errb.String(), tc.stderr) {
			t.Errorf("%v: stdout %q, stderr %q", tc.args, out.String(), errb.String())
		}
	}
}
