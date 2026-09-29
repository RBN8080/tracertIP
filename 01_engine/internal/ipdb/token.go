package ipdb

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

// Token is a secret that never prints itself (clig.dev; log/slog LogValuer).
type Token struct{ s string }

func (Token) String() string           { return "[redacted]" }
func (Token) GoString() string         { return "[redacted]" }
func (Token) LogValue() slog.Value     { return slog.StringValue("[redacted]") }
func (t Token) Empty() bool            { return t.s == "" }
func (t Token) reveal() string         { return t.s }
func (t Token) redact(s string) string { return redactIn(s, t.s) }

// TokenOptions says where a token may come from, in this order.
type TokenOptions struct {
	File       string // --token-file; must not be readable by group or others
	Credential string // file name inside $CREDENTIALS_DIRECTORY (systemd LoadCredential)
	Prompt     string // shown when asking on a terminal; empty disables asking
	In         io.Reader
	Out        io.Writer
}

// ErrNoToken means no source gave a token; callers skip what needs one.
var ErrNoToken = errors.New("no token")

// LoadToken reads a token from a file, a systemd credential or, on a Linux
// terminal, a prompt without echo. Environment variables are not read: they
// leak to child processes (clig.dev; systemd.exec(5)).
func LoadToken(o TokenOptions) (Token, error) {
	if o.File != "" {
		return readTokenFile(o.File, true)
	}
	if dir := os.Getenv("CREDENTIALS_DIRECTORY"); dir != "" && o.Credential != "" {
		t, err := readTokenFile(filepath.Join(dir, o.Credential), false)
		if err == nil || !errors.Is(err, os.ErrNotExist) {
			return t, err
		}
	}
	if o.Prompt != "" && o.In != nil {
		s, err := promptNoEcho(o.In, o.Out, o.Prompt)
		if err != nil {
			return Token{}, err
		}
		if s = strings.TrimSpace(s); s != "" {
			return Token{s}, nil
		}
	}
	return Token{}, ErrNoToken
}

func readTokenFile(path string, checkMode bool) (Token, error) {
	f, err := os.Open(path)
	if err != nil {
		return Token{}, err
	}
	defer f.Close()
	if checkMode && runtime.GOOS != "windows" {
		st, err := f.Stat()
		if err != nil {
			return Token{}, err
		}
		if st.Mode().Perm()&0o077 != 0 {
			return Token{}, fmt.Errorf("%s is readable by group or others (mode %v); use chmod 600", path, st.Mode().Perm())
		}
	}
	line, err := bufio.NewReader(io.LimitReader(f, 4096)).ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return Token{}, err
	}
	if s := strings.TrimSpace(line); s != "" {
		return Token{s}, nil
	}
	return Token{}, fmt.Errorf("%s is empty", path)
}

func redactIn(s, secret string) string {
	if secret == "" {
		return s
	}
	return strings.ReplaceAll(s, secret, "[redacted]")
}
