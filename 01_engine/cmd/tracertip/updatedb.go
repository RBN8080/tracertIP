package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"time"

	"github.com/rbn8080/tracertip/01_engine/internal/ipdb"
)

// downloadTimeout bounds one base download (the largest was 86 MB).
const downloadTimeout = 10 * time.Minute

func defaultBasesDir() string {
	d, err := os.UserCacheDir()
	if err != nil {
		return "bases"
	}
	return filepath.Join(d, "tracertip", "bases")
}

func runUpdateDB(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("update-db", flag.ContinueOnError)
	fs.SetOutput(stderr)
	dir := fs.String("dir", defaultBasesDir(), "folder for the bases")
	only := fs.String("only", "", "comma-separated bases to update (default: all)")
	tokenFile := fs.String("token-file", "", "file with the IPinfo token (mode 0600); optional")
	noInput := fs.Bool("no-input", false, "never ask for a token")
	force := fs.Bool("force", false, "fetch even if the base in use is younger than its source's pace")
	fs.Usage = func() {
		fmt.Fprintln(stderr, "usage: tracertip update-db [flags]")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil || fs.NArg() != 0 {
		return exitUsage
	}
	var want []string
	if *only != "" {
		want = strings.Split(*only, ",")
	}
	if err := os.MkdirAll(*dir, 0o755); err != nil { // public data, read by other users
		fmt.Fprintln(stderr, "tracertip:", err)
		return exitFail
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	client := ipdb.NewClient(downloadTimeout)
	ipdb.UserAgent = "tracertip/" + version() + " (+https://github.com/RBN8080/tracertIP)"
	failed := false
	for _, src := range ipdb.Sources() {
		if want != nil && !slices.Contains(want, src.Name) {
			continue
		}
		due, cur, err := ipdb.Due(*dir, src, time.Now())
		if err != nil {
			fmt.Fprintf(stderr, "tracertip: %s: %v\n", src.Name, err)
			failed = true
			continue
		}
		if !due && !*force {
			fmt.Fprintf(stdout, "%-12s fresh: fetched %s (pace %s)\n", src.Name, cur.Date.Format(time.RFC3339), src.MinAge)
			continue
		}
		var tok ipdb.Token
		if src.NeedsToken {
			o := ipdb.TokenOptions{File: *tokenFile, Credential: "ipinfo-token", In: os.Stdin, Out: stderr}
			if !*noInput {
				o.Prompt = "IPinfo token (Enter to skip): "
			}
			var err error
			if tok, err = ipdb.LoadToken(o); err != nil {
				if errors.Is(err, ipdb.ErrNoToken) {
					fmt.Fprintf(stdout, "%-12s skipped: no token\n", src.Name)
					continue
				}
				fmt.Fprintf(stderr, "tracertip: %s: %v\n", src.Name, err)
				failed = true
				continue
			}
		}
		e, err := ipdb.Update(ctx, client, *dir, src, tok, time.Now())
		if err != nil {
			fmt.Fprintf(stderr, "tracertip: %v (the file in use is kept)\n", err)
			failed = true
			continue
		}
		fmt.Fprintf(stdout, "%-12s %9d rows  %s  sha256 %s\n", src.Name, e.Rows, e.Date.Format(time.RFC3339), e.SHA256[:16])
	}
	if failed {
		return exitFail
	}
	return exitOK
}
