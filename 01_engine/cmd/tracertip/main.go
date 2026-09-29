// Command tracertip traces the path to one IP and judges every hop.
package main

import (
	"fmt"
	"io"
	"os"
	"runtime/debug"
)

// Exit codes (clig.dev).
const (
	exitOK    = 0
	exitFail  = 1
	exitUsage = 2
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		usage(stderr)
		return exitUsage
	}
	switch args[0] {
	case "trace":
		return runTrace(args[1:], stdout, stderr)
	case "lookup":
		return runLookup(args[1:], os.Stdin, stdout, stderr)
	case "update-db":
		return runUpdateDB(args[1:], stdout, stderr)
	case "targets":
		return runTargets(args[1:], stdout, stderr)
	case "version":
		fmt.Fprintln(stdout, "tracertip", version())
		return exitOK
	case "help", "-h", "--help":
		usage(stdout)
		return exitOK
	}
	fmt.Fprintf(stderr, "tracertip: unknown command %q\n", args[0])
	usage(stderr)
	return exitUsage
}

func usage(w io.Writer) {
	fmt.Fprint(w, `usage: tracertip <command> [flags]

commands:
  trace     trace the path to an IPv4 or IPv6 target (Linux, needs CAP_NET_RAW)
  lookup    class, AS, name and location hints of IP addresses
  update-db download and verify the local IP bases
  targets   choose and check the study's destinations (RIPE Atlas anchors)
  version   print the version
  help      print this help
`)
}

// version comes from the module version and the VCS data Go embeds at build.
func version() string {
	bi, ok := debug.ReadBuildInfo()
	if !ok {
		return "unknown"
	}
	for _, s := range bi.Settings {
		if s.Key == "vcs.revision" && len(s.Value) >= 12 {
			return bi.Main.Version + " (" + s.Value[:12] + ")"
		}
	}
	return bi.Main.Version
}
