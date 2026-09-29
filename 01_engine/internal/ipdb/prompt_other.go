//go:build !linux

package ipdb

import "io"

// promptNoEcho does not ask outside Linux: turning echo off needs a module
// beyond the standard library there. Use --token-file instead.
func promptNoEcho(io.Reader, io.Writer, string) (string, error) { return "", nil }
