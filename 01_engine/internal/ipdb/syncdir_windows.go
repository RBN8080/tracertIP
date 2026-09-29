package ipdb

// syncDir is a no-op: Windows cannot fsync a folder, and the engine only
// measures on Linux.
func syncDir(string) error { return nil }
