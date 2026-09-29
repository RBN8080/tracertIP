//go:build !windows

package ipdb

import "os"

// syncDir makes the renames in dir survive a power cut.
func syncDir(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}
