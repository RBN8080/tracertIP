//go:build linux

package ipdb

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"syscall"
	"unsafe"
)

// promptNoEcho asks for a secret on a terminal with echo off (termios via
// syscall, no extra module). Not a terminal: it does not ask.
func promptNoEcho(in io.Reader, out io.Writer, prompt string) (string, error) {
	f, ok := in.(*os.File)
	if !ok {
		return "", nil
	}
	fd := f.Fd()
	var old syscall.Termios
	if _, _, e := syscall.Syscall(syscall.SYS_IOCTL, fd, syscall.TCGETS, uintptr(unsafe.Pointer(&old))); e != 0 {
		return "", nil // not a terminal
	}
	quiet := old
	quiet.Lflag &^= syscall.ECHO
	if _, _, e := syscall.Syscall(syscall.SYS_IOCTL, fd, syscall.TCSETS, uintptr(unsafe.Pointer(&quiet))); e != 0 {
		return "", fmt.Errorf("turning echo off: %w", e)
	}
	defer syscall.Syscall(syscall.SYS_IOCTL, fd, syscall.TCSETS, uintptr(unsafe.Pointer(&old)))
	fmt.Fprint(out, prompt)
	line, err := bufio.NewReader(f).ReadString('\n')
	fmt.Fprintln(out)
	if err != nil && !errors.Is(err, io.EOF) {
		return "", err
	}
	return line, nil
}
