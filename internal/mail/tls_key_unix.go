//go:build !windows

package mail

import (
	"os"
	"syscall"
)

func openClientKey(path string) (*os.File, error) {
	return os.OpenFile(path, os.O_RDONLY|syscall.O_NONBLOCK, 0)
}
