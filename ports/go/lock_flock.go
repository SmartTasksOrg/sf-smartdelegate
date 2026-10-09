//go:build linux || darwin || freebsd || netbsd || openbsd || dragonfly

package smartdelegate

import (
	"os"
	"syscall"
)

// The state directory lock is flock(2) on the `lock` file: the same lock the
// Python reference and the Rust port take, so the three can share a state
// directory.

func lockFile(f *os.File) error {
	for {
		err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX)
		if err != syscall.EINTR {
			return err
		}
	}
}

func unlockFile(f *os.File) error {
	return syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
}

// crossProcessLock reports whether lockFile excludes other processes.
const crossProcessLock = true
