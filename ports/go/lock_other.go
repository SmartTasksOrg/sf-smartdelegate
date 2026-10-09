//go:build !(linux || darwin || freebsd || netbsd || openbsd || dragonfly || windows)

package smartdelegate

import "os"

// No file lock on this platform: one engine is still safe to share between
// goroutines, but a state directory must NOT be shared between processes.

func lockFile(f *os.File) error   { return nil }
func unlockFile(f *os.File) error { return nil }

const crossProcessLock = false
