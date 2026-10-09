//go:build windows

package smartdelegate

import (
	"os"
	"syscall"
	"unsafe"
)

// On Windows the lock is LockFileEx on the first byte of the `lock` file.
// The Python reference locks the same byte with msvcrt.locking, and both are
// mandatory byte-range locks, so they exclude each other. This path compiles
// but is not exercised by this port's tests (they run on Linux).

var procLockFileEx = syscall.NewLazyDLL("kernel32.dll").NewProc("LockFileEx")
var procUnlockFileEx = syscall.NewLazyDLL("kernel32.dll").NewProc("UnlockFileEx")

const lockfileExclusiveLock = 0x2

func lockFile(f *os.File) error {
	var ol syscall.Overlapped
	r, _, err := procLockFileEx.Call(f.Fd(), lockfileExclusiveLock, 0, 1, 0, uintptr(unsafe.Pointer(&ol)))
	if r == 0 {
		return err
	}
	return nil
}

func unlockFile(f *os.File) error {
	var ol syscall.Overlapped
	r, _, err := procUnlockFileEx.Call(f.Fd(), 0, 1, 0, uintptr(unsafe.Pointer(&ol)))
	if r == 0 {
		return err
	}
	return nil
}

const crossProcessLock = true
