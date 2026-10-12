package main

import (
	"runtime"
	"syscall"

	"golang.org/x/sys/unix"
)

// macOS has no *at variants of the xattr calls. Resolving the ciphertext path
// string again follows a directory that was swapped for a symlink after it was
// checked (the ciphertext directory may be shared or synced). The calls below
// name the entry by a single component relative to a directory fd instead, or
// go through an open file.

// xattrIO is the ciphertext entry the xattr calls of one operation go to.
type xattrIO interface {
	get(attr string, dest []byte) (int, error)
	set(attr string, data []byte, flags int) error
	remove(attr string) error
	list(dest []byte) (int, error)
}

// nameXattr is an entry of the calling thread's working directory (see
// inDirectory). The L* calls do not follow it if it is a symlink.
type nameXattr string

func (n nameXattr) get(attr string, dest []byte) (int, error) {
	return unix.Lgetxattr(string(n), attr, dest)
}
func (n nameXattr) set(attr string, data []byte, flags int) error {
	return unix.Lsetxattr(string(n), attr, data, flags)
}
func (n nameXattr) remove(attr string) error { return unix.Lremovexattr(string(n), attr) }
func (n nameXattr) list(dest []byte) (int, error) {
	return unix.Llistxattr(string(n), dest)
}

// fdXattr is an open file. It keeps working after the file was unlinked or
// replaced and its path names something else.
type fdXattr int

func (fd fdXattr) get(attr string, dest []byte) (int, error) {
	return unix.Fgetxattr(int(fd), attr, dest)
}
func (fd fdXattr) set(attr string, data []byte, flags int) error {
	return unix.Fsetxattr(int(fd), attr, data, flags)
}
func (fd fdXattr) remove(attr string) error { return unix.Fremovexattr(int(fd), attr) }
func (fd fdXattr) list(dest []byte) (int, error) {
	return unix.Flistxattr(int(fd), dest)
}

// inDirectory runs fn with the calling thread's working directory set to
// dirfd (__pthread_fchdir; other threads keep the process-wide one), so that
// fn can name an entry relative to it.
func inDirectory(dirfd int, fn func() error) error {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	if err := pthreadFchdir(dirfd); err != nil {
		return err
	}
	// -1 returns the thread to the process-wide working directory. A call from
	// C runs on the caller's thread, which must not keep ours.
	defer pthreadFchdir(-1)
	return fn()
}

func pthreadFchdir(fd int) error {
	if _, _, errno := unix.Syscall(unix.SYS___PTHREAD_FCHDIR, uintptr(fd), 0, 0); errno != 0 {
		return errno
	}
	return nil
}

// xattrOp runs fn on the ciphertext entry of plainPath, or of the open handle
// when handleID >= 0.
func (volume *Volume) xattrOp(plainPath string, handleID int, fn func(io xattrIO) error) error {
	if handleID >= 0 {
		f := volume.lockFile(handleID)
		if f == nil {
			return syscall.EBADF
		}
		defer f.fdLock.RUnlock()
		return fn(fdXattr(f.fd.Fd()))
	}
	dirfd, cName, err := volume.prepareAtSyscall(plainPath)
	if err != nil {
		return err
	}
	defer syscall.Close(dirfd)
	return inDirectory(dirfd, func() error { return fn(nameXattr(cName)) })
}
