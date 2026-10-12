package main

/*
#include <stdlib.h>
#include <string.h>
#include <sys/attr.h>
#include <unistd.h>

// setattrlist on an entry of dirfd, never following a symlink, or on fd itself
// when name is NULL.
static int gcfc_setattrlist(int fd, const char *name, attrgroup_t common, void *buf, size_t len) {
	struct attrlist al;
	memset(&al, 0, sizeof(al));
	al.bitmapcount = ATTR_BIT_MAP_COUNT;
	al.commonattr = common;
	if (name != NULL) {
		return setattrlistat(fd, name, &al, buf, len, FSOPT_NOFOLLOW);
	}
	return fsetattrlist(fd, &al, buf, len, 0);
}
*/
import "C"

import (
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
)

// passthroughFlags are the st_flags a plaintext item shares with its ciphertext
// file. The others describe the ciphertext file itself (UF_COMPRESSED,
// UF_TRACKED, SF_DATALESS …): they are neither reported for the plaintext item
// nor changed through it.
const passthroughFlags = unix.UF_NODUMP | unix.UF_IMMUTABLE | unix.UF_APPEND | unix.UF_OPAQUE | unix.UF_HIDDEN |
	unix.SF_ARCHIVED | unix.SF_IMMUTABLE | unix.SF_APPEND

// lockingFlags make an item refuse every other change, so they are set last
// and cleared first.
const lockingFlags = unix.UF_IMMUTABLE | unix.UF_APPEND | unix.SF_IMMUTABLE | unix.SF_APPEND

// appendFlags cannot be newly set: the engine opens ciphertext files O_RDWR and
// writes at block offsets, which an append-only file refuses, so the item would
// stay unwritable. One already set on the ciphertext is reported and can be
// cleared.
const appendFlags = unix.UF_APPEND | unix.SF_APPEND

type setAttrRequest struct {
	valid               uint32
	mode, uid, gid      uint32
	flags               uint32
	atime, mtime, btime unix.Timespec
}

// attrTarget is the ciphertext entry an attribute change goes to: name in the
// directory fd (never following a symlink), or the open file fd when name is "".
type attrTarget struct {
	fd   int
	name string
}

func (t attrTarget) stat() (unix.Stat_t, error) {
	var st unix.Stat_t
	if t.name == "" {
		return st, unix.Fstat(t.fd, &st)
	}
	return st, unix.Fstatat(t.fd, t.name, &st, unix.AT_SYMLINK_NOFOLLOW)
}

func (t attrTarget) chmod(mode uint32) error {
	if t.name == "" {
		return unix.Fchmod(t.fd, mode)
	}
	return unix.Fchmodat(t.fd, t.name, mode, unix.AT_SYMLINK_NOFOLLOW)
}

func (t attrTarget) chown(uid, gid int) error {
	if t.name == "" {
		return unix.Fchown(t.fd, uid, gid)
	}
	return unix.Fchownat(t.fd, t.name, uid, gid, unix.AT_SYMLINK_NOFOLLOW)
}

func (t attrTarget) setattrlist(common C.attrgroup_t, buf unsafe.Pointer, size uintptr) error {
	var name *C.char
	if t.name != "" {
		name = C.CString(t.name)
		defer C.free(unsafe.Pointer(name))
	}
	if r, err := C.gcfc_setattrlist(C.int(t.fd), name, common, buf, C.size_t(size)); r != 0 {
		return err
	}
	return nil
}

func (t attrTarget) setFlags(flags uint32) error {
	v := C.uint32_t(flags)
	return t.setattrlist(C.ATTR_CMN_FLAGS, unsafe.Pointer(&v), unsafe.Sizeof(v))
}

// setTimes sets birth, modification and access time in one call. The buffer
// holds the timespecs in attribute-bit order.
func (t attrTarget) setTimes(req setAttrRequest) error {
	var common C.attrgroup_t
	var times [3]C.struct_timespec
	n := 0
	add := func(bit uint32, attr C.attrgroup_t, ts unix.Timespec) {
		if req.valid&bit != 0 {
			common |= attr
			times[n] = C.struct_timespec{tv_sec: C.__darwin_time_t(ts.Sec), tv_nsec: C.long(ts.Nsec)}
			n++
		}
	}
	add(setBtime, C.ATTR_CMN_CRTIME, req.btime)
	add(setMtime, C.ATTR_CMN_MODTIME, req.mtime)
	add(setAtime, C.ATTR_CMN_ACCTIME, req.atime)
	if n == 0 {
		return nil
	}
	return t.setattrlist(common, unsafe.Pointer(&times[0]), uintptr(n)*unsafe.Sizeof(times[0]))
}

// setAttr applies req to t. Not atomic: on error, earlier changes stay.
func setAttr(t attrTarget, req setAttrRequest) error {
	lockLast := false
	var flags uint32
	if req.valid&setFlags != 0 {
		st, err := t.stat()
		if err != nil {
			return err
		}
		if req.flags&appendFlags&^st.Flags != 0 {
			return syscall.ENOTSUP
		}
		flags = (st.Flags &^ passthroughFlags) | (req.flags & passthroughFlags)
		lockLast = flags&lockingFlags != 0
		if !lockLast {
			if err := t.setFlags(flags); err != nil {
				return err
			}
		}
	}
	if req.valid&setMode != 0 {
		if err := t.chmod(req.mode & 07777); err != nil {
			return err
		}
	}
	if req.valid&(setUID|setGID) != 0 {
		uid, gid := -1, -1
		if req.valid&setUID != 0 {
			uid = int(req.uid)
		}
		if req.valid&setGID != 0 {
			gid = int(req.gid)
		}
		if err := t.chown(uid, gid); err != nil {
			return err
		}
	}
	if err := t.setTimes(req); err != nil {
		return err
	}
	if lockLast {
		return t.setFlags(flags)
	}
	return nil
}

func (volume *Volume) setAttrPath(path string, req setAttrRequest) error {
	dirfd, cName, err := volume.prepareAtSyscall(path)
	if err != nil {
		return err
	}
	defer syscall.Close(dirfd)
	return setAttr(attrTarget{fd: dirfd, name: cName}, req)
}

// setAttrHandle changes an open file, which keeps working after the file was
// unlinked or replaced and its path names something else.
func (volume *Volume) setAttrHandle(handleID int, req setAttrRequest) error {
	f := volume.lockFile(handleID)
	if f == nil {
		return syscall.EBADF
	}
	defer f.fdLock.RUnlock()
	return setAttr(attrTarget{fd: int(f.fd.Fd())}, req)
}
