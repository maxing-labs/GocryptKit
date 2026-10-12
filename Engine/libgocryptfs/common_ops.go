package main

import (
	"C"
	"golang.org/x/sys/unix"
	"syscall"

	"libgocryptfs/v2/internal/nametransform"
	"libgocryptfs/v2/internal/syscallcompat"
)

func gcf_get_attrs(sessionID int, relPath string) (uint32, uint64, uint64, bool) {
	volume := acquireVolume(sessionID)
	if volume == nil {
		return 0, 0, 0, false
	}
	defer volume.release()
	dirfd, cName, err := volume.prepareAtSyscall(relPath)
	if err != nil {
		return 0, 0, 0, false
	}
	defer syscall.Close(dirfd)

	st, err := syscallcompat.Fstatat2(dirfd, cName, unix.AT_SYMLINK_NOFOLLOW)
	if err != nil {
		return 0, 0, 0, false
	}

	// Translate ciphertext size to plaintext size
	size := volume.translateSize(dirfd, cName, st)

	return uint32(st.Mode), size, uint64(syscallcompat.StatMtimeSec(st)), true
}

// libgocryptfs: using Renameat instead of Renameat2 to support older kernels
func (volume *Volume) rename(oldPath string, newPath string) error {
	// Renaming a parent invalidates every cached descendant directory fd.
	defer volume.dirCache.Clear()
	dirfd, cName, err := volume.prepareAtSyscall(oldPath)
	if err != nil {
		return err
	}
	defer syscall.Close(dirfd)

	dirfd2, cName2, err := volume.prepareAtSyscall(newPath)
	if err != nil {
		return err
	}
	defer syscall.Close(dirfd2)

	// Easy case.
	if volume.plainTextNames {
		return syscallcompat.Renameat(dirfd, cName, dirfd2, cName2)
	}
	// Long destination file name: create .name file
	nameFileAlreadyThere := false
	if nametransform.IsLongContent(cName2) {
		err = volume.nameTransform.WriteLongNameAt(dirfd2, cName2, newPath)
		// Failure to write the .name file is expected when the target path already
		// exists. Since hashes are pretty unique, there is no need to modify the
		// .name file in this case, and we ignore the error.
		if err == syscall.EEXIST {
			nameFileAlreadyThere = true
		} else if err != nil {
			return err
		}
	}
	// Actual rename
	err = syscallcompat.Renameat(dirfd, cName, dirfd2, cName2)
	if err == syscall.ENOTEMPTY || err == syscall.EEXIST {
		// If an empty directory is overwritten we will always get an error as
		// the "empty" directory will still contain gocryptfs.diriv.
		// Interestingly, ext4 returns ENOTEMPTY while xfs returns EEXIST.
		// We handle that by trying to fs.Rmdir() the target directory and trying
		// again.
		if volume.rmdir(newPath) == nil {
			err = syscallcompat.Renameat(dirfd, cName, dirfd2, cName2)
		}
	}
	if err != nil {
		if nametransform.IsLongContent(cName2) && !nameFileAlreadyThere {
			// Roll back .name creation unless the .name file was already there
			nametransform.DeleteLongNameAt(dirfd2, cName2)
		}
		return err
	}
	if nametransform.IsLongContent(cName) {
		nametransform.DeleteLongNameAt(dirfd, cName)
	}
	return nil
}

func gcf_rename(sessionID int, oldPath string, newPath string) bool {
	volume := acquireVolume(sessionID)
	if volume == nil {
		return false
	}
	defer volume.release()
	return errToBool(volume.rename(oldPath, newPath))
}
