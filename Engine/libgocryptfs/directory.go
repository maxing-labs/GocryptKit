package main

import (
	"C"
	"fmt"
	"io"
	"strings"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"

	"libgocryptfs/v2/allocator"
	"libgocryptfs/v2/internal/configfile"
	"libgocryptfs/v2/internal/cryptocore"
	"libgocryptfs/v2/internal/nametransform"
	"libgocryptfs/v2/internal/syscallcompat"
)

func (volume *Volume) mkdirWithIv(dirfd int, cName string, mode uint32) error {
	// Between the creation of the directory and the creation of gocryptfs.diriv
	// the directory is inconsistent. Take the lock to prevent other readers
	// from seeing it.
	volume.dirIVLock.Lock()
	defer volume.dirIVLock.Unlock()
	err := unix.Mkdirat(dirfd, cName, mode)
	if err != nil {
		return err
	}
	dirfd2, err := syscallcompat.Openat(dirfd, cName, syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscallcompat.O_PATH, 0)
	if err == nil {
		// Create gocryptfs.diriv
		err = nametransform.WriteDirIVAt(dirfd2)
		syscall.Close(dirfd2)
	}
	if err != nil {
		// Delete inconsistent directory (missing gocryptfs.diriv!)
		syscallcompat.Unlinkat(dirfd, cName, unix.AT_REMOVEDIR)
	}
	return err
}

func gcf_list_dir(sessionID int, dirName string) (*C.char, *C.int, C.int) {
	volume := acquireVolume(sessionID)
	if volume == nil {
		return nil, nil, 0
	}
	defer volume.release()
	parentDirFd, cDirName, err := volume.prepareAtSyscallMyself(dirName)
	if err != nil {
		return nil, nil, 0
	}
	defer syscall.Close(parentDirFd)
	// Read ciphertext directory
	fd, err := syscallcompat.Openat(parentDirFd, cDirName, syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, nil, 0
	}
	defer syscall.Close(fd)
	cipherEntries, err := syscallcompat.Getdents(fd)
	if err != nil {
		return nil, nil, 0
	}
	// Get DirIV (stays nil if PlaintextNames is used)
	var cachedIV []byte
	if !volume.plainTextNames {
		// Read the DirIV from disk
		cachedIV, err = volume.nameTransform.ReadDirIVAt(fd)
		if err != nil {
			return nil, nil, 0
		}
	}
	// Decrypted directory entries
	var plain strings.Builder
	var modes []uint32
	// Filter and decrypt filenames
	for i := range cipherEntries {
		cName := cipherEntries[i].Name
		if dirName == "/" && cName == configfile.ConfDefaultName {
			// silently ignore "gocryptfs.conf" in the top level dir
			continue
		}
		if volume.plainTextNames {
			plain.WriteString(cipherEntries[i].Name + "\x00")
			modes = append(modes, cipherEntries[i].Mode)
			continue
		}
		if cName == nametransform.DirIVFilename {
			// silently ignore "gocryptfs.diriv" everywhere if dirIV is enabled
			continue
		}
		// Handle long file name
		isLong := nametransform.NameType(cName)
		if isLong == nametransform.LongNameContent {
			cNameLong, err := nametransform.ReadLongNameAt(fd, cName)
			if err != nil {
				continue
			}
			cName = cNameLong
		} else if isLong == nametransform.LongNameFilename {
			// ignore "gocryptfs.longname.*.name"
			continue
		}
		name, err := volume.nameTransform.DecryptName(cName, cachedIV)
		if err != nil {
			continue
		}
		// Override the ciphertext name with the plaintext name but reuse the rest
		// of the structure
		cipherEntries[i].Name = name
		plain.WriteString(cipherEntries[i].Name + "\x00")
		modes = append(modes, cipherEntries[i].Mode)
	}
	p := allocator.Malloc(len(modes))
	for i := 0; i < len(modes); i++ {
		offset := C.sizeof_int * uintptr(i)
		*(*C.int)(unsafe.Pointer(uintptr(p) + offset)) = (C.int)(modes[i])
	}
	return C.CString(plain.String()), (*C.int)(p), (C.int)(len(modes))
}

func (volume *Volume) mkdir(path string, mode uint32) error {
	dirfd, cName, err := volume.prepareAtSyscall(path)
	if err != nil {
		return err
	}
	defer syscall.Close(dirfd)

	if volume.plainTextNames {
		err = unix.Mkdirat(dirfd, cName, mode)
		if err != nil {
			return err
		}
		var ust unix.Stat_t
		return syscallcompat.Fstatat(dirfd, cName, &ust, unix.AT_SYMLINK_NOFOLLOW)
	}
	// We need write and execute permissions to create gocryptfs.diriv.
	// Also, we need read permissions to open the directory (to avoid
	// race-conditions between getting and setting the mode).
	origMode := mode
	mode = mode | 0700

	// Handle long file name
	if nametransform.IsLongContent(cName) {
		// Create ".name"
		err = volume.nameTransform.WriteLongNameAt(dirfd, cName, path)
		if err != nil {
			return err
		}

		// Create directory
		err = volume.mkdirWithIv(dirfd, cName, mode)
		if err != nil {
			nametransform.DeleteLongNameAt(dirfd, cName)
			return err
		}
	} else {
		err = volume.mkdirWithIv(dirfd, cName, mode)
		if err != nil {
			return err
		}
	}

	fd, err := syscallcompat.Openat(dirfd, cName,
		syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return err
	}
	defer syscall.Close(fd)

	var st syscall.Stat_t
	err = syscall.Fstat(fd, &st)
	if err != nil {
		return err
	}

	// Fix permissions
	if origMode != mode {
		// Preserve SGID bit if it was set due to inheritance.
		origMode = uint32(st.Mode&^0777) | origMode
		syscall.Fchmod(fd, origMode)
	}
	return nil
}

func gcf_mkdir(sessionID int, path string, mode uint32) bool {
	volume := acquireVolume(sessionID)
	if volume == nil {
		return false
	}
	defer volume.release()
	return errToBool(volume.mkdir(path, mode))
}

func (volume *Volume) rmdir(relPath string) error {
	defer volume.dirCache.Clear()
	parentDirFd, cName, err := volume.prepareAtSyscall(relPath)
	if err != nil {
		return err
	}
	defer syscall.Close(parentDirFd)
	if volume.plainTextNames {
		// Unlinkat with AT_REMOVEDIR is equivalent to Rmdir
		return unix.Unlinkat(parentDirFd, cName, unix.AT_REMOVEDIR)
	}
	dirfd, err := syscallcompat.Openat(parentDirFd, cName, syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return err
	}
	defer syscall.Close(dirfd)
	// Check directory contents
	children, err := syscallcompat.Getdents(dirfd)
	if err == io.EOF {
		// The directory is empty
		return unix.Unlinkat(parentDirFd, cName, unix.AT_REMOVEDIR)
	}
	if err != nil {
		return err
	}
	// If the directory is not empty besides gocryptfs.diriv, do not even
	// attempt the dance around gocryptfs.diriv.
	if len(children) > 1 {
		return syscall.ENOTEMPTY
	}
	// Move "gocryptfs.diriv" to the parent dir as "gocryptfs.diriv.rmdir.XYZ"
	tmpName := fmt.Sprintf("%s.rmdir.%d", nametransform.DirIVFilename, cryptocore.RandUint64())
	// The directory is in an inconsistent state between rename and rmdir.
	// Protect against concurrent readers.
	volume.dirIVLock.Lock()
	defer volume.dirIVLock.Unlock()
	err = syscallcompat.Renameat(dirfd, nametransform.DirIVFilename, parentDirFd, tmpName)
	if err != nil {
		return err
	}
	// Actual Rmdir
	err = syscallcompat.Unlinkat(parentDirFd, cName, unix.AT_REMOVEDIR)
	if err != nil {
		// This can happen if another file in the directory was created in the
		// meantime, undo the rename
		syscallcompat.Renameat(parentDirFd, tmpName, dirfd, nametransform.DirIVFilename)
		return err
	}
	// Delete "gocryptfs.diriv.rmdir.XYZ"
	syscallcompat.Unlinkat(parentDirFd, tmpName, 0)
	// Delete .name file
	if nametransform.IsLongContent(cName) {
		nametransform.DeleteLongNameAt(parentDirFd, cName)
	}
	return nil
}

func gcf_rmdir(sessionID int, relPath string) bool {
	volume := acquireVolume(sessionID)
	if volume == nil {
		return false
	}
	defer volume.release()
	return errToBool(volume.rmdir(relPath))
}
