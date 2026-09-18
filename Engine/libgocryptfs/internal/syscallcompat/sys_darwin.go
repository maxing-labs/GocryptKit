//go:build darwin

package syscallcompat

import (
	"os"
	"syscall"

	"golang.org/x/sys/unix"
)

const (
	O_DIRECT = 0
	O_PATH   = 0

	RENAME_NOREPLACE = unix.RENAME_EXCL
	RENAME_WHITEOUT  = 1 << 30
	RENAME_EXCHANGE  = unix.RENAME_SWAP
)

func EnospcPrealloc(fd int, off int64, len int64) error {
	return nil
}

func fillDirEntries(fd int, names []string) ([]DirEntry, error) {
	out := make([]DirEntry, 0, len(names))
	for _, name := range names {
		var st unix.Stat_t
		err := Fstatat(fd, name, &st, unix.AT_SYMLINK_NOFOLLOW)
		if err == syscall.ENOENT {
			continue
		}
		if err != nil {
			return nil, err
		}
		newEntry := DirEntry{
			Name: name,
			Mode: uint32(st.Mode) & syscall.S_IFMT,
		}
		out = append(out, newEntry)
	}
	return out, nil
}

func Getdents(fd int) ([]DirEntry, error) {
	newFd, err := syscall.Dup(fd)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(newFd), "")
	defer f.Close()
	names, err := f.Readdirnames(0)
	if err != nil {
		return nil, err
	}
	return fillDirEntries(fd, names)
}

func StatMtimeSec(st *syscall.Stat_t) int64 {
	return int64(st.Mtimespec.Sec)
}
