package main

/*
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
    char* name;
    uint32_t mode;
} gcfc_dir_entry_t;

// Attributes of one item. `size` is the plaintext size for regular files and
// symlinks; `mode` is the full st_mode including the file type bits.
typedef struct {
    uint64_t ino;
    uint64_t size;
    uint32_t mode;
    uint32_t nlink;
    uint32_t uid;
    uint32_t gid;
    uint32_t flags;
    int64_t atime_sec;
    int64_t atime_nsec;
    int64_t mtime_sec;
    int64_t mtime_nsec;
    int64_t ctime_sec;
    int64_t ctime_nsec;
    int64_t btime_sec;
    int64_t btime_nsec;
} gcfc_stat_t;

// Fields of gcfc_setattr_t to apply.
#define GCFC_SET_MODE  0x01
#define GCFC_SET_UID   0x02
#define GCFC_SET_GID   0x04
#define GCFC_SET_FLAGS 0x08
#define GCFC_SET_ATIME 0x10
#define GCFC_SET_MTIME 0x20
#define GCFC_SET_BTIME 0x40

// Attribute changes for gcfc_setattr / gcfc_fsetattr; `valid` says which
// fields to apply. Only the user-visible flags are applied (see
// passthroughFlags); the others of the ciphertext file are kept.
typedef struct {
    uint32_t valid;
    uint32_t mode;
    uint32_t uid;
    uint32_t gid;
    uint32_t flags;
    int64_t atime_sec;
    int64_t atime_nsec;
    int64_t mtime_sec;
    int64_t mtime_nsec;
    int64_t btime_sec;
    int64_t btime_nsec;
} gcfc_setattr_t;
*/
import "C"

import (
	"bytes"
	"errors"
	"math"
	"os"
	"path/filepath"
	"runtime/debug"
	"strings"
	"syscall"
	"unicode/utf8"
	"unsafe"

	"golang.org/x/sys/unix"

	"libgocryptfs/v2/internal/configfile"
	"libgocryptfs/v2/internal/contentenc"
	"libgocryptfs/v2/internal/nametransform"
	"libgocryptfs/v2/internal/stupidgcm"
	"libgocryptfs/v2/internal/syscallcompat"
)

// Go names for the C types above. cgo resolves C.name against each file's own
// preamble, and a copy of a typedef elsewhere may drift unnoticed (cgo does
// not compare them); capi_shim.go uses these instead.
type (
	cDirEntry = C.gcfc_dir_entry_t
	cStat     = C.gcfc_stat_t
	cSetattr  = C.gcfc_setattr_t
)

// recoverTo 把 panic 转成返回值。c-archive 里逃出导出函数的 panic 会终止宿主
// FSKit 扩展进程，该进程上的卷随即被静默卸载，所以每个 gcfc_* 的第一条语句都必须
// 是 `defer recoverTo(&ret, ...)`（capi_recover_test.go 会检查）。
//
// 这只是兜底：runtime 的 fatal error（并发读写 map、解锁未加锁的互斥锁、OOM）
// 以及其它 goroutine 里的 panic 拦不住，根因仍然要修。
func recoverTo[T any](ret *T, fallback T) {
	if r := recover(); r != nil {
		*ret = fallback
	}
}

// recoverVoid 用于没有返回值的导出函数。
func recoverVoid() {
	_ = recover()
}

// Every export that can fail returns >= 0 or a negative errno, and hands
// strings and arrays back through out parameters. The exceptions (status
// codes of gcfc_init and gcfc_init_vault, a boolean, size arithmetic, and the
// functions that return nothing) are listed with their reasons in
// errnoExceptions; TestEveryCExportReportsErrno holds every export to this.

// gcfc_init 的失败码。-3 是"引擎内部 panic"，与 -1/-2 区分开：前两者是用户能
// 理解并纠正的（没有 conf、密码不对），-3 只可能是 bug。
const initInternalError = -3

//export gcfc_init
func gcfc_init(rootCipherDir *C.char, password *C.char, givenScryptHash *C.uint8_t, hashLen C.size_t, returnedScryptHashBuff *C.uint8_t, returnedHashCap C.size_t) (ret C.int) {
	// 挂载是整条链上唯一会跑 scrypt 派生和 cryptocore 初始化的地方，那里有
	// log.Panicf（RandBytes 等）。c-archive 里未捕获的 panic 会终止宿主 FSKit
	// 扩展进程 —— 对已经挂着的其他卷来说就是被静默卸载。在 C 边界兜住。
	defer recoverTo(&ret, C.int(initInternalError))
	if rootCipherDir == nil {
		return -1
	}
	rDir := C.GoString(rootCipherDir)

	// C.GoBytes, not C.GoString: a Go string is an immutable copy that cannot be wiped.
	var pwBytes []byte
	if password != nil {
		pwBytes = C.GoBytes(unsafe.Pointer(password), C.int(C.strlen(password)))
	}
	defer wipe(pwBytes)

	var givenHash []byte
	if givenScryptHash != nil && hashLen > 0 {
		givenHash = C.GoBytes(unsafe.Pointer(givenScryptHash), C.int(hashLen))
	}
	defer wipe(givenHash)

	var retBuff []byte
	if returnedScryptHashBuff != nil && returnedHashCap >= 32 {
		retBuff = make([]byte, 32)
	}
	defer wipe(retBuff)

	cf, err := configfile.Load(filepath.Join(rDir, configfile.ConfDefaultName))
	if err != nil {
		return -1
	}

	masterkey, err := cf.GetMasterkey(pwBytes, givenHash, retBuff)
	if err != nil {
		return -2
	}
	defer wipe(masterkey)

	if retBuff != nil && returnedScryptHashBuff != nil {
		C.memcpy(unsafe.Pointer(returnedScryptHashBuff), unsafe.Pointer(&retBuff[0]), C.size_t(len(retBuff)))
	}

	debug.FreeOSMemory()
	volID := registerNewVolume(rDir, masterkey, cf)
	return C.int(volID)
}

//export gcfc_close
func gcfc_close(volumeID C.int) {
	defer recoverVoid()
	gcf_close(int(volumeID))
}

//export gcfc_is_closed
func gcfc_is_closed(volumeID C.int) (ret C.int) {
	defer recoverTo(&ret, C.int(1))
	if gcf_is_closed(int(volumeID)) {
		return 1
	}
	return 0
}

// gcfc_open_read_mode 成功返回句柄（>= 0），失败返回负的 errno。
//
//export gcfc_open_read_mode
func gcfc_open_read_mode(volumeID C.int, plainPath *C.char) (ret C.int) {
	defer recoverTo(&ret, -C.int(syscall.EIO))
	if plainPath == nil {
		return -C.int(syscall.EINVAL)
	}
	volume := acquireVolume(int(volumeID))
	if volume == nil {
		return -C.int(syscall.EBADF)
	}
	defer volume.release()
	h, err := volume.openRead(C.GoString(plainPath))
	if err != nil {
		return errnoOf(err)
	}
	return C.int(h)
}

//export gcfc_read_file
func gcfc_read_file(volumeID C.int, handleID C.int, offset C.uint64_t, dst unsafe.Pointer, length C.size_t) (ret C.int64_t) {
	defer recoverTo(&ret, -C.int64_t(syscall.EIO))
	if dst == nil || length == 0 {
		return 0
	}
	// pread(2) refuses a negative off_t; the ciphertext offset would wrap.
	if uint64(offset) > math.MaxInt64 {
		return -C.int64_t(syscall.EINVAL)
	}
	volume := acquireVolume(int(volumeID))
	if volume == nil {
		return -C.int64_t(syscall.EBADF)
	}
	defer volume.release()

	f := volume.lockFile(int(handleID))
	if f == nil {
		return -C.int64_t(syscall.EBADF)
	}

	defer f.fdLock.RUnlock()
	f.contentLock.RLock()
	defer f.contentLock.RUnlock()

	// If the file on disk has size 0, it is an empty file: reading returns 0 (EOF) immediately.
	if fi, err := f.fd.Stat(); err == nil && fi.Size() == 0 {
		return 0
	}

	// doRead 底层使用固定大小（contentenc.MAX_KERNEL_WRITE = 128 KiB）的缓冲池。
	// 单次请求超长（如 512 KiB 或更大）时若直接传给 doRead 会越界 panic，
	// 若简单截断为 128 KiB 则会导致上层（如 FSKit / VFS）收到短读并判定为 EIO。
	// 这里像 gcfc_write_file 一样，通过分块逐段循环读取并拼接，支持任意大小的单次 read 请求。
	var totalRead int64
	remLen := uint64(length)
	currOffset := uint64(offset)

	for remLen > 0 {
		reqLen := remLen
		if reqLen > contentenc.MAX_KERNEL_WRITE {
			reqLen = contentenc.MAX_KERNEL_WRITE
		}

		out, success := volume.doRead(f, nil, currOffset, reqLen)
		if !success {
			if totalRead > 0 {
				return C.int64_t(totalRead)
			}
			return -C.int64_t(syscall.EIO)
		}
		n := len(out)
		if n == 0 {
			// 到达 EOF
			break
		}
		targetPtr := unsafe.Pointer(uintptr(dst) + uintptr(totalRead))
		C.memcpy(targetPtr, unsafe.Pointer(&out[0]), C.size_t(n))
		totalRead += int64(n)
		currOffset += uint64(n)

		if uint64(n) < reqLen {
			// 在该分块内提前触碰 EOF
			break
		}
		remLen -= uint64(n)
	}
	return C.int64_t(totalRead)
}

//export gcfc_close_file
func gcfc_close_file(volumeID C.int, handleID C.int) {
	defer recoverVoid()
	gcf_close_file(int(volumeID), int(handleID))
}

//export gcfc_plain_size
func gcfc_plain_size(volumeID C.int, cipherSize C.uint64_t) (ret C.uint64_t) {
	defer recoverTo(&ret, C.uint64_t(0))
	vol := acquireVolume(int(volumeID))
	if vol == nil {
		return 0
	}
	defer vol.release()
	return C.uint64_t(vol.contentEnc.CipherSizeToPlainSize(uint64(cipherSize)))
}

func (volume *Volume) getCipherPath(plainPath string) (string, error) {
	clean := filepath.Clean(plainPath)
	if clean == "." || clean == "/" || clean == "" {
		return volume.rootCipherDir, nil
	}
	clean = strings.TrimPrefix(clean, "/")
	parts := strings.Split(clean, "/")
	// After Clean, ".." can only lead a relative path; joined to the cipher
	// directory it would climb out of it.
	if parts[0] == ".." {
		return "", syscall.EPERM
	}

	if volume.plainTextNames {
		return filepath.Join(append([]string{volume.rootCipherDir}, parts...)...), nil
	}

	// 逐级用 dirfd 走下去，diriv 一律经 ReadDirIVAt 读取：O_NOFOLLOW、限长读、
	// 必须恰好 16 字节且非全零。密文目录可能在共享或同步盘上，里面的 diriv 不可信：
	// os.ReadFile 会跟随符号链接，并按文件大小分配内存（一个稀疏的巨型 diriv
	// 就能把扩展进程 OOM 掉）。
	dirfd, err := syscallcompat.Open(volume.rootCipherDir, syscall.O_DIRECTORY|syscallcompat.O_PATH, 0)
	if err != nil {
		return "", err
	}
	defer func() { syscall.Close(dirfd) }()
	curCipherDir := volume.rootCipherDir
	for i, part := range parts {
		iv, err := volume.nameTransform.ReadDirIVAt(dirfd)
		if err != nil {
			return "", err
		}
		cName, err := volume.nameTransform.EncryptAndHashName(part, iv)
		if err != nil {
			return "", err
		}
		curCipherDir = filepath.Join(curCipherDir, cName)
		if i == len(parts)-1 {
			break
		}
		next, err := syscallcompat.Openat(dirfd, cName, syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscallcompat.O_PATH, 0)
		if err != nil {
			return "", err
		}
		syscall.Close(dirfd)
		dirfd = next
	}
	return curCipherDir, nil
}

// gcfc_cipher_path stores the ciphertext path of plainPath in *out (free it
// with gcfc_free_string) and returns 0, or returns a negative errno.
//
//export gcfc_cipher_path
func gcfc_cipher_path(volumeID C.int, plainPath *C.char, out **C.char) (ret C.int) {
	defer recoverTo(&ret, -C.int(syscall.EIO))
	if plainPath == nil || out == nil {
		return -C.int(syscall.EINVAL)
	}
	*out = nil
	volume := acquireVolume(int(volumeID))
	if volume == nil {
		return -C.int(syscall.EBADF)
	}
	defer volume.release()
	cPath, err := volume.getCipherPath(C.GoString(plainPath))
	if err != nil {
		return errnoOf(err)
	}
	*out = C.CString(cPath)
	return 0
}

// gcfc_readlink stores the decrypted target of the symlink at plainPath in
// *out (free it with gcfc_free_string) and returns 0, or returns a negative
// errno: ENOENT when it is gone, EINVAL when it is not a symlink, EIO when the
// target does not decrypt.
//
//export gcfc_readlink
func gcfc_readlink(volumeID C.int, plainPath *C.char, out **C.char) (ret C.int) {
	defer recoverTo(&ret, -C.int(syscall.EIO))
	if plainPath == nil || out == nil {
		return -C.int(syscall.EINVAL)
	}
	*out = nil
	volume := acquireVolume(int(volumeID))
	if volume == nil {
		return -C.int(syscall.EBADF)
	}
	defer volume.release()
	dirfd, cName, err := volume.prepareAtSyscall(C.GoString(plainPath))
	if err != nil {
		return errnoOf(err)
	}
	defer syscall.Close(dirfd)
	target, err := volume.readlink(dirfd, cName)
	if err != nil {
		return errnoOf(err)
	}
	*out = C.CString(string(target))
	return 0
}

// gcfc_list_dir returns 0 and the entries of plainDir, or a negative errno.
//
//export gcfc_list_dir
func gcfc_list_dir(volumeID C.int, plainDir *C.char, outEntries **C.gcfc_dir_entry_t, outCount *C.int) (ret C.int) {
	defer recoverTo(&ret, -C.int(syscall.EIO))
	if plainDir == nil || outEntries == nil || outCount == nil {
		return -C.int(syscall.EINVAL)
	}
	volume := acquireVolume(int(volumeID))
	if volume == nil {
		return -C.int(syscall.EBADF)
	}
	defer volume.release()
	dir := C.GoString(plainDir)
	if dir == "" {
		dir = "/"
	}

	parentDirFd, cDirName, err := volume.prepareAtSyscallMyself(dir)
	if err != nil {
		return errnoOf(err)
	}
	defer syscall.Close(parentDirFd)

	fd, err := syscallcompat.Openat(parentDirFd, cDirName, syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return errnoOf(err)
	}
	defer syscall.Close(fd)

	cipherEntries, err := syscallcompat.Getdents(fd)
	if err != nil {
		return errnoOf(err)
	}

	var cachedIV []byte
	if !volume.plainTextNames {
		// A missing or broken diriv is damage, not a missing directory: EIO,
		// as upstream does.
		cachedIV, err = volume.nameTransform.ReadDirIVAt(fd)
		if err != nil {
			return -C.int(syscall.EIO)
		}
	}

	type entry struct {
		name string
		mode uint32
	}
	var res []entry

	for i := range cipherEntries {
		cName := cipherEntries[i].Name
		if dir == "/" && cName == configfile.ConfDefaultName {
			continue
		}
		if volume.plainTextNames {
			res = append(res, entry{name: cName, mode: cipherEntries[i].Mode})
			continue
		}
		if cName == nametransform.DirIVFilename {
			continue
		}
		isLong := nametransform.NameType(cName)
		if isLong == nametransform.LongNameContent {
			cNameLong, err := nametransform.ReadLongNameAt(fd, cName)
			if err != nil {
				continue
			}
			cName = cNameLong
		} else if isLong == nametransform.LongNameFilename {
			continue
		}
		name, err := volume.nameTransform.DecryptName(cName, cachedIV)
		if err != nil {
			continue
		}
		res = append(res, entry{name: name, mode: cipherEntries[i].Mode})
	}

	count := len(res)
	*outCount = C.int(count)
	if count == 0 {
		*outEntries = nil
		return 0
	}

	size := C.size_t(count) * C.size_t(unsafe.Sizeof(C.gcfc_dir_entry_t{}))
	entriesMem := (*C.gcfc_dir_entry_t)(C.malloc(size))
	entriesSlice := (*[1 << 28]C.gcfc_dir_entry_t)(unsafe.Pointer(entriesMem))[:count:count]

	for i, e := range res {
		entriesSlice[i].name = C.CString(e.name)
		entriesSlice[i].mode = C.uint32_t(e.mode)
	}

	*outEntries = entriesMem
	return 0
}

//export gcfc_free_dir_entries
func gcfc_free_dir_entries(entries *C.gcfc_dir_entry_t, count C.int) {
	defer recoverVoid()
	if entries == nil || count <= 0 {
		return
	}
	slice := (*[1 << 28]C.gcfc_dir_entry_t)(unsafe.Pointer(entries))[:int(count):int(count)]
	for i := 0; i < int(count); i++ {
		if slice[i].name != nil {
			C.free(unsafe.Pointer(slice[i].name))
		}
	}
	C.free(unsafe.Pointer(entries))
}

//export gcfc_free_string
func gcfc_free_string(str *C.char) {
	defer recoverVoid()
	if str != nil {
		C.free(unsafe.Pointer(str))
	}
}

// gcfc_open_write_mode opens a file for writing, creating it when missing,
// and returns the handle (>= 0) or a negative errno. Only tests, vaultctl and
// iOS use it; the extension creates with gcfc_create_file and reopens with
// gcfc_open_write_existing.
//
//export gcfc_open_write_mode
func gcfc_open_write_mode(volumeID C.int, plainPath *C.char, mode C.uint32_t) (ret C.int) {
	defer recoverTo(&ret, -C.int(syscall.EIO))
	return openWriteC(volumeID, plainPath, uint32(mode), openOrCreate)
}

// openWriteC 是 gcfc_open_write_mode / gcfc_create_file / gcfc_open_write_existing 的公共部分：
// 成功返回句柄（>= 0），失败返回负的 errno。
func openWriteC(volumeID C.int, plainPath *C.char, mode uint32, how openHow) C.int {
	if plainPath == nil {
		return -C.int(syscall.EINVAL)
	}
	volume := acquireVolume(int(volumeID))
	if volume == nil {
		return -C.int(syscall.EBADF)
	}
	defer volume.release()
	h, err := volume.openWrite(C.GoString(plainPath), mode, how)
	if err != nil {
		return errnoOf(err)
	}
	return C.int(h)
}

// gcfc_create_file 独占创建（O_CREAT|O_EXCL）一个新文件并返回可写句柄；名字已
// 存在时返回 -EEXIST。FSKit 的 createItem 必须走这里：gcfc_open_write_mode 的
// "不存在就建、存在就打开"会让两个并发的 O_EXCL 创建都成功（锁文件失效）。
//
//export gcfc_create_file
func gcfc_create_file(volumeID C.int, plainPath *C.char, mode C.uint32_t) (ret C.int) {
	defer recoverTo(&ret, -C.int(syscall.EIO))
	return openWriteC(volumeID, plainPath, uint32(mode), createExclusive)
}

// gcfc_open_write_existing 只打开已存在的文件，绝不创建。写入方丢了句柄之后
// 按路径重开时必须用它：带 O_CREAT 会把刚被删掉的文件"复活"。
//
//export gcfc_open_write_existing
func gcfc_open_write_existing(volumeID C.int, plainPath *C.char) (ret C.int) {
	defer recoverTo(&ret, -C.int(syscall.EIO))
	return openWriteC(volumeID, plainPath, 0, openExisting)
}

func fillStat(out *C.gcfc_stat_t, st *syscall.Stat_t, size uint64) {
	out.ino = C.uint64_t(st.Ino)
	out.size = C.uint64_t(size)
	out.mode = C.uint32_t(st.Mode)
	out.nlink = C.uint32_t(st.Nlink)
	out.uid = C.uint32_t(st.Uid)
	out.gid = C.uint32_t(st.Gid)
	out.flags = C.uint32_t(st.Flags & passthroughFlags)
	out.atime_sec, out.atime_nsec = C.int64_t(st.Atimespec.Sec), C.int64_t(st.Atimespec.Nsec)
	out.mtime_sec, out.mtime_nsec = C.int64_t(st.Mtimespec.Sec), C.int64_t(st.Mtimespec.Nsec)
	out.ctime_sec, out.ctime_nsec = C.int64_t(st.Ctimespec.Sec), C.int64_t(st.Ctimespec.Nsec)
	out.btime_sec, out.btime_nsec = C.int64_t(st.Birthtimespec.Sec), C.int64_t(st.Birthtimespec.Nsec)
}

// gcfc_lstat 取明文路径对应条目的属性，不跟随符号链接。经目录 fd 解析
// （openat + fstatat），中间层也不跟随符号链接。成功返回 0，失败返回负的 errno
// （条目不存在时是 -ENOENT，调用方据此回报给内核，而不是交出一份空属性）。
//
//export gcfc_lstat
func gcfc_lstat(volumeID C.int, plainPath *C.char, out *C.gcfc_stat_t) (ret C.int) {
	defer recoverTo(&ret, -C.int(syscall.EIO))
	if plainPath == nil || out == nil {
		return -C.int(syscall.EINVAL)
	}
	volume := acquireVolume(int(volumeID))
	if volume == nil {
		return -C.int(syscall.EBADF)
	}
	defer volume.release()
	dirfd, cName, err := volume.prepareAtSyscall(C.GoString(plainPath))
	if err != nil {
		return errnoOf(err)
	}
	defer syscall.Close(dirfd)
	st, err := syscallcompat.Fstatat2(dirfd, cName, unix.AT_SYMLINK_NOFOLLOW)
	if err != nil {
		return errnoOf(err)
	}
	fillStat(out, st, volume.translateSize(dirfd, cName, st))
	return 0
}

// gcfc_fstat 按已打开的句柄取属性。条目被删除或被覆盖之后路径已经不指向它，
// 但句柄还在（POSIX：unlink 之后 fd 仍可读写、可 fstat）。
//
//export gcfc_fstat
func gcfc_fstat(volumeID C.int, handleID C.int, out *C.gcfc_stat_t) (ret C.int) {
	defer recoverTo(&ret, -C.int(syscall.EIO))
	if out == nil {
		return -C.int(syscall.EINVAL)
	}
	volume := acquireVolume(int(volumeID))
	if volume == nil {
		return -C.int(syscall.EBADF)
	}
	defer volume.release()
	f := volume.lockFile(int(handleID))
	if f == nil {
		return -C.int(syscall.EBADF)
	}
	defer f.fdLock.RUnlock()
	var st syscall.Stat_t
	if err := syscall.Fstat(int(f.fd.Fd()), &st); err != nil {
		return errnoOf(err)
	}
	fillStat(out, &st, volume.contentEnc.CipherSizeToPlainSize(uint64(st.Size)))
	return 0
}

//export gcfc_write_file
func gcfc_write_file(volumeID C.int, handleID C.int, offset C.uint64_t, src unsafe.Pointer, length C.size_t) (ret C.int64_t) {
	defer recoverTo(&ret, -C.int64_t(syscall.EIO))
	if src == nil || length == 0 {
		return 0
	}
	volume := acquireVolume(int(volumeID))
	if volume == nil {
		return -C.int64_t(syscall.EBADF)
	}
	defer volume.release()
	if err := volume.checkPlainRange(uint64(offset), uint64(length)); err != nil {
		return C.int64_t(errnoOf(err))
	}

	f := volume.lockFile(int(handleID))
	if f == nil {
		return -C.int64_t(syscall.EBADF)
	}

	defer f.fdLock.RUnlock()
	f.contentLock.Lock()
	defer f.contentLock.Unlock()

	data := C.GoBytes(src, C.int(length))

	// 越过文件末尾写入时先把旧的末尾半块补零到块边界（上游的 writePadHole）。
	if err := volume.writePadHole(f, uint64(offset)); err != nil {
		return C.int64_t(errnoOf(err))
	}

	// doWrite 底层用固定大小（contentenc.MAX_KERNEL_WRITE = 128 KiB）的缓冲池，
	// 一次性提交超长数据会越界并触发 Go runtime abort。在 c-archive 场景下
	// runtime abort 会直接 exit() 掉整个宿主 FSKit 扩展进程 —— 表现为写入
	// Input/output error、卷被静默卸载、已写文件丢失。
	// 上游 gcf_write_file 的做法是直接拒绝超长写入；这里改为分块逐段写，
	// 既不崩溃也能支持任意大小的单次 write 请求。
	var written uint64
	for start := 0; start < len(data); start += contentenc.MAX_KERNEL_WRITE {
		end := start + contentenc.MAX_KERNEL_WRITE
		if end > len(data) {
			end = len(data)
		}
		chunk := data[start:end]
		n, err := volume.doWrite(f, chunk, uint64(offset)+uint64(start))
		if err != nil {
			if written > 0 {
				// 部分成功：返回已写字节数，由上层决定是否重试剩余部分
				return C.int64_t(written)
			}
			return C.int64_t(errnoOf(err))
		}
		written += uint64(n)
		if int(n) < len(chunk) {
			// 短写，停止并向上层如实汇报
			break
		}
	}
	return C.int64_t(written)
}

//export gcfc_ftruncate
func gcfc_ftruncate(volumeID C.int, handleID C.int, size C.uint64_t) (ret C.int) {
	defer recoverTo(&ret, -C.int(syscall.EIO))
	volume := acquireVolume(int(volumeID))
	if volume == nil {
		return -C.int(syscall.EBADF)
	}
	defer volume.release()
	if err := volume.ftruncate(int(handleID), uint64(size)); err != nil {
		return errnoOf(err)
	}
	return 0
}

//export gcfc_truncate
func gcfc_truncate(volumeID C.int, plainPath *C.char, offset C.uint64_t) (ret C.int) {
	defer recoverTo(&ret, -C.int(syscall.EIO))
	return pathOp(volumeID, plainPath, func(volume *Volume, path string) error {
		return volume.truncatePath(path, uint64(offset))
	})
}

// pathOp 是按明文路径做修改的导出函数的公共部分：失败时返回负的真实 errno
// （EEXIST / ENOENT / ENOTEMPTY / ENOSPC ……），而不是一律 EIO。
func pathOp(volumeID C.int, plainPath *C.char, op func(volume *Volume, path string) error) C.int {
	if plainPath == nil {
		return -C.int(syscall.EINVAL)
	}
	volume := acquireVolume(int(volumeID))
	if volume == nil {
		return -C.int(syscall.EBADF)
	}
	defer volume.release()
	if err := op(volume, C.GoString(plainPath)); err != nil {
		return errnoOf(err)
	}
	return 0
}

//export gcfc_remove_file
func gcfc_remove_file(volumeID C.int, plainPath *C.char) (ret C.int) {
	defer recoverTo(&ret, -C.int(syscall.EIO))
	return pathOp(volumeID, plainPath, func(volume *Volume, path string) error {
		return volume.removeFile(path)
	})
}

//export gcfc_mkdir
func gcfc_mkdir(volumeID C.int, plainPath *C.char, mode C.uint32_t) (ret C.int) {
	defer recoverTo(&ret, -C.int(syscall.EIO))
	return pathOp(volumeID, plainPath, func(volume *Volume, path string) error {
		return volume.mkdir(path, uint32(mode))
	})
}

//export gcfc_rmdir
func gcfc_rmdir(volumeID C.int, plainPath *C.char) (ret C.int) {
	defer recoverTo(&ret, -C.int(syscall.EIO))
	return pathOp(volumeID, plainPath, func(volume *Volume, path string) error {
		return volume.rmdir(path)
	})
}

//export gcfc_rename
func gcfc_rename(volumeID C.int, oldPath *C.char, newPath *C.char) (ret C.int) {
	defer recoverTo(&ret, -C.int(syscall.EIO))
	if newPath == nil {
		return -C.int(syscall.EINVAL)
	}
	newP := C.GoString(newPath)
	return pathOp(volumeID, oldPath, func(volume *Volume, path string) error {
		return volume.rename(path, newP)
	})
}

// Which fields of setAttrRequest to apply.
const (
	setMode  = C.GCFC_SET_MODE
	setUID   = C.GCFC_SET_UID
	setGID   = C.GCFC_SET_GID
	setFlags = C.GCFC_SET_FLAGS
	setAtime = C.GCFC_SET_ATIME
	setMtime = C.GCFC_SET_MTIME
	setBtime = C.GCFC_SET_BTIME
)

func goSetAttr(req *C.gcfc_setattr_t) setAttrRequest {
	return setAttrRequest{
		valid: uint32(req.valid),
		mode:  uint32(req.mode),
		uid:   uint32(req.uid),
		gid:   uint32(req.gid),
		flags: uint32(req.flags),
		atime: unix.Timespec{Sec: int64(req.atime_sec), Nsec: int64(req.atime_nsec)},
		mtime: unix.Timespec{Sec: int64(req.mtime_sec), Nsec: int64(req.mtime_nsec)},
		btime: unix.Timespec{Sec: int64(req.btime_sec), Nsec: int64(req.btime_nsec)},
	}
}

// gcfc_setattr 改条目自身的权限、属主、flags 和时间：经目录 fd 定位、不跟随
// 符号链接（按密文路径字符串调 chmod(2) 会跟随最后一层符号链接，改到卷外的
// 文件上）。成功返回 0，失败返回负的 errno（改属主到别的用户是 -EPERM）。
//
//export gcfc_setattr
func gcfc_setattr(volumeID C.int, plainPath *C.char, req *C.gcfc_setattr_t) (ret C.int) {
	defer recoverTo(&ret, -C.int(syscall.EIO))
	if req == nil {
		return -C.int(syscall.EINVAL)
	}
	r := goSetAttr(req)
	return pathOp(volumeID, plainPath, func(volume *Volume, path string) error {
		return volume.setAttrPath(path, r)
	})
}

// gcfc_fsetattr 同 gcfc_setattr，但作用于已打开的句柄：条目被删除或被覆盖之后，
// 路径已经指向别的文件。
//
//export gcfc_fsetattr
func gcfc_fsetattr(volumeID C.int, handleID C.int, req *C.gcfc_setattr_t) (ret C.int) {
	defer recoverTo(&ret, -C.int(syscall.EIO))
	if req == nil {
		return -C.int(syscall.EINVAL)
	}
	volume := acquireVolume(int(volumeID))
	if volume == nil {
		return -C.int(syscall.EBADF)
	}
	defer volume.release()
	if err := volume.setAttrHandle(int(handleID), goSetAttr(req)); err != nil {
		return errnoOf(err)
	}
	return 0
}

// ── 新建 vault ────────────────────────────────────────────────────────────────

// gcfc_init_vault 的返回码。成功是 0，其余全部为负。
//
// 这些值与 Swift 侧 GocryptfsEngine.InitStatus 一一对应，改动时两边一起改。
const (
	initVaultOK            = 0
	initVaultBadArgs       = -1 // 空指针、空路径或空密码
	initVaultBadDir        = -2 // 目录不存在、不是目录，或无法读取
	initVaultAlreadyExists = -3 // 目录里已经有 gocryptfs.conf
	initVaultDirNotEmpty   = -4 // 目录非空
	initVaultBadLogN       = -5 // scrypt logN 越界
	initVaultConfFailed    = -6 // 写 gocryptfs.conf 失败
	initVaultDirIVFailed   = -7 // 写 root gocryptfs.diriv 失败
	initVaultInternal      = -8 // 捕获到 panic
)

// scrypt logN 的取值范围。上游 ScryptKDF.DeriveKey 在 N < 2^10 时直接
// os.Exit(exitcodes.ScryptParams)，而 1<<logN 在 logN 足够大时会溢出成负数。
// c-archive 场景下 os.Exit 会带走整个宿主 FSKit 扩展进程，所以参数必须在
// 进门处挡住，不能指望下游报错。
const (
	initVaultDefaultLogN = 16 // 同 configfile.ScryptDefaultLogN
	initVaultMinLogN     = 10
	initVaultMaxLogN     = 20 // R 固定为 8：128·2^20·8 = 1 GiB，打开卷时的内存上限（scrypt.go）
)

// Creator 只是写给人看的出处标记，不参与任何判定。
const initVaultCreator = "gocryptfs v2.6.1; GocryptKit"

// gcfc_init_vault 在 rootCipherDir 就地创建一个新的 gocryptfs 卷：
// 随机 master key → scrypt 派生的 KEK 包裹 → 写 gocryptfs.conf → 写根目录的
// gocryptfs.diriv。目录必须已存在且为空。
//
// logN 传 0 表示用默认值 16；成功时 returnedScryptHashBuff（至少 32 字节）
// 收到 scrypt hash，调用方可以直接拿它挂载，省掉一次数秒级的重复派生。
//
// 这里没有复用上游的 gcf_create_volume：那个入口只回传 bool（分不清"目录非空"
// 和"磁盘写失败"），而且把 logN 原样透传给 NewScryptKDF。
func gcfc_init_vault_impl(rootCipherDir *C.char, password *C.char, logN C.int, returnedScryptHashBuff *C.uint8_t, returnedHashCap C.size_t) C.int {
	if rootCipherDir == nil || password == nil || returnedScryptHashBuff == nil || returnedHashCap < 32 {
		return initVaultBadArgs
	}

	rDir := C.GoString(rootCipherDir)
	pwBytes := C.GoBytes(unsafe.Pointer(password), C.int(C.strlen(password)))
	defer wipe(pwBytes)
	// 空密码一律拒绝。这里绝不替用户编一个默认密码 —— 一个图方便的兜底
	// 密码曾经让凭据通道三个里程碑无人发现是坏的。
	if rDir == "" || len(pwBytes) == 0 {
		return initVaultBadArgs
	}

	n := int(logN)
	if n == 0 {
		n = initVaultDefaultLogN
	}
	if n < initVaultMinLogN || n > initVaultMaxLogN {
		return initVaultBadLogN
	}

	fi, err := os.Stat(rDir)
	if err != nil || !fi.IsDir() {
		return initVaultBadDir
	}

	confPath := filepath.Join(rDir, configfile.ConfDefaultName)
	if _, err := os.Lstat(confPath); err == nil {
		// 已经是一个 vault。覆盖它等于用新 master key 换掉旧的，里面的密文
		// 将永远解不开 —— 只能拒绝。
		return initVaultAlreadyExists
	}

	// 非空目录同样拒绝：gocryptfs 不会把已有文件加密，它们会原样留在密文目录里，
	// 挂载后却看不见，用户很容易误以为这些数据已经被保护了。
	entries, err := os.ReadDir(rDir)
	if err != nil {
		return initVaultBadDir
	}
	for _, e := range entries {
		// Finder 逛一圈就会留下 .DS_Store，不该因此挡住用户。
		if e.Name() == ".DS_Store" {
			continue
		}
		return initVaultDirNotEmpty
	}

	scryptHash := make([]byte, 32)
	defer wipe(scryptHash)

	err = configfile.Create(&configfile.CreateArgs{
		Filename:       confPath,
		Password:       pwBytes,
		PlaintextNames: false,
		LogN:           n,
		Creator:        initVaultCreator,
		AESSIV:         false,
		// 文件名加密保留 DirIV（每个目录一份随机 IV），这是 gocryptfs 的默认值。
		DeterministicNames: false,
		// Apple Silicon 有 AES 硬件加速，走 AES-GCM；没有的机器退回 XChaCha20。
		XChaCha20Poly1305: !stupidgcm.HasAESGCMHardwareSupport(),
		LongNameMax:       255,
		Masterkey:         nil,
	}, scryptHash)
	if err != nil {
		os.Remove(confPath)
		return initVaultConfFailed
	}

	dirfd, err := syscall.Open(rDir, syscall.O_DIRECTORY|syscallcompat.O_PATH, 0)
	if err != nil {
		os.Remove(confPath)
		return initVaultDirIVFailed
	}
	err = nametransform.WriteDirIVAt(dirfd)
	syscall.Close(dirfd)
	if err != nil {
		// 半成品卷比没有卷更糟：conf 解得开、根目录却没有 IV，挂载后
		// 目录读取直接 EIO。宁可回到"这里什么都没有"的状态。
		os.Remove(confPath)
		return initVaultDirIVFailed
	}

	C.memcpy(unsafe.Pointer(returnedScryptHashBuff), unsafe.Pointer(&scryptHash[0]), 32)
	debug.FreeOSMemory()
	return initVaultOK
}

//export gcfc_init_vault
func gcfc_init_vault(rootCipherDir *C.char, password *C.char, logN C.int, returnedScryptHashBuff *C.uint8_t, returnedHashCap C.size_t) (ret C.int) {
	// configfile.Create 这条路径上有 log.Panicf（cryptocore.RandBytes、
	// ScryptKDF.DeriveKey）。在 c-archive 里未捕获的 panic 会终止整个宿主
	// 进程 —— 对 FSKit 扩展来说就是卷被静默卸载。所以在 C 边界上兜住，
	// 一律转成错误码返回。
	defer recoverTo(&ret, C.int(initVaultInternal))
	return gcfc_init_vault_impl(rootCipherDir, password, logN, returnedScryptHashBuff, returnedHashCap)
}

// ── 扩展属性（xattr）──────────────────────────────────────────────────────────
//
// 存储方案与上游 gocryptfs 一致：xattr 落在**密文侧那个文件自己的原生 xattr**
// 上，名字用固定 IV 走 EME 加密再 base64，值用 contentenc 加密。名字和值都不以
// 明文落盘。
//
// 为什么必须做：FSKit 卷不声明 xattr 支持时，macOS 内核会给每个文件生成一个
// AppleDouble 边车文件（`._foo`，4 KiB，其中 97% 是零填充）来代存 xattr。而
// macOS 14+ 会给**每一个**新建文件自动挂上 com.apple.provenance —— 于是"每个
// 文件都多一个 4 KiB 垃圾"。这些垃圾是密文目录里的真实文件，会跟着同步到其他
// 设备，在 DroidFS 里一览无余。

// 前缀与上游 gocryptfs 相同。
const xattrStorePrefix = "user.gocryptfs."

// xattr 名字没有目录级 IV 可用，而同一个名字每次都必须加密成同样的密文，否则写进去
// 就读不回来，所以用固定 IV。这是上游 gocryptfs 的取值
// （internal/nametransform/xattr.go），与 Linux 版互通靠它。
var xattrNameIV = []byte("xattr_name_iv_xx")

// GocryptKit 1.3.9 及更早版本写入的名字用的是全零 IV。旧条目照常能读、能删，
// 但不再写：每次写入都落成上游格式并删掉同名旧条目（惰性迁移，不批量改写）。
var legacyXattrNameIV = make([]byte, nametransform.DirIVLen)

const (
	// macOS `sys/xattr.h` 的 XATTR_MAXNAMELEN。
	xattrMaxNameLen = 127
	// 单个 xattr 值的上限。与 Swift 侧 maximumXattrSizeInBits = 16 对应。
	xattrMaxValueLen = 64 * 1024
	// 与 setxattr(2) 的 XATTR_CREATE / XATTR_REPLACE 对应。
	xattrFlagCreate  = 1
	xattrFlagReplace = 2
)

// xattrC 是 xattr 导出函数的公共部分：条目由明文路径（经目录 fd 解析，见
// xattr_at.go）或 handleID >= 0 的已打开句柄指定。失败时返回负的 errno。
func xattrC(volumeID C.int, plainPath *C.char, handleID C.int, fn func(volume *Volume, io xattrIO) error) C.int {
	if plainPath == nil && handleID < 0 {
		return -C.int(syscall.EINVAL)
	}
	volume := acquireVolume(int(volumeID))
	if volume == nil {
		return -C.int(syscall.EBADF)
	}
	defer volume.release()
	var path string
	if handleID < 0 {
		path = C.GoString(plainPath)
	}
	err := volume.xattrOp(path, int(handleID), func(io xattrIO) error { return fn(volume, io) })
	if err != nil {
		return errnoOf(err)
	}
	return 0
}

func (volume *Volume) encryptXattrName(attr string, iv []byte) (string, error) {
	cName, err := volume.nameTransform.EncryptName(attr, iv)
	if err != nil {
		return "", err
	}
	full := xattrStorePrefix + cName
	// 加密后的名字比原名长约 1.8 倍，超长的只能拒绝 —— 底层文件系统存不下。
	if len(full) > xattrMaxNameLen {
		return "", syscall.ENAMETOOLONG
	}
	return full, nil
}

// plausibleXattrName 用来分辨一个密文名是按哪种 IV 写的。用错 IV 解密时，填充校验
// 有约 1/256 的概率碰巧通过，得到的是一串随机字节；真正的属性名是可打印的 UTF-8。
func plausibleXattrName(name string) bool {
	if name == "" || !utf8.ValidString(name) {
		return false
	}
	for _, r := range name {
		if r < 0x20 || r == 0x7f {
			return false
		}
	}
	return true
}

// decryptXattrName 先按上游 IV 解，再按旧的全零 IV 解。
func (volume *Volume) decryptXattrName(cAttr string) (string, error) {
	if !strings.HasPrefix(cAttr, xattrStorePrefix) {
		return "", syscall.EINVAL
	}
	cName := cAttr[len(xattrStorePrefix):]
	fallback, found := "", false
	for _, iv := range [][]byte{xattrNameIV, legacyXattrNameIV} {
		name, err := volume.nameTransform.DecryptName(cName, iv)
		if err != nil {
			continue
		}
		if plausibleXattrName(name) {
			return name, nil
		}
		if !found {
			fallback, found = name, true
		}
	}
	if found {
		return fallback, nil
	}
	return "", syscall.EINVAL
}

func getxattrAll(io xattrIO, cAttr string, maxSize int) ([]byte, error) {
	// 先探长度再读，避免为每个 xattr 都预分配 64 KiB。
	size, err := io.get(cAttr, nil)
	if err != nil {
		return nil, err
	}
	// 超过上限的值不是本卷写的，是在密文侧植入的。不能照探测到的长度分配：
	// 几 GiB 的分配失败是 Go 的 fatal error，recover 拦不住。
	if size > maxSize {
		return nil, syscall.E2BIG
	}
	data := make([]byte, size)
	n, err := io.get(cAttr, data)
	if err != nil {
		return nil, err
	}
	return data[:n], nil
}

func (volume *Volume) xattrGet(io xattrIO, attr string) ([]byte, error) {
	for _, iv := range [][]byte{xattrNameIV, legacyXattrNameIV} {
		cAttr, err := volume.encryptXattrName(attr, iv)
		if err != nil {
			return nil, err
		}
		cData, err := getxattrAll(io, cAttr, xattrMaxValueLen+int(volume.contentEnc.BlockOverhead()))
		if err == unix.ENOATTR {
			continue
		}
		if err != nil {
			return nil, err
		}
		plain, err := volume.contentEnc.DecryptBlock(cData, 0, nil)
		if err != nil {
			// 解不开说明这条 xattr 不是我们写的，或者卷被动过手脚。
			return nil, syscall.EIO
		}
		return copyOut(plain), nil
	}
	return nil, unix.ENOATTR
}

func (volume *Volume) xattrSet(io xattrIO, attr string, plain []byte, flags int) error {
	cAttr, err := volume.encryptXattrName(attr, xattrNameIV)
	if err != nil {
		return err
	}
	legacyAttr, err := volume.encryptXattrName(attr, legacyXattrNameIV)
	if err != nil {
		return err
	}
	_, legacyErr := io.get(legacyAttr, nil)
	legacyExists := legacyErr == nil
	cData := copyOut(volume.contentEnc.EncryptBlock(plain, 0, nil))

	// CREATE / REPLACE 语义按**明文**名字判断：旧格式的同名条目也算"已存在"。
	var sysFlags int
	switch flags {
	case xattrFlagCreate:
		if legacyExists {
			return syscall.EEXIST
		}
		sysFlags = unix.XATTR_CREATE
	case xattrFlagReplace:
		if !legacyExists {
			sysFlags = unix.XATTR_REPLACE
		}
	}
	if err := io.set(cAttr, cData, sysFlags); err != nil {
		return err
	}
	// 先写新名、再删旧名：中途失败只会两条并存，读取时新格式优先。
	if legacyExists {
		io.remove(legacyAttr)
	}
	return nil
}

func (volume *Volume) xattrRemove(io xattrIO, attr string) error {
	removed := false
	for _, iv := range [][]byte{xattrNameIV, legacyXattrNameIV} {
		cAttr, err := volume.encryptXattrName(attr, iv)
		if err != nil {
			return err
		}
		err = io.remove(cAttr)
		if err == nil {
			removed = true
		} else if err != unix.ENOATTR {
			return err
		}
	}
	if !removed {
		return unix.ENOATTR
	}
	return nil
}

func (volume *Volume) xattrList(io xattrIO) ([]string, error) {
	size, err := io.list(nil)
	if err != nil {
		return nil, err
	}
	buf := make([]byte, size)
	n, err := io.list(buf)
	if err != nil {
		return nil, err
	}
	var names []string
	seen := make(map[string]bool)
	for _, raw := range bytes.Split(buf[:n], []byte{0}) {
		if len(raw) == 0 {
			continue
		}
		// 不是我们写的 xattr（比如底层文件系统自己的）一律跳过，不往上报。
		plainName, err := volume.decryptXattrName(string(raw))
		if err != nil || seen[plainName] {
			continue
		}
		seen[plainName] = true
		names = append(names, plainName)
	}
	return names, nil
}

// EncryptBlock / DecryptBlock 返回的是缓冲池里的切片，池子随时可能被复用，
// 所以一律拷贝一份再交出去。
func copyOut(b []byte) []byte {
	out := make([]byte, len(b))
	copy(out, b)
	return out
}

func errnoOf(err error) C.int {
	var e syscall.Errno
	if errors.As(err, &e) {
		return -C.int(e)
	}
	return -C.int(syscall.EIO)
}

// xattr 的四个导出函数：条目由 plainPath 指定，或在 handleID >= 0 时由已打开的
// 句柄指定（条目被删除或被覆盖之后，路径已经指向别的文件）。
//
//export gcfc_get_xattr
func gcfc_get_xattr(volumeID C.int, plainPath *C.char, handleID C.int, name *C.char, dst unsafe.Pointer, dstLen C.size_t) (ret C.int64_t) {
	defer recoverTo(&ret, -C.int64_t(syscall.EIO))
	if name == nil {
		return -C.int64_t(syscall.EINVAL)
	}
	var plain []byte
	if res := xattrC(volumeID, plainPath, handleID, func(volume *Volume, io xattrIO) (err error) {
		plain, err = volume.xattrGet(io, C.GoString(name))
		return err
	}); res != 0 {
		return C.int64_t(res)
	}

	// dst 为空是"只问长度"的探测调用，POSIX getxattr 也是这个约定。
	if dst == nil || dstLen == 0 {
		return C.int64_t(len(plain))
	}
	if C.size_t(len(plain)) > dstLen {
		return -C.int64_t(syscall.ERANGE)
	}
	if len(plain) > 0 {
		C.memcpy(dst, unsafe.Pointer(&plain[0]), C.size_t(len(plain)))
	}
	return C.int64_t(len(plain))
}

//export gcfc_set_xattr
func gcfc_set_xattr(volumeID C.int, plainPath *C.char, handleID C.int, name *C.char, value unsafe.Pointer, valueLen C.size_t, flags C.int) (ret C.int) {
	defer recoverTo(&ret, -C.int(syscall.EIO))
	if name == nil {
		return -C.int(syscall.EINVAL)
	}
	if valueLen > xattrMaxValueLen {
		return -C.int(syscall.E2BIG)
	}
	var plain []byte
	if value != nil && valueLen > 0 {
		plain = C.GoBytes(value, C.int(valueLen))
	}
	return xattrC(volumeID, plainPath, handleID, func(volume *Volume, io xattrIO) error {
		return volume.xattrSet(io, C.GoString(name), plain, int(flags))
	})
}

//export gcfc_remove_xattr
func gcfc_remove_xattr(volumeID C.int, plainPath *C.char, handleID C.int, name *C.char) (ret C.int) {
	defer recoverTo(&ret, -C.int(syscall.EIO))
	if name == nil {
		return -C.int(syscall.EINVAL)
	}
	return xattrC(volumeID, plainPath, handleID, func(volume *Volume, io xattrIO) error {
		return volume.xattrRemove(io, C.GoString(name))
	})
}

// gcfc_list_xattr 按 listxattr(2) 的约定回填：一串以 NUL 分隔、整体不带结尾
// 哨兵的名字。dst 为空时只返回所需字节数。
//
//export gcfc_list_xattr
func gcfc_list_xattr(volumeID C.int, plainPath *C.char, handleID C.int, dst unsafe.Pointer, dstLen C.size_t) (ret C.int64_t) {
	defer recoverTo(&ret, -C.int64_t(syscall.EIO))
	var names []string
	if res := xattrC(volumeID, plainPath, handleID, func(volume *Volume, io xattrIO) (err error) {
		names, err = volume.xattrList(io)
		return err
	}); res != 0 {
		return C.int64_t(res)
	}
	var out []byte
	for _, name := range names {
		out = append(out, []byte(name)...)
		out = append(out, 0)
	}

	if dst == nil || dstLen == 0 {
		return C.int64_t(len(out))
	}
	if C.size_t(len(out)) > dstLen {
		return -C.int64_t(syscall.ERANGE)
	}
	if len(out) > 0 {
		C.memcpy(dst, unsafe.Pointer(&out[0]), C.size_t(len(out)))
	}
	return C.int64_t(len(out))
}
