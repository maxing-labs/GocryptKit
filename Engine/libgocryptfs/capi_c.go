package main

/*
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
    char* name;
    uint32_t mode;
} gcfc_dir_entry_t;
*/
import "C"

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"runtime/debug"
	"strings"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"

	"libgocryptfs/v2/internal/configfile"
	"libgocryptfs/v2/internal/contentenc"
	"libgocryptfs/v2/internal/nametransform"
	"libgocryptfs/v2/internal/stupidgcm"
	"libgocryptfs/v2/internal/syscallcompat"
)

// gcfc_init 的失败码。-3 是"引擎内部 panic"，与 -1/-2 区分开：前两者是用户能
// 理解并纠正的（没有 conf、密码不对），-3 只可能是 bug。
const initInternalError = -3

//export gcfc_init
func gcfc_init(rootCipherDir *C.char, password *C.char, givenScryptHash *C.uint8_t, hashLen C.size_t, returnedScryptHashBuff *C.uint8_t, returnedHashCap C.size_t) (ret C.int) {
	// 挂载是整条链上唯一会跑 scrypt 派生和 cryptocore 初始化的地方，那里有
	// log.Panicf（RandBytes 等）。c-archive 里未捕获的 panic 会终止宿主 FSKit
	// 扩展进程 —— 对已经挂着的其他卷来说就是被静默卸载。在 C 边界兜住。
	defer func() {
		if r := recover(); r != nil {
			ret = initInternalError
		}
	}()
	if rootCipherDir == nil {
		return -1
	}
	rDir := C.GoString(rootCipherDir)

	var pwBytes []byte
	if password != nil {
		pwBytes = []byte(C.GoString(password))
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
	gcf_close(int(volumeID))
}

//export gcfc_is_closed
func gcfc_is_closed(volumeID C.int) C.int {
	if gcf_is_closed(int(volumeID)) {
		return 1
	}
	return 0
}

//export gcfc_open_read_mode
func gcfc_open_read_mode(volumeID C.int, plainPath *C.char) C.int {
	if plainPath == nil {
		return -1
	}
	path := C.GoString(plainPath)
	h := gcf_open_read_mode(int(volumeID), path)
	return C.int(h)
}

//export gcfc_read_file
func gcfc_read_file(volumeID C.int, handleID C.int, offset C.uint64_t, dst unsafe.Pointer, length C.size_t) C.int64_t {
	if dst == nil || length == 0 {
		return 0
	}
	val, ok := OpenedVolumes.Load(int(volumeID))
	if !ok {
		return -C.int64_t(syscall.EBADF)
	}
	volume := val.(*Volume)

	volume.handlesLock.RLock()
	f, exists := volume.fileHandles[int(handleID)]
	volume.handlesLock.RUnlock()
	if !exists || f == nil {
		return -C.int64_t(syscall.EBADF)
	}

	f.fdLock.RLock()
	defer f.fdLock.RUnlock()
	f.contentLock.RLock()
	defer f.contentLock.RUnlock()

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
	gcf_close_file(int(volumeID), int(handleID))
}

//export gcfc_plain_size
func gcfc_plain_size(volumeID C.int, cipherSize C.uint64_t) C.uint64_t {
	val, ok := OpenedVolumes.Load(int(volumeID))
	if !ok {
		return 0
	}
	vol := val.(*Volume)
	return C.uint64_t(vol.contentEnc.CipherSizeToPlainSize(uint64(cipherSize)))
}

func (volume *Volume) getCipherPath(plainPath string) (string, error) {
	clean := filepath.Clean(plainPath)
	if clean == "." || clean == "/" || clean == "" {
		return volume.rootCipherDir, nil
	}
	clean = strings.TrimPrefix(clean, "/")
	parts := strings.Split(clean, "/")

	if volume.plainTextNames {
		return filepath.Join(append([]string{volume.rootCipherDir}, parts...)...), nil
	}

	curCipherDir := volume.rootCipherDir
	for _, part := range parts {
		var iv []byte
		if volume.nameTransform.DeterministicNames() {
			iv = make([]byte, nametransform.DirIVLen)
		} else {
			dirivFile := filepath.Join(curCipherDir, nametransform.DirIVFilename)
			data, err := os.ReadFile(dirivFile)
			if err != nil {
				return "", err
			}
			if len(data) < nametransform.DirIVLen {
				return "", syscall.EIO
			}
			iv = data[:nametransform.DirIVLen]
		}

		cName, err := volume.nameTransform.EncryptAndHashName(part, iv)
		if err != nil {
			return "", err
		}
		curCipherDir = filepath.Join(curCipherDir, cName)
	}
	return curCipherDir, nil
}

//export gcfc_cipher_path
func gcfc_cipher_path(volumeID C.int, plainPath *C.char) *C.char {
	if plainPath == nil {
		return nil
	}
	val, ok := OpenedVolumes.Load(int(volumeID))
	if !ok {
		return nil
	}
	volume := val.(*Volume)
	p := C.GoString(plainPath)

	cPath, err := volume.getCipherPath(p)
	if err != nil {
		return nil
	}
	return C.CString(cPath)
}

//export gcfc_readlink
func gcfc_readlink(volumeID C.int, plainPath *C.char) *C.char {
	if plainPath == nil {
		return nil
	}
	val, ok := OpenedVolumes.Load(int(volumeID))
	if !ok {
		return nil
	}
	volume := val.(*Volume)
	p := C.GoString(plainPath)

	dirfd, cName, err := volume.prepareAtSyscall(p)
	if err != nil {
		return nil
	}
	defer syscall.Close(dirfd)

	target := volume.readlink(dirfd, cName)
	if target == nil {
		return nil
	}
	return C.CString(string(target))
}

//export gcfc_list_dir
func gcfc_list_dir(volumeID C.int, plainDir *C.char, outEntries **C.gcfc_dir_entry_t, outCount *C.int) C.int {
	if plainDir == nil || outEntries == nil || outCount == nil {
		return -C.int(syscall.EINVAL)
	}
	val, ok := OpenedVolumes.Load(int(volumeID))
	if !ok {
		return -C.int(syscall.EBADF)
	}
	volume := val.(*Volume)
	dir := C.GoString(plainDir)
	if dir == "" {
		dir = "/"
	}

	parentDirFd, cDirName, err := volume.prepareAtSyscallMyself(dir)
	if err != nil {
		return -C.int(syscall.ENOENT)
	}
	defer syscall.Close(parentDirFd)

	fd, err := syscallcompat.Openat(parentDirFd, cDirName, syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return -C.int(syscall.ENOENT)
	}
	defer syscall.Close(fd)

	cipherEntries, err := syscallcompat.Getdents(fd)
	if err != nil {
		return -C.int(syscall.EIO)
	}

	var cachedIV []byte
	if !volume.plainTextNames {
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
	if str != nil {
		C.free(unsafe.Pointer(str))
	}
}

//export gcfc_open_write_mode
func gcfc_open_write_mode(volumeID C.int, plainPath *C.char, mode C.uint32_t) C.int {
	if plainPath == nil {
		return -1
	}
	path := C.GoString(plainPath)
	h := gcf_open_write_mode(int(volumeID), path, uint32(mode))
	return C.int(h)
}

//export gcfc_write_file
func gcfc_write_file(volumeID C.int, handleID C.int, offset C.uint64_t, src unsafe.Pointer, length C.size_t) C.int64_t {
	if src == nil || length == 0 {
		return 0
	}
	val, ok := OpenedVolumes.Load(int(volumeID))
	if !ok {
		return -C.int64_t(syscall.EBADF)
	}
	volume := val.(*Volume)

	volume.handlesLock.RLock()
	f, exists := volume.fileHandles[int(handleID)]
	volume.handlesLock.RUnlock()
	if !exists || f == nil {
		return -C.int64_t(syscall.EBADF)
	}

	f.fdLock.RLock()
	defer f.fdLock.RUnlock()
	f.contentLock.Lock()
	defer f.contentLock.Unlock()

	data := C.GoBytes(src, C.int(length))

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
		n, success := volume.doWrite(int(handleID), chunk, uint64(offset)+uint64(start))
		if !success {
			if written > 0 {
				// 部分成功：返回已写字节数，由上层决定是否重试剩余部分
				return C.int64_t(written)
			}
			return -C.int64_t(syscall.EIO)
		}
		written += uint64(n)
		if int(n) < len(chunk) {
			// 短写，停止并向上层如实汇报
			break
		}
	}
	return C.int64_t(written)
}

//export gcfc_truncate
func gcfc_truncate(volumeID C.int, plainPath *C.char, offset C.uint64_t) C.int {
	if plainPath == nil {
		return -C.int(syscall.EINVAL)
	}
	path := C.GoString(plainPath)
	if gcf_truncate(int(volumeID), path, uint64(offset)) {
		return 0
	}
	return -C.int(syscall.EIO)
}

//export gcfc_remove_file
func gcfc_remove_file(volumeID C.int, plainPath *C.char) C.int {
	if plainPath == nil {
		return -C.int(syscall.EINVAL)
	}
	path := C.GoString(plainPath)
	if gcf_remove_file(int(volumeID), path) {
		return 0
	}
	return -C.int(syscall.EIO)
}

//export gcfc_mkdir
func gcfc_mkdir(volumeID C.int, plainPath *C.char, mode C.uint32_t) C.int {
	if plainPath == nil {
		return -C.int(syscall.EINVAL)
	}
	path := C.GoString(plainPath)
	if gcf_mkdir(int(volumeID), path, uint32(mode)) {
		return 0
	}
	return -C.int(syscall.EIO)
}

//export gcfc_rmdir
func gcfc_rmdir(volumeID C.int, plainPath *C.char) C.int {
	if plainPath == nil {
		return -C.int(syscall.EINVAL)
	}
	path := C.GoString(plainPath)
	if gcf_rmdir(int(volumeID), path) {
		return 0
	}
	return -C.int(syscall.EIO)
}

//export gcfc_rename
func gcfc_rename(volumeID C.int, oldPath *C.char, newPath *C.char) C.int {
	if oldPath == nil || newPath == nil {
		return -C.int(syscall.EINVAL)
	}
	oldP := C.GoString(oldPath)
	newP := C.GoString(newPath)
	if gcf_rename(int(volumeID), oldP, newP) {
		return 0
	}
	return -C.int(syscall.EIO)
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
	initVaultMaxLogN     = 31
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
	pwBytes := []byte(C.GoString(password))
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
	defer func() {
		if r := recover(); r != nil {
			ret = initVaultInternal
		}
	}()
	return gcfc_init_vault_impl(rootCipherDir, password, logN, returnedScryptHashBuff, returnedHashCap)
}

// ── 扩展属性（xattr）──────────────────────────────────────────────────────────
//
// 存储方案与上游 gocryptfs 一致：xattr 落在**密文侧那个文件自己的原生 xattr**
// 上，名字用固定的全零 IV 走 EME 加密再 base64，值用 contentenc 加密。名字和值
// 都不以明文落盘。
//
// 为什么必须做：FSKit 卷不声明 xattr 支持时，macOS 内核会给每个文件生成一个
// AppleDouble 边车文件（`._foo`，4 KiB，其中 97% 是零填充）来代存 xattr。而
// macOS 14+ 会给**每一个**新建文件自动挂上 com.apple.provenance —— 于是"每个
// 文件都多一个 4 KiB 垃圾"。这些垃圾是密文目录里的真实文件，会跟着同步到其他
// 设备，在 DroidFS 里一览无余。

// 与上游 gocryptfs 相同的前缀，便于 Linux 上的 gocryptfs 直接读写同一批 xattr。
const xattrStorePrefix = "user.gocryptfs."

// xattr 名字没有目录级 IV 可用，而同一个名字每次都必须加密成同样的密文，
// 否则写进去就读不回来。所以固定用全零 IV —— 这也是上游的做法。
var xattrNameIV = make([]byte, nametransform.DirIVLen)

const (
	// macOS `sys/xattr.h` 的 XATTR_MAXNAMELEN。
	xattrMaxNameLen = 127
	// 单个 xattr 值的上限。与 Swift 侧 maximumXattrSizeInBits = 16 对应。
	xattrMaxValueLen = 64 * 1024
	// 与 setxattr(2) 的 XATTR_CREATE / XATTR_REPLACE 对应。
	xattrFlagCreate  = 1
	xattrFlagReplace = 2
)

// xattrTarget 把明文路径解析成密文侧的真实路径。
func xattrTarget(volumeID C.int, plainPath *C.char) (*Volume, string, bool) {
	if plainPath == nil {
		return nil, "", false
	}
	val, ok := OpenedVolumes.Load(int(volumeID))
	if !ok {
		return nil, "", false
	}
	volume := val.(*Volume)
	cPath, err := volume.getCipherPath(C.GoString(plainPath))
	if err != nil {
		return nil, "", false
	}
	return volume, cPath, true
}

func (volume *Volume) encryptXattrName(attr string) (string, error) {
	cName, err := volume.nameTransform.EncryptName(attr, xattrNameIV)
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

func (volume *Volume) decryptXattrName(cAttr string) (string, error) {
	if !strings.HasPrefix(cAttr, xattrStorePrefix) {
		return "", syscall.EINVAL
	}
	return volume.nameTransform.DecryptName(cAttr[len(xattrStorePrefix):], xattrNameIV)
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

//export gcfc_get_xattr
func gcfc_get_xattr(volumeID C.int, plainPath *C.char, name *C.char, dst unsafe.Pointer, dstLen C.size_t) (ret C.int64_t) {
	defer func() {
		if r := recover(); r != nil {
			ret = -C.int64_t(syscall.EIO)
		}
	}()
	if name == nil {
		return -C.int64_t(syscall.EINVAL)
	}
	volume, cPath, ok := xattrTarget(volumeID, plainPath)
	if !ok {
		return -C.int64_t(syscall.ENOENT)
	}
	cAttr, err := volume.encryptXattrName(C.GoString(name))
	if err != nil {
		return C.int64_t(errnoOf(err))
	}

	// 先探长度再读，避免为每个 xattr 都预分配 64 KiB。
	size, err := unix.Lgetxattr(cPath, cAttr, nil)
	if err != nil {
		return C.int64_t(errnoOf(err))
	}
	cData := make([]byte, size)
	n, err := unix.Lgetxattr(cPath, cAttr, cData)
	if err != nil {
		return C.int64_t(errnoOf(err))
	}
	plain, err := volume.contentEnc.DecryptBlock(cData[:n], 0, nil)
	if err != nil {
		// 解不开说明这条 xattr 不是我们写的，或者卷被动过手脚。
		return -C.int64_t(syscall.EIO)
	}
	plain = copyOut(plain)

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
func gcfc_set_xattr(volumeID C.int, plainPath *C.char, name *C.char, value unsafe.Pointer, valueLen C.size_t, flags C.int) (ret C.int) {
	defer func() {
		if r := recover(); r != nil {
			ret = -C.int(syscall.EIO)
		}
	}()
	if name == nil {
		return -C.int(syscall.EINVAL)
	}
	if valueLen > xattrMaxValueLen {
		return -C.int(syscall.E2BIG)
	}
	volume, cPath, ok := xattrTarget(volumeID, plainPath)
	if !ok {
		return -C.int(syscall.ENOENT)
	}
	cAttr, err := volume.encryptXattrName(C.GoString(name))
	if err != nil {
		return errnoOf(err)
	}

	var plain []byte
	if value != nil && valueLen > 0 {
		plain = C.GoBytes(value, C.int(valueLen))
	}
	cData := copyOut(volume.contentEnc.EncryptBlock(plain, 0, nil))

	// CREATE / REPLACE 语义要按**明文**名字判断，所以转换成密文名之后直接透传
	// 给底层 setxattr —— 密文名和明文名是一一对应的，语义不会走样。
	var sysFlags int
	switch flags {
	case xattrFlagCreate:
		sysFlags = unix.XATTR_CREATE
	case xattrFlagReplace:
		sysFlags = unix.XATTR_REPLACE
	}
	if err := unix.Lsetxattr(cPath, cAttr, cData, sysFlags); err != nil {
		return errnoOf(err)
	}
	return 0
}

//export gcfc_remove_xattr
func gcfc_remove_xattr(volumeID C.int, plainPath *C.char, name *C.char) (ret C.int) {
	defer func() {
		if r := recover(); r != nil {
			ret = -C.int(syscall.EIO)
		}
	}()
	if name == nil {
		return -C.int(syscall.EINVAL)
	}
	volume, cPath, ok := xattrTarget(volumeID, plainPath)
	if !ok {
		return -C.int(syscall.ENOENT)
	}
	cAttr, err := volume.encryptXattrName(C.GoString(name))
	if err != nil {
		return errnoOf(err)
	}
	if err := unix.Lremovexattr(cPath, cAttr); err != nil {
		return errnoOf(err)
	}
	return 0
}

// gcfc_list_xattr 按 listxattr(2) 的约定回填：一串以 NUL 分隔、整体不带结尾
// 哨兵的名字。dst 为空时只返回所需字节数。
//
//export gcfc_list_xattr
func gcfc_list_xattr(volumeID C.int, plainPath *C.char, dst unsafe.Pointer, dstLen C.size_t) (ret C.int64_t) {
	defer func() {
		if r := recover(); r != nil {
			ret = -C.int64_t(syscall.EIO)
		}
	}()
	volume, cPath, ok := xattrTarget(volumeID, plainPath)
	if !ok {
		return -C.int64_t(syscall.ENOENT)
	}

	size, err := unix.Llistxattr(cPath, nil)
	if err != nil {
		return C.int64_t(errnoOf(err))
	}
	buf := make([]byte, size)
	n, err := unix.Llistxattr(cPath, buf)
	if err != nil {
		return C.int64_t(errnoOf(err))
	}

	var out []byte
	for _, raw := range bytes.Split(buf[:n], []byte{0}) {
		if len(raw) == 0 {
			continue
		}
		// 不是我们写的 xattr（比如底层文件系统自己的）一律跳过，不往上报。
		plainName, err := volume.decryptXattrName(string(raw))
		if err != nil {
			continue
		}
		out = append(out, []byte(plainName)...)
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
