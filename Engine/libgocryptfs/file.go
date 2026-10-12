package main

import (
	"C"
	"bytes"
	"io"
	"math"
	"os"
	"syscall"

	"golang.org/x/sys/unix"

	"libgocryptfs/v2/internal/contentenc"
	"libgocryptfs/v2/internal/nametransform"
	"libgocryptfs/v2/internal/syscallcompat"
)

// mangleOpenFlags is used by Create() and Open() to convert the open flags the user
// wants to the flags we internally use to open the backing file.
// The returned flags always contain O_NOFOLLOW.
func mangleOpenFlags(flags uint32) (newFlags int) {
	newFlags = int(flags)
	// Convert WRONLY to RDWR. We always need read access to do read-modify-write cycles.
	if (newFlags & syscall.O_ACCMODE) == syscall.O_WRONLY {
		newFlags = newFlags ^ os.O_WRONLY | os.O_RDWR
	}
	// We also cannot open the file in append mode, we need to seek back for RMW
	newFlags = newFlags &^ os.O_APPEND
	// O_DIRECT accesses must be aligned in both offset and length. Due to our
	// crypto header, alignment will be off, even if userspace makes aligned
	// accesses. Running xfstests generic/013 on ext4 used to trigger lots of
	// EINVAL errors due to missing alignment. Just fall back to buffered IO.
	newFlags = newFlags &^ syscallcompat.O_DIRECT
	// Create and Open are two separate FUSE operations, so O_CREAT should not
	// be part of the open flags.
	newFlags = newFlags &^ syscall.O_CREAT
	// We always want O_NOFOLLOW to be safe against symlink races
	newFlags |= syscall.O_NOFOLLOW
	return newFlags
}

// refuseSpecialFile fails if the name exists and is not a regular file.
// Opening a FIFO blocks until a peer shows up, which would pin an FSKit worker
// thread forever; the ciphertext directory may be shared or synced, so such a
// file can be planted. Checked before open(2) rather than with O_NONBLOCK,
// which changes how dataless (cloud placeholder) files behave.
func refuseSpecialFile(dirfd int, cName string) error {
	st, err := syscallcompat.Fstatat2(dirfd, cName, unix.AT_SYMLINK_NOFOLLOW)
	if err == syscall.ENOENT {
		return nil
	}
	if err != nil {
		return err
	}
	if !isRegular(uint32(st.Mode)) {
		return syscall.EINVAL
	}
	return nil
}

func (volume *Volume) registerFileHandle(fd int, cName, path string) int {
	osFile := os.NewFile(uintptr(fd), cName)
	info, err := osFile.Stat()
	if err != nil {
		osFile.Close()
		return -1
	}
	// Content I/O is only defined for regular files. The ciphertext directory
	// may be shared or synced, so a FIFO, socket or device can be planted in it.
	if !info.Mode().IsRegular() {
		osFile.Close()
		return -1
	}
	st := info.Sys().(*syscall.Stat_t)
	key := inodeKey{dev: uint64(st.Dev), ino: uint64(st.Ino)}
	volume.handlesLock.Lock()
	defer volume.handlesLock.Unlock()
	if volume.nextHandle >= math.MaxInt32 {
		// The C ABI carries handles as int32.
		osFile.Close()
		return -1
	}
	c := volume.nextHandle
	volume.nextHandle++
	entry := volume.fileEntries[key]
	if entry == nil {
		entry = &fileEntry{}
		volume.fileEntries[key] = entry
	}
	entry.refs++
	volume.fileHandles[c] = &File{
		fd:        osFile,
		path:      string([]byte(path[:])),
		key:       key,
		fileEntry: entry,
	}
	return c
}

// Acquire fdLock while the handle is still registered. No I/O below this
// boundary may reacquire handlesLock while holding fdLock/contentLock.
func (volume *Volume) lockFile(handleID int) *File {
	volume.handlesLock.RLock()
	defer volume.handlesLock.RUnlock()
	f := volume.fileHandles[handleID]
	if f != nil {
		f.fdLock.RLock()
	}
	return f
}

// readFileID loads the file header from disk and extracts the file ID.
// Returns io.EOF if the file is empty.
func readFileID(fd *os.File) ([]byte, error) {
	// We read +1 byte to determine if the file has actual content
	// and not only the header. A header-only file will be considered empty.
	// This makes File ID poisoning more difficult.
	readLen := contentenc.HeaderLen + 1
	buf := make([]byte, readLen)
	_, err := fd.ReadAt(buf, 0)
	if err != nil {
		return nil, err
	}
	buf = buf[:contentenc.HeaderLen]
	h, err := contentenc.ParseHeader(buf)
	if err != nil {
		return nil, err
	}
	return h.ID, nil
}

// createHeader creates a new random header and writes it to disk.
// Returns the new file ID.
// The caller must hold the shared contentLock exclusively.
func createHeader(fd *os.File) (fileID []byte, err error) {
	h := contentenc.RandomHeader()
	buf := h.Pack()
	// Prevent partially written (=corrupt) header by preallocating the space beforehand
	err = syscallcompat.EnospcPrealloc(int(fd.Fd()), 0, contentenc.HeaderLen)
	if err != nil {
		return nil, err
	}
	// Actually write header
	_, err = fd.WriteAt(buf, 0)
	if err != nil {
		return nil, err
	}
	return h.ID, err
}

// doRead - read "length" plaintext bytes from plaintext offset "off" and append
// to "dst".
// Arguments "length" and "off" do not have to be block-aligned.
//
// doRead reads the corresponding ciphertext blocks from disk, decrypts them and
// returns the requested part of the plaintext.
//
// Called by Read() for normal reading,
// by Write() and Truncate() via doWrite() for Read-Modify-Write.
func (volume *Volume) doRead(f *File, dst []byte, off uint64, length uint64) ([]byte, bool) {
	if length == 0 {
		return dst, true
	}
	fd := f.fd
	// Get the file ID, either from the open file table, or from disk.
	var fileID []byte
	f.idLock.Lock()
	if f.ID != nil {
		// Use the cached value in the file table
		fileID = f.ID
	} else {
		// Not cached, we have to read it from disk.
		var err error
		fileID, err = readFileID(fd)
		if err != nil {
			f.idLock.Unlock()
			if err == io.EOF {
				return dst, true
			}
			return nil, false
		}
		f.ID = fileID
	}
	f.idLock.Unlock()
	// Read the backing ciphertext in one go
	blocks := volume.contentEnc.ExplodePlainRange(off, length)
	alignedOffset, alignedLength := blocks[0].JointCiphertextRange(blocks)
	// f.fd.ReadAt takes an int64!
	if alignedOffset > math.MaxInt64 {
		return nil, false
	}
	skip := blocks[0].Skip

	ciphertext := volume.contentEnc.CReqPool.Get()
	ciphertext = ciphertext[:int(alignedLength)]
	n, err := fd.ReadAt(ciphertext, int64(alignedOffset))
	if err != nil && err != io.EOF {
		volume.contentEnc.CReqPool.Put(ciphertext)
		return nil, false
	}
	// The ReadAt came back empty. We can skip all the decryption and return early.
	if n == 0 {
		volume.contentEnc.CReqPool.Put(ciphertext)
		return dst, true
	}
	// Truncate ciphertext buffer down to actually read bytes
	ciphertext = ciphertext[0:n]

	firstBlockNo := blocks[0].BlockNo

	// Decrypt it
	plaintext, err := volume.contentEnc.DecryptBlocks(ciphertext, firstBlockNo, fileID)
	volume.contentEnc.CReqPool.Put(ciphertext)
	if err != nil {
		return nil, false
	}

	// Crop down to the relevant part
	var out []byte
	lenHave := len(plaintext)
	lenWant := int(skip + length)
	if lenHave > lenWant {
		out = plaintext[skip:lenWant]
	} else if lenHave > int(skip) {
		out = plaintext[skip:lenHave]
	}
	// else: out stays empty, file was smaller than the requested offset

	out = append(dst, out...)
	volume.contentEnc.PReqPool.Put(plaintext)

	return out, true
}

// doWrite - encrypt "data" and write it to plaintext offset "off"
//
// Arguments do not have to be block-aligned, read-modify-write is
// performed internally as necessary
//
// Called by Write() for normal writing,
// and by Truncate() to rewrite the last file block.
//
// Empty writes do nothing and are allowed.
// Errors carry the errno of the failing system call; a block that does not
// authenticate is EIO.
func (volume *Volume) doWrite(f *File, data []byte, off uint64) (uint32, error) {
	if len(data) == 0 {
		return 0, nil
	}
	fd := f.fd
	fileWasEmpty := false
	// An external truncation can remove a header without going through this entry.
	info, statErr := fd.Stat()
	if statErr != nil {
		return 0, statErr
	}
	if info.Size() < contentenc.HeaderLen {
		f.ID = nil
	}
	var fileID []byte
	if f.ID != nil {
		fileID = f.ID
	} else {
		// If the file ID is not cached, read it from disk
		var err error
		fileID, err = readFileID(fd)
		// Write a new file header if the file is empty
		if err == io.EOF {
			fileID, err = createHeader(fd)
			fileWasEmpty = true
		}
		if err != nil {
			return 0, err
		}
		f.ID = fileID
	}
	// Handle payload data
	dataBuf := bytes.NewBuffer(data)
	blocks := volume.contentEnc.ExplodePlainRange(off, uint64(len(data)))
	toEncrypt := make([][]byte, len(blocks))
	for i, b := range blocks {
		blockData := dataBuf.Next(int(b.Length))
		// Incomplete block -> Read-Modify-Write
		if b.IsPartial() {
			// Read
			oldData, success := volume.doRead(f, nil, b.BlockPlainOff(), volume.contentEnc.PlainBS())
			if !success {
				return 0, syscall.EIO
			}
			// Modify
			blockData = volume.contentEnc.MergeBlocks(oldData, blockData, int(b.Skip))
		}
		// Write into the to-encrypt list
		toEncrypt[i] = blockData
	}
	// Encrypt all blocks
	ciphertext := volume.contentEnc.EncryptBlocks(toEncrypt, blocks[0].BlockNo, fileID)
	// Preallocate so we cannot run out of space in the middle of the write.
	// This prevents partially written (=corrupt) blocks.
	var err error
	cOff := blocks[0].BlockCipherOff()
	// f.fd.WriteAt & syscallcompat.EnospcPrealloc take int64 offsets!
	if cOff > math.MaxInt64 {
		return 0, syscall.EFBIG
	}
	err = syscallcompat.EnospcPrealloc(int(fd.Fd()), int64(cOff), int64(len(ciphertext)))
	if err != nil {
		if fileWasEmpty {
			// Kill the file header again
			if syscall.Ftruncate(int(fd.Fd()), 0) == nil {
				f.ID = nil
			}
		}
		return 0, err
	}
	// Write
	_, err = f.fd.WriteAt(ciphertext, int64(cOff))
	// Return memory to CReqPool
	volume.contentEnc.CReqPool.Put(ciphertext)
	if err != nil {
		return 0, err
	}
	return uint32(len(data)), nil
}

// Zero-pad the file of size plainSize to the next block boundary. This is a no-op
// if the file is already block-aligned.
func (volume *Volume) zeroPad(f *File, plainSize uint64) error {
	lastBlockLen := plainSize % volume.contentEnc.PlainBS()
	if lastBlockLen == 0 {
		// Already block-aligned
		return nil
	}
	missing := volume.contentEnc.PlainBS() - lastBlockLen
	pad := make([]byte, missing)
	_, err := volume.doWrite(f, pad, plainSize)
	return err
}

// checkPlainRange refuses a plaintext range the ciphertext file cannot hold,
// before anything is written. Above MaxInt64 the ciphertext offset wraps around
// 2^64 and lands inside the file; below it, a range whose ciphertext end does
// not fit an off_t would fail only after the old last block was zero-padded.
func (volume *Volume) checkPlainRange(off, length uint64) error {
	if off > math.MaxInt64 {
		return syscall.EINVAL
	}
	if length > math.MaxInt64-off || volume.contentEnc.PlainSizeToCipherSize(off+length) > math.MaxInt64 {
		return syscall.EFBIG
	}
	return nil
}

// writePadHole zero-pads the last block when a write starts beyond the block
// that follows the current end of file. Without it the old partial last block
// ends up in the middle of the file and no longer authenticates (EIO).
// The caller must hold contentLock exclusively.
func (volume *Volume) writePadHole(f *File, targetOff uint64) error {
	info, err := f.fd.Stat()
	if err != nil {
		return err
	}
	plainSize := volume.contentEnc.CipherSizeToPlainSize(uint64(info.Size()))
	// Appending a single byte would write to "nextBlock".
	nextBlock := volume.contentEnc.PlainOffToBlockNo(plainSize)
	targetBlock := volume.contentEnc.PlainOffToBlockNo(targetOff)
	// The write goes into an existing block or directly after the last one.
	if targetBlock <= nextBlock {
		return nil
	}
	return volume.zeroPad(f, plainSize)
}

// truncateGrowFile extends a file using seeking or ftruncate performing RMW on
// the first and last block as necessary. New blocks in the middle become
// file holes unless they have been fallocate()'d beforehand.
func (volume *Volume) truncateGrowFile(f *File, oldPlainSz uint64, newPlainSz uint64) error {
	if newPlainSz <= oldPlainSz {
		return syscall.EINVAL
	}
	newEOFOffset := newPlainSz - 1
	if oldPlainSz > 0 {
		n1 := volume.contentEnc.PlainOffToBlockNo(oldPlainSz - 1)
		n2 := volume.contentEnc.PlainOffToBlockNo(newEOFOffset)
		// The file is grown within one block, no need to pad anything.
		// Write a single zero to the last byte and let doWrite figure out the RMW.
		if n1 == n2 {
			buf := make([]byte, 1)
			_, err := volume.doWrite(f, buf, newEOFOffset)
			return err
		}
	}
	// The truncate creates at least one new block.
	//
	// Make sure the old last block is padded to the block boundary. This call
	// is a no-op if it is already block-aligned.
	if err := volume.zeroPad(f, oldPlainSz); err != nil {
		return err
	}
	// The new size is block-aligned. In this case we can do everything ourselves
	// and avoid the call to doWrite.
	if newPlainSz%volume.contentEnc.PlainBS() == 0 {
		// The file was empty, so it did not have a header. Create one.
		if oldPlainSz == 0 {
			id, err := createHeader(f.fd)
			if err != nil {
				return err
			}
			f.ID = id
		}
		cSz := int64(volume.contentEnc.PlainSizeToCipherSize(newPlainSz))
		return syscall.Ftruncate(int(f.fd.Fd()), cSz)
	}
	// The new size is NOT aligned, so we need to write a partial block.
	// Write a single zero to the last byte and let doWrite figure it out.
	buf := make([]byte, 1)
	_, err := volume.doWrite(f, buf, newEOFOffset)
	return err
}

func (volume *Volume) truncate(f *File, newSize uint64) error {
	if err := volume.checkPlainRange(newSize, 0); err != nil {
		return err
	}
	fileFD := int(f.fd.Fd())
	var err error
	// Common case first: Truncate to zero
	if newSize == 0 {
		err = syscall.Ftruncate(fileFD, 0)
		if err == nil {
			f.ID = nil
		}
		return err
	}
	// We need the old file size to determine if we are growing or shrinking
	// the file
	info, err := f.fd.Stat()
	if err != nil {
		return err
	}
	oldSize := volume.contentEnc.CipherSizeToPlainSize(uint64(info.Size()))

	// File size stays the same - nothing to do
	if newSize == oldSize {
		return nil
	}
	// File grows
	if newSize > oldSize {
		return volume.truncateGrowFile(f, oldSize, newSize)
	}

	// File shrinks
	blockNo := volume.contentEnc.PlainOffToBlockNo(newSize)
	cipherOff := volume.contentEnc.BlockNoToCipherOff(blockNo)
	plainOff := volume.contentEnc.BlockNoToPlainOff(blockNo)
	lastBlockLen := newSize - plainOff
	var data []byte
	if lastBlockLen > 0 {
		var success bool
		data, success = volume.doRead(f, nil, plainOff, lastBlockLen)
		if !success {
			return syscall.EIO
		}
	}
	// Truncate down to the last complete block
	err = syscall.Ftruncate(fileFD, int64(cipherOff))
	if err != nil {
		return err
	}
	// Append partial block
	if lastBlockLen > 0 {
		_, err = volume.doWrite(f, data, plainOff)
		return err
	}
	return nil
}

// openRead opens an existing file for reading.
func (volume *Volume) openRead(path string) (int, error) {
	dirfd, cName, err := volume.prepareAtSyscallMyself(path)
	if err != nil {
		return -1, err
	}
	defer syscall.Close(dirfd)

	if err := refuseSpecialFile(dirfd, cName); err != nil {
		return -1, err
	}
	// Open backing file
	fd, err := syscallcompat.Openat(dirfd, cName, mangleOpenFlags(0), 0)
	if err != nil {
		return -1, err
	}
	h := volume.registerFileHandle(fd, cName, path)
	if h < 0 {
		return -1, syscall.EIO
	}
	return h, nil
}

func gcf_open_read_mode(sessionID int, path string) int {
	volume := acquireVolume(sessionID)
	if volume == nil {
		return -1
	}
	defer volume.release()
	h, err := volume.openRead(path)
	if err != nil {
		return -1
	}
	return h
}

type openHow int

const (
	// openExisting never creates: a writer that lost its file must fail
	// rather than resurrect the name (or write into whatever replaced it).
	openExisting openHow = iota
	// openOrCreate is the legacy gcf_open_write_mode behaviour.
	openOrCreate
	// createExclusive fails with EEXIST when the name already exists.
	createExclusive
)

// openWrite opens (and, depending on how, creates) a file for writing.
func (volume *Volume) openWrite(path string, mode uint32, how openHow) (int, error) {
	dirfd, cName, err := volume.prepareAtSyscall(path)
	if err != nil {
		return -1, err
	}
	defer syscall.Close(dirfd)

	if how != createExclusive {
		if err := refuseSpecialFile(dirfd, cName); err != nil {
			return -1, err
		}
	}
	newFlags := mangleOpenFlags(syscall.O_RDWR)
	switch how {
	case openOrCreate:
		newFlags |= syscall.O_CREAT
	case createExclusive:
		newFlags |= syscall.O_CREAT | syscall.O_EXCL
	}
	// Handle long file name: create ".name" before the content file.
	nameCreated := false
	if how != openExisting && !volume.plainTextNames && nametransform.IsLongContent(cName) {
		err = volume.nameTransform.WriteLongNameAt(dirfd, cName, path)
		nameCreated = (err == nil)
		// A leftover ".name" is not authoritative; the content file decides.
		if err != nil && err != syscall.EEXIST {
			return -1, err
		}
	}
	fd, err := syscallcompat.Openat(dirfd, cName, newFlags, mode)
	if err != nil {
		if nameCreated {
			nametransform.DeleteLongNameAt(dirfd, cName)
		}
		return -1, err
	}
	h := volume.registerFileHandle(fd, cName, path)
	if h < 0 {
		return -1, syscall.EIO
	}
	return h, nil
}

func gcf_open_write_mode(sessionID int, path string, mode uint32) int {
	volume := acquireVolume(sessionID)
	if volume == nil {
		return -1
	}
	defer volume.release()
	h, err := volume.openWrite(path, mode, openOrCreate)
	if err != nil {
		return -1
	}
	return h
}

func (volume *Volume) ftruncate(handleID int, size uint64) error {
	f := volume.lockFile(handleID)
	if f == nil {
		return syscall.EBADF
	}
	defer f.fdLock.RUnlock()
	f.contentLock.Lock()
	defer f.contentLock.Unlock()
	return volume.truncate(f, size)
}

func gcf_ftruncate(sessionID, handleID int, size uint64) bool {
	volume := acquireVolume(sessionID)
	if volume == nil {
		return false
	}
	defer volume.release()
	return errToBool(volume.ftruncate(handleID, size))
}

func gcf_truncate(sessionID int, path string, size uint64) bool {
	volume := acquireVolume(sessionID)
	if volume == nil {
		return false
	}
	defer volume.release()
	return errToBool(volume.truncatePath(path, size))
}

// truncatePath is the compatibility path API: resolve once and open an existing
// writable fd. Never scan handles by a stale path or create a missing file.
func (volume *Volume) truncatePath(path string, size uint64) error {
	h, err := volume.openWrite(path, 0, openExisting)
	if err != nil {
		return err
	}
	defer volume.closeFile(h)
	return volume.ftruncate(h, size)
}

func gcf_read_file(sessionID, handleID int, offset uint64, dst_buff []byte) uint32 {
	length := len(dst_buff)
	if length > contentenc.MAX_KERNEL_WRITE {
		// This would crash us due to our fixed-size buffer pool
		return 0
	}

	volume := acquireVolume(sessionID)
	if volume == nil {
		return 0
	}
	defer volume.release()

	f := volume.lockFile(handleID)
	if f == nil {
		return 0
	}
	defer f.fdLock.RUnlock()
	f.contentLock.RLock()
	defer f.contentLock.RUnlock()
	out, success := volume.doRead(f, dst_buff[:0], offset, uint64(length))
	if !success {
		return 0
	} else {
		return uint32(len(out))
	}
}

func gcf_write_file(sessionID, handleID int, offset uint64, data []byte) uint32 {
	length := len(data)
	if length > contentenc.MAX_KERNEL_WRITE {
		// This would crash us due to our fixed-size buffer pool
		return 0
	}

	volume := acquireVolume(sessionID)
	if volume == nil {
		return 0
	}
	defer volume.release()

	f := volume.lockFile(handleID)
	if f == nil {
		return 0
	}
	defer f.fdLock.RUnlock()
	f.contentLock.Lock()
	defer f.contentLock.Unlock()
	if volume.writePadHole(f, offset) != nil {
		return 0
	}
	n, _ := volume.doWrite(f, data, offset)
	return n
}

// closeFile removes the handle from the table before waiting for its I/O:
// in-flight operations hold fdLock and must never need handlesLock again.
func (volume *Volume) closeFile(handleID int) {
	volume.handlesLock.Lock()
	f := volume.fileHandles[handleID]
	delete(volume.fileHandles, handleID)
	volume.handlesLock.Unlock()
	if f == nil {
		return
	}
	// Wait for I/O without holding the table lock, then release the entry.
	f.fdLock.Lock()
	f.fd.Close()
	f.fdLock.Unlock()
	volume.handlesLock.Lock()
	f.refs--
	if f.refs == 0 {
		delete(volume.fileEntries, f.key)
	}
	volume.handlesLock.Unlock()
}

func gcf_close_file(sessionID, handleID int) {
	volume := acquireVolume(sessionID)
	if volume == nil {
		return
	}
	defer volume.release()
	volume.closeFile(handleID)
}

func (volume *Volume) removeFile(path string) error {
	dirfd, cName, err := volume.prepareAtSyscall(path)
	if err != nil {
		return err
	}
	defer syscall.Close(dirfd)

	// Delete content
	err = syscallcompat.Unlinkat(dirfd, cName, 0)
	if err != nil {
		return err
	}
	// Delete ".name" file
	if !volume.plainTextNames && nametransform.IsLongContent(cName) {
		err = nametransform.DeleteLongNameAt(dirfd, cName)
	}
	return err
}

func gcf_remove_file(sessionID int, path string) bool {
	volume := acquireVolume(sessionID)
	if volume == nil {
		return false
	}
	defer volume.release()
	return errToBool(volume.removeFile(path))
}
