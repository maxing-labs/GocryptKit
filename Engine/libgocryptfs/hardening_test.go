package main

import (
	"bytes"
	"fmt"
	"math"
	"os"
	"os/signal"
	"runtime"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"libgocryptfs/v2/internal/syscallcompat"
)

// I-3: a late call with the ID of a closed volume must not reach the volume
// that was opened next.
func TestVolumeIDsAreNotReused(t *testing.T) {
	first, _, _ := integrityVault(t)
	gcf_close(first)
	second, _, _ := integrityVault(t)
	if second == first {
		t.Fatal("volume ID reused")
	}
	if h := gcf_open_write_mode(first, "stray", 0600); h >= 0 {
		t.Error("an operation on a closed volume ID succeeded")
	}
	if _, _, _, exists := gcf_get_attrs(second, "stray"); exists {
		t.Error("a stale volume ID created a file in another vault")
	}
}

// I-4: a FIFO planted in the ciphertext directory must be refused, not opened
// (open(2) on a FIFO blocks until a peer appears).
func TestOpenRefusesPlantedFIFO(t *testing.T) {
	id, _, _ := integrityVault(t)
	volume := testVolume(t, id)
	integrityWrite(t, id, "pipe", []byte("regular"))
	cipherPath, err := volume.getCipherPath("pipe")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(cipherPath); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Mkfifo(cipherPath, 0600); err != nil {
		t.Fatal(err)
	}
	opens := map[string]func() int{
		"read":  func() int { return gcf_open_read_mode(id, "pipe") },
		"write": func() int { return gcf_open_write_mode(id, "pipe", 0600) },
	}
	for name, open := range opens {
		done := make(chan int, 1)
		go func() { done <- open() }()
		select {
		case h := <-done:
			if h >= 0 {
				t.Errorf("%s open of a FIFO returned a handle", name)
			}
		case <-time.After(3 * time.Second):
			// Unblock the stuck opener so the test process can exit.
			if peer, err := os.OpenFile(cipherPath, os.O_RDWR, 0); err == nil {
				defer peer.Close()
			}
			t.Fatalf("%s open of a planted FIFO blocked", name)
		}
	}
}

// F-21: closing a volume must end its directory-cache goroutine. It kept the
// volume, and the filename cipher with it, reachable for the life of the process.
func TestCloseStopsDirCacheGoroutine(t *testing.T) {
	dir := t.TempDir()
	password := []byte("goroutine-leak-test")
	if !gcf_create_volume(dir, bytes.Clone(password), false, 0, 10, "hardening-test", nil) {
		t.Fatal("create vault")
	}
	cycle := func() {
		id := gcf_init(dir, bytes.Clone(password), nil, nil)
		if id < 0 {
			t.Fatal("open vault")
		}
		gcf_mkdir(id, "d", 0700)
		gcf_get_attrs(id, "d/probe") // populates the directory cache, which starts its goroutine
		gcf_close(id)
	}
	cycle()
	time.Sleep(50 * time.Millisecond)
	before := runtime.NumGoroutine()
	for i := 0; i < 20; i++ {
		cycle()
	}
	time.Sleep(200 * time.Millisecond)
	if leaked := runtime.NumGoroutine() - before; leaked > 2 {
		t.Fatalf("%d goroutines leaked across 20 open/close cycles", leaked)
	}
}

// I-1: mutations report what actually went wrong.
func TestMutationsReportErrno(t *testing.T) {
	id, _, _ := integrityVault(t)
	volume := testVolume(t, id)
	if err := volume.mkdir("d", 0700); err != nil {
		t.Fatal(err)
	}
	integrityWrite(t, id, "d/f", []byte("x"))
	cases := []struct {
		name string
		err  error
		want syscall.Errno
	}{
		{"mkdir over an existing directory", volume.mkdir("d", 0700), syscall.EEXIST},
		{"rmdir of a non-empty directory", volume.rmdir("d"), syscall.ENOTEMPTY},
		{"rmdir of a missing directory", volume.rmdir("missing"), syscall.ENOENT},
		{"remove of a missing file", volume.removeFile("missing"), syscall.ENOENT},
		{"rename of a missing file", volume.rename("missing", "other"), syscall.ENOENT},
	}
	for _, c := range cases {
		if c.err != c.want {
			t.Errorf("%s: want %v, got %v", c.name, c.want, c.err)
		}
	}
}

// withFileSizeLimit runs fn with RLIMIT_FSIZE lowered to limit: growing a file
// past it fails with EFBIG (SIGXFSZ is ignored meanwhile).
func withFileSizeLimit(t *testing.T, limit uint64, fn func()) {
	t.Helper()
	var old syscall.Rlimit
	if err := syscall.Getrlimit(syscall.RLIMIT_FSIZE, &old); err != nil {
		t.Fatal(err)
	}
	signal.Ignore(syscall.SIGXFSZ)
	defer signal.Reset(syscall.SIGXFSZ)
	lowered := old
	lowered.Cur = limit
	if err := syscall.Setrlimit(syscall.RLIMIT_FSIZE, &lowered); err != nil {
		t.Fatal(err)
	}
	defer syscall.Setrlimit(syscall.RLIMIT_FSIZE, &old)
	fn()
}

// I-1: truncate and write report what went wrong instead of a blanket EIO.
func TestTruncateAndWriteReportErrno(t *testing.T) {
	id, _, _ := integrityVault(t)
	integrityWrite(t, id, "f", []byte("data"))
	h := gcf_open_write_mode(id, "f", 0600)
	if h < 0 {
		t.Fatal("open writer")
	}
	defer gcf_close_file(id, h)
	stale := gcf_open_write_mode(id, "f", 0600)
	gcf_close_file(id, stale)

	var aligned, unaligned, write int
	withFileSizeLimit(t, 1<<20, func() {
		aligned = shimFtruncate(id, h, 4<<20)
		unaligned = shimFtruncate(id, h, 4<<20+1)
		write = int(shimWriteFile(id, h, 3<<20, []byte("x")))
	})
	cases := []struct {
		name string
		got  int
		want syscall.Errno
	}{
		{"ftruncate of a closed handle", shimFtruncate(id, stale, 0), syscall.EBADF},
		{"truncate of a missing path", shimTruncate(id, "missing", 0), syscall.ENOENT},
		{"block-aligned grow past RLIMIT_FSIZE", aligned, syscall.EFBIG},
		{"unaligned grow past RLIMIT_FSIZE", unaligned, syscall.EFBIG},
		{"write past RLIMIT_FSIZE", write, syscall.EFBIG},
	}
	for _, c := range cases {
		if c.got != -int(c.want) {
			t.Errorf("%s: want -%d (%v), got %d", c.name, int(c.want), c.want, c.got)
		}
	}
	if got := integrityRead(t, id, "f"); !bytes.HasPrefix(got, []byte("data")) {
		t.Error("the failed grows damaged the file")
	}
}

// Fstatat2 feeds every path-based stat. It dropped st_flags and the birth time,
// so the mounted volume showed all files as created in 1970 and never hidden.
func TestFstatat2KeepsFlagsAndBirthTime(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/f"
	if err := os.WriteFile(path, []byte("x"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := unix.Chflags(path, unix.UF_HIDDEN); err != nil {
		t.Fatal(err)
	}
	defer unix.Chflags(path, 0)
	var want unix.Stat_t
	if err := unix.Lstat(path, &want); err != nil {
		t.Fatal(err)
	}
	got, err := syscallcompat.Fstatat2(unix.AT_FDCWD, path, unix.AT_SYMLINK_NOFOLLOW)
	if err != nil {
		t.Fatal(err)
	}
	if got.Flags != want.Flags {
		t.Errorf("flags: want %#x, got %#x", want.Flags, got.Flags)
	}
	if got.Birthtimespec.Sec != want.Btim.Sec || got.Birthtimespec.Nsec != want.Btim.Nsec {
		t.Errorf("birth time: want %v, got %v", want.Btim, got.Birthtimespec)
	}
}

func plaintextNamesVault(t *testing.T) (int, string) {
	t.Helper()
	dir := t.TempDir()
	password := []byte("plaintextnames-test")
	if !gcf_create_volume(dir, bytes.Clone(password), true, 0, 10, "plaintextnames-test", nil) {
		t.Fatal("create vault")
	}
	id := gcf_init(dir, bytes.Clone(password), nil, nil)
	if id < 0 {
		t.Fatal("open vault")
	}
	t.Cleanup(func() { gcf_close(id) })
	return id, dir
}

// P-1: with plaintextnames the root gocryptfs.conf sits next to the user's files
// under its own name. Every path operation must refuse it, however it is
// spelled; renaming a file onto it would replace the wrapped master key.
func TestPlaintextNamesReserveRootConf(t *testing.T) {
	id, dir := plaintextNamesVault(t)
	volume := testVolume(t, id)
	confPath := dir + "/gocryptfs.conf"
	conf, err := os.ReadFile(confPath)
	if err != nil {
		t.Fatal(err)
	}
	var before unix.Stat_t
	if err := unix.Lstat(confPath, &before); err != nil {
		t.Fatal(err)
	}
	xattrNames := func() string {
		buf := make([]byte, 4096)
		n, _ := unix.Llistxattr(confPath, buf)
		return string(buf[:n])
	}
	xattrsBefore := xattrNames() // macOS may add com.apple.provenance itself
	if err := volume.mkdir("sub", 0700); err != nil {
		t.Fatal(err)
	}
	integrityWrite(t, id, "evil", []byte("not a config"))

	for _, p := range []string{"gocryptfs.conf", "/gocryptfs.conf", "//gocryptfs.conf", "sub/../gocryptfs.conf"} {
		if _, _, err := volume.prepareAtSyscall(p); err != syscall.EPERM {
			t.Errorf("%q: resolve: want EPERM, got %v", p, err)
		}
		if err := volume.setAttrPath(p, setAttrRequest{valid: setMode, mode: 0644}); err != syscall.EPERM {
			t.Errorf("%q: setattr: want EPERM, got %v", p, err)
		}
		if rc := shimSetXattr(id, p, "user.x", []byte("v"), 0); rc != -int(syscall.EPERM) {
			t.Errorf("%q: set xattr: want -EPERM, got %d", p, rc)
		}
		if _, err := volume.openWrite(p, 0600, openExisting); err != syscall.EPERM {
			t.Errorf("%q: open for writing: want EPERM, got %v", p, err)
		}
		if err := volume.rename("evil", p); err != syscall.EPERM {
			t.Errorf("%q: rename onto it: want EPERM, got %v", p, err)
		}
		if err := volume.removeFile(p); err != syscall.EPERM {
			t.Errorf("%q: remove: want EPERM, got %v", p, err)
		}
	}

	after, err := os.ReadFile(confPath)
	if err != nil || !bytes.Equal(after, conf) {
		t.Fatalf("gocryptfs.conf changed (err %v)", err)
	}
	var st unix.Stat_t
	if err := unix.Lstat(confPath, &st); err != nil || st.Mode != before.Mode {
		t.Errorf("gocryptfs.conf mode changed: %o -> %o (err %v)", before.Mode, st.Mode, err)
	}
	if got := xattrNames(); got != xattrsBefore {
		t.Errorf("gocryptfs.conf xattrs changed: %q -> %q", xattrsBefore, got)
	}

	// Only the root one is reserved.
	integrityWrite(t, id, "sub/gocryptfs.conf", []byte("user data"))
	if got := integrityRead(t, id, "sub/gocryptfs.conf"); !bytes.Equal(got, []byte("user data")) {
		t.Errorf("sub/gocryptfs.conf: got %q", got)
	}
}

// P-2: a failed read open says why. It returned -1 for every failure, which the
// extension reported as ENOENT for a file that is listed right there.
func TestReadOpenReportsErrno(t *testing.T) {
	id, dir := plaintextNamesVault(t)
	integrityWrite(t, id, "f", []byte("x"))
	if err := os.Chmod(dir+"/f", 0); err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name string
		rc   int
		want syscall.Errno
	}{
		{"unreadable file", shimOpenRead(id, "f"), syscall.EACCES},
		{"missing file", shimOpenRead(id, "missing"), syscall.ENOENT},
		{"closed volume", shimOpenRead(-1, "f"), syscall.EBADF},
	}
	for _, c := range cases {
		if c.rc != -int(c.want) {
			t.Errorf("%s: want %d, got %d", c.name, -int(c.want), c.rc)
		}
	}
	if err := os.Chmod(dir+"/f", 0600); err != nil {
		t.Fatal(err)
	}
	h := shimOpenRead(id, "f")
	if h < 0 {
		t.Fatalf("readable file: got %d", h)
	}
	gcf_close_file(id, h)
}

// D-2: a last path component of ".." named the directory above the cipher
// directory: with plaintextnames the name goes to the *at call as is.
func TestDotDotStaysInsideCipherDir(t *testing.T) {
	outer := t.TempDir()
	dir := outer + "/cipher"
	if err := os.Mkdir(dir, 0700); err != nil {
		t.Fatal(err)
	}
	password := []byte("dotdot-test")
	if !gcf_create_volume(dir, bytes.Clone(password), true, 0, 10, "dotdot-test", nil) {
		t.Fatal("create vault")
	}
	id := gcf_init(dir, bytes.Clone(password), nil, nil)
	if id < 0 {
		t.Fatal("open vault")
	}
	t.Cleanup(func() { gcf_close(id) })
	volume := testVolume(t, id)
	if err := volume.mkdir("sub", 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(outer, 0755); err != nil {
		t.Fatal(err)
	}

	for _, p := range []string{"/..", "..", "sub/..", "/."} {
		if _, _, err := volume.prepareAtSyscall(p); err != syscall.EPERM {
			t.Errorf("%q: resolve: want EPERM, got %v", p, err)
		}
		if err := volume.setAttrPath(p, setAttrRequest{valid: setMode, mode: 0700}); err != syscall.EPERM {
			t.Errorf("%q: setattr: want EPERM, got %v", p, err)
		}
		if rc := shimSetXattr(id, p, "user.x", []byte("v"), 0); rc != -int(syscall.EPERM) {
			t.Errorf("%q: set xattr: want -EPERM, got %d", p, rc)
		}
	}
	if p, err := volume.getCipherPath(".."); err == nil {
		t.Errorf("getCipherPath(\"..\") resolved to %s", p)
	}

	var st unix.Stat_t
	if err := unix.Lstat(outer, &st); err != nil {
		t.Fatal(err)
	}
	if st.Mode&07777 != 0755 {
		t.Errorf("the directory above the vault changed mode to %o", st.Mode&07777)
	}
	buf := make([]byte, 4096)
	if n, _ := unix.Llistxattr(outer, buf); bytes.Contains(buf[:n], []byte("user.gocryptfs.")) {
		t.Error("the directory above the vault got an xattr")
	}
}

// D-3: the engine opens ciphertext files O_RDWR and writes at block offsets,
// which an append-only file refuses, so a passed-through UF_APPEND left the
// file unwritable for good. Setting it is refused; one already set on the
// ciphertext can still be cleared.
func TestAppendOnlyFlagIsNotSet(t *testing.T) {
	id, _, _ := integrityVault(t)
	volume := testVolume(t, id)
	integrityWrite(t, id, "f", []byte("body"))
	cPath, err := volume.getCipherPath("f")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { unix.Chflags(cPath, 0) })

	for _, flag := range []uint32{unix.UF_APPEND, unix.SF_APPEND} {
		if err := volume.setAttrPath("f", setAttrRequest{valid: setFlags, flags: flag}); err != syscall.ENOTSUP {
			t.Errorf("set %#x: want ENOTSUP, got %v", flag, err)
		}
	}
	h, err := volume.openWrite("f", 0600, openExisting)
	if err != nil {
		t.Fatalf("the file is no longer writable: %v", err)
	}
	gcf_close_file(id, h)

	if err := unix.Chflags(cPath, unix.UF_APPEND); err != nil {
		t.Fatal(err)
	}
	if err := volume.setAttrPath("f", setAttrRequest{valid: setFlags, flags: 0}); err != nil {
		t.Fatalf("clear: %v", err)
	}
	var st unix.Stat_t
	if err := unix.Lstat(cPath, &st); err != nil || st.Flags&unix.UF_APPEND != 0 {
		t.Errorf("UF_APPEND was not cleared: %#x (err %v)", st.Flags, err)
	}
}

// D-5: offsets and sizes arrive as uint64. Above MaxInt64 the ciphertext offset
// 18 + n*4128 of block n wraps around 2^64: for n = 4468688002352121 it is 3890,
// inside block 0, so a write there overwrote the start of the file and a
// truncate to that size cut the file short. Below MaxInt64, a write or truncate
// whose ciphertext end does not fit an off_t failed only after zero-padding the
// old last block. All of them must fail before anything is written.
func TestHugeOffsetsAreRefusedUpFront(t *testing.T) {
	id, _, _ := integrityVault(t)
	volume := testVolume(t, id)
	body := bytes.Repeat([]byte("0123456789"), 410) // 4100 bytes: the last block is partial
	wrapping := uint64(4468688002352121) * 4096
	tooFar := uint64(math.MaxInt64) - 4096 // fits an off_t, its ciphertext offset does not

	cases := []struct {
		name string
		op   func(h int, path string) int64
		want syscall.Errno
	}{
		{"write at a wrapping offset", func(h int, _ string) int64 { return shimWriteFile(id, h, wrapping, make([]byte, 4096)) }, syscall.EINVAL},
		{"read at a wrapping offset", func(h int, _ string) int64 { return shimReadFile(id, h, wrapping, make([]byte, 16)) }, syscall.EINVAL},
		{"ftruncate to a wrapping size", func(h int, _ string) int64 { return int64(shimFtruncate(id, h, wrapping)) }, syscall.EINVAL},
		{"truncate to a wrapping size", func(_ int, p string) int64 { return int64(shimTruncate(id, p, wrapping)) }, syscall.EINVAL},
		{"write past the largest ciphertext offset", func(h int, _ string) int64 { return shimWriteFile(id, h, tooFar, []byte("x")) }, syscall.EFBIG},
		{"ftruncate past the largest ciphertext size", func(h int, _ string) int64 { return int64(shimFtruncate(id, h, tooFar)) }, syscall.EFBIG},
	}
	for i, c := range cases {
		path := fmt.Sprintf("f%d", i)
		integrityWrite(t, id, path, body)
		h := gcf_open_write_mode(id, path, 0600)
		if h < 0 {
			t.Fatal("open writer")
		}
		if rc := c.op(h, path); rc != -int64(c.want) {
			t.Errorf("%s: want -%d, got %d", c.name, c.want, rc)
		}
		gcf_close_file(id, h)

		cPath, err := volume.getCipherPath(path)
		if err != nil {
			t.Fatal(err)
		}
		var st unix.Stat_t
		if err := unix.Lstat(cPath, &st); err != nil {
			t.Fatal(err)
		}
		if size := shimPlainSize(id, uint64(st.Size)); size != uint64(len(body)) {
			t.Errorf("%s: the size changed to %d", c.name, size)
		}
		if got := integrityRead(t, id, path); !bytes.Equal(got, body) {
			t.Errorf("%s: the content changed (%d bytes readable)", c.name, len(got))
		}
	}
}
