package main

import (
	"bytes"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// F-10: xattr names use upstream gocryptfs's fixed IV, while entries written
// with the old all-zero IV stay readable and are migrated when rewritten.

var upstreamXattrIV = []byte("xattr_name_iv_xx")

func xattrFixture(t *testing.T) (int, *Volume, string) {
	t.Helper()
	id, _, _ := integrityVault(t)
	integrityWrite(t, id, "f", []byte("body"))
	value, _ := OpenedVolumes.Load(id)
	volume := value.(*Volume)
	cPath, err := volume.getCipherPath("f")
	if err != nil {
		t.Fatal(err)
	}
	return id, volume, cPath
}

// storedName computes the on-disk xattr name independently of the code under test.
func storedName(t *testing.T, volume *Volume, attr string, iv []byte) string {
	t.Helper()
	cName, err := volume.nameTransform.EncryptName(attr, iv)
	if err != nil {
		t.Fatal(err)
	}
	return "user.gocryptfs." + cName
}

// plantLegacy writes an attribute the way GocryptKit <= 1.3.9 did.
func plantLegacy(t *testing.T, volume *Volume, cPath, attr string, value []byte) {
	t.Helper()
	cData := append([]byte(nil), volume.contentEnc.EncryptBlock(value, 0, nil)...)
	if err := unix.Lsetxattr(cPath, storedName(t, volume, attr, make([]byte, 16)), cData, 0); err != nil {
		t.Fatal(err)
	}
}

func rawXattrNames(t *testing.T, cPath string) []string {
	t.Helper()
	buf := make([]byte, 16384)
	n, err := unix.Llistxattr(cPath, buf)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, raw := range bytes.Split(buf[:n], []byte{0}) {
		if strings.HasPrefix(string(raw), "user.gocryptfs.") {
			names = append(names, string(raw))
		}
	}
	sort.Strings(names)
	return names
}

func TestXattrNamesUseUpstreamIV(t *testing.T) {
	id, volume, cPath := xattrFixture(t)
	if rc := shimSetXattr(id, "f", "com.apple.quarantine", []byte("0081"), 0); rc != 0 {
		t.Fatalf("set: %d", rc)
	}
	want := storedName(t, volume, "com.apple.quarantine", upstreamXattrIV)
	if got := rawXattrNames(t, cPath); len(got) != 1 || got[0] != want {
		t.Fatalf("stored xattr name is not in upstream format:\n got %v\nwant %s", got, want)
	}
	if value, rc := shimGetXattr(id, "f", "com.apple.quarantine"); rc != 0 || !bytes.Equal(value, []byte("0081")) {
		t.Fatalf("round trip: %q %d", value, rc)
	}
}

func TestLegacyXattrsStayReadable(t *testing.T) {
	id, volume, cPath := xattrFixture(t)
	plantLegacy(t, volume, cPath, "com.apple.provenance", []byte{1, 2, 3})
	plantLegacy(t, volume, cPath, "com.apple.metadata:_kMDItemUserTags", []byte("red"))
	if value, rc := shimGetXattr(id, "f", "com.apple.provenance"); rc != 0 || !bytes.Equal(value, []byte{1, 2, 3}) {
		t.Fatalf("legacy get: %v %d", value, rc)
	}
	names, rc := shimListXattr(id, "f")
	sort.Strings(names)
	if rc != 0 || len(names) != 2 || names[0] != "com.apple.metadata:_kMDItemUserTags" || names[1] != "com.apple.provenance" {
		t.Fatalf("legacy list: %v %d", names, rc)
	}
	if rc := shimRemoveXattr(id, "f", "com.apple.provenance"); rc != 0 {
		t.Fatalf("legacy remove: %d", rc)
	}
	if _, rc := shimGetXattr(id, "f", "com.apple.provenance"); rc != -int(unix.ENOATTR) {
		t.Fatalf("removed legacy attribute still readable: %d", rc)
	}
	if rc := shimRemoveXattr(id, "f", "com.apple.provenance"); rc != -int(unix.ENOATTR) {
		t.Fatalf("second remove: want -ENOATTR, got %d", rc)
	}
}

func TestRewriteMigratesLegacyXattr(t *testing.T) {
	id, volume, cPath := xattrFixture(t)
	plantLegacy(t, volume, cPath, "user.tag", []byte("old"))
	if rc := shimSetXattr(id, "f", "user.tag", []byte("new"), 0); rc != 0 {
		t.Fatalf("set: %d", rc)
	}
	want := storedName(t, volume, "user.tag", upstreamXattrIV)
	if got := rawXattrNames(t, cPath); len(got) != 1 || got[0] != want {
		t.Fatalf("rewrite left %v, want only %s", got, want)
	}
	if value, _ := shimGetXattr(id, "f", "user.tag"); !bytes.Equal(value, []byte("new")) {
		t.Fatalf("value after rewrite: %q", value)
	}
	if names, _ := shimListXattr(id, "f"); len(names) != 1 || names[0] != "user.tag" {
		t.Fatalf("list after rewrite: %v", names)
	}
}

func TestXattrCreateAndReplaceSeeBothFormats(t *testing.T) {
	id, volume, cPath := xattrFixture(t)
	plantLegacy(t, volume, cPath, "user.legacy", []byte("old"))
	if rc := shimSetXattr(id, "f", "user.legacy", []byte("x"), xattrFlagCreate); rc != -int(syscall.EEXIST) {
		t.Errorf("CREATE over a legacy attribute: want -EEXIST, got %d", rc)
	}
	if rc := shimSetXattr(id, "f", "user.legacy", []byte("replaced"), xattrFlagReplace); rc != 0 {
		t.Errorf("REPLACE of a legacy attribute: %d", rc)
	}
	if value, _ := shimGetXattr(id, "f", "user.legacy"); !bytes.Equal(value, []byte("replaced")) {
		t.Errorf("value after REPLACE: %q", value)
	}
	if got := rawXattrNames(t, cPath); len(got) != 1 || got[0] != storedName(t, volume, "user.legacy", upstreamXattrIV) {
		t.Errorf("REPLACE did not migrate: %v", got)
	}
	if rc := shimSetXattr(id, "f", "user.absent", []byte("x"), xattrFlagReplace); rc != -int(unix.ENOATTR) {
		t.Errorf("REPLACE of a missing attribute: want -ENOATTR, got %d", rc)
	}
	if rc := shimSetXattr(id, "f", "user.fresh", []byte("x"), xattrFlagCreate); rc != 0 {
		t.Errorf("CREATE of a new attribute: %d", rc)
	}
	if rc := shimSetXattr(id, "f", "user.fresh", []byte("y"), xattrFlagCreate); rc != -int(syscall.EEXIST) {
		t.Errorf("second CREATE: want -EEXIST, got %d", rc)
	}
}

// With the wrong IV the padding check passes for about one name in 256 and
// yields random bytes. Listing many legacy names must still return each one.
func TestListingManyLegacyNamesNeverReturnsGarbage(t *testing.T) {
	id, volume, _ := xattrFixture(t)
	integrityWrite(t, id, "bulk", []byte("x"))
	bulk, err := volume.getCipherPath("bulk")
	if err != nil {
		t.Fatal(err)
	}
	ambiguous := 0
	for i := 0; i < 600; i++ {
		name := "user.legacy." + strings.Repeat("n", i%7) + string(rune('a'+i%26)) + string(rune('a'+(i/26)%26))
		legacy := storedName(t, volume, name, make([]byte, 16))
		if _, err := volume.nameTransform.DecryptName(strings.TrimPrefix(legacy, "user.gocryptfs."), upstreamXattrIV); err == nil {
			ambiguous++ // decrypts under both IVs: only plausibility tells them apart
		}
		plantLegacy(t, volume, bulk, name, []byte("v"))
		names, rc := shimListXattr(id, "bulk")
		if rc != 0 || len(names) != 1 || names[0] != name {
			t.Fatalf("legacy name %q listed as %q (rc %d)", name, names, rc)
		}
		if rc := shimRemoveXattr(id, "bulk", name); rc != 0 {
			t.Fatalf("remove %q: %d", name, rc)
		}
	}
	t.Logf("%d of 600 legacy names also decrypt under the upstream IV", ambiguous)
}

// F-11: an xattr call resolves its entry once, through directory fds. The old
// code resolved the ciphertext path string a second time, so a directory
// swapped for a symlink in between (a sync client can do that) sent the call
// out of the vault.
func TestXattrDoesNotFollowSwappedDirectory(t *testing.T) {
	id, _, _ := integrityVault(t)
	volume := testVolume(t, id)
	if err := volume.mkdir("d", 0700); err != nil {
		t.Fatal(err)
	}
	integrityWrite(t, id, "d/f", []byte("body"))
	cDir, err := volume.getCipherPath("d")
	if err != nil {
		t.Fatal(err)
	}
	cFile, err := volume.getCipherPath("d/f")
	if err != nil {
		t.Fatal(err)
	}
	// A look-alike outside the vault, reached when the directory is a symlink.
	outside := t.TempDir()
	decoy := filepath.Join(outside, filepath.Base(cFile))
	if err := os.WriteFile(decoy, nil, 0600); err != nil {
		t.Fatal(err)
	}
	link := cDir + ".link"
	if err := os.Symlink(outside, link); err != nil {
		t.Fatal(err)
	}

	// Swap the directory and the symlink back and forth (atomically) while
	// several callers set and get an attribute of d/f.
	stop := make(chan struct{})
	var swapper, callers sync.WaitGroup
	swapper.Add(1)
	go func() {
		defer swapper.Done()
		for swapped := false; ; swapped = !swapped {
			select {
			case <-stop:
				if swapped {
					unix.RenamexNp(cDir, link, unix.RENAME_SWAP) // put the real directory back
				}
				return
			default:
			}
			if err := unix.RenamexNp(cDir, link, unix.RENAME_SWAP); err != nil {
				t.Error(err)
				return
			}
		}
	}()
	for i := 0; i < 4; i++ {
		callers.Add(1)
		go func() {
			defer callers.Done()
			for deadline := time.Now().Add(2 * time.Second); time.Now().Before(deadline); {
				shimSetXattr(id, "d/f", "user.probe", []byte("v"), 0)
				shimGetXattr(id, "d/f", "user.probe")
			}
		}()
	}
	callers.Wait()
	close(stop)
	swapper.Wait()
	if names := rawXattrNames(t, decoy); len(names) > 0 {
		t.Fatalf("an xattr call followed the swapped directory out of the vault (%d attributes on the decoy)", len(names))
	}
}

// inDirectory must hand the thread back with the process-wide working
// directory: a call from C runs on the caller's thread.
func TestInDirectoryRestoresWorkingDirectory(t *testing.T) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	var before, inside, dir, after unix.Stat_t
	if err := unix.Stat(".", &before); err != nil {
		t.Fatal(err)
	}
	path := t.TempDir()
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_DIRECTORY, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(fd)
	if err := inDirectory(fd, func() error { return unix.Stat(".", &inside) }); err != nil {
		t.Fatal(err)
	}
	unix.Stat(path, &dir)
	unix.Stat(".", &after)
	if inside.Ino != dir.Ino {
		t.Error("fn did not run in the directory")
	}
	if after.Ino != before.Ino || after.Dev != before.Dev {
		t.Error("the thread kept the directory as its working directory")
	}
}

// plantedSizeIO reports a ciphertext xattr of the given size for every name and
// records the largest buffer it was asked to fill.
type plantedSizeIO struct {
	size, largestDest int
}

func (p *plantedSizeIO) get(attr string, dest []byte) (int, error) {
	if dest == nil {
		return p.size, nil
	}
	if len(dest) > p.largestDest {
		p.largestDest = len(dest)
	}
	return 0, syscall.ERANGE
}
func (p *plantedSizeIO) set(string, []byte, int) error { return nil }
func (p *plantedSizeIO) remove(string) error           { return nil }
func (p *plantedSizeIO) list([]byte) (int, error)      { return 0, nil }

// D-1: whoever can write the ciphertext can plant a value of several GiB. A
// failed allocation is a fatal error in Go that recover cannot catch, so the
// probed size must be checked before allocating.
func TestOversizedXattrIsNotAllocated(t *testing.T) {
	_, volume, _ := xattrFixture(t)
	io := &plantedSizeIO{size: 32 << 20}
	if _, err := volume.xattrGet(io, "com.apple.provenance"); err != syscall.E2BIG {
		t.Errorf("want E2BIG, got %v", err)
	}
	if io.largestDest > 0 {
		t.Errorf("allocated %d bytes for a planted value", io.largestDest)
	}
}

func TestPlantedOversizedXattrIsRefused(t *testing.T) {
	id, volume, cPath := xattrFixture(t)
	largest := bytes.Repeat([]byte{7}, xattrMaxValueLen)
	if rc := shimSetXattr(id, "f", "com.example.largest", largest, 0); rc != 0 {
		t.Fatalf("set the largest allowed value: %d", rc)
	}
	if value, rc := shimGetXattr(id, "f", "com.example.largest"); rc != 0 || !bytes.Equal(value, largest) {
		t.Fatalf("the largest allowed value did not round trip: %d bytes, rc %d", len(value), rc)
	}
	big := make([]byte, 32<<20)
	if err := unix.Lsetxattr(cPath, storedName(t, volume, "com.apple.provenance", upstreamXattrIV), big, 0); err != nil {
		t.Skipf("the file system refused a 32 MiB xattr: %v", err)
	}
	if _, rc := shimGetXattr(id, "f", "com.apple.provenance"); rc != -int(syscall.E2BIG) {
		t.Fatalf("want -E2BIG, got %d", rc)
	}
}
