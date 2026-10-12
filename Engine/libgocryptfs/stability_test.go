package main

import (
	"bytes"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"syscall"
	"testing"
	"time"
)

// F-6 (2): unmounting must not wipe the ciphers under in-flight operations,
// including handles opened after gcf_close started and handle-less paths.
func TestCloseVolumeDuringIO(t *testing.T) {
	for round := 0; round < 5; round++ {
		id, _, _ := integrityVault(t)
		integrityWrite(t, id, "r", bytes.Repeat([]byte("r"), 100000))
		held := gcf_open_read_mode(id, "r")
		stop := make(chan struct{})
		var wg sync.WaitGroup
		worker := func(body func()) {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for {
					select {
					case <-stop:
						return
					default:
						body()
					}
				}
			}()
		}
		worker(func() { // read on a handle that predates the close
			buf := make([]byte, 65536)
			gcf_read_file(id, held, 0, buf)
		})
		worker(func() { // handles opened while the volume is closing
			h := gcf_open_read_mode(id, "r")
			if h >= 0 {
				buf := make([]byte, 65536)
				gcf_read_file(id, h, 0, buf)
				gcf_close_file(id, h)
			}
		})
		worker(func() { // writes use the content cipher as well
			h := gcf_open_write_mode(id, "w", 0600)
			if h >= 0 {
				gcf_write_file(id, h, 0, []byte("payload"))
				gcf_close_file(id, h)
			}
		})
		worker(func() { gcf_get_attrs(id, "r") })
		time.Sleep(30 * time.Millisecond)
		gcf_close(id)
		time.Sleep(30 * time.Millisecond)
		close(stop)
		wg.Wait()
	}
}

// The C boundary must turn an internal panic into an error code: an escaped
// panic terminates the host FSKit extension and every volume it serves.
func TestExportsRecoverFromPanic(t *testing.T) {
	id, _, _ := integrityVault(t)
	integrityWrite(t, id, "f", bytes.Repeat([]byte("f"), 5000))
	h := gcf_open_read_mode(id, "f")
	defer gcf_close_file(id, h)
	value, _ := OpenedVolumes.Load(id)
	volume := value.(*Volume)
	saved := volume.contentEnc
	volume.contentEnc = nil // simulate an internal bug: nil dereference inside the engine
	defer func() { volume.contentEnc = saved }()
	buf := make([]byte, 4096)
	if n := shimReadFile(id, h, 0, buf); n != -int64(syscall.EIO) {
		t.Errorf("gcfc_read_file: want -EIO, got %d", n)
	}
	if n := shimPlainSize(id, 5000); n != 0 {
		t.Errorf("gcfc_plain_size: want 0, got %d", n)
	}
}

// F-7: a planted gocryptfs.diriv must not be trusted on the path-resolution
// route either: no unbounded read, no symlink following, exactly 16 non-zero bytes.
func TestCipherPathRejectsHostileDirIV(t *testing.T) {
	id, _, _ := integrityVault(t)
	value, _ := OpenedVolumes.Load(id)
	volume := value.(*Volume)
	plant := func(name string, write func(diriv string)) string {
		t.Helper()
		if !gcf_mkdir(id, name, 0700) {
			t.Fatal("mkdir")
		}
		dir, err := volume.getCipherPath(name)
		if err != nil {
			t.Fatal(err)
		}
		diriv := filepath.Join(dir, "gocryptfs.diriv")
		if err := os.Remove(diriv); err != nil {
			t.Fatal(err)
		}
		write(diriv)
		return name + "/child"
	}
	huge := plant("huge", func(diriv string) {
		f, err := os.Create(diriv)
		if err != nil {
			t.Fatal(err)
		}
		defer f.Close()
		if err := f.Truncate(512 << 20); err != nil { // sparse: costs no disk space
			t.Fatal(err)
		}
	})
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	_, err := volume.getCipherPath(huge)
	runtime.ReadMemStats(&after)
	if err == nil {
		t.Error("oversized diriv accepted")
	}
	if grown := after.TotalAlloc - before.TotalAlloc; grown > 1<<20 {
		t.Errorf("oversized diriv made the engine allocate %d MiB", grown>>20)
	}

	outside := filepath.Join(t.TempDir(), "iv")
	if err := os.WriteFile(outside, bytes.Repeat([]byte{7}, 16), 0600); err != nil {
		t.Fatal(err)
	}
	cases := map[string]func(string){
		"symlink":  func(diriv string) { os.Symlink(outside, diriv) },
		"all-zero": func(diriv string) { os.WriteFile(diriv, make([]byte, 16), 0400) },
		"short":    func(diriv string) { os.WriteFile(diriv, bytes.Repeat([]byte{7}, 15), 0400) },
		"long":     func(diriv string) { os.WriteFile(diriv, bytes.Repeat([]byte{7}, 17), 0400) },
	}
	for name, write := range cases {
		if _, err := volume.getCipherPath(plant(name, write)); err == nil {
			t.Errorf("%s diriv accepted", name)
		}
	}
}

// A write beyond EOF must zero-pad the old partial last block; otherwise that
// block ends up mid-file and fails authentication on the next read.
func TestWritePastEOFKeepsPartialBlockReadable(t *testing.T) {
	for _, viaCABI := range []bool{false, true} {
		id, _, reopen := integrityVault(t)
		integrityWrite(t, id, "f", []byte("head\n"))
		h := gcf_open_write_mode(id, "f", 0600)
		tail := bytes.Repeat([]byte("T"), 4096)
		const off = 1 << 20
		var n int64
		if viaCABI {
			n = shimWriteFile(id, h, off, tail)
		} else {
			n = int64(gcf_write_file(id, h, off, tail))
		}
		if n != int64(len(tail)) {
			t.Fatalf("sparse write: %d", n)
		}
		gcf_close_file(id, h)
		id = reopen()
		r := gcf_open_read_mode(id, "f")
		buf := make([]byte, 8192)
		if got := gcf_read_file(id, r, 0, buf); got == 0 || !bytes.Equal(buf[:5], []byte("head\n")) {
			t.Errorf("first block unreadable after a write past EOF (cABI=%v)", viaCABI)
		}
		if got := gcf_read_file(id, r, off, buf); !bytes.Equal(buf[:got], tail) {
			t.Errorf("tail unreadable after a write past EOF (cABI=%v)", viaCABI)
		}
		gcf_close_file(id, r)
	}
}

// A stale handle ID must fail instead of addressing whichever file reused the
// number: handle IDs are never recycled within a volume.
func TestHandleIDsAreNotReused(t *testing.T) {
	id, _, _ := integrityVault(t)
	integrityWrite(t, id, "a", []byte("AAAA"))
	integrityWrite(t, id, "b", []byte("BBBB"))
	stale := gcf_open_write_mode(id, "a", 0600)
	gcf_close_file(id, stale)
	other := gcf_open_write_mode(id, "b", 0600)
	defer gcf_close_file(id, other)
	if other == stale {
		t.Fatal("handle ID reused")
	}
	if n := gcf_write_file(id, stale, 0, []byte("XXXX")); n != 0 {
		t.Error("write through a closed handle succeeded")
	}
	if got := integrityRead(t, id, "b"); !bytes.Equal(got, []byte("BBBB")) {
		t.Error("stale handle wrote into another file")
	}
}
