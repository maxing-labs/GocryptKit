package main

import (
	"bytes"
	"crypto/rand"
	"os"
	"sync"
	"testing"
	"time"
)

func integrityVault(t *testing.T) (int, string, func() int) {
	t.Helper()
	dir := t.TempDir()
	password := make([]byte, 32)
	if _, err := rand.Read(password); err != nil {
		t.Fatal(err)
	}
	if !gcf_create_volume(dir, bytes.Clone(password), false, 0, 10, "integrity-test", nil) {
		t.Fatal("create vault")
	}
	id := gcf_init(dir, bytes.Clone(password), nil, nil)
	if id < 0 {
		t.Fatal("open vault")
	}
	t.Cleanup(func() { gcf_close(id); wipe(password) })
	return id, dir, func() int {
		gcf_close(id)
		id = gcf_init(dir, bytes.Clone(password), nil, nil)
		if id < 0 {
			t.Fatal("reopen vault")
		}
		return id
	}
}

func integrityWrite(t *testing.T, id int, path string, data []byte) {
	t.Helper()
	h := gcf_open_write_mode(id, path, 0600)
	if h < 0 {
		t.Fatal("open writer")
	}
	defer gcf_close_file(id, h)
	if n := gcf_write_file(id, h, 0, data); int(n) != len(data) {
		t.Fatalf("write: %d bytes", n)
	}
}

func integrityRead(t *testing.T, id int, path string) []byte {
	t.Helper()
	h := gcf_open_read_mode(id, path)
	if h < 0 {
		t.Fatal("open reader")
	}
	defer gcf_close_file(id, h)
	buf := make([]byte, 16384)
	n := gcf_read_file(id, h, 0, buf)
	return buf[:n]
}

func TestRewriteAfterZeroTruncate(t *testing.T) {
	id, dir, _ := integrityVault(t)
	h := gcf_open_write_mode(id, "f", 0600)
	if h < 0 {
		t.Fatal("open writer")
	}
	initial := bytes.Repeat([]byte("a"), 10000)
	if n := gcf_write_file(id, h, 0, initial); int(n) != len(initial) {
		t.Fatal("initial write")
	}
	if !gcf_truncate(id, "f", 0) {
		t.Fatal("truncate")
	}
	want := []byte("replacement content")
	if n := gcf_write_file(id, h, 0, want); int(n) != len(want) {
		t.Fatal("replacement write")
	}
	gcf_close_file(id, h)
	if got := integrityRead(t, id, "f"); !bytes.Equal(got, want) {
		t.Error("reopened reader did not read replacement")
	}
	// This vault has exactly one content file; inspect only its format header.
	files, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, file := range files {
		if file.Name() == "gocryptfs.conf" || file.Name() == "gocryptfs.diriv" {
			continue
		}
		raw, err := os.ReadFile(dir + "/" + file.Name())
		if err != nil {
			t.Fatal(err)
		}
		if len(raw) < 18 || !bytes.Equal(raw[:2], []byte{0, 2}) {
			t.Error("invalid ciphertext header after rewrite")
		}
	}
}

func TestOpenReaderSurvivesRewrite(t *testing.T) {
	id, _, _ := integrityVault(t)
	integrityWrite(t, id, "f", bytes.Repeat([]byte("a"), 10000))
	r := gcf_open_read_mode(id, "f")
	defer gcf_close_file(id, r)
	buf := make([]byte, 16384)
	gcf_read_file(id, r, 0, buf) // keep a reader with a cached file ID
	w := gcf_open_write_mode(id, "f", 0600)
	defer gcf_close_file(id, w)
	ok := false
	for i := 0; i < 40 && !ok; i++ {
		ok = gcf_truncate(id, "f", 0)
	}
	if !ok {
		t.Fatal("truncate with reader open")
	}
	want := []byte("replacement content")
	if n := gcf_write_file(id, w, 0, want); int(n) != len(want) {
		t.Fatal("replacement write")
	}
	n := gcf_read_file(id, r, 0, buf)
	if !bytes.Equal(buf[:n], want) {
		t.Fatal("existing reader did not read replacement")
	}
	if !bytes.Equal(integrityRead(t, id, "f"), want) {
		t.Fatal("new reader did not read replacement")
	}
}

func TestTruncateWithReadAndWriteHandles(t *testing.T) {
	id, _, _ := integrityVault(t)
	integrityWrite(t, id, "f", []byte("initial"))
	for i := 0; i < 40; i++ {
		r := gcf_open_read_mode(id, "f")
		w := gcf_open_write_mode(id, "f", 0600)
		ok := gcf_truncate(id, "f", 0)
		gcf_close_file(id, r)
		gcf_close_file(id, w)
		if !ok {
			t.Fatal("truncate selected a read-only handle")
		}
	}
}

func TestTruncateConcurrentOpenClose(t *testing.T) {
	id, _, _ := integrityVault(t)
	integrityWrite(t, id, "f", []byte("initial"))
	integrityWrite(t, id, "other", []byte("other"))
	w := gcf_open_write_mode(id, "f", 0600)
	defer gcf_close_file(id, w)
	stop := time.Now().Add(10 * time.Second)
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		for time.Now().Before(stop) {
			if !gcf_truncate(id, "f", 0) {
				t.Error("concurrent truncate failed")
				return
			}
		}
	}()
	go func() {
		defer wg.Done()
		for time.Now().Before(stop) {
			h := gcf_open_read_mode(id, "other")
			if h < 0 {
				t.Error("concurrent open failed")
				return
			}
			gcf_close_file(id, h)
		}
	}()
	wg.Wait()
}

func integritySwap(t *testing.T, id int) {
	t.Helper()
	for _, path := range []string{"A", "A/x", "Old", "Old/x"} {
		if !gcf_mkdir(id, path, 0700) {
			t.Fatal("mkdir")
		}
	}
	integrityWrite(t, id, "A/x/f", []byte("original"))
	integrityWrite(t, id, "Old/x/f", []byte("incoming"))
	integrityRead(t, id, "A/x/f")
	if !gcf_rename(id, "A", "Tmp") || !gcf_rename(id, "Old", "A") {
		t.Fatal("swap directories")
	}
}

func TestDirectorySwapWrite(t *testing.T) {
	id, _, reopen := integrityVault(t)
	integritySwap(t, id)
	integrityWrite(t, id, "A/x/f", []byte("updated!"))
	id = reopen()
	if !bytes.Equal(integrityRead(t, id, "A/x/f"), []byte("updated!")) {
		t.Error("write missed destination")
	}
	if !bytes.Equal(integrityRead(t, id, "Tmp/x/f"), []byte("original")) {
		t.Error("write modified moved-away file")
	}
}

func TestDirectorySwapRemove(t *testing.T) {
	id, _, reopen := integrityVault(t)
	integritySwap(t, id)
	if !gcf_remove_file(id, "A/x/f") {
		t.Fatal("remove")
	}
	id = reopen()
	if _, _, _, exists := gcf_get_attrs(id, "A/x/f"); exists {
		t.Error("destination file survived remove")
	}
	if !bytes.Equal(integrityRead(t, id, "Tmp/x/f"), []byte("original")) {
		t.Error("remove affected moved-away file")
	}
}

func TestRecreateDirectoryImmediately(t *testing.T) {
	id, _, reopen := integrityVault(t)
	if !gcf_mkdir(id, "D", 0700) {
		t.Fatal("mkdir")
	}
	gcf_get_attrs(id, "D/probe") // populate directory cache even though child is absent
	if !gcf_rmdir(id, "D") || !gcf_mkdir(id, "D", 0700) {
		t.Fatal("recreate directory")
	}
	integrityWrite(t, id, "D/f", []byte("new file"))
	id = reopen()
	if !bytes.Equal(integrityRead(t, id, "D/f"), []byte("new file")) {
		t.Fatal("recreated directory unreadable")
	}
}
