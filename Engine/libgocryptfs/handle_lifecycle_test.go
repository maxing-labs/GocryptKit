package main

import (
	"bytes"
	"os"
	"testing"
	"time"
)

// Regressions for the handle-lifecycle fixes that shipped with 5caadcd
// (review items F-5 and F-6 (1)(3)(4)(5)). They fail on a4f06cc.

// F-5: closing a handle while a multi-chunk write is in flight used to
// deadlock the whole volume (handlesLock vs fdLock taken in opposite orders).
func TestCloseDuringChunkedWriteDoesNotDeadlock(t *testing.T) {
	id, _, _ := integrityVault(t)
	integrityWrite(t, id, "w", []byte("w"))
	for round := 0; round < 20; round++ {
		h := gcf_open_write_mode(id, "w", 0600)
		if h < 0 {
			t.Fatal("open writer")
		}
		buf := bytes.Repeat([]byte("D"), 1<<20) // 8 engine chunks per call
		done := make(chan struct{}, 2)
		go func() {
			for i := 0; i < 50; i++ {
				if shimWriteFile(id, h, 0, buf) < 0 {
					break // the handle was closed underneath us: expected
				}
			}
			done <- struct{}{}
		}()
		go func() {
			time.Sleep(time.Duration(round) * time.Millisecond)
			gcf_close_file(id, h)
			done <- struct{}{}
		}()
		for i := 0; i < 2; i++ {
			select {
			case <-done:
			case <-time.After(20 * time.Second):
				t.Fatal("close and in-flight write deadlocked")
			}
		}
		opened := make(chan int, 1)
		go func() { opened <- gcf_open_read_mode(id, "w") }()
		select {
		case r := <-opened:
			gcf_close_file(id, r)
		case <-time.After(5 * time.Second):
			t.Fatal("volume wedged after close/write race")
		}
	}
}

// F-6 (1): gcf_close must cope with holes in the handle table.
func TestCloseVolumeWithHandleTableHoles(t *testing.T) {
	id, _, _ := integrityVault(t)
	integrityWrite(t, id, "a", []byte("a"))
	h0 := gcf_open_read_mode(id, "a")
	h1 := gcf_open_read_mode(id, "a")
	h2 := gcf_open_read_mode(id, "a")
	if h0 < 0 || h1 < 0 || h2 < 0 {
		t.Fatal("open readers")
	}
	gcf_close_file(id, h0)
	gcf_close_file(id, h1)
	gcf_close(id) // h2 is still open; the table has holes below it
	if !gcf_is_closed(id) {
		t.Fatal("volume still open")
	}
}

// F-6 (3): shrinking after the ciphertext file was replaced underneath an
// open handle (sync client) used to index an empty block list.
func TestTruncateAfterExternalReplace(t *testing.T) {
	id, _, _ := integrityVault(t)
	integrityWrite(t, id, "s", bytes.Repeat([]byte("s"), 100))
	integrityWrite(t, id, "s2", bytes.Repeat([]byte("z"), 10000))
	h := gcf_open_write_mode(id, "s", 0600)
	defer gcf_close_file(id, h)
	value, _ := OpenedVolumes.Load(id)
	volume := value.(*Volume)
	c1, err1 := volume.getCipherPath("s")
	c2, err2 := volume.getCipherPath("s2")
	if err1 != nil || err2 != nil {
		t.Fatal("cipher paths")
	}
	if err := os.Rename(c2, c1); err != nil {
		t.Fatal(err)
	}
	func() {
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("truncate panicked: %v", r)
			}
		}()
		if !gcf_truncate(id, "s", 5000) {
			t.Fatal("truncate of the replacement failed")
		}
	}()
	got := integrityRead(t, id, "s")
	if !bytes.Equal(got, bytes.Repeat([]byte("z"), 5000)) {
		t.Fatalf("replacement not truncated to 5000 bytes: got %d", len(got))
	}
}

// F-6 (4): truncating while a reader that was opened on the then-empty file
// (no cached file ID) is still open used to hit "RUnlock of unlocked RWMutex".
func TestTruncateWithReaderOpenedWhileEmpty(t *testing.T) {
	id, _, _ := integrityVault(t)
	for i := 0; i < 20; i++ {
		creator := gcf_open_write_mode(id, "e", 0600)
		gcf_close_file(id, creator)
		if !gcf_truncate(id, "e", 0) {
			t.Fatal("reset to empty")
		}
		r := gcf_open_read_mode(id, "e") // file ID not cached: the file is empty
		integrityWrite(t, id, "e", bytes.Repeat([]byte("y"), 10000))
		ok := gcf_truncate(id, "e", 5000)
		gcf_close_file(id, r)
		if !ok {
			t.Fatal("truncate with an empty-opened reader failed")
		}
		if got := integrityRead(t, id, "e"); !bytes.Equal(got, bytes.Repeat([]byte("y"), 5000)) {
			t.Fatalf("truncated content wrong: %d bytes", len(got))
		}
	}
}

// F-6 (5): closing an unknown or already-closed handle is a no-op.
func TestCloseUnknownHandle(t *testing.T) {
	id, _, _ := integrityVault(t)
	integrityWrite(t, id, "a", []byte("a"))
	h := gcf_open_read_mode(id, "a")
	gcf_close_file(id, h)
	gcf_close_file(id, h)
	gcf_close_file(id, 12345)
	gcf_close_file(id, -1)
}
