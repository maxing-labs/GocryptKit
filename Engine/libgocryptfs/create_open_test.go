package main

import (
	"bytes"
	"strings"
	"syscall"
	"testing"
)

func testVolume(t *testing.T, id int) *Volume {
	t.Helper()
	value, ok := OpenedVolumes.Load(id)
	if !ok {
		t.Fatal("volume not open")
	}
	return value.(*Volume)
}

// F-8: createItem needs O_EXCL semantics; a second create must fail with
// EEXIST and leave the existing content alone.
func TestCreateExclusive(t *testing.T) {
	id, _, _ := integrityVault(t)
	volume := testVolume(t, id)
	for _, name := range []string{"lock", strings.Repeat("long-name-", 20)} {
		h, err := volume.openWrite(name, 0600, createExclusive)
		if err != nil {
			t.Fatalf("first create: %v", err)
		}
		gcf_write_file(id, h, 0, []byte("owner"))
		gcf_close_file(id, h)
		if _, err := volume.openWrite(name, 0600, createExclusive); err != syscall.EEXIST {
			t.Errorf("second create: want EEXIST, got %v", err)
		}
		if got := integrityRead(t, id, name); !bytes.Equal(got, []byte("owner")) {
			t.Error("failed exclusive create modified the existing file")
		}
	}
}

// F-8: a writer reopening by path must never create. Otherwise a write that
// arrives after unlink resurrects the file.
func TestOpenExistingNeverCreates(t *testing.T) {
	id, _, _ := integrityVault(t)
	volume := testVolume(t, id)
	for _, name := range []string{"gone", strings.Repeat("long-name-", 20)} {
		if _, err := volume.openWrite(name, 0600, openExisting); err != syscall.ENOENT {
			t.Errorf("open of a missing file: want ENOENT, got %v", err)
		}
		if _, _, _, exists := gcf_get_attrs(id, name); exists {
			t.Error("open-existing created the file")
		}
		integrityWrite(t, id, name, []byte("data"))
		h, err := volume.openWrite(name, 0600, openExisting)
		if err != nil {
			t.Fatalf("open of an existing file: %v", err)
		}
		gcf_close_file(id, h)
		if !gcf_remove_file(id, name) {
			t.Fatal("remove")
		}
		if entries, err := syscallReadDirNames(volume.rootCipherDir); err != nil || len(entries) != 2 {
			t.Errorf("leftover ciphertext entries after remove: %v %v", entries, err)
		}
	}
}

func syscallReadDirNames(dir string) ([]string, error) {
	fd, err := syscall.Open(dir, syscall.O_RDONLY|syscall.O_DIRECTORY, 0)
	if err != nil {
		return nil, err
	}
	defer syscall.Close(fd)
	var names []string
	buf := make([]byte, 8192)
	for {
		n, err := syscall.ReadDirent(fd, buf)
		if err != nil {
			return nil, err
		}
		if n <= 0 {
			break
		}
		_, _, names = syscall.ParseDirent(buf[:n], -1, names)
	}
	return names, nil
}
