package main

import (
	"os"
	"syscall"
	"testing"
)

// A-2: a failed listing says why. Any failure to reach the directory was
// reported as ENOENT, so an unreadable directory looked like a missing one.
func TestListDirReportsErrno(t *testing.T) {
	id, dir := plaintextNamesVault(t)
	integrityWrite(t, id, "f", []byte("x"))
	if err := os.Mkdir(dir+"/locked", 0); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chmod(dir+"/locked", 0700) })
	cases := []struct {
		name string
		dir  string
		id   int
		want syscall.Errno
	}{
		{"unreadable directory", "locked", id, syscall.EACCES},
		{"regular file", "f", id, syscall.ENOTDIR},
		{"missing directory", "missing", id, syscall.ENOENT},
		{"closed volume", "/", -1, syscall.EBADF},
	}
	for _, c := range cases {
		if _, rc := shimListDir(c.id, c.dir); rc != -int(c.want) {
			t.Errorf("%s: want %d, got %d", c.name, -int(c.want), rc)
		}
	}
	if names, rc := shimListDir(id, "/"); rc != 0 || len(names) != 2 {
		t.Errorf("root: got %v, %d", names, rc)
	}
}

// A-2: gcfc_readlink returned NULL for every failure, which the extension
// reported as EIO.
func TestReadlinkReportsErrno(t *testing.T) {
	id, dir := plaintextNamesVault(t)
	integrityWrite(t, id, "f", []byte("x"))
	if err := os.Symlink("target", dir+"/l"); err != nil {
		t.Fatal(err)
	}
	if target, rc := shimReadlink(id, "l"); rc != 0 || target != "target" {
		t.Errorf("symlink: got %q, %d", target, rc)
	}
	cases := []struct {
		name string
		path string
		id   int
		want syscall.Errno
	}{
		{"missing symlink", "missing", id, syscall.ENOENT},
		{"regular file", "f", id, syscall.EINVAL},
		{"closed volume", "l", -1, syscall.EBADF},
	}
	for _, c := range cases {
		if _, rc := shimReadlink(c.id, c.path); rc != -int(c.want) {
			t.Errorf("%s: want %d, got %d", c.name, -int(c.want), rc)
		}
	}

	// A target that does not decrypt is damage, not a missing link.
	encID, _, _ := integrityVault(t)
	cipherPath, rc := shimCipherPath(encID, "l")
	if rc != 0 {
		t.Fatalf("cipher path: %d", rc)
	}
	if err := os.Symlink("not-a-ciphertext", cipherPath); err != nil {
		t.Fatal(err)
	}
	if _, rc := shimReadlink(encID, "l"); rc != -int(syscall.EIO) {
		t.Errorf("undecryptable target: want %d, got %d", -int(syscall.EIO), rc)
	}
}

// A-2: gcfc_cipher_path returned NULL for every failure.
func TestCipherPathReportsErrno(t *testing.T) {
	id, _, _ := integrityVault(t)
	cases := []struct {
		name string
		path string
		id   int
		want syscall.Errno
	}{
		{"missing parent", "missing/f", id, syscall.ENOENT},
		{"leading ..", "../x", id, syscall.EPERM},
		{"closed volume", "f", -1, syscall.EBADF},
	}
	for _, c := range cases {
		if _, rc := shimCipherPath(c.id, c.path); rc != -int(c.want) {
			t.Errorf("%s: want %d, got %d", c.name, -int(c.want), rc)
		}
	}
}

// Exports that do not follow ">= 0 or a negative errno", and why.
var errnoExceptions = map[string]string{
	"gcfc_init":             "volume ID or a status code: -1 no conf, -2 wrong password, -3 panic",
	"gcfc_init_vault":       "status codes shared with VaultCreation (initVault*)",
	"gcfc_is_closed":        "a boolean",
	"gcfc_plain_size":       "size arithmetic; 0 for an unknown volume",
	"gcfc_close":            "returns nothing",
	"gcfc_close_file":       "returns nothing",
	"gcfc_free_dir_entries": "returns nothing",
	"gcfc_free_string":      "returns nothing",
}

// A-2: every export that can fail returns >= 0 or a negative errno. Each
// export is either in the table below or in errnoExceptions, so a new one
// fails this test until its convention is decided.
func TestEveryCExportReportsErrno(t *testing.T) {
	// How each export names its item: by path, by handle, or either (xattrs).
	addressing := map[string]string{
		"gcfc_open_read_mode":      "path",
		"gcfc_open_write_mode":     "path",
		"gcfc_create_file":         "path",
		"gcfc_open_write_existing": "path",
		"gcfc_lstat":               "path",
		"gcfc_truncate":            "path",
		"gcfc_remove_file":         "path",
		"gcfc_mkdir":               "path",
		"gcfc_rmdir":               "path",
		"gcfc_rename":              "path",
		"gcfc_setattr":             "path",
		"gcfc_list_dir":            "path",
		"gcfc_readlink":            "path",
		"gcfc_cipher_path":         "path",
		"gcfc_fstat":               "handle",
		"gcfc_read_file":           "handle",
		"gcfc_write_file":          "handle",
		"gcfc_ftruncate":           "handle",
		"gcfc_fsetattr":            "handle",
		"gcfc_get_xattr":           "both",
		"gcfc_set_xattr":           "both",
		"gcfc_remove_xattr":        "both",
		"gcfc_list_xattr":          "both",
	}
	for name := range cExports(t) {
		_, inTable := addressing[name]
		_, excepted := errnoExceptions[name]
		if inTable == excepted {
			t.Errorf("%s: list it in exactly one of the table and errnoExceptions", name)
		}
	}

	id, _, _ := integrityVault(t)
	integrityWrite(t, id, "f", []byte("x"))
	missing, file := "missing/x", "f"
	const badHandle, noHandle, closedVolume = 1 << 30, -1, -1
	type call struct {
		what   string
		volume int
		path   *string
		handle int
		want   syscall.Errno
	}
	pathCalls := []call{
		{"missing path", id, &missing, noHandle, syscall.ENOENT},
		{"NULL path", id, nil, noHandle, syscall.EINVAL},
		{"closed volume", closedVolume, &file, noHandle, syscall.EBADF},
	}
	handleCalls := []call{
		{"unknown handle", id, nil, badHandle, syscall.EBADF},
		{"closed volume", closedVolume, nil, 0, syscall.EBADF},
	}
	for name, how := range addressing {
		var calls []call
		if how != "handle" {
			calls = append(calls, pathCalls...)
		}
		if how != "path" {
			calls = append(calls, handleCalls...)
		}
		for _, c := range calls {
			rc, ok := shimErrnoCall(name, c.volume, c.path, c.handle)
			if !ok {
				t.Errorf("%s: shimErrnoCall does not know it", name)
				break
			}
			if rc != -int64(c.want) {
				t.Errorf("%s, %s: want %d, got %d", name, c.what, -int(c.want), rc)
			}
		}
	}
}
