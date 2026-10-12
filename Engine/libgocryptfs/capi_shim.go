package main

/*
#include <stdint.h>
#include <stdlib.h>
*/
import "C"

import (
	"bytes"
	"unsafe"
)

// Go-typed entry points into the C ABI for *_test.go files, which cannot
// import "C". Nothing else references them, so the linker drops them from the
// shipped archive.

func shimReadFile(volumeID, handleID int, offset uint64, dst []byte) int64 {
	return int64(gcfc_read_file(C.int(volumeID), C.int(handleID), C.uint64_t(offset), unsafe.Pointer(&dst[0]), C.size_t(len(dst))))
}

func shimWriteFile(volumeID, handleID int, offset uint64, src []byte) int64 {
	return int64(gcfc_write_file(C.int(volumeID), C.int(handleID), C.uint64_t(offset), unsafe.Pointer(&src[0]), C.size_t(len(src))))
}

func shimPlainSize(volumeID int, cipherSize uint64) uint64 {
	return uint64(gcfc_plain_size(C.int(volumeID), C.uint64_t(cipherSize)))
}

func shimSetXattr(volumeID int, path, name string, value []byte, flags int) int {
	cPath, cName := C.CString(path), C.CString(name)
	defer C.free(unsafe.Pointer(cPath))
	defer C.free(unsafe.Pointer(cName))
	var ptr unsafe.Pointer
	if len(value) > 0 {
		ptr = unsafe.Pointer(&value[0])
	}
	return int(gcfc_set_xattr(C.int(volumeID), cPath, -1, cName, ptr, C.size_t(len(value)), C.int(flags)))
}

// shimGetXattr returns the value, or nil and the negative errno.
func shimGetXattr(volumeID int, path, name string) ([]byte, int) {
	cPath, cName := C.CString(path), C.CString(name)
	defer C.free(unsafe.Pointer(cPath))
	defer C.free(unsafe.Pointer(cName))
	buf := make([]byte, 64*1024)
	n := int(gcfc_get_xattr(C.int(volumeID), cPath, -1, cName, unsafe.Pointer(&buf[0]), C.size_t(len(buf))))
	if n < 0 {
		return nil, n
	}
	return buf[:n], 0
}

func shimRemoveXattr(volumeID int, path, name string) int {
	cPath, cName := C.CString(path), C.CString(name)
	defer C.free(unsafe.Pointer(cPath))
	defer C.free(unsafe.Pointer(cName))
	return int(gcfc_remove_xattr(C.int(volumeID), cPath, -1, cName))
}

func shimListXattr(volumeID int, path string) ([]string, int) {
	cPath := C.CString(path)
	defer C.free(unsafe.Pointer(cPath))
	buf := make([]byte, 64*1024)
	n := int(gcfc_list_xattr(C.int(volumeID), cPath, -1, unsafe.Pointer(&buf[0]), C.size_t(len(buf))))
	if n < 0 {
		return nil, n
	}
	var names []string
	for _, raw := range bytes.Split(buf[:n], []byte{0}) {
		if len(raw) > 0 {
			names = append(names, string(raw))
		}
	}
	return names, 0
}

func shimFtruncate(volumeID, handleID int, size uint64) int {
	return int(gcfc_ftruncate(C.int(volumeID), C.int(handleID), C.uint64_t(size)))
}

func shimTruncate(volumeID int, path string, size uint64) int {
	cPath := C.CString(path)
	defer C.free(unsafe.Pointer(cPath))
	return int(gcfc_truncate(C.int(volumeID), cPath, C.uint64_t(size)))
}

func shimOpenRead(volumeID int, path string) int {
	cPath := C.CString(path)
	defer C.free(unsafe.Pointer(cPath))
	return int(gcfc_open_read_mode(C.int(volumeID), cPath))
}

// shimListDir returns the names in dir, or nil and the negative errno.
func shimListDir(volumeID int, dir string) ([]string, int) {
	cDir := C.CString(dir)
	defer C.free(unsafe.Pointer(cDir))
	var entries *cDirEntry
	var count C.int
	if rc := int(gcfc_list_dir(C.int(volumeID), cDir, &entries, &count)); rc != 0 {
		return nil, rc
	}
	defer gcfc_free_dir_entries(entries, count)
	names := []string{}
	for _, e := range unsafe.Slice(entries, int(count)) {
		names = append(names, C.GoString(e.name))
	}
	return names, 0
}

// shimReadlink returns the target, or "" and the negative errno.
func shimReadlink(volumeID int, path string) (string, int) {
	cPath := C.CString(path)
	defer C.free(unsafe.Pointer(cPath))
	var out *C.char
	if rc := int(gcfc_readlink(C.int(volumeID), cPath, &out)); rc != 0 {
		return "", rc
	}
	defer gcfc_free_string(out)
	return C.GoString(out), 0
}

// shimCipherPath returns the ciphertext path, or "" and the negative errno.
func shimCipherPath(volumeID int, path string) (string, int) {
	cPath := C.CString(path)
	defer C.free(unsafe.Pointer(cPath))
	var out *C.char
	if rc := int(gcfc_cipher_path(C.int(volumeID), cPath, &out)); rc != 0 {
		return "", rc
	}
	defer gcfc_free_string(out)
	return C.GoString(out), 0
}

// cPath returns path as a C string, or NULL for nil, and the function that
// frees it.
func cPath(path *string) (*C.char, func()) {
	if path == nil {
		return nil, func() {}
	}
	c := C.CString(*path)
	return c, func() { C.free(unsafe.Pointer(c)) }
}

// shimErrnoCall calls the named export on a volume with a path (nil passes
// NULL) or a handle; each export ignores the one it does not take. ok is false
// for a name it does not know. For TestEveryCExportReportsErrno.
func shimErrnoCall(name string, volumeID int, path *string, handleID int) (rc int64, ok bool) {
	p, freePath := cPath(path)
	defer freePath()
	other, attr := C.CString("other"), C.CString("user.test")
	defer C.free(unsafe.Pointer(other))
	defer C.free(unsafe.Pointer(attr))
	v, h := C.int(volumeID), C.int(handleID)
	buf := make([]byte, 64)
	b, n := unsafe.Pointer(&buf[0]), C.size_t(len(buf))
	var st cStat
	req := cSetattr{valid: setMode, mode: 0600}
	var out *C.char
	defer func() { gcfc_free_string(out) }()
	var entries *cDirEntry
	var count C.int

	switch name {
	case "gcfc_open_read_mode":
		rc = int64(gcfc_open_read_mode(v, p))
	case "gcfc_open_write_mode":
		rc = int64(gcfc_open_write_mode(v, p, 0600))
	case "gcfc_create_file":
		rc = int64(gcfc_create_file(v, p, 0600))
	case "gcfc_open_write_existing":
		rc = int64(gcfc_open_write_existing(v, p))
	case "gcfc_lstat":
		rc = int64(gcfc_lstat(v, p, &st))
	case "gcfc_fstat":
		rc = int64(gcfc_fstat(v, h, &st))
	case "gcfc_read_file":
		rc = int64(gcfc_read_file(v, h, 0, b, n))
	case "gcfc_write_file":
		rc = int64(gcfc_write_file(v, h, 0, b, n))
	case "gcfc_ftruncate":
		rc = int64(gcfc_ftruncate(v, h, 0))
	case "gcfc_truncate":
		rc = int64(gcfc_truncate(v, p, 0))
	case "gcfc_remove_file":
		rc = int64(gcfc_remove_file(v, p))
	case "gcfc_mkdir":
		rc = int64(gcfc_mkdir(v, p, 0700))
	case "gcfc_rmdir":
		rc = int64(gcfc_rmdir(v, p))
	case "gcfc_rename":
		rc = int64(gcfc_rename(v, p, other))
	case "gcfc_setattr":
		rc = int64(gcfc_setattr(v, p, &req))
	case "gcfc_fsetattr":
		rc = int64(gcfc_fsetattr(v, h, &req))
	case "gcfc_list_dir":
		rc = int64(gcfc_list_dir(v, p, &entries, &count))
		gcfc_free_dir_entries(entries, count)
	case "gcfc_readlink":
		rc = int64(gcfc_readlink(v, p, &out))
	case "gcfc_cipher_path":
		rc = int64(gcfc_cipher_path(v, p, &out))
	case "gcfc_get_xattr":
		rc = int64(gcfc_get_xattr(v, p, h, attr, b, n))
	case "gcfc_set_xattr":
		rc = int64(gcfc_set_xattr(v, p, h, attr, b, 1, 0))
	case "gcfc_remove_xattr":
		rc = int64(gcfc_remove_xattr(v, p, h, attr))
	case "gcfc_list_xattr":
		rc = int64(gcfc_list_xattr(v, p, h, b, n))
	default:
		return 0, false
	}
	return rc, true
}
