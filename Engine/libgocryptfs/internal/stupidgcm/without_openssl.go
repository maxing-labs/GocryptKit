//go:build !cgo || without_openssl

package stupidgcm

import (
	"crypto/cipher"
)

const (
	// BuiltWithoutOpenssl indicates if openssl been disabled at compile-time
	BuiltWithoutOpenssl = true
)

// 上游在这里 os.Exit。改成 panic 的理由：c-archive 里 os.Exit 必然带走宿主
// FSKit 扩展进程且无从拦截，而 panic 会被 C 边界上的 recover 兜住，转成错误码
// 返回给 Swift。两者都属于"不该发生"，但只有后者是可恢复的。
func errExit() {
	panic("libgocryptfs was built with -tags without_openssl, but something asked for the openssl backend")
}

func NewAES256GCM(_ []byte) cipher.AEAD {
	errExit()
	return nil
}

func NewChacha20poly1305(_ []byte) cipher.AEAD {
	errExit()
	return nil
}

func NewXchacha20poly1305(_ []byte) cipher.AEAD {
	errExit()
	return nil
}
