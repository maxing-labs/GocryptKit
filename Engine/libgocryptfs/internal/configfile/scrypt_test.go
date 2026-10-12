package configfile

import (
	"runtime"
	"testing"
)

func kdf(logN, r, p, keyLen int) ScryptKDF {
	return ScryptKDF{Salt: make([]byte, scryptMinSaltLen), N: 1 << logN, R: r, P: p, KeyLen: keyLen}
}

// F-9: gocryptfs.conf may have been planted or altered. Its scrypt parameters
// decide how much memory (128·N·R bytes) and CPU the key derivation takes.
func TestValidateParamsBoundsResources(t *testing.T) {
	accepted := map[string]ScryptKDF{
		"default (64 MiB)":      kdf(16, 8, 1, 32),
		"logN 20 (1 GiB)":       kdf(20, 8, 1, 32),
		"R 16, logN 19 (1 GiB)": kdf(19, 16, 1, 32),
		"P 16":                  kdf(10, 8, 16, 32),
		"P 16, logN 16":         kdf(16, 8, 16, 32),
		"P 2, logN 19":          kdf(19, 8, 2, 32),
	}
	for name, s := range accepted {
		if err := s.validateParams(); err != nil {
			t.Errorf("%s: refused: %v", name, err)
		}
	}
	rejected := map[string]ScryptKDF{
		"logN 21 (2 GiB)":       kdf(21, 8, 1, 32),
		"logN 30 (1 TiB)":       kdf(30, 8, 1, 32),
		"R 16, logN 20 (2 GiB)": kdf(20, 16, 1, 32),
		"huge R":                kdf(10, 1<<40, 1, 32),
		"P 17":                  kdf(10, 8, 17, 32),
		"P 2, logN 20":          kdf(20, 8, 2, 32),  // D-6: twice the CPU of the largest P 1
		"P 16, logN 20":         kdf(20, 8, 16, 32), // 16 times
		"KeyLen 1 MiB":          kdf(10, 8, 1, 1<<20),
		"KeyLen 64":             kdf(10, 8, 1, 64),
	}
	for name, s := range rejected {
		if err := s.validateParams(); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// The limits apply before anything is allocated.
func TestDeriveKeyRefusesOversizedParamsUpFront(t *testing.T) {
	s := kdf(21, 8, 1, 32) // 2 GiB if it were run
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	if _, err := s.DeriveKey([]byte("password")); err == nil {
		t.Fatal("derived a key with 2 GiB parameters")
	}
	runtime.ReadMemStats(&after)
	if grown := after.TotalAlloc - before.TotalAlloc; grown > 1<<20 {
		t.Errorf("allocated %d bytes before refusing", grown)
	}
}
