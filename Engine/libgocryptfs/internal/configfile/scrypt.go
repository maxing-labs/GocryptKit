package configfile

import (
	"fmt"
	"math"

	"golang.org/x/crypto/scrypt"

	"libgocryptfs/v2/internal/cryptocore"
)

const (
	// ScryptDefaultLogN is the default scrypt logN configuration parameter.
	// logN=16 (N=2^16) uses 64MB of memory and takes 4 seconds on my Atom Z3735F
	// netbook.
	ScryptDefaultLogN = 16
	// From RFC7914, section 2:
	// At the current time, r=8 and p=1 appears to yield good
	// results, but as memory latency and CPU parallelism increase, it is
	// likely that the optimum values for both r and p will increase.
	// We reject all lower values that we might get through modified config files.
	scryptMinR = 8
	scryptMinP = 1
	// logN=10 takes 6ms on a Pentium G630. This should be fast enough for all
	// purposes. We reject lower values.
	scryptMinLogN = 10
	// We always generate 32-byte salts. Anything smaller than that is rejected.
	scryptMinSaltLen = 32

	// Upper limits. The parameters come from gocryptfs.conf, which may have been
	// planted or altered (the ciphertext directory may be shared or synced).
	// scrypt allocates 128·N·R bytes up front (logN 30 is 1 TiB) and runs P
	// times: an out-of-memory crash of the FSKit extension, or hours of CPU in
	// the host app. 1 GiB is 16 times the default (logN 16, R 8); gocryptfs
	// always writes P 1, and N·R·P may not exceed what 1 GiB allows at P 1.
	scryptMaxMemory = 1 << 30
	scryptMaxP      = 16
)

// ScryptKDF is an instance of the scrypt key deriviation function.
type ScryptKDF struct {
	// Salt is the random salt that is passed to scrypt
	Salt []byte
	// N: scrypt CPU/Memory cost parameter
	N int
	// R: scrypt block size parameter
	R int
	// P: scrypt parallelization parameter
	P int
	// KeyLen is the output data length
	KeyLen int
}

// NewScryptKDF returns a new instance of ScryptKDF.
func NewScryptKDF(logN int) ScryptKDF {
	var s ScryptKDF
	s.Salt = cryptocore.RandBytes(cryptocore.KeyLen)
	if logN <= 0 {
		s.N = 1 << ScryptDefaultLogN
	} else {
		s.N = 1 << uint32(logN)
	}
	s.R = 8 // Always 8
	s.P = 1 // Always 1
	s.KeyLen = cryptocore.KeyLen
	return s
}

// DeriveKey returns a new key from a supplied password.
//
// 上游在参数非法时 os.Exit、在 scrypt.Key 出错时 log.Panicf。libgocryptfs 在本
// 项目里是以 c-archive 形式嵌进 FSKit 扩展进程的，两者都会带走整个扩展进程 ——
// 表现为已挂载的卷被静默卸载、在途写入丢失。这里一律改为向上返回错误，由 C ABI
// 层转成错误码交给 Swift。
func (s *ScryptKDF) DeriveKey(pw []byte) ([]byte, error) {
	if err := s.validateParams(); err != nil {
		return nil, err
	}
	k, err := scrypt.Key(pw, s.Salt, s.N, s.R, s.P, s.KeyLen)
	if err != nil {
		return nil, fmt.Errorf("DeriveKey failed: %w", err)
	}
	return k, nil
}

// LogN - N is saved as 2^LogN, but LogN is much easier to work with.
// This function gives you LogN = Log2(N).
func (s *ScryptKDF) LogN() int {
	return int(math.Log2(float64(s.N)) + 0.5)
}

// validateParams checks that all parameters are within hardcoded limits: not
// so weak that the key is easy to guess, not so costly that deriving it takes
// the process down. Both can come from a rogue gocryptfs.conf.
func (s *ScryptKDF) validateParams() error {
	minN := 1 << scryptMinLogN
	if s.N < minN {
		return fmt.Errorf("fatal: scryptn below 10 is too low to make sense")
	}
	if s.R < scryptMinR {
		return fmt.Errorf("fatal: scrypt parameter R below minimum: value=%d, min=%d", s.R, scryptMinR)
	}
	if s.P < scryptMinP {
		return fmt.Errorf("fatal: scrypt parameter P below minimum: value=%d, min=%d", s.P, scryptMinP)
	}
	// 128·N·R <= scryptMaxMemory, written so that it cannot overflow (R >= 8 here).
	if maxNR := scryptMaxMemory / 128; s.R > maxNR || s.N > maxNR/s.R {
		return fmt.Errorf("fatal: scrypt parameters N=%d R=%d need more than %d MiB of memory", s.N, s.R, scryptMaxMemory>>20)
	}
	if s.P > scryptMaxP {
		return fmt.Errorf("fatal: scrypt parameter P above maximum: value=%d, max=%d", s.P, scryptMaxP)
	}
	// The CPU time grows with N·R·P. Allow as much as the largest memory with P 1.
	if maxNR := scryptMaxMemory / 128; s.N*s.R > maxNR/s.P {
		return fmt.Errorf("fatal: scrypt parameters N=%d R=%d P=%d exceed N·R·P=%d", s.N, s.R, s.P, maxNR)
	}
	if len(s.Salt) < scryptMinSaltLen {
		return fmt.Errorf("fatal: scrypt salt length below minimum: value=%d, min=%d", len(s.Salt), scryptMinSaltLen)
	}
	// Any other length makes cryptocore.New panic, and a huge one is allocated first.
	if s.KeyLen != cryptocore.KeyLen {
		return fmt.Errorf("fatal: scrypt parameter KeyLen must be %d: value=%d", cryptocore.KeyLen, s.KeyLen)
	}
	return nil
}
