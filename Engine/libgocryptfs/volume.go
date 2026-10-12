// gocryptfs is an encrypted overlay filesystem written in Go.
// See README.md ( https://github.com/rfjakob/gocryptfs/blob/master/README.md )
// and the official website ( https://nuetzlich.net/gocryptfs/ ) for details.
package main

import (
	"C"
	"os"
	"path/filepath"
	"runtime/debug"
	"sync"
	"syscall"

	"libgocryptfs/v2/internal/configfile"
	"libgocryptfs/v2/internal/contentenc"
	"libgocryptfs/v2/internal/cryptocore"
	"libgocryptfs/v2/internal/nametransform"
	"libgocryptfs/v2/internal/stupidgcm"
	"libgocryptfs/v2/internal/syscallcompat"
)

type inodeKey struct {
	dev uint64
	ino uint64
}

// All handles for one backing inode share header identity and content locking.
type fileEntry struct {
	ID          []byte
	idLock      sync.Mutex
	contentLock sync.RWMutex
	refs        int // protected by Volume.handlesLock
}

type File struct {
	fd   *os.File
	path string
	key  inodeKey
	*fileEntry
	// fdLock prevents the fd to be closed while we are in the middle of
	// an operation.
	// lockFile takes RLock while holding handlesLock; close removes the
	// handle from the table before taking Lock and closing the fd.
	fdLock sync.RWMutex
}

type Volume struct {
	volumeID       int
	rootCipherDir  string
	plainTextNames bool
	// dirIVLock: Lock()ed if any "gocryptfs.diriv" file is modified
	// Readers must RLock() it to prevent them from seeing intermediate
	// states
	dirIVLock     sync.RWMutex
	nameTransform *nametransform.NameTransform
	cryptoCore    *cryptocore.CryptoCore
	contentEnc    *contentenc.ContentEnc
	dirCache      dirCache
	handlesLock   sync.RWMutex
	fileHandles   map[int]*File
	fileEntries   map[inodeKey]*fileEntry
	// Handle IDs are never reused: a stale ID held by a racing caller must
	// fail with EBADF instead of landing on another file. Protected by handlesLock.
	nextHandle int
	// Exported operations hold an in-flight reference (acquireVolume/release)
	// so gcf_close cannot wipe the key material underneath them.
	lifeLock sync.Mutex
	lifeCond *sync.Cond
	closing  bool
	active   int
}

// acquireVolume returns the volume with an in-flight reference, or nil if it
// is unknown or already closing. Every successful call must be paired with
// release(). A nested call made while the volume is closing fails instead of
// blocking, so it cannot deadlock against gcf_close.
func acquireVolume(volumeID int) *Volume {
	value, ok := OpenedVolumes.Load(volumeID)
	if !ok {
		return nil
	}
	volume := value.(*Volume)
	volume.lifeLock.Lock()
	defer volume.lifeLock.Unlock()
	if volume.closing {
		return nil
	}
	volume.active++
	return volume
}

func (volume *Volume) release() {
	volume.lifeLock.Lock()
	volume.active--
	if volume.active == 0 {
		volume.lifeCond.Broadcast()
	}
	volume.lifeLock.Unlock()
}

var OpenedVolumes sync.Map

// Volume IDs are never reused: a late call carrying the ID of a closed volume
// must fail instead of operating on whichever volume was opened next.
var (
	volumeIDLock sync.Mutex
	nextVolumeID int
)

func wipe(d []byte) {
	for i := range d {
		d[i] = 0
	}
	d = nil
}

func errToBool(err error) bool {
	return err == nil
}

func registerNewVolume(rootCipherDir string, masterkey []byte, cf *configfile.ConfFile) int {
	var newVolume Volume

	newVolume.plainTextNames = cf.IsFeatureFlagSet(configfile.FlagPlaintextNames)

	cryptoBackend, err := cf.ContentEncryption()
	if err != nil {
		return -1
	}
	if cryptoBackend == cryptocore.BackendXChaCha20Poly1305 && stupidgcm.PreferOpenSSLXchacha20poly1305() {
		cryptoBackend = cryptocore.BackendXChaCha20Poly1305OpenSSL
	} else if cryptoBackend == cryptocore.BackendGoGCM && stupidgcm.PreferOpenSSLAES256GCM() {
		cryptoBackend = cryptocore.BackendOpenSSL
	}
	newVolume.cryptoCore = cryptocore.New(masterkey, cryptoBackend, cryptoBackend.NonceSize*8, cf.IsFeatureFlagSet(configfile.FlagHKDF))
	newVolume.contentEnc = contentenc.New(newVolume.cryptoCore, contentenc.DefaultBS)
	var badname []string
	newVolume.nameTransform = nametransform.New(
		newVolume.cryptoCore.EMECipher,
		true,
		cf.LongNameMax,
		cf.IsFeatureFlagSet(configfile.FlagRaw64),
		badname,
		!cf.IsFeatureFlagSet(configfile.FlagDirIV),
	)

	//copying rootCipherDir
	newVolume.rootCipherDir = string([]byte(rootCipherDir[:]))

	ivLen := nametransform.DirIVLen
	if newVolume.plainTextNames {
		ivLen = 0
	}
	newVolume.dirCache = dirCache{ivLen: ivLen}
	newVolume.fileHandles = make(map[int]*File)
	newVolume.fileEntries = make(map[inodeKey]*fileEntry)
	newVolume.lifeCond = sync.NewCond(&newVolume.lifeLock)

	volumeIDLock.Lock()
	volumeID := nextVolumeID
	nextVolumeID++
	volumeIDLock.Unlock()
	newVolume.volumeID = volumeID
	OpenedVolumes.Store(volumeID, &newVolume)
	return volumeID
}

func gcf_init(rootCipherDir string, password, givenScryptHash, returnedScryptHashBuff []byte) int {
	defer wipe(password)
	cf, err := configfile.Load(filepath.Join(rootCipherDir, configfile.ConfDefaultName))
	if err != nil {
		return -1
	}
	masterkey, err := cf.GetMasterkey(password, givenScryptHash, returnedScryptHashBuff)
	if err != nil {
		return -2
	}
	debug.FreeOSMemory()
	volumeID := registerNewVolume(rootCipherDir, masterkey, cf)
	wipe(masterkey)
	return volumeID
}

func gcf_close(volumeID int) {
	// Unpublish first so no new operation can find the volume.
	value, ok := OpenedVolumes.LoadAndDelete(volumeID)
	if !ok {
		return
	}
	volume := value.(*Volume)
	// Then wait for in-flight operations. Handle-less paths (names, xattrs,
	// symlinks) and handles opened after a snapshot also use the ciphers.
	volume.lifeLock.Lock()
	volume.closing = true
	for volume.active > 0 {
		volume.lifeCond.Wait()
	}
	volume.lifeLock.Unlock()
	volume.handlesLock.Lock()
	handles := volume.fileHandles
	volume.fileHandles = make(map[int]*File)
	volume.fileEntries = make(map[inodeKey]*fileEntry)
	volume.handlesLock.Unlock()
	for _, f := range handles {
		f.fd.Close()
	}
	// Stop the expiry goroutine: it would keep the volume, and with it the
	// filename cipher's key schedule, reachable for the life of the process.
	volume.dirCache.Stop()
	volume.cryptoCore.Wipe()
	volume.nameTransform = nil
	volume.contentEnc = nil
}

func gcf_is_closed(volumeID int) bool {
	_, ok := OpenedVolumes.Load(volumeID)
	return !ok
}

func gcf_change_password(rootCipherDir string, oldPassword, givenScryptHash, newPassword, returnedScryptHashBuff []byte) bool {
	success := false
	cf, err := configfile.Load(filepath.Join(rootCipherDir, configfile.ConfDefaultName))
	if err == nil {
		masterkey, err := cf.GetMasterkey(oldPassword, givenScryptHash, nil)
		if err == nil {
			logN := cf.ScryptObject.LogN()
			scryptHash, err := cf.EncryptKey(masterkey, newPassword, logN, len(returnedScryptHashBuff) > 0)
			wipe(masterkey)
			if err == nil {
				for i := range scryptHash {
					returnedScryptHashBuff[i] = scryptHash[i]
					scryptHash[i] = 0
				}
				success = errToBool(cf.WriteFile())
			}
		}
	}
	wipe(newPassword)
	wipe(oldPassword)
	wipe(givenScryptHash)
	return success
}

func gcf_create_volume(rootCipherDir string, password []byte, plaintextNames bool, xchacha int8, logN int, creator string, returnedScryptHashBuff []byte) bool {
	var useXChaCha bool
	switch xchacha {
	case 1:
		useXChaCha = true
	case 0:
		useXChaCha = false
	default:
		useXChaCha = !stupidgcm.HasAESGCMHardwareSupport()
	}
	err := configfile.Create(&configfile.CreateArgs{
		Filename:           filepath.Join(rootCipherDir, configfile.ConfDefaultName),
		Password:           password,
		PlaintextNames:     plaintextNames,
		LogN:               logN,
		Creator:            creator,
		AESSIV:             false,
		DeterministicNames: false,
		XChaCha20Poly1305:  useXChaCha,
		LongNameMax:        255,
		Masterkey:          nil,
	}, returnedScryptHashBuff)
	wipe(password)
	if err == nil {
		if plaintextNames {
			return true
		} else {
			dirfd, err := syscall.Open(rootCipherDir, syscall.O_DIRECTORY|syscallcompat.O_PATH, 0)
			if err == nil {
				err = nametransform.WriteDirIVAt(dirfd)
				syscall.Close(dirfd)
				return errToBool(err)
			}
		}
	}
	return false
}
