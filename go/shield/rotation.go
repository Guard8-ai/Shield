package shield

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"time"

	"golang.org/x/crypto/pbkdf2"
)

var (
	// ErrNoActiveKey indicates no active key is available.
	ErrNoActiveKey = errors.New("shield: no active key")
	// ErrKeyVersionNotFound indicates key version not found.
	ErrKeyVersionNotFound = errors.New("shield: key version not found")
)

// VersionedKey represents a key with version and timestamp.
type VersionedKey struct {
	Key       []byte
	Version   uint32
	CreatedAt int64
	ExpiredAt int64
}

// KeyRotationManager manages key rotation.
type KeyRotationManager struct {
	masterSecret []byte
	keys         map[uint32]*VersionedKey
	currentVer   uint32
	rotationSec  int64
}

// NewKeyRotationManager creates a new rotation manager.
func NewKeyRotationManager(masterSecret []byte, rotationIntervalSeconds int64) *KeyRotationManager {
	if rotationIntervalSeconds <= 0 {
		rotationIntervalSeconds = 86400 * 30 // 30 days default
	}

	km := &KeyRotationManager{
		masterSecret: make([]byte, len(masterSecret)),
		keys:         make(map[uint32]*VersionedKey),
		currentVer:   0,
		rotationSec:  rotationIntervalSeconds,
	}
	copy(km.masterSecret, masterSecret)

	// Generate initial key
	km.rotate()

	return km
}

// rotate creates a new key version.
func (km *KeyRotationManager) rotate() *VersionedKey {
	km.currentVer++
	now := time.Now().Unix()

	// Derive key from master secret and version
	verBytes := make([]byte, 4)
	binary.LittleEndian.PutUint32(verBytes, km.currentVer)

	salt := sha256.Sum256(append([]byte("rotation:"), verBytes...))
	key := pbkdf2.Key(km.masterSecret, salt[:], 100000, KeySize, sha256.New)

	vk := &VersionedKey{
		Key:       key,
		Version:   km.currentVer,
		CreatedAt: now,
		ExpiredAt: 0,
	}

	// Mark previous key as expired
	if prev, ok := km.keys[km.currentVer-1]; ok {
		prev.ExpiredAt = now
	}

	km.keys[km.currentVer] = vk
	return vk
}

// Rotate creates a new key version.
func (km *KeyRotationManager) Rotate() *VersionedKey {
	return km.rotate()
}

// CurrentKey returns the current active key.
func (km *KeyRotationManager) CurrentKey() (*VersionedKey, error) {
	if km.currentVer == 0 {
		return nil, ErrNoActiveKey
	}
	return km.keys[km.currentVer], nil
}

// GetKey retrieves a specific key version.
func (km *KeyRotationManager) GetKey(version uint32) (*VersionedKey, error) {
	if vk, ok := km.keys[version]; ok {
		return vk, nil
	}
	return nil, ErrKeyVersionNotFound
}

// Encrypt encrypts data with current key, prefixing version.
func (km *KeyRotationManager) Encrypt(plaintext []byte) ([]byte, error) {
	current, err := km.CurrentKey()
	if err != nil {
		return nil, err
	}

	encrypted, err := EncryptWithKey(current.Key, plaintext)
	if err != nil {
		return nil, err
	}

	// Prefix with version
	result := make([]byte, 4+len(encrypted))
	binary.LittleEndian.PutUint32(result[:4], current.Version)
	copy(result[4:], encrypted)

	return result, nil
}

// Decrypt decrypts data, auto-selecting key version.
func (km *KeyRotationManager) Decrypt(ciphertext []byte) ([]byte, error) {
	if len(ciphertext) < 4 {
		return nil, ErrCiphertextTooShort
	}

	version := binary.LittleEndian.Uint32(ciphertext[:4])
	vk, err := km.GetKey(version)
	if err != nil {
		return nil, err
	}

	return DecryptWithKey(vk.Key, ciphertext[4:])
}

// NeedsRotation checks if rotation is due.
func (km *KeyRotationManager) NeedsRotation() bool {
	current, err := km.CurrentKey()
	if err != nil {
		return true
	}

	elapsed := time.Now().Unix() - current.CreatedAt
	return elapsed >= km.rotationSec
}

// AutoRotate rotates if needed.
func (km *KeyRotationManager) AutoRotate() bool {
	if km.NeedsRotation() {
		km.Rotate()
		return true
	}
	return false
}

// ReEncrypt re-encrypts data with the current key.
func (km *KeyRotationManager) ReEncrypt(ciphertext []byte) ([]byte, error) {
	plaintext, err := km.Decrypt(ciphertext)
	if err != nil {
		return nil, err
	}
	return km.Encrypt(plaintext)
}

// Version returns the current key version.
func (km *KeyRotationManager) Version() uint32 {
	return km.currentVer
}

// AllVersions returns all available key versions.
func (km *KeyRotationManager) AllVersions() []uint32 {
	versions := make([]uint32, 0, len(km.keys))
	for v := range km.keys {
		versions = append(versions, v)
	}
	return versions
}

// Fingerprint returns the current key fingerprint.
func (km *KeyRotationManager) Fingerprint() string {
	current, err := km.CurrentKey()
	if err != nil {
		return ""
	}
	h := sha256.Sum256(current.Key)
	return hex.EncodeToString(h[:8])
}
