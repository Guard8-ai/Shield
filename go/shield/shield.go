// Package shield provides authenticated symmetric encryption.
//
// Wire format v4 uses a standard AEAD (AES-256-GCM by default, ChaCha20-Poly1305
// optional) from the Go standard library and golang.org/x/crypto. Keys are
// derived with PBKDF2-HMAC-SHA256 (random per-instance salt, 600k iterations) and
// HKDF-SHA256-Expand. No cryptography is hand-rolled. The format matches every
// other Shield binding byte-for-byte (see tests/v4_test_vectors.json).
package shield

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"time"

	"golang.org/x/crypto/chacha20poly1305"
)

const (
	// KeySize is the size of encryption keys in bytes.
	KeySize = 32
	// NonceSize is the nonce size used by the auxiliary keystream layers
	// (ratchet/stream). The base AEAD cipher uses its own 12-byte nonce.
	NonceSize = 16
	// MACSize is the tag size used by the auxiliary keystream layers.
	MACSize = 16
	// SaltSize is the size of the per-instance random salt in bytes.
	SaltSize = 16
	// Iterations is the PBKDF2 iteration count (OWASP 2023 floor for PBKDF2-HMAC-SHA256).
	Iterations = 600000

	// VersionPassword is the leading authenticated version byte for password mode:
	// 0x03 || suite(1) || salt(16) || nonce(12) || ciphertext||tag.
	VersionPassword = 0x03
	// VersionKey is the leading authenticated version byte for pre-shared-key mode:
	// 0x13 || suite(1) || nonce(12) || ciphertext||tag.
	VersionKey = 0x13

	// SuiteAES256GCM selects AES-256-GCM (default, FIPS-approved).
	SuiteAES256GCM = 0x01
	// SuiteChaCha20Poly1305 selects ChaCha20-Poly1305.
	SuiteChaCha20Poly1305 = 0x02

	// MinPadding is the minimum inner padding size.
	MinPadding = 32
	// MaxPadding is the maximum inner padding size.
	MaxPadding = 128
	// DefaultMaxAgeMs is the default maximum message age in milliseconds.
	DefaultMaxAgeMs = 60000

	// aeadNonceSize is the AEAD nonce size (96-bit) for the base cipher.
	aeadNonceSize = 12
	// tagSize is the AEAD authentication tag size (128-bit).
	tagSize = 16
	// innerHeaderSize is the inner-plaintext header: timestamp(8) + pad_len(1).
	innerHeaderSize = 9
	// hkdfAEADInfo is the HKDF-Expand info string deriving the AEAD key.
	hkdfAEADInfo = "shield/aead/v4"
)

var (
	// ErrCiphertextTooShort indicates the ciphertext is malformed.
	ErrCiphertextTooShort = errors.New("shield: ciphertext too short")
	// ErrAuthenticationFailed indicates AEAD authentication failed.
	ErrAuthenticationFailed = errors.New("shield: authentication failed")
	// ErrInvalidKeySize indicates wrong key size.
	ErrInvalidKeySize = errors.New("shield: invalid key size")
	// ErrInvalidVersion indicates an unrecognized leading version byte.
	ErrInvalidVersion = errors.New("shield: invalid version byte")
	// ErrInvalidSuite indicates an unrecognized cipher-suite byte.
	ErrInvalidSuite = errors.New("shield: invalid cipher suite")
	// ErrNoPassword indicates a password-mode ciphertext was given to a pre-shared-key instance.
	ErrNoPassword = errors.New("shield: cannot derive key without password")
)

// Shield provides password-based encryption.
type Shield struct {
	key      [KeySize]byte // master key
	aeadKey  [KeySize]byte // HKDF-derived AEAD key
	suite    byte          // cipher suite used on encrypt
	maxAgeMs *int64        // nil = freshness check disabled

	// Password mode fields (nil/empty in pre-shared-key mode).
	password   []byte
	service    []byte
	iterations int
	salt       []byte // per-instance random salt; nil in pre-shared-key mode
	keyCache   map[[SaltSize]byte][KeySize]byte
}

// deriveAEADKey derives the AEAD key from a master key via HKDF-SHA256-Expand
// (info = "shield/aead/v4", L = 32).
func deriveAEADKey(masterKey []byte) [KeySize]byte {
	okm, err := hkdf.Expand(sha256.New, masterKey, hkdfAEADInfo, KeySize)
	if err != nil {
		// HKDF-Expand of a 32-byte output never fails.
		panic(err)
	}
	var out [KeySize]byte
	copy(out[:], okm)
	return out
}

// aeadForSuite returns a cipher.AEAD for the given suite and key.
func aeadForSuite(suite byte, key []byte) (cipher.AEAD, error) {
	switch suite {
	case SuiteAES256GCM:
		block, err := aes.NewCipher(key)
		if err != nil {
			return nil, err
		}
		return cipher.NewGCM(block)
	case SuiteChaCha20Poly1305:
		return chacha20poly1305.New(key)
	default:
		return nil, ErrInvalidSuite
	}
}

// New creates a Shield instance from password and service name (password mode).
//
// A cryptographically secure random 16-byte salt is generated per instance.
// master = PBKDF2-HMAC-SHA256(password, salt || service, iterations, 32);
// aeadKey = HKDF-Expand(master, "shield/aead/v4", 32). The random salt is stored
// in the ciphertext header so a recipient with the same password+service can
// re-derive the key. service is retained as a domain separator.
//
// maxAgeMs: maximum message age in milliseconds (use nil to disable the freshness window).
func New(password, service string, maxAgeMs *int64) *Shield {
	salt := make([]byte, SaltSize)
	if _, err := rand.Read(salt); err != nil {
		panic(err)
	}
	return newWithSalt(password, service, salt, Iterations, maxAgeMs)
}

// newWithSalt constructs a password-mode Shield with an explicit salt.
func newWithSalt(password, service string, salt []byte, iterations int, maxAgeMs *int64) *Shield {
	s := &Shield{
		suite:      SuiteAES256GCM,
		maxAgeMs:   maxAgeMs,
		password:   []byte(password),
		service:    []byte(service),
		iterations: iterations,
		salt:       salt,
		keyCache:   make(map[[SaltSize]byte][KeySize]byte),
	}
	master := s.deriveKey(salt)
	copy(s.key[:], master[:])
	s.aeadKey = deriveAEADKey(s.key[:])
	return s
}

// deriveKey derives the 32-byte master key for a given salt (cached by salt).
func (s *Shield) deriveKey(salt []byte) [KeySize]byte {
	var saltKey [SaltSize]byte
	copy(saltKey[:], salt)
	if cached, ok := s.keyCache[saltKey]; ok {
		return cached
	}
	input := make([]byte, len(salt)+len(s.service))
	copy(input, salt)
	copy(input[len(salt):], s.service)
	derived, err := pbkdf2.Key(sha256.New, string(s.password), input, s.iterations, KeySize)
	if err != nil {
		panic(err)
	}
	var out [KeySize]byte
	copy(out[:], derived)
	s.keyCache[saltKey] = out
	return out
}

// WithKey creates a Shield instance with a pre-shared key (no password derivation).
func WithKey(key []byte) (*Shield, error) {
	if len(key) != KeySize {
		return nil, ErrInvalidKeySize
	}
	defaultMaxAge := int64(DefaultMaxAgeMs)
	s := &Shield{suite: SuiteAES256GCM, maxAgeMs: &defaultMaxAge}
	copy(s.key[:], key)
	s.aeadKey = deriveAEADKey(s.key[:])
	// Pre-shared-key mode: no password, no salt.
	return s, nil
}

// Encrypt encrypts plaintext and returns authenticated ciphertext.
//
// Password mode output: 0x03 || suite || salt(16) || nonce(12) || ciphertext||tag.
// Pre-shared-key mode output: 0x13 || suite || nonce(12) || ciphertext||tag.
func (s *Shield) Encrypt(plaintext []byte) ([]byte, error) {
	return seal(s.aeadKey[:], s.suite, s.salt, plaintext)
}

// Decrypt decrypts and verifies ciphertext, dispatching on the leading
// authenticated version byte.
func (s *Shield) Decrypt(ciphertext []byte) ([]byte, error) {
	if len(ciphertext) < 1 {
		return nil, ErrCiphertextTooShort
	}

	switch ciphertext[0] {
	case VersionPassword:
		if s.salt == nil {
			return nil, ErrNoPassword
		}
		aadLen := 2 + SaltSize
		if len(ciphertext) < aadLen+aeadNonceSize+tagSize {
			return nil, ErrCiphertextTooShort
		}
		suite := ciphertext[1]
		salt := ciphertext[2 : 2+SaltSize]
		master := s.deriveKey(salt)
		aeadKey := deriveAEADKey(master[:])
		return open(aeadKey[:], suite, ciphertext, aadLen, s.maxAgeMs)

	case VersionKey:
		suite := ciphertext[1]
		return open(s.aeadKey[:], suite, ciphertext, 2, s.maxAgeMs)

	default:
		return nil, ErrInvalidVersion
	}
}

// DerivedKey exposes the raw master key. Exposed only for cross-language interop tests.
func (s *Shield) DerivedKey() []byte {
	return s.key[:]
}

// QuickEncrypt encrypts with a pre-shared key (no password derivation).
// Equivalent to WithKey(key).Encrypt(plaintext).
func QuickEncrypt(key, plaintext []byte) ([]byte, error) {
	s, err := WithKey(key)
	if err != nil {
		return nil, err
	}
	return s.Encrypt(plaintext)
}

// QuickDecrypt decrypts with a pre-shared key, applying the default 60-second
// freshness window (matching the Rust source of truth).
func QuickDecrypt(key, encrypted []byte) ([]byte, error) {
	s, err := WithKey(key)
	if err != nil {
		return nil, err
	}
	return s.Decrypt(encrypted)
}

// EncryptWithKey encrypts using an explicit key (pre-shared-key mode, AES-256-GCM).
func EncryptWithKey(key, plaintext []byte) ([]byte, error) {
	aeadKey := deriveAEADKey(key)
	return seal(aeadKey[:], SuiteAES256GCM, nil, plaintext)
}

// DecryptWithKey decrypts using an explicit key (pre-shared-key mode).
func DecryptWithKey(key, encrypted []byte, maxAgeMs *int64) ([]byte, error) {
	if len(encrypted) < 1 {
		return nil, ErrCiphertextTooShort
	}
	if encrypted[0] != VersionKey {
		return nil, ErrInvalidVersion
	}
	if len(encrypted) < 2+aeadNonceSize+tagSize {
		return nil, ErrCiphertextTooShort
	}
	aeadKey := deriveAEADKey(key)
	return open(aeadKey[:], encrypted[1], encrypted, 2, maxAgeMs)
}

// buildAAD builds the AEAD additional data (= wire prefix before the nonce):
// version || suite || [salt].
func buildAAD(suite byte, salt []byte) []byte {
	if salt != nil {
		aad := make([]byte, 0, 2+len(salt))
		aad = append(aad, VersionPassword, suite)
		aad = append(aad, salt...)
		return aad
	}
	return []byte{VersionKey, suite}
}

// seal seals plaintext with a fresh random nonce, timestamp and padding.
func seal(aeadKey []byte, suite byte, salt, plaintext []byte) ([]byte, error) {
	nonce := make([]byte, aeadNonceSize)
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}

	// Random padding: 32-128 bytes (rejection sampling to avoid modulo bias).
	padRange := MaxPadding - MinPadding + 1 // 97
	var padLen int
	for {
		b := make([]byte, 1)
		if _, err := rand.Read(b); err != nil {
			return nil, err
		}
		val := int(b[0])
		if val < padRange*(256/padRange) {
			padLen = (val % padRange) + MinPadding
			break
		}
	}
	padding := make([]byte, padLen)
	if _, err := rand.Read(padding); err != nil {
		return nil, err
	}

	return sealDeterministic(
		aeadKey, suite, salt, nonce, uint64(time.Now().UnixMilli()), byte(padLen), padding, plaintext,
	)
}

// sealDeterministic seals over fully specified inputs (used for conformance
// vectors and wrapped by seal).
func sealDeterministic(aeadKey []byte, suite byte, salt, nonce []byte, timestampMs uint64, padLen byte, padding, plaintext []byte) ([]byte, error) {
	aad := buildAAD(suite, salt)

	inner := make([]byte, innerHeaderSize+len(padding)+len(plaintext))
	binary.LittleEndian.PutUint64(inner[0:8], timestampMs)
	inner[8] = padLen
	copy(inner[innerHeaderSize:], padding)
	copy(inner[innerHeaderSize+len(padding):], plaintext)

	aead, err := aeadForSuite(suite, aeadKey)
	if err != nil {
		return nil, err
	}
	ctTag := aead.Seal(nil, nonce, inner, aad)

	out := make([]byte, 0, len(aad)+len(nonce)+len(ctTag))
	out = append(out, aad...)
	out = append(out, nonce...)
	out = append(out, ctTag...)
	return out, nil
}

// open verifies and decrypts an AEAD ciphertext, validating the inner layout and
// freshness window. aadLen is the offset of the nonce (= len(version||suite||[salt])).
func open(aeadKey []byte, suite byte, encrypted []byte, aadLen int, maxAgeMs *int64) ([]byte, error) {
	if len(encrypted) < aadLen+aeadNonceSize+tagSize {
		return nil, ErrCiphertextTooShort
	}
	aead, err := aeadForSuite(suite, aeadKey)
	if err != nil {
		return nil, err
	}

	aad := encrypted[:aadLen]
	nonce := encrypted[aadLen : aadLen+aeadNonceSize]
	ctTag := encrypted[aadLen+aeadNonceSize:]

	inner, err := aead.Open(nil, nonce, ctTag, aad)
	if err != nil {
		return nil, ErrAuthenticationFailed
	}

	if len(inner) < innerHeaderSize {
		return nil, ErrInvalidVersion
	}
	timestampMs := binary.LittleEndian.Uint64(inner[0:8])
	padLen := int(inner[8])
	if padLen < MinPadding || padLen > MaxPadding {
		return nil, ErrAuthenticationFailed
	}
	dataStart := innerHeaderSize + padLen
	if len(inner) < dataStart {
		return nil, ErrCiphertextTooShort
	}

	// Freshness window (NOT full replay protection).
	if maxAgeMs != nil {
		nowMs := time.Now().UnixMilli()
		age := nowMs - int64(timestampMs)
		if int64(timestampMs) > nowMs+5000 || age > *maxAgeMs {
			return nil, ErrAuthenticationFailed
		}
	}

	return inner[dataStart:], nil
}

// generateKeystream generates a SHA256-based keystream. Retained for the
// auxiliary ratchet/stream layers (the base cipher now uses a standard AEAD).
func generateKeystream(key, nonce []byte, length int) []byte {
	numBlocks := (length + 31) / 32
	keystream := make([]byte, 0, numBlocks*32)

	for i := 0; i < numBlocks; i++ {
		counter := make([]byte, 4)
		binary.LittleEndian.PutUint32(counter, uint32(i))

		h := sha256.New()
		h.Write(key)
		h.Write(nonce)
		h.Write(counter)
		keystream = append(keystream, h.Sum(nil)...)
	}

	return keystream[:length]
}
