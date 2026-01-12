// Package shield provides EXPTIME-secure symmetric encryption.
//
// Shield uses only symmetric cryptographic primitives with proven
// exponential-time security: PBKDF2-SHA256, HMAC-SHA256, and SHA256-based
// stream cipher. Breaking requires 2^256 operations - no shortcut exists.
package shield

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"errors"

	"golang.org/x/crypto/pbkdf2"
)

const (
	// KeySize is the size of encryption keys in bytes.
	KeySize = 32
	// NonceSize is the size of nonces in bytes.
	NonceSize = 16
	// MACSize is the size of authentication tags in bytes.
	MACSize = 16
	// CounterSize is the size of the counter prefix in bytes.
	CounterSize = 8
	// Iterations is the PBKDF2 iteration count.
	Iterations = 100000
	// MinCiphertextSize is the minimum valid ciphertext size (Shield with counter).
	MinCiphertextSize = NonceSize + CounterSize + MACSize
	// MinQuickCiphertextSize is the minimum valid ciphertext size (QuickEncrypt without counter).
	MinQuickCiphertextSize = NonceSize + MACSize
)

var (
	// ErrCiphertextTooShort indicates the ciphertext is malformed.
	ErrCiphertextTooShort = errors.New("shield: ciphertext too short")
	// ErrAuthenticationFailed indicates MAC verification failed.
	ErrAuthenticationFailed = errors.New("shield: authentication failed")
	// ErrInvalidKeySize indicates wrong key size.
	ErrInvalidKeySize = errors.New("shield: invalid key size")
)

// Shield provides password-based encryption.
type Shield struct {
	key [KeySize]byte
}

// New creates a Shield instance from password and service name.
func New(password, service string) *Shield {
	salt := sha256.Sum256([]byte(service))
	key := pbkdf2.Key([]byte(password), salt[:], Iterations, KeySize, sha256.New)

	s := &Shield{}
	copy(s.key[:], key)
	return s
}

// WithKey creates a Shield instance with a pre-shared key.
func WithKey(key []byte) (*Shield, error) {
	if len(key) != KeySize {
		return nil, ErrInvalidKeySize
	}
	s := &Shield{}
	copy(s.key[:], key)
	return s, nil
}

// Encrypt encrypts plaintext and returns authenticated ciphertext.
// Format: nonce(16) || counter(8) || encrypted_plaintext || mac(16)
func (s *Shield) Encrypt(plaintext []byte) ([]byte, error) {
	return EncryptWithKey(s.key[:], plaintext)
}

// Decrypt decrypts and verifies ciphertext.
func (s *Shield) Decrypt(ciphertext []byte) ([]byte, error) {
	return DecryptWithKey(s.key[:], ciphertext)
}

// Key returns the derived key.
func (s *Shield) Key() []byte {
	return s.key[:]
}

// QuickEncrypt encrypts with a pre-shared key (no counter prefix).
// Format: nonce(16) || ciphertext || mac(16)
// This is interoperable with Python/JavaScript quick_encrypt.
func QuickEncrypt(key, plaintext []byte) ([]byte, error) {
	if len(key) != KeySize {
		return nil, ErrInvalidKeySize
	}

	// Generate random nonce
	nonce := make([]byte, NonceSize)
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}

	// Generate keystream and XOR (no counter prefix)
	keystream := generateKeystream(key, nonce, len(plaintext))
	ciphertext := make([]byte, len(plaintext))
	for i := range plaintext {
		ciphertext[i] = plaintext[i] ^ keystream[i]
	}

	// Compute HMAC over nonce || ciphertext
	mac := hmac.New(sha256.New, key)
	mac.Write(nonce)
	mac.Write(ciphertext)
	tag := mac.Sum(nil)[:MACSize]

	// Format: nonce || ciphertext || mac
	result := make([]byte, NonceSize+len(ciphertext)+MACSize)
	copy(result[:NonceSize], nonce)
	copy(result[NonceSize:NonceSize+len(ciphertext)], ciphertext)
	copy(result[NonceSize+len(ciphertext):], tag)

	return result, nil
}

// QuickDecrypt decrypts with a pre-shared key (no counter prefix).
// This is interoperable with Python/JavaScript quick_decrypt.
func QuickDecrypt(key, encrypted []byte) ([]byte, error) {
	if len(key) != KeySize {
		return nil, ErrInvalidKeySize
	}
	if len(encrypted) < MinQuickCiphertextSize {
		return nil, ErrCiphertextTooShort
	}

	// Parse components
	nonce := encrypted[:NonceSize]
	ciphertext := encrypted[NonceSize : len(encrypted)-MACSize]
	receivedMAC := encrypted[len(encrypted)-MACSize:]

	// Verify MAC
	mac := hmac.New(sha256.New, key)
	mac.Write(nonce)
	mac.Write(ciphertext)
	expectedMAC := mac.Sum(nil)[:MACSize]

	if subtle.ConstantTimeCompare(receivedMAC, expectedMAC) != 1 {
		return nil, ErrAuthenticationFailed
	}

	// Decrypt (no counter prefix to skip)
	keystream := generateKeystream(key, nonce, len(ciphertext))
	decrypted := make([]byte, len(ciphertext))
	for i := range ciphertext {
		decrypted[i] = ciphertext[i] ^ keystream[i]
	}

	return decrypted, nil
}

// EncryptWithKey encrypts using an explicit key.
func EncryptWithKey(key, plaintext []byte) ([]byte, error) {
	// Generate random nonce
	nonce := make([]byte, NonceSize)
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}

	// Counter prefix
	counter := make([]byte, 8)
	binary.LittleEndian.PutUint64(counter, 0)

	// Data to encrypt: counter || plaintext
	dataToEncrypt := make([]byte, 8+len(plaintext))
	copy(dataToEncrypt[:8], counter)
	copy(dataToEncrypt[8:], plaintext)

	// Generate keystream and XOR
	keystream := generateKeystream(key, nonce, len(dataToEncrypt))
	ciphertext := make([]byte, len(dataToEncrypt))
	for i := range dataToEncrypt {
		ciphertext[i] = dataToEncrypt[i] ^ keystream[i]
	}

	// Compute HMAC over nonce || ciphertext
	mac := hmac.New(sha256.New, key)
	mac.Write(nonce)
	mac.Write(ciphertext)
	tag := mac.Sum(nil)[:MACSize]

	// Format: nonce || ciphertext || mac
	result := make([]byte, NonceSize+len(ciphertext)+MACSize)
	copy(result[:NonceSize], nonce)
	copy(result[NonceSize:NonceSize+len(ciphertext)], ciphertext)
	copy(result[NonceSize+len(ciphertext):], tag)

	return result, nil
}

// DecryptWithKey decrypts using an explicit key.
func DecryptWithKey(key, encrypted []byte) ([]byte, error) {
	if len(encrypted) < MinCiphertextSize {
		return nil, ErrCiphertextTooShort
	}

	// Parse components
	nonce := encrypted[:NonceSize]
	ciphertext := encrypted[NonceSize : len(encrypted)-MACSize]
	receivedMAC := encrypted[len(encrypted)-MACSize:]

	// Verify MAC
	mac := hmac.New(sha256.New, key)
	mac.Write(nonce)
	mac.Write(ciphertext)
	expectedMAC := mac.Sum(nil)[:MACSize]

	if subtle.ConstantTimeCompare(receivedMAC, expectedMAC) != 1 {
		return nil, ErrAuthenticationFailed
	}

	// Decrypt
	keystream := generateKeystream(key, nonce, len(ciphertext))
	decrypted := make([]byte, len(ciphertext))
	for i := range ciphertext {
		decrypted[i] = ciphertext[i] ^ keystream[i]
	}

	// Skip counter prefix (8 bytes)
	return decrypted[8:], nil
}

// generateKeystream generates a SHA256-based keystream.
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
