package shield

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"time"

	"golang.org/x/crypto/pbkdf2"
)

var (
	// ErrLamportKeyUsed indicates the Lamport key was already used.
	ErrLamportKeyUsed = errors.New("shield: Lamport key already used")
	// ErrInvalidSignature indicates signature verification failed.
	ErrInvalidSignature = errors.New("shield: invalid signature")
)

// SymmetricSignature provides HMAC-based signatures.
type SymmetricSignature struct {
	signingKey      [KeySize]byte
	VerificationKey [KeySize]byte
}

// NewSymmetricSignature creates a signature from a signing key.
func NewSymmetricSignature(signingKey []byte) (*SymmetricSignature, error) {
	if len(signingKey) != KeySize {
		return nil, ErrInvalidKeySize
	}

	ss := &SymmetricSignature{}
	copy(ss.signingKey[:], signingKey)

	// Derive verification key
	h := sha256.New()
	h.Write([]byte("verify:"))
	h.Write(signingKey)
	copy(ss.VerificationKey[:], h.Sum(nil))

	return ss, nil
}

// GenerateSymmetricSignature generates a new random signature identity.
func GenerateSymmetricSignature() (*SymmetricSignature, error) {
	key := make([]byte, KeySize)
	if _, err := rand.Read(key); err != nil {
		return nil, err
	}
	return NewSymmetricSignature(key)
}

// SymmetricSignatureFromPassword derives signature from password and identity.
func SymmetricSignatureFromPassword(password, identity string) *SymmetricSignature {
	salt := sha256.Sum256([]byte("sign:" + identity))
	key := pbkdf2.Key([]byte(password), salt[:], 100000, KeySize, sha256.New)

	ss := &SymmetricSignature{}
	copy(ss.signingKey[:], key)

	h := sha256.New()
	h.Write([]byte("verify:"))
	h.Write(key)
	copy(ss.VerificationKey[:], h.Sum(nil))

	return ss
}

// Sign signs a message.
func (ss *SymmetricSignature) Sign(message []byte, includeTimestamp bool) []byte {
	if includeTimestamp {
		timestamp := time.Now().Unix()
		tsBytes := make([]byte, 8)
		binary.LittleEndian.PutUint64(tsBytes, uint64(timestamp))

		sigData := append(tsBytes, message...)
		mac := hmac.New(sha256.New, ss.signingKey[:])
		mac.Write(sigData)
		sig := mac.Sum(nil)

		return append(tsBytes, sig...)
	}

	mac := hmac.New(sha256.New, ss.signingKey[:])
	mac.Write(message)
	return mac.Sum(nil)
}

// Verify verifies a signature.
func (ss *SymmetricSignature) Verify(message, signature []byte, verificationKey []byte, maxAge int64) bool {
	if subtle.ConstantTimeCompare(verificationKey, ss.VerificationKey[:]) != 1 {
		return false
	}

	if len(signature) == 40 {
		// Timestamped signature
		timestamp := binary.LittleEndian.Uint64(signature[:8])
		sig := signature[8:]

		if maxAge > 0 {
			now := time.Now().Unix()
			diff := now - int64(timestamp)
			if diff < 0 {
				diff = -diff
			}
			if diff > maxAge {
				return false
			}
		}

		// Create new slice to avoid mutating signature
		sigData := make([]byte, 8+len(message))
		copy(sigData[:8], signature[:8])
		copy(sigData[8:], message)

		mac := hmac.New(sha256.New, ss.signingKey[:])
		mac.Write(sigData)
		expected := mac.Sum(nil)

		return subtle.ConstantTimeCompare(sig, expected) == 1
	}

	if len(signature) == 32 {
		mac := hmac.New(sha256.New, ss.signingKey[:])
		mac.Write(message)
		expected := mac.Sum(nil)
		return subtle.ConstantTimeCompare(signature, expected) == 1
	}

	return false
}

// Fingerprint returns the key fingerprint.
func (ss *SymmetricSignature) Fingerprint() string {
	h := sha256.Sum256(ss.VerificationKey[:])
	return hex.EncodeToString(h[:8])
}

// LamportSignature provides one-time post-quantum signatures.
type LamportSignature struct {
	privateKey [][2][KeySize]byte
	PublicKey  []byte
	used       bool
}

// GenerateLamportSignature generates a new Lamport key pair.
func GenerateLamportSignature() (*LamportSignature, error) {
	const bits = 256
	ls := &LamportSignature{
		privateKey: make([][2][KeySize]byte, bits),
		PublicKey:  make([]byte, bits*64),
	}

	for i := 0; i < bits; i++ {
		if _, err := rand.Read(ls.privateKey[i][0][:]); err != nil {
			return nil, err
		}
		if _, err := rand.Read(ls.privateKey[i][1][:]); err != nil {
			return nil, err
		}

		h0 := sha256.Sum256(ls.privateKey[i][0][:])
		h1 := sha256.Sum256(ls.privateKey[i][1][:])

		copy(ls.PublicKey[i*64:i*64+32], h0[:])
		copy(ls.PublicKey[i*64+32:i*64+64], h1[:])
	}

	return ls, nil
}

// Sign signs a message (ONE TIME ONLY).
func (ls *LamportSignature) Sign(message []byte) ([]byte, error) {
	if ls.used {
		return nil, ErrLamportKeyUsed
	}
	ls.used = true

	msgHash := sha256.Sum256(message)
	signature := make([]byte, 256*32)

	for i := 0; i < 256; i++ {
		byteIdx := i / 8
		bitIdx := i % 8
		bit := (msgHash[byteIdx] >> bitIdx) & 1

		if bit == 1 {
			copy(signature[i*32:(i+1)*32], ls.privateKey[i][1][:])
		} else {
			copy(signature[i*32:(i+1)*32], ls.privateKey[i][0][:])
		}
	}

	return signature, nil
}

// VerifyLamport verifies a Lamport signature.
func VerifyLamport(message, signature, publicKey []byte) bool {
	if len(signature) != 256*32 || len(publicKey) != 256*64 {
		return false
	}

	msgHash := sha256.Sum256(message)

	for i := 0; i < 256; i++ {
		byteIdx := i / 8
		bitIdx := i % 8
		bit := (msgHash[byteIdx] >> bitIdx) & 1

		revealed := signature[i*32 : (i+1)*32]
		hashed := sha256.Sum256(revealed)

		var expected []byte
		if bit == 1 {
			expected = publicKey[i*64+32 : i*64+64]
		} else {
			expected = publicKey[i*64 : i*64+32]
		}

		if subtle.ConstantTimeCompare(hashed[:], expected) != 1 {
			return false
		}
	}

	return true
}

// IsUsed returns whether the key has been used.
func (ls *LamportSignature) IsUsed() bool {
	return ls.used
}

// Fingerprint returns the public key fingerprint.
func (ls *LamportSignature) Fingerprint() string {
	h := sha256.Sum256(ls.PublicKey)
	return hex.EncodeToString(h[:8])
}
