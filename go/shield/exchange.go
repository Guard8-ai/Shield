package shield

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"

	"golang.org/x/crypto/pbkdf2"
)

var (
	// ErrPAKEVerificationFailed indicates PAKE verification failed.
	ErrPAKEVerificationFailed = errors.New("shield: PAKE verification failed")
	// ErrInvalidShareCount indicates invalid share count for splitting.
	ErrInvalidShareCount = errors.New("shield: invalid share count")
)

// PAKEExchange provides Password-Authenticated Key Exchange.
type PAKEExchange struct {
	password     string
	identity     string
	privateValue [KeySize]byte
	PublicValue  []byte
}

// NewPAKEExchange creates a new PAKE exchange.
func NewPAKEExchange(password, identity string) (*PAKEExchange, error) {
	pe := &PAKEExchange{
		password: password,
		identity: identity,
	}

	// Generate private random value
	if _, err := rand.Read(pe.privateValue[:]); err != nil {
		return nil, err
	}

	// Derive password verifier
	salt := sha256.Sum256([]byte("pake:" + identity))
	verifier := pbkdf2.Key([]byte(password), salt[:], 100000, KeySize, sha256.New)

	// Public value = H(verifier || privateValue)
	h := sha256.New()
	h.Write(verifier)
	h.Write(pe.privateValue[:])
	pe.PublicValue = h.Sum(nil)

	return pe, nil
}

// DeriveKey derives shared key from peer's public value.
func (pe *PAKEExchange) DeriveKey(peerPublic []byte) []byte {
	// Derive password verifier
	salt := sha256.Sum256([]byte("pake:" + pe.identity))
	verifier := pbkdf2.Key([]byte(pe.password), salt[:], 100000, KeySize, sha256.New)

	// Shared secret = H(verifier || sorted(myPublic, peerPublic))
	// Sorting ensures both parties derive the same key
	h := sha256.New()
	h.Write(verifier)

	// Use lexicographic ordering for consistency
	cmp := bytes.Compare(pe.PublicValue, peerPublic)
	if cmp < 0 {
		h.Write(pe.PublicValue)
		h.Write(peerPublic)
	} else {
		h.Write(peerPublic)
		h.Write(pe.PublicValue)
	}

	return h.Sum(nil)
}

// Verify verifies peer's proof.
func (pe *PAKEExchange) Verify(peerPublic, peerProof []byte) bool {
	sharedKey := pe.DeriveKey(peerPublic)

	// Expected proof = HMAC(sharedKey, peerPublic)
	mac := hmac.New(sha256.New, sharedKey)
	mac.Write(peerPublic)
	expected := mac.Sum(nil)

	return subtle.ConstantTimeCompare(peerProof, expected) == 1
}

// CreateProof creates proof of key knowledge.
func (pe *PAKEExchange) CreateProof(peerPublic []byte) []byte {
	sharedKey := pe.DeriveKey(peerPublic)

	mac := hmac.New(sha256.New, sharedKey)
	mac.Write(pe.PublicValue)

	return mac.Sum(nil)
}

// PAKEDerive derives a PAKE contribution from password and salt.
// This is the static function used by ShieldChannel.
func PAKEDerive(password string, salt []byte, role string, iterations int) []byte {
	context := []byte("SHIELD-PAKE-" + role)
	fullSalt := append(salt, context...)
	return pbkdf2.Key([]byte(password), fullSalt, iterations, KeySize, sha256.New)
}

// PAKECombine combines two contributions to produce a shared key.
func PAKECombine(local, remote []byte) []byte {
	combined := append(local, remote...)
	h := sha256.Sum256(combined)
	return h[:]
}

// QRExchange provides QR code-based key exchange.
type QRExchange struct {
	Code      string
	key       [KeySize]byte
	challenge [16]byte
}

// NewQRExchange creates initiator QR exchange.
func NewQRExchange() (*QRExchange, error) {
	qe := &QRExchange{}

	if _, err := rand.Read(qe.key[:]); err != nil {
		return nil, err
	}
	if _, err := rand.Read(qe.challenge[:]); err != nil {
		return nil, err
	}

	// Format: base64(key || challenge)
	data := make([]byte, KeySize+16)
	copy(data[:KeySize], qe.key[:])
	copy(data[KeySize:], qe.challenge[:])
	qe.Code = base64.StdEncoding.EncodeToString(data)

	return qe, nil
}

// ScanQRExchange creates responder from scanned code.
func ScanQRExchange(code string) (*QRExchange, error) {
	data, err := base64.StdEncoding.DecodeString(code)
	if err != nil {
		return nil, err
	}
	if len(data) != KeySize+16 {
		return nil, ErrInvalidKeySize
	}

	qe := &QRExchange{Code: code}
	copy(qe.key[:], data[:KeySize])
	copy(qe.challenge[:], data[KeySize:])

	return qe, nil
}

// CreateResponse creates challenge response.
func (qe *QRExchange) CreateResponse() []byte {
	mac := hmac.New(sha256.New, qe.key[:])
	mac.Write(qe.challenge[:])
	return mac.Sum(nil)
}

// VerifyResponse verifies challenge response.
func (qe *QRExchange) VerifyResponse(response []byte) bool {
	expected := qe.CreateResponse()
	return subtle.ConstantTimeCompare(response, expected) == 1
}

// Key returns the shared key.
func (qe *QRExchange) Key() []byte {
	return qe.key[:]
}

// KeySplitter provides threshold key splitting.
type KeySplitter struct{}

// NewKeySplitter creates a new key splitter.
func NewKeySplitter() *KeySplitter {
	return &KeySplitter{}
}

// Split splits key into n shares (XOR-based, all shares required).
func (ks *KeySplitter) Split(key []byte, n int) ([][]byte, error) {
	if n < 2 {
		return nil, ErrInvalidShareCount
	}

	shares := make([][]byte, n)

	// Generate n-1 random shares
	for i := 0; i < n-1; i++ {
		shares[i] = make([]byte, len(key))
		if _, err := rand.Read(shares[i]); err != nil {
			return nil, err
		}
	}

	// Last share = XOR of key with all other shares
	shares[n-1] = make([]byte, len(key))
	copy(shares[n-1], key)
	for i := 0; i < n-1; i++ {
		for j := range shares[n-1] {
			shares[n-1][j] ^= shares[i][j]
		}
	}

	// Add index prefix to each share
	result := make([][]byte, n)
	for i := 0; i < n; i++ {
		result[i] = make([]byte, 4+len(key))
		binary.LittleEndian.PutUint32(result[i][:4], uint32(i))
		copy(result[i][4:], shares[i])
	}

	return result, nil
}

// Combine combines all shares to recover key.
func (ks *KeySplitter) Combine(shares [][]byte) ([]byte, error) {
	if len(shares) < 2 {
		return nil, ErrInvalidShareCount
	}

	// Extract share data (skip index prefix)
	shareData := make([][]byte, len(shares))
	for i, share := range shares {
		if len(share) < 5 {
			return nil, ErrInvalidKeySize
		}
		shareData[i] = share[4:]
	}

	// XOR all shares together
	keyLen := len(shareData[0])
	result := make([]byte, keyLen)
	for _, share := range shareData {
		if len(share) != keyLen {
			return nil, ErrInvalidKeySize
		}
		for i := range result {
			result[i] ^= share[i]
		}
	}

	return result, nil
}

// Fingerprint returns a share fingerprint for identification.
func (ks *KeySplitter) Fingerprint(share []byte) string {
	h := sha256.Sum256(share)
	return hex.EncodeToString(h[:8])
}
