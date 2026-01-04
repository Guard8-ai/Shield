package shield

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"errors"
)

var (
	// ErrReplayDetected indicates a replay attack was detected.
	ErrReplayDetected = errors.New("shield: replay detected")
	// ErrOutOfOrder indicates messages arrived out of order.
	ErrOutOfOrder = errors.New("shield: out of order message")
)

// RatchetSession provides forward secrecy through key ratcheting.
type RatchetSession struct {
	sendKey     [KeySize]byte
	recvKey     [KeySize]byte
	sendCounter uint64
	recvCounter uint64
	isInitiator bool
}

// NewRatchetSession creates a new ratchet session.
func NewRatchetSession(rootKey []byte, isInitiator bool) (*RatchetSession, error) {
	if len(rootKey) != KeySize {
		return nil, ErrInvalidKeySize
	}

	rs := &RatchetSession{
		isInitiator: isInitiator,
	}

	// Derive initial send/recv keys from root key
	if isInitiator {
		rs.sendKey = deriveChainKey(rootKey, []byte("init_send"))
		rs.recvKey = deriveChainKey(rootKey, []byte("init_recv"))
	} else {
		rs.sendKey = deriveChainKey(rootKey, []byte("init_recv"))
		rs.recvKey = deriveChainKey(rootKey, []byte("init_send"))
	}

	return rs, nil
}

// Encrypt encrypts a message with forward secrecy.
func (rs *RatchetSession) Encrypt(plaintext []byte) ([]byte, error) {
	// Derive message key from chain key
	messageKey := deriveChainKey(rs.sendKey[:], []byte("message"))

	// Generate nonce
	nonce := make([]byte, NonceSize)
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}

	// Encrypt
	keystream := generateKeystream(messageKey[:], nonce, len(plaintext))
	ciphertext := make([]byte, len(plaintext))
	for i := range plaintext {
		ciphertext[i] = plaintext[i] ^ keystream[i]
	}

	// Counter
	counterBytes := make([]byte, 8)
	binary.LittleEndian.PutUint64(counterBytes, rs.sendCounter)

	// MAC over counter || nonce || ciphertext
	mac := hmac.New(sha256.New, messageKey[:])
	mac.Write(counterBytes)
	mac.Write(nonce)
	mac.Write(ciphertext)
	tag := mac.Sum(nil)[:MACSize]

	// Ratchet send key
	rs.sendKey = deriveChainKey(rs.sendKey[:], []byte("ratchet"))
	rs.sendCounter++

	// Format: counter(8) || nonce(16) || ciphertext || mac(16)
	result := make([]byte, 8+NonceSize+len(ciphertext)+MACSize)
	copy(result[:8], counterBytes)
	copy(result[8:8+NonceSize], nonce)
	copy(result[8+NonceSize:8+NonceSize+len(ciphertext)], ciphertext)
	copy(result[8+NonceSize+len(ciphertext):], tag)

	return result, nil
}

// Decrypt decrypts a message with forward secrecy verification.
func (rs *RatchetSession) Decrypt(encrypted []byte) ([]byte, error) {
	if len(encrypted) < 8+NonceSize+MACSize {
		return nil, ErrCiphertextTooShort
	}

	// Parse
	counter := binary.LittleEndian.Uint64(encrypted[:8])
	nonce := encrypted[8 : 8+NonceSize]
	ciphertext := encrypted[8+NonceSize : len(encrypted)-MACSize]
	receivedMAC := encrypted[len(encrypted)-MACSize:]

	// Check counter
	if counter < rs.recvCounter {
		return nil, ErrReplayDetected
	}
	if counter > rs.recvCounter {
		return nil, ErrOutOfOrder
	}

	// Derive message key
	messageKey := deriveChainKey(rs.recvKey[:], []byte("message"))

	// Verify MAC
	counterBytes := make([]byte, 8)
	binary.LittleEndian.PutUint64(counterBytes, counter)

	mac := hmac.New(sha256.New, messageKey[:])
	mac.Write(counterBytes)
	mac.Write(nonce)
	mac.Write(ciphertext)
	expectedMAC := mac.Sum(nil)[:MACSize]

	if subtle.ConstantTimeCompare(receivedMAC, expectedMAC) != 1 {
		return nil, ErrAuthenticationFailed
	}

	// Decrypt
	keystream := generateKeystream(messageKey[:], nonce, len(ciphertext))
	plaintext := make([]byte, len(ciphertext))
	for i := range ciphertext {
		plaintext[i] = ciphertext[i] ^ keystream[i]
	}

	// Ratchet receive key
	rs.recvKey = deriveChainKey(rs.recvKey[:], []byte("ratchet"))
	rs.recvCounter++

	return plaintext, nil
}

// SendCounter returns the current send counter.
func (rs *RatchetSession) SendCounter() uint64 {
	return rs.sendCounter
}

// RecvCounter returns the current receive counter.
func (rs *RatchetSession) RecvCounter() uint64 {
	return rs.recvCounter
}

func deriveChainKey(key, info []byte) [KeySize]byte {
	h := sha256.New()
	h.Write(key)
	h.Write(info)
	var result [KeySize]byte
	copy(result[:], h.Sum(nil))
	return result
}
