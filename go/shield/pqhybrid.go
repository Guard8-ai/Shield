// Post-Quantum Hybrid Key Exchange.
//
// Lets two parties who have never shared a secret agree on a 32-byte key over an
// open network, safe even against an attacker who records the traffic today and
// owns a quantum computer later ("harvest now, decrypt later").
//
// It is a HYBRID exchange combining two independent key exchanges and mixing both
// results, so an attacker must break BOTH to win:
//
//   - X25519     classical elliptic-curve Diffie-Hellman (battle-tested today)
//   - ML-KEM-768 NIST FIPS 203 lattice KEM (quantum-resistant), aka CRYSTALS-Kyber
//
// Both primitives come from the Go standard library (crypto/ecdh, crypto/mlkem).
// The 32-byte output feeds straight into WithKey / QuickEncrypt.
//
// This is byte-compatible with the Python (shield.pqhybrid) and other Shield
// bindings: same primitives, same FIPS 203 / RFC 7748 encodings, and the same KDF
// binding (see deriveSharedKey).
//
// Security properties (and limits): confidential against a passive eavesdropper
// who does not hold the recipient's private key (including a future quantum
// computer); the shared key is bound to the recipient's exact public key and this
// handshake (no unknown-key-share); the SENDER is anonymous (not authenticated);
// and there is NO forward secrecy against compromise of the recipient's LONG-TERM
// key (its ML-KEM/X25519 keys are static — a stolen recipient key exposes recorded
// sessions). For full forward secrecy use an interactive ratchet, not this one-shot
// exchange. Rotate the recipient keypair periodically to bound exposure.
package shield

import (
	"crypto/ecdh"
	"crypto/hkdf"
	"crypto/mlkem"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
)

// ML-KEM-768 = NIST security level 3 (~AES-192): the recommended default.
const (
	mlkemPublicSize     = 1184 // ML-KEM-768 public (encapsulation) key
	mlkemCiphertextSize = 1088 // ML-KEM-768 encapsulation ciphertext
	mlkemSeedSize       = 64   // portable FIPS 203 seed (d || z)
	x25519PublicSize    = 32
	x25519PrivateSize   = 32
	pqSharedKeySize     = 32

	// PQPublicBundleSize is the serialized public key: ML-KEM public || X25519 public.
	PQPublicBundleSize = mlkemPublicSize + x25519PublicSize // 1216
	// PQHandshakeSize is the serialized handshake: ephemeral X25519 public || ML-KEM ciphertext.
	PQHandshakeSize = x25519PublicSize + mlkemCiphertextSize // 1120
	// PQPrivateKeySize is the serialized private key: ML-KEM seed || X25519 scalar.
	PQPrivateKeySize = mlkemSeedSize + x25519PrivateSize // 96
)

// pqKDFSalt is the versioned domain-separation label for the hybrid KDF.
var pqKDFSalt = []byte("shield/pq-hybrid/v1")

// ErrInvalidPQKeySize is returned when a serialized key/handshake has the wrong length.
var ErrInvalidPQKeySize = errors.New("shield: invalid post-quantum key or handshake size")

// deriveSharedKey mixes the two exchange results into one 32-byte key.
//
// Concatenating the secrets and running them through HKDF binds the result to BOTH
// exchanges (hybrid security) and to the full transcript (the public keys and
// ciphertext), preventing an attacker from substituting their own keys.
func deriveSharedKey(classicalSecret, pqSecret, transcript []byte) ([]byte, error) {
	ikm := make([]byte, 0, len(classicalSecret)+len(pqSecret))
	ikm = append(ikm, classicalSecret...)
	ikm = append(ikm, pqSecret...)
	return hkdf.Key(sha256.New, ikm, pqKDFSalt, string(transcript), pqSharedKeySize)
}

// HybridPublicKey is a recipient's published "address": an ML-KEM public key plus
// an X25519 public key. Safe to publish anywhere.
type HybridPublicKey struct {
	MLKEMPublic   []byte
	X25519Public  []byte
}

// ToBytes serializes the public key for publishing/transport (PQPublicBundleSize bytes).
func (pk *HybridPublicKey) ToBytes() []byte {
	out := make([]byte, 0, PQPublicBundleSize)
	out = append(out, pk.MLKEMPublic...)
	out = append(out, pk.X25519Public...)
	return out
}

// HybridPublicKeyFromBytes parses a public key produced by ToBytes.
func HybridPublicKeyFromBytes(data []byte) (*HybridPublicKey, error) {
	if len(data) != PQPublicBundleSize {
		return nil, fmt.Errorf("%w: public bundle must be %d bytes, got %d",
			ErrInvalidPQKeySize, PQPublicBundleSize, len(data))
	}
	return &HybridPublicKey{
		MLKEMPublic:  append([]byte(nil), data[:mlkemPublicSize]...),
		X25519Public: append([]byte(nil), data[mlkemPublicSize:]...),
	}, nil
}

// HybridPrivateKey is a recipient's private key. Generate once, keep secret,
// publish the public key.
type HybridPrivateKey struct {
	mlkem   *mlkem.DecapsulationKey768
	x25519  *ecdh.PrivateKey
}

// GenerateHybridKey creates a fresh keypair using the system CSPRNG.
func GenerateHybridKey() (*HybridPrivateKey, error) {
	mlkemKey, err := mlkem.GenerateKey768()
	if err != nil {
		return nil, err
	}
	x25519Key, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	return &HybridPrivateKey{mlkem: mlkemKey, x25519: x25519Key}, nil
}

// ToBytes serializes the PRIVATE key for secure storage (PQPrivateKeySize bytes):
// ML-KEM-768 64-byte seed || X25519 32-byte scalar. Keep it secret.
func (sk *HybridPrivateKey) ToBytes() []byte {
	out := make([]byte, 0, PQPrivateKeySize)
	out = append(out, sk.mlkem.Bytes()...) // 64-byte FIPS 203 seed
	out = append(out, sk.x25519.Bytes()...)
	return out
}

// HybridPrivateKeyFromBytes restores a keypair produced by (*HybridPrivateKey).ToBytes.
func HybridPrivateKeyFromBytes(data []byte) (*HybridPrivateKey, error) {
	if len(data) != PQPrivateKeySize {
		return nil, fmt.Errorf("%w: private key must be %d bytes, got %d",
			ErrInvalidPQKeySize, PQPrivateKeySize, len(data))
	}
	mlkemKey, err := mlkem.NewDecapsulationKey768(data[:mlkemSeedSize])
	if err != nil {
		return nil, err
	}
	x25519Key, err := ecdh.X25519().NewPrivateKey(data[mlkemSeedSize:])
	if err != nil {
		return nil, err
	}
	return &HybridPrivateKey{mlkem: mlkemKey, x25519: x25519Key}, nil
}

// PublicKey returns the publishable public half of this keypair.
func (sk *HybridPrivateKey) PublicKey() *HybridPublicKey {
	return &HybridPublicKey{
		MLKEMPublic:  sk.mlkem.EncapsulationKey().Bytes(),
		X25519Public: sk.x25519.PublicKey().Bytes(),
	}
}

// Accept (recipient side) turns a sender's handshake into the shared 32-byte key.
func (sk *HybridPrivateKey) Accept(handshake []byte) ([]byte, error) {
	if len(handshake) != PQHandshakeSize {
		return nil, fmt.Errorf("%w: handshake must be %d bytes, got %d",
			ErrInvalidPQKeySize, PQHandshakeSize, len(handshake))
	}
	ephX25519Public := handshake[:x25519PublicSize]
	kemCiphertext := handshake[x25519PublicSize:]

	// ML-KEM: open the padlock to recover the post-quantum secret.
	pqSecret, err := sk.mlkem.Decapsulate(kemCiphertext)
	if err != nil {
		return nil, err
	}

	// X25519: classical Diffie-Hellman with the sender's ephemeral public key.
	ephPub, err := ecdh.X25519().NewPublicKey(ephX25519Public)
	if err != nil {
		return nil, err
	}
	classicalSecret, err := sk.x25519.ECDH(ephPub)
	if err != nil {
		return nil, err
	}

	myPublic := sk.PublicKey().ToBytes()
	transcript := make([]byte, 0, len(myPublic)+len(handshake))
	transcript = append(transcript, myPublic...)
	transcript = append(transcript, ephX25519Public...)
	transcript = append(transcript, kemCiphertext...)
	return deriveSharedKey(classicalSecret, pqSecret, transcript)
}

// InitiatePQ (sender side) derives a shared key for peer and the handshake to send.
// Returns (handshake, sharedKey, error): transmit handshake to the recipient (who
// passes it to Accept); use sharedKey with WithKey / QuickEncrypt.
func InitiatePQ(peer *HybridPublicKey) (handshake, sharedKey []byte, err error) {
	// ML-KEM: lock a fresh secret inside the recipient's public padlock.
	peerMLKEM, err := mlkem.NewEncapsulationKey768(peer.MLKEMPublic)
	if err != nil {
		return nil, nil, err
	}
	pqSecret, kemCiphertext := peerMLKEM.Encapsulate()

	// X25519: a one-time ("ephemeral") classical exchange against the peer's key.
	ephPriv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	ephX25519Public := ephPriv.PublicKey().Bytes()
	peerX25519, err := ecdh.X25519().NewPublicKey(peer.X25519Public)
	if err != nil {
		return nil, nil, err
	}
	classicalSecret, err := ephPriv.ECDH(peerX25519)
	if err != nil {
		return nil, nil, err
	}

	peerBundle := peer.ToBytes()
	transcript := make([]byte, 0, len(peerBundle)+x25519PublicSize+len(kemCiphertext))
	transcript = append(transcript, peerBundle...)
	transcript = append(transcript, ephX25519Public...)
	transcript = append(transcript, kemCiphertext...)

	sharedKey, err = deriveSharedKey(classicalSecret, pqSecret, transcript)
	if err != nil {
		return nil, nil, err
	}
	handshake = make([]byte, 0, PQHandshakeSize)
	handshake = append(handshake, ephX25519Public...)
	handshake = append(handshake, kemCiphertext...)
	return handshake, sharedKey, nil
}
