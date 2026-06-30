package shield

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// TestPQHybridRoundtrip: a fresh exchange agrees on the same key, and that key
// decrypts a Shield message (the whole point).
func TestPQHybridRoundtrip(t *testing.T) {
	bob, err := GenerateHybridKey()
	if err != nil {
		t.Fatalf("GenerateHybridKey: %v", err)
	}
	handshake, aliceKey, err := InitiatePQ(bob.PublicKey())
	if err != nil {
		t.Fatalf("InitiatePQ: %v", err)
	}
	bobKey, err := bob.Accept(handshake)
	if err != nil {
		t.Fatalf("Accept: %v", err)
	}
	if !bytes.Equal(aliceKey, bobKey) {
		t.Fatalf("keys differ:\n alice %x\n bob   %x", aliceKey, bobKey)
	}

	// End-to-end with Shield pre-shared-key mode.
	msg := []byte("hello bob, quantum-safe from Go")
	ct, err := QuickEncrypt(aliceKey, msg)
	if err != nil {
		t.Fatalf("QuickEncrypt: %v", err)
	}
	pt, err := QuickDecrypt(bobKey, ct)
	if err != nil {
		t.Fatalf("QuickDecrypt: %v", err)
	}
	if !bytes.Equal(pt, msg) {
		t.Fatalf("decrypted %q != %q", pt, msg)
	}
}

// TestPQHybridSerializationRoundtrip: a restored private key behaves identically.
func TestPQHybridSerializationRoundtrip(t *testing.T) {
	bob, err := GenerateHybridKey()
	if err != nil {
		t.Fatal(err)
	}
	restored, err := HybridPrivateKeyFromBytes(bob.ToBytes())
	if err != nil {
		t.Fatalf("FromBytes: %v", err)
	}
	if !bytes.Equal(bob.PublicKey().ToBytes(), restored.PublicKey().ToBytes()) {
		t.Fatal("public key changed after serialization round-trip")
	}
	handshake, aliceKey, err := InitiatePQ(restored.PublicKey())
	if err != nil {
		t.Fatal(err)
	}
	bobKey, err := bob.Accept(handshake)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(aliceKey, bobKey) {
		t.Fatal("restored key failed a full exchange")
	}
}

// TestPQHybridCrossLanguageVectors: decrypt the Python-generated conformance
// vectors. This proves byte-identical interop of ML-KEM, X25519, and the KDF
// between the Go and Python bindings.
func TestPQHybridCrossLanguageVectors(t *testing.T) {
	path := filepath.Join("..", "..", "tests", "pq_kex_vectors.json")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read vectors: %v", err)
	}
	var doc struct {
		Vectors []struct {
			Name                 string `json:"name"`
			BobPrivateHex        string `json:"bob_private_hex"`
			BobPublicBundleHex   string `json:"bob_public_bundle_hex"`
			HandshakeHex         string `json:"handshake_hex"`
			ExpectedSharedKeyHex string `json:"expected_shared_key_hex"`
		} `json:"vectors"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatalf("parse vectors: %v", err)
	}
	if len(doc.Vectors) == 0 {
		t.Fatal("no vectors found")
	}
	for _, v := range doc.Vectors {
		t.Run(v.Name, func(t *testing.T) {
			bob, err := HybridPrivateKeyFromBytes(mustHex(t, v.BobPrivateHex))
			if err != nil {
				t.Fatalf("FromBytes: %v", err)
			}
			// Public bundle must match (confirms key encoding is identical).
			if got := bob.PublicKey().ToBytes(); !bytes.Equal(got, mustHex(t, v.BobPublicBundleHex)) {
				t.Fatalf("public bundle mismatch\n got %x", got)
			}
			// Accept the Python handshake and reproduce Python's shared key.
			key, err := bob.Accept(mustHex(t, v.HandshakeHex))
			if err != nil {
				t.Fatalf("Accept: %v", err)
			}
			if want := mustHex(t, v.ExpectedSharedKeyHex); !bytes.Equal(key, want) {
				t.Fatalf("shared key mismatch\n got  %x\n want %x", key, want)
			}
		})
	}
}

func TestPQHybridRejectsBadSizes(t *testing.T) {
	bob, _ := GenerateHybridKey()
	if _, err := bob.Accept(make([]byte, PQHandshakeSize-1)); err == nil {
		t.Fatal("expected error for short handshake")
	}
	if _, err := HybridPublicKeyFromBytes(make([]byte, PQPublicBundleSize-1)); err == nil {
		t.Fatal("expected error for short public bundle")
	}
	if _, err := HybridPrivateKeyFromBytes(make([]byte, PQPrivateKeySize-1)); err == nil {
		t.Fatal("expected error for short private key")
	}
}

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("bad hex: %v", err)
	}
	return b
}
