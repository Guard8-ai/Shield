package shield

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// v4Vector mirrors one entry in tests/v4_test_vectors.json.
type v4Vector struct {
	Name              string `json:"name"`
	Mode              string `json:"mode"`
	Suite             string `json:"suite"`
	Password          string `json:"password"`
	Service           string `json:"service"`
	Iterations        int    `json:"iterations"`
	SaltHex           string `json:"salt_hex"`
	KeyHex            string `json:"key_hex"`
	NonceHex          string `json:"nonce_hex"`
	TimestampMs       uint64 `json:"timestamp_ms"`
	PadLen            int    `json:"pad_len"`
	PaddingHex        string `json:"padding_hex"`
	PlaintextHex      string `json:"plaintext_hex"`
	MasterKeyHex      string `json:"master_key_hex"`
	AEADKeyHex        string `json:"aead_key_hex"`
	ExpectedOutputHex string `json:"expected_output_hex"`
}

type v4Doc struct {
	Deterministic        []v4Vector `json:"deterministic_vectors"`
	DeterministicChaCha  []v4Vector `json:"deterministic_vectors_chacha"`
}

func loadV4Vectors(t *testing.T) []v4Vector {
	t.Helper()
	path := filepath.Join("..", "..", "tests", "v4_test_vectors.json")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read vectors: %v", err)
	}
	var doc v4Doc
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatalf("parse vectors: %v", err)
	}
	return append(append([]v4Vector{}, doc.Deterministic...), doc.DeterministicChaCha...)
}

// masterFor recomputes the master key the same way the reference did.
func masterFor(t *testing.T, v v4Vector) []byte {
	t.Helper()
	if v.Mode == "password" {
		salt, _ := hex.DecodeString(v.SaltHex)
		maxAge := int64(0)
		s := newWithSalt(v.Password, v.Service, salt, v.Iterations, &maxAge)
		return s.DerivedKey()
	}
	key, _ := hex.DecodeString(v.KeyHex)
	return key
}

func suiteByte(v v4Vector) byte {
	if v.Suite == "0x02" {
		return SuiteChaCha20Poly1305
	}
	return SuiteAES256GCM
}

func TestV4VectorsKDF(t *testing.T) {
	for _, v := range loadV4Vectors(t) {
		master := masterFor(t, v)
		if got := hex.EncodeToString(master); got != v.MasterKeyHex {
			t.Errorf("%s: master key drift\n got %s\nwant %s", v.Name, got, v.MasterKeyHex)
		}
		aeadKey := deriveAEADKey(master)
		if got := hex.EncodeToString(aeadKey[:]); got != v.AEADKeyHex {
			t.Errorf("%s: aead key drift\n got %s\nwant %s", v.Name, got, v.AEADKeyHex)
		}
	}
}

func TestV4VectorsReproduceBytes(t *testing.T) {
	for _, v := range loadV4Vectors(t) {
		master := masterFor(t, v)
		aeadKey := deriveAEADKey(master)
		var salt []byte
		if v.Mode == "password" {
			salt, _ = hex.DecodeString(v.SaltHex)
		}
		nonce, _ := hex.DecodeString(v.NonceHex)
		padding, _ := hex.DecodeString(v.PaddingHex)
		plaintext, _ := hex.DecodeString(v.PlaintextHex)

		out, err := sealDeterministic(
			aeadKey[:], suiteByte(v), salt, nonce, v.TimestampMs, byte(v.PadLen), padding, plaintext,
		)
		if err != nil {
			t.Fatalf("%s: seal: %v", v.Name, err)
		}
		if got := hex.EncodeToString(out); got != v.ExpectedOutputHex {
			t.Errorf("%s: BYTE DRIFT\n got %s\nwant %s", v.Name, got, v.ExpectedOutputHex)
		}
	}
}

func TestV4VectorsDecrypt(t *testing.T) {
	for _, v := range loadV4Vectors(t) {
		master := masterFor(t, v)
		aeadKey := deriveAEADKey(master)
		encrypted, _ := hex.DecodeString(v.ExpectedOutputHex)
		aadLen := 2
		if v.Mode == "password" {
			aadLen = 2 + SaltSize
		}
		opened, err := open(aeadKey[:], suiteByte(v), encrypted, aadLen, nil)
		if err != nil {
			t.Fatalf("%s: open: %v", v.Name, err)
		}
		want, _ := hex.DecodeString(v.PlaintextHex)
		if !bytes.Equal(opened, want) {
			t.Errorf("%s: decrypt mismatch", v.Name)
		}
	}
}
