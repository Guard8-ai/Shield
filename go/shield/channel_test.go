package shield

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// TestSessionKeyDependsOnService verifies that the channel session key is bound
// to the service identifier: the same password/salt/contributions under two
// different services must derive two different session keys, so a shared secret
// provisioned for one service cannot establish a channel for another.
func TestSessionKeyDependsOnService(t *testing.T) {
	salt := bytes.Repeat([]byte{0x07}, 16)
	contribution := bytes.Repeat([]byte{0x09}, 32)

	ch := &ShieldChannel{}
	keyA := ch.computeSessionKey(NewChannelConfig("same-password", "service-a"), salt, contribution, contribution)
	keyB := ch.computeSessionKey(NewChannelConfig("same-password", "service-b"), salt, contribution, contribution)

	if bytes.Equal(keyA, keyB) {
		t.Fatal("session key must be bound to the service identifier")
	}
}

// TestChannelSessionConformanceVectors reproduces the shared cross-language
// session-key vectors byte-for-byte. Rust (shield-core) is the source of truth;
// Go/JS/Python/Android all read tests/channel_session_vectors.json and must
// match. Anchors PAKEDerive/PAKECombine + the session mix against divergence.
func TestChannelSessionConformanceVectors(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "tests", "channel_session_vectors.json"))
	if err != nil {
		t.Fatalf("read vectors: %v", err)
	}
	var doc struct {
		Vectors []struct {
			Name        string `json:"name"`
			Password    string `json:"password"`
			SaltHex     string `json:"salt_hex"`
			Service     string `json:"service"`
			Iterations  int    `json:"iterations"`
			LocalHex    string `json:"local_contribution_hex"`
			RemoteHex   string `json:"remote_contribution_hex"`
			ExpectedHex string `json:"expected_session_key_hex"`
		} `json:"vectors"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("parse vectors: %v", err)
	}

	for _, v := range doc.Vectors {
		cfg := NewChannelConfig(v.Password, v.Service)
		cfg.Iterations = v.Iterations
		salt, _ := hex.DecodeString(v.SaltHex)
		local, _ := hex.DecodeString(v.LocalHex)
		remote, _ := hex.DecodeString(v.RemoteHex)

		ch := &ShieldChannel{}
		got := hex.EncodeToString(ch.computeSessionKey(cfg, salt, local, remote))
		if got != v.ExpectedHex {
			t.Errorf("%s: got %s want %s", v.Name, got, v.ExpectedHex)
		}
	}
}
