package shield

import (
	"bytes"
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
