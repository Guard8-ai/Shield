package shield

import (
	"bytes"
	"strings"
	"testing"
	"time"
)

// Core Shield tests
func TestShieldEncryptDecrypt(t *testing.T) {
	s := New("password123", "test-service")
	plaintext := []byte("Hello, Shield!")

	encrypted, err := s.Encrypt(plaintext)
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	decrypted, err := s.Decrypt(encrypted)
	if err != nil {
		t.Fatalf("Decrypt failed: %v", err)
	}

	if !bytes.Equal(plaintext, decrypted) {
		t.Errorf("Decrypted != plaintext")
	}
}

func TestShieldWithKey(t *testing.T) {
	key := make([]byte, KeySize)
	for i := range key {
		key[i] = byte(i)
	}

	s, err := WithKey(key)
	if err != nil {
		t.Fatalf("WithKey failed: %v", err)
	}

	plaintext := []byte("Test message")
	encrypted, err := s.Encrypt(plaintext)
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	decrypted, err := s.Decrypt(encrypted)
	if err != nil {
		t.Fatalf("Decrypt failed: %v", err)
	}

	if !bytes.Equal(plaintext, decrypted) {
		t.Errorf("Decrypted != plaintext")
	}
}

func TestQuickEncryptDecrypt(t *testing.T) {
	key := make([]byte, KeySize)
	plaintext := []byte("Quick test")

	encrypted, err := QuickEncrypt(key, plaintext)
	if err != nil {
		t.Fatalf("QuickEncrypt failed: %v", err)
	}

	decrypted, err := QuickDecrypt(key, encrypted)
	if err != nil {
		t.Fatalf("QuickDecrypt failed: %v", err)
	}

	if !bytes.Equal(plaintext, decrypted) {
		t.Errorf("Decrypted != plaintext")
	}
}

func TestInvalidKeySize(t *testing.T) {
	_, err := WithKey([]byte("short"))
	if err != ErrInvalidKeySize {
		t.Errorf("Expected ErrInvalidKeySize, got %v", err)
	}
}

func TestAuthenticationFailed(t *testing.T) {
	s := New("password", "service")
	encrypted, _ := s.Encrypt([]byte("test"))

	// Tamper with ciphertext
	encrypted[len(encrypted)-1] ^= 0xFF

	_, err := s.Decrypt(encrypted)
	if err != ErrAuthenticationFailed {
		t.Errorf("Expected ErrAuthenticationFailed, got %v", err)
	}
}

// Stream cipher tests
func TestStreamCipher(t *testing.T) {
	key := make([]byte, KeySize)
	sc, err := NewStreamCipher(key, 1024)
	if err != nil {
		t.Fatalf("NewStreamCipher failed: %v", err)
	}

	plaintext := make([]byte, 10000)
	for i := range plaintext {
		plaintext[i] = byte(i % 256)
	}

	encrypted, err := sc.Encrypt(plaintext)
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	decrypted, err := sc.Decrypt(encrypted)
	if err != nil {
		t.Fatalf("Decrypt failed: %v", err)
	}

	if !bytes.Equal(plaintext, decrypted) {
		t.Errorf("Decrypted != plaintext")
	}
}

func TestStreamCipherFromPassword(t *testing.T) {
	salt := []byte("test-salt")
	sc := StreamCipherFromPassword("password", salt, 0)

	plaintext := []byte("Stream test")
	encrypted, err := sc.Encrypt(plaintext)
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	decrypted, err := sc.Decrypt(encrypted)
	if err != nil {
		t.Fatalf("Decrypt failed: %v", err)
	}

	if !bytes.Equal(plaintext, decrypted) {
		t.Errorf("Decrypted != plaintext")
	}
}

// Ratchet session tests
func TestRatchetSession(t *testing.T) {
	rootKey := make([]byte, KeySize)

	alice, err := NewRatchetSession(rootKey, true)
	if err != nil {
		t.Fatalf("NewRatchetSession (alice) failed: %v", err)
	}

	bob, err := NewRatchetSession(rootKey, false)
	if err != nil {
		t.Fatalf("NewRatchetSession (bob) failed: %v", err)
	}

	// Alice sends to Bob
	msg1 := []byte("Hello Bob!")
	encrypted1, err := alice.Encrypt(msg1)
	if err != nil {
		t.Fatalf("Alice encrypt failed: %v", err)
	}

	decrypted1, err := bob.Decrypt(encrypted1)
	if err != nil {
		t.Fatalf("Bob decrypt failed: %v", err)
	}

	if !bytes.Equal(msg1, decrypted1) {
		t.Errorf("Bob received wrong message")
	}

	// Verify counters
	if alice.SendCounter() != 1 {
		t.Errorf("Alice send counter should be 1")
	}
	if bob.RecvCounter() != 1 {
		t.Errorf("Bob recv counter should be 1")
	}
}

func TestRatchetReplayProtection(t *testing.T) {
	rootKey := make([]byte, KeySize)

	alice, _ := NewRatchetSession(rootKey, true)
	bob, _ := NewRatchetSession(rootKey, false)

	encrypted, _ := alice.Encrypt([]byte("test"))
	bob.Decrypt(encrypted)

	// Try to replay
	_, err := bob.Decrypt(encrypted)
	if err != ErrReplayDetected {
		t.Errorf("Expected ErrReplayDetected, got %v", err)
	}
}

// TOTP tests
func TestTOTPGenerateVerify(t *testing.T) {
	secret, err := GenerateSecret()
	if err != nil {
		t.Fatalf("GenerateSecret failed: %v", err)
	}

	totp := NewTOTP(secret, 6, 30)

	now := time.Now().Unix()
	code := totp.Generate(now)

	if len(code) != 6 {
		t.Errorf("Code length should be 6, got %d", len(code))
	}

	if !totp.Verify(code, now, 1) {
		t.Errorf("TOTP verification failed")
	}
}

func TestTOTPBase32(t *testing.T) {
	secret := []byte("12345678901234567890")
	encoded := SecretToBase32(secret)

	decoded, err := SecretFromBase32(encoded)
	if err != nil {
		t.Fatalf("SecretFromBase32 failed: %v", err)
	}

	if !bytes.Equal(secret, decoded) {
		t.Errorf("Base32 round-trip failed")
	}
}

func TestProvisioningURI(t *testing.T) {
	secret := []byte("12345678901234567890")
	totp := NewTOTP(secret, 6, 30)

	uri := totp.ProvisioningURI("user@example.com", "MyService")

	if !strings.Contains(uri, "otpauth://totp/") {
		t.Errorf("URI should start with otpauth://totp/")
	}
	if !strings.Contains(uri, "MyService") {
		t.Errorf("URI should contain issuer")
	}
}

func TestRecoveryCodes(t *testing.T) {
	rc, err := NewRecoveryCodes(5)
	if err != nil {
		t.Fatalf("NewRecoveryCodes failed: %v", err)
	}

	if rc.Remaining() != 5 {
		t.Errorf("Should have 5 codes, got %d", rc.Remaining())
	}

	codes := rc.Codes()
	if len(codes) != 5 {
		t.Errorf("Should return 5 codes")
	}

	// Verify and consume a code
	if !rc.Verify(codes[0]) {
		t.Errorf("First code should verify")
	}

	if rc.Remaining() != 4 {
		t.Errorf("Should have 4 codes after using one")
	}

	// Same code shouldn't work twice
	if rc.Verify(codes[0]) {
		t.Errorf("Used code shouldn't verify again")
	}
}

// Signature tests
func TestSymmetricSignature(t *testing.T) {
	ss, err := GenerateSymmetricSignature()
	if err != nil {
		t.Fatalf("GenerateSymmetricSignature failed: %v", err)
	}

	message := []byte("Sign this message")
	signature := ss.Sign(message, false)

	if !ss.Verify(message, signature, ss.VerificationKey[:], 0) {
		t.Errorf("Signature verification failed")
	}
}

func TestSymmetricSignatureWithTimestamp(t *testing.T) {
	ss, err := GenerateSymmetricSignature()
	if err != nil {
		t.Fatalf("GenerateSymmetricSignature failed: %v", err)
	}

	message := []byte("Timestamped message")
	signature := ss.Sign(message, true)

	if len(signature) != 40 {
		t.Errorf("Timestamped signature should be 40 bytes")
	}

	if !ss.Verify(message, signature, ss.VerificationKey[:], 60) {
		t.Errorf("Timestamped signature verification failed")
	}
}

func TestSymmetricSignatureFromPassword(t *testing.T) {
	ss := SymmetricSignatureFromPassword("password", "user@example.com")

	message := []byte("Test message")
	signature := ss.Sign(message, false)

	if !ss.Verify(message, signature, ss.VerificationKey[:], 0) {
		t.Errorf("Password-derived signature verification failed")
	}
}

func TestLamportSignature(t *testing.T) {
	ls, err := GenerateLamportSignature()
	if err != nil {
		t.Fatalf("GenerateLamportSignature failed: %v", err)
	}

	message := []byte("Lamport signed message")
	signature, err := ls.Sign(message)
	if err != nil {
		t.Fatalf("Lamport sign failed: %v", err)
	}

	if !VerifyLamport(message, signature, ls.PublicKey) {
		t.Errorf("Lamport verification failed")
	}
}

func TestLamportOneTimeUse(t *testing.T) {
	ls, _ := GenerateLamportSignature()
	ls.Sign([]byte("first"))

	_, err := ls.Sign([]byte("second"))
	if err != ErrLamportKeyUsed {
		t.Errorf("Expected ErrLamportKeyUsed, got %v", err)
	}
}

// Exchange tests
func TestPAKEExchange(t *testing.T) {
	password := "shared-secret"
	identity := "channel-1"

	alice, err := NewPAKEExchange(password, identity)
	if err != nil {
		t.Fatalf("Alice PAKE failed: %v", err)
	}

	bob, err := NewPAKEExchange(password, identity)
	if err != nil {
		t.Fatalf("Bob PAKE failed: %v", err)
	}

	aliceKey := alice.DeriveKey(bob.PublicValue)
	bobKey := bob.DeriveKey(alice.PublicValue)

	if !bytes.Equal(aliceKey, bobKey) {
		t.Errorf("PAKE keys should match")
	}

	// Test proof verification
	aliceProof := alice.CreateProof(bob.PublicValue)
	if !bob.Verify(alice.PublicValue, aliceProof) {
		t.Errorf("Bob should verify Alice's proof")
	}
}

func TestQRExchange(t *testing.T) {
	initiator, err := NewQRExchange()
	if err != nil {
		t.Fatalf("NewQRExchange failed: %v", err)
	}

	responder, err := ScanQRExchange(initiator.Code)
	if err != nil {
		t.Fatalf("ScanQRExchange failed: %v", err)
	}

	response := responder.CreateResponse()
	if !initiator.VerifyResponse(response) {
		t.Errorf("QR response verification failed")
	}

	if !bytes.Equal(initiator.Key(), responder.Key()) {
		t.Errorf("QR exchange keys should match")
	}
}

func TestKeySplitter(t *testing.T) {
	ks := NewKeySplitter()
	key := make([]byte, KeySize)
	for i := range key {
		key[i] = byte(i)
	}

	shares, err := ks.Split(key, 3)
	if err != nil {
		t.Fatalf("Split failed: %v", err)
	}

	if len(shares) != 3 {
		t.Errorf("Should have 3 shares")
	}

	recovered, err := ks.Combine(shares)
	if err != nil {
		t.Fatalf("Combine failed: %v", err)
	}

	if !bytes.Equal(key, recovered) {
		t.Errorf("Recovered key doesn't match original")
	}
}

// Rotation tests
func TestKeyRotation(t *testing.T) {
	master := []byte("master-secret-key-32-bytes-long!")
	km := NewKeyRotationManager(master, 1) // 1 second rotation

	plaintext := []byte("Rotation test")

	encrypted1, err := km.Encrypt(plaintext)
	if err != nil {
		t.Fatalf("First encrypt failed: %v", err)
	}

	// Rotate
	km.Rotate()

	encrypted2, err := km.Encrypt(plaintext)
	if err != nil {
		t.Fatalf("Second encrypt failed: %v", err)
	}

	// Both should decrypt
	decrypted1, err := km.Decrypt(encrypted1)
	if err != nil {
		t.Fatalf("Decrypt v1 failed: %v", err)
	}

	decrypted2, err := km.Decrypt(encrypted2)
	if err != nil {
		t.Fatalf("Decrypt v2 failed: %v", err)
	}

	if !bytes.Equal(plaintext, decrypted1) || !bytes.Equal(plaintext, decrypted2) {
		t.Errorf("Decryption mismatch")
	}

	if km.Version() != 2 {
		t.Errorf("Version should be 2, got %d", km.Version())
	}
}

func TestReEncrypt(t *testing.T) {
	master := []byte("master-secret-key-32-bytes-long!")
	km := NewKeyRotationManager(master, 86400)

	plaintext := []byte("Re-encrypt test")
	encrypted, _ := km.Encrypt(plaintext)

	km.Rotate()

	reencrypted, err := km.ReEncrypt(encrypted)
	if err != nil {
		t.Fatalf("ReEncrypt failed: %v", err)
	}

	decrypted, _ := km.Decrypt(reencrypted)
	if !bytes.Equal(plaintext, decrypted) {
		t.Errorf("Re-encrypted decryption failed")
	}
}

// Group encryption tests
func TestGroupEncryption(t *testing.T) {
	aliceKey := make([]byte, KeySize)
	bobKey := make([]byte, KeySize)
	bobKey[0] = 1

	group, err := NewGroupEncryption("alice", aliceKey)
	if err != nil {
		t.Fatalf("NewGroupEncryption failed: %v", err)
	}

	encryptedGroupKey, err := group.AddMember("bob", bobKey)
	if err != nil {
		t.Fatalf("AddMember failed: %v", err)
	}

	bobGroup, err := JoinGroup("bob", bobKey, encryptedGroupKey)
	if err != nil {
		t.Fatalf("JoinGroup failed: %v", err)
	}

	message := []byte("Group message")
	encrypted, _ := group.Encrypt(message)
	decrypted, _ := bobGroup.Decrypt(encrypted)

	if !bytes.Equal(message, decrypted) {
		t.Errorf("Group decryption failed")
	}
}

func TestBroadcastEncryption(t *testing.T) {
	senderKey := make([]byte, KeySize)
	recipientKey := make([]byte, KeySize)
	recipientKey[0] = 1

	be, err := NewBroadcastEncryption(senderKey)
	if err != nil {
		t.Fatalf("NewBroadcastEncryption failed: %v", err)
	}

	be.AddRecipient("recipient1", recipientKey)

	message := []byte("Broadcast message")
	broadcast, err := be.Broadcast(message)
	if err != nil {
		t.Fatalf("Broadcast failed: %v", err)
	}

	decrypted, err := ReceiveBroadcast(broadcast, "recipient1", recipientKey)
	if err != nil {
		t.Fatalf("ReceiveBroadcast failed: %v", err)
	}

	if !bytes.Equal(message, decrypted) {
		t.Errorf("Broadcast decryption failed")
	}

	if !VerifySender(broadcast, senderKey) {
		t.Errorf("Sender verification failed")
	}
}

// Identity tests
func TestIdentityProvider(t *testing.T) {
	key := make([]byte, KeySize)
	ip, err := NewIdentityProvider(key, "test-issuer", 3600)
	if err != nil {
		t.Fatalf("NewIdentityProvider failed: %v", err)
	}

	claims := map[string]string{"role": "admin"}
	token := ip.IssueToken("user123", claims, 3600)

	subject, parsedClaims, err := ip.VerifyToken(token)
	if err != nil {
		t.Fatalf("VerifyToken failed: %v", err)
	}

	if subject != "user123" {
		t.Errorf("Subject mismatch: %s", subject)
	}

	if parsedClaims["role"] != "admin" {
		t.Errorf("Claims mismatch")
	}
}

func TestExpiredToken(t *testing.T) {
	key := make([]byte, KeySize)
	ip, _ := NewIdentityProvider(key, "test-issuer", 1)

	token := ip.IssueToken("user", nil, 1)

	time.Sleep(2 * time.Second)

	_, _, err := ip.VerifyToken(token)
	if err != ErrTokenExpired {
		t.Errorf("Expected ErrTokenExpired, got %v", err)
	}
}

func TestIdentity(t *testing.T) {
	identity := NewIdentity("user@example.com", "password123")

	challenge, _ := identity.CreateChallenge()
	response := identity.SignChallenge(challenge)

	if !identity.VerifyChallenge(challenge, response) {
		t.Errorf("Challenge verification failed")
	}
}

func TestSession(t *testing.T) {
	identity := NewIdentity("user@example.com", "password")
	session, err := NewSession(identity, 3600)
	if err != nil {
		t.Fatalf("NewSession failed: %v", err)
	}

	if session.IsExpired() {
		t.Errorf("New session shouldn't be expired")
	}

	plaintext := []byte("Session data")
	encrypted, _ := session.Encrypt(plaintext)
	decrypted, _ := session.Decrypt(encrypted)

	if !bytes.Equal(plaintext, decrypted) {
		t.Errorf("Session encryption failed")
	}
}

func TestSecureSession(t *testing.T) {
	identity := NewIdentity("user@example.com", "password")
	session, err := NewSecureSession(identity, 3600, 1)
	if err != nil {
		t.Fatalf("NewSecureSession failed: %v", err)
	}

	plaintext := []byte("Secure session data")
	encrypted1, _ := session.Encrypt(plaintext)

	session.ForceRotate()
	encrypted2, _ := session.Encrypt(plaintext)

	// Both should decrypt
	decrypted1, _ := session.Decrypt(encrypted1)
	decrypted2, _ := session.Decrypt(encrypted2)

	if !bytes.Equal(plaintext, decrypted1) || !bytes.Equal(plaintext, decrypted2) {
		t.Errorf("Secure session decryption failed")
	}
}

// Fingerprint tests
func TestFingerprints(t *testing.T) {
	// Shield fingerprint
	s := New("password", "service")
	// Just verify key exists
	if len(s.Key()) != KeySize {
		t.Errorf("Key should be %d bytes", KeySize)
	}

	// Symmetric signature fingerprint
	ss, _ := GenerateSymmetricSignature()
	fp := ss.Fingerprint()
	if len(fp) != 16 {
		t.Errorf("Fingerprint should be 16 hex chars, got %d", len(fp))
	}

	// Lamport fingerprint
	ls, _ := GenerateLamportSignature()
	fp = ls.Fingerprint()
	if len(fp) != 16 {
		t.Errorf("Lamport fingerprint should be 16 hex chars, got %d", len(fp))
	}

	// Rotation manager fingerprint
	km := NewKeyRotationManager(make([]byte, KeySize), 86400)
	fp = km.Fingerprint()
	if len(fp) != 16 {
		t.Errorf("Rotation fingerprint should be 16 hex chars, got %d", len(fp))
	}

	// Group fingerprint
	ge, _ := NewGroupEncryption("test", make([]byte, KeySize))
	fp = ge.Fingerprint()
	if len(fp) != 16 {
		t.Errorf("Group fingerprint should be 16 hex chars, got %d", len(fp))
	}

	// Identity fingerprint
	identity := NewIdentity("test", "password")
	fp = identity.Fingerprint()
	if len(fp) != 16 {
		t.Errorf("Identity fingerprint should be 16 hex chars, got %d", len(fp))
	}
}
