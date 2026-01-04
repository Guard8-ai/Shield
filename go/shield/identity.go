package shield

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"strings"
	"time"

	"golang.org/x/crypto/pbkdf2"
)

var (
	// ErrInvalidToken indicates token is invalid.
	ErrInvalidToken = errors.New("shield: invalid token")
	// ErrTokenExpired indicates token has expired.
	ErrTokenExpired = errors.New("shield: token expired")
	// ErrSessionExpired indicates session has expired.
	ErrSessionExpired = errors.New("shield: session expired")
)

// IdentityProvider provides SSO-like identity tokens.
type IdentityProvider struct {
	signingKey [KeySize]byte
	issuer     string
	defaultTTL int64
}

// NewIdentityProvider creates a new identity provider.
func NewIdentityProvider(signingKey []byte, issuer string, defaultTTLSeconds int64) (*IdentityProvider, error) {
	if len(signingKey) != KeySize {
		return nil, ErrInvalidKeySize
	}
	if defaultTTLSeconds <= 0 {
		defaultTTLSeconds = 3600 // 1 hour default
	}

	ip := &IdentityProvider{
		issuer:     issuer,
		defaultTTL: defaultTTLSeconds,
	}
	copy(ip.signingKey[:], signingKey)

	return ip, nil
}

// IssueToken issues an identity token for a subject.
func (ip *IdentityProvider) IssueToken(subject string, claims map[string]string, ttlSeconds int64) string {
	if ttlSeconds <= 0 {
		ttlSeconds = ip.defaultTTL
	}

	now := time.Now().Unix()
	exp := now + ttlSeconds

	// Build claims string
	var claimsBuilder strings.Builder
	claimsBuilder.WriteString("iss:")
	claimsBuilder.WriteString(ip.issuer)
	claimsBuilder.WriteString("|sub:")
	claimsBuilder.WriteString(subject)
	claimsBuilder.WriteString("|iat:")
	claimsBuilder.WriteString(string(rune(now)))
	claimsBuilder.WriteString("|exp:")
	claimsBuilder.WriteString(string(rune(exp)))

	if claims != nil {
		for k, v := range claims {
			claimsBuilder.WriteString("|")
			claimsBuilder.WriteString(k)
			claimsBuilder.WriteString(":")
			claimsBuilder.WriteString(v)
		}
	}

	// Encode claims properly
	payload := make([]byte, 8+8+len(subject))
	binary.LittleEndian.PutUint64(payload[:8], uint64(now))
	binary.LittleEndian.PutUint64(payload[8:16], uint64(exp))
	copy(payload[16:], subject)

	// Add custom claims
	for k, v := range claims {
		payload = append(payload, []byte("|"+k+":"+v)...)
	}

	// Sign
	mac := hmac.New(sha256.New, ip.signingKey[:])
	mac.Write([]byte(ip.issuer))
	mac.Write(payload)
	sig := mac.Sum(nil)

	// Format: base64(payload) . base64(sig)
	token := base64.RawURLEncoding.EncodeToString(payload) + "." +
		base64.RawURLEncoding.EncodeToString(sig)

	return token
}

// VerifyToken verifies and decodes a token.
func (ip *IdentityProvider) VerifyToken(token string) (subject string, claims map[string]string, err error) {
	parts := strings.Split(token, ".")
	if len(parts) != 2 {
		return "", nil, ErrInvalidToken
	}

	payload, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return "", nil, ErrInvalidToken
	}

	sig, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return "", nil, ErrInvalidToken
	}

	if len(payload) < 16 {
		return "", nil, ErrInvalidToken
	}

	// Verify signature
	mac := hmac.New(sha256.New, ip.signingKey[:])
	mac.Write([]byte(ip.issuer))
	mac.Write(payload)
	expected := mac.Sum(nil)

	if subtle.ConstantTimeCompare(sig, expected) != 1 {
		return "", nil, ErrInvalidToken
	}

	// Parse payload
	// iat := int64(binary.LittleEndian.Uint64(payload[:8]))
	exp := int64(binary.LittleEndian.Uint64(payload[8:16]))

	// Check expiration
	if time.Now().Unix() > exp {
		return "", nil, ErrTokenExpired
	}

	// Extract subject and claims
	rest := string(payload[16:])
	parts2 := strings.Split(rest, "|")
	subject = parts2[0]

	claims = make(map[string]string)
	for _, part := range parts2[1:] {
		kv := strings.SplitN(part, ":", 2)
		if len(kv) == 2 {
			claims[kv[0]] = kv[1]
		}
	}

	return subject, claims, nil
}

// RevokeToken marks a token as revoked (returns revocation ID).
// Note: Actual revocation requires external storage.
func (ip *IdentityProvider) RevokeToken(token string) string {
	h := sha256.Sum256([]byte(token))
	return hex.EncodeToString(h[:16])
}

// Identity represents a user identity.
type Identity struct {
	ID          string
	key         [KeySize]byte
	displayName string
	metadata    map[string]string
}

// NewIdentity creates a new identity.
func NewIdentity(id, password string) *Identity {
	salt := sha256.Sum256([]byte("identity:" + id))
	key := pbkdf2.Key([]byte(password), salt[:], 100000, KeySize, sha256.New)

	identity := &Identity{
		ID:       id,
		metadata: make(map[string]string),
	}
	copy(identity.key[:], key)

	return identity
}

// SetDisplayName sets the display name.
func (i *Identity) SetDisplayName(name string) {
	i.displayName = name
}

// DisplayName returns the display name.
func (i *Identity) DisplayName() string {
	return i.displayName
}

// SetMetadata sets a metadata value.
func (i *Identity) SetMetadata(key, value string) {
	i.metadata[key] = value
}

// GetMetadata gets a metadata value.
func (i *Identity) GetMetadata(key string) string {
	return i.metadata[key]
}

// CreateChallenge creates an authentication challenge.
func (i *Identity) CreateChallenge() ([]byte, error) {
	challenge := make([]byte, 32)
	if _, err := rand.Read(challenge); err != nil {
		return nil, err
	}
	return challenge, nil
}

// SignChallenge signs an authentication challenge.
func (i *Identity) SignChallenge(challenge []byte) []byte {
	mac := hmac.New(sha256.New, i.key[:])
	mac.Write(challenge)
	return mac.Sum(nil)
}

// VerifyChallenge verifies a challenge response.
func (i *Identity) VerifyChallenge(challenge, response []byte) bool {
	expected := i.SignChallenge(challenge)
	return subtle.ConstantTimeCompare(response, expected) == 1
}

// Fingerprint returns the identity fingerprint.
func (i *Identity) Fingerprint() string {
	h := sha256.Sum256(i.key[:])
	return hex.EncodeToString(h[:8])
}

// Key returns the identity key.
func (i *Identity) Key() []byte {
	return i.key[:]
}

// Session represents a user session.
type Session struct {
	ID        string
	IdentityID string
	key       [KeySize]byte
	createdAt int64
	expiresAt int64
	metadata  map[string]string
}

// NewSession creates a new session for an identity.
func NewSession(identity *Identity, ttlSeconds int64) (*Session, error) {
	if ttlSeconds <= 0 {
		ttlSeconds = 3600 // 1 hour default
	}

	sessionID := make([]byte, 16)
	if _, err := rand.Read(sessionID); err != nil {
		return nil, err
	}

	now := time.Now().Unix()

	// Derive session key from identity key and session ID
	h := sha256.New()
	h.Write(identity.key[:])
	h.Write(sessionID)
	h.Write([]byte("session"))

	session := &Session{
		ID:        hex.EncodeToString(sessionID),
		IdentityID: identity.ID,
		createdAt: now,
		expiresAt: now + ttlSeconds,
		metadata:  make(map[string]string),
	}
	copy(session.key[:], h.Sum(nil))

	return session, nil
}

// IsExpired checks if the session is expired.
func (s *Session) IsExpired() bool {
	return time.Now().Unix() > s.expiresAt
}

// Refresh extends the session expiration.
func (s *Session) Refresh(ttlSeconds int64) {
	s.expiresAt = time.Now().Unix() + ttlSeconds
}

// Encrypt encrypts data for this session.
func (s *Session) Encrypt(plaintext []byte) ([]byte, error) {
	if s.IsExpired() {
		return nil, ErrSessionExpired
	}
	return EncryptWithKey(s.key[:], plaintext)
}

// Decrypt decrypts data for this session.
func (s *Session) Decrypt(ciphertext []byte) ([]byte, error) {
	if s.IsExpired() {
		return nil, ErrSessionExpired
	}
	return DecryptWithKey(s.key[:], ciphertext)
}

// Key returns the session key.
func (s *Session) Key() []byte {
	return s.key[:]
}

// SetMetadata sets a session metadata value.
func (s *Session) SetMetadata(key, value string) {
	s.metadata[key] = value
}

// GetMetadata gets a session metadata value.
func (s *Session) GetMetadata(key string) string {
	return s.metadata[key]
}

// SecureSession provides encrypted session with rotation.
type SecureSession struct {
	*Session
	rotationManager *KeyRotationManager
}

// NewSecureSession creates a session with key rotation.
func NewSecureSession(identity *Identity, ttlSeconds, rotationSeconds int64) (*SecureSession, error) {
	session, err := NewSession(identity, ttlSeconds)
	if err != nil {
		return nil, err
	}

	if rotationSeconds <= 0 {
		rotationSeconds = 300 // 5 minutes default
	}

	return &SecureSession{
		Session:         session,
		rotationManager: NewKeyRotationManager(session.key[:], rotationSeconds),
	}, nil
}

// Encrypt encrypts with automatic key rotation.
func (ss *SecureSession) Encrypt(plaintext []byte) ([]byte, error) {
	if ss.IsExpired() {
		return nil, ErrSessionExpired
	}
	ss.rotationManager.AutoRotate()
	return ss.rotationManager.Encrypt(plaintext)
}

// Decrypt decrypts with automatic version selection.
func (ss *SecureSession) Decrypt(ciphertext []byte) ([]byte, error) {
	if ss.IsExpired() {
		return nil, ErrSessionExpired
	}
	return ss.rotationManager.Decrypt(ciphertext)
}

// ForceRotate forces key rotation.
func (ss *SecureSession) ForceRotate() {
	ss.rotationManager.Rotate()
}

// KeyVersion returns the current key version.
func (ss *SecureSession) KeyVersion() uint32 {
	return ss.rotationManager.Version()
}
