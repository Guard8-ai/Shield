package shield

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"strings"
	"time"
)

const (
	// DefaultTOTPDigits is the default number of TOTP digits.
	DefaultTOTPDigits = 6
	// DefaultTOTPInterval is the default TOTP interval in seconds.
	DefaultTOTPInterval = 30
	// DefaultSecretSize is the default TOTP secret size.
	DefaultSecretSize = 20
)

// TOTP generates and verifies time-based one-time passwords.
type TOTP struct {
	secret   []byte
	digits   int
	interval int64
}

// NewTOTP creates a new TOTP with the given secret.
func NewTOTP(secret []byte, digits, interval int) *TOTP {
	if digits <= 0 {
		digits = DefaultTOTPDigits
	}
	if interval <= 0 {
		interval = DefaultTOTPInterval
	}
	return &TOTP{
		secret:   secret,
		digits:   digits,
		interval: int64(interval),
	}
}

// GenerateSecret generates a random TOTP secret.
func GenerateSecret() ([]byte, error) {
	secret := make([]byte, DefaultSecretSize)
	if _, err := rand.Read(secret); err != nil {
		return nil, err
	}
	return secret, nil
}

// Generate generates a TOTP code for the given time.
// If t is zero, uses current time.
func (t *TOTP) Generate(timestamp int64) string {
	if timestamp == 0 {
		timestamp = time.Now().Unix()
	}
	counter := timestamp / t.interval
	return t.generateHOTP(uint64(counter))
}

// Verify verifies a TOTP code with time window.
func (t *TOTP) Verify(code string, timestamp int64, window int) bool {
	if timestamp == 0 {
		timestamp = time.Now().Unix()
	}
	if window <= 0 {
		window = 1
	}

	for i := 0; i <= window; i++ {
		// Check current and past
		checkTime := timestamp - int64(i)*t.interval
		if t.Generate(checkTime) == code {
			return true
		}
		// Check future (except for i=0)
		if i > 0 {
			checkTime = timestamp + int64(i)*t.interval
			if t.Generate(checkTime) == code {
				return true
			}
		}
	}
	return false
}

func (t *TOTP) generateHOTP(counter uint64) string {
	counterBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(counterBytes, counter)

	mac := hmac.New(sha1.New, t.secret)
	mac.Write(counterBytes)
	hash := mac.Sum(nil)

	// Dynamic truncation
	offset := hash[19] & 0x0f
	code := binary.BigEndian.Uint32(hash[offset:offset+4]) & 0x7fffffff

	modulo := uint32(1)
	for i := 0; i < t.digits; i++ {
		modulo *= 10
	}

	return fmt.Sprintf("%0*d", t.digits, code%modulo)
}

// SecretToBase32 encodes secret to base32.
func SecretToBase32(secret []byte) string {
	return base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(secret)
}

// SecretFromBase32 decodes secret from base32.
func SecretFromBase32(encoded string) ([]byte, error) {
	encoded = strings.ToUpper(strings.TrimRight(encoded, "="))
	return base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(encoded)
}

// ProvisioningURI generates an otpauth:// URI for QR codes.
func (t *TOTP) ProvisioningURI(account, issuer string) string {
	secret := SecretToBase32(t.secret)
	return fmt.Sprintf(
		"otpauth://totp/%s:%s?secret=%s&issuer=%s&algorithm=SHA1&digits=%d&period=%d",
		issuer, account, secret, issuer, t.digits, t.interval,
	)
}

// Secret returns the TOTP secret.
func (t *TOTP) Secret() []byte {
	return t.secret
}

// RecoveryCodes manages backup recovery codes.
type RecoveryCodes struct {
	codes map[string]bool
}

// NewRecoveryCodes generates new recovery codes.
func NewRecoveryCodes(count int) (*RecoveryCodes, error) {
	if count <= 0 {
		count = 10
	}

	codes := make(map[string]bool)
	for i := 0; i < count; i++ {
		code, err := generateRecoveryCode()
		if err != nil {
			return nil, err
		}
		codes[code] = true
	}

	return &RecoveryCodes{codes: codes}, nil
}

func generateRecoveryCode() (string, error) {
	bytes := make([]byte, 4)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return fmt.Sprintf("%04X-%04X",
		binary.BigEndian.Uint16(bytes[:2]),
		binary.BigEndian.Uint16(bytes[2:]),
	), nil
}

// Verify verifies and consumes a recovery code.
func (rc *RecoveryCodes) Verify(code string) bool {
	code = strings.ToUpper(strings.ReplaceAll(code, " ", ""))
	if len(code) == 8 {
		code = code[:4] + "-" + code[4:]
	}

	if rc.codes[code] {
		delete(rc.codes, code)
		return true
	}
	return false
}

// Codes returns all remaining codes.
func (rc *RecoveryCodes) Codes() []string {
	result := make([]string, 0, len(rc.codes))
	for code := range rc.codes {
		result = append(result, code)
	}
	return result
}

// Remaining returns the count of remaining codes.
func (rc *RecoveryCodes) Remaining() int {
	return len(rc.codes)
}
