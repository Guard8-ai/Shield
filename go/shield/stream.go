package shield

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"io"

	"golang.org/x/crypto/pbkdf2"
)

const (
	// DefaultChunkSize is the default streaming chunk size.
	DefaultChunkSize = 64 * 1024
)

// StreamCipher provides streaming encryption for large data.
type StreamCipher struct {
	key       [KeySize]byte
	chunkSize int
}

// NewStreamCipher creates a new StreamCipher with the given key.
func NewStreamCipher(key []byte, chunkSize int) (*StreamCipher, error) {
	if len(key) != KeySize {
		return nil, ErrInvalidKeySize
	}
	if chunkSize <= 0 {
		chunkSize = DefaultChunkSize
	}
	sc := &StreamCipher{chunkSize: chunkSize}
	copy(sc.key[:], key)
	return sc, nil
}

// StreamCipherFromPassword creates a StreamCipher from password and salt.
func StreamCipherFromPassword(password string, salt []byte, chunkSize int) *StreamCipher {
	key := pbkdf2.Key([]byte(password), salt, Iterations, KeySize, sha256.New)
	if chunkSize <= 0 {
		chunkSize = DefaultChunkSize
	}
	sc := &StreamCipher{chunkSize: chunkSize}
	copy(sc.key[:], key)
	return sc
}

// Encrypt encrypts data in chunks.
func (sc *StreamCipher) Encrypt(plaintext []byte) ([]byte, error) {
	if len(plaintext) == 0 {
		return []byte{}, nil
	}

	var result []byte
	numChunks := (len(plaintext) + sc.chunkSize - 1) / sc.chunkSize

	// Write chunk count header
	header := make([]byte, 4)
	binary.LittleEndian.PutUint32(header, uint32(numChunks))
	result = append(result, header...)

	for i := 0; i < len(plaintext); i += sc.chunkSize {
		end := i + sc.chunkSize
		if end > len(plaintext) {
			end = len(plaintext)
		}
		chunk := plaintext[i:end]

		encryptedChunk, err := sc.encryptChunk(chunk)
		if err != nil {
			return nil, err
		}

		// Length prefix + encrypted chunk
		lenBuf := make([]byte, 4)
		binary.LittleEndian.PutUint32(lenBuf, uint32(len(encryptedChunk)))
		result = append(result, lenBuf...)
		result = append(result, encryptedChunk...)
	}

	return result, nil
}

// Decrypt decrypts chunked data.
func (sc *StreamCipher) Decrypt(ciphertext []byte) ([]byte, error) {
	if len(ciphertext) < 4 {
		return nil, ErrCiphertextTooShort
	}

	numChunks := binary.LittleEndian.Uint32(ciphertext[:4])
	offset := 4

	var result []byte
	for i := uint32(0); i < numChunks; i++ {
		if offset+4 > len(ciphertext) {
			return nil, ErrCiphertextTooShort
		}

		chunkLen := binary.LittleEndian.Uint32(ciphertext[offset : offset+4])
		offset += 4

		if offset+int(chunkLen) > len(ciphertext) {
			return nil, ErrCiphertextTooShort
		}

		chunk := ciphertext[offset : offset+int(chunkLen)]
		offset += int(chunkLen)

		decrypted, err := sc.decryptChunk(chunk)
		if err != nil {
			return nil, err
		}
		result = append(result, decrypted...)
	}

	return result, nil
}

func (sc *StreamCipher) encryptChunk(data []byte) ([]byte, error) {
	nonce := make([]byte, NonceSize)
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}

	keystream := generateKeystream(sc.key[:], nonce, len(data))
	ciphertext := make([]byte, len(data))
	for i := range data {
		ciphertext[i] = data[i] ^ keystream[i]
	}

	mac := hmac.New(sha256.New, sc.key[:])
	mac.Write(nonce)
	mac.Write(ciphertext)
	tag := mac.Sum(nil)[:MACSize]

	result := make([]byte, NonceSize+len(ciphertext)+MACSize)
	copy(result[:NonceSize], nonce)
	copy(result[NonceSize:NonceSize+len(ciphertext)], ciphertext)
	copy(result[NonceSize+len(ciphertext):], tag)

	return result, nil
}

func (sc *StreamCipher) decryptChunk(encrypted []byte) ([]byte, error) {
	if len(encrypted) < NonceSize+MACSize {
		return nil, ErrCiphertextTooShort
	}

	nonce := encrypted[:NonceSize]
	ciphertext := encrypted[NonceSize : len(encrypted)-MACSize]
	receivedMAC := encrypted[len(encrypted)-MACSize:]

	mac := hmac.New(sha256.New, sc.key[:])
	mac.Write(nonce)
	mac.Write(ciphertext)
	expectedMAC := mac.Sum(nil)[:MACSize]

	if subtle.ConstantTimeCompare(receivedMAC, expectedMAC) != 1 {
		return nil, ErrAuthenticationFailed
	}

	keystream := generateKeystream(sc.key[:], nonce, len(ciphertext))
	plaintext := make([]byte, len(ciphertext))
	for i := range ciphertext {
		plaintext[i] = ciphertext[i] ^ keystream[i]
	}

	return plaintext, nil
}

// EncryptReader encrypts data from a reader to a writer.
func (sc *StreamCipher) EncryptReader(r io.Reader, w io.Writer) error {
	data, err := io.ReadAll(r)
	if err != nil {
		return err
	}
	encrypted, err := sc.Encrypt(data)
	if err != nil {
		return err
	}
	_, err = w.Write(encrypted)
	return err
}

// DecryptReader decrypts data from a reader to a writer.
func (sc *StreamCipher) DecryptReader(r io.Reader, w io.Writer) error {
	data, err := io.ReadAll(r)
	if err != nil {
		return err
	}
	decrypted, err := sc.Decrypt(data)
	if err != nil {
		return err
	}
	_, err = w.Write(decrypted)
	return err
}
