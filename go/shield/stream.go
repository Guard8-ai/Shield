package shield

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"io"

	"golang.org/x/crypto/pbkdf2"
)

const (
	// DefaultChunkSize is the default streaming chunk size.
	DefaultChunkSize = 64 * 1024

	// streamSaltSize is the size of the per-stream salt in the header.
	streamSaltSize = 16
	// eofTagSize is the size of the authenticated end-of-stream tag.
	eofTagSize = 32
	// eofLabel is the domain-separation label for the end-of-stream key.
	eofLabel = "shield-stream-eof"
)

// ErrStreamTruncated indicates a stream that is missing its authenticated
// end-of-stream marker (the trailing chunks and/or the end-of-stream tag were
// dropped), which signals truncation.
var ErrStreamTruncated = errors.New("shield: stream truncated: missing end-of-stream marker")

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
//
// Wire format:
//
//	header: chunk_size(u32 LE, 4) || stream_salt(16)
//	frame:  chunk_len(u32 LE, 4) || nonce(16) || ciphertext || mac(16)   (repeated)
//	trailer: u32 LE 0 || eof_tag(32)
//
// The trailer is an authenticated, length-committing end-of-stream marker, so a
// stream truncated at a chunk boundary (with or without a re-appended bare zero
// marker) is detected on decrypt.
func (sc *StreamCipher) Encrypt(plaintext []byte) ([]byte, error) {
	// Header: chunk_size(4 LE) || stream_salt(16)
	streamSalt := make([]byte, streamSaltSize)
	if _, err := rand.Read(streamSalt); err != nil {
		return nil, err
	}

	result := make([]byte, 0, 20+len(plaintext))
	header := make([]byte, 20)
	binary.LittleEndian.PutUint32(header[:4], uint32(sc.chunkSize))
	copy(header[4:], streamSalt)
	result = append(result, header...)

	var chunkNum uint64
	for i := 0; i < len(plaintext); i += sc.chunkSize {
		end := i + sc.chunkSize
		if end > len(plaintext) {
			end = len(plaintext)
		}
		chunk := plaintext[i:end]

		chunkKey := sc.deriveChunkKey(streamSalt, chunkNum)
		encryptedChunk, err := encryptChunk(chunkKey, chunk)
		if err != nil {
			return nil, err
		}

		// Length prefix + encrypted chunk
		lenBuf := make([]byte, 4)
		binary.LittleEndian.PutUint32(lenBuf, uint32(len(encryptedChunk)))
		result = append(result, lenBuf...)
		result = append(result, encryptedChunk...)
		chunkNum++
	}

	// Authenticated end-of-stream trailer: zero marker || eof_tag.
	eofTag := computeEofTag(sc.key[:], streamSalt, chunkNum)
	result = append(result, 0, 0, 0, 0)
	result = append(result, eofTag...)

	return result, nil
}

// Decrypt decrypts chunked data, requiring the authenticated end-of-stream tag.
func (sc *StreamCipher) Decrypt(ciphertext []byte) ([]byte, error) {
	if len(ciphertext) < 20 {
		return nil, ErrCiphertextTooShort
	}

	streamSalt := ciphertext[4:20]
	offset := 20
	var chunkNum uint64
	sawEndMarker := false

	var result []byte
	for offset+4 <= len(ciphertext) {
		chunkLen := binary.LittleEndian.Uint32(ciphertext[offset : offset+4])

		if chunkLen == 0 {
			// Authenticated end-of-stream marker: require the 32-byte tag.
			if offset+4+eofTagSize > len(ciphertext) {
				return nil, ErrStreamTruncated
			}
			tag := ciphertext[offset+4 : offset+4+eofTagSize]
			expected := computeEofTag(sc.key[:], streamSalt, chunkNum)
			if subtle.ConstantTimeCompare(tag, expected) != 1 {
				return nil, ErrAuthenticationFailed
			}
			sawEndMarker = true
			break
		}

		offset += 4
		if offset+int(chunkLen) > len(ciphertext) {
			return nil, ErrCiphertextTooShort
		}

		chunk := ciphertext[offset : offset+int(chunkLen)]
		offset += int(chunkLen)

		chunkKey := sc.deriveChunkKey(streamSalt, chunkNum)
		decrypted, err := decryptChunk(chunkKey, chunk)
		if err != nil {
			return nil, err
		}
		result = append(result, decrypted...)
		chunkNum++
	}

	// A stream that ends without the authenticated marker has been truncated.
	if !sawEndMarker {
		return nil, ErrStreamTruncated
	}

	return result, nil
}

// deriveChunkKey derives the per-chunk key from the master key, stream salt and
// chunk number: SHA256(key || stream_salt || chunk_num as u64 LE).
func (sc *StreamCipher) deriveChunkKey(streamSalt []byte, chunkNum uint64) []byte {
	h := sha256.New()
	h.Write(sc.key[:])
	h.Write(streamSalt)
	var numBuf [8]byte
	binary.LittleEndian.PutUint64(numBuf[:], chunkNum)
	h.Write(numBuf[:])
	return h.Sum(nil)
}

// computeEofTag computes the authenticated end-of-stream tag.
//
//	eof_key = HMAC_SHA256(master_key, "shield-stream-eof")
//	eof_tag = HMAC_SHA256(eof_key, stream_salt || chunk_count as u64 LE)
//
// The tag commits to the stream salt and total chunk count (a length
// commitment); an attacker cannot forge a matching tag without the master key,
// so truncation -- including re-appending a bare zero marker -- is detected.
func computeEofTag(masterKey, streamSalt []byte, chunkCount uint64) []byte {
	ek := hmac.New(sha256.New, masterKey)
	ek.Write([]byte(eofLabel))
	eofKey := ek.Sum(nil)

	t := hmac.New(sha256.New, eofKey)
	t.Write(streamSalt)
	var countBuf [8]byte
	binary.LittleEndian.PutUint64(countBuf[:], chunkCount)
	t.Write(countBuf[:])
	return t.Sum(nil)
}

func encryptChunk(key, data []byte) ([]byte, error) {
	nonce := make([]byte, NonceSize)
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}

	keystream := generateKeystream(key, nonce, len(data))
	ciphertext := make([]byte, len(data))
	for i := range data {
		ciphertext[i] = data[i] ^ keystream[i]
	}

	mac := hmac.New(sha256.New, key)
	mac.Write(nonce)
	mac.Write(ciphertext)
	tag := mac.Sum(nil)[:MACSize]

	result := make([]byte, NonceSize+len(ciphertext)+MACSize)
	copy(result[:NonceSize], nonce)
	copy(result[NonceSize:NonceSize+len(ciphertext)], ciphertext)
	copy(result[NonceSize+len(ciphertext):], tag)

	return result, nil
}

func decryptChunk(key, encrypted []byte) ([]byte, error) {
	if len(encrypted) < NonceSize+MACSize {
		return nil, ErrCiphertextTooShort
	}

	nonce := encrypted[:NonceSize]
	ciphertext := encrypted[NonceSize : len(encrypted)-MACSize]
	receivedMAC := encrypted[len(encrypted)-MACSize:]

	mac := hmac.New(sha256.New, key)
	mac.Write(nonce)
	mac.Write(ciphertext)
	expectedMAC := mac.Sum(nil)[:MACSize]

	if subtle.ConstantTimeCompare(receivedMAC, expectedMAC) != 1 {
		return nil, ErrAuthenticationFailed
	}

	keystream := generateKeystream(key, nonce, len(ciphertext))
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
