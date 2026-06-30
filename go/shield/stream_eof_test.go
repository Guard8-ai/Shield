package shield

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"testing"
)

const eofGoldenHex = "52d4dfbeccc364bd69a2f232aa460bd1eb79b0c93903f344dd7b937703918431"

// TestEOFTagConformanceVector checks the authenticated end-of-stream tag against
// the cross-language golden vector:
//
//	master_key  = 32 x 0x42
//	stream_salt = 16 x 0x01
//	chunk_count = 3
func TestEOFTagConformanceVector(t *testing.T) {
	masterKey := bytes.Repeat([]byte{0x42}, 32)
	streamSalt := bytes.Repeat([]byte{0x01}, 16)

	got := hex.EncodeToString(computeEofTag(masterKey, streamSalt, 3))
	if got != eofGoldenHex {
		t.Fatalf("eof_tag mismatch:\n got  %s\n want %s", got, eofGoldenHex)
	}
}

// TestStreamTruncationRejected verifies that dropping trailing chunks and the
// authenticated trailer is rejected.
func TestStreamTruncationRejected(t *testing.T) {
	key := make([]byte, KeySize)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	sc, err := NewStreamCipher(key, 16)
	if err != nil {
		t.Fatal(err)
	}

	data := make([]byte, 64) // 4 chunks of 16 bytes
	if _, err := rand.Read(data); err != nil {
		t.Fatal(err)
	}
	encrypted, err := sc.Encrypt(data)
	if err != nil {
		t.Fatal(err)
	}

	// Header (20) + framed chunk (4 + 48 = 52) per chunk. Keep header + first
	// two chunk frames, drop the rest and the trailer.
	truncated := encrypted[:20+2*52]
	if len(truncated) >= len(encrypted) {
		t.Fatalf("truncated slice not shorter than original")
	}

	if _, err := sc.Decrypt(truncated); err == nil {
		t.Fatal("expected decrypt of truncated stream to fail")
	}
}

// TestStreamForgedMarkerRejected verifies that re-appending a bare zero marker
// (without a valid end-of-stream tag) is rejected.
func TestStreamForgedMarkerRejected(t *testing.T) {
	key := make([]byte, KeySize)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	sc, err := NewStreamCipher(key, 16)
	if err != nil {
		t.Fatal(err)
	}

	data := make([]byte, 64)
	if _, err := rand.Read(data); err != nil {
		t.Fatal(err)
	}
	encrypted, err := sc.Encrypt(data)
	if err != nil {
		t.Fatal(err)
	}

	forged := make([]byte, 0)
	forged = append(forged, encrypted[:20+2*52]...)
	forged = append(forged, 0, 0, 0, 0) // bare marker, no tag

	if _, err := sc.Decrypt(forged); err == nil {
		t.Fatal("expected decrypt of forged-marker stream to fail")
	}
}
