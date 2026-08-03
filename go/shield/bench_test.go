package shield

import (
	"fmt"
	"testing"
)

// Benchmarks for the v4 Shield Go binding.
// Run: go test -bench=. -run=^$ -benchtime=1s ./shield/

const (
	benchKB = 1024
	benchMB = 1024 * benchKB
)

var benchSizes = []int{64, 256, benchKB, 16 * benchKB, 64 * benchKB, benchMB}

func benchData(size int) []byte {
	d := make([]byte, size)
	for i := range d {
		d[i] = byte(i % 256)
	}
	return d
}

func BenchmarkEncrypt(b *testing.B) {
	s := New("benchmark_password", "benchmark.service", nil)
	for _, size := range benchSizes {
		data := benchData(size)
		b.Run(fmt.Sprintf("%dB", size), func(b *testing.B) {
			b.SetBytes(int64(size))
			for i := 0; i < b.N; i++ {
				if _, err := s.Encrypt(data); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func BenchmarkDecrypt(b *testing.B) {
	s := New("benchmark_password", "benchmark.service", nil)
	for _, size := range benchSizes {
		data := benchData(size)
		ct, err := s.Encrypt(data)
		if err != nil {
			b.Fatal(err)
		}
		b.Run(fmt.Sprintf("%dB", size), func(b *testing.B) {
			b.SetBytes(int64(size))
			for i := 0; i < b.N; i++ {
				if _, err := s.Decrypt(ct); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func BenchmarkKeyDerivation(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_ = New("benchmark_password", "benchmark.service", nil)
	}
}
