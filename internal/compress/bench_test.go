//go:build cgo

package compress

import (
	"bytes"
	"testing"
)

func makeData(size int, pattern []byte) []byte {
	buf := bytes.Repeat(pattern, size/len(pattern)+1)
	return buf[:size]
}

func BenchmarkCompressText1MB(b *testing.B) {
	data := makeData(1<<20, []byte("{\"a\":1,\"b\":\"test\"}\n"))
	b.SetBytes(int64(len(data)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		out, err := Compress(data)
		if err != nil {
			b.Fatal(err)
		}
		_ = out
	}
}

func BenchmarkDecompressText1MB(b *testing.B) {
	data := makeData(1<<20, []byte("{\"a\":1,\"b\":\"test\"}\n"))
	compressed, err := Compress(data)
	if err != nil {
		b.Fatal(err)
	}
	b.SetBytes(int64(len(data)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		out, err := Decompress(compressed)
		if err != nil {
			b.Fatal(err)
		}
		_ = out
	}
}
