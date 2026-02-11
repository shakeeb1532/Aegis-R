//go:build !cgo

package compress

import "errors"

func Compress(_ []byte) ([]byte, error) {
	return nil, errors.New("lz4 compression requires cgo")
}

func Decompress(_ []byte) ([]byte, error) {
	return nil, errors.New("lz4 decompression requires cgo")
}
