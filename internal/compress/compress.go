package compress

/*
#cgo CFLAGS: -O3
#include "lz4.h"
*/
import "C"

import (
	"encoding/binary"
	"errors"
	"unsafe"
)

const headerSize = 4

func Compress(data []byte) ([]byte, error) {
	if len(data) == 0 {
		return []byte{}, nil
	}
	max := int(C.LZ4_compressBound(C.int(len(data))))
	buf := make([]byte, headerSize+max)
	binary.LittleEndian.PutUint32(buf[:headerSize], uint32(len(data)))
	out := C.LZ4_compress_default(
		(*C.char)(unsafe.Pointer(&data[0])),
		(*C.char)(unsafe.Pointer(&buf[headerSize])),
		C.int(len(data)),
		C.int(max),
	)
	if out <= 0 {
		return nil, errors.New("lz4 compression failed")
	}
	return buf[:headerSize+int(out)], nil
}

func Decompress(data []byte) ([]byte, error) {
	if len(data) == 0 {
		return []byte{}, nil
	}
	if len(data) < headerSize {
		return nil, errors.New("lz4 data too small")
	}
	orig := int(binary.LittleEndian.Uint32(data[:headerSize]))
	if orig <= 0 {
		return nil, errors.New("lz4 invalid original size")
	}
	outBuf := make([]byte, orig)
	res := C.LZ4_decompress_safe(
		(*C.char)(unsafe.Pointer(&data[headerSize])),
		(*C.char)(unsafe.Pointer(&outBuf[0])),
		C.int(len(data)-headerSize),
		C.int(orig),
	)
	if res < 0 {
		return nil, errors.New("lz4 decompression failed")
	}
	return outBuf, nil
}
