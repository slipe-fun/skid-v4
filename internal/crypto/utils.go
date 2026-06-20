package crypto

import (
	"crypto/rand"
	"encoding/binary"
	"runtime"

	"golang.org/x/crypto/blake2b"
)

func ConcatBytes(fields ...[]byte) []byte {
	totalLen := 0
	for _, f := range fields {
		totalLen += 4 + len(f)
	}

	res := make([]byte, totalLen)
	offset := 0
	for _, f := range fields {
		binary.BigEndian.PutUint32(res[offset:offset+4], uint32(len(f)))
		offset += 4
		copy(res[offset:], f)
		offset += len(f)
	}
	return res
}

func RandomBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	_, err := rand.Read(b)
	if err != nil {
		return nil, err
	}
	return b, nil
}

func Zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
	runtime.KeepAlive(b)
}

func HashPublicKeys(ecdhPK, mlkemPK []byte) []byte {
	combined := make([]byte, len(ecdhPK)+len(mlkemPK))
	copy(combined, ecdhPK)
	copy(combined[len(ecdhPK):], mlkemPK)

	hash := blake2b.Sum256(combined)
	return hash[:10]
}
