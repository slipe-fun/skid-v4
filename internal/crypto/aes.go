package crypto

import (
	"errors"
	"runtime"

	"github.com/tink-crypto/tink-go/v2/aead/subtle"
)

func NewAes(key []byte) (*subtle.AESGCMSIV, error) {
	if len(key) != 16 && len(key) != 32 {
		return nil, errors.New("invalid AES key size: must be exactly 16 or 32 bytes")
	}

	localKey := make([]byte, len(key))
	copy(localKey, key)

	defer func() {
		for i := range localKey {
			localKey[i] = 0
		}
		runtime.KeepAlive(localKey)
	}()

	return subtle.NewAESGCMSIV(localKey)
}

func Encrypt(key, plaintext, aad []byte) ([]byte, []byte, error) {
	aes, err := NewAes(key)
	if err != nil {
		return nil, nil, err
	}

	defer func() {
		if aes != nil {
			var zeroAES subtle.AESGCMSIV
			*aes = zeroAES
			runtime.KeepAlive(aes)
		}
	}()

	fullResult, err := aes.Encrypt(plaintext, aad)
	if err != nil {
		return nil, nil, err
	}

	if len(fullResult) < 12 {
		return nil, nil, errors.New("failed to encrypt: output too short")
	}

	ciphertext := make([]byte, len(fullResult)-12)
	iv := make([]byte, 12)
	copy(iv, fullResult[:12])
	copy(ciphertext, fullResult[12:])

	defer func() {
		for i := range fullResult {
			fullResult[i] = 0
		}
		runtime.KeepAlive(fullResult)
	}()

	return ciphertext, iv, nil
}

func Decrypt(key, ciphertext, iv, aad []byte) ([]byte, error) {
	if len(iv) != 12 {
		return nil, errors.New("invalid IV length: must be exactly 12 bytes")
	}

	if len(ciphertext) < 16 {
		return nil, errors.New("ciphertext too short: must be at least 16 bytes (tag size)")
	}

	aes, err := NewAes(key)
	if err != nil {
		return nil, err
	}

	defer func() {
		if aes != nil {
			var zeroAES subtle.AESGCMSIV
			*aes = zeroAES
			runtime.KeepAlive(aes)
		}
	}()

	fullCiphertext := make([]byte, 0, len(iv)+len(ciphertext))
	fullCiphertext = append(fullCiphertext, iv...)
	fullCiphertext = append(fullCiphertext, ciphertext...)

	defer func() {
		for i := range fullCiphertext {
			fullCiphertext[i] = 0
		}
		runtime.KeepAlive(fullCiphertext)
	}()

	return aes.Decrypt(fullCiphertext, aad)
}
