package crypto

import (
	"crypto/rand"
	"errors"
	"fmt"
	"runtime"

	"github.com/cloudflare/circl/sign/ed448"
)

func GenerateEd448KeyPair() ([]byte, []byte, error) {
	pk, sk, err := ed448.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}

	pkOut := make([]byte, ed448.PublicKeySize)
	skOut := make([]byte, ed448.PrivateKeySize)
	copy(pkOut, pk)
	copy(skOut, sk)

	defer func() {
		for i := range sk {
			sk[i] = 0
		}
		runtime.KeepAlive(sk)
	}()

	return pkOut, skOut, nil
}

func SignEd448(skBytes []byte, message []byte, ctx string) ([]byte, error) {
	if len(skBytes) != ed448.PrivateKeySize {
		return nil, errors.New("invalid private key size: must be exactly 114 bytes")
	}
	if len(ctx) > 255 {
		return nil, errors.New("context string is too long: must be 255 bytes or less")
	}

	sk := make(ed448.PrivateKey, len(skBytes))
	copy(sk, skBytes)

	defer func() {
		for i := range sk {
			sk[i] = 0
		}
		runtime.KeepAlive(sk)
	}()

	var signature []byte
	var signErr error

	func() {
		defer func() {
			if r := recover(); r != nil {
				signErr = fmt.Errorf("signing panic: %v", r)
			}
		}()
		signature = ed448.Sign(sk, message, ctx)
	}()

	if signErr != nil {
		return nil, signErr
	}

	sigOut := make([]byte, len(signature))
	copy(sigOut, signature)

	return sigOut, nil
}

func VerifyEd448(pkBytes []byte, message []byte, signature []byte, ctx string) (bool, error) {
	if len(pkBytes) != ed448.PublicKeySize {
		return false, errors.New("invalid public key size: must be exactly 57 bytes")
	}
	if len(signature) != ed448.SignatureSize {
		return false, errors.New("invalid signature size: must be exactly 114 bytes")
	}
	if len(ctx) > 255 {
		return false, errors.New("context string is too long: must be 255 bytes or less")
	}

	pk := ed448.PublicKey(pkBytes)
	var ok bool
	var verifyErr error

	func() {
		defer func() {
			if r := recover(); r != nil {
				verifyErr = fmt.Errorf("verification panic: %v", r)
			}
		}()
		ok = ed448.Verify(pk, message, signature, ctx)
	}()

	if verifyErr != nil {
		return false, verifyErr
	}

	return ok, nil
}
