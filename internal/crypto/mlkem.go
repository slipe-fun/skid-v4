package crypto

import (
	"crypto/rand"
	"errors"
	"runtime"

	"github.com/cloudflare/circl/kem/mlkem/mlkem768"
)

func GenerateMLKEMKeyPair() ([]byte, []byte, error) {
	pk, sk, err := mlkem768.GenerateKeyPair(rand.Reader)
	if err != nil {
		return nil, nil, err
	}

	defer func() {
		if sk != nil {
			var zeroSK mlkem768.PrivateKey
			*sk = zeroSK
			runtime.KeepAlive(sk)
		}
	}()

	pkBytes, err := pk.MarshalBinary()
	if err != nil {
		return nil, nil, err
	}

	skBytes, err := sk.MarshalBinary()
	if err != nil {
		return nil, nil, err
	}

	return pkBytes, skBytes, nil
}

func EncapsulateMLKEM(pkBytes []byte) ([]byte, []byte, error) {
	if len(pkBytes) != mlkem768.PublicKeySize {
		return nil, nil, errors.New("invalid public key size")
	}

	pk := new(mlkem768.PublicKey)

	if err := pk.Unpack(pkBytes); err != nil {
		return nil, nil, errors.New("invalid public key: " + err.Error())
	}

	defer func() {
		if pk != nil {
			var zeroPK mlkem768.PublicKey
			*pk = zeroPK
			runtime.KeepAlive(pk)
		}
	}()

	ct, ss, err := mlkem768.Scheme().Encapsulate(pk)
	if err != nil {
		return nil, nil, err
	}

	return ct, ss, nil
}

func DecapsulateMLKEM(skBytes, ct []byte) ([]byte, error) {
	if len(skBytes) != mlkem768.PrivateKeySize {
		return nil, errors.New("invalid secret key size")
	}

	if len(ct) != mlkem768.CiphertextSize {
		return nil, errors.New("invalid ciphertext size")
	}

	sk := new(mlkem768.PrivateKey)

	defer func() {
		if sk != nil {
			var zeroSK mlkem768.PrivateKey
			*sk = zeroSK
			runtime.KeepAlive(sk)
		}
	}()

	if err := sk.Unpack(skBytes); err != nil {
		return nil, errors.New("invalid secret key: " + err.Error())
	}

	ss, err := mlkem768.Scheme().Decapsulate(sk, ct)
	if err != nil {
		for i := range ss {
			ss[i] = 0
		}
		return nil, err
	}

	return ss, nil
}
