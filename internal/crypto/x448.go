package crypto

import (
	"crypto/rand"
	"errors"
	"io"
	"runtime"

	"github.com/cloudflare/circl/dh/x448"
)

func GenerateECDHKeyPair() ([]byte, []byte, error) {
	var pk, sk x448.Key

	if _, err := io.ReadFull(rand.Reader, sk[:]); err != nil {
		return nil, nil, errors.New("crypto/rand is unavailable: " + err.Error())
	}

	x448.KeyGen(&pk, &sk)

	pubOut := make([]byte, x448.Size)
	privOut := make([]byte, x448.Size)
	copy(pubOut, pk[:])
	copy(privOut, sk[:])

	defer func() {
		for i := range sk {
			sk[i] = 0
		}
		runtime.KeepAlive(sk)
	}()

	return pubOut, privOut, nil
}

func DeriveECDHSharedSecret(sk, pk []byte) ([]byte, error) {
	if len(sk) != x448.Size || len(pk) != x448.Size {
		return nil, errors.New("invalid ECDH key length: must be exactly 56 bytes")
	}

	var shared, secret, public x448.Key
	copy(secret[:], sk)
	copy(public[:], pk)

	defer func() {
		for i := range secret {
			secret[i] = 0
		}
		for i := range public {
			public[i] = 0
		}
		for i := range shared {
			shared[i] = 0
		}
		runtime.KeepAlive(secret)
		runtime.KeepAlive(public)
		runtime.KeepAlive(shared)
	}()

	if ok := x448.Shared(&shared, &secret, &public); !ok {
		return nil, errors.New("invalid public key (low-order point detected)")
	}

	sharedOut := make([]byte, x448.Size)
	copy(sharedOut, shared[:])

	return sharedOut, nil
}
