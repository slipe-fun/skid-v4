package identity

import (
	"errors"
	"runtime"

	"github.com/cloudflare/circl/dh/x448"
	"github.com/cloudflare/circl/kem/mlkem/mlkem768"
	"github.com/cloudflare/circl/sign/ed448"
	"github.com/slipe-fun/skid-v3/internal/crypto"
)

func GenerateIdentity() (user *User, secret *SecretKeys, err error) {
	var mlKem768Secret, x448Secret, ed448Secret []byte

	defer func() {
		if err != nil {
			for i := range mlKem768Secret {
				mlKem768Secret[i] = 0
			}
			for i := range x448Secret {
				x448Secret[i] = 0
			}
			for i := range ed448Secret {
				ed448Secret[i] = 0
			}

			runtime.KeepAlive(mlKem768Secret)
			runtime.KeepAlive(x448Secret)
			runtime.KeepAlive(ed448Secret)
		}
	}()

	var mlKem768Public []byte
	mlKem768Public, mlKem768Secret, err = crypto.GenerateMLKEMKeyPair()
	if err != nil {
		return nil, nil, err
	}

	var x448Public []byte
	x448Public, x448Secret, err = crypto.GenerateECDHKeyPair()
	if err != nil {
		return nil, nil, err
	}

	var ed448Public []byte
	ed448Public, ed448Secret, err = crypto.GenerateEd448KeyPair()
	if err != nil {
		return nil, nil, err
	}

	user = &User{
		PublicKeys: PublicKeys{
			MlKem768: mlKem768Public,
			X448:     x448Public,
			Ed448:    ed448Public,
		},
	}

	secret = &SecretKeys{
		MlKem768: mlKem768Secret,
		X448:     x448Secret,
		Ed448:    ed448Secret,
	}

	return user, secret, nil
}

func NewSecretKeys(kem, ecdh, ed []byte) (secret *SecretKeys, err error) {
	if len(kem) != mlkem768.PrivateKeySize {
		return nil, errors.New("invalid ML-KEM-768 secret key size: must be exactly 2400 bytes")
	}
	if len(ecdh) != x448.Size {
		return nil, errors.New("invalid X448 secret key size: must be exactly 56 bytes")
	}
	if len(ed) != ed448.PrivateKeySize {
		return nil, errors.New("invalid Ed448 secret key size: must be exactly 114 bytes")
	}

	var kemCopy, ecdhCopy, edCopy []byte

	defer func() {
		if err != nil {
			for i := range kemCopy {
				kemCopy[i] = 0
			}
			for i := range ecdhCopy {
				ecdhCopy[i] = 0
			}
			for i := range edCopy {
				edCopy[i] = 0
			}
			runtime.KeepAlive(kemCopy)
			runtime.KeepAlive(ecdhCopy)
			runtime.KeepAlive(edCopy)
		}
	}()

	kemCopy = make([]byte, len(kem))
	copy(kemCopy, kem)

	ecdhCopy = make([]byte, len(ecdh))
	copy(ecdhCopy, ecdh)

	edCopy = make([]byte, len(ed))
	copy(edCopy, ed)

	secret = &SecretKeys{
		MlKem768: kemCopy,
		X448:     ecdhCopy,
		Ed448:    edCopy,
	}

	return secret, nil
}
