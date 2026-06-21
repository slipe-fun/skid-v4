package identity

import (
	"errors"

	"github.com/cloudflare/circl/dh/x448"
	"github.com/cloudflare/circl/kem/mlkem/mlkem768"
	"github.com/cloudflare/circl/sign/ed448"
	"github.com/mr-tron/base58/base58"
	"github.com/slipe-fun/skid-v3/internal/crypto"
	"github.com/vmihailenco/msgpack/v5"
)

type PublicKeys struct {
	MlKem768 []byte `json:"ml_kem768_public_key"`
	X448     []byte `json:"x448_public_key"`
	Ed448    []byte `json:"ed448_public_key"`
}

type SecretKeys struct {
	MlKem768 []byte
	X448     []byte
	Ed448    []byte
}

type EncryptedSecretKeys struct {
	Ciphertext []byte `json:"ciphertext"`
	Nonce      []byte `json:"nonce"`
	Salt       []byte `json:"salt"`
	Signature  []byte `json:"signature"`
}

type User struct {
	ID         string     `json:"id"`
	PublicKeys PublicKeys `json:"public_keys"`
}

func (s *SecretKeys) Wipe() {
	if s == nil {
		return
	}

	crypto.Zero(s.MlKem768)
	crypto.Zero(s.X448)
	crypto.Zero(s.Ed448)
}

func (s *SecretKeys) Pack() ([]byte, error) {
	return msgpack.Marshal(s)
}

func Unpack(packed []byte) (*SecretKeys, error) {
	var s SecretKeys
	err := msgpack.Unmarshal(packed, &s)
	return &s, err
}

func GenerateUserID(ecdhPK []byte, mlkemPK []byte) string {
	truncatedHash := crypto.HashPublicKeys(ecdhPK, mlkemPK)

	return base58.Encode(truncatedHash)
}

func GenerateIdentity() (user *User, secret *SecretKeys, err error) {
	var mlKem768Secret, x448Secret, ed448Secret []byte

	defer func() {
		if err != nil {
			crypto.Zero(mlKem768Secret)
			crypto.Zero(x448Secret)
			crypto.Zero(ed448Secret)
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
		ID: GenerateUserID(x448Public, mlKem768Public),
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
			crypto.Zero(kemCopy)
			crypto.Zero(ecdhCopy)
			crypto.Zero(edCopy)
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

func EncryptSecretKeys(user *User, userSecretKeys *SecretKeys, masterKey []byte) (*EncryptedSecretKeys, error) {
	var (
		packedSecretKeys []byte
		derivedKey       []byte
		err              error
	)

	defer func() {
		crypto.Zero(packedSecretKeys)
		crypto.Zero(derivedKey)
	}()

	packedSecretKeys, err = userSecretKeys.Pack()
	if err != nil {
		return nil, err
	}

	salt, err := crypto.RandomBytes(32)
	if err != nil {
		return nil, err
	}

	derivedKey, err = crypto.HKDF(masterKey, salt, "skid:v3:master_key", 32)
	if err != nil {
		return nil, err
	}

	secretKeysAAD := crypto.BuildAAD("secret_keys",
		user.PublicKeys.MlKem768,
		user.PublicKeys.X448,
		user.PublicKeys.Ed448,
	)

	ciphertext, nonce, err := crypto.Encrypt(derivedKey, packedSecretKeys, secretKeysAAD)
	if err != nil {
		return nil, err
	}

	messageToSign := crypto.ConcatBytes(
		ciphertext,
		nonce,
		salt,
		user.PublicKeys.MlKem768,
		user.PublicKeys.X448,
		user.PublicKeys.Ed448,
	)

	signature, err := crypto.SignEd448(userSecretKeys.Ed448, messageToSign, "")
	if err != nil {
		return nil, err
	}

	return &EncryptedSecretKeys{
		Ciphertext: ciphertext,
		Nonce:      nonce,
		Salt:       salt,
		Signature:  signature,
	}, nil
}

func DecryptSecretKeys(encryptedSecretKeys *EncryptedSecretKeys, user *User, masterKey []byte) (*SecretKeys, error) {
	var (
		derivedKey       []byte
		packedSecretKeys []byte
		err              error
	)

	defer func() {
		crypto.Zero(derivedKey)
		crypto.Zero(packedSecretKeys)
	}()

	signedMessage := crypto.ConcatBytes(
		encryptedSecretKeys.Ciphertext,
		encryptedSecretKeys.Nonce,
		encryptedSecretKeys.Salt,
		user.PublicKeys.MlKem768,
		user.PublicKeys.X448,
		user.PublicKeys.Ed448,
	)

	var isSignatureValid bool
	isSignatureValid, err = crypto.VerifyEd448(user.PublicKeys.Ed448, signedMessage, encryptedSecretKeys.Signature, "")
	if err != nil {
		return nil, err
	}

	if !isSignatureValid {
		return nil, errors.New("invalid Ed448 signature")
	}

	derivedKey, err = crypto.HKDF(masterKey, encryptedSecretKeys.Salt, "skid:v3:master_key", 32)
	if err != nil {
		return nil, err
	}

	secretKeysAAD := crypto.BuildAAD("secret_keys",
		user.PublicKeys.MlKem768,
		user.PublicKeys.X448,
		user.PublicKeys.Ed448,
	)

	packedSecretKeys, err = crypto.Decrypt(derivedKey, encryptedSecretKeys.Ciphertext, encryptedSecretKeys.Nonce, secretKeysAAD)
	if err != nil {
		return nil, err
	}

	unpackedSecretKeys, err := Unpack(packedSecretKeys)
	if err != nil {
		return nil, err
	}

	return unpackedSecretKeys, nil
}
