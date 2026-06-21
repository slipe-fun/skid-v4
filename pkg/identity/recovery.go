package identity

import (
	"errors"

	"github.com/slipe-fun/skid-v4/internal/crypto"
)

type EncryptedMasterKey struct {
	Ciphertext []byte `json:"ciphertext"`
	Nonce      []byte `json:"nonce"`
	Salt       []byte `json:"salt"`
	Signature  []byte `json:"signature"`
}

func EncryptMasterKey(masterKey []byte, recoveryKey []byte, user *User, userSecretKeys *SecretKeys) (*EncryptedMasterKey, error) {
	if user == nil {
		return nil, errors.New("user cannot be nil")
	}
	if userSecretKeys == nil {
		return nil, errors.New("userSecretKeys cannot be nil")
	}

	if len(masterKey) == 0 {
		return nil, errors.New("masterKey cannot be empty")
	}
	if len(recoveryKey) == 0 {
		return nil, errors.New("recoveryKey cannot be empty")
	}
	if len(userSecretKeys.Ed448) == 0 {
		return nil, errors.New("Ed448 secret key is empty or missing")
	}

	if len(user.PublicKeys.MlKem768) == 0 || len(user.PublicKeys.X448) == 0 || len(user.PublicKeys.Ed448) == 0 {
		return nil, errors.New("user public keys are incomplete")
	}

	var (
		derivedKey []byte
		err        error
	)

	defer func() {
		crypto.Zero(derivedKey)
	}()

	salt, err := crypto.RandomBytes(32)
	if err != nil {
		return nil, err
	}

	derivedKey, err = crypto.HKDF(recoveryKey, salt, "skid:v4:recovery_key", 32)
	if err != nil {
		return nil, err
	}

	masterKeyAAD := crypto.BuildAAD("master_key",
		user.PublicKeys.MlKem768,
		user.PublicKeys.X448,
		user.PublicKeys.Ed448,
	)

	ciphertext, nonce, err := crypto.Encrypt(derivedKey, masterKey, masterKeyAAD)
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

	return &EncryptedMasterKey{
		Ciphertext: ciphertext,
		Nonce:      nonce,
		Salt:       salt,
		Signature:  signature,
	}, nil
}

func DecryptMasterKey(encryptedMasterKey *EncryptedMasterKey, recoveryKey []byte, user *User) ([]byte, error) {
	if encryptedMasterKey == nil {
		return nil, errors.New("encryptedMasterKey cannot be nil")
	}
	if user == nil {
		return nil, errors.New("user cannot be nil")
	}

	if len(recoveryKey) == 0 {
		return nil, errors.New("recoveryKey cannot be empty")
	}
	if len(encryptedMasterKey.Ciphertext) == 0 {
		return nil, errors.New("ciphertext cannot be empty")
	}
	if len(encryptedMasterKey.Nonce) == 0 {
		return nil, errors.New("nonce cannot be empty")
	}
	if len(encryptedMasterKey.Salt) == 0 {
		return nil, errors.New("salt cannot be empty")
	}
	if len(encryptedMasterKey.Signature) == 0 {
		return nil, errors.New("signature cannot be empty")
	}

	if len(user.PublicKeys.MlKem768) == 0 || len(user.PublicKeys.X448) == 0 || len(user.PublicKeys.Ed448) == 0 {
		return nil, errors.New("user public keys are incomplete")
	}

	var (
		derivedKey []byte
		err        error
	)

	defer func() {
		crypto.Zero(derivedKey)
	}()

	signedMessage := crypto.ConcatBytes(
		encryptedMasterKey.Ciphertext,
		encryptedMasterKey.Nonce,
		encryptedMasterKey.Salt,
		user.PublicKeys.MlKem768,
		user.PublicKeys.X448,
		user.PublicKeys.Ed448,
	)

	var isSignatureValid bool
	isSignatureValid, err = crypto.VerifyEd448(user.PublicKeys.Ed448, signedMessage, encryptedMasterKey.Signature, "")
	if err != nil {
		return nil, err
	}

	if !isSignatureValid {
		return nil, errors.New("invalid Ed448 signature")
	}

	derivedKey, err = crypto.HKDF(recoveryKey, encryptedMasterKey.Salt, "skid:v4:recovery_key", 32)
	if err != nil {
		return nil, err
	}

	masterKeyAAD := crypto.BuildAAD("master_key",
		user.PublicKeys.MlKem768,
		user.PublicKeys.X448,
		user.PublicKeys.Ed448,
	)

	masterKey, err := crypto.Decrypt(derivedKey, encryptedMasterKey.Ciphertext, encryptedMasterKey.Nonce, masterKeyAAD)
	if err != nil {
		return nil, err
	}

	return masterKey, nil
}
