package identity

import (
	"crypto/sha256"
	"errors"

	"github.com/slipe-fun/skid-v3/internal/crypto"
)

type EncryptedSyncKey struct {
	Ciphertext []byte `json:"ciphertext"`
	Nonce      []byte `json:"nonce"`
}

type HandshakePayload struct {
	ReceiverCiphertext []byte `json:"receiver_ciphertext"`
	SenderCiphertext   []byte `json:"sender_ciphertext"`
	EncryptedSyncKey   EncryptedSyncKey
}

func InitiateKeyExchange(sender *User, senderSecretKeys *SecretKeys, receiver *User) (*HandshakePayload, []byte, []byte, error) {
	if sender == nil || receiver == nil {
		return nil, nil, nil, errors.New("initiate: sender and receiver cannot be nil")
	}
	if senderSecretKeys == nil {
		return nil, nil, nil, errors.New("initiate: senderSecretKeys cannot be nil")
	}

	var (
		senderMlKemCiphertext     []byte
		senderMlKemSharedSecret   []byte
		receiverMlKemCiphertext   []byte
		receiverMlKemSharedSecret []byte
		ecdhSharedSecret          []byte
		syncMSK                   []byte
		temp                      []byte
		syncKey                   []byte
		syncAAD                   []byte
		syncKeyCiphertext         []byte
		syncKeyNonce              []byte
		material                  []byte
		rootKey                   []byte
		chatKey                   []byte
		err                       error
	)

	defer func() {
		crypto.Zero(senderMlKemSharedSecret)
		crypto.Zero(receiverMlKemSharedSecret)
		crypto.Zero(ecdhSharedSecret)

		crypto.Zero(syncMSK)
		crypto.Zero(temp)
		crypto.Zero(material)

		crypto.Zero(rootKey)
	}()

	senderMlKemCiphertext, senderMlKemSharedSecret, err = crypto.EncapsulateMLKEM(sender.PublicKeys.MlKem768)
	if err != nil {
		return nil, nil, nil, err
	}

	receiverMlKemCiphertext, receiverMlKemSharedSecret, err = crypto.EncapsulateMLKEM(receiver.PublicKeys.MlKem768)
	if err != nil {
		return nil, nil, nil, err
	}

	ecdhSharedSecret, err = crypto.DeriveECDHSharedSecret(senderSecretKeys.X448, receiver.PublicKeys.X448)
	if err != nil {
		return nil, nil, nil, err
	}

	contextData := crypto.ConcatBytes(
		[]byte(sender.ID),
		[]byte(receiver.ID),
		sender.PublicKeys.X448,
		receiver.PublicKeys.X448,
		sender.PublicKeys.MlKem768,
		receiver.PublicKeys.MlKem768,
		senderMlKemCiphertext,
		receiverMlKemCiphertext,
	)

	sessionID := sha256.Sum256(contextData)

	temp, err = crypto.HKDF(senderSecretKeys.X448, sessionID[:], "skid:v3:sync_step1", 32)
	if err != nil {
		return nil, nil, nil, err
	}

	syncMSK, err = crypto.HKDF(senderSecretKeys.MlKem768, temp, "skid:v3:sync_master_key", 32)
	if err != nil {
		return nil, nil, nil, err
	}

	syncKey, err = crypto.HKDF(syncMSK, sessionID[:], "skid:v3:sync_key", 32)
	if err != nil {
		return nil, nil, nil, err
	}

	syncAAD = crypto.BuildAAD("sync_material",
		sessionID[:],
		[]byte(sender.ID),
		[]byte(receiver.ID),
		senderMlKemCiphertext,
		receiverMlKemCiphertext,
	)

	syncKeyCiphertext, syncKeyNonce, err = crypto.Encrypt(syncKey, receiverMlKemSharedSecret, syncAAD)
	if err != nil {
		return nil, nil, nil, err
	}

	material = crypto.ConcatBytes(receiverMlKemSharedSecret, ecdhSharedSecret)

	rootKey, err = crypto.HKDF(material, sessionID[:], "skid:v3:root_key", 32)
	if err != nil {
		return nil, nil, nil, err
	}

	chatKey, err = crypto.HKDF(rootKey, sessionID[:], "skid:v3:chat_key", 32)
	if err != nil {
		return nil, nil, nil, err
	}

	return &HandshakePayload{
		SenderCiphertext:   senderMlKemCiphertext,
		ReceiverCiphertext: receiverMlKemCiphertext,
		EncryptedSyncKey: EncryptedSyncKey{
			Ciphertext: syncKeyCiphertext,
			Nonce:      syncKeyNonce,
		},
	}, chatKey, syncKey, nil
}

func FinalizeKeyExchange(payload *HandshakePayload, sender *User, senderSecretKeys *SecretKeys, receiver *User, receiverSecretKeys *SecretKeys, isSelf bool) ([]byte, []byte, error) {
	if payload == nil {
		return nil, nil, errors.New("finalize: payload cannot be nil")
	}
	if sender == nil || receiver == nil {
		return nil, nil, errors.New("finalize: sender and receiver cannot be nil")
	}
	if isSelf {
		if senderSecretKeys == nil {
			return nil, nil, errors.New("finalize: senderSecretKeys cannot be nil when isSelf is true")
		}
	} else {
		if receiverSecretKeys == nil {
			return nil, nil, errors.New("finalize: receiverSecretKeys cannot be nil when isSelf is false")
		}
	}

	var (
		senderMlKemSharedSecret   []byte
		receiverMlKemSharedSecret []byte
		ecdhSharedSecret          []byte
		syncMSK                   []byte
		temp                      []byte
		syncKey                   []byte
		material                  []byte
		rootKey                   []byte
		chatKey                   []byte
		err                       error
	)

	defer func() {
		crypto.Zero(senderMlKemSharedSecret)
		crypto.Zero(receiverMlKemSharedSecret)
		crypto.Zero(ecdhSharedSecret)

		crypto.Zero(temp)
		crypto.Zero(syncMSK)
		crypto.Zero(material)

		crypto.Zero(rootKey)
	}()

	contextData := crypto.ConcatBytes(
		[]byte(sender.ID),
		[]byte(receiver.ID),
		sender.PublicKeys.X448,
		receiver.PublicKeys.X448,
		sender.PublicKeys.MlKem768,
		receiver.PublicKeys.MlKem768,
		payload.SenderCiphertext,
		payload.ReceiverCiphertext,
	)

	sessionID := sha256.Sum256(contextData)

	if isSelf {
		ecdhSharedSecret, err = crypto.DeriveECDHSharedSecret(senderSecretKeys.X448, receiver.PublicKeys.X448)
		if err != nil {
			return nil, nil, err
		}

		temp, err = crypto.HKDF(senderSecretKeys.X448, sessionID[:], "skid:v3:sync_step1", 32)
		if err != nil {
			return nil, nil, err
		}

		syncMSK, err = crypto.HKDF(senderSecretKeys.MlKem768, temp, "skid:v3:sync_master_key", 32)
		if err != nil {
			return nil, nil, err
		}

		syncKey, err = crypto.HKDF(syncMSK, sessionID[:], "skid:v3:sync_key", 32)
		if err != nil {
			return nil, nil, err
		}

		syncAAD := crypto.BuildAAD("sync_material",
			sessionID[:],
			[]byte(sender.ID),
			[]byte(receiver.ID),
			payload.SenderCiphertext,
			payload.ReceiverCiphertext,
		)

		receiverMlKemSharedSecret, err = crypto.Decrypt(syncKey, payload.EncryptedSyncKey.Ciphertext, payload.EncryptedSyncKey.Nonce, syncAAD)
		if err != nil {
			return nil, nil, err
		}
	} else {
		ecdhSharedSecret, err = crypto.DeriveECDHSharedSecret(receiverSecretKeys.X448, sender.PublicKeys.X448)
		if err != nil {
			return nil, nil, err
		}
		receiverMlKemSharedSecret, err = crypto.DecapsulateMLKEM(receiverSecretKeys.MlKem768, payload.ReceiverCiphertext)
		if err != nil {
			return nil, nil, err
		}

		temp, err = crypto.HKDF(receiverSecretKeys.X448, sessionID[:], "skid:v3:sync_step1", 32)
		if err != nil {
			return nil, nil, err
		}

		syncMSK, err = crypto.HKDF(receiverSecretKeys.MlKem768, temp, "skid:v3:sync_master_key", 32)
		if err != nil {
			return nil, nil, err
		}

		syncKey, err = crypto.HKDF(syncMSK, sessionID[:], "skid:v3:sync_key", 32)
		if err != nil {
			return nil, nil, err
		}
	}

	material = crypto.ConcatBytes(receiverMlKemSharedSecret, ecdhSharedSecret)

	rootKey, err = crypto.HKDF(material, sessionID[:], "skid:v3:root_key", 32)
	if err != nil {
		return nil, nil, err
	}

	chatKey, err = crypto.HKDF(rootKey, sessionID[:], "skid:v3:chat_key", 32)
	if err != nil {
		return nil, nil, err
	}

	return chatKey, syncKey, nil
}
