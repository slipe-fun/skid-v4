package messages

import (
	"crypto/hmac"
	"encoding/binary"
	"errors"
	"time"

	"github.com/slipe-fun/skid-v4/internal/crypto"
	"github.com/slipe-fun/skid-v4/pkg/identity"
	"github.com/vmihailenco/msgpack/v5"
)

type EncryptedMessage struct {
	Ciphertext []byte
	Nonce      []byte
	Salt       []byte
}

type Message struct {
	Content   []byte
	AuthorID  string
	SyncTag   []byte
	Timestamp int64
}

func Pack(m *Message) ([]byte, error) {
	return msgpack.Marshal(m)
}

func Unpack(packed []byte) (*Message, error) {
	var m Message
	err := msgpack.Unmarshal(packed, &m)
	return &m, err
}

func Encrypt(key, content, syncKey []byte, me, recipient *identity.User) (*EncryptedMessage, error) {
	if me == nil {
		return nil, errors.New("sender (me) cannot be nil")
	}
	if recipient == nil {
		return nil, errors.New("recipient cannot be nil")
	}

	if me.ID == "" {
		return nil, errors.New("sender ID cannot be empty")
	}
	if recipient.ID == "" {
		return nil, errors.New("recipient ID cannot be empty")
	}

	if len(key) == 0 {
		return nil, errors.New("encryption key cannot be empty")
	}
	if len(syncKey) == 0 {
		return nil, errors.New("sync key cannot be empty")
	}

	var (
		derivedKey    []byte
		payloadData   []byte
		packedMessage []byte
		err           error
	)

	defer func() {
		crypto.Zero(derivedKey)
		crypto.Zero(payloadData)
		crypto.Zero(packedMessage)
	}()

	salt, err := crypto.RandomBytes(32)
	if err != nil {
		return nil, err
	}

	messageInfo, err := crypto.GenerateMessageInfo(me.ID, recipient.ID)
	if err != nil {
		return nil, err
	}

	derivedKey, err = crypto.HKDF(key, salt, messageInfo, 32)
	if err != nil {
		return nil, err
	}

	firstID := me.ID
	secondID := recipient.ID
	if secondID < firstID {
		firstID = recipient.ID
		secondID = me.ID
	}

	messageAAD := crypto.BuildAAD("message",
		[]byte(firstID),
		[]byte(secondID),
	)

	timestamp := time.Now().Unix()

	timestampBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(timestampBytes, uint64(timestamp))

	payloadData = crypto.ConcatBytes(timestampBytes, []byte(me.ID), content)

	syncTag, err := crypto.ComputeHMAC(syncKey, payloadData)
	if err != nil {
		return nil, err
	}

	message := Message{
		Content:   content,
		AuthorID:  me.ID,
		SyncTag:   syncTag,
		Timestamp: timestamp,
	}

	packedMessage, err = Pack(&message)
	if err != nil {
		return nil, err
	}

	ciphertext, nonce, err := crypto.Encrypt(derivedKey, packedMessage, messageAAD)
	if err != nil {
		return nil, err
	}

	return &EncryptedMessage{
		Ciphertext: ciphertext,
		Nonce:      nonce,
		Salt:       salt,
	}, nil
}

func Decrypt(key []byte, encryptedMessage EncryptedMessage, syncKey []byte, me, recipient *identity.User) (*Message, error) {
	if me == nil {
		return nil, errors.New("recipient (me) cannot be nil")
	}
	if recipient == nil {
		return nil, errors.New("sender (recipient) cannot be nil")
	}

	if me.ID == "" {
		return nil, errors.New("recipient ID cannot be empty")
	}
	if recipient.ID == "" {
		return nil, errors.New("sender ID cannot be empty")
	}

	if len(key) == 0 {
		return nil, errors.New("decryption key cannot be empty")
	}
	if len(syncKey) == 0 {
		return nil, errors.New("sync key cannot be empty")
	}
	if len(encryptedMessage.Ciphertext) == 0 {
		return nil, errors.New("ciphertext cannot be empty")
	}
	if len(encryptedMessage.Nonce) == 0 {
		return nil, errors.New("nonce cannot be empty")
	}
	if len(encryptedMessage.Salt) == 0 {
		return nil, errors.New("salt cannot be empty")
	}

	var (
		derivedKey      []byte
		packedMessage   []byte
		unpackedMessage *Message
		payloadData     []byte
		err             error
	)

	defer func() {
		crypto.Zero(derivedKey)
		crypto.Zero(packedMessage)
		crypto.Zero(payloadData)
	}()

	messageInfo, err := crypto.GenerateMessageInfo(me.ID, recipient.ID)
	if err != nil {
		return nil, err
	}

	derivedKey, err = crypto.HKDF(key, encryptedMessage.Salt, messageInfo, 32)
	if err != nil {
		return nil, err
	}

	firstID := me.ID
	secondID := recipient.ID
	if secondID < firstID {
		firstID = recipient.ID
		secondID = me.ID
	}

	messageAAD := crypto.BuildAAD("message",
		[]byte(firstID),
		[]byte(secondID),
	)

	packedMessage, err = crypto.Decrypt(derivedKey, encryptedMessage.Ciphertext, encryptedMessage.Nonce, messageAAD)
	if err != nil {
		return nil, err
	}

	unpackedMessage, err = Unpack(packedMessage)
	if err != nil {
		return nil, err
	}

	timestampBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(timestampBytes, uint64(unpackedMessage.Timestamp))

	payloadData = crypto.ConcatBytes(timestampBytes, []byte(me.ID), unpackedMessage.Content)

	syncTag, err := crypto.ComputeHMAC(syncKey, payloadData)
	if err != nil {
		return nil, err
	}

	if hmac.Equal(unpackedMessage.SyncTag, syncTag) {
		unpackedMessage.AuthorID = me.ID
	} else {
		unpackedMessage.AuthorID = recipient.ID
	}

	return unpackedMessage, nil
}
