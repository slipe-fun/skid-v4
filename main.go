package main

import (
	"encoding/hex"
	"fmt"

	"github.com/slipe-fun/skid-v3/pkg/identity"
	"github.com/slipe-fun/skid-v3/pkg/messages"
	"github.com/tink-crypto/tink-go/v2/subtle/random"
)

func main() {
	userA, secretA, err := identity.GenerateIdentity()
	if err != nil {
		panic(err)
	}
	defer secretA.Wipe()

	restoredUser := identity.User{
		ID: identity.GenerateUserID(userA.PublicKeys.X448, userA.PublicKeys.MlKem768),
		PublicKeys: identity.PublicKeys{
			MlKem768: userA.PublicKeys.MlKem768,
			X448:     userA.PublicKeys.X448,
			Ed448:    userA.PublicKeys.Ed448,
		},
	}
	_ = restoredUser

	restoredSecret, err := identity.NewSecretKeys(secretA.MlKem768, secretA.X448, secretA.Ed448)
	if err != nil {
		panic(err)
	}
	defer restoredSecret.Wipe()

	userB, secretB, err := identity.GenerateIdentity()
	if err != nil {
		panic(err)
	}
	defer secretB.Wipe()

	userARecoveryKey := random.GetRandomBytes(32)

	userAMasterKey := random.GetRandomBytes(32)

	userAPrefix := fmt.Sprintf("[User %s]", userA.ID)
	userBPrefix := fmt.Sprintf("[User %s]", userB.ID)

	fmt.Println(userAPrefix, "created")
	fmt.Println(userBPrefix, "created")

	fmt.Println()

	fmt.Println(userAPrefix, "Encrypting it's master key using recovery key...")
	encryptedMasterKey, err := identity.EncryptMasterKey(userAMasterKey, userARecoveryKey, userA, secretA)
	if err != nil {
		panic(err)
	}
	fmt.Println(userAPrefix, "Master key encrypted!")

	fmt.Println()

	fmt.Println(userAPrefix, "Decrypting master key...")
	decryptedMasterKey, err := identity.DecryptMasterKey(encryptedMasterKey, userARecoveryKey, userA)
	if err != nil {
		panic(err)
	}
	fmt.Println(userAPrefix, "Master key decrypted!")
	fmt.Println(userAPrefix, "Decrypted master key:", hex.EncodeToString(decryptedMasterKey))

	fmt.Println()

	fmt.Println(userAPrefix, "Encrypting it's secret keys...")
	encryptedSecretKeys, err := identity.EncryptSecretKeys(userA, secretA, userAMasterKey)
	if err != nil {
		panic(err)
	}
	fmt.Println(userAPrefix, "Secret keys encrypted!")

	fmt.Println()

	fmt.Println(userAPrefix, "Decrypting secret keys...")
	decryptedSecretKeys, err := identity.DecryptSecretKeys(encryptedSecretKeys, userA, userAMasterKey)
	if err != nil {
		panic(err)
	}
	defer decryptedSecretKeys.Wipe()
	fmt.Println(userAPrefix, "Secret keys decrypted!")

	fmt.Println(userAPrefix, "Decrypted MlKem768 key lenth:", len(decryptedSecretKeys.MlKem768))
	fmt.Println(userAPrefix, "Decrypted X448 key lenth:", len(decryptedSecretKeys.X448))
	fmt.Println(userAPrefix, "Decrypted Ed448 key lenth:", len(decryptedSecretKeys.Ed448))

	fmt.Println()

	fmt.Println(userAPrefix, "Initializing handshake with", userB.ID)
	handshakePayload, initializedChatKey, senderSyncKey, err := identity.InitiateKeyExchange(userA, secretA, userB)
	if err != nil {
		panic(err)
	}

	fmt.Println(userAPrefix, "Hanshake initialized!")
	fmt.Println(userAPrefix, "Chat key:", hex.EncodeToString(initializedChatKey))

	fmt.Println()

	fmt.Println(userAPrefix, "Self-finalizing handshake...")
	syncedChatKey, syncedSenderSyncKey, err := identity.FinalizeKeyExchange(handshakePayload, userA, secretA, userB, nil, true)
	if err != nil {
		panic(err)
	}
	fmt.Println(userAPrefix, "Hanshake finalized!")
	fmt.Println(userAPrefix, "Chat key:", hex.EncodeToString(syncedChatKey))

	fmt.Println()

	fmt.Println(userBPrefix, "Finalizing handshake with", userA.ID)
	receiverChatKey, receiverSyncKey, err := identity.FinalizeKeyExchange(handshakePayload, userA, nil, userB, secretB, false)
	if err != nil {
		panic(err)
	}
	fmt.Println(userBPrefix, "Hanshake finalized!")
	fmt.Println(userBPrefix, "Chat key:", hex.EncodeToString(receiverChatKey))

	fmt.Println()

	fmt.Println(userAPrefix, "Sending message to", userB.ID)
	encryptedMsg1, err := messages.Encrypt(initializedChatKey, []byte("Hello, Bob!"), senderSyncKey, userA, userB)
	if err != nil {
		panic(err)
	}
	fmt.Println(userAPrefix, "Message encrypted!")

	fmt.Println()

	fmt.Println(userBPrefix, "Receiving message from", userA.ID)
	decryptedMsg1, err := messages.Decrypt(receiverChatKey, *encryptedMsg1, receiverSyncKey, userB, userA)
	if err != nil {
		panic(err)
	}
	fmt.Println(userBPrefix, "Message decrypted!")
	fmt.Println(userBPrefix, "Content:", string(decryptedMsg1.Content))
	fmt.Println(userBPrefix, "Author ID:", decryptedMsg1.AuthorID)

	fmt.Println()

	fmt.Println(userAPrefix, "Syncing own outgoing message...")
	syncedMsg1, err := messages.Decrypt(syncedChatKey, *encryptedMsg1, syncedSenderSyncKey, userA, userB)
	if err != nil {
		panic(err)
	}
	fmt.Println(userAPrefix, "Outgoing message synced!")
	fmt.Println(userAPrefix, "Content:", string(syncedMsg1.Content))
	fmt.Println(userAPrefix, "Author ID:", syncedMsg1.AuthorID)

	fmt.Println()

	fmt.Println(userBPrefix, "Sending reply to", userA.ID)
	encryptedMsg2, err := messages.Encrypt(receiverChatKey, []byte("Hey, Alice!"), receiverSyncKey, userB, userA)
	if err != nil {
		panic(err)
	}
	fmt.Println(userBPrefix, "Message encrypted!")

	fmt.Println()

	fmt.Println(userAPrefix, "Receiving reply from", userB.ID)
	decryptedMsg2, err := messages.Decrypt(syncedChatKey, *encryptedMsg2, syncedSenderSyncKey, userA, userB)
	if err != nil {
		panic(err)
	}
	fmt.Println(userAPrefix, "Message decrypted!")
	fmt.Println(userAPrefix, "Content:", string(decryptedMsg2.Content))
	fmt.Println(userAPrefix, "Author ID:", decryptedMsg2.AuthorID)

	fmt.Println("\neverything works!!!")
}
