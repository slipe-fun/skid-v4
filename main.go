package main

import (
	"encoding/hex"
	"fmt"

	"github.com/slipe-fun/skid-v3/pkg/identity"
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

	userAPrefix := fmt.Sprintf("[User %s]", userA.ID)
	userBPrefix := fmt.Sprintf("[User %s]", userB.ID)

	fmt.Println(userAPrefix, "Initializing handshake with", userB.ID)
	handshakePayload, initializedChatKey, err := identity.InitiateKeyExchange(userA, secretA, userB)
	if err != nil {
		panic(err)
	}

	fmt.Println(userAPrefix, "Hanshake initialized!")
	fmt.Println(userAPrefix, "Chat key:", hex.EncodeToString(initializedChatKey))

	fmt.Println()

	fmt.Println(userAPrefix, "Self-finalizing handshake...")
	syncedChatKey, err := identity.FinalizeKeyExchange(handshakePayload, userA, secretA, userB, nil, true)
	if err != nil {
		panic(err)
	}
	fmt.Println(userAPrefix, "Hanshake finalized!")
	fmt.Println(userAPrefix, "Chat key:", hex.EncodeToString(syncedChatKey))

	fmt.Println()

	fmt.Println(userBPrefix, "Finalizing handshake with", userA.ID)
	receiverChatKey, err := identity.FinalizeKeyExchange(handshakePayload, userA, nil, userB, secretB, false)
	if err != nil {
		panic(err)
	}
	fmt.Println(userBPrefix, "Hanshake finalized!")
	fmt.Println(userBPrefix, "Chat key:", hex.EncodeToString(receiverChatKey))

	fmt.Println("\neverything works!!!")
}
