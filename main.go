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
	_ = userBPrefix

	handshakePayload, chatKey, err := identity.InitiateKeyExchange(userA, secretA, userB)
	if err != nil {
		panic(err)
	}
	_ = handshakePayload

	fmt.Println(userAPrefix, "Hanshake initialized!")
	fmt.Println(userAPrefix, "Chat key:", hex.EncodeToString(chatKey))
	fmt.Println("everything works!!!")
}
