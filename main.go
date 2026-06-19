package main

import (
	"fmt"

	"github.com/slipe-fun/skid-v3/pkg/identity"
)

func main() {
	user, secret, err := identity.GenerateIdentity()
	if err != nil {
		panic(err)
	}
	defer secret.Wipe()

	userID := "8MNQQ2ky6YVTCT"

	restoredUser := identity.User{
		ID: userID,
		PublicKeys: identity.PublicKeys{
			MlKem768: user.PublicKeys.MlKem768,
			X448:     user.PublicKeys.X448,
			Ed448:    user.PublicKeys.Ed448,
		},
	}
	_ = restoredUser

	restoredSecret, err := identity.NewSecretKeys(secret.MlKem768, secret.X448, secret.Ed448)
	if err != nil {
		panic(err)
	}
	defer restoredSecret.Wipe()

	fmt.Println("everything works")
}
