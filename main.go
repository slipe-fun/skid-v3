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

	userID := "8MNQQ2ky6YVTCT"

	restoredUser := identity.User{
		ID: userID,
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

	handshakePayload, chatKey, err := identity.InitiateKeyExchange(userA, secretA, userB)
	if err != nil {
		panic(err)
	}
	_ = handshakePayload

	fmt.Println(hex.EncodeToString(chatKey))
	fmt.Println("everything works")
}
