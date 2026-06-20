package identity

import (
	"github.com/slipe-fun/skid-v3/internal/crypto"
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
