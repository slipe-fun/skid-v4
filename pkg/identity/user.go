package identity

import "runtime"

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
	for i := range s.MlKem768 {
		s.MlKem768[i] = 0
	}
	for i := range s.X448 {
		s.X448[i] = 0
	}
	for i := range s.Ed448 {
		s.Ed448[i] = 0
	}

	runtime.KeepAlive(s.MlKem768)
	runtime.KeepAlive(s.X448)
	runtime.KeepAlive(s.Ed448)
}
