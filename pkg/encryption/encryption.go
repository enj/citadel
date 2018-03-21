package encryption

import (
	"fmt"

	"github.com/enj/kms/pkg/kek"
)

type EncryptionService interface {
	Decrypt(ciphertext []byte) (plaintext []byte, err error)
	Encrypt(plaintext []byte) (ciphertext []byte, err error)
}

type EncryptionHandler func(kek.KeyEncryptionKeyService) (EncryptionService, error)

var _ fmt.Stringer = EncryptionMode{}

type EncryptionMode struct {
	Name    string
	Version string
	Handler EncryptionHandler
}

func (e EncryptionMode) String() string {
	return e.Name
}
