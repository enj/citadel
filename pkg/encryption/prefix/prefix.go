package prefix

import (
	"bytes"
	"errors"
	"strings"

	"github.com/enj/citadel/pkg/encryption"
)

const (
	kmsName = "ck"
	sep     = ":"
)

func NewPrefixEncryption(mode encryption.EncryptionMode, delegate encryption.EncryptionService) encryption.EncryptionService {
	modeStr := strings.Join([]string{kmsName, mode.Name, mode.Version}, sep)
	return &prefixEncryption{
		prefix:   []byte(sep + modeStr + sep),
		delegate: delegate,
	}
}

var errInvalidPrefix = errors.New("invalid encryption mode prefix")

type prefixEncryption struct {
	prefix   []byte
	delegate encryption.EncryptionService
}

func (p *prefixEncryption) Decrypt(ciphertext []byte) ([]byte, error) {
	if !bytes.HasPrefix(ciphertext, p.prefix) {
		return nil, errInvalidPrefix
	}
	return p.delegate.Decrypt(ciphertext[len(p.prefix):])
}

func (p *prefixEncryption) Encrypt(plaintext []byte) ([]byte, error) {
	result, err := p.delegate.Encrypt(plaintext)
	if err != nil {
		return nil, err
	}
	prefixedData := make([]byte, len(p.prefix), len(p.prefix)+len(result))
	copy(prefixedData, p.prefix)
	return append(prefixedData, result...), nil
}
