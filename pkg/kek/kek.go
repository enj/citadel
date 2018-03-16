package kek

import "os/exec"

type KeyEncryptionKeyService interface {
	Get() (kek []byte, err error)
}

func NewCommandKEKService(cmd string) (KeyEncryptionKeyService, error) {
	kek, err := exec.Command("sh", "-c", cmd).Output() // TODO pass env vars?
	if err != nil {
		return nil, err
	}
	return &cmdKEK{kek: kek}, nil
}

// TODO implement timeout
type cmdKEK struct {
	kek []byte
}

func (c *cmdKEK) Get() ([]byte, error) {
	return c.kek, nil
}
