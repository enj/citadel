package encryption

type EncryptionService interface {
	Decrypt(ciphertext []byte) (plaintext []byte, err error)
	Encrypt(plaintext []byte) (ciphertext []byte, err error)
}
