package plugin

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"io"

	"google.golang.org/api/cloudkms/v1"
)

type LocalAESKMSService struct {
	aesKeyPhrase string
	aesBlock     cipher.Block
	gcmInstance  cipher.AEAD
}

func (l *LocalAESKMSService) start() error {
	aesBlock, err := aes.NewCipher([]byte(l.aesKeyPhrase))
	if err != nil {
		return err
	}

	gcmInstance, err := cipher.NewGCM(aesBlock)
	if err != nil {
		return err
	}

	l.aesBlock = aesBlock
	l.gcmInstance = gcmInstance

	return nil
}

func (l *LocalAESKMSService) encrypt(value []byte) ([]byte, error) {
	nonce := make([]byte, l.gcmInstance.NonceSize())
	_, _ = io.ReadFull(rand.Reader, nonce)

	cipheredText := l.gcmInstance.Seal(nil, nonce, value, nil)
	return cipheredText, nil
}

func (l *LocalAESKMSService) decrypt(ciphered []byte) ([]byte, error) {
	gcmInstance, err := cipher.NewGCM(l.aesBlock)
	if err != nil {
		return nil, err
	}

	nonceSize := l.gcmInstance.NonceSize()
	nonce, cipheredText := ciphered[:nonceSize], ciphered[nonceSize:]

	originalText, err := gcmInstance.Open(nil, nonce, cipheredText, nil)
	if err != nil {
		return nil, err
	}
	return originalText, nil
}

func NewLocalAESKMSService(key string) *LocalAESKMSService {
	l := &LocalAESKMSService{
		aesKeyPhrase: key,
	}
	err := l.start()
	if err != nil {
		panic(err)
	}
	return l
}

func (l *LocalAESKMSService) Encrypt(req *cloudkms.EncryptRequest) (*cloudkms.EncryptResponse, error) {
	encryptedBytes, err := l.encrypt([]byte(req.Plaintext))
	if err != nil {
		return nil, err
	}

	res := &cloudkms.EncryptResponse{
		Ciphertext: string(encryptedBytes),
	}
	return res, nil
}

func (l *LocalAESKMSService) Decrypt(req *cloudkms.DecryptRequest) (*cloudkms.DecryptResponse, error) {
	decryptedBytes, err := l.decrypt([]byte(req.Ciphertext))
	if err != nil {
		return nil, err
	}

	res := &cloudkms.DecryptResponse{
		Plaintext: string(decryptedBytes),
	}
	return res, nil
}
