package plugin

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"

	"google.golang.org/api/cloudkms/v1"
)

type LocalAESKMSService struct {
	aesKeyPhrase string
	aead         cipher.AEAD
	keyId        string
}

func (l *LocalAESKMSService) start() error {
	aesBlock, err := aes.NewCipher([]byte(l.aesKeyPhrase))
	if err != nil {
		return err
	}

	g, err := cipher.NewGCM(aesBlock)
	if err != nil {
		return err
	}
	l.aead = g
	return nil
}

func (l *LocalAESKMSService) encrypt(plaintext []byte) ([]byte, error) {
	nonceSize := l.aead.NonceSize()

	result := make([]byte, nonceSize+l.aead.Overhead()+len(plaintext))
	n, err := rand.Read(result[:nonceSize])
	if err != nil {
		return nil, err
	}
	if n != nonceSize {
		return nil, fmt.Errorf("unable to read sufficient random bytes")
	}

	cipherText := l.aead.Seal(result[nonceSize:nonceSize], result[:nonceSize], plaintext, nil)

	return result[:nonceSize+len(cipherText)], nil
}

func (l *LocalAESKMSService) decrypt(ciphertext []byte) ([]byte, error) {
	nonceSize := l.aead.NonceSize()
	data := ciphertext

	return l.aead.Open(nil, data[:nonceSize], data[nonceSize:], nil)
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
		Name:       l.keyId,
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
