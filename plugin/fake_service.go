package plugin

import (
	"crypto/aes"
	"crypto/cipher"

	"google.golang.org/api/cloudkms/v1"
)

type LocalAESKMSService struct {
	aesKeyPhrase string
	aesBlock     cipher.Block
}

func (l *LocalAESKMSService) start() error {
	aesBlock, err := aes.NewCipher([]byte(l.aesKeyPhrase))
	if err != nil {
		return err
	}

	l.aesBlock = aesBlock
	return nil
}

func (l *LocalAESKMSService) encrypt(plainText []byte) ([]byte, error) {
	encText := make([]byte, len(plainText))
	l.aesBlock.Encrypt(encText, plainText)
	return encText, nil
}

func (l *LocalAESKMSService) decrypt(encText []byte) ([]byte, error) {
	plainText := make([]byte, len(encText))
	l.aesBlock.Decrypt(plainText, encText)
	return plainText, nil
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
