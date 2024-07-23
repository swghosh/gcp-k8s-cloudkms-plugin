package plugin

import (
	"crypto/rand"
	"io"
	"testing"

	"k8s.io/apiserver/pkg/storage/value/encrypt/aes"

	"google.golang.org/api/cloudkms/v1"
)

func TestPluginFunctionality(t *testing.T) {
	aesKey := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, aesKey); err != nil {
		t.Fatal(err)
	}
	_ = aesKey

	service := NewLocalAESKMSService("passphrasewhichneedstobe32bytes!")

	k, err := aes.GenerateKey(32)
	if err != nil {
		t.Fatal(err)
	}
	_ = k

	inpTestStrings := []string{
		"################",
		"ArbitrarySizeObjectsWorkToo",
		string(k),
	}
	outCiphers := make([][]byte, len(inpTestStrings))

	for i, txt := range inpTestStrings {
		res, err := service.Encrypt(&cloudkms.EncryptRequest{
			Plaintext: txt,
		})
		if err != nil {
			t.Fatal(err)
		}
		outCiphers[i] = []byte(res.Ciphertext)
		t.Logf("[%d] Cipher(%q) is:\n%q, len(cipher): %d", i+1, txt, res.Ciphertext, len(res.Ciphertext))
	}

	for i, enc := range outCiphers {
		res, err := service.Decrypt(&cloudkms.DecryptRequest{
			Ciphertext: string(outCiphers[i]),
		})
		if err != nil {
			t.Fatal(err)
		}

		t.Logf("[%d] Decrypted cipher: %q", i+1, res.Plaintext)
		if inpTestStrings[i] != string(res.Plaintext) {
			t.Fatalf("[%d] %q decrypted to %q, but %q was expected, len(txt): %d", i+1, enc, res.Plaintext, inpTestStrings[i], len(res.Plaintext))
		}
	}

}
