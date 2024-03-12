package plugin

import (
	"context"
	"crypto/rand"
	"io"
	"testing"

	"k8s.io/apiserver/pkg/storage/value/encrypt/aes"
)

func TestPluginFunctionality(t *testing.T) {
	aesKey := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, aesKey); err != nil {
		t.Fatal(err)
	}

	service := New(string(aesKey), "", "/tmp/socket.sock")

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
		res, err := service.Encrypt(context.TODO(), &EncryptRequest{
			Plain: []byte(txt),
		})
		if err != nil {
			t.Fatal(err)
		}
		outCiphers[i] = res.GetCipher()
		t.Logf("[%d] Cipher(%q) is:\n%q, len(cipher): %d", i+1, txt, res.GetCipher(), len(res.GetCipher()))
	}

	for i, enc := range outCiphers {
		res, err := service.Decrypt(context.TODO(), &DecryptRequest{
			Cipher: enc,
		})
		if err != nil {
			t.Fatal(err)
		}

		t.Logf("[%d] Decrypted cipher: %q", i+1, res.GetPlain())
		if inpTestStrings[i] != string(res.GetPlain()) {
			t.Fatalf("[%d] %q decrypted to %q, but %q was expected, len(txt): %d", i+1, enc, res.GetPlain(), inpTestStrings[i], len(res.GetPlain()))
		}
	}

}
