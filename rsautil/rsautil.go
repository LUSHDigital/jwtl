package rsautil

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"log"
)

func UnsafelyGenerateKeyPair() (private []byte, public []byte, err error) {
	// Generate the key of length bits
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return
	}

	// Convert it to pem
	privateBlock := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	}
	b, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		log.Fatalln(err)
	}
	publicBlock := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: b,
	}
	return pem.EncodeToMemory(privateBlock), pem.EncodeToMemory(publicBlock), nil
}
