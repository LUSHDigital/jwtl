package unsafersa

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
)

const (
	// KeySize is the standard size of an RSA key in bits.
	KeySize = 2048
)

// GenerateUnsafeKeyPair will generate a public and private RSA key and return it in PEM format as bytes.
func GenerateUnsafeKeyPair() (private []byte, public []byte, err error) {
	// Generate the key of length bits
	key, err := rsa.GenerateKey(rand.Reader, KeySize)
	if err != nil {
		return
	}
	// Convert the RSA key to the PEM format.
	privateBlock := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	}
	b, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		return nil, nil, err
	}
	publicBlock := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: b,
	}
	return pem.EncodeToMemory(privateBlock), pem.EncodeToMemory(publicBlock), nil
}
