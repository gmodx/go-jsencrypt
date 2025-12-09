package jsencrypt

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"strings"
)

// JSEncrypt is a Go implementation of the JSEncrypt library.
type JSEncrypt struct {
	privateKey       *rsa.PrivateKey
	publicKey        *rsa.PublicKey
	DefaultKeySize   int
	DefaultPublicExp string // Not used in Go's rsa.GenerateKey (fixed to 65537 usually), kept for API compatibility
	Log              bool
}

// NewJSEncrypt creates a new JSEncrypt instance.
func NewJSEncrypt() *JSEncrypt {
	return &JSEncrypt{
		DefaultKeySize: 1024,
	}
}

// SetKey sets the RSA key. It accepts a PEM encoded string.
// It tries to parse it as a private key first, then as a public key.
func (j *JSEncrypt) SetKey(keyStr string) error {
	// Simple cleanup to handle some formatting issues if any
	keyStr = strings.TrimSpace(keyStr)

	block, _ := pem.Decode([]byte(keyStr))
	if block == nil {
		// Try to handle keys without headers or just base64
		// But for now, let's assume valid PEM or at least try to Wrap it if it looks like base64?
		// Given Go's strictness, standard PEM is preferred.
		// If fails, we return error.
		return errors.New("failed to parse PEM block")
	}

	// 1. Try PKCS#1 Private Key
	if priv, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		j.privateKey = priv
		j.publicKey = &priv.PublicKey
		return nil
	}

	// 2. Try PKCS#8 Private Key
	if key, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
		if priv, ok := key.(*rsa.PrivateKey); ok {
			j.privateKey = priv
			j.publicKey = &priv.PublicKey
			return nil
		}
	}

	// 3. Try PKIX Public Key
	if pub, err := x509.ParsePKIXPublicKey(block.Bytes); err == nil {
		if rsaPub, ok := pub.(*rsa.PublicKey); ok {
			j.publicKey = rsaPub
			return nil
		}
	}

	// 4. Try PKCS#1 Public Key
	if pub, err := x509.ParsePKCS1PublicKey(block.Bytes); err == nil {
		j.publicKey = pub
		return nil
	}

	return errors.New("failed to parse key")
}

// SetPrivateKey sets the private key.
func (j *JSEncrypt) SetPrivateKey(privKeyStr string) error {
	return j.SetKey(privKeyStr)
}

// SetPublicKey sets the public key.
func (j *JSEncrypt) SetPublicKey(pubKeyStr string) error {
	return j.SetKey(pubKeyStr)
}

// getKey ensures a key exists, generating one if necessary.
func (j *JSEncrypt) getKey() (*rsa.PrivateKey, error) {
	if j.privateKey != nil {
		return j.privateKey, nil
	}
	// Generate key
	priv, err := rsa.GenerateKey(rand.Reader, j.DefaultKeySize)
	if err != nil {
		return nil, err
	}
	j.privateKey = priv
	j.publicKey = &priv.PublicKey
	return priv, nil
}

// Encrypt encrypts a string using the public key. Returns base64 encoded string.
func (j *JSEncrypt) Encrypt(str string) (string, error) {
	if j.publicKey == nil {
		// Attempt to generate or ensure key?
		// The TS library generates a key on getKey(), but Encrypt uses public components.
		// If we don't have a public key, we might have a private key which contains it.
		// If we have neither, the TS library generates a new pair.
		if _, err := j.getKey(); err != nil {
			return "", err
		}
	}

	encrypted, err := rsa.EncryptPKCS1v15(rand.Reader, j.publicKey, []byte(str))
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(encrypted), nil
}

// Decrypt decrypts a base64 encoded string using the private key.
func (j *JSEncrypt) Decrypt(str string) (string, error) {
	if j.privateKey == nil {
		// If no key, generate one (though decrypting with a new key won't work for existing data,
		// but for API consistency we generally check if key is set).
		// However, decrypting random stuff with a new key makes no sense.
		// But TS implementation does `this.getKey().decrypt(...)`.
		if _, err := j.getKey(); err != nil {
			return "", err
		}
	}

	decoded, err := base64.StdEncoding.DecodeString(str)
	if err != nil {
		return "", err
	}

	decrypted, err := rsa.DecryptPKCS1v15(rand.Reader, j.privateKey, decoded)
	if err != nil {
		return "", err
	}
	return string(decrypted), nil
}

// Sign signs a string using SHA256 and returns base64 encoded signature.
// This matches SignSha256 in TS.
func (j *JSEncrypt) Sign(str string) (string, error) {
	if j.privateKey == nil {
		if _, err := j.getKey(); err != nil {
			return "", err
		}
	}

	hashed := sha256.Sum256([]byte(str))
	signature, err := rsa.SignPKCS1v15(rand.Reader, j.privateKey, crypto.SHA256, hashed[:])
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(signature), nil
}

// Verify verifies a string against a base64 encoded signature using SHA256.
func (j *JSEncrypt) Verify(str, signature string) (bool, error) {
	if j.publicKey == nil {
		if _, err := j.getKey(); err != nil {
			return false, err
		}
	}

	sigBytes, err := base64.StdEncoding.DecodeString(signature)
	if err != nil {
		return false, err
	}

	hashed := sha256.Sum256([]byte(str))
	err = rsa.VerifyPKCS1v15(j.publicKey, crypto.SHA256, hashed[:], sigBytes)
	if err != nil {
		return false, nil // Signature not valid
	}
	return true, nil
}

// GetPrivateKey returns the PEM encoded private key.
func (j *JSEncrypt) GetPrivateKey() (string, error) {
	if _, err := j.getKey(); err != nil {
		return "", err
	}

	// Encode to PKCS#1
	privBytes := x509.MarshalPKCS1PrivateKey(j.privateKey)
	pemBlock := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: privBytes,
	}
	return string(pem.EncodeToMemory(pemBlock)), nil
}

// GetPublicKey returns the PEM encoded public key.
func (j *JSEncrypt) GetPublicKey() (string, error) {
	if j.publicKey == nil {
		if _, err := j.getKey(); err != nil {
			return "", err
		}
	}

	// Marshal PKIX
	pubBytes, err := x509.MarshalPKIXPublicKey(j.publicKey)
	if err != nil {
		return "", err
	}
	pemBlock := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubBytes,
	}
	return string(pem.EncodeToMemory(pemBlock)), nil
}
