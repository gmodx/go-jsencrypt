package jsencrypt

import (
	"testing"
)

// Test keys for simple examples
var simpleTestKeys = struct {
	publicKey  string
	privateKey string
}{
	publicKey: `-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAtKrsFSnzYl19m5wTwYdu
/r1UVZJV+zkAFud6+XTInAy8HbCR9n59H9+54P+Af/fUE6rvEPc4H09Z63vQzIGM
iL6GlqzMmptv/KRDIhj7Mk3MXomvEVfUsXrz5IpO0lf6NSeGhz4PGZUkHZ30VRx3
Jd/a0KIhgftZHxzmMsh8iB/n781B18pCP2eOPTF+5gRCaW+0fVPBlb/mBlg8MJrd
ScGCAReQ9NfTq8slJ0aO1NWaaRRANPQcCMljnTIK1ssyXBaSHKfoWeGx141mWMRx
/LxyZ13Zc3lqgmICiKFqMrQl5UeV1IUXYpj5hO9f60LGpZVHDqqo/JdF3+VAheaf
QwIDAQAB
-----END PUBLIC KEY-----`,
	privateKey: `-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEAtKrsFSnzYl19m5wTwYdu/r1UVZJV+zkAFud6+XTInAy8HbCR
9n59H9+54P+Af/fUE6rvEPc4H09Z63vQzIGMiL6GlqzMmptv/KRDIhj7Mk3MXomv
EVfUsXrz5IpO0lf6NSeGhz4PGZUkHZ30VRx3Jd/a0KIhgftZHxzmMsh8iB/n781B
18pCP2eOPTF+5gRCaW+0fVPBlb/mBlg8MJrdScGCAReQ9NfTq8slJ0aO1NWaaRRA
NPQcCMljnTIK1ssyXBaSHKfoWeGx141mWMRx/LxyZ13Zc3lqgmICiKFqMrQl5UeV
1IUXYpj5hO9f60LGpZVHDqqo/JdF3+VAheafQwIDAQABAoIBAQCS/++PWM7bXk5x
apD4ioXZZ5tS9PpYqoxUFoyMpGUF86asUZqyAUE1ygen9rxLYw5/4jkaiMx1TU9Q
tzGw9Eewi7Veq8LemVKJMe4dtE3PJFYBJe34IorAzdXcQlzX8RV4YmynZetLWXpF
Ttwa1Ept2rJjx0eURzrAgfcbot0Qs+c8bB0qnGC67PoL3DyYg8vX5PDmiiA2VZMG
EylVQS09toJn5ReaKCtjxJb/XFQjBeSP0xLjvZZftGDJgpwmmi7Sy/zAZoF4+7wf
8nihXk4ZfYC+beBj5U9pcUcs6LdNobUofWFRLSjueseRQBI0sKUslr3Ye4zhkrWM
CDnsSxBhAoGBANi0spS/Mc6xH1189mR7dJV9gy7KkGxheAstwCJr7WzbXqglhFm2
SvY9hrpE9OYWir5EqX6jM6VipSobTn0RpCsYUC/J1ISMyEA5UkPLP4jHQw6UUDN2
1fNAXffEyuju5ShP9Mk2unZstlUweKlFF7d1k7YAzWDIKnF6bOL06YC9AoGBANVt
XM4OH0zw8M97W04WwYGoa5s1Y5JYc4RMV200cr3iONVfLZgSP8thP1qPuoMM3OJg
Bqe6MRmo/VXhgVvpke04ZJ83LSz/SoqfVRNwxuCHqp3beJQPxrAp1d/L7Ey7f41U
QBE8pibFb8bbgOTUW5iyZbg7lLS8nghsn+BqYp//AoGBAJO/574o+YGOG+92wttR
nPRLhgSCEaQDdIBSqhwN7+v3SXtlUO6FrmhjHJelaj/yAJinYdS42v6Y2jlyMrpt
K7xCMHHUrzPMdL/tFRyp1+Ce0yZ+kov0Kv1V1nuWzi2wq8cndKM30Dvr9QjyKmJm
fDwWSyadN2oUL3P9X34CM64VAoGAbajAW1skN/tAL8r48dl9WWo4x8mZvJLX36z9
6q1dGzVF8FPz8EPIJW51B8n7keQlBedC5CElo0KRz/OK7LfI87La+Hd4LbuKCEmv
g8qZVLpALtWaUbD9bHxCWLfFVPOtqOcV+AVKdXdSZEFaK7j0yzM2Un/Ce07CgB+X
0c23mO8CgYAOqnUR/uPIzkvj/eIbO7pnhHoKZ4Ji2TrIBqjskzaFd0Tox9i3SWKa
cRdQciRIT1wkMdywnHFrJT1rwYXxcgfQXAku/vnYqAfvIzY7TyoL3pWX55O0Zrs7
05R9mA5TZmzUU9m/PzUrRjasOGYSKkCz4Y2qGlrKI3H0aE+p+R56kQ==
-----END RSA PRIVATE KEY-----`,
}

// Test basic text encryption - simplified version
func TestExamplesSimple_BasicTextEncryption(t *testing.T) {
	jsCrypt := NewJSEncrypt()
	err := jsCrypt.SetPrivateKey(simpleTestKeys.privateKey)
	if err != nil {
		t.Fatalf("Failed to set private key: %v", err)
	}
	err = jsCrypt.SetPublicKey(simpleTestKeys.publicKey)
	if err != nil {
		t.Fatalf("Failed to set public key: %v", err)
	}

	message := "Hello World"
	encrypted, err := jsCrypt.Encrypt(message)
	if err != nil {
		t.Fatalf("Encryption failed: %v", err)
	}
	if encrypted == "" {
		t.Fatal("Encrypted string is empty")
	}

	decrypted, err := jsCrypt.Decrypt(encrypted)
	if err != nil {
		t.Fatalf("Decryption failed: %v", err)
	}
	if decrypted != message {
		t.Errorf("Decrypted message doesn't match. Got %s, want %s", decrypted, message)
	}
}

// Test encrypt credentials - simplified version
func TestExamplesSimple_EncryptCredentials(t *testing.T) {
	jsCrypt := NewJSEncrypt()
	err := jsCrypt.SetPublicKey(simpleTestKeys.publicKey)
	if err != nil {
		t.Fatalf("Failed to set public key: %v", err)
	}

	credentials := `{"u":"john","p":"pass"}`
	encrypted, err := jsCrypt.Encrypt(credentials)
	if err != nil {
		t.Fatalf("Encryption failed: %v", err)
	}
	if encrypted == "" {
		t.Fatal("Encrypted string is empty")
	}

	jsCrypt2 := NewJSEncrypt()
	err = jsCrypt2.SetPrivateKey(simpleTestKeys.privateKey)
	if err != nil {
		t.Fatalf("Failed to set private key: %v", err)
	}

	decrypted, err := jsCrypt2.Decrypt(encrypted)
	if err != nil {
		t.Fatalf("Decryption failed: %v", err)
	}
	if decrypted != credentials {
		t.Errorf("Decrypted credentials don't match. Got %s, want %s", decrypted, credentials)
	}
}

// Test API data encryption - simplified version
func TestExamplesSimple_APIData(t *testing.T) {
	jsCrypt := NewJSEncrypt()
	err := jsCrypt.SetPublicKey(simpleTestKeys.publicKey)
	if err != nil {
		t.Fatalf("Failed to set public key: %v", err)
	}

	apiData := `{"id":123,"data":"test"}`
	encrypted, err := jsCrypt.Encrypt(apiData)
	if err != nil {
		t.Fatalf("Encryption failed: %v", err)
	}
	if encrypted == "" {
		t.Fatal("Encrypted string is empty")
	}

	jsCrypt2 := NewJSEncrypt()
	err = jsCrypt2.SetPrivateKey(simpleTestKeys.privateKey)
	if err != nil {
		t.Fatalf("Failed to set private key: %v", err)
	}

	decrypted, err := jsCrypt2.Decrypt(encrypted)
	if err != nil {
		t.Fatalf("Decryption failed: %v", err)
	}
	if decrypted != apiData {
		t.Errorf("Decrypted API data doesn't match. Got %s, want %s", decrypted, apiData)
	}
}

// Test document signing workflow - simplified version
func TestExamplesSimple_DocumentSigning(t *testing.T) {
	jsCrypt := NewJSEncrypt()
	err := jsCrypt.SetPrivateKey(simpleTestKeys.privateKey)
	if err != nil {
		t.Fatalf("Failed to set private key: %v", err)
	}

	docHash := "abc123"
	signature, err := jsCrypt.Sign(docHash)
	if err != nil {
		t.Fatalf("Signing failed: %v", err)
	}
	if signature == "" {
		t.Fatal("Signature is empty")
	}

	// Verify signature
	jsCrypt2 := NewJSEncrypt()
	err = jsCrypt2.SetPublicKey(simpleTestKeys.publicKey)
	if err != nil {
		t.Fatalf("Failed to set public key: %v", err)
	}

	valid, err := jsCrypt2.Verify(docHash, signature)
	if err != nil {
		t.Fatalf("Verification failed: %v", err)
	}
	if !valid {
		t.Error("Signature verification failed")
	}
}

// Test chunked data - simplified version
func TestExamplesSimple_ChunkedData(t *testing.T) {
	jsCrypt := NewJSEncrypt()
	err := jsCrypt.SetPrivateKey(simpleTestKeys.privateKey)
	if err != nil {
		t.Fatalf("Failed to set private key: %v", err)
	}
	err = jsCrypt.SetPublicKey(simpleTestKeys.publicKey)
	if err != nil {
		t.Fatalf("Failed to set public key: %v", err)
	}

	chunks := []string{"chunk1", "chunk2", "chunk3"}
	var encryptedChunks []string
	for _, chunk := range chunks {
		encrypted, err := jsCrypt.Encrypt(chunk)
		if err != nil {
			t.Fatalf("Encryption failed for chunk: %v", err)
		}
		if encrypted == "" {
			t.Fatal("Encrypted chunk is empty")
		}
		encryptedChunks = append(encryptedChunks, encrypted)
	}

	var decryptedChunks []string
	for _, encryptedChunk := range encryptedChunks {
		decrypted, err := jsCrypt.Decrypt(encryptedChunk)
		if err != nil {
			t.Fatalf("Decryption failed for chunk: %v", err)
		}
		decryptedChunks = append(decryptedChunks, decrypted)
	}

	if len(decryptedChunks) != len(chunks) {
		t.Errorf("Decrypted chunks count doesn't match. Got %d, want %d", len(decryptedChunks), len(chunks))
	}

	for i, decrypted := range decryptedChunks {
		if decrypted != chunks[i] {
			t.Errorf("Chunk %d doesn't match. Got %s, want %s", i, decrypted, chunks[i])
		}
	}
}

// Test storage data encryption - simplified version
func TestExamplesSimple_StorageData(t *testing.T) {
	jsCrypt := NewJSEncrypt()
	err := jsCrypt.SetPublicKey(simpleTestKeys.publicKey)
	if err != nil {
		t.Fatalf("Failed to set public key: %v", err)
	}

	storageData := `{"key":"value"}`
	encrypted, err := jsCrypt.Encrypt(storageData)
	if err != nil {
		t.Fatalf("Encryption failed: %v", err)
	}
	if encrypted == "" {
		t.Fatal("Encrypted string is empty")
	}

	jsCrypt2 := NewJSEncrypt()
	err = jsCrypt2.SetPrivateKey(simpleTestKeys.privateKey)
	if err != nil {
		t.Fatalf("Failed to set private key: %v", err)
	}

	decrypted, err := jsCrypt2.Decrypt(encrypted)
	if err != nil {
		t.Fatalf("Decryption failed: %v", err)
	}
	if decrypted != storageData {
		t.Errorf("Decrypted storage data doesn't match. Got %s, want %s", decrypted, storageData)
	}
}

// Test encryption validation - simplified version
func TestExamplesSimple_EncryptionValidation(t *testing.T) {
	jsCrypt := NewJSEncrypt()
	err := jsCrypt.SetPublicKey(simpleTestKeys.publicKey)
	if err != nil {
		t.Fatalf("Failed to set public key: %v", err)
	}

	data := "test data"
	encrypted, err := jsCrypt.Encrypt(data)
	if err != nil {
		t.Fatalf("Encryption failed: %v", err)
	}
	if encrypted == "" {
		t.Fatal("Encrypted string is empty")
	}

	jsCrypt2 := NewJSEncrypt()
	err = jsCrypt2.SetPrivateKey(simpleTestKeys.privateKey)
	if err != nil {
		t.Fatalf("Failed to set private key: %v", err)
	}
	err = jsCrypt2.SetPublicKey(simpleTestKeys.publicKey)
	if err != nil {
		t.Fatalf("Failed to set public key: %v", err)
	}

	decrypted, err := jsCrypt2.Decrypt(encrypted)
	if err != nil {
		t.Fatalf("Decryption failed: %v", err)
	}
	if decrypted != data {
		t.Errorf("Decrypted data doesn't match. Got %s, want %s", decrypted, data)
	}
}

// Test security features - simplified version
func TestExamplesSimple_SecurityFeatures(t *testing.T) {
	jsCrypt := NewJSEncrypt()
	err := jsCrypt.SetPrivateKey(simpleTestKeys.privateKey)
	if err != nil {
		t.Fatalf("Failed to set private key: %v", err)
	}
	err = jsCrypt.SetPublicKey(simpleTestKeys.publicKey)
	if err != nil {
		t.Fatalf("Failed to set public key: %v", err)
	}

	secureData := "secure123"
	encrypted, err := jsCrypt.Encrypt(secureData)
	if err != nil {
		t.Fatalf("Encryption failed: %v", err)
	}
	if encrypted == "" {
		t.Fatal("Encrypted string is empty")
	}

	decrypted, err := jsCrypt.Decrypt(encrypted)
	if err != nil {
		t.Fatalf("Decryption failed: %v", err)
	}
	if decrypted != secureData {
		t.Errorf("Decrypted data doesn't match. Got %s, want %s", decrypted, secureData)
	}
}

