package jsencrypt

import (
	"encoding/json"
	"testing"
)

// Test keys for examples - using the working test keys from jsencrypt
var exampleTestKeys = struct {
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

// Test basic encryption/decryption examples
func TestExamples_BasicEncryptionDecryption(t *testing.T) {
	jsCrypt := NewJSEncrypt()
	err := jsCrypt.SetPrivateKey(exampleTestKeys.privateKey)
	if err != nil {
		t.Fatalf("Failed to set private key: %v", err)
	}
	err = jsCrypt.SetPublicKey(exampleTestKeys.publicKey)
	if err != nil {
		t.Fatalf("Failed to set public key: %v", err)
	}

	message := "Secret message"
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

// Test encrypt credentials example
func TestExamples_EncryptCredentials(t *testing.T) {
	jsCrypt := NewJSEncrypt()
	err := jsCrypt.SetPublicKey(exampleTestKeys.publicKey)
	if err != nil {
		t.Fatalf("Failed to set public key: %v", err)
	}

	credentials := map[string]string{
		"u": "john.doe",
		"p": "myPass123",
	}
	credentialsJSON, _ := json.Marshal(credentials)

	encrypted, err := jsCrypt.Encrypt(string(credentialsJSON))
	if err != nil {
		t.Fatalf("Encryption failed: %v", err)
	}
	if encrypted == "" {
		t.Fatal("Encrypted string is empty")
	}

	// Verify we can decrypt it
	jsCrypt2 := NewJSEncrypt()
	err = jsCrypt2.SetPrivateKey(exampleTestKeys.privateKey)
	if err != nil {
		t.Fatalf("Failed to set private key: %v", err)
	}

	decrypted, err := jsCrypt2.Decrypt(encrypted)
	if err != nil {
		t.Fatalf("Decryption failed: %v", err)
	}

	var decryptedCreds map[string]string
	err = json.Unmarshal([]byte(decrypted), &decryptedCreds)
	if err != nil {
		t.Fatalf("Failed to parse decrypted credentials: %v", err)
	}

	if decryptedCreds["u"] != "john.doe" {
		t.Errorf("Username doesn't match. Got %s, want john.doe", decryptedCreds["u"])
	}
}

// Test secure API communication example
func TestExamples_SecureAPICommunication(t *testing.T) {
	jsCrypt := NewJSEncrypt()
	err := jsCrypt.SetPublicKey(exampleTestKeys.publicKey)
	if err != nil {
		t.Fatalf("Failed to set public key: %v", err)
	}

	requestData := map[string]interface{}{
		"userId": 12345,
		"fields": []string{"name", "email", "preferences"},
	}
	requestJSON, _ := json.Marshal(requestData)

	encrypted, err := jsCrypt.Encrypt(string(requestJSON))
	if err != nil {
		t.Fatalf("Encryption failed: %v", err)
	}
	if encrypted == "" {
		t.Fatal("Encrypted string is empty")
	}

	// Decrypt
	jsCrypt2 := NewJSEncrypt()
	err = jsCrypt2.SetPrivateKey(exampleTestKeys.privateKey)
	if err != nil {
		t.Fatalf("Failed to set private key: %v", err)
	}

	decrypted, err := jsCrypt2.Decrypt(encrypted)
	if err != nil {
		t.Fatalf("Decryption failed: %v", err)
	}

	var decryptedData map[string]interface{}
	err = json.Unmarshal([]byte(decrypted), &decryptedData)
	if err != nil {
		t.Fatalf("Failed to parse decrypted data: %v", err)
	}

	if int(decryptedData["userId"].(float64)) != 12345 {
		t.Errorf("UserId doesn't match")
	}
}

// Test document signing example
func TestExamples_DocumentSigning(t *testing.T) {
	jsCrypt := NewJSEncrypt()
	err := jsCrypt.SetPrivateKey(exampleTestKeys.privateKey)
	if err != nil {
		t.Fatalf("Failed to set private key: %v", err)
	}

	documentContent := "This is a digital contract between parties..."
	signature, err := jsCrypt.Sign(documentContent)
	if err != nil {
		t.Fatalf("Signing failed: %v", err)
	}
	if signature == "" {
		t.Fatal("Signature is empty")
	}

	// Verify signature
	jsCrypt2 := NewJSEncrypt()
	err = jsCrypt2.SetPublicKey(exampleTestKeys.publicKey)
	if err != nil {
		t.Fatalf("Failed to set public key: %v", err)
	}

	valid, err := jsCrypt2.Verify(documentContent, signature)
	if err != nil {
		t.Fatalf("Verification failed: %v", err)
	}
	if !valid {
		t.Error("Signature verification failed")
	}

	// Test tampered document
	valid, err = jsCrypt2.Verify(documentContent+"modified", signature)
	if err == nil && valid {
		t.Error("Should have failed verification for tampered document")
	}
}

// Test secure file upload with chunking
func TestExamples_SecureFileUpload(t *testing.T) {
	jsCrypt := NewJSEncrypt()
	err := jsCrypt.SetPublicKey(exampleTestKeys.publicKey)
	if err != nil {
		t.Fatalf("Failed to set public key: %v", err)
	}

	fileContent := "This is a test file content that needs to be encrypted before upload."
	chunkSize := 50 // Smaller chunks for testing

	// Split into chunks and encrypt
	var encryptedChunks []string
	for i := 0; i < len(fileContent); i += chunkSize {
		end := i + chunkSize
		if end > len(fileContent) {
			end = len(fileContent)
		}
		chunk := fileContent[i:end]
		encrypted, err := jsCrypt.Encrypt(chunk)
		if err != nil {
			t.Fatalf("Failed to encrypt chunk: %v", err)
		}
		encryptedChunks = append(encryptedChunks, encrypted)
	}

	if len(encryptedChunks) == 0 {
		t.Fatal("No encrypted chunks created")
	}

	// Decrypt chunks
	jsCrypt2 := NewJSEncrypt()
	err = jsCrypt2.SetPrivateKey(exampleTestKeys.privateKey)
	if err != nil {
		t.Fatalf("Failed to set private key: %v", err)
	}

	var decryptedChunks []string
	for _, encryptedChunk := range encryptedChunks {
		decrypted, err := jsCrypt2.Decrypt(encryptedChunk)
		if err != nil {
			t.Fatalf("Failed to decrypt chunk: %v", err)
		}
		decryptedChunks = append(decryptedChunks, decrypted)
	}

	reconstructedContent := ""
	for _, chunk := range decryptedChunks {
		reconstructedContent += chunk
	}

	if reconstructedContent != fileContent {
		t.Errorf("Reconstructed content doesn't match. Got %s, want %s", reconstructedContent, fileContent)
	}
}

// Test license key generation and validation
func TestExamples_LicenseKeyGeneration(t *testing.T) {
	jsCrypt := NewJSEncrypt()
	err := jsCrypt.SetPrivateKey(exampleTestKeys.privateKey)
	if err != nil {
		t.Fatalf("Failed to set private key: %v", err)
	}

	licenseData := map[string]interface{}{
		"customerName": "Acme Corporation",
		"productName":  "Super Software Pro",
		"version":      "2.0",
		"maxUsers":     100,
	}
	licenseJSON, _ := json.Marshal(licenseData)

	encryptedLicense, err := jsCrypt.Encrypt(string(licenseJSON))
	if err != nil {
		t.Fatalf("Failed to encrypt license: %v", err)
	}
	if encryptedLicense == "" {
		t.Fatal("Encrypted license is empty")
	}

	// Validate license
	jsCrypt2 := NewJSEncrypt()
	err = jsCrypt2.SetPublicKey(exampleTestKeys.publicKey)
	if err != nil {
		t.Fatalf("Failed to set public key: %v", err)
	}

	// Note: In real implementation, you'd decrypt and validate
	// For testing, we just verify encryption/decryption works
	jsCrypt3 := NewJSEncrypt()
	err = jsCrypt3.SetPrivateKey(exampleTestKeys.privateKey)
	if err != nil {
		t.Fatalf("Failed to set private key: %v", err)
	}

	decryptedLicense, err := jsCrypt3.Decrypt(encryptedLicense)
	if err != nil {
		t.Fatalf("Failed to decrypt license: %v", err)
	}

	var license map[string]interface{}
	err = json.Unmarshal([]byte(decryptedLicense), &license)
	if err != nil {
		t.Fatalf("Failed to parse license: %v", err)
	}

	if license["customerName"] != "Acme Corporation" {
		t.Errorf("Customer name doesn't match")
	}
}

// Test browser storage encryption
func TestExamples_BrowserStorageEncryption(t *testing.T) {
	jsCrypt := NewJSEncrypt()
	err := jsCrypt.SetPublicKey(exampleTestKeys.publicKey)
	if err != nil {
		t.Fatalf("Failed to set public key: %v", err)
	}

	userData := map[string]interface{}{
		"userId":       12345,
		"email":        "user@example.com",
		"sessionToken": "abc123xyz",
	}
	userDataJSON, _ := json.Marshal(userData)

	encrypted, err := jsCrypt.Encrypt(string(userDataJSON))
	if err != nil {
		t.Fatalf("Encryption failed: %v", err)
	}
	if encrypted == "" {
		t.Fatal("Encrypted data is empty")
	}

	// Decrypt
	jsCrypt2 := NewJSEncrypt()
	err = jsCrypt2.SetPrivateKey(exampleTestKeys.privateKey)
	if err != nil {
		t.Fatalf("Failed to set private key: %v", err)
	}

	decrypted, err := jsCrypt2.Decrypt(encrypted)
	if err != nil {
		t.Fatalf("Decryption failed: %v", err)
	}

	var retrievedData map[string]interface{}
	err = json.Unmarshal([]byte(decrypted), &retrievedData)
	if err != nil {
		t.Fatalf("Failed to parse decrypted data: %v", err)
	}

	if int(retrievedData["userId"].(float64)) != 12345 {
		t.Errorf("UserId doesn't match")
	}
}

// Test error handling and validation
func TestExamples_ErrorHandling(t *testing.T) {
	jsCrypt := NewJSEncrypt()
	err := jsCrypt.SetPublicKey(exampleTestKeys.publicKey)
	if err != nil {
		t.Fatalf("Failed to set public key: %v", err)
	}

	// Test with valid data
	testData := "test data"
	encrypted, err := jsCrypt.Encrypt(testData)
	if err != nil {
		t.Fatalf("Encryption failed: %v", err)
	}
	if encrypted == "" {
		t.Fatal("Encrypted string is empty")
	}

	// Test validation
	jsCrypt2 := NewJSEncrypt()
	err = jsCrypt2.SetPrivateKey(exampleTestKeys.privateKey)
	if err != nil {
		t.Fatalf("Failed to set private key: %v", err)
	}

	decrypted, err := jsCrypt2.Decrypt(encrypted)
	if err != nil {
		t.Fatalf("Decryption failed: %v", err)
	}

	if decrypted != testData {
		t.Errorf("Decrypted data doesn't match. Got %s, want %s", decrypted, testData)
	}
}
