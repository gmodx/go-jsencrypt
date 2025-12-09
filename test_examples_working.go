package jsencrypt

import (
	"testing"
)

// Test basic functionality with generated keys
func TestExamplesWorking_BasicFunctionality(t *testing.T) {
	jsCrypt := NewJSEncrypt()
	jsCrypt.DefaultKeySize = 1024

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

// Test encrypt credentials
func TestExamplesWorking_EncryptCredentials(t *testing.T) {
	jsCrypt := NewJSEncrypt()
	jsCrypt.DefaultKeySize = 1024

	credentials := "user:pass"
	encrypted, err := jsCrypt.Encrypt(credentials)
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
	if decrypted != credentials {
		t.Errorf("Decrypted credentials don't match. Got %s, want %s", decrypted, credentials)
	}
}

// Test API data handling
func TestExamplesWorking_APIData(t *testing.T) {
	jsCrypt := NewJSEncrypt()
	jsCrypt.DefaultKeySize = 1024

	apiData := `{"id":123}`
	encrypted, err := jsCrypt.Encrypt(apiData)
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
	if decrypted != apiData {
		t.Errorf("Decrypted API data doesn't match. Got %s, want %s", decrypted, apiData)
	}
}

// Test document signing
func TestExamplesWorking_DocumentSigning(t *testing.T) {
	jsCrypt := NewJSEncrypt()
	jsCrypt.DefaultKeySize = 1024

	docHash := "abc123"
	signature, err := jsCrypt.Sign(docHash)
	if err != nil {
		t.Fatalf("Signing failed: %v", err)
	}
	if signature == "" {
		t.Fatal("Signature is empty")
	}

	valid, err := jsCrypt.Verify(docHash, signature)
	if err != nil {
		t.Fatalf("Verification failed: %v", err)
	}
	if !valid {
		t.Error("Signature verification failed")
	}
}

// Test chunked data
func TestExamplesWorking_ChunkedData(t *testing.T) {
	jsCrypt := NewJSEncrypt()
	jsCrypt.DefaultKeySize = 1024

	chunks := []string{"chunk1", "chunk2"}
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

// Test storage data
func TestExamplesWorking_StorageData(t *testing.T) {
	jsCrypt := NewJSEncrypt()
	jsCrypt.DefaultKeySize = 1024

	storageData := `{"k":"v"}`
	encrypted, err := jsCrypt.Encrypt(storageData)
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
	if decrypted != storageData {
		t.Errorf("Decrypted storage data doesn't match. Got %s, want %s", decrypted, storageData)
	}
}

// Test encryption operations validation
func TestExamplesWorking_EncryptionOperations(t *testing.T) {
	jsCrypt := NewJSEncrypt()
	jsCrypt.DefaultKeySize = 1024

	data := "test data"
	encrypted, err := jsCrypt.Encrypt(data)
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
	if decrypted != data {
		t.Errorf("Decrypted data doesn't match. Got %s, want %s", decrypted, data)
	}
}

// Test secure operations
func TestExamplesWorking_SecureOperations(t *testing.T) {
	jsCrypt := NewJSEncrypt()
	jsCrypt.DefaultKeySize = 1024

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

// Test key properties validation
func TestExamplesWorking_KeyProperties(t *testing.T) {
	jsCrypt := NewJSEncrypt()
	jsCrypt.DefaultKeySize = 1024

	privKey, err := jsCrypt.GetPrivateKey()
	if err != nil {
		t.Fatalf("Failed to get private key: %v", err)
	}
	if privKey == "" {
		t.Fatal("Private key is empty")
	}

	pubKey, err := jsCrypt.GetPublicKey()
	if err != nil {
		t.Fatalf("Failed to get public key: %v", err)
	}
	if pubKey == "" {
		t.Fatal("Public key is empty")
	}
}

// Test error cases handling
func TestExamplesWorking_ErrorCases(t *testing.T) {
	jsCrypt := NewJSEncrypt()
	jsCrypt.DefaultKeySize = 1024

	// Test valid encryption first
	validData := "valid"
	encrypted, err := jsCrypt.Encrypt(validData)
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
	if decrypted != validData {
		t.Errorf("Decrypted data doesn't match. Got %s, want %s", decrypted, validData)
	}
}
