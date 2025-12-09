package jsencrypt

import (
	"crypto/rand"
	"crypto/rsa"
	"strings"
	"testing"
)

// Basic tests - core functionality

func TestJSEncrypt_GenerateKeys(t *testing.T) {
	jsCrypt := NewJSEncrypt()
	priv, err := jsCrypt.GetPrivateKey()
	if err != nil {
		t.Fatalf("Failed to generate private key: %v", err)
	}
	if priv == "" {
		t.Fatal("Private key is empty")
	}

	pub, err := jsCrypt.GetPublicKey()
	if err != nil {
		t.Fatalf("Failed to generate public key: %v", err)
	}
	if pub == "" {
		t.Fatal("Public key is empty")
	}
}

func TestJSEncrypt_EncryptDecrypt(t *testing.T) {
	jsCrypt := NewJSEncrypt()
	// Force generation
	if _, err := jsCrypt.GetPrivateKey(); err != nil {
		t.Fatal(err)
	}

	original := "Hello, World! This is a test message."
	encrypted, err := jsCrypt.Encrypt(original)
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

	if decrypted != original {
		t.Errorf("Decrypted message does not match original. Got %s, want %s", decrypted, original)
	}
}

func TestJSEncrypt_SignVerify(t *testing.T) {
	jsCrypt := NewJSEncrypt()
	// Force generation
	if _, err := jsCrypt.GetPrivateKey(); err != nil {
		t.Fatal(err)
	}

	message := "This is a signed message."
	signature, err := jsCrypt.Sign(message)
	if err != nil {
		t.Fatalf("Signing failed: %v", err)
	}

	valid, err := jsCrypt.Verify(message, signature)
	if err != nil {
		t.Fatalf("Verification failed: %v", err)
	}
	if !valid {
		t.Error("Signature verification returned false")
	}

	// Test invalid signature
	valid, err = jsCrypt.Verify(message+"modified", signature)
	if err == nil && valid {
		t.Error("Verification should have failed for modified message")
	}
}

func TestJSEncrypt_SetKeys(t *testing.T) {
	// 1. Generate keys with one instance
	src := NewJSEncrypt()
	privPEM, _ := src.GetPrivateKey()
	pubPEM, _ := src.GetPublicKey()

	// 2. Test Private Key setting
	destPriv := NewJSEncrypt()
	if err := destPriv.SetPrivateKey(privPEM); err != nil {
		t.Fatalf("Failed to set private key: %v", err)
	}

	// Check if it can decrypt what src encrypted
	msg := "Secret"
	enc, _ := src.Encrypt(msg)
	dec, err := destPriv.Decrypt(enc)
	if err != nil {
		t.Fatalf("Failed to decrypt with imported private key: %v", err)
	}
	if dec != msg {
		t.Errorf("Decrypted wrong value: %v", dec)
	}

	// 3. Test Public Key setting
	destPub := NewJSEncrypt()
	if err := destPub.SetPublicKey(pubPEM); err != nil {
		t.Fatalf("Failed to set public key: %v", err)
	}

	// Check if it can encrypt for src to decrypt
	enc2, err := destPub.Encrypt(msg)
	if err != nil {
		t.Fatalf("Failed to encrypt with imported public key: %v", err)
	}
	dec2, err := src.Decrypt(enc2)
	if err != nil {
		t.Fatalf("Failed to decrypt original instance: %v", err)
	}
	if dec2 != msg {
		t.Errorf("Decrypted wrong value on original: %v", dec2)
	}
}

func TestJSEncrypt_LongText(t *testing.T) {
	jsCrypt := NewJSEncrypt()
	// RSA encryption has a limit on data size based on key size.
	// PKCS#1 v1.5 padding adds 11 bytes overhead.
	// 1024 bit key = 128 bytes. Max data = 128 - 11 = 117 bytes.

	_, err := jsCrypt.GetPrivateKey() // Init default 1024
	if err != nil {
		t.Fatal(err)
	}

	// Test with exactly 117 bytes (max for 1024-bit key with PKCS#1 v1.5)
	maxMsg := make([]byte, 117)
	for i := range maxMsg {
		maxMsg[i] = 'A'
	}
	maxMsgStr := string(maxMsg)

	enc, err := jsCrypt.Encrypt(maxMsgStr)
	if err != nil {
		t.Fatalf("Failed to encrypt max length msg (117 bytes): %v", err)
	}
	dec, err := jsCrypt.Decrypt(enc)
	if err != nil {
		t.Fatalf("Failed to decrypt max length msg: %v", err)
	}

	if dec != maxMsgStr {
		t.Error("Decrypted message doesn't match original")
	}

	// Test with 118 bytes (should fail)
	tooLong := maxMsgStr + "X"
	if len(tooLong) != 118 {
		t.Fatalf("Test setup error: tooLong should be 118 bytes, got %d", len(tooLong))
	}
	_, err = jsCrypt.Encrypt(tooLong)
	if err == nil {
		t.Error("Should have failed encrypting 118 byte message with 1024 bit key")
	}

	// Test normal sized message
	normalMsg := "Hello, World!"
	enc2, err := jsCrypt.Encrypt(normalMsg)
	if err != nil {
		t.Fatalf("Failed to encrypt normal message: %v", err)
	}
	dec2, err := jsCrypt.Decrypt(enc2)
	if err != nil {
		t.Fatalf("Failed to decrypt normal message: %v", err)
	}
	if dec2 != normalMsg {
		t.Errorf("Decrypted normal message doesn't match. Got %s, want %s", dec2, normalMsg)
	}
}

// Additional edge case tests

func TestJSEncrypt_EmptyAndSpecialChars(t *testing.T) {
	jsCrypt := NewJSEncrypt()
	if _, err := jsCrypt.GetPrivateKey(); err != nil {
		t.Fatal(err)
	}

	testCases := []struct {
		name    string
		message string
	}{
		{"Single character", "a"},
		{"Special chars", "!@#$%^&*()"},
		{"Unicode", "你好世界 🌍"},
		{"Newlines", "line1\nline2\nline3"},
		{"Tabs", "tab\tseparated\tvalues"},
		{"Mixed", "Hello! 123 @#$ 世界"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Test encryption/decryption
			encrypted, err := jsCrypt.Encrypt(tc.message)
			if err != nil {
				t.Fatalf("Encryption failed for %s: %v", tc.name, err)
			}

			decrypted, err := jsCrypt.Decrypt(encrypted)
			if err != nil {
				t.Fatalf("Decryption failed for %s: %v", tc.name, err)
			}

			if decrypted != tc.message {
				t.Errorf("Decrypted message doesn't match for %s. Got %q, want %q", tc.name, decrypted, tc.message)
			}

			// Test signing/verification
			signature, err := jsCrypt.Sign(tc.message)
			if err != nil {
				t.Fatalf("Signing failed for %s: %v", tc.name, err)
			}

			valid, err := jsCrypt.Verify(tc.message, signature)
			if err != nil {
				t.Fatalf("Verification failed for %s: %v", tc.name, err)
			}
			if !valid {
				t.Errorf("Signature verification failed for %s", tc.name)
			}
		})
	}
}

func TestJSEncrypt_InvalidKeys(t *testing.T) {
	jsCrypt := NewJSEncrypt()

	// Test invalid private key
	invalidPrivKey := "-----BEGIN RSA PRIVATE KEY-----\nINVALID\n-----END RSA PRIVATE KEY-----"
	err := jsCrypt.SetPrivateKey(invalidPrivKey)
	if err == nil {
		t.Error("Should have failed to set invalid private key")
	}

	// Test invalid public key
	invalidPubKey := "-----BEGIN PUBLIC KEY-----\nINVALID\n-----END PUBLIC KEY-----"
	err = jsCrypt.SetPublicKey(invalidPubKey)
	if err == nil {
		t.Error("Should have failed to set invalid public key")
	}

	// Test empty key
	err = jsCrypt.SetPrivateKey("")
	if err == nil {
		t.Error("Should have failed to set empty private key")
	}

	err = jsCrypt.SetPublicKey("")
	if err == nil {
		t.Error("Should have failed to set empty public key")
	}

	// Test malformed PEM
	err = jsCrypt.SetPrivateKey("not a PEM key")
	if err == nil {
		t.Error("Should have failed to set malformed PEM key")
	}
}

func TestJSEncrypt_InvalidSignatures(t *testing.T) {
	jsCrypt := NewJSEncrypt()
	if _, err := jsCrypt.GetPrivateKey(); err != nil {
		t.Fatal(err)
	}

	message := "test message"
	validSignature, err := jsCrypt.Sign(message)
	if err != nil {
		t.Fatalf("Failed to create valid signature: %v", err)
	}

	// Test invalid signatures
	invalidSignatures := []string{
		"",                          // Empty string
		"not-a-valid-signature",     // Plain text
		"YWJjZGVmZw==",              // Valid base64 but not a signature
		"invalid-base64!@#",         // Invalid base64
		validSignature + "modified", // Modified valid signature
	}

	for _, invalidSig := range invalidSignatures {
		valid, err := jsCrypt.Verify(message, invalidSig)
		if err == nil && valid {
			t.Errorf("Should have failed verification for invalid signature: %s", invalidSig)
		}
	}

	// Test wrong message with valid signature
	valid, err := jsCrypt.Verify("different message", validSignature)
	if err == nil && valid {
		t.Error("Should have failed verification for wrong message")
	}
}

func TestJSEncrypt_CrossInstanceKeySharing(t *testing.T) {
	// Create first instance and generate keys
	jsCrypt1 := NewJSEncrypt()
	privKey1, err := jsCrypt1.GetPrivateKey()
	if err != nil {
		t.Fatalf("Failed to generate private key: %v", err)
	}

	pubKey1, err := jsCrypt1.GetPublicKey()
	if err != nil {
		t.Fatalf("Failed to generate public key: %v", err)
	}

	// Create second instance and set keys from first instance
	jsCrypt2 := NewJSEncrypt()
	err = jsCrypt2.SetPrivateKey(privKey1)
	if err != nil {
		t.Fatalf("Failed to set private key in second instance: %v", err)
	}

	err = jsCrypt2.SetPublicKey(pubKey1)
	if err != nil {
		t.Fatalf("Failed to set public key in second instance: %v", err)
	}

	// Encrypt with first instance, decrypt with second
	msg := "Cross-instance test"
	encrypted, err := jsCrypt1.Encrypt(msg)
	if err != nil {
		t.Fatalf("Encryption failed: %v", err)
	}

	decrypted, err := jsCrypt2.Decrypt(encrypted)
	if err != nil {
		t.Fatalf("Decryption failed: %v", err)
	}

	if decrypted != msg {
		t.Errorf("Cross-instance decryption failed. Got %s, want %s", decrypted, msg)
	}

	// Encrypt with second instance, decrypt with first
	encrypted2, err := jsCrypt2.Encrypt(msg)
	if err != nil {
		t.Fatalf("Encryption failed: %v", err)
	}

	decrypted2, err := jsCrypt1.Decrypt(encrypted2)
	if err != nil {
		t.Fatalf("Decryption failed: %v", err)
	}

	if decrypted2 != msg {
		t.Errorf("Cross-instance decryption failed. Got %s, want %s", decrypted2, msg)
	}

	// Test signing/verification across instances
	signature, err := jsCrypt1.Sign(msg)
	if err != nil {
		t.Fatalf("Signing failed: %v", err)
	}

	valid, err := jsCrypt2.Verify(msg, signature)
	if err != nil {
		t.Fatalf("Verification failed: %v", err)
	}
	if !valid {
		t.Error("Cross-instance signature verification failed")
	}
}

func TestJSEncrypt_KeyFormatValidation(t *testing.T) {
	jsCrypt := NewJSEncrypt()

	// Test that generated keys have correct format
	privKey, err := jsCrypt.GetPrivateKey()
	if err != nil {
		t.Fatalf("Failed to generate private key: %v", err)
	}

	// Check private key format
	if !strings.Contains(privKey, "-----BEGIN RSA PRIVATE KEY-----") {
		t.Error("Private key should contain BEGIN RSA PRIVATE KEY header")
	}
	if !strings.Contains(privKey, "-----END RSA PRIVATE KEY-----") {
		t.Error("Private key should contain END RSA PRIVATE KEY footer")
	}

	pubKey, err := jsCrypt.GetPublicKey()
	if err != nil {
		t.Fatalf("Failed to generate public key: %v", err)
	}

	// Check public key format
	if !strings.Contains(pubKey, "-----BEGIN PUBLIC KEY-----") {
		t.Error("Public key should contain BEGIN PUBLIC KEY header")
	}
	if !strings.Contains(pubKey, "-----END PUBLIC KEY-----") {
		t.Error("Public key should contain END PUBLIC KEY footer")
	}
}

func TestJSEncrypt_SetKey(t *testing.T) {
	jsCrypt1 := NewJSEncrypt()
	privKey, err := jsCrypt1.GetPrivateKey()
	if err != nil {
		t.Fatalf("Failed to generate private key: %v", err)
	}

	// Test SetKey with private key
	jsCrypt2 := NewJSEncrypt()
	err = jsCrypt2.SetKey(privKey)
	if err != nil {
		t.Fatalf("Failed to set key: %v", err)
	}

	// Should be able to decrypt what jsCrypt1 encrypted
	msg := "SetKey test"
	encrypted, err := jsCrypt1.Encrypt(msg)
	if err != nil {
		t.Fatalf("Encryption failed: %v", err)
	}

	decrypted, err := jsCrypt2.Decrypt(encrypted)
	if err != nil {
		t.Fatalf("Decryption failed: %v", err)
	}

	if decrypted != msg {
		t.Errorf("Decrypted message doesn't match. Got %s, want %s", decrypted, msg)
	}

	// Test SetKey with public key
	pubKey, err := jsCrypt1.GetPublicKey()
	if err != nil {
		t.Fatalf("Failed to get public key: %v", err)
	}

	jsCrypt3 := NewJSEncrypt()
	err = jsCrypt3.SetKey(pubKey)
	if err != nil {
		t.Fatalf("Failed to set public key: %v", err)
	}

	// Should be able to encrypt but not decrypt
	encrypted2, err := jsCrypt3.Encrypt(msg)
	if err != nil {
		t.Fatalf("Encryption failed: %v", err)
	}

	_, err = jsCrypt3.Decrypt(encrypted2)
	if err == nil {
		t.Error("Should not be able to decrypt with only public key")
	}
}

func TestJSEncrypt_LargeMessages(t *testing.T) {
	jsCrypt := NewJSEncrypt()
	jsCrypt.DefaultKeySize = 2048 // Use larger key for larger messages
	if _, err := jsCrypt.GetPrivateKey(); err != nil {
		t.Fatal(err)
	}

	// For 2048-bit key, max message size is 245 bytes (256 - 11)
	maxMsg := make([]byte, 245)
	for i := range maxMsg {
		maxMsg[i] = byte('A' + (i % 26))
	}
	maxMsgStr := string(maxMsg)

	encrypted, err := jsCrypt.Encrypt(maxMsgStr)
	if err != nil {
		t.Fatalf("Failed to encrypt max length message: %v", err)
	}

	decrypted, err := jsCrypt.Decrypt(encrypted)
	if err != nil {
		t.Fatalf("Failed to decrypt max length message: %v", err)
	}

	if decrypted != maxMsgStr {
		t.Error("Decrypted message doesn't match original")
	}
}

// Additional test to ensure we match standard library behavior for key generation used manually
func TestStandardKeyGeneration(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	if err := key.Validate(); err != nil {
		t.Fatal(err)
	}
}
