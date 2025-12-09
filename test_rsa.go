package jsencrypt

import (
	"fmt"
	"strings"
	"testing"
)

// Test keys from jsencrypt test.rsa.js
var testPublicKeys = []string{
	`-----BEGIN PUBLIC KEY-----
MCwwDQYJKoZIhvcNAQEBBQADGwAwGAIRAMfE82X6tlpNK7Bxbhg6nEECAwEAAQ==
-----END PUBLIC KEY-----`,
	`-----BEGIN PUBLIC KEY-----
MDwwDQYJKoZIhvcNAQEBBQADKwAwKAIhAMLw0mRGv5KF+P0LsgNvfrM5AJdVBWqr
Q6Bf2gES5gwPAgMBAAE=
-----END PUBLIC KEY-----`,
	`-----BEGIN PUBLIC KEY-----
MFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBAKEpu21RDTXxEly55HdkVV9SlFL3Hgpl
i6+IohAsnaqFnApsKi1R7fAd3tBLmeHV2tlxYIogtxpzfpcc+QBVDx8CAwEAAQ==
-----END PUBLIC KEY-----`,
	`-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC5LO5xVlO9g4PL1xdWudnihIAP
bMsixr396bIbBIwKBul98UWQ3UALbqByq2bXVuoIbl48UokxOVstenGCyyo026NF
h3Fg6Cnvj9ptvbmqk2i3eTOBrt+e26Z1sepsnQL5OojiVIbrWwS6v1pFCXpnnLLv
yy6GPt/kftbhazH3oQIDAQAB
-----END PUBLIC KEY-----`,
	`-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAtKrsFSnzYl19m5wTwYdu
/r1UVZJV+zkAFud6+XTInAy8HbCR9n59H9+54P+Af/fUE6rvEPc4H09Z63vQzIGM
iL6GlqzMmptv/KRDIhj7Mk3MXomvEVfUsXrz5IpO0lf6NSeGhz4PGZUkHZ30VRx3
Jd/a0KIhgftZHxzmMsh8iB/n781B18pCP2eOPTF+5gRCaW+0fVPBlb/mBlg8MJrd
ScGCAReQ9NfTq8slJ0aO1NWaaRRANPQcCMljnTIK1ssyXBaSHKfoWeGx141mWMRx
/LxyZ13Zc3lqgmICiKFqMrQl5UeV1IUXYpj5hO9f60LGpZVHDqqo/JdF3+VAheaf
QwIDAQAB
-----END PUBLIC KEY-----`,
}

var testPrivateKeys = []string{
	`-----BEGIN RSA PRIVATE KEY-----
MGMCAQACEQDHxPNl+rZaTSuwcW4YOpxBAgMBAAECEQCqk6mhsmpyv17fK1dPeD3h
AgkA9Lo1aGRom0sCCQDQ+JpqE6KDIwIJAKstyIfBnA3rAggOsWwqCTdkAQIIOP95
RV9y2iQ=
-----END RSA PRIVATE KEY-----`,
	`-----BEGIN RSA PRIVATE KEY-----
MIGqAgEAAiEAwvDSZEa/koX4/QuyA29+szkAl1UFaqtDoF/aARLmDA8CAwEAAQIh
AME2Z5Ez/hR/7PUBboKxM2U7hSaavytvocBdQjLvOUWhAhEA8HgiLHRk9KjJ2hp0
5q3BfQIRAM+H7dYUXRnKXjYoqiKueXsCEGnaaCirf/lXB6vzs3wMBr0CEHT2Xwzw
nSgT7dUIRhsVylECEFQRGFtZcKRmL8lqTBwECWI=
-----END RSA PRIVATE KEY-----`,
	`-----BEGIN RSA PRIVATE KEY-----
MIIBOQIBAAJBAKEpu21RDTXxEly55HdkVV9SlFL3Hgpli6+IohAsnaqFnApsKi1R
7fAd3tBLmeHV2tlxYIogtxpzfpcc+QBVDx8CAwEAAQJAFn0VS07JEiLelhPWfpaA
lzmVuvICvh6nXEormygupBGiIPSXfIsTFid26yxt9wu4JHeRF0lq+Ozo55XpBQED
4QIhAM0E7ikuEa2bDsR2hQJhIz3SvzzyhE5dJcqFjRtKtMQvAiEAyT0C0gUyqCdN
YuRON1T7FUffarMdQXR+8tgRkhoCeBECID+ZKfAoVF+QXDJhub0VOQNyntRfPt+4
UYLTjwRKVm0NAiBuOCtuSoiHTxd0naU1aycmbboxn67bZeoOKkfdZL+LcQIgK6Xh
1wb9I/sNYv9ByJEGBNJRwtUEZrk5babLEdkUq90=
-----END RSA PRIVATE KEY-----`,
	`-----BEGIN RSA PRIVATE KEY-----
MIICXgIBAAKBgQC5LO5xVlO9g4PL1xdWudnihIAPbMsixr396bIbBIwKBul98UWQ
3UALbqByq2bXVuoIbl48UokxOVstenGCyyo026NFh3Fg6Cnvj9ptvbmqk2i3eTOB
rt+e26Z1sepsnQL5OojiVIbrWwS6v1pFCXpnnLLvyy6GPt/kftbhazH3oQIDAQAB
AoGAA+EiGbPCS10e/L1D2uhH3UwDVs9jrhXV0yT7Oz+sI2WjrKTKXU+VUOf/aoeW
vvouKwEM7lyYTTSzaU+AY0oYVzv7HN9hWoVwi0NoPpd4V1RFfFb4+4DmXh+NZS7E
DX9+WY435Yc9Qj7uHoc8EoRk3QfWaZTXd69b/9tS4Yy/tnECQQDxHsSe7Qxd+6tf
/f4eO+bENCxIMbPU8GPWQCvq9eT9Av2I0LTTchmlhG1TSatq62zq+Unef8M/IOBs
j5z3issdAkEAxJpYiuAVXulViUOLdS3QX72owIQLxpFBAKQ9cPTafqc47ms4Swy2
FCa4MZfTJXrDX5pur+PNeP/ce6xZN5DzVQJBAJI1kgy8uU8UGKswnTNAJ4K6EFAG
s4Ff82orp3XmfWBeu9aGl9/PxHV1g8WJWoSPFZC2cXCWEJLrIKszun7wjpECQQCs
Z+mjh1RWUepHn+rozE9B1jDo+iLVc8V8CYszxhThIkWjlnTcI358d2PpYYmxAVHZ
QbU1G2CxbjZsYbwvJTatAkEAspmMlIyKWgrQkLJ4rbPespMJCGe6VYharl1Qc5CF
/2SgKSCuLfhA/Cur0nO3dxt6XJijk/r3+j+8L/m+wqud+A==
-----END RSA PRIVATE KEY-----`,
	`-----BEGIN RSA PRIVATE KEY-----
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

const pkcs1PublicKey = `-----BEGIN RSA PUBLIC KEY-----
MIGJAoGBALEylyQ/kf6bhtC5KG8q2B8GKOcl61f78xup8IgRIPjZbArbC8fpb4R6
rkkWhXXv38G4rJVHYH6VIHxkJNdeLlJu0Ttrusuk/zQ+W8rN3Izl45gCQ9ep+06f
tSTEmD2DCs8jzg4AR3tBe6LiSYCP5YN4LxCn+peajm7VAQZucGM7AgMBAAE=
-----END RSA PUBLIC KEY-----`

// Test different key sizes - corresponds to test.rsa.js keySizes.forEach
func TestJSEncrypt_DifferentKeySizes(t *testing.T) {
	keySizes := []int{1024, 2048}

	for _, keySize := range keySizes {
		t.Run(fmt.Sprintf("KeySize_%d", keySize), func(t *testing.T) {
			jsCrypt := NewJSEncrypt()
			jsCrypt.DefaultKeySize = keySize

			// Generate keys
			priv, err := jsCrypt.GetPrivateKey()
			if err != nil {
				t.Fatalf("Failed to generate private key for size %d: %v", keySize, err)
			}
			if priv == "" {
				t.Fatal("Private key is empty")
			}

			pub, err := jsCrypt.GetPublicKey()
			if err != nil {
				t.Fatalf("Failed to generate public key for size %d: %v", keySize, err)
			}
			if pub == "" {
				t.Fatal("Public key is empty")
			}

			// Test encryption/decryption
			msg := "Test message"
			encrypted, err := jsCrypt.Encrypt(msg)
			if err != nil {
				t.Fatalf("Encryption failed for key size %d: %v", keySize, err)
			}

			decrypted, err := jsCrypt.Decrypt(encrypted)
			if err != nil {
				t.Fatalf("Decryption failed for key size %d: %v", keySize, err)
			}

			if decrypted != msg {
				t.Errorf("Decrypted message doesn't match for key size %d. Got %s, want %s", keySize, decrypted, msg)
			}

			// Test signing/verification
			signature, err := jsCrypt.Sign(msg)
			if err != nil {
				t.Fatalf("Signing failed for key size %d: %v", keySize, err)
			}

			valid, err := jsCrypt.Verify(msg, signature)
			if err != nil {
				t.Fatalf("Verification failed for key size %d: %v", keySize, err)
			}
			if !valid {
				t.Errorf("Signature verification failed for key size %d", keySize)
			}
		})
	}
}

// Test encrypt/decrypt with max length - corresponds to test.rsa.js #encrypt() | #decrypt()
func TestJSEncrypt_EncryptDecryptMaxLength(t *testing.T) {
	keySizes := []int{1024, 2048}

	for _, keySize := range keySizes {
		t.Run(fmt.Sprintf("KeySize_%d", keySize), func(t *testing.T) {
			jsCrypt := NewJSEncrypt()
			jsCrypt.DefaultKeySize = keySize
			if _, err := jsCrypt.GetPrivateKey(); err != nil {
				t.Fatal(err)
			}

			// Calculate max length: (keySize/8) - 11 (PKCS#1 v1.5 padding)
			maxLength := (keySize / 8) - 11

			// Test with max length
			maxMsg := make([]byte, maxLength)
			for i := range maxMsg {
				maxMsg[i] = 'a'
			}
			maxMsgStr := string(maxMsg)

			encrypted, err := jsCrypt.Encrypt(maxMsgStr)
			if err != nil {
				t.Fatalf("Failed to encrypt max length msg (%d bytes): %v", maxLength, err)
			}
			if encrypted == "" {
				t.Fatal("Encrypted string is empty")
			}

			decrypted, err := jsCrypt.Decrypt(encrypted)
			if err != nil {
				t.Fatalf("Failed to decrypt max length msg: %v", err)
			}
			if decrypted != maxMsgStr {
				t.Error("Decrypted message doesn't match original")
			}

			// Test with maxLength + 1 (should fail)
			tooLong := maxMsgStr + "X"
			_, err = jsCrypt.Encrypt(tooLong)
			if err == nil {
				t.Errorf("Should have failed encrypting %d byte message with %d bit key", maxLength+1, keySize)
			}
		})
	}
}


// Test getPublicKey - corresponds to test.rsa.js #getPublicKey()
func TestJSEncrypt_GetPublicKey(t *testing.T) {
	jsCrypt := NewJSEncrypt()
	pubKey, err := jsCrypt.GetPublicKey()
	if err != nil {
		t.Fatalf("Failed to get public key: %v", err)
	}

	// Should be a non-empty string
	if pubKey == "" {
		t.Fatal("Public key is empty")
	}

	// Should contain public header and footer
	if !strings.Contains(pubKey, "-----BEGIN PUBLIC KEY-----") {
		t.Error("Public key should contain BEGIN PUBLIC KEY header")
	}
	if !strings.Contains(pubKey, "-----END PUBLIC KEY-----") {
		t.Error("Public key should contain END PUBLIC KEY footer")
	}
}

// Test getPrivateKey - corresponds to test.rsa.js #getPrivateKey()
func TestJSEncrypt_GetPrivateKey(t *testing.T) {
	jsCrypt := NewJSEncrypt()
	privKey, err := jsCrypt.GetPrivateKey()
	if err != nil {
		t.Fatalf("Failed to get private key: %v", err)
	}

	// Should be a non-empty string
	if privKey == "" {
		t.Fatal("Private key is empty")
	}

	// Should contain private header and footer
	if !strings.Contains(privKey, "-----BEGIN RSA PRIVATE KEY-----") {
		t.Error("Private key should contain BEGIN RSA PRIVATE KEY header")
	}
	if !strings.Contains(privKey, "-----END RSA PRIVATE KEY-----") {
		t.Error("Private key should contain END RSA PRIVATE KEY footer")
	}
}

// Test setPrivateKey - corresponds to test.rsa.js #setPrivateKey()
func TestJSEncrypt_SetPrivateKey(t *testing.T) {
	// Use test keys from jsencrypt test suite
	for i, testPrivKey := range testPrivateKeys {
		if i >= len(testPublicKeys) {
			break
		}

		t.Run(fmt.Sprintf("TestKey_%d", i), func(t *testing.T) {
			jsCrypt := NewJSEncrypt()
			err := jsCrypt.SetPrivateKey(testPrivKey)
			if err != nil {
				t.Fatalf("Failed to set private key: %v", err)
			}

			// Should both encrypt and decrypt
			testMsg := "test"
			encrypted, err := jsCrypt.Encrypt(testMsg)
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
			if decrypted != testMsg {
				t.Errorf("Decrypted message doesn't match. Got %s, want %s", decrypted, testMsg)
			}
		})
	}
}

// Test setPublicKey X509 format - corresponds to test.rsa.js #setPublicKey() X509 format
func TestJSEncrypt_SetPublicKeyX509(t *testing.T) {
	// Use test keys from jsencrypt test suite
	for i, testPubKey := range testPublicKeys {
		t.Run(fmt.Sprintf("TestKey_%d", i), func(t *testing.T) {
			jsCrypt := NewJSEncrypt()
			err := jsCrypt.SetPublicKey(testPubKey)
			if err != nil {
				t.Fatalf("Failed to set public key: %v", err)
			}

			// Should only encrypt (not decrypt)
			testMsg := "test"
			encrypted, err := jsCrypt.Encrypt(testMsg)
			if err != nil {
				t.Fatalf("Encryption failed: %v", err)
			}
			if encrypted == "" {
				t.Fatal("Encrypted string is empty")
			}

			// Should not be able to decrypt without private key
			_, err = jsCrypt.Decrypt(encrypted)
			if err == nil {
				t.Error("Should not be able to decrypt with only public key")
			}
		})
	}
}

// Test setPublicKey PKCS#1 format - corresponds to test.rsa.js #setPublicKey() PKCS #1 format
func TestJSEncrypt_SetPublicKeyPKCS1(t *testing.T) {
	jsCrypt := NewJSEncrypt()
	err := jsCrypt.SetPublicKey(pkcs1PublicKey)
	if err != nil {
		t.Fatalf("Failed to set PKCS#1 public key: %v", err)
	}

	// Should only encrypt (not decrypt)
	testMsg := "test"
	encrypted, err := jsCrypt.Encrypt(testMsg)
	if err != nil {
		t.Fatalf("Encryption failed: %v", err)
	}
	if encrypted == "" {
		t.Fatal("Encrypted string is empty")
	}

	// Should not be able to decrypt without private key
	_, err = jsCrypt.Decrypt(encrypted)
	if err == nil {
		t.Error("Should not be able to decrypt with only public key")
	}
}

