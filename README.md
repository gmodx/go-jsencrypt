# go-jsencrypt

A Go implementation of the [JSEncrypt](https://github.com/travist/jsencrypt) library, providing RSA encryption, decryption, signing, and verification functionality compatible with OpenSSL and JavaScript JSEncrypt.

[![Go Reference](https://pkg.go.dev/badge/github.com/gmodx/go-jsencrypt.svg)](https://pkg.go.dev/github.com/gmodx/go-jsencrypt)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

**📦 Go Package:** [https://pkg.go.dev/github.com/gmodx/go-jsencrypt](https://pkg.go.dev/github.com/gmodx/go-jsencrypt)

## Why go-jsencrypt?

When choosing an RSA encryption library for Go, you need a solution that's reliable, secure, and compatible with existing JavaScript implementations. go-jsencrypt delivers on all fronts.

**go-jsencrypt stands out** by providing enterprise-grade RSA encryption capabilities with full compatibility with JSEncrypt and OpenSSL-generated keys.

### Key Benefits

- **🔒 OpenSSL Compatible** - Direct support for PEM-formatted keys generated with OpenSSL
- **🌐 JSEncrypt Compatible** - Works seamlessly with JavaScript JSEncrypt library
- **⚡ Standard Library** - Built on Go's `crypto/rsa` and `crypto/rand` for security
- **📦 Zero Dependencies** - Uses only Go standard library
- **🛡️ Production Ready** - Well-tested and follows Go best practices
- **🚀 Simple API** - Clean, idiomatic Go interface

## Installation

### Using go get

```bash
go get github.com/gmodx/go-jsencrypt
```

### Using go mod

```bash
go mod require github.com/gmodx/go-jsencrypt
```

## Basic Usage

### 1. Import the Package

```go
import "github.com/gmodx/go-jsencrypt"
```

### 2. Create RSA Keys

For the highest security, you'll need RSA key pairs to use go-jsencrypt. Generate them using OpenSSL:

```bash
# Generate a 2048-bit private key
openssl genrsa -out private.pem 2048

# Extract the public key
openssl rsa -pubout -in private.pem -out public.pem
```

### 3. Basic Encryption/Decryption

```go
package main

import (
    "fmt"
    "log"
    
    "github.com/gmodx/go-jsencrypt"
)

func main() {
    // Create JSEncrypt instance
    crypt := jsencrypt.NewJSEncrypt()
    
    // Set your private key (for decryption)
    privateKeyPEM := `-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEA4f5wg5l2hKsTeNem/V41fGnJm6gOdrj8ym3rFkEjWT9u
U38KPhX7l3YXkLMfJj8sE3PUi0EaL6rN6rOUY8dq1fQhPhT1wfI6V8KQtQnq
1FKnNgQCVmQpCxK7qFR7Z+9MRWoJrPb8lZMmT1ELkKL6FBfkp3H3WcTl+BF0
XoZnLK0CfXfKzPJPm9jfKKE7dqnCsRiXYJbBwkNpQ5xo2lRKnNaH8GjPzJ4X
TZ5J7G6hDpXN1F3YzWZNVQRzfDfLB+w9FDaZ5kFhRc2PgB1Y8dNOhgK7RFJF
JDZhqBhSRnQ1YkLkQOnHq4Bz8l7YgRJkJHdIfTOO8l3YXkLMfJj8sE3PUi0E
qL6r9OOCzGJnVgQCVmQpCxK7qFR7Z+9MRWoJrPb8lZMmT1ELkKL6FBfkp3H3
...
-----END RSA PRIVATE KEY-----`
    
    err := crypt.SetPrivateKey(privateKeyPEM)
    if err != nil {
        log.Fatal(err)
    }
    
    // The public key is automatically derived from the private key
    // Or you can set it explicitly:
    // err = crypt.SetPublicKey(publicKeyPEM)
    
    // Encrypt data
    originalText := "Hello, World!"
    encrypted, err := crypt.Encrypt(originalText)
    if err != nil {
        log.Fatal(err)
    }
    
    // Decrypt data
    decrypted, err := crypt.Decrypt(encrypted)
    if err != nil {
        log.Fatal(err)
    }
    
    fmt.Println("Original:", originalText)
    fmt.Println("Encrypted:", encrypted)
    fmt.Println("Decrypted:", decrypted)
    fmt.Println("Match:", originalText == decrypted) // true
}
```

## Key Concepts

### Public vs Private Keys

- **Public Key**: Used for **encryption**. Safe to share publicly.
- **Private Key**: Used for **decryption**. Keep this secret!

```go
crypt := jsencrypt.NewJSEncrypt()

// For encryption only (using public key)
err := crypt.SetPublicKey(publicKeyString)
if err != nil {
    log.Fatal(err)
}
encrypted, err := crypt.Encrypt("secret message")

// For decryption (requires private key)
err = crypt.SetPrivateKey(privateKeyString)
if err != nil {
    log.Fatal(err)
}
decrypted, err := crypt.Decrypt(encrypted)
```

## Key Generation

go-jsencrypt supports two approaches for obtaining RSA keys: **OpenSSL generation (recommended)** and **Go generation (convenient)**.

### Option 1: OpenSSL Key Generation (Recommended)

For production applications and maximum security, generate keys using OpenSSL:

```bash
# Generate a 2048-bit private key (recommended minimum)
openssl genrsa -out private.pem 2048

# Generate a 4096-bit private key (higher security)
openssl genrsa -out private.pem 4096

# Extract the public key
openssl rsa -pubout -in private.pem -out public.pem

# View the private key
cat private.pem

# View the public key  
cat public.pem
```

**Why OpenSSL is more secure:**
- Uses cryptographically secure random number generators
- Better entropy sources from the operating system
- Optimized and audited implementations
- Industry standard for key generation

### Option 2: Go Key Generation (Convenience)

go-jsencrypt can generate keys directly in Go, which is convenient for testing, demos, or non-critical applications:

```go
// Create JSEncrypt instance
crypt := jsencrypt.NewJSEncrypt()

// Generate a new key pair (default: 1024-bit)
privateKey, err := crypt.GetPrivateKey()
if err != nil {
    log.Fatal(err)
}
publicKey, err := crypt.GetPublicKey()
if err != nil {
    log.Fatal(err)
}

fmt.Println("Private Key:", privateKey)
fmt.Println("Public Key:", publicKey)

// You can also specify key size (1024, 2048, 4096)
crypt2048 := jsencrypt.NewJSEncrypt()
crypt2048.DefaultKeySize = 2048
strongerPrivateKey, err := crypt2048.GetPrivateKey()
if err != nil {
    log.Fatal(err)
}
strongerPublicKey, err := crypt2048.GetPublicKey()
if err != nil {
    log.Fatal(err)
}
```

#### Different Key Sizes

```go
// 1024-bit (default - basic security)
crypt1024 := jsencrypt.NewJSEncrypt()
crypt1024.DefaultKeySize = 1024

// 2048-bit (recommended minimum for production)
crypt2048 := jsencrypt.NewJSEncrypt()
crypt2048.DefaultKeySize = 2048

// 4096-bit (high security but slower)
crypt4096 := jsencrypt.NewJSEncrypt()
crypt4096.DefaultKeySize = 4096
```

**⚠️ Security Note:** Go key generation uses `crypto/rand` which provides cryptographically secure random number generation. For production applications handling sensitive data, OpenSSL-generated keys are still recommended for consistency with other systems.

**💡 Use Cases for Go Generation:**
- Rapid prototyping and testing
- Server-side demos and examples  
- Educational purposes
- Non-critical applications
- When OpenSSL is not available

## Advanced Features

### Digital Signatures

```go
// Sign with the private key
sign := jsencrypt.NewJSEncrypt()
err := sign.SetPrivateKey(privateKey)
if err != nil {
    log.Fatal(err)
}
signature, err := sign.Sign(data)
if err != nil {
    log.Fatal(err)
}

// Verify with the public key
verify := jsencrypt.NewJSEncrypt()
err = verify.SetPublicKey(publicKey)
if err != nil {
    log.Fatal(err)
}
valid, err := verify.Verify(data, signature)
if err != nil {
    log.Fatal(err)
}
fmt.Println("Signature valid:", valid)
```

### Cross-Instance Key Sharing

```go
// Create first instance and generate keys
crypt1 := jsencrypt.NewJSEncrypt()
privKey1, err := crypt1.GetPrivateKey()
if err != nil {
    log.Fatal(err)
}

pubKey1, err := crypt1.GetPublicKey()
if err != nil {
    log.Fatal(err)
}

// Create second instance and set keys from first instance
crypt2 := jsencrypt.NewJSEncrypt()
err = crypt2.SetPrivateKey(privKey1)
if err != nil {
    log.Fatal(err)
}

err = crypt2.SetPublicKey(pubKey1)
if err != nil {
    log.Fatal(err)
}

// Encrypt with first instance, decrypt with second
msg := "Cross-instance test"
encrypted, err := crypt1.Encrypt(msg)
if err != nil {
    log.Fatal(err)
}

decrypted, err := crypt2.Decrypt(encrypted)
if err != nil {
    log.Fatal(err)
}
fmt.Println("Decrypted:", decrypted) // "Cross-instance test"
```

## Development & Testing

### Running Tests

```bash
# Run all tests
go test -v

# Run tests with coverage
go test -cover

# Run specific test file
go test -v -run TestJSEncrypt_EncryptDecrypt
```

### Test Structure

The test suite is organized to match the JavaScript JSEncrypt test structure:

- `jsencrypt_test.go` - Basic functionality tests
- `test_rsa.go` - RSA core functionality tests (corresponds to `test.rsa.js`)
- `test_examples.go` - Example usage tests (corresponds to `test.examples.js`)
- `test_examples_simple.go` - Simplified example tests (corresponds to `test.examples.simple.js`)
- `test_examples_working.go` - Working example tests (corresponds to `test.examples.working.js`)

## API Reference

### JSEncrypt

#### Methods

- `NewJSEncrypt() *JSEncrypt` - Create a new instance
- `SetKey(keyStr string) error` - Set RSA key from PEM string (auto-detects private/public)
- `SetPrivateKey(privKeyStr string) error` - Set private key
- `SetPublicKey(pubKeyStr string) error` - Set public key
- `Encrypt(str string) (string, error)` - Encrypt string, returns base64 encoded
- `Decrypt(str string) (string, error)` - Decrypt base64 encoded string
- `Sign(str string) (string, error)` - Sign string with SHA-256, returns base64 encoded signature
- `Verify(str, signature string) (bool, error)` - Verify signature, returns true if valid
- `GetPrivateKey() (string, error)` - Get PEM encoded private key (generates if not exists)
- `GetPublicKey() (string, error)` - Get PEM encoded public key (generates if not exists)

#### Properties

- `DefaultKeySize int` - Key size in bits (default: 1024)
- `DefaultPublicExp string` - Public exponent (kept for API compatibility, not used)
- `Log bool` - Enable logging (for debugging)

## Message Size Limits

RSA encryption has size limits based on the key size:

- **1024-bit key**: Max message size = 117 bytes (128 - 11 for PKCS#1 v1.5 padding)
- **2048-bit key**: Max message size = 245 bytes (256 - 11 for padding)
- **4096-bit key**: Max message size = 501 bytes (512 - 11 for padding)

For larger data, consider encrypting a symmetric key with RSA and using that for the actual data encryption.

## Key Format Support

go-jsencrypt works with standard PEM-formatted RSA keys:

**Private Key (PKCS#1):**
```
-----BEGIN RSA PRIVATE KEY-----
MIICXgIBAAKBgQDHikastc8+I81zCg/qWW8dMr8mqvXQ3qbPAmu0RjxoZVI47tvs...
-----END RSA PRIVATE KEY-----
```

**Private Key (PKCS#8):**
```
-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC...
-----END PRIVATE KEY-----
```

**Public Key (PKCS#8/PKIX):**
```
-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDlOJu6TyygqxfWT7eLtGDwajtN...
-----END PUBLIC KEY-----
```

**Public Key (PKCS#1):**
```
-----BEGIN RSA PUBLIC KEY-----
MIGJAoGBALEylyQ/kf6bhtC5KG8q2B8GKOcl61f78xup8IgRIPjZbArbC8fpb4R6...
-----END RSA PUBLIC KEY-----
```

## Differences from JavaScript JSEncrypt

1. **Error Handling**: Returns explicit errors instead of `false` or `null`
2. **Key Generation**: Uses Go's `crypto/rand` for secure random number generation
3. **Default Signature**: The `Sign()` method uses SHA-256 by default
4. **No OAEP Support**: Currently only PKCS#1 v1.5 padding is implemented
5. **Synchronous Only**: Go is inherently synchronous, no async/callback patterns

## Compatibility

go-jsencrypt is designed to be compatible with:

- ✅ JavaScript JSEncrypt library
- ✅ OpenSSL-generated keys
- ✅ Standard RSA implementations
- ✅ PKCS#1 and PKCS#8 key formats

## Technical Background

This library provides a Go wrapper around Go's standard `crypto/rsa` package, ensuring compatibility with JavaScript JSEncrypt and OpenSSL-generated keys. The implementation follows the same patterns and key formats as JSEncrypt for maximum interoperability.

## Contributing

Contributions are welcome! Please read our contributing guidelines and ensure all tests pass before submitting a pull request.

```bash
# Clone the repository
git clone https://github.com/gmodx/go-jsencrypt.git
cd go-jsencrypt

# Run tests
go test -v

# Run tests with coverage
go test -cover
```

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Resources

- **JavaScript JSEncrypt:** https://github.com/travist/jsencrypt
- **Go crypto/rsa:** https://pkg.go.dev/crypto/rsa
- **RSA Algorithm Details:** http://www.di-mgt.com.au/rsa_alg.html
- **ASN.1 Key Structures:** https://polarssl.org/kb/cryptography/asn1-key-structures-in-der-and-pem

---

**Made with ❤️ for the Go community**
