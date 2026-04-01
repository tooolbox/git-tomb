// Package crypt handles encryption and decryption of data streams.
//
// Two encryption schemes are used:
//   - Age (asymmetric): used only for encrypting the shared secret (secret.age)
//     and for bundle-mode encryption. Recipients are SSH public keys.
//   - AES-256-GCM (symmetric): used for per-file blob encryption, commit messages,
//     and manifests. Keyed on the shared secret from secret.age.
package crypt

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"io"

	"filippo.io/age"
	"golang.org/x/crypto/hkdf"
)

// Encrypt encrypts src to dst for the given recipients using age.
func Encrypt(dst io.Writer, src io.Reader, recipients []age.Recipient) error {
	w, err := age.Encrypt(dst, recipients...)
	if err != nil {
		return err
	}
	if _, err := io.Copy(w, src); err != nil {
		return err
	}
	return w.Close()
}

// Decrypt decrypts src to dst using the given identities.
func Decrypt(dst io.Writer, src io.Reader, identities []age.Identity) error {
	r, err := age.Decrypt(src, identities...)
	if err != nil {
		return err
	}
	_, err = io.Copy(dst, r)
	return err
}

// HKDF context strings for deriving separate subkeys from the shared secret.
var (
	hkdfBlob     = []byte("git-tomb blob encryption")
	hkdfMessage  = []byte("git-tomb message encryption")
	hkdfManifest = []byte("git-tomb manifest encryption")
)

// DeriveKey derives a 32-byte subkey from the shared secret using HKDF-SHA256.
func DeriveKey(secret, context []byte) ([]byte, error) {
	r := hkdf.New(sha256.New, secret, nil, context)
	key := make([]byte, 32)
	if _, err := io.ReadFull(r, key); err != nil {
		return nil, fmt.Errorf("deriving key: %w", err)
	}
	return key, nil
}

// BlobKey derives the subkey used for file blob encryption.
func BlobKey(secret []byte) ([]byte, error) { return DeriveKey(secret, hkdfBlob) }

// MessageKey derives the subkey used for commit message encryption.
func MessageKey(secret []byte) ([]byte, error) { return DeriveKey(secret, hkdfMessage) }

// ManifestKey derives the subkey used for manifest encryption.
func ManifestKey(secret []byte) ([]byte, error) { return DeriveKey(secret, hkdfManifest) }

// SymmetricEncrypt encrypts src to dst using AES-256-GCM with the given key.
// Wire format: [12-byte nonce][ciphertext + GCM tag].
func SymmetricEncrypt(dst io.Writer, src io.Reader, key []byte) error {
	plaintext, err := io.ReadAll(src)
	if err != nil {
		return fmt.Errorf("reading plaintext: %w", err)
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return fmt.Errorf("creating cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return fmt.Errorf("creating GCM: %w", err)
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return fmt.Errorf("generating nonce: %w", err)
	}

	ciphertext := gcm.Seal(nil, nonce, plaintext, nil)

	if _, err := dst.Write(nonce); err != nil {
		return err
	}
	_, err = dst.Write(ciphertext)
	return err
}

// SymmetricDecrypt decrypts src to dst using AES-256-GCM with the given key.
func SymmetricDecrypt(dst io.Writer, src io.Reader, key []byte) error {
	data, err := io.ReadAll(src)
	if err != nil {
		return fmt.Errorf("reading ciphertext: %w", err)
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return fmt.Errorf("creating cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return fmt.Errorf("creating GCM: %w", err)
	}

	nonceSize := gcm.NonceSize()
	if len(data) < nonceSize {
		return fmt.Errorf("ciphertext too short")
	}

	nonce := data[:nonceSize]
	ciphertext := data[nonceSize:]

	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return fmt.Errorf("decrypting: %w", err)
	}

	_, err = dst.Write(plaintext)
	return err
}
