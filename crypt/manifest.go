package crypt

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"

	"filippo.io/age"
)

// ManifestFile is the name of the encrypted manifest stored in each commit tree.
const ManifestFile = ".tomb-manifest.age"

// Manifest maps scrambled paths to original paths.
// Key: scrambled path, Value: original path.
type Manifest map[string]string

// EncryptManifest serializes and encrypts the manifest for the given recipients.
func EncryptManifest(m Manifest, recipients []age.Recipient) ([]byte, error) {
	data, err := json.Marshal(m)
	if err != nil {
		return nil, fmt.Errorf("marshaling manifest: %w", err)
	}

	var buf bytes.Buffer
	if err := Encrypt(&buf, bytes.NewReader(data), recipients); err != nil {
		return nil, fmt.Errorf("encrypting manifest: %w", err)
	}
	return buf.Bytes(), nil
}

// DecryptManifest decrypts and deserializes a manifest.
func DecryptManifest(encData []byte, identities []age.Identity) (Manifest, error) {
	var buf bytes.Buffer
	if err := Decrypt(&buf, bytes.NewReader(encData), identities); err != nil {
		return nil, fmt.Errorf("decrypting manifest: %w", err)
	}

	var m Manifest
	if err := json.Unmarshal(buf.Bytes(), &m); err != nil {
		return nil, fmt.Errorf("parsing manifest: %w", err)
	}
	return m, nil
}

// BuildManifest creates a manifest by scrambling all paths from a file list.
func BuildManifest(secret []byte, paths []string, mode ScrambleMode) Manifest {
	m := make(Manifest, len(paths))
	for _, p := range paths {
		scrambled := ScramblePath(secret, p, mode)
		m[scrambled] = p
	}
	return m
}

// Inverted returns the manifest inverted: original path → scrambled path.
func (m Manifest) Inverted() map[string]string {
	inv := make(map[string]string, len(m))
	for scrambled, original := range m {
		inv[original] = scrambled
	}
	return inv
}

// EncryptMessage encrypts a commit message with age.
func EncryptMessage(msg string, recipients []age.Recipient) (string, error) {
	var buf bytes.Buffer
	if err := Encrypt(&buf, bytes.NewReader([]byte(msg)), recipients); err != nil {
		return "", err
	}
	// Encode as raw bytes — we'll base64 it at the call site or store as binary blob.
	return buf.String(), nil
}

// DecryptMessage decrypts a commit message.
func DecryptMessage(encrypted string, identities []age.Identity) (string, error) {
	var buf bytes.Buffer
	if err := Decrypt(&buf, io.NopCloser(bytes.NewReader([]byte(encrypted))), identities); err != nil {
		return "", err
	}
	return buf.String(), nil
}
