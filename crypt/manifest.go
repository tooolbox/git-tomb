package crypt

import (
	"bytes"
	"encoding/json"
	"fmt"
)

// ManifestFile is the name of the encrypted manifest stored in each commit tree.
const ManifestFile = ".tomb-manifest.age"

// Manifest maps scrambled paths to original paths.
// Key: scrambled path, Value: original path.
type Manifest map[string]string

// EncryptManifest serializes and encrypts the manifest using the shared secret.
func EncryptManifest(m Manifest, secret []byte) ([]byte, error) {
	data, err := json.Marshal(m)
	if err != nil {
		return nil, fmt.Errorf("marshaling manifest: %w", err)
	}

	key, err := ManifestKey(secret)
	if err != nil {
		return nil, err
	}

	var buf bytes.Buffer
	if err := SymmetricEncrypt(&buf, bytes.NewReader(data), key); err != nil {
		return nil, fmt.Errorf("encrypting manifest: %w", err)
	}
	return buf.Bytes(), nil
}

// DecryptManifest decrypts and deserializes a manifest using the shared secret.
func DecryptManifest(encData []byte, secret []byte) (Manifest, error) {
	key, err := ManifestKey(secret)
	if err != nil {
		return nil, err
	}

	var buf bytes.Buffer
	if err := SymmetricDecrypt(&buf, bytes.NewReader(encData), key); err != nil {
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
