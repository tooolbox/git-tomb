package tomb

import (
	"bytes"
	"crypto/rand"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"filippo.io/age"

	"github.com/tooolbox/git-tomb/crypt"
)

const secretFile = "secret.age"
const secretLen = 32

// SecretPath returns the path to the encrypted secret file.
func SecretPath(root string) string {
	return filepath.Join(root, configDir, secretFile)
}

// GenerateSecret creates a new random 32-byte secret and encrypts it
// for the given recipients, writing it to .tomb/secret.age.
func GenerateSecret(root string, recipients []age.Recipient) error {
	secret := make([]byte, secretLen)
	if _, err := rand.Read(secret); err != nil {
		return fmt.Errorf("generating random secret: %w", err)
	}

	return saveSecret(root, secret, recipients)
}

// ReencryptSecret decrypts the existing secret with the given identities,
// then re-encrypts it for the new set of recipients.
// Used when adding or removing recipients.
func ReencryptSecret(root string, identities []age.Identity, recipients []age.Recipient) error {
	secret, err := LoadSecret(root, identities)
	if err != nil {
		return fmt.Errorf("decrypting existing secret: %w", err)
	}
	return saveSecret(root, secret, recipients)
}

// LoadSecret decrypts and returns the tomb secret.
func LoadSecret(root string, identities []age.Identity) ([]byte, error) {
	path := SecretPath(root)
	encData, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("no tomb secret found — run 'git tomb init' first")
	}
	if err != nil {
		return nil, fmt.Errorf("reading secret: %w", err)
	}

	var buf bytes.Buffer
	if err := crypt.Decrypt(&buf, bytes.NewReader(encData), identities); err != nil {
		return nil, fmt.Errorf("decrypting secret: %w", err)
	}

	return buf.Bytes(), nil
}

// SecretExists checks whether the secret file exists.
func SecretExists(root string) bool {
	_, err := os.Stat(SecretPath(root))
	return err == nil
}

func saveSecret(root string, secret []byte, recipients []age.Recipient) error {
	dir := filepath.Join(root, configDir)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("creating .tomb directory: %w", err)
	}

	var buf bytes.Buffer
	if err := crypt.Encrypt(&buf, bytes.NewReader(secret), recipients); err != nil {
		return fmt.Errorf("encrypting secret: %w", err)
	}

	return os.WriteFile(SecretPath(root), buf.Bytes(), 0o644)
}
