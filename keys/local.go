package keys

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

func init() {
	Register(&Local{})
}

// Local reads SSH public keys from local files.
// The "username" is either a file path, or empty to auto-discover from ~/.ssh/.
type Local struct{}

func (l *Local) Name() string { return "file" }

func (l *Local) FetchKeys(username string) ([]Key, error) {
	if username != "" {
		// Treat username as a file path.
		return readPubKeyFile(username)
	}
	return discoverLocalKeys()
}

// discoverLocalKeys finds SSH public keys in ~/.ssh/.
func discoverLocalKeys() ([]Key, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, fmt.Errorf("finding home directory: %w", err)
	}

	sshDir := filepath.Join(home, ".ssh")
	pubFiles := []string{"id_ed25519.pub", "id_ecdsa.pub", "id_rsa.pub"}

	var allKeys []Key
	for _, name := range pubFiles {
		path := filepath.Join(sshDir, name)
		keys, err := readPubKeyFile(path)
		if err != nil {
			continue // File doesn't exist or isn't parseable, skip.
		}
		allKeys = append(allKeys, keys...)
	}

	if len(allKeys) == 0 {
		return nil, fmt.Errorf("no SSH public keys found in %s (looked for %s)", sshDir, strings.Join(pubFiles, ", "))
	}

	return allKeys, nil
}

// readPubKeyFile reads and parses a single SSH public key file.
func readPubKeyFile(path string) ([]Key, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", path, err)
	}
	return parseAuthorizedKeys(string(data))
}
