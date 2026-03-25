// Package tomb manages the .tomb directory and recipient configuration.
package tomb

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

const configDir = ".tomb"
const recipientsFile = "recipients.json"

// Recipient represents a person who can decrypt the repo.
type Recipient struct {
	// Provider is the key source (e.g. "github", "gitlab").
	Provider string `json:"provider"`
	// Username is the username on that provider.
	Username string `json:"username"`
	// Keys are the pinned SSH public keys for this recipient.
	Keys []PinnedKey `json:"keys"`
}

// PinnedKey is a pinned SSH public key.
type PinnedKey struct {
	// Raw is the authorized_keys format line.
	Raw string `json:"raw"`
	// Fingerprint is the SHA-256 fingerprint.
	Fingerprint string `json:"fingerprint"`
}

// Config is the tomb configuration for a repository.
type Config struct {
	Recipients []Recipient `json:"recipients"`
}

// FindRoot walks up from dir looking for a .tomb directory.
// Returns the repo root (parent of .tomb) or an error.
func FindRoot(dir string) (string, error) {
	dir, err := filepath.Abs(dir)
	if err != nil {
		return "", err
	}
	for {
		if info, err := os.Stat(filepath.Join(dir, configDir)); err == nil && info.IsDir() {
			return dir, nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", errors.New("not a tomb repository (no .tomb directory found)")
		}
		dir = parent
	}
}

// ConfigPath returns the path to the recipients file given the repo root.
func ConfigPath(root string) string {
	return filepath.Join(root, configDir, recipientsFile)
}

// LoadConfig reads the tomb config from disk. Returns an empty config if it doesn't exist yet.
func LoadConfig(root string) (*Config, error) {
	path := ConfigPath(root)
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return &Config{}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("reading config: %w", err)
	}
	var cfg Config
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parsing config: %w", err)
	}
	return &cfg, nil
}

// SaveConfig writes the tomb config to disk, creating .tomb/ if needed.
func SaveConfig(root string, cfg *Config) error {
	dir := filepath.Join(root, configDir)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("creating .tomb directory: %w", err)
	}
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return fmt.Errorf("marshaling config: %w", err)
	}
	return os.WriteFile(ConfigPath(root), data, 0o644)
}

// AddRecipient adds a recipient to the config. If the recipient already exists
// (same provider + username), it updates their keys.
func (c *Config) AddRecipient(r Recipient) {
	for i, existing := range c.Recipients {
		if existing.Provider == r.Provider && existing.Username == r.Username {
			c.Recipients[i] = r
			return
		}
	}
	c.Recipients = append(c.Recipients, r)
}

// RemoveRecipient removes a recipient by username (across all providers).
// Returns true if a recipient was removed.
func (c *Config) RemoveRecipient(username string) bool {
	filtered := c.Recipients[:0]
	removed := false
	for _, r := range c.Recipients {
		if r.Username == username {
			removed = true
		} else {
			filtered = append(filtered, r)
		}
	}
	c.Recipients = filtered
	return removed
}
