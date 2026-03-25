// Package keys provides pluggable SSH public key discovery from hosting services.
package keys

import (
	"fmt"
)

// Key represents a fetched SSH public key.
type Key struct {
	// Raw is the authorized_keys format line (e.g. "ssh-ed25519 AAAA... user@host").
	Raw string
	// Fingerprint is the SHA-256 fingerprint of the key for pinning.
	Fingerprint string
}

// Provider fetches SSH public keys for a given username.
type Provider interface {
	// Name returns the provider name (e.g. "github", "gitlab").
	Name() string
	// FetchKeys fetches all SSH public keys for the given username.
	FetchKeys(username string) ([]Key, error)
}

// registry holds registered providers by name.
var registry = map[string]Provider{}

// Register adds a provider to the global registry.
func Register(p Provider) {
	registry[p.Name()] = p
}

// Get returns a registered provider by name, or an error if not found.
func Get(name string) (Provider, error) {
	p, ok := registry[name]
	if !ok {
		return nil, fmt.Errorf("unknown key provider: %q", name)
	}
	return p, nil
}

// Providers returns the names of all registered providers.
func Providers() []string {
	names := make([]string, 0, len(registry))
	for name := range registry {
		names = append(names, name)
	}
	return names
}
