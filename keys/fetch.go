package keys

import (
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"strings"

	"golang.org/x/crypto/ssh"
)

// fetchAndParseKeys fetches SSH public keys from a URL that returns
// authorized_keys format and parses them into Keys.
func fetchAndParseKeys(url, username string) ([]Key, error) {
	resp, err := http.Get(url)
	if err != nil {
		return nil, fmt.Errorf("fetching keys for %s: %w", username, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil, fmt.Errorf("user %q not found at %s", username, url)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("got status %d fetching keys for %s", resp.StatusCode, username)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading response: %w", err)
	}

	return parseAuthorizedKeys(string(body))
}

// parseAuthorizedKeys parses an authorized_keys format string into Keys.
func parseAuthorizedKeys(data string) ([]Key, error) {
	var keys []Key
	for _, line := range strings.Split(strings.TrimSpace(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		pub, _, _, _, err := ssh.ParseAuthorizedKey([]byte(line))
		if err != nil {
			return nil, fmt.Errorf("parsing key: %w", err)
		}
		fp := sshFingerprint(pub)
		keys = append(keys, Key{Raw: line, Fingerprint: fp})
	}
	return keys, nil
}

// sshFingerprint returns the SHA-256 fingerprint of an SSH public key.
func sshFingerprint(pub ssh.PublicKey) string {
	h := sha256.Sum256(pub.Marshal())
	return "SHA256:" + base64.RawStdEncoding.EncodeToString(h[:])
}
