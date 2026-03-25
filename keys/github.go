package keys

import "fmt"

func init() {
	Register(&GitHub{})
}

// GitHub fetches SSH public keys from GitHub.
type GitHub struct{}

func (g *GitHub) Name() string { return "github" }

func (g *GitHub) FetchKeys(username string) ([]Key, error) {
	url := fmt.Sprintf("https://github.com/%s.keys", username)
	return fetchAndParseKeys(url, username)
}

