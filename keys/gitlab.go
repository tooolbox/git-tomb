package keys

import "fmt"

func init() {
	Register(&GitLab{})
}

// GitLab fetches SSH public keys from GitLab.
type GitLab struct{}

func (g *GitLab) Name() string { return "gitlab" }

func (g *GitLab) FetchKeys(username string) ([]Key, error) {
	url := fmt.Sprintf("https://gitlab.com/%s.keys", username)
	return fetchAndParseKeys(url, username)
}
