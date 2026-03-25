// git-tomb is the CLI for managing tomb-encrypted git repositories.
//
// Installation:
//
//	go install github.com/tooolbox/git-tomb/cmd/...@latest
//
// This installs both git-tomb (the CLI) and git-remote-tomb (the git remote helper).
// Git automatically finds git-remote-tomb on your PATH for tomb:: URLs.
package main

import (
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/tooolbox/git-tomb/keys"
	_ "github.com/tooolbox/git-tomb/keys" // Register providers.
	"github.com/tooolbox/git-tomb/tomb"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(1)
	}

	switch os.Args[1] {
	case "add":
		cmdAdd(os.Args[2:])
	case "remove", "rm":
		cmdRemove(os.Args[2:])
	case "list", "ls":
		cmdList()
	case "refresh":
		cmdRefresh()
	case "help", "--help", "-h":
		usage()
	default:
		fmt.Fprintf(os.Stderr, "unknown command: %s\n", os.Args[1])
		usage()
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintf(os.Stderr, `Usage: git tomb <command> [args]

Commands:
  add <provider> <username>   Add a recipient (fetches their SSH keys)
  remove <username>           Remove a recipient
  list                        List all recipients
  refresh                     Re-fetch keys for all recipients

Providers: github, gitlab

Install:
  go install github.com/tooolbox/git-tomb/cmd/...@latest

Example:
  git tomb add github mmccullough
  git remote add origin tomb::https://github.com/user/repo.git
  git push origin main
`)
}

func cmdAdd(args []string) {
	if len(args) < 2 {
		fatal("usage: git tomb add <provider> <username>")
	}
	provider, username := args[0], args[1]

	p, err := keys.Get(provider)
	if err != nil {
		fatal("%v\nAvailable providers: %s", err, strings.Join(keys.Providers(), ", "))
	}

	fmt.Printf("Fetching SSH keys for %s from %s...\n", username, provider)
	fetchedKeys, err := p.FetchKeys(username)
	if err != nil {
		fatal("failed to fetch keys: %v", err)
	}

	if len(fetchedKeys) == 0 {
		fatal("no SSH keys found for %s on %s", username, provider)
	}

	root, err := findOrInitRoot()
	if err != nil {
		fatal("%v", err)
	}

	cfg, err := tomb.LoadConfig(root)
	if err != nil {
		fatal("%v", err)
	}

	var pinned []tomb.PinnedKey
	for _, k := range fetchedKeys {
		pinned = append(pinned, tomb.PinnedKey{
			Raw:         k.Raw,
			Fingerprint: k.Fingerprint,
		})
	}

	cfg.AddRecipient(tomb.Recipient{
		Provider: provider,
		Username: username,
		Keys:     pinned,
	})

	if err := tomb.SaveConfig(root, cfg); err != nil {
		fatal("saving config: %v", err)
	}

	fmt.Printf("Added %d key(s) for %s (%s):\n", len(fetchedKeys), username, provider)
	for _, k := range fetchedKeys {
		fmt.Printf("  %s %s\n", k.Fingerprint, strings.Fields(k.Raw)[0])
	}
}

func cmdRemove(args []string) {
	if len(args) < 1 {
		fatal("usage: git tomb remove <username>")
	}
	username := args[0]

	root, err := tomb.FindRoot(".")
	if err != nil {
		fatal("%v", err)
	}

	cfg, err := tomb.LoadConfig(root)
	if err != nil {
		fatal("%v", err)
	}

	if !cfg.RemoveRecipient(username) {
		fatal("recipient %q not found", username)
	}

	if err := tomb.SaveConfig(root, cfg); err != nil {
		fatal("saving config: %v", err)
	}

	fmt.Printf("Removed %s\n", username)
}

func cmdList() {
	root, err := tomb.FindRoot(".")
	if err != nil {
		fatal("%v", err)
	}

	cfg, err := tomb.LoadConfig(root)
	if err != nil {
		fatal("%v", err)
	}

	if len(cfg.Recipients) == 0 {
		fmt.Println("No recipients configured.")
		return
	}

	for _, r := range cfg.Recipients {
		fmt.Printf("%s/%s (%d keys):\n", r.Provider, r.Username, len(r.Keys))
		for _, k := range r.Keys {
			fmt.Printf("  %s %s\n", k.Fingerprint, strings.Fields(k.Raw)[0])
		}
	}
}

func cmdRefresh() {
	root, err := tomb.FindRoot(".")
	if err != nil {
		fatal("%v", err)
	}

	cfg, err := tomb.LoadConfig(root)
	if err != nil {
		fatal("%v", err)
	}

	if len(cfg.Recipients) == 0 {
		fmt.Println("No recipients to refresh.")
		return
	}

	for i, r := range cfg.Recipients {
		p, err := keys.Get(r.Provider)
		if err != nil {
			fmt.Fprintf(os.Stderr, "warning: unknown provider %q for %s, skipping\n", r.Provider, r.Username)
			continue
		}

		fmt.Printf("Refreshing keys for %s/%s...\n", r.Provider, r.Username)
		fetchedKeys, err := p.FetchKeys(r.Username)
		if err != nil {
			fmt.Fprintf(os.Stderr, "warning: failed to fetch keys for %s: %v\n", r.Username, err)
			continue
		}

		// Check for changes.
		oldFPs := map[string]bool{}
		for _, k := range r.Keys {
			oldFPs[k.Fingerprint] = true
		}
		newFPs := map[string]bool{}
		for _, k := range fetchedKeys {
			newFPs[k.Fingerprint] = true
		}

		changed := false
		for fp := range newFPs {
			if !oldFPs[fp] {
				fmt.Printf("  NEW key: %s\n", fp)
				changed = true
			}
		}
		for fp := range oldFPs {
			if !newFPs[fp] {
				fmt.Printf("  REMOVED key: %s\n", fp)
				changed = true
			}
		}

		if !changed {
			fmt.Printf("  No changes.\n")
			continue
		}

		var pinned []tomb.PinnedKey
		for _, k := range fetchedKeys {
			pinned = append(pinned, tomb.PinnedKey{
				Raw:         k.Raw,
				Fingerprint: k.Fingerprint,
			})
		}
		cfg.Recipients[i].Keys = pinned
	}

	if err := tomb.SaveConfig(root, cfg); err != nil {
		fatal("saving config: %v", err)
	}

	fmt.Println("Done.")
}

// findOrInitRoot finds an existing .tomb dir or creates one in the current git repo root.
func findOrInitRoot() (string, error) {
	root, err := tomb.FindRoot(".")
	if err == nil {
		return root, nil
	}

	// No .tomb found — check if we're in a git repo and init there.
	cmd := exec.Command("git", "rev-parse", "--show-toplevel")
	out, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("not in a git repository — run 'git init' first")
	}

	gitRoot := strings.TrimSpace(string(out))
	fmt.Println("Initializing tomb in this repository...")
	return gitRoot, nil
}

func fatal(format string, args ...interface{}) {
	fmt.Fprintf(os.Stderr, "tomb: "+format+"\n", args...)
	os.Exit(1)
}
