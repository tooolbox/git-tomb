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
	case "init":
		cmdInit(os.Args[2:])
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
  init [provider] [username]  Initialize a tomb (adds your keys)
  add <provider> <username>   Add a recipient (fetches their SSH keys)
  remove <username>           Remove a recipient
  list                        List all recipients
  refresh                     Re-fetch keys for all recipients

Providers: github, gitlab, file

Init examples:
  git tomb init                             # auto-discover local ~/.ssh/ keys
  git tomb init github mmccullough          # use GitHub SSH keys
  git tomb init file ~/.ssh/id_ed25519.pub  # use a specific key file

Workflow:
  git tomb init github mmccullough
  git tomb add github joeblow
  git remote add origin tomb::https://github.com/user/repo.git
  git push origin main

Install:
  go install github.com/tooolbox/git-tomb/cmd/...@latest
`)
}

func cmdInit(args []string) {
	// Check we're in a git repo.
	gitRoot, err := gitRepoRoot()
	if err != nil {
		fatal("not in a git repository — run 'git init' first")
	}

	// Check we're not already initialized.
	if _, err := tomb.FindRoot(gitRoot); err == nil {
		fatal("tomb is already initialized in this repository")
	}

	// Determine how to get keys.
	var provider string
	var username string
	var fetchedKeys []keys.Key

	switch len(args) {
	case 0:
		// Auto-discover local SSH keys.
		provider = "file"
		fmt.Println("Discovering local SSH keys...")
		p, pErr := keys.Get("file")
		if pErr != nil {
			fatal("file provider not registered: %v", pErr)
		}
		fetchedKeys, err = p.FetchKeys("")
		if err != nil {
			fatal("no SSH keys found: %v\nTry: git tomb init github <username>", err)
		}
	case 2:
		provider = args[0]
		username = args[1]
		p, err := keys.Get(provider)
		if err != nil {
			fatal("%v\nAvailable providers: %s", err, strings.Join(keys.Providers(), ", "))
		}
		if provider == "file" {
			fmt.Printf("Reading SSH key from %s...\n", username)
		} else {
			fmt.Printf("Fetching SSH keys for %s from %s...\n", username, provider)
		}
		fetchedKeys, err = p.FetchKeys(username)
		if err != nil {
			fatal("failed to fetch keys: %v", err)
		}
	default:
		fatal("usage: git tomb init [provider username]")
	}

	if len(fetchedKeys) == 0 {
		fatal("no SSH keys found — cannot initialize tomb without your keys")
	}

	// Build recipient.
	var pinned []tomb.PinnedKey
	for _, k := range fetchedKeys {
		pinned = append(pinned, tomb.PinnedKey{
			Raw:         k.Raw,
			Fingerprint: k.Fingerprint,
		})
	}

	displayName := username
	if displayName == "" {
		displayName = "local"
	}

	cfg := &tomb.Config{
		Recipients: []tomb.Recipient{
			{
				Provider: provider,
				Username: displayName,
				Keys:     pinned,
			},
		},
	}

	if err := tomb.SaveConfig(gitRoot, cfg); err != nil {
		fatal("saving config: %v", err)
	}

	fmt.Printf("Tomb initialized with %d key(s) for %s:\n", len(fetchedKeys), displayName)
	for _, k := range fetchedKeys {
		fmt.Printf("  %s %s\n", k.Fingerprint, strings.Fields(k.Raw)[0])
	}
}

func cmdAdd(args []string) {
	if len(args) < 2 {
		fatal("usage: git tomb add <provider> <username>")
	}
	provider, username := args[0], args[1]

	root, err := tomb.FindRoot(".")
	if err != nil {
		fatal("not a tomb repository — run 'git tomb init' first")
	}

	p, err := keys.Get(provider)
	if err != nil {
		fatal("%v\nAvailable providers: %s", err, strings.Join(keys.Providers(), ", "))
	}

	if provider == "file" {
		fmt.Printf("Reading SSH key from %s...\n", username)
	} else {
		fmt.Printf("Fetching SSH keys for %s from %s...\n", username, provider)
	}
	fetchedKeys, err := p.FetchKeys(username)
	if err != nil {
		fatal("failed to fetch keys: %v", err)
	}

	if len(fetchedKeys) == 0 {
		fatal("no SSH keys found for %s on %s", username, provider)
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
		fatal("not a tomb repository — run 'git tomb init' first")
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
		fatal("not a tomb repository — run 'git tomb init' first")
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
		fatal("not a tomb repository — run 'git tomb init' first")
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
		if r.Provider == "file" {
			fmt.Printf("Skipping %s (local key, use 'git tomb add file <path>' to update)\n", r.Username)
			continue
		}

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

func gitRepoRoot() (string, error) {
	cmd := exec.Command("git", "rev-parse", "--show-toplevel")
	out, err := cmd.Output()
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(out)), nil
}

func fatal(format string, args ...interface{}) {
	fmt.Fprintf(os.Stderr, "tomb: "+format+"\n", args...)
	os.Exit(1)
}
