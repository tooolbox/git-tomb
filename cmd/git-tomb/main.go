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
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime/debug"
	"strings"

	"filippo.io/age"
	"filippo.io/age/agessh"
	"golang.org/x/crypto/ssh"

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
	case "config":
		cmdConfig(os.Args[2:])
	case "keygen":
		cmdKeygen(os.Args[2:])
	case "version", "--version", "-v":
		cmdVersion()
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
  init [options] [provider] [username]  Initialize a tomb (adds your keys)
  add <provider> <username>             Add a recipient (fetches their SSH keys)
  remove <username>                     Remove a recipient
  list                                  List all recipients
  refresh                               Re-fetch keys for all recipients
  config [key] [value]                  View or set configuration
  keygen [path]                         Generate an ed25519 SSH keypair

Providers: github, gitlab, file

Encryption modes (required for init):
  --encryption=bundle         Encrypt entire repo as a single blob (max privacy)
  --encryption=per-file       Encrypt each file individually (incremental push/pull)

Scramble options (per-file mode only):
  --scramble=full             Scramble filenames and extensions (default)
  --scramble=keep-extensions  Scramble filenames, keep extensions (.go, .js, etc.)
  --scramble=keep-filenames   Scramble directories only, keep original filenames

Init examples:
  git tomb init --encryption=bundle github mmccullough
  git tomb init --encryption=per-file github mmccullough
  git tomb init --encryption=per-file --scramble=keep-extensions github alice

Workflow:
  git tomb init --encryption=per-file github mmccullough
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

	// Parse --encryption and --scramble flags from args.
	var encryptionMode tomb.EncryptionMode
	scrambleMode := tomb.ScrambleFull
	var remaining []string
	for _, a := range args {
		if strings.HasPrefix(a, "--encryption=") {
			val := strings.TrimPrefix(a, "--encryption=")
			switch tomb.EncryptionMode(val) {
			case tomb.EncryptionBundle, tomb.EncryptionPerFile:
				encryptionMode = tomb.EncryptionMode(val)
			default:
				fatal("unknown encryption mode: %s (use bundle or per-file)", val)
			}
		} else if strings.HasPrefix(a, "--scramble=") {
			val := strings.TrimPrefix(a, "--scramble=")
			switch tomb.ScrambleMode(val) {
			case tomb.ScrambleFull, tomb.ScrambleKeepExtensions, tomb.ScrambleKeepFilenames:
				scrambleMode = tomb.ScrambleMode(val)
			default:
				fatal("unknown scramble mode: %s (use full, keep-extensions, or keep-filenames)", val)
			}
		} else {
			remaining = append(remaining, a)
		}
	}
	args = remaining

	if encryptionMode == "" {
		fatal("--encryption is required\n  --encryption=bundle     encrypt entire repo as a single blob (max privacy)\n  --encryption=per-file   encrypt each file individually (incremental push/pull)")
	}

	if encryptionMode == tomb.EncryptionBundle && scrambleMode != tomb.ScrambleFull {
		fatal("--scramble is only supported with --encryption=per-file")
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
		fatal("usage: git tomb init --encryption=MODE [--scramble=MODE] [provider username]")
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
		Encryption: encryptionMode,
		Scramble:   scrambleMode,
	}

	if err := tomb.SaveConfig(gitRoot, cfg); err != nil {
		fatal("saving config: %v", err)
	}

	// Per-file mode needs a symmetric secret for filename scrambling.
	if encryptionMode == tomb.EncryptionPerFile {
		var ageRecipients []age.Recipient
		for _, k := range fetchedKeys {
			rcpt, err := agessh.ParseRecipient(k.Raw)
			if err != nil {
				fatal("parsing SSH key for age: %v", err)
			}
			ageRecipients = append(ageRecipients, rcpt)
		}

		if err := tomb.GenerateSecret(gitRoot, ageRecipients); err != nil {
			fatal("generating secret: %v", err)
		}
	}

	fmt.Printf("Tomb initialized with %d key(s) for %s (encryption: %s", len(fetchedKeys), displayName, encryptionMode)
	if encryptionMode == tomb.EncryptionPerFile {
		fmt.Printf(", scramble: %s", scrambleMode)
	}
	fmt.Println("):")
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

	// Re-encrypt the secret for the updated recipient set.
	if tomb.SecretExists(root) {
		allRecipients, err := allAgeRecipients(cfg)
		if err != nil {
			fatal("parsing recipient keys: %v", err)
		}

		identities, err := loadLocalIdentities()
		if err != nil {
			fatal("loading SSH keys for re-encryption: %v", err)
		}

		if err := tomb.ReencryptSecret(root, identities, allRecipients); err != nil {
			fatal("re-encrypting secret: %v", err)
		}
		fmt.Println("Secret re-encrypted for updated recipient set.")
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

	// Re-encrypt the secret for the remaining recipients.
	if tomb.SecretExists(root) && len(cfg.Recipients) > 0 {
		allRecipients, err := allAgeRecipients(cfg)
		if err != nil {
			fatal("parsing recipient keys: %v", err)
		}

		identities, err := loadLocalIdentities()
		if err != nil {
			fatal("loading SSH keys for re-encryption: %v", err)
		}

		if err := tomb.ReencryptSecret(root, identities, allRecipients); err != nil {
			fatal("re-encrypting secret: %v", err)
		}
		fmt.Println("Secret re-encrypted for updated recipient set.")
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

func cmdConfig(args []string) {
	root, err := tomb.FindRoot(".")
	if err != nil {
		fatal("not a tomb repository — run 'git tomb init' first")
	}

	cfg, err := tomb.LoadConfig(root)
	if err != nil {
		fatal("%v", err)
	}

	switch len(args) {
	case 0:
		// Show all config.
		encryption := cfg.Encryption
		if encryption == "" {
			encryption = tomb.EncryptionBundle
		}
		fmt.Printf("encryption = %s\n", encryption)
		if encryption == tomb.EncryptionPerFile {
			scramble := cfg.Scramble
			if scramble == "" {
				scramble = tomb.ScrambleFull
			}
			fmt.Printf("scramble   = %s\n", scramble)
		}

	case 1:
		// Get a specific key.
		switch args[0] {
		case "encryption":
			encryption := cfg.Encryption
			if encryption == "" {
				encryption = tomb.EncryptionBundle
			}
			fmt.Println(encryption)
		case "scramble":
			scramble := cfg.Scramble
			if scramble == "" {
				scramble = tomb.ScrambleFull
			}
			fmt.Println(scramble)
		default:
			fatal("unknown config key: %s\nAvailable keys: encryption, scramble", args[0])
		}

	case 2:
		// Set a key.
		switch args[0] {
		case "encryption":
			fatal("encryption mode cannot be changed after init — create a new tomb instead")
		case "scramble":
			if cfg.Encryption == tomb.EncryptionBundle {
				fatal("scramble mode is only available with per-file encryption")
			}
			val := tomb.ScrambleMode(args[1])
			switch val {
			case tomb.ScrambleFull, tomb.ScrambleKeepExtensions, tomb.ScrambleKeepFilenames:
				cfg.Scramble = val
			default:
				fatal("unknown scramble mode: %s\nAvailable: full, keep-extensions, keep-filenames", args[1])
			}
		default:
			fatal("unknown config key: %s\nAvailable keys: encryption, scramble", args[0])
		}

		if err := tomb.SaveConfig(root, cfg); err != nil {
			fatal("saving config: %v", err)
		}
		fmt.Printf("%s = %s\n", args[0], args[1])

	default:
		fatal("usage: git tomb config [key] [value]")
	}
}

func cmdKeygen(args []string) {
	// Determine output path.
	var keyPath string
	switch len(args) {
	case 0:
		// Default: ~/.ssh/id_ed25519
		home, err := os.UserHomeDir()
		if err != nil {
			fatal("finding home directory: %v", err)
		}
		keyPath = filepath.Join(home, ".ssh", "id_ed25519")
	case 1:
		keyPath = args[0]
	default:
		fatal("usage: git tomb keygen [path]")
	}

	pubPath := keyPath + ".pub"

	// Check if keys already exist.
	if _, err := os.Stat(keyPath); err == nil {
		fatal("key already exists: %s\nRemove it first or specify a different path.", keyPath)
	}
	if _, err := os.Stat(pubPath); err == nil {
		fatal("public key already exists: %s\nRemove it first or specify a different path.", pubPath)
	}

	// Generate ed25519 keypair.
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		fatal("generating key: %v", err)
	}

	// Marshal public key to authorized_keys format.
	sshPub, err := ssh.NewPublicKey(pub)
	if err != nil {
		fatal("creating SSH public key: %v", err)
	}
	pubKeyStr := string(ssh.MarshalAuthorizedKey(sshPub))

	// Marshal private key to OpenSSH PEM format.
	privPEM, err := ssh.MarshalPrivateKey(priv, "")
	if err != nil {
		fatal("marshaling private key: %v", err)
	}
	privKeyData := pem.EncodeToMemory(privPEM)

	// Ensure the directory exists.
	dir := filepath.Dir(keyPath)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		fatal("creating directory %s: %v", dir, err)
	}

	// Write the keys.
	if err := os.WriteFile(keyPath, privKeyData, 0o600); err != nil {
		fatal("writing private key: %v", err)
	}
	if err := os.WriteFile(pubPath, []byte(pubKeyStr), 0o644); err != nil {
		fatal("writing public key: %v", err)
	}

	// Compute fingerprint.
	fp := ssh.FingerprintSHA256(sshPub)

	fmt.Printf("Generated ed25519 SSH keypair:\n")
	fmt.Printf("  Private: %s\n", keyPath)
	fmt.Printf("  Public:  %s\n", pubPath)
	fmt.Printf("  Fingerprint: %s\n", fp)
}

func cmdVersion() {
	info, ok := debug.ReadBuildInfo()
	if !ok {
		fmt.Println("git-tomb (unknown version)")
		return
	}

	version := info.Main.Version
	if version == "" || version == "(devel)" {
		version = "dev"
	}

	fmt.Printf("git-tomb %s\n", version)

	// Print VCS info if available (commit, dirty, time).
	var commit, time string
	var dirty bool
	for _, s := range info.Settings {
		switch s.Key {
		case "vcs.revision":
			commit = s.Value
		case "vcs.time":
			time = s.Value
		case "vcs.modified":
			dirty = s.Value == "true"
		}
	}
	if commit != "" {
		short := commit
		if len(short) > 12 {
			short = short[:12]
		}
		suffix := ""
		if dirty {
			suffix = " (dirty)"
		}
		fmt.Printf("  commit: %s%s\n", short, suffix)
	}
	if time != "" {
		fmt.Printf("  built:  %s\n", time)
	}
	fmt.Printf("  go:     %s\n", info.GoVersion)
}

func gitRepoRoot() (string, error) {
	cmd := exec.Command("git", "rev-parse", "--show-toplevel")
	out, err := cmd.Output()
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(out)), nil
}

// allAgeRecipients converts all SSH keys in the config to age recipients.
func allAgeRecipients(cfg *tomb.Config) ([]age.Recipient, error) {
	var recipients []age.Recipient
	for _, r := range cfg.Recipients {
		for _, k := range r.Keys {
			rcpt, err := agessh.ParseRecipient(k.Raw)
			if err != nil {
				return nil, fmt.Errorf("parsing key for %s/%s: %w", r.Provider, r.Username, err)
			}
			recipients = append(recipients, rcpt)
		}
	}
	return recipients, nil
}

// loadLocalIdentities loads the user's SSH private keys for decryption.
// This is a simplified version for CLI commands (not the remote helper).
func loadLocalIdentities() ([]age.Identity, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, err
	}

	// Also check HOME env var (git-bash on Windows).
	sshDir := filepath.Join(home, ".ssh")
	if h := os.Getenv("HOME"); h != "" {
		candidate := filepath.Join(h, ".ssh")
		if info, statErr := os.Stat(candidate); statErr == nil && info.IsDir() {
			sshDir = candidate
		}
	}

	var identities []age.Identity
	for _, name := range []string{"id_ed25519", "id_ecdsa", "id_rsa"} {
		pemData, err := os.ReadFile(filepath.Join(sshDir, name))
		if err != nil {
			continue
		}
		id, err := agessh.ParseIdentity(pemData)
		if err != nil {
			continue
		}
		identities = append(identities, id)
	}

	if len(identities) == 0 {
		return nil, fmt.Errorf("no SSH keys found in %s", sshDir)
	}
	return identities, nil
}

func fatal(format string, args ...interface{}) {
	fmt.Fprintf(os.Stderr, "tomb: "+format+"\n", args...)
	os.Exit(1)
}
