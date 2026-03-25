// Package remote implements the git remote helper protocol for tomb.
//
// Git invokes git-remote-tomb when it encounters a URL like tomb::https://github.com/user/repo.git
// The helper speaks the fetch/push remote helper protocol over stdin/stdout.
package remote

import (
	"bufio"
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"filippo.io/age"
	"filippo.io/age/agessh"
	"golang.org/x/crypto/ssh"
	"golang.org/x/term"

	"github.com/tooolbox/git-tomb/crypt"
	"github.com/tooolbox/git-tomb/tomb"
)

// Run runs the git remote helper protocol.
// remoteName is the git remote name, url is the actual remote URL (after tomb:: prefix).
func Run(remoteName, url string) error {
	gitDir := os.Getenv("GIT_DIR")
	if gitDir == "" {
		gitDir = ".git"
	}

	h := &helper{
		remoteName: remoteName,
		url:        url,
		gitDir:     gitDir,
	}

	scanner := bufio.NewScanner(os.Stdin)
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			continue
		}

		cmd, args, _ := strings.Cut(line, " ")
		switch cmd {
		case "capabilities":
			if err := h.capabilities(); err != nil {
				return err
			}
		case "list":
			if err := h.list(args); err != nil {
				return err
			}
		case "fetch":
			// Collect all fetch lines until blank line.
			refs := []string{args}
			for scanner.Scan() {
				l := scanner.Text()
				if l == "" {
					break
				}
				_, a, _ := strings.Cut(l, " ")
				refs = append(refs, a)
			}
			if err := h.fetch(refs); err != nil {
				return err
			}
		case "push":
			// Collect all push lines until blank line.
			specs := []string{args}
			for scanner.Scan() {
				l := scanner.Text()
				if l == "" {
					break
				}
				_, a, _ := strings.Cut(l, " ")
				specs = append(specs, a)
			}
			if err := h.push(specs); err != nil {
				return err
			}
		case "":
			return nil
		default:
			return fmt.Errorf("unknown command: %q", cmd)
		}
	}

	return scanner.Err()
}

type helper struct {
	remoteName string
	url        string
	gitDir     string
}

func (h *helper) capabilities() error {
	fmt.Println("fetch")
	fmt.Println("push")
	fmt.Println()
	return nil
}

// list reports the refs available on the remote.
func (h *helper) list(forPush string) error {
	refs, err := h.fetchRemoteRefs()
	if err != nil {
		// Could be an empty remote, or could be an actual error.
		// Log to stderr so the user can see what's happening.
		fmt.Fprintf(os.Stderr, "tomb: list refs: %v\n", err)
		fmt.Println()
		return nil
	}
	for _, ref := range refs {
		fmt.Fprintf(os.Stderr, "tomb: ref: %s\n", ref)
		fmt.Println(ref)
	}
	fmt.Println()
	return nil
}

// fetch decrypts and unbundles objects from the remote.
func (h *helper) fetch(refs []string) error {
	identities, err := loadIdentities()
	if err != nil {
		return fmt.Errorf("loading SSH keys: %w", err)
	}

	// Clone the encrypted remote into a temp dir (regular clone to get working tree files).
	tmpDir, err := os.MkdirTemp("", "tomb-fetch-*")
	if err != nil {
		return err
	}
	defer os.RemoveAll(tmpDir)

	cmd := exec.Command("git", "clone", "--quiet", "--depth=1", h.url, tmpDir)
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("cloning encrypted remote: %w", err)
	}

	// Read the encrypted bundle from the working tree.
	bundlePath := filepath.Join(tmpDir, "tomb.bundle.age")
	encData, err := os.ReadFile(bundlePath)
	if err != nil {
		return fmt.Errorf("reading encrypted bundle: %w", err)
	}

	// Decrypt the bundle to a temp file.
	decBundle, err := os.CreateTemp("", "tomb-bundle-*.bundle")
	if err != nil {
		return err
	}
	defer os.Remove(decBundle.Name())

	if err := crypt.Decrypt(decBundle, bytes.NewReader(encData), identities); err != nil {
		return fmt.Errorf("decrypting bundle: %w", err)
	}
	decBundle.Close()

	// Unbundle into the local repo using GIT_DIR directly.
	absGitDir, _ := filepath.Abs(h.gitDir)
	cmd = exec.Command("git", "--git-dir", absGitDir, "bundle", "unbundle", decBundle.Name())
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("unbundling: %w", err)
	}

	fmt.Println()
	return nil
}

// push bundles, encrypts, and pushes to the remote.
func (h *helper) push(specs []string) error {
	root, err := tomb.FindRoot(h.repoDir())
	if err != nil {
		return err
	}

	cfg, err := tomb.LoadConfig(root)
	if err != nil {
		return err
	}

	if len(cfg.Recipients) == 0 {
		return fmt.Errorf("no recipients configured — run 'git tomb add <provider> <username>' first")
	}

	recipients, err := recipientsFromConfig(cfg)
	if err != nil {
		return err
	}

	// Create a bundle of the entire repo.
	bundleFile, err := os.CreateTemp("", "tomb-bundle-*.bundle")
	if err != nil {
		return err
	}
	defer os.Remove(bundleFile.Name())
	bundleFile.Close()

	cmd := exec.Command("git", "bundle", "create", bundleFile.Name(), "--all")
	cmd.Dir = h.repoDir()
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("creating bundle: %w", err)
	}

	// Encrypt the bundle.
	bundleData, err := os.ReadFile(bundleFile.Name())
	if err != nil {
		return err
	}

	encFile, err := os.CreateTemp("", "tomb-encrypted-*.age")
	if err != nil {
		return err
	}
	defer os.Remove(encFile.Name())

	if err := crypt.Encrypt(encFile, bytes.NewReader(bundleData), recipients); err != nil {
		return fmt.Errorf("encrypting bundle: %w", err)
	}
	encFile.Close()

	// Encrypt the ref list.
	refList, err := h.localRefs()
	if err != nil {
		return err
	}

	encRefsFile, err := os.CreateTemp("", "tomb-refs-*.age")
	if err != nil {
		return err
	}
	defer os.Remove(encRefsFile.Name())

	if err := crypt.Encrypt(encRefsFile, strings.NewReader(refList), recipients); err != nil {
		return fmt.Errorf("encrypting refs: %w", err)
	}
	encRefsFile.Close()

	// Create a temp working directory, commit encrypted files, and push to the real remote.
	workDir, err := os.MkdirTemp("", "tomb-push-*")
	if err != nil {
		return err
	}
	defer os.RemoveAll(workDir)

	// Init a fresh repo in the work dir.
	if err := run(workDir, "git", "init", "--quiet"); err != nil {
		return fmt.Errorf("init temp repo: %w", err)
	}
	if err := run(workDir, "git", "config", "user.email", "tomb@localhost"); err != nil {
		return err
	}
	if err := run(workDir, "git", "config", "user.name", "tomb"); err != nil {
		return err
	}

	// Copy encrypted files into the work dir.
	encData, _ := os.ReadFile(encFile.Name())
	os.WriteFile(filepath.Join(workDir, "tomb.bundle.age"), encData, 0o644)

	encRefsData, _ := os.ReadFile(encRefsFile.Name())
	os.WriteFile(filepath.Join(workDir, "tomb.refs.age"), encRefsData, 0o644)

	// Commit.
	if err := run(workDir, "git", "add", "-A"); err != nil {
		return err
	}
	if err := run(workDir, "git", "commit", "--quiet", "-m", "tomb: encrypted update"); err != nil {
		return fmt.Errorf("committing encrypted data: %w", err)
	}

	// Force push to the actual remote.
	if err := run(workDir, "git", "push", "--force", "--quiet", h.url, "HEAD:refs/heads/main"); err != nil {
		return fmt.Errorf("pushing to remote: %w", err)
	}

	// Report success for each push spec.
	for _, spec := range specs {
		dst := spec
		if idx := strings.Index(spec, ":"); idx >= 0 {
			dst = spec[idx+1:]
		}
		fmt.Printf("ok %s\n", dst)
	}
	fmt.Println()
	return nil
}

func (h *helper) repoDir() string {
	abs, _ := filepath.Abs(h.gitDir)
	if filepath.Base(abs) == ".git" {
		return filepath.Dir(abs)
	}
	return abs
}

func (h *helper) localRefs() (string, error) {
	cmd := exec.Command("git", "show-ref")
	cmd.Dir = h.repoDir()
	out, err := cmd.Output()
	if err != nil {
		return "", err
	}

	var sb strings.Builder
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		if line == "" {
			continue
		}
		sb.WriteString(line)
		sb.WriteString("\n")
	}

	// Get HEAD symref.
	cmd = exec.Command("git", "symbolic-ref", "HEAD")
	cmd.Dir = h.repoDir()
	headOut, err := cmd.Output()
	if err == nil {
		sb.WriteString("@" + strings.TrimSpace(string(headOut)) + " HEAD\n")
	}

	return sb.String(), nil
}

func (h *helper) fetchRemoteRefs() ([]string, error) {
	fmt.Fprintf(os.Stderr, "tomb: fetching refs from %s\n", h.url)

	identities, err := loadIdentities()
	if err != nil {
		return nil, fmt.Errorf("loading identities: %w", err)
	}
	fmt.Fprintf(os.Stderr, "tomb: loaded %d SSH identities\n", len(identities))

	// Shallow clone the remote to get the encrypted refs file.
	tmpDir, err := os.MkdirTemp("", "tomb-refs-*")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(tmpDir)

	cmd := exec.Command("git", "clone", "--quiet", "--depth=1", h.url, tmpDir)
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("cloning remote: %w", err)
	}

	// List what we got.
	entries, _ := os.ReadDir(tmpDir)
	for _, e := range entries {
		if e.Name() != ".git" {
			fmt.Fprintf(os.Stderr, "tomb: found file: %s\n", e.Name())
		}
	}

	refsPath := filepath.Join(tmpDir, "tomb.refs.age")
	encData, err := os.ReadFile(refsPath)
	if err != nil {
		return nil, fmt.Errorf("reading refs file: %w", err)
	}
	fmt.Fprintf(os.Stderr, "tomb: encrypted refs file: %d bytes\n", len(encData))

	var sb strings.Builder
	if err := crypt.Decrypt(&sb, bytes.NewReader(encData), identities); err != nil {
		return nil, fmt.Errorf("decrypting refs: %w", err)
	}

	decrypted := sb.String()
	fmt.Fprintf(os.Stderr, "tomb: decrypted refs:\n%s", decrypted)

	var refs []string
	for _, line := range strings.Split(strings.TrimSpace(decrypted), "\n") {
		if line != "" {
			refs = append(refs, line)
		}
	}
	return refs, nil
}

// recipientsFromConfig converts pinned SSH keys in the config to age recipients.
func recipientsFromConfig(cfg *tomb.Config) ([]age.Recipient, error) {
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

// sshDir returns the .ssh directory, checking HOME env var first
// (which bash/git-bash sets correctly) before falling back to
// os.UserHomeDir() (which may differ on Windows).
func sshDir() (string, error) {
	if home := os.Getenv("HOME"); home != "" {
		dir := filepath.Join(home, ".ssh")
		if info, err := os.Stat(dir); err == nil && info.IsDir() {
			return dir, nil
		}
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".ssh"), nil
}

// loadIdentities loads the user's SSH private keys for decryption.
// Supports passphrase-protected keys by prompting on stderr/stdin.
func loadIdentities() ([]age.Identity, error) {
	dir, err := sshDir()
	if err != nil {
		return nil, err
	}

	fmt.Fprintf(os.Stderr, "tomb: looking for SSH keys in %s\n", dir)

	var identities []age.Identity
	keyFiles := []string{"id_ed25519", "id_ecdsa", "id_rsa"}

	for _, name := range keyFiles {
		path := filepath.Join(dir, name)
		pemData, err := os.ReadFile(path)
		if err != nil {
			continue
		}

		// Try parsing without passphrase first.
		id, err := agessh.ParseIdentity(pemData)
		if err == nil {
			fmt.Fprintf(os.Stderr, "tomb: loaded key %s\n", name)
			identities = append(identities, id)
			continue
		}

		// Check if it's passphrase-protected.
		if !strings.Contains(err.Error(), "passphrase") {
			fmt.Fprintf(os.Stderr, "tomb: skipping %s: %v\n", name, err)
			continue
		}

		// Parse the public key from the .pub file to get the key type.
		pubPath := path + ".pub"
		pubData, err := os.ReadFile(pubPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "tomb: skipping %s: passphrase-protected but no .pub file found\n", name)
			continue
		}
		pubKey, _, _, _, err := ssh.ParseAuthorizedKey(pubData)
		if err != nil {
			fmt.Fprintf(os.Stderr, "tomb: skipping %s: could not parse public key: %v\n", name, err)
			continue
		}

		// Use NewEncryptedSSHIdentity with a passphrase prompt.
		encID, err := agessh.NewEncryptedSSHIdentity(pubKey, pemData, func() ([]byte, error) {
			return readPassphrase(fmt.Sprintf("Enter passphrase for %s: ", path))
		})
		if err != nil {
			fmt.Fprintf(os.Stderr, "tomb: skipping %s: %v\n", name, err)
			continue
		}
		fmt.Fprintf(os.Stderr, "tomb: loaded key %s (passphrase-protected)\n", name)
		identities = append(identities, encID)
	}

	if len(identities) == 0 {
		return nil, fmt.Errorf("no SSH keys found in %s (looked for %s)", dir, strings.Join(keyFiles, ", "))
	}

	return identities, nil
}

// readPassphrase prompts for a passphrase on stderr and reads from the terminal.
// stdin is used by the git remote helper protocol, so we open the terminal directly.
func readPassphrase(prompt string) ([]byte, error) {
	fmt.Fprint(os.Stderr, prompt)

	// Open the terminal directly — stdin is taken by the git protocol.
	// Try /dev/tty first (works on Unix and Git Bash/MSYS2 on Windows).
	tty, err := os.Open("/dev/tty")
	if err != nil {
		// Fall back to Windows console input.
		tty, err = os.Open("CONIN$")
		if err != nil {
			return nil, fmt.Errorf("cannot open terminal for passphrase input: %w", err)
		}
	}
	defer tty.Close()

	fd := int(tty.Fd())
	pass, err := term.ReadPassword(fd)
	fmt.Fprintln(os.Stderr) // newline after passphrase
	return pass, err
}

// run executes a command in the given directory, inheriting stderr.
func run(dir string, name string, args ...string) error {
	cmd := exec.Command(name, args...)
	cmd.Dir = dir
	cmd.Stderr = os.Stderr
	return cmd.Run()
}
