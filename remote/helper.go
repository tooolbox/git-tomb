// Package remote implements the git remote helper protocol for tomb.
//
// Git invokes git-remote-tomb when it encounters a URL like tomb::https://github.com/user/repo.git
// The helper speaks the fetch/push remote helper protocol over stdin/stdout.
package remote

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"filippo.io/age"
	"filippo.io/age/agessh"
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
// We store encrypted bundles, so we need to fetch and decrypt the ref list.
func (h *helper) list(forPush string) error {
	// Try to fetch the encrypted ref list from the remote.
	refs, err := h.fetchRemoteRefs()
	if err != nil {
		// No refs yet (empty remote) — just return empty list.
		fmt.Println()
		return nil
	}
	for _, ref := range refs {
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

	// Clone the encrypted remote into a temp dir.
	tmpDir, err := os.MkdirTemp("", "tomb-fetch-*")
	if err != nil {
		return err
	}
	defer os.RemoveAll(tmpDir)

	// Git clone the actual remote (which has encrypted data).
	cmd := exec.Command("git", "clone", "--bare", "--quiet", h.url, tmpDir)
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("cloning encrypted remote: %w", err)
	}

	// Read the encrypted bundle.
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

	if err := crypt.Decrypt(decBundle, strings.NewReader(string(encData)), identities); err != nil {
		return fmt.Errorf("decrypting bundle: %w", err)
	}
	decBundle.Close()

	// Unbundle into the local repo.
	cmd = exec.Command("git", "bundle", "unbundle", decBundle.Name())
	cmd.Dir = h.repoDir()
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
		return fmt.Errorf("no recipients configured — run 'tomb add <provider> <username>' first")
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

	// Read the bundle and encrypt it.
	bundleData, err := os.ReadFile(bundleFile.Name())
	if err != nil {
		return err
	}

	encFile, err := os.CreateTemp("", "tomb-encrypted-*.age")
	if err != nil {
		return err
	}
	defer os.Remove(encFile.Name())

	if err := crypt.Encrypt(encFile, strings.NewReader(string(bundleData)), recipients); err != nil {
		return fmt.Errorf("encrypting bundle: %w", err)
	}
	encFile.Close()

	// Push the encrypted bundle to the actual remote.
	// We create a temporary bare repo, put the encrypted file in it, and push.
	tmpDir, err := os.MkdirTemp("", "tomb-push-*")
	if err != nil {
		return err
	}
	defer os.RemoveAll(tmpDir)

	// Init bare repo.
	cmd = exec.Command("git", "init", "--bare", "--quiet", tmpDir)
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("creating temp repo: %w", err)
	}

	// Copy encrypted bundle into the bare repo.
	encData, err := os.ReadFile(encFile.Name())
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(tmpDir, "tomb.bundle.age"), encData, 0o644); err != nil {
		return err
	}

	// Also store an encrypted ref list so 'list' can work without full decrypt.
	refList, err := h.localRefs()
	if err != nil {
		return err
	}
	refFile, err := os.CreateTemp("", "tomb-refs-*.age")
	if err != nil {
		return err
	}
	defer os.Remove(refFile.Name())

	if err := crypt.Encrypt(refFile, strings.NewReader(refList), recipients); err != nil {
		return fmt.Errorf("encrypting refs: %w", err)
	}
	refFile.Close()

	refData, err := os.ReadFile(refFile.Name())
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(tmpDir, "tomb.refs.age"), refData, 0o644); err != nil {
		return err
	}

	// Commit and push.
	cmd = exec.Command("git", "-C", tmpDir, "config", "user.email", "tomb@localhost")
	cmd.Run()
	cmd = exec.Command("git", "-C", tmpDir, "config", "user.name", "tomb")
	cmd.Run()

	// We need a working tree to commit. Use a temp worktree approach.
	workDir, err := os.MkdirTemp("", "tomb-work-*")
	if err != nil {
		return err
	}
	defer os.RemoveAll(workDir)

	cmd = exec.Command("git", "clone", "--quiet", tmpDir, workDir)
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("cloning temp repo: %w", err)
	}

	// Copy files into work dir.
	for _, name := range []string{"tomb.bundle.age", "tomb.refs.age"} {
		data, _ := os.ReadFile(filepath.Join(tmpDir, name))
		os.WriteFile(filepath.Join(workDir, name), data, 0o644)
	}

	cmd = exec.Command("git", "-C", workDir, "add", "-A")
	cmd.Run()
	cmd = exec.Command("git", "-C", workDir, "commit", "-m", "tomb: encrypted update", "--allow-empty")
	cmd.Stderr = os.Stderr
	cmd.Run()

	// Force push to actual remote.
	cmd = exec.Command("git", "-C", workDir, "push", "--force", "--quiet", h.url, "HEAD:refs/heads/main")
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
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
	// GIT_DIR is typically .git — the repo root is its parent.
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

	// Also get HEAD.
	cmd = exec.Command("git", "symbolic-ref", "HEAD")
	cmd.Dir = h.repoDir()
	headOut, err := cmd.Output()
	if err == nil {
		sb.WriteString("@" + strings.TrimSpace(string(headOut)) + " HEAD\n")
	}

	return sb.String(), nil
}

func (h *helper) fetchRemoteRefs() ([]string, error) {
	identities, err := loadIdentities()
	if err != nil {
		return nil, err
	}

	// Fetch just the refs file from the remote using git archive or a shallow clone.
	tmpDir, err := os.MkdirTemp("", "tomb-refs-*")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(tmpDir)

	cmd := exec.Command("git", "clone", "--bare", "--quiet", "--depth=1", h.url, tmpDir)
	cmd.Stderr = io.Discard
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("fetching remote refs: %w", err)
	}

	refsPath := filepath.Join(tmpDir, "tomb.refs.age")
	encData, err := os.ReadFile(refsPath)
	if err != nil {
		return nil, err
	}

	var sb strings.Builder
	if err := crypt.Decrypt(&sb, strings.NewReader(string(encData)), identities); err != nil {
		return nil, fmt.Errorf("decrypting refs: %w", err)
	}

	var refs []string
	for _, line := range strings.Split(strings.TrimSpace(sb.String()), "\n") {
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

// loadIdentities loads the user's SSH private keys for decryption.
func loadIdentities() ([]age.Identity, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, err
	}

	var identities []age.Identity
	keyFiles := []string{"id_ed25519", "id_rsa"}

	for _, name := range keyFiles {
		path := filepath.Join(home, ".ssh", name)
		data, err := os.ReadFile(path)
		if err != nil {
			continue // Key file doesn't exist, skip.
		}
		id, err := agessh.ParseIdentity(data)
		if err != nil {
			continue // Not a supported key type, skip.
		}
		identities = append(identities, id)
	}

	if len(identities) == 0 {
		return nil, fmt.Errorf("no SSH keys found in ~/.ssh/ (looked for %s)", strings.Join(keyFiles, ", "))
	}

	return identities, nil
}
