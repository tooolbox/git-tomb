// Package remote implements the git remote helper protocol for tomb.
//
// Git invokes git-remote-tomb when it encounters a URL like tomb::https://github.com/user/repo.git
// The helper speaks the fetch/push remote helper protocol over stdin/stdout.
//
// The remote repository is a normal git repo containing encrypted files with
// scrambled filenames. Anyone can clone it and see the files — but the content
// and names are only meaningful to recipients who hold the correct keys.
package remote

import (
	"bufio"
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
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

	// cachedIdentities holds SSH identities loaded once per session.
	cachedIdentities []age.Identity
}

func (h *helper) identities() ([]age.Identity, error) {
	if h.cachedIdentities != nil {
		return h.cachedIdentities, nil
	}
	ids, err := loadIdentities()
	if err != nil {
		return nil, err
	}
	h.cachedIdentities = ids
	return ids, nil
}

func (h *helper) capabilities() error {
	fmt.Println("fetch")
	fmt.Println("push")
	fmt.Println()
	return nil
}

// list reports the refs available on the remote.
func (h *helper) list(forPush string) error {
	mode := h.encryptionMode()
	if mode == tomb.EncryptionBundle {
		return h.bundleList(forPush)
	}
	return h.perFileList(forPush)
}

// perFileList reports refs for per-file mode by ls-remote + unscrambling.
func (h *helper) perFileList(forPush string) error {
	cmd := exec.Command("git", "ls-remote", h.url)
	cmd.Stderr = os.Stderr
	out, err := cmd.Output()
	if err != nil {
		fmt.Fprintf(os.Stderr, "tomb: list refs: %v\n", err)
		fmt.Println()
		return nil
	}

	root, cfg, secret, err := h.loadTombState()
	if err != nil {
		fmt.Fprintf(os.Stderr, "tomb: warning: could not load tomb config: %v\n", err)
		fmt.Print(string(out))
		fmt.Println()
		return nil
	}
	_ = root

	refMap := h.buildRefMap(cfg, secret)

	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		if line == "" {
			continue
		}
		parts := strings.Fields(line)
		if len(parts) < 2 {
			continue
		}
		sha := parts[0]
		ref := parts[1]

		if orig, ok := refMap[ref]; ok {
			ref = orig
		}

		fmt.Fprintf(os.Stderr, "tomb: ref: %s %s\n", sha, ref)
		fmt.Printf("%s %s\n", sha, ref)
	}

	fmt.Println()
	return nil
}

// encryptionMode reads the config to determine bundle vs per-file mode.
func (h *helper) encryptionMode() tomb.EncryptionMode {
	root, err := tomb.FindRoot(h.repoDir())
	if err != nil {
		return tomb.EncryptionBundle // safe fallback for legacy repos
	}
	cfg, err := tomb.LoadConfig(root)
	if err != nil {
		return tomb.EncryptionBundle
	}
	if cfg.Encryption == "" {
		return tomb.EncryptionBundle
	}
	return cfg.Encryption
}

// fetch dispatches to the appropriate fetch implementation.
func (h *helper) fetch(refs []string) error {
	mode := h.encryptionMode()
	if mode == tomb.EncryptionBundle {
		return h.bundleFetch(refs)
	}
	return h.perFileFetch(refs)
}

// push dispatches to the appropriate push implementation.
func (h *helper) push(specs []string) error {
	mode := h.encryptionMode()
	if mode == tomb.EncryptionBundle {
		return h.bundlePush(specs)
	}
	return h.perFilePush(specs)
}

// perFileFetch decrypts commits from the remote and injects plaintext objects locally.
func (h *helper) perFileFetch(refs []string) error {
	// Fetch the encrypted objects from the remote into a temp bare repo first,
	// because on a fresh clone we may need to extract .tomb/ from the remote
	// before we can load the secret.
	tmpDir, err := os.MkdirTemp("", "tomb-fetch-*")
	if err != nil {
		return err
	}
	defer os.RemoveAll(tmpDir)

	if err := run(tmpDir, "git", "init", "--bare", "--quiet"); err != nil {
		return fmt.Errorf("init temp repo: %w", err)
	}

	if err := run(tmpDir, "git", "fetch", "--quiet", h.url, "+refs/*:refs/*"); err != nil {
		return fmt.Errorf("fetching remote: %w", err)
	}

	// Try to load tomb state from the local repo.
	root, cfg, secret, err := h.loadTombState()
	if err != nil {
		// On a fresh clone, .tomb/ doesn't exist locally yet.
		// Extract it from the remote's latest commit.
		fmt.Fprintf(os.Stderr, "tomb: local .tomb/ not found, extracting from remote...\n")
		if extractErr := h.extractTombFromRemote(tmpDir); extractErr != nil {
			return fmt.Errorf("could not load tomb state locally or from remote: local: %v, remote: %v", err, extractErr)
		}
		// Retry loading state.
		root, cfg, secret, err = h.loadTombState()
		if err != nil {
			return fmt.Errorf("loading tomb state after extraction: %w", err)
		}
	}

	cm, err := loadCommitMap(root)
	if err != nil {
		return fmt.Errorf("loading commit map: %w", err)
	}

	absGitDir, _ := filepath.Abs(h.gitDir)
	mode := crypt.ScrambleMode(cfg.Scramble)
	if mode == "" {
		mode = crypt.ScrambleFull
	}

	rw, err := newRewriter(secret, mode, cm, tmpDir, absGitDir)
	if err != nil {
		return fmt.Errorf("creating rewriter: %w", err)
	}

	// For each ref the user wants to fetch, translate the commit chain.
	for _, ref := range refs {
		// ref is like "sha refname" — we need the sha.
		sha := strings.Fields(ref)[0]

		// The SHA from the remote points to an encrypted commit.
		// We need to find the corresponding remote SHA in our temp repo.
		// The ref in our temp repo might be scrambled.
		fmt.Fprintf(os.Stderr, "tomb: decrypting commit %s...\n", sha[:8])

		localSHA, err := rw.decryptCommit(sha)
		if err != nil {
			return fmt.Errorf("decrypting commit %s: %w", sha[:8], err)
		}

		// Update local ref to point to the decrypted commit.
		refName := ""
		parts := strings.Fields(ref)
		if len(parts) >= 2 {
			refName = parts[1]
		}
		if refName != "" {
			if err := rw.updateRef(absGitDir, refName, localSHA); err != nil {
				return fmt.Errorf("updating ref %s: %w", refName, err)
			}
		}
	}

	if err := saveCommitMap(root, cm); err != nil {
		fmt.Fprintf(os.Stderr, "tomb: warning: could not save commit map: %v\n", err)
	}

	fmt.Println()
	return nil
}

// perFilePush encrypts local commits and pushes them to the remote.
func (h *helper) perFilePush(specs []string) error {
	root, cfg, secret, err := h.loadTombState()
	if err != nil {
		return fmt.Errorf("loading tomb state: %w", err)
	}

	if len(cfg.Recipients) == 0 {
		return fmt.Errorf("no recipients configured — run 'git tomb add <provider> <username>' first")
	}

	cm, err := loadCommitMap(root)
	if err != nil {
		return fmt.Errorf("loading commit map: %w", err)
	}

	// Create a temp bare repo for staging encrypted objects.
	tmpDir, err := os.MkdirTemp("", "tomb-push-*")
	if err != nil {
		return err
	}
	defer os.RemoveAll(tmpDir)

	if err := run(tmpDir, "git", "init", "--bare", "--quiet"); err != nil {
		return fmt.Errorf("init temp repo: %w", err)
	}

	absGitDir, _ := filepath.Abs(h.gitDir)
	mode := crypt.ScrambleMode(cfg.Scramble)
	if mode == "" {
		mode = crypt.ScrambleFull
	}

	rw, err := newRewriter(secret, mode, cm, tmpDir, absGitDir)
	if err != nil {
		return fmt.Errorf("creating rewriter: %w", err)
	}

	// Fetch existing remote objects so we can do incremental push.
	// Non-fatal if remote is empty.
	fetchCmd := exec.Command("git", "fetch", "--quiet", h.url, "+refs/*:refs/*")
	fetchCmd.Dir = tmpDir
	fetchCmd.Stderr = os.Stderr
	fetchCmd.Run() // ignore error — remote might be empty

	// Process each push spec.
	for _, spec := range specs {
		src, dst, _ := strings.Cut(spec, ":")
		if src == "" {
			// Delete ref — not supported yet.
			fmt.Printf("error %s unsupported delete\n", dst)
			continue
		}

		// Resolve the local ref to a SHA.
		localSHA, err := rw.resolveRef(absGitDir, src)
		if err != nil {
			fmt.Printf("error %s %v\n", dst, err)
			continue
		}

		fmt.Fprintf(os.Stderr, "tomb: encrypting commit %s for %s...\n", localSHA[:8], dst)

		remoteSHA, err := rw.encryptCommit(localSHA)
		if err != nil {
			fmt.Printf("error %s %v\n", dst, err)
			continue
		}

		// Scramble the destination ref name.
		scrambledDst := crypt.ScrambleRef(secret, dst)
		fmt.Fprintf(os.Stderr, "tomb: %s → %s (sha %s)\n", dst, scrambledDst, remoteSHA[:8])

		// Update the ref in the temp repo.
		if err := rw.updateRef(tmpDir, scrambledDst, remoteSHA); err != nil {
			fmt.Printf("error %s %v\n", dst, err)
			continue
		}

		// Push this ref to the remote.
		pushCmd := exec.Command("git", "push", h.url, scrambledDst+":"+scrambledDst)
		pushCmd.Dir = tmpDir
		pushCmd.Stderr = os.Stderr
		if err := pushCmd.Run(); err != nil {
			fmt.Printf("error %s push failed: %v\n", dst, err)
			continue
		}

		fmt.Printf("ok %s\n", dst)
	}

	if err := saveCommitMap(root, cm); err != nil {
		fmt.Fprintf(os.Stderr, "tomb: warning: could not save commit map: %v\n", err)
	}

	fmt.Println()
	return nil
}

// loadTombState loads the config, secret, and identities needed for operations.
func (h *helper) loadTombState() (root string, cfg *tomb.Config, secret []byte, err error) {
	root, err = tomb.FindRoot(h.repoDir())
	if err != nil {
		return
	}

	cfg, err = tomb.LoadConfig(root)
	if err != nil {
		return
	}

	identities, err := h.identities()
	if err != nil {
		return
	}

	secret, err = tomb.LoadSecret(root, identities)
	return
}

// extractTombFromRemote finds .tomb/ in the remote's latest commit and
// writes it to the local working tree. This is needed on a fresh clone
// where the local repo has no .tomb/ yet.
func (h *helper) extractTombFromRemote(tmpDir string) error {
	// Find any ref in the temp repo to get a commit with a .tomb/ entry.
	cmd := exec.Command("git", "for-each-ref", "--format=%(objectname)", "--count=1", "refs/")
	cmd.Dir = tmpDir
	out, err := cmd.Output()
	if err != nil || strings.TrimSpace(string(out)) == "" {
		return fmt.Errorf("no refs found in remote")
	}
	commitSHA := strings.TrimSpace(string(out))

	// Get the tree SHA from the commit.
	cmd = exec.Command("git", "rev-parse", commitSHA+"^{tree}")
	cmd.Dir = tmpDir
	out, err = cmd.Output()
	if err != nil {
		return fmt.Errorf("getting tree from commit: %w", err)
	}
	treeSHA := strings.TrimSpace(string(out))

	// Look for .tomb/ in the tree.
	cmd = exec.Command("git", "ls-tree", treeSHA, ".tomb/")
	cmd.Dir = tmpDir
	out, err = cmd.Output()
	if err != nil || strings.TrimSpace(string(out)) == "" {
		return fmt.Errorf(".tomb/ not found in remote tree")
	}

	// Use git archive to extract .tomb/ into the local working tree.
	repoDir := h.repoDir()
	cmd = exec.Command("git", "archive", "--format=tar", commitSHA, ".tomb/")
	cmd.Dir = tmpDir

	tar := exec.Command("tar", "xf", "-")
	tar.Dir = repoDir
	tar.Stdin, _ = cmd.StdoutPipe()
	tar.Stderr = os.Stderr

	if err := tar.Start(); err != nil {
		return fmt.Errorf("starting tar: %w", err)
	}
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("git archive: %w", err)
	}
	if err := tar.Wait(); err != nil {
		return fmt.Errorf("tar extract: %w", err)
	}

	fmt.Fprintf(os.Stderr, "tomb: extracted .tomb/ from remote\n")
	return nil
}

// buildRefMap builds a scrambled→original ref mapping for all known local refs.
func (h *helper) buildRefMap(cfg *tomb.Config, secret []byte) map[string]string {
	refMap := make(map[string]string)

	// Get local refs and compute their scrambled equivalents.
	cmd := exec.Command("git", "show-ref")
	cmd.Dir = h.repoDir()
	out, err := cmd.Output()
	if err != nil {
		return refMap
	}

	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		if line == "" {
			continue
		}
		parts := strings.Fields(line)
		if len(parts) < 2 {
			continue
		}
		ref := parts[1]
		scrambled := crypt.ScrambleRef(secret, ref)
		refMap[scrambled] = ref
	}

	return refMap
}

func (rw *rewriter) resolveRef(gitDir, ref string) (string, error) {
	out, err := rw.gitOutput(gitDir, "rev-parse", ref)
	if err != nil {
		return "", fmt.Errorf("resolving %s: %w", ref, err)
	}
	return strings.TrimSpace(string(out)), nil
}

func (rw *rewriter) updateRef(gitDir, ref, sha string) error {
	cmd := exec.Command("git", "update-ref", ref, sha)
	cmd.Dir = gitDir
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

func (h *helper) repoDir() string {
	abs, _ := filepath.Abs(h.gitDir)
	if filepath.Base(abs) == ".git" {
		return filepath.Dir(abs)
	}
	return abs
}

// forgivingIdentity wraps an age.Identity and converts any error during
// Unwrap into age.ErrIncorrectIdentity, so that age continues trying
// other identities instead of aborting. Once a key fails, it remembers
// and skips immediately on subsequent calls.
type forgivingIdentity struct {
	inner  age.Identity
	name   string
	failed bool
}

func (f *forgivingIdentity) Unwrap(stanzas []*age.Stanza) ([]byte, error) {
	if f.failed {
		return nil, age.ErrIncorrectIdentity
	}
	fileKey, err := f.inner.Unwrap(stanzas)
	if err != nil {
		f.failed = true
		fmt.Fprintf(os.Stderr, "tomb: key %s failed: %v, trying next key...\n", f.name, err)
		return nil, age.ErrIncorrectIdentity
	}
	return fileKey, nil
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
		keyPath := path // capture for closure
		encID, err := agessh.NewEncryptedSSHIdentity(pubKey, pemData, func() ([]byte, error) {
			return readPassphrase(fmt.Sprintf("Enter passphrase for %s: ", keyPath))
		})
		if err != nil {
			fmt.Fprintf(os.Stderr, "tomb: skipping %s: %v\n", name, err)
			continue
		}
		fmt.Fprintf(os.Stderr, "tomb: loaded key %s (passphrase-protected)\n", name)
		// Wrap in a forgiving identity that returns ErrIncorrectIdentity
		// on passphrase failures, so age continues to the next identity.
		identities = append(identities, &forgivingIdentity{inner: encID, name: name})
	}

	if len(identities) == 0 {
		return nil, fmt.Errorf("no SSH keys found in %s (looked for %s)", dir, strings.Join(keyFiles, ", "))
	}

	return identities, nil
}

// readPassphrase prompts for a passphrase.
// Since stdin is used by the git remote helper protocol, we can't read from it.
// Strategy:
//  1. SSH_ASKPASS / GIT_ASKPASS — external program (works everywhere, including mintty)
//  2. /dev/tty — Unix terminals
//  3. Error with guidance
func readPassphrase(prompt string) ([]byte, error) {
	// Try SSH_ASKPASS or GIT_ASKPASS (works in mintty, GUI environments, CI, etc.)
	for _, env := range []string{"GIT_ASKPASS", "SSH_ASKPASS"} {
		askpass := os.Getenv(env)
		if askpass == "" {
			continue
		}
		cmd := exec.Command(askpass, prompt)
		cmd.Stderr = os.Stderr
		out, err := cmd.Output()
		if err != nil {
			fmt.Fprintf(os.Stderr, "tomb: %s (%s) failed: %v\n", env, askpass, err)
			continue
		}
		return bytes.TrimRight(out, "\r\n"), nil
	}

	// Try /dev/tty (Unix terminals).
	if runtime.GOOS != "windows" {
		tty, err := os.OpenFile("/dev/tty", os.O_RDWR, 0)
		if err == nil {
			defer tty.Close()
			fmt.Fprint(tty, prompt)
			pass, err := term.ReadPassword(int(tty.Fd()))
			fmt.Fprintln(tty)
			return pass, err
		}
	}

	return nil, fmt.Errorf("cannot prompt for passphrase: set SSH_ASKPASS or GIT_ASKPASS, or use ssh-add to load your key into the agent")
}

// run executes a command in the given directory, inheriting stderr.
func run(dir string, name string, args ...string) error {
	cmd := exec.Command(name, args...)
	cmd.Dir = dir
	cmd.Stderr = os.Stderr
	return cmd.Run()
}
