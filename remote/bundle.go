// Bundle-mode encryption: the entire repo is packed into a single encrypted
// git bundle. The remote sees only two opaque files (tomb.bundle.age and
// tomb.refs.age). Maximum privacy — hides file count, structure, and branch
// names — but requires a full re-upload on every push.
package remote

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/tooolbox/git-tomb/crypt"
	"github.com/tooolbox/git-tomb/tomb"
)

// bundleList reports refs by fetching the encrypted refs file from the remote.
func (h *helper) bundleList(forPush string) error {
	refs, err := h.fetchBundleRefs()
	if err != nil {
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

// bundleFetch decrypts and unbundles objects from the remote.
func (h *helper) bundleFetch(refs []string) error {
	identities, err := h.identities()
	if err != nil {
		return fmt.Errorf("loading SSH keys: %w", err)
	}

	// Clone the encrypted remote into a temp dir.
	tmpDir, err := os.MkdirTemp("", "tomb-fetch-*")
	if err != nil {
		return err
	}
	defer os.RemoveAll(tmpDir)

	// Init a temp bare repo and fetch the remote's content.
	initCmd := exec.Command("git", "init", "--bare", "--quiet", tmpDir)
	initCmd.Env = filterGitEnv(os.Environ())
	if err := initCmd.Run(); err != nil {
		return fmt.Errorf("init temp repo: %w", err)
	}

	fetchCmd := exec.Command("git", "--git-dir", tmpDir, "fetch", "--quiet", h.url, "+refs/heads/*:refs/heads/*")
	fetchCmd.Env = filterGitEnv(os.Environ())
	fetchCmd.Stderr = os.Stderr
	if err := fetchCmd.Run(); err != nil {
		return fmt.Errorf("fetching remote: %w", err)
	}

	// Find a commit SHA to extract the bundle from.
	refOut, err := exec.Command("git", "--git-dir", tmpDir, "for-each-ref", "--format=%(objectname)", "--count=1", "refs/").Output()
	if err != nil || strings.TrimSpace(string(refOut)) == "" {
		return fmt.Errorf("no refs found in remote")
	}
	commitSHA := strings.TrimSpace(string(refOut))

	// Read and decrypt the bundle.
	showCmd := exec.Command("git", "--git-dir", tmpDir, "show", commitSHA+":tomb.bundle.age")
	showCmd.Env = filterGitEnv(os.Environ())
	encData, err := showCmd.Output()
	if err != nil {
		return fmt.Errorf("reading encrypted bundle: %w", err)
	}

	decBundle, err := os.CreateTemp("", "tomb-bundle-*.bundle")
	if err != nil {
		return err
	}
	defer os.Remove(decBundle.Name())

	if err := crypt.Decrypt(decBundle, bytes.NewReader(encData), identities); err != nil {
		return fmt.Errorf("decrypting bundle: %w", err)
	}
	decBundle.Close()

	// Unbundle into the local repo.
	absGitDir, _ := filepath.Abs(h.gitDir)
	unbundleCmd := exec.Command("git", "--git-dir", absGitDir, "bundle", "unbundle", decBundle.Name())
	unbundleCmd.Env = filterGitEnv(os.Environ())
	unbundleCmd.Stderr = os.Stderr
	if err := unbundleCmd.Run(); err != nil {
		return fmt.Errorf("unbundling: %w", err)
	}

	fmt.Println()
	return nil
}

// bundlePush bundles, encrypts, and pushes to the remote.
func (h *helper) bundlePush(specs []string) error {
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

	// Create a temp working directory, commit encrypted files, and push.
	workDir, err := os.MkdirTemp("", "tomb-push-*")
	if err != nil {
		return err
	}
	defer os.RemoveAll(workDir)

	// Pass workDir explicitly — the inherited GIT_DIR env var from the parent
	// git process would otherwise cause init to target the wrong directory.
	if err := run(workDir, "git", "init", "--quiet", workDir); err != nil {
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

	// Commit and force push.
	if err := run(workDir, "git", "add", "-A"); err != nil {
		return err
	}
	if err := run(workDir, "git", "commit", "--quiet", "-m", "tomb: encrypted update"); err != nil {
		return fmt.Errorf("committing encrypted data: %w", err)
	}

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

func (h *helper) fetchBundleRefs() ([]string, error) {
	fmt.Fprintf(os.Stderr, "tomb: fetching refs from %s\n", h.url)

	identities, err := h.identities()
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

	// Init a temp bare repo and fetch the remote's content.
	if err := exec.Command("git", "init", "--bare", "--quiet", tmpDir).Run(); err != nil {
		return nil, fmt.Errorf("init temp repo: %w", err)
	}

	fetchCmd := exec.Command("git", "--git-dir", tmpDir, "fetch", "--quiet", h.url, "+refs/heads/*:refs/heads/*")
	fetchCmd.Env = filterGitEnv(os.Environ())
	fetchCmd.Stderr = os.Stderr
	if err := fetchCmd.Run(); err != nil {
		return nil, fmt.Errorf("fetching remote: %w", err)
	}

	// Find the first ref and extract the refs file from its tree.
	refOut, err := exec.Command("git", "--git-dir", tmpDir, "for-each-ref", "--format=%(objectname)", "--count=1", "refs/").Output()
	if err != nil || strings.TrimSpace(string(refOut)) == "" {
		return nil, fmt.Errorf("no refs found in remote")
	}
	commitSHA := strings.TrimSpace(string(refOut))

	// Extract tomb.refs.age from the commit's tree.
	showCmd := exec.Command("git", "--git-dir", tmpDir, "show", commitSHA+":tomb.refs.age")
	showCmd.Env = filterGitEnv(os.Environ())
	encData, err := showCmd.Output()
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
