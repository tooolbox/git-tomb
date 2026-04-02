package remote

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"filippo.io/age"
	"filippo.io/age/agessh"
	"golang.org/x/crypto/ssh"

	"github.com/tooolbox/git-tomb/crypt"
	"github.com/tooolbox/git-tomb/tomb"
)

// TestE2E_PushAndClone exercises the full push and fetch flow:
//
//  1. Generate a test SSH keypair
//  2. Create a "local" repo, init tomb, add files, commit
//  3. Push to a bare "remote" repo via the rewrite engine
//  4. Verify the remote contains scrambled filenames and encrypted content
//  5. Fetch into a fresh "clone" repo and verify plaintext is recovered
func TestE2E_PushAndClone(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping e2e test in short mode")
	}

	// Set up temp directory structure.
	tmp := t.TempDir()
	sshDir := filepath.Join(tmp, "ssh")
	localDir := filepath.Join(tmp, "local")
	remoteDir := filepath.Join(tmp, "remote.git")
	cloneDir := filepath.Join(tmp, "clone")

	for _, d := range []string{sshDir, localDir, cloneDir} {
		must(t, os.MkdirAll(d, 0o700))
	}

	// 1. Generate test SSH keypair.
	pubKeyStr, privKeyPath := generateTestKey(t, sshDir)
	_ = privKeyPath

	// Parse the public key for age.
	recipient, err := agessh.ParseRecipient(pubKeyStr)
	if err != nil {
		t.Fatalf("parsing public key as age recipient: %v", err)
	}

	privPEM, err := os.ReadFile(privKeyPath)
	if err != nil {
		t.Fatalf("reading private key: %v", err)
	}
	identity, err := agessh.ParseIdentity(privPEM)
	if err != nil {
		t.Fatalf("parsing private key as age identity: %v", err)
	}

	// 2. Create bare remote repo.
	git(t, "", "init", "--bare", "--quiet", remoteDir)

	// 3. Create local repo and initialize tomb FIRST so .tomb/ is committed.
	git(t, "", "init", "--quiet", localDir)
	git(t, localDir, "config", "user.email", "test@test.com")
	git(t, localDir, "config", "user.name", "Test User")

	tombRoot := localDir
	cfg := &tomb.Config{
		Recipients: []tomb.Recipient{
			{
				Provider: "file",
				Username: "test",
				Keys: []tomb.PinnedKey{
					{Raw: pubKeyStr, Fingerprint: "test-fp"},
				},
			},
		},
		Scramble: tomb.ScrambleFull,
	}
	must(t, tomb.SaveConfig(tombRoot, cfg))
	must(t, tomb.GenerateSecret(tombRoot, []age.Recipient{recipient}))

	// Load the secret.
	secret, err := tomb.LoadSecret(tombRoot, []age.Identity{identity})
	if err != nil {
		t.Fatalf("loading secret: %v", err)
	}

	// Now add files and commit (including .tomb/).
	writeFile(t, localDir, "README.md", "# Hello World\n\nThis is a test repo.\n")
	writeFile(t, localDir, "src/main.go", "package main\n\nfunc main() {\n\tfmt.Println(\"hello\")\n}\n")
	writeFile(t, localDir, "src/util.go", "package main\n\nfunc add(a, b int) int { return a + b }\n")
	writeFile(t, localDir, "docs/guide.txt", "This is the user guide.\n")

	git(t, localDir, "add", "-A")
	git(t, localDir, "commit", "--quiet", "-m", "Initial commit with some files")

	// Add a second commit to test incremental handling.
	writeFile(t, localDir, "CHANGELOG.md", "## v0.1.0\n- Initial release\n")
	git(t, localDir, "add", "-A")
	git(t, localDir, "commit", "--quiet", "-m", "Add changelog")

	// 5. Push using the rewrite engine.
	localGitDir := filepath.Join(localDir, ".git")
	cm := newCommitMap()

	// Create a temp bare repo for staging encrypted objects.
	pushWorkDir := filepath.Join(tmp, "push-work")
	must(t, os.MkdirAll(pushWorkDir, 0o700))
	git(t, "", "init", "--bare", "--quiet", pushWorkDir)

	rw, err := newRewriter(secret, crypt.ScrambleFull, cm, pushWorkDir, localGitDir)
	if err != nil {
		t.Fatalf("newRewriter: %v", err)
	}

	// Get the local HEAD SHA.
	headSHA := strings.TrimSpace(gitOutput(t, localDir, "rev-parse", "HEAD"))

	// Encrypt the commit chain.
	remoteSHA, err := rw.encryptCommit(headSHA)
	if err != nil {
		t.Fatalf("encryptCommit: %v", err)
	}
	t.Logf("local HEAD %s → remote %s", headSHA[:8], remoteSHA[:8])

	// Update the ref in the push work repo and push to the bare remote.
	git(t, pushWorkDir, "update-ref", "refs/heads/main", remoteSHA)
	git(t, pushWorkDir, "push", remoteDir, "refs/heads/main:refs/heads/main")

	// 6. Verify the remote contains scrambled files.
	t.Log("--- Verifying remote repo contents ---")
	verifyRemoteScrambled(t, remoteDir, secret)

	// 7. Fetch into a fresh clone repo and verify plaintext.
	// The clone has NO .tomb/ initially — decryptCommit must include it
	// from the remote tree so the collaborator can access the secret.
	t.Log("--- Fetching into fresh clone ---")
	cloneGitDir := filepath.Join(cloneDir, ".git")
	git(t, "", "init", "--quiet", cloneDir)
	git(t, cloneDir, "config", "user.email", "test@test.com")
	git(t, cloneDir, "config", "user.name", "Test User")

	// Create a temp bare repo to fetch remote objects into.
	fetchWorkDir := filepath.Join(tmp, "fetch-work")
	must(t, os.MkdirAll(fetchWorkDir, 0o700))
	git(t, "", "init", "--bare", "--quiet", fetchWorkDir)
	git(t, fetchWorkDir, "fetch", "--quiet", remoteDir, "+refs/*:refs/*")

	// The clone needs the secret to decrypt. In real usage, the helper
	// extracts .tomb/ from the remote. Here we simulate by using the
	// same secret (the collaborator can decrypt secret.age with their key).
	cm2 := newCommitMap()
	rw2, err := newRewriter(secret, crypt.ScrambleFull, cm2, fetchWorkDir, cloneGitDir)
	if err != nil {
		t.Fatalf("newRewriter: %v", err)
	}

	// Decrypt the commit chain.
	localSHA, err := rw2.decryptCommit(remoteSHA)
	if err != nil {
		t.Fatalf("decryptCommit: %v", err)
	}
	t.Logf("remote %s → local %s", remoteSHA[:8], localSHA[:8])

	// Update ref and checkout.
	git(t, cloneDir, "update-ref", "refs/heads/main", localSHA)
	git(t, cloneDir, "checkout", "main")

	// 8. Verify the clone has the original files.
	verifyFile(t, cloneDir, "README.md", "# Hello World\n\nThis is a test repo.\n")
	verifyFile(t, cloneDir, "src/main.go", "package main\n\nfunc main() {\n\tfmt.Println(\"hello\")\n}\n")
	verifyFile(t, cloneDir, "src/util.go", "package main\n\nfunc add(a, b int) int { return a + b }\n")
	verifyFile(t, cloneDir, "docs/guide.txt", "This is the user guide.\n")
	verifyFile(t, cloneDir, "CHANGELOG.md", "## v0.1.0\n- Initial release\n")

	// Verify commit messages were preserved.
	log := gitOutput(t, cloneDir, "log", "--oneline")
	if !strings.Contains(log, "Add changelog") {
		t.Errorf("expected 'Add changelog' in git log, got:\n%s", log)
	}
	if !strings.Contains(log, "Initial commit with some files") {
		t.Errorf("expected 'Initial commit with some files' in git log, got:\n%s", log)
	}

	// Verify commit count.
	count := strings.Count(strings.TrimSpace(log), "\n") + 1
	if count != 2 {
		t.Errorf("expected 2 commits, got %d:\n%s", count, log)
	}

	t.Log("--- E2E test passed ---")
}

// TestE2E_ScrambleModes verifies all three scramble modes produce correct output.
func TestE2E_ScrambleModes(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping e2e test in short mode")
	}

	modes := []struct {
		name string
		mode crypt.ScrambleMode
	}{
		{"full", crypt.ScrambleFull},
		{"keep-extensions", crypt.ScrambleKeepExtensions},
		{"keep-filenames", crypt.ScrambleKeepFilenames},
	}

	for _, tt := range modes {
		t.Run(tt.name, func(t *testing.T) {
			tmp := t.TempDir()
			sshDir := filepath.Join(tmp, "ssh")
			localDir := filepath.Join(tmp, "local")
			remoteDir := filepath.Join(tmp, "remote.git")

			for _, d := range []string{sshDir, localDir} {
				must(t, os.MkdirAll(d, 0o700))
			}

			pubKeyStr, privKeyPath := generateTestKey(t, sshDir)
			recipient, _ := agessh.ParseRecipient(pubKeyStr)
			privPEM, _ := os.ReadFile(privKeyPath)
			identity, _ := agessh.ParseIdentity(privPEM)

			git(t, "", "init", "--bare", "--quiet", remoteDir)
			git(t, "", "init", "--quiet", localDir)
			git(t, localDir, "config", "user.email", "test@test.com")
			git(t, localDir, "config", "user.name", "Test User")

			// Init tomb BEFORE commits so .tomb/ is in the tree.
			cfg := &tomb.Config{
				Recipients: []tomb.Recipient{
					{Provider: "file", Username: "test", Keys: []tomb.PinnedKey{{Raw: pubKeyStr, Fingerprint: "fp"}}},
				},
				Scramble: tomb.ScrambleMode(tt.mode),
			}
			must(t, tomb.SaveConfig(localDir, cfg))
			must(t, tomb.GenerateSecret(localDir, []age.Recipient{recipient}))
			secret, _ := tomb.LoadSecret(localDir, []age.Identity{identity})

			writeFile(t, localDir, "src/main.go", "package main\n")
			writeFile(t, localDir, "docs/README.md", "# Docs\n")
			git(t, localDir, "add", "-A")
			git(t, localDir, "commit", "--quiet", "-m", "init")

			localGitDir := filepath.Join(localDir, ".git")
			workDir := filepath.Join(tmp, "work")
			must(t, os.MkdirAll(workDir, 0o700))
			git(t, "", "init", "--bare", "--quiet", workDir)

			rw, err := newRewriter(secret, tt.mode, newCommitMap(), workDir, localGitDir)
			if err != nil {
				t.Fatalf("newRewriter: %v", err)
			}

			headSHA := strings.TrimSpace(gitOutput(t, localDir, "rev-parse", "HEAD"))
			remoteSHA, err := rw.encryptCommit(headSHA)
			if err != nil {
				t.Fatalf("encryptCommit: %v", err)
			}

			git(t, workDir, "update-ref", "refs/heads/main", remoteSHA)
			git(t, workDir, "push", remoteDir, "refs/heads/main:refs/heads/main")

			// Check what files exist in the remote.
			files := gitOutput(t, remoteDir, "ls-tree", "-r", "--name-only", "refs/heads/main")
			t.Logf("Remote tree (%s mode):\n%s", tt.name, files)

			lines := strings.Split(strings.TrimSpace(files), "\n")

			// Helper to skip non-content entries.
			isPassthrough := func(f string) bool {
				return f == crypt.ManifestFile || strings.HasPrefix(f, ".tomb/") || f == ".tomb"
			}

			switch tt.mode {
			case crypt.ScrambleFull:
				for _, f := range lines {
					if isPassthrough(f) {
						continue
					}
					if !strings.HasSuffix(f, ".tomb") {
						t.Errorf("expected .tomb extension in full mode, got %q", f)
					}
					// No original names should appear.
					if strings.Contains(f, "main") || strings.Contains(f, "README") || strings.Contains(f, "src") || strings.Contains(f, "docs") {
						t.Errorf("original name leaked in full mode: %q", f)
					}
				}

			case crypt.ScrambleKeepExtensions:
				for _, f := range lines {
					if isPassthrough(f) {
						continue
					}
					// Should have original extensions.
					if strings.Contains(f, ".tomb") {
						t.Errorf("should not have .tomb extension in keep-extensions mode: %q", f)
					}
					// Should still have scrambled names (no "main" or "README").
					base := filepath.Base(f)
					name := strings.TrimSuffix(base, filepath.Ext(base))
					if name == "main" || name == "README" {
						t.Errorf("original filename should be scrambled in keep-extensions mode: %q", f)
					}
				}

			case crypt.ScrambleKeepFilenames:
				foundMain := false
				foundReadme := false
				for _, f := range lines {
					if isPassthrough(f) {
						continue
					}
					base := filepath.Base(f)
					if base == "main.go" {
						foundMain = true
					}
					if base == "README.md" {
						foundReadme = true
					}
					// Directories should be scrambled.
					dir := filepath.Dir(f)
					if dir == "src" || dir == "docs" {
						t.Errorf("directory name should be scrambled: %q", f)
					}
				}
				if !foundMain {
					t.Error("expected main.go filename preserved in keep-filenames mode")
				}
				if !foundReadme {
					t.Error("expected README.md filename preserved in keep-filenames mode")
				}
			}
		})
	}
}

// --- helpers ---

func generateTestKey(t *testing.T, dir string) (pubKeyStr string, privKeyPath string) {
	t.Helper()

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generating ed25519 key: %v", err)
	}

	sshPub, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatalf("creating SSH public key: %v", err)
	}
	pubKeyStr = strings.TrimSpace(string(ssh.MarshalAuthorizedKey(sshPub)))

	// Write public key.
	pubPath := filepath.Join(dir, "id_ed25519.pub")
	must(t, os.WriteFile(pubPath, []byte(pubKeyStr+"\n"), 0o644))

	// Marshal private key to OpenSSH PEM format.
	privPEM, err := ssh.MarshalPrivateKey(priv, "")
	if err != nil {
		t.Fatalf("marshaling private key: %v", err)
	}
	privKeyPath = filepath.Join(dir, "id_ed25519")
	must(t, os.WriteFile(privKeyPath, pem.EncodeToMemory(privPEM), 0o600))

	return pubKeyStr, privKeyPath
}

func git(t *testing.T, dir string, args ...string) {
	t.Helper()
	cmd := exec.Command("git", args...)
	if dir != "" {
		cmd.Dir = dir
	}
	cmd.Env = append(os.Environ(),
		"GIT_CONFIG_GLOBAL=/dev/null",
		"GIT_CONFIG_SYSTEM=/dev/null",
	)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %s (dir=%s): %v\n%s", strings.Join(args, " "), dir, err, out)
	}
}

func gitOutput(t *testing.T, dir string, args ...string) string {
	t.Helper()
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(),
		"GIT_CONFIG_GLOBAL=/dev/null",
		"GIT_CONFIG_SYSTEM=/dev/null",
	)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %s (dir=%s): %v\n%s", strings.Join(args, " "), dir, err, out)
	}
	return string(out)
}

func writeFile(t *testing.T, dir, relPath, content string) {
	t.Helper()
	full := filepath.Join(dir, filepath.FromSlash(relPath))
	must(t, os.MkdirAll(filepath.Dir(full), 0o755))
	must(t, os.WriteFile(full, []byte(content), 0o644))
}

func verifyFile(t *testing.T, dir, relPath, expectedContent string) {
	t.Helper()
	full := filepath.Join(dir, filepath.FromSlash(relPath))
	data, err := os.ReadFile(full)
	if err != nil {
		t.Fatalf("reading %s: %v", relPath, err)
	}
	if string(data) != expectedContent {
		t.Errorf("file %s: expected %q, got %q", relPath, expectedContent, string(data))
	}
}

func verifyRemoteScrambled(t *testing.T, remoteDir string, secret []byte) {
	t.Helper()

	// List all files in the remote's HEAD tree.
	files := gitOutput(t, remoteDir, "ls-tree", "-r", "--name-only", "refs/heads/main")
	t.Logf("Remote tree:\n%s", files)

	lines := strings.Split(strings.TrimSpace(files), "\n")

	// Should have the manifest file.
	foundManifest := false
	for _, f := range lines {
		if f == crypt.ManifestFile {
			foundManifest = true
		}
	}
	if !foundManifest {
		t.Error("manifest file not found in remote tree")
	}

	// No original filenames should appear (except in .tomb/ which is passthrough).
	for _, f := range lines {
		if f == crypt.ManifestFile || strings.HasPrefix(f, ".tomb/") || f == ".tomb" {
			continue
		}
		for _, orig := range []string{"README", "main.go", "util.go", "guide.txt", "CHANGELOG", "src", "docs"} {
			if strings.Contains(f, orig) {
				t.Errorf("original name %q leaked in remote file %q", orig, f)
			}
		}
	}

	// Verify the commit message is encrypted (not plaintext).
	msg := gitOutput(t, remoteDir, "log", "--format=%s", "-1", "refs/heads/main")
	msg = strings.TrimSpace(msg)
	if strings.Contains(msg, "changelog") || strings.Contains(msg, "Initial") {
		t.Errorf("commit message not encrypted: %q", msg)
	}
	if !strings.HasPrefix(msg, crypt.TombMessagePrefix) {
		t.Errorf("commit message missing tomb prefix: %q", msg)
	}
	t.Logf("Remote commit message: %.60s...", msg)
}

// TestE2E_PushFetchWithGitDirEnv verifies that perFilePush and perFileFetch
// work correctly when GIT_DIR is set in the environment, as happens when git
// invokes the remote helper. Previously, the inherited GIT_DIR caused
// git init --bare in the temp directory to target the wrong repo.
func TestE2E_PushFetchWithGitDirEnv(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping e2e test in short mode")
	}

	tmp := t.TempDir()
	sshDir := filepath.Join(tmp, "ssh")
	localDir := filepath.Join(tmp, "local")
	remoteDir := filepath.Join(tmp, "remote.git")
	cloneDir := filepath.Join(tmp, "clone")

	for _, d := range []string{sshDir, localDir, cloneDir} {
		must(t, os.MkdirAll(d, 0o700))
	}

	// Generate test SSH keypair.
	pubKeyStr, privKeyPath := generateTestKey(t, sshDir)
	privPEM, err := os.ReadFile(privKeyPath)
	if err != nil {
		t.Fatalf("reading private key: %v", err)
	}
	recipient, err := agessh.ParseRecipient(pubKeyStr)
	if err != nil {
		t.Fatalf("parsing public key: %v", err)
	}
	identity, err := agessh.ParseIdentity(privPEM)
	if err != nil {
		t.Fatalf("parsing private key: %v", err)
	}

	// Create bare remote repo.
	git(t, "", "init", "--bare", "--quiet", remoteDir)

	// Create local repo with tomb config and files.
	git(t, "", "init", "--quiet", localDir)
	git(t, localDir, "config", "user.email", "test@test.com")
	git(t, localDir, "config", "user.name", "Test User")

	cfg := &tomb.Config{
		Recipients: []tomb.Recipient{
			{
				Provider: "file",
				Username: "test",
				Keys:     []tomb.PinnedKey{{Raw: pubKeyStr, Fingerprint: "test-fp"}},
			},
		},
		Scramble: tomb.ScrambleFull,
	}
	must(t, tomb.SaveConfig(localDir, cfg))
	must(t, tomb.GenerateSecret(localDir, []age.Recipient{recipient}))

	writeFile(t, localDir, "hello.txt", "hello world\n")
	git(t, localDir, "add", "-A")
	git(t, localDir, "commit", "--quiet", "-m", "Initial commit")

	localGitDir := filepath.Join(localDir, ".git")
	headSHA := strings.TrimSpace(gitOutput(t, localDir, "rev-parse", "HEAD"))

	// Redirect stdout since perFilePush/perFileFetch write protocol responses there.
	origStdout := os.Stdout
	devNull, err := os.Open(os.DevNull)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { os.Stdout = origStdout }()

	// --- Test push with GIT_DIR set ---
	// Set GIT_DIR in the environment, simulating how git invokes the remote helper.
	// This is the key part of the test — it must not interfere with temp repo creation.
	t.Setenv("GIT_DIR", localGitDir)

	h := &helper{
		remoteName:       "origin",
		url:              remoteDir,
		gitDir:           localGitDir,
		cachedIdentities: []age.Identity{identity},
	}

	os.Stdout = devNull
	err = h.perFilePush([]string{"refs/heads/master:refs/heads/master"})
	os.Stdout = origStdout
	if err != nil {
		t.Fatalf("perFilePush with GIT_DIR set: %v", err)
	}

	// Clear GIT_DIR for verification and setup steps.
	t.Setenv("GIT_DIR", "")
	os.Unsetenv("GIT_DIR")

	// Verify the remote has content (use --git-dir to target the remote).
	remoteRefs := gitOutput(t, remoteDir, "show-ref")
	if remoteRefs == "" {
		t.Fatal("remote has no refs after push")
	}
	t.Logf("Remote refs after push:\n%s", remoteRefs)

	git(t, "", "init", "--quiet", cloneDir)
	git(t, cloneDir, "config", "user.email", "test@test.com")
	git(t, cloneDir, "config", "user.name", "Test User")

	// Copy .tomb/ to the clone so it can load the secret.
	// Remove commit-map.json since it references objects that only exist in the
	// original local repo, not in this fresh clone.
	tombSrc := filepath.Join(localDir, ".tomb")
	tombDst := filepath.Join(cloneDir, ".tomb")
	must(t, copyDir(tombSrc, tombDst))
	os.Remove(filepath.Join(tombDst, "commit-map.json"))

	cloneGitDir := filepath.Join(cloneDir, ".git")

	// Get the encrypted commit SHA from the remote (first ref line).
	remoteSHA := strings.Fields(strings.TrimSpace(remoteRefs))[0]

	// Now set GIT_DIR to the clone, simulating git invoking the remote helper.
	t.Setenv("GIT_DIR", cloneGitDir)

	h2 := &helper{
		remoteName:       "origin",
		url:              remoteDir,
		gitDir:           cloneGitDir,
		cachedIdentities: []age.Identity{identity},
	}

	// Format: "sha refname" — the remote SHA and the local ref to update.
	os.Stdout = devNull
	err = h2.perFileFetch([]string{remoteSHA + " refs/heads/master"})
	os.Stdout = origStdout
	if err != nil {
		t.Fatalf("perFileFetch with GIT_DIR set: %v", err)
	}

	// Verify the clone has refs.
	cloneRefs := gitOutput(t, cloneDir, "show-ref")
	t.Logf("Clone refs after fetch:\n%s", cloneRefs)

	// Checkout and verify file content.
	refLines := strings.Split(strings.TrimSpace(cloneRefs), "\n")
	if len(refLines) == 0 || refLines[0] == "" {
		t.Fatal("no refs in clone after fetch")
	}
	cloneSHA := strings.Fields(refLines[0])[0]
	// Clear GIT_DIR for checkout.
	t.Setenv("GIT_DIR", "")
	os.Unsetenv("GIT_DIR")
	git(t, cloneDir, "checkout", "--quiet", "-f", cloneSHA)
	verifyFile(t, cloneDir, "hello.txt", "hello world\n")

	t.Logf("Push local HEAD %s succeeded with GIT_DIR set", headSHA[:8])
}

// copyDir recursively copies a directory tree.
func copyDir(src, dst string) error {
	return filepath.Walk(src, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(src, path)
		target := filepath.Join(dst, rel)
		if info.IsDir() {
			return os.MkdirAll(target, info.Mode())
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		return os.WriteFile(target, data, info.Mode())
	})
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}
