package remote

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// TestE2E_ShellIntegration exercises the full tomb workflow using only CLI
// commands — no Go-level API calls, no simulations. This mirrors exactly how
// a user would interact with git-tomb.
//
// It tests both per-file and bundle encryption modes.
func TestE2E_ShellIntegration(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping shell integration test in short mode")
	}

	// Build binaries once for all subtests.
	binDir := t.TempDir()
	t.Log("Building git-tomb and git-remote-tomb...")
	buildBin(t, binDir, "git-tomb", "github.com/tooolbox/git-tomb/cmd/git-tomb")
	buildBin(t, binDir, "git-remote-tomb", "github.com/tooolbox/git-tomb/cmd/git-remote-tomb")

	t.Run("per-file", func(t *testing.T) {
		shellTestPerFile(t, binDir)
	})

	t.Run("bundle", func(t *testing.T) {
		shellTestBundle(t, binDir)
	})
}

// shellTestPerFile tests per-file encryption mode: push, verify scrambled
// remote, fetch into a fresh clone, verify plaintext.
func shellTestPerFile(t *testing.T, binDir string) {
	tmp := t.TempDir()

	sshDir := filepath.Join(tmp, ".ssh")
	localDir := filepath.Join(tmp, "local")
	remoteDir := filepath.Join(tmp, "remote.git")
	cloneDir := filepath.Join(tmp, "clone")

	for _, d := range []string{sshDir, localDir} {
		must(t, os.MkdirAll(d, 0o700))
	}

	env := shellTestEnv(binDir, tmp)
	run := shellRunner(t, env)

	// Generate SSH keypair.
	keyPath := filepath.Join(sshDir, "id_ed25519")
	run("", filepath.Join(binDir, binName("git-tomb")), "keygen", keyPath)

	// Create bare remote.
	run("", "git", "init", "--bare", "--quiet", remoteDir)

	// Create local repo with tomb.
	run("", "git", "init", "--quiet", localDir)
	run(localDir, "git", "config", "user.email", "test@test.com")
	run(localDir, "git", "config", "user.name", "Test User")
	run(localDir, filepath.Join(binDir, binName("git-tomb")), "init",
		"--encryption=per-file", "--scramble=full",
		"file", keyPath+".pub")

	// Add files and commit.
	writeFile(t, localDir, "README.md", "# Test Repo\n\nThis is a test.\n")
	writeFile(t, localDir, "src/main.go", "package main\n\nfunc main() {}\n")
	writeFile(t, localDir, "docs/guide.txt", "User guide content.\n")

	run(localDir, "git", "add", "-A")
	run(localDir, "git", "commit", "--quiet", "-m", "Initial commit with test files")

	writeFile(t, localDir, "CHANGELOG.md", "## v0.1.0\n- First release\n")
	run(localDir, "git", "add", "-A")
	run(localDir, "git", "commit", "--quiet", "-m", "Add changelog")

	// Push.
	run(localDir, "git", "remote", "add", "origin", "tomb::"+remoteDir)
	run(localDir, "git", "push", "--set-upstream", "origin", "master")

	// Verify remote has scrambled content.
	remoteRefs := run(remoteDir, "git", "show-ref")
	t.Logf("Remote refs:\n%s", remoteRefs)
	if remoteRefs == "" {
		t.Fatal("remote has no refs after push")
	}

	remoteRef := strings.Fields(strings.TrimSpace(remoteRefs))[1]
	remoteTree := run(remoteDir, "git", "ls-tree", "-r", "--name-only", remoteRef)
	t.Logf("Remote tree:\n%s", remoteTree)
	for _, orig := range []string{"README", "main.go", "guide.txt", "CHANGELOG", "src", "docs"} {
		if strings.Contains(remoteTree, orig) {
			t.Errorf("original name %q leaked in remote tree", orig)
		}
	}

	// Clone (init + fetch + checkout).
	run("", "git", "init", "--quiet", cloneDir)
	run(cloneDir, "git", "config", "user.email", "test@test.com")
	run(cloneDir, "git", "config", "user.name", "Test User")
	run(cloneDir, "git", "remote", "add", "origin", "tomb::"+remoteDir)
	fetchOut := run(cloneDir, "git", "fetch", "origin")
	t.Logf("Fetch output:\n%s", fetchOut)

	run(cloneDir, "git", "checkout", "master")

	// Verify cloned files.
	verifyFile(t, cloneDir, "README.md", "# Test Repo\n\nThis is a test.\n")
	verifyFile(t, cloneDir, "src/main.go", "package main\n\nfunc main() {}\n")
	verifyFile(t, cloneDir, "docs/guide.txt", "User guide content.\n")
	verifyFile(t, cloneDir, "CHANGELOG.md", "## v0.1.0\n- First release\n")

	// Verify commit messages and count.
	cloneLog := run(cloneDir, "git", "log", "--oneline")
	t.Logf("Clone log:\n%s", cloneLog)
	if !strings.Contains(cloneLog, "Add changelog") {
		t.Errorf("missing commit message 'Add changelog'")
	}
	if !strings.Contains(cloneLog, "Initial commit with test files") {
		t.Errorf("missing commit message 'Initial commit with test files'")
	}
	count := strings.Count(strings.TrimSpace(cloneLog), "\n") + 1
	if count != 2 {
		t.Errorf("expected 2 commits, got %d", count)
	}
}

// shellTestBundle tests bundle encryption mode: push, fetch into a fresh clone.
func shellTestBundle(t *testing.T, binDir string) {
	tmp := t.TempDir()

	sshDir := filepath.Join(tmp, ".ssh")
	localDir := filepath.Join(tmp, "local")
	remoteDir := filepath.Join(tmp, "remote.git")
	cloneDir := filepath.Join(tmp, "clone")

	for _, d := range []string{sshDir, localDir} {
		must(t, os.MkdirAll(d, 0o700))
	}

	env := shellTestEnv(binDir, tmp)
	run := shellRunner(t, env)

	// Generate SSH keypair.
	keyPath := filepath.Join(sshDir, "id_ed25519")
	run("", filepath.Join(binDir, binName("git-tomb")), "keygen", keyPath)

	// Create bare remote.
	run("", "git", "init", "--bare", "--quiet", remoteDir)

	// Create local repo with tomb (bundle mode).
	run("", "git", "init", "--quiet", localDir)
	run(localDir, "git", "config", "user.email", "test@test.com")
	run(localDir, "git", "config", "user.name", "Test User")
	run(localDir, filepath.Join(binDir, binName("git-tomb")), "init",
		"--encryption=bundle",
		"file", keyPath+".pub")

	// Add files and commit.
	writeFile(t, localDir, "README.md", "# Bundle Test\n")
	writeFile(t, localDir, "data.txt", "Some data.\n")

	run(localDir, "git", "add", "-A")
	run(localDir, "git", "commit", "--quiet", "-m", "Bundle commit")

	// Push.
	run(localDir, "git", "remote", "add", "origin", "tomb::"+remoteDir)
	run(localDir, "git", "push", "--set-upstream", "origin", "master")

	// Verify remote has encrypted bundle (not plaintext files).
	// Bundle mode pushes to refs/heads/main.
	remoteTree := run(remoteDir, "git", "ls-tree", "-r", "--name-only", "refs/heads/main")
	t.Logf("Remote tree:\n%s", remoteTree)
	if strings.Contains(remoteTree, "README") || strings.Contains(remoteTree, "data.txt") {
		t.Errorf("plaintext filenames leaked in remote tree")
	}
	if !strings.Contains(remoteTree, "tomb.bundle.age") {
		t.Errorf("expected tomb.bundle.age in remote tree")
	}

	// Clone (init + fetch + checkout).
	run("", "git", "init", "--quiet", cloneDir)
	run(cloneDir, "git", "config", "user.email", "test@test.com")
	run(cloneDir, "git", "config", "user.name", "Test User")
	run(cloneDir, "git", "remote", "add", "origin", "tomb::"+remoteDir)
	fetchOut := run(cloneDir, "git", "fetch", "origin")
	t.Logf("Fetch output:\n%s", fetchOut)

	// For bundle mode, the fetch should have created local refs.
	allRefs := run(cloneDir, "git", "show-ref")
	t.Logf("All refs after fetch:\n%s", allRefs)

	run(cloneDir, "git", "checkout", "master")

	// Verify cloned files.
	verifyFile(t, cloneDir, "README.md", "# Bundle Test\n")
	verifyFile(t, cloneDir, "data.txt", "Some data.\n")

	cloneLog := run(cloneDir, "git", "log", "--oneline")
	t.Logf("Clone log:\n%s", cloneLog)
	if !strings.Contains(cloneLog, "Bundle commit") {
		t.Errorf("missing commit message 'Bundle commit'")
	}
}

// --- helpers ---

func binName(name string) string {
	if os.PathSeparator == '\\' {
		return name + ".exe"
	}
	return name
}

func shellTestEnv(binDir, homeDir string) []string {
	env := filterTestEnv(os.Environ())
	env = append(env,
		"PATH="+binDir+string(os.PathListSeparator)+os.Getenv("PATH"),
		"HOME="+homeDir,
		"GIT_CONFIG_GLOBAL=/dev/null",
		"GIT_CONFIG_SYSTEM=/dev/null",
	)
	return env
}

func shellRunner(t *testing.T, env []string) func(dir, name string, args ...string) string {
	return func(dir, name string, args ...string) string {
		t.Helper()
		cmd := exec.Command(name, args...)
		if dir != "" {
			cmd.Dir = dir
		}
		cmd.Env = env
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("%s %s (dir=%s): %v\n%s", name, strings.Join(args, " "), dir, err, out)
		}
		return string(out)
	}
}

// buildBin compiles a Go binary into dir.
func buildBin(t *testing.T, dir, name, pkg string) {
	t.Helper()
	out := filepath.Join(dir, binName(name))
	cmd := exec.Command("go", "build", "-buildvcs=false", "-o", out, pkg)
	cmd.Dir = filepath.Join(".")
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("building %s: %v", name, err)
	}
}

// filterTestEnv removes env vars that would interfere with our test.
func filterTestEnv(env []string) []string {
	out := make([]string, 0, len(env))
	for _, e := range env {
		upper := strings.ToUpper(e)
		if strings.HasPrefix(upper, "GIT_DIR=") ||
			strings.HasPrefix(upper, "GIT_WORK_TREE=") ||
			strings.HasPrefix(upper, "HOME=") {
			continue
		}
		out = append(out, e)
	}
	return out
}
