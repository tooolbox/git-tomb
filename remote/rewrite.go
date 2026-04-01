package remote

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/tooolbox/git-tomb/crypt"
)

// commitMap tracks the correspondence between local and remote commit SHAs.
type commitMap struct {
	// LocalToRemote maps local commit SHA → remote commit SHA.
	LocalToRemote map[string]string `json:"local_to_remote"`
	// RemoteToLocal maps remote commit SHA → local commit SHA.
	RemoteToLocal map[string]string `json:"remote_to_local"`
}

func newCommitMap() *commitMap {
	return &commitMap{
		LocalToRemote: make(map[string]string),
		RemoteToLocal: make(map[string]string),
	}
}

func (cm *commitMap) Add(localSHA, remoteSHA string) {
	cm.LocalToRemote[localSHA] = remoteSHA
	cm.RemoteToLocal[remoteSHA] = localSHA
}

func loadCommitMap(tombRoot string) (*commitMap, error) {
	path := filepath.Join(tombRoot, ".tomb", "commit-map.json")
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return newCommitMap(), nil
	}
	if err != nil {
		return nil, err
	}
	var cm commitMap
	if err := json.Unmarshal(data, &cm); err != nil {
		return newCommitMap(), nil
	}
	if cm.LocalToRemote == nil {
		cm.LocalToRemote = make(map[string]string)
	}
	if cm.RemoteToLocal == nil {
		cm.RemoteToLocal = make(map[string]string)
	}
	return &cm, nil
}

func saveCommitMap(tombRoot string, cm *commitMap) error {
	path := filepath.Join(tombRoot, ".tomb", "commit-map.json")
	data, err := json.MarshalIndent(cm, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o644)
}

// rewriter translates commits between plaintext (local) and encrypted (remote) forms.
type rewriter struct {
	secret  []byte
	blobKey []byte // derived subkey for blob encryption
	msgKey  []byte // derived subkey for commit message encryption
	mode    crypt.ScrambleMode
	cm      *commitMap

	// workDir is a bare repo used for staging remote objects.
	workDir string
	// localGitDir is the path to the local repo's .git directory.
	localGitDir string
}

// newRewriter creates a rewriter with derived subkeys.
func newRewriter(secret []byte, mode crypt.ScrambleMode, cm *commitMap, workDir, localGitDir string) (*rewriter, error) {
	blobKey, err := crypt.BlobKey(secret)
	if err != nil {
		return nil, fmt.Errorf("deriving blob key: %w", err)
	}
	msgKey, err := crypt.MessageKey(secret)
	if err != nil {
		return nil, fmt.Errorf("deriving message key: %w", err)
	}
	return &rewriter{
		secret:      secret,
		blobKey:     blobKey,
		msgKey:      msgKey,
		mode:        mode,
		cm:          cm,
		workDir:     workDir,
		localGitDir: localGitDir,
	}, nil
}

// treeEntry represents one entry in a git tree object.
type treeEntry struct {
	mode string
	path string
	sha  string
}

// isTree returns true if the entry is a subtree (directory).
// Git may output the mode as "40000" or "040000".
func (e treeEntry) isTree() bool {
	return e.mode == "40000" || e.mode == "040000"
}

// encryptCommit takes a local commit SHA and produces an encrypted commit
// in the work repo, returning the new SHA.
func (rw *rewriter) encryptCommit(localSHA string) (string, error) {
	// Check if already mapped.
	if remoteSHA, ok := rw.cm.LocalToRemote[localSHA]; ok {
		return remoteSHA, nil
	}

	// Get commit info.
	info, err := rw.readCommit(rw.localGitDir, localSHA)
	if err != nil {
		return "", fmt.Errorf("reading commit %s: %w", localSHA[:8], err)
	}

	// Recursively ensure all parents are translated first.
	remoteParents := make([]string, len(info.parents))
	for i, parent := range info.parents {
		rp, err := rw.encryptCommit(parent)
		if err != nil {
			return "", fmt.Errorf("translating parent %s: %w", parent[:8], err)
		}
		remoteParents[i] = rp
	}

	// Read the local tree and encrypt each file.
	entries, err := rw.readTree(rw.localGitDir, info.tree)
	if err != nil {
		return "", fmt.Errorf("reading tree %s: %w", info.tree[:8], err)
	}

	// Collect all file paths for manifest.
	allPaths, err := rw.collectPaths(rw.localGitDir, info.tree, "")
	if err != nil {
		return "", fmt.Errorf("collecting paths: %w", err)
	}

	manifest := crypt.BuildManifest(rw.secret, allPaths, rw.mode)

	// Build the encrypted tree.
	encTreeSHA, err := rw.encryptTree(entries, manifest.Inverted(), "")
	if err != nil {
		return "", fmt.Errorf("building encrypted tree: %w", err)
	}

	// Add manifest to the tree.
	manifestData, err := crypt.EncryptManifest(manifest, rw.secret)
	if err != nil {
		return "", fmt.Errorf("encrypting manifest: %w", err)
	}

	manifestBlobSHA, err := rw.writeBlob(rw.workDir, manifestData)
	if err != nil {
		return "", fmt.Errorf("writing manifest blob: %w", err)
	}

	// Add manifest entry to the top-level tree.
	encTreeSHA, err = rw.addEntryToTree(encTreeSHA, treeEntry{
		mode: "100644",
		path: crypt.ManifestFile,
		sha:  manifestBlobSHA,
	})
	if err != nil {
		return "", fmt.Errorf("adding manifest to tree: %w", err)
	}

	// Encrypt the commit message.
	encMsg, err := rw.encryptMessage(info.message)
	if err != nil {
		return "", fmt.Errorf("encrypting commit message: %w", err)
	}

	// Create the encrypted commit.
	remoteSHA, err := rw.createCommit(encTreeSHA, remoteParents, encMsg, info.authorName, info.authorEmail, info.authorDate, info.committerName, info.committerEmail, info.committerDate)
	if err != nil {
		return "", fmt.Errorf("creating encrypted commit: %w", err)
	}

	rw.cm.Add(localSHA, remoteSHA)
	return remoteSHA, nil
}

// decryptCommit takes a remote commit SHA and produces a plaintext commit
// in the local repo, returning the new SHA.
func (rw *rewriter) decryptCommit(remoteSHA string) (string, error) {
	if localSHA, ok := rw.cm.RemoteToLocal[remoteSHA]; ok {
		return localSHA, nil
	}

	info, err := rw.readCommit(rw.workDir, remoteSHA)
	if err != nil {
		return "", fmt.Errorf("reading remote commit %s: %w", remoteSHA[:8], err)
	}

	// Translate parents.
	localParents := make([]string, len(info.parents))
	for i, parent := range info.parents {
		lp, err := rw.decryptCommit(parent)
		if err != nil {
			return "", fmt.Errorf("translating parent %s: %w", parent[:8], err)
		}
		localParents[i] = lp
	}

	// Read manifest from the tree.
	manifestSHA, err := rw.findEntryInTree(rw.workDir, info.tree, crypt.ManifestFile)
	if err != nil {
		return "", fmt.Errorf("finding manifest in tree: %w", err)
	}

	manifestData, err := rw.readBlob(rw.workDir, manifestSHA)
	if err != nil {
		return "", fmt.Errorf("reading manifest blob: %w", err)
	}

	manifest, err := crypt.DecryptManifest(manifestData, rw.secret)
	if err != nil {
		return "", fmt.Errorf("decrypting manifest: %w", err)
	}

	// Read encrypted tree and decrypt.
	entries, err := rw.readTree(rw.workDir, info.tree)
	if err != nil {
		return "", fmt.Errorf("reading encrypted tree: %w", err)
	}

	decTreeSHA, err := rw.decryptTree(entries, manifest, "")
	if err != nil {
		return "", fmt.Errorf("decrypting tree: %w", err)
	}

	// Decrypt the commit message.
	decMsg := info.message
	if payload, ok := crypt.DecodeMessage(info.message); ok {
		decMsg, err = rw.decryptMessage(payload)
		if err != nil {
			// Non-fatal — show the encrypted message.
			fmt.Fprintf(os.Stderr, "tomb: warning: could not decrypt commit message: %v\n", err)
			decMsg = info.message
		}
	}

	localSHA, err := rw.createCommitIn(rw.localGitDir, decTreeSHA, localParents, decMsg, info.authorName, info.authorEmail, info.authorDate, info.committerName, info.committerEmail, info.committerDate)
	if err != nil {
		return "", fmt.Errorf("creating decrypted commit: %w", err)
	}

	rw.cm.Add(localSHA, remoteSHA)
	return localSHA, nil
}

// encryptTree recursively builds an encrypted tree in the work repo.
func (rw *rewriter) encryptTree(entries []treeEntry, invertedManifest map[string]string, prefix string) (string, error) {
	var newEntries []treeEntry

	for _, e := range entries {
		fullPath := e.path
		if prefix != "" {
			fullPath = prefix + "/" + e.path
		}

		if e.isTree() {
			// Subtree — recurse.
			subEntries, err := rw.readTree(rw.localGitDir, e.sha)
			if err != nil {
				return "", err
			}
			subTreeSHA, err := rw.encryptTree(subEntries, invertedManifest, fullPath)
			if err != nil {
				return "", err
			}
			// Scramble the directory name.
			scrambledDir := rw.scrambleDirName(fullPath, invertedManifest)
			newEntries = append(newEntries, treeEntry{mode: e.mode, path: scrambledDir, sha: subTreeSHA})
		} else {
			// Blob — encrypt content.
			plainData, err := rw.readBlob(rw.localGitDir, e.sha)
			if err != nil {
				return "", err
			}

			var encBuf bytes.Buffer
			if err := crypt.SymmetricEncrypt(&encBuf, bytes.NewReader(plainData), rw.blobKey); err != nil {
				return "", fmt.Errorf("encrypting %s: %w", fullPath, err)
			}

			encSHA, err := rw.writeBlob(rw.workDir, encBuf.Bytes())
			if err != nil {
				return "", err
			}

			// Scramble the filename.
			scrambledName := rw.scrambleFileName(fullPath, invertedManifest)
			newEntries = append(newEntries, treeEntry{mode: e.mode, path: scrambledName, sha: encSHA})
		}
	}

	return rw.writeTree(rw.workDir, newEntries)
}

// decryptTree recursively builds a plaintext tree in the local repo.
func (rw *rewriter) decryptTree(entries []treeEntry, manifest crypt.Manifest, prefix string) (string, error) {
	var newEntries []treeEntry

	for _, e := range entries {
		// Skip the manifest file.
		if prefix == "" && e.path == crypt.ManifestFile {
			continue
		}

		scrambledPath := e.path
		if prefix != "" {
			scrambledPath = prefix + "/" + e.path
		}

		if e.isTree() {
			// Subtree — we need to find the original dir name.
			// Look through manifest for any path that starts with this scrambled prefix.
			origDir := rw.findOriginalDirName(scrambledPath, manifest)
			if origDir == "" {
				// Fallback — keep scrambled name.
				origDir = e.path
			}

			subEntries, err := rw.readTree(rw.workDir, e.sha)
			if err != nil {
				return "", err
			}
			subTreeSHA, err := rw.decryptTree(subEntries, manifest, scrambledPath)
			if err != nil {
				return "", err
			}
			newEntries = append(newEntries, treeEntry{mode: e.mode, path: origDir, sha: subTreeSHA})
		} else {
			// Blob — decrypt content.
			encData, err := rw.readBlob(rw.workDir, e.sha)
			if err != nil {
				return "", err
			}

			var decBuf bytes.Buffer
			if err := crypt.SymmetricDecrypt(&decBuf, bytes.NewReader(encData), rw.blobKey); err != nil {
				return "", fmt.Errorf("decrypting %s: %w", scrambledPath, err)
			}

			decSHA, err := rw.writeBlobTo(rw.localGitDir, decBuf.Bytes())
			if err != nil {
				return "", err
			}

			// Look up the original filename from the manifest.
			origName := rw.findOriginalFileName(scrambledPath, manifest)
			if origName == "" {
				origName = e.path
			}
			newEntries = append(newEntries, treeEntry{mode: e.mode, path: origName, sha: decSHA})
		}
	}

	return rw.writeTreeTo(rw.localGitDir, newEntries)
}

// scrambleDirName finds the scrambled directory name by looking up any file
// under this directory in the inverted manifest and extracting the directory
// component at the same depth.
func (rw *rewriter) scrambleDirName(fullDirPath string, invertedManifest map[string]string) string {
	// Find any file under this directory in the inverted manifest.
	prefix := fullDirPath + "/"
	for origPath, scrambledPath := range invertedManifest {
		if strings.HasPrefix(origPath, prefix) {
			// Extract the directory component at the same depth.
			depth := strings.Count(fullDirPath, "/")
			parts := strings.Split(scrambledPath, "/")
			if depth < len(parts) {
				return parts[depth]
			}
		}
	}
	// Fallback: should not happen if manifest is complete.
	return "unknown"
}

// scrambleFileName extracts the filename component from a scrambled full path.
func (rw *rewriter) scrambleFileName(fullPath string, invertedManifest map[string]string) string {
	if scrambled, ok := invertedManifest[fullPath]; ok {
		parts := strings.Split(scrambled, "/")
		return parts[len(parts)-1]
	}
	return "unknown.tomb"
}

// findOriginalDirName finds the original directory name for a scrambled directory path
// by searching the manifest for entries under this scrambled prefix.
func (rw *rewriter) findOriginalDirName(scrambledDirPath string, manifest crypt.Manifest) string {
	prefix := scrambledDirPath + "/"
	for scrambledFile, originalFile := range manifest {
		if strings.HasPrefix(scrambledFile, prefix) {
			// Extract the corresponding original directory component.
			// scrambledDirPath has N "/" separators, original has same structure.
			depth := strings.Count(scrambledDirPath, "/")
			origParts := strings.Split(originalFile, "/")
			if depth < len(origParts) {
				return origParts[depth]
			}
		}
	}
	return ""
}

// findOriginalFileName finds the original filename for a scrambled file path.
func (rw *rewriter) findOriginalFileName(scrambledPath string, manifest crypt.Manifest) string {
	if orig, ok := manifest[scrambledPath]; ok {
		parts := strings.Split(orig, "/")
		return parts[len(parts)-1]
	}
	return ""
}

// encryptMessage encrypts a commit message and wraps it with the tomb prefix.
func (rw *rewriter) encryptMessage(msg string) (string, error) {
	var buf bytes.Buffer
	if err := crypt.SymmetricEncrypt(&buf, bytes.NewReader([]byte(msg)), rw.msgKey); err != nil {
		return "", err
	}
	encoded := base64.StdEncoding.EncodeToString(buf.Bytes())
	return crypt.EncodeMessage(encoded), nil
}

// decryptMessage decrypts a base64-encoded encrypted commit message.
func (rw *rewriter) decryptMessage(payload string) (string, error) {
	data, err := base64.StdEncoding.DecodeString(payload)
	if err != nil {
		return "", fmt.Errorf("base64 decode: %w", err)
	}
	var buf bytes.Buffer
	if err := crypt.SymmetricDecrypt(&buf, bytes.NewReader(data), rw.msgKey); err != nil {
		return "", err
	}
	return buf.String(), nil
}

// --- git plumbing operations ---

type commitInfo struct {
	tree           string
	parents        []string
	message        string
	authorName     string
	authorEmail    string
	authorDate     string
	committerName  string
	committerEmail string
	committerDate  string
}

func (rw *rewriter) readCommit(gitDir, sha string) (*commitInfo, error) {
	// Use git cat-file to read commit object.
	out, err := rw.gitOutput(gitDir, "cat-file", "commit", sha)
	if err != nil {
		return nil, err
	}

	info := &commitInfo{}
	lines := strings.SplitN(string(out), "\n\n", 2)
	if len(lines) == 2 {
		info.message = strings.TrimSpace(lines[1])
	}

	for _, hdr := range strings.Split(lines[0], "\n") {
		key, val, _ := strings.Cut(hdr, " ")
		switch key {
		case "tree":
			info.tree = val
		case "parent":
			info.parents = append(info.parents, val)
		case "author":
			info.authorName, info.authorEmail, info.authorDate = parseIdent(val)
		case "committer":
			info.committerName, info.committerEmail, info.committerDate = parseIdent(val)
		}
	}

	return info, nil
}

func parseIdent(s string) (name, email, date string) {
	// Format: "Name <email> timestamp timezone"
	ltIdx := strings.Index(s, "<")
	gtIdx := strings.Index(s, ">")
	if ltIdx < 0 || gtIdx < 0 {
		return s, "", ""
	}
	name = strings.TrimSpace(s[:ltIdx])
	email = s[ltIdx+1 : gtIdx]
	date = strings.TrimSpace(s[gtIdx+1:])
	return
}

func (rw *rewriter) readTree(gitDir, sha string) ([]treeEntry, error) {
	out, err := rw.gitOutput(gitDir, "ls-tree", sha)
	if err != nil {
		return nil, err
	}

	var entries []treeEntry
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		if line == "" {
			continue
		}
		// Format: <mode> <type> <sha>\t<path>
		tabIdx := strings.IndexByte(line, '\t')
		if tabIdx < 0 {
			continue
		}
		fields := strings.Fields(line[:tabIdx])
		if len(fields) < 3 {
			continue
		}
		entries = append(entries, treeEntry{
			mode: fields[0],
			path: line[tabIdx+1:],
			sha:  fields[2],
		})
	}
	return entries, nil
}

func (rw *rewriter) readBlob(gitDir, sha string) ([]byte, error) {
	return rw.gitOutputRaw(gitDir, "cat-file", "blob", sha)
}

func (rw *rewriter) writeBlob(gitDir string, data []byte) (string, error) {
	return rw.gitInputOutput(gitDir, data, "hash-object", "-w", "--stdin")
}

func (rw *rewriter) writeBlobTo(gitDir string, data []byte) (string, error) {
	return rw.gitInputOutput(gitDir, data, "hash-object", "-w", "--stdin")
}

func (rw *rewriter) writeTree(gitDir string, entries []treeEntry) (string, error) {
	return rw.writeTreeTo(gitDir, entries)
}

func (rw *rewriter) writeTreeTo(gitDir string, entries []treeEntry) (string, error) {
	var input strings.Builder
	for _, e := range entries {
		// Format for mktree: "<mode> <type> <sha>\t<path>\n"
		typ := "blob"
		if e.isTree() {
			typ = "tree"
		}
		fmt.Fprintf(&input, "%s %s %s\t%s\n", e.mode, typ, e.sha, e.path)
	}
	return rw.gitInputOutput(gitDir, []byte(input.String()), "mktree")
}

func (rw *rewriter) findEntryInTree(gitDir, treeSHA, name string) (string, error) {
	entries, err := rw.readTree(gitDir, treeSHA)
	if err != nil {
		return "", err
	}
	for _, e := range entries {
		if e.path == name {
			return e.sha, nil
		}
	}
	return "", fmt.Errorf("entry %q not found in tree %s", name, treeSHA[:8])
}

func (rw *rewriter) addEntryToTree(treeSHA string, entry treeEntry) (string, error) {
	entries, err := rw.readTree(rw.workDir, treeSHA)
	if err != nil {
		return "", err
	}
	entries = append(entries, entry)
	return rw.writeTree(rw.workDir, entries)
}

func (rw *rewriter) createCommit(treeSHA string, parents []string, msg, authorName, authorEmail, authorDate, committerName, committerEmail, committerDate string) (string, error) {
	return rw.createCommitIn(rw.workDir, treeSHA, parents, msg, authorName, authorEmail, authorDate, committerName, committerEmail, committerDate)
}

func (rw *rewriter) createCommitIn(gitDir, treeSHA string, parents []string, msg, authorName, authorEmail, authorDate, committerName, committerEmail, committerDate string) (string, error) {
	args := []string{"commit-tree", treeSHA}
	for _, p := range parents {
		args = append(args, "-p", p)
	}
	args = append(args, "-m", msg)

	cmd := gitCmd(gitDir, args...)
	cmd.Env = append(os.Environ(),
		"GIT_AUTHOR_NAME="+authorName,
		"GIT_AUTHOR_EMAIL="+authorEmail,
		"GIT_AUTHOR_DATE="+authorDate,
		"GIT_COMMITTER_NAME="+committerName,
		"GIT_COMMITTER_EMAIL="+committerEmail,
		"GIT_COMMITTER_DATE="+committerDate,
	)
	out, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("commit-tree: %w", err)
	}
	return strings.TrimSpace(string(out)), nil
}

// collectPaths collects all blob paths in a tree recursively.
func (rw *rewriter) collectPaths(gitDir, treeSHA, prefix string) ([]string, error) {
	entries, err := rw.readTree(gitDir, treeSHA)
	if err != nil {
		return nil, err
	}

	var paths []string
	for _, e := range entries {
		fullPath := e.path
		if prefix != "" {
			fullPath = prefix + "/" + e.path
		}

		if e.isTree() {
			sub, err := rw.collectPaths(gitDir, e.sha, fullPath)
			if err != nil {
				return nil, err
			}
			paths = append(paths, sub...)
		} else {
			paths = append(paths, fullPath)
		}
	}
	return paths, nil
}

// --- helpers ---

// gitCmd builds a git command targeting the given git directory.
// For bare repos and .git directories, we use --git-dir so git
// doesn't need to discover the repo from the working directory.
func gitCmd(gitDir string, args ...string) *exec.Cmd {
	// Use forward slashes for git compatibility on Windows.
	cleanDir := strings.ReplaceAll(gitDir, "\\", "/")
	fullArgs := append([]string{"--git-dir", cleanDir}, args...)
	return exec.Command("git", fullArgs...)
}

func (rw *rewriter) gitOutput(gitDir string, args ...string) ([]byte, error) {
	cmd := gitCmd(gitDir, args...)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("git %v (gitDir=%s): %w: %s", args, gitDir, err, stderr.String())
	}
	return out, nil
}

func (rw *rewriter) gitOutputRaw(gitDir string, args ...string) ([]byte, error) {
	cmd := gitCmd(gitDir, args...)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("git %v (gitDir=%s): %w: %s", args, gitDir, err, stderr.String())
	}
	return out, nil
}

func (rw *rewriter) gitInputOutput(gitDir string, input []byte, args ...string) (string, error) {
	cmd := gitCmd(gitDir, args...)
	cmd.Stdin = bytes.NewReader(input)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("git %v (gitDir=%s): %w: %s", args, gitDir, err, stderr.String())
	}
	return strings.TrimSpace(string(out)), nil
}
