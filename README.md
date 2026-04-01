# git-tomb

Encrypted git repos for everyone. Like Keybase encrypted git, but using [age](https://age-encryption.org) encryption and SSH keys from GitHub/GitLab.

## Install

```bash
go install github.com/tooolbox/git-tomb/cmd/...@latest
```

This installs two binaries:
- `git-tomb` — the CLI (invoked as `git tomb`)
- `git-remote-tomb` — the git remote helper (invoked automatically by git for `tomb::` URLs)

## Quick Start

```bash
cd myproject
git init

# Initialize tomb with your GitHub SSH keys
git tomb init --encryption=per-file github yourname

# Add a collaborator
git tomb add github theirname

# Push encrypted
git remote add origin tomb::https://github.com/you/repo.git
git push origin main
```

### Clone an encrypted repo

If someone has added your keys, just:

```bash
git clone tomb::https://github.com/them/repo.git
```

That's it. Decryption is automatic using your local SSH key.

## Encryption Modes

You choose an encryption mode when initializing a tomb. This controls how the remote repository stores your encrypted data.

### Bundle mode (`--encryption=bundle`)

```bash
git tomb init --encryption=bundle github yourname
```

The entire repo is packed into a single age-encrypted git bundle on every push. The remote contains only two opaque files (`tomb.bundle.age` and `tomb.refs.age`).

**Pros:** Maximum privacy. Hides file count, directory structure, branch names, and commit messages. An observer sees nothing but two blobs.

**Cons:** Every push re-uploads the entire repo. No incremental fetch. The remote is not a normal git repo — it only works with tomb.

### Per-file mode (`--encryption=per-file`)

```bash
git tomb init --encryption=per-file github yourname
```

Each file is individually encrypted with AES-256-GCM, with filenames scrambled to word pairs. The remote is a normal git repo — anyone can `git clone` it without tomb installed and see the files, they're just opaque.

**Pros:** Incremental push/pull (only changed files). Remote is a normal, browsable git repo. Adding a recipient is instant (no re-encryption needed). Committer identity and timestamps are preserved.

**Cons:** Leaks file count, directory structure shape, and individual file sizes. Commit graph is visible.

**What the remote looks like:**
```
.tomb-manifest.age          (encrypted filename mapping)
apple-banana/
  cedar-drift.tomb          (encrypted src/main.go)
  rover-lotus.tomb          (encrypted src/util.go)
nerve-dream.tomb            (encrypted README.md)
```

Commit messages are encrypted on the remote. Locally, `git log` shows everything normally.

#### Scramble modes

Control how much filename information is visible on the remote. Set at init time or change later with `git tomb config`.

| Mode | Example | What leaks |
|------|---------|------------|
| `full` (default) | `src/main.go` → `apple-banana/cedar-drift.tomb` | Nothing — names and extensions are scrambled |
| `keep-extensions` | `src/main.go` → `apple-banana/cedar-drift.go` | File type via extension |
| `keep-filenames` | `src/main.go` → `apple-banana/main.go` | Original filenames |

```bash
# Set at init
git tomb init --encryption=per-file --scramble=keep-extensions github yourname

# Or change later
git tomb config scramble keep-filenames
```

## How It Works

git-tomb uses a **git remote helper** to transparently encrypt and decrypt your repo during push and pull. You interact with git normally — `git push`, `git pull`, `git log` — and encryption happens automatically.

### Architecture

```
Local repo (plaintext)          tomb:: remote helper          Remote (encrypted)
├── src/main.go          →    encrypt + scramble         →   apple-banana/cedar-drift.tomb
├── README.md            →    encrypt + scramble         →   nerve-dream.tomb
└── .tomb/                                                   .tomb-manifest.age
    ├── recipients.json                                      (encrypted path mapping)
    └── secret.age
```

### Encryption layers

git-tomb uses two layers of encryption:

1. **Symmetric layer (AES-256-GCM):** File contents, commit messages, and the filename manifest are encrypted with a shared symmetric secret. Separate subkeys are derived via HKDF-SHA256 for each purpose (blobs, messages, manifests). This is fast and means adding a recipient does not require re-encrypting any data.

2. **Asymmetric layer (age + SSH keys):** The shared symmetric secret itself is encrypted with [age](https://age-encryption.org) for each recipient's SSH public key and stored as `.tomb/secret.age`. This is the mechanism that grants access — if you can decrypt `secret.age` with your SSH private key, you can decrypt the repo.

Filename scrambling uses HMAC-SHA256 keyed on the shared secret to deterministically map original paths to word-pair names.

### Push flow (per-file mode)

1. Load the shared secret (decrypt `.tomb/secret.age` with your SSH key)
2. Walk local git history, commit by commit
3. For each commit:
   - Encrypt each file blob with AES-256-GCM (blob subkey)
   - Scramble each file path with HMAC-SHA256
   - Encrypt the commit message (message subkey)
   - Build an encrypted manifest mapping scrambled → original paths
   - Create the encrypted commit in a staging area
4. Push the encrypted commits to the remote (incremental — only new commits)

### Fetch flow (per-file mode)

1. Fetch encrypted commits from the remote
2. Load the shared secret
3. For each commit:
   - Decrypt the manifest to recover original filenames
   - Decrypt each file blob
   - Decrypt the commit message
   - Reconstruct the plaintext commit locally

## Adding and Removing Recipients

### Adding a recipient

```bash
git tomb add github theirname
```

This fetches their SSH public keys from GitHub and adds them to `.tomb/recipients.json`. The shared secret (`.tomb/secret.age`) is re-encrypted so the new recipient can decrypt it. **No file re-encryption is needed** — since all file blobs are encrypted with the shared symmetric key, anyone who can decrypt `secret.age` can immediately decrypt the entire repo, including all history.

The new recipient can clone immediately:
```bash
git clone tomb::https://github.com/you/repo.git
```

### Removing a recipient

```bash
git tomb remove theirname
```

This removes them from `.tomb/recipients.json` and re-encrypts `secret.age` for the remaining recipients. **New pushes** will use a `secret.age` that the removed person cannot decrypt.

**However**, removal has limits:

- The removed person **already has the shared secret** from when they had access. They can still decrypt any data they previously fetched.
- If the removed person has a copy of the remote, they can still decrypt it — the blobs on the remote are still encrypted with the same symmetric key.
- Removing a recipient **prevents future access** (they can't decrypt the updated `secret.age`), but does not retroactively revoke access to data they already had.

This is a fundamental property of any encrypted system — you cannot un-share data that someone has already downloaded.

### Full revocation (re-keying)

If you need to truly revoke a removed recipient's access to all data (including what's currently on the remote), you must **rotate the secret and re-encrypt everything**:

1. Remove the recipient: `git tomb remove theirname`
2. Delete `.tomb/secret.age` and `.tomb/commit-map.json`
3. Re-initialize the secret: this generates a new symmetric key
4. Force-push: this re-encrypts all commits with the new key

After rotation:
- All blob ciphertext on the remote changes (new symmetric key)
- All scrambled filenames change (new HMAC key)
- All remote commit SHAs change (different tree contents)
- Other collaborators must re-clone or reset their commit maps

**The removed person can still decrypt any data they downloaded before the rotation.** There is no way to prevent this — it is a copy of the data, and they had the key. Rotation only protects data on the remote going forward.

## Comparison with git-crypt

[git-crypt](https://github.com/AGWA/git-crypt) is a well-known tool for encrypting files in a git repo. git-tomb takes a different approach.

| | git-crypt | git-tomb |
|--|-----------|----------|
| **Scope** | Selected files only (via `.gitattributes`) | Entire repo |
| **Integration** | Git clean/smudge filters | Git remote helper |
| **Encryption** | AES-256-CTR (deterministic) | AES-256-GCM (per-file mode) or age (bundle mode) |
| **Key discovery** | Manual GPG key exchange | Automatic via GitHub/GitLab SSH keys |
| **Adding users** | Requires GPG infrastructure | `git tomb add github username` |
| **Removing users** | Not supported (must re-init) | `git tomb remove username` |
| **Filenames** | Plaintext (visible) | Scrambled to word pairs |
| **Commit messages** | Plaintext (visible) | Encrypted |
| **Remote without tool** | Readable (unencrypted files visible, encrypted files are binary) | Per-file: cloneable, files are opaque. Bundle: two opaque blobs |
| **Incremental push** | Yes (via git's normal delta mechanism) | Per-file: yes. Bundle: no |
| **Best for** | A few secrets in a mostly-public repo | Encrypting an entire private repo |

**Key differences:**

- **git-crypt** encrypts individual files transparently using git filters. Unencrypted files in the same repo work normally. Filenames, commit messages, and directory structure are always visible. Requires GPG for multi-user access. Has no mechanism for removing users — you must re-initialize from scratch.

- **git-tomb** encrypts the entire repo at the transport layer. Everything is opaque on the remote (to varying degrees depending on mode). Uses SSH keys from GitHub/GitLab instead of GPG, so adding a collaborator is as simple as knowing their GitHub username.

## Commands

| Command | Description |
|---------|-------------|
| `git tomb init --encryption=MODE [provider] [user]` | Initialize tomb (encryption mode required) |
| `git tomb add <provider> <username>` | Add a recipient |
| `git tomb remove <username>` | Remove a recipient |
| `git tomb list` | List all recipients and their key fingerprints |
| `git tomb refresh` | Re-fetch keys for all recipients |
| `git tomb config` | Show all configuration |
| `git tomb config <key>` | Get a config value |
| `git tomb config <key> <value>` | Set a config value |
| `git tomb keygen` | Generate an ed25519 SSH keypair in `~/.ssh/` |
| `git tomb keygen <path>` | Generate an ed25519 SSH keypair at a custom path |

**Providers:** `github`, `gitlab`, `file`

## Key Trust Model

Keys are pinned on first fetch (TOFU — trust on first use), similar to SSH's `known_hosts`. Use `git tomb refresh` to re-fetch and review any changes.

## Requirements

- Go 1.21+
- Git
- An SSH key (ed25519 or RSA) in `~/.ssh/` — if you don't have one and don't have `ssh-keygen`, run `git tomb keygen`
