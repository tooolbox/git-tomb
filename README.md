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

Each file is individually age-encrypted with deterministic word-based filename scrambling. The remote is a normal git repo — anyone can `git clone` it without tomb installed and see the files, they're just opaque.

**Pros:** Incremental push/pull (only changed files). Remote is a normal, browsable git repo. Committer identity and timestamps are preserved. Supports three filename scramble modes.

**Cons:** Leaks file count, directory structure shape, and individual file sizes. Commit graph is visible.

**What the remote looks like:**
```
.tomb-manifest.age          (encrypted filename mapping)
apple-banana/
  cedar-drift.tomb          (encrypted src/main.go)
  rover-lotus.tomb          (encrypted src/util.go)
nerve-dream.tomb            (encrypted README.md)
```

Commit messages are encrypted — `git log` on the remote shows `tomb:YWdlLW...` instead of your real messages. Locally, `git log` shows everything normally.

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

## How It Works

1. `git tomb init` pins your SSH public keys in `.tomb/recipients.json` and sets the encryption mode
2. `git tomb add` fetches a collaborator's SSH keys from GitHub/GitLab and pins them
3. On `git push tomb::...`, the remote helper encrypts your repo (using the configured mode) and pushes
4. On `git clone tomb::...` or `git pull`, the remote helper fetches and decrypts automatically

**Bundle mode** encrypts the entire repo as a single blob on each push.

**Per-file mode** translates each commit: file contents are age-encrypted, filenames are HMAC-scrambled to word pairs using a shared symmetric secret, and commit messages are encrypted. A `.tomb-manifest.age` file in each commit allows recipients to recover the original filenames.

Age supports SSH keys natively — both ed25519 and RSA. No additional key management needed.

## Key Trust Model

Keys are pinned on first fetch (TOFU — trust on first use), similar to SSH's `known_hosts`. Use `git tomb refresh` to re-fetch and review any changes.

When you add or remove recipients, the shared secret (per-file mode) is automatically re-encrypted for the updated set.

## Requirements

- Go 1.21+
- Git
- An SSH key (ed25519 or RSA) in `~/.ssh/` — if you don't have one and don't have `ssh-keygen`, run `git tomb keygen`
