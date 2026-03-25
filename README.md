# git-tomb

Encrypted git repos for everyone. Like Keybase encrypted git, but using [age](https://age-encryption.org) encryption and SSH keys from GitHub/GitLab.

The remote only sees encrypted blobs — no branch names, no commit messages, no file contents.

## Install

```bash
go install github.com/tooolbox/git-tomb/cmd/...@latest
```

This installs two binaries:
- `git-tomb` — the CLI (invoked as `git tomb`)
- `git-remote-tomb` — the git remote helper (invoked automatically by git for `tomb::` URLs)

## Quick Start

### Set up an encrypted repo

```bash
cd myproject
git init

# Initialize tomb with your keys (auto-discovers ~/.ssh/ keys)
git tomb init

# Or use your GitHub SSH keys
git tomb init github yourname

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

## Commands

| Command | Description |
|---------|-------------|
| `git tomb init` | Initialize tomb, auto-discover local SSH keys |
| `git tomb init github <user>` | Initialize tomb with GitHub SSH keys |
| `git tomb init gitlab <user>` | Initialize tomb with GitLab SSH keys |
| `git tomb init file <path>` | Initialize tomb with a specific key file |
| `git tomb add github <user>` | Add a recipient using their GitHub SSH keys |
| `git tomb add gitlab <user>` | Add a recipient using their GitLab SSH keys |
| `git tomb add file <path>` | Add a recipient using a local public key file |
| `git tomb remove <user>` | Remove a recipient |
| `git tomb list` | List all recipients and their key fingerprints |
| `git tomb refresh` | Re-fetch keys for all recipients from their providers |

## How It Works

1. `git tomb init` pins your SSH public keys in `.tomb/recipients.json`
2. `git tomb add` fetches a collaborator's SSH public keys from GitHub/GitLab and pins them
3. On `git push tomb::...`, the remote helper bundles your repo, encrypts it with [age](https://age-encryption.org) for all recipients, and pushes the encrypted blob
4. On `git clone tomb::...`, the remote helper fetches the encrypted blob, decrypts it with your local SSH key, and unpacks it

Age supports SSH keys natively — both ed25519 and RSA. No additional key management needed.

## Key Trust Model

Keys are pinned on first fetch (TOFU — trust on first use), similar to SSH's `known_hosts`. Use `git tomb refresh` to re-fetch and review any changes.

## Requirements

- Go 1.21+
- Git
- An SSH key (ed25519 or RSA) in `~/.ssh/`
