// Package crypt — scramble.go provides deterministic path scrambling
// and manifest encryption for per-file tomb encryption.
package crypt

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"path"
	"strings"
)

// Wordlist is a curated list of short, memorable, distinct English words
// used to generate human-readable scrambled filenames like "apple-banana".
var Wordlist = []string{
	"acorn", "apple", "arrow", "atlas", "badge",
	"baker", "basil", "beach", "birch", "blaze",
	"bloom", "bluff", "board", "bonus", "booth",
	"boxer", "brass", "brave", "brick", "brook",
	"brush", "cabin", "camel", "candy", "cargo",
	"cedar", "chain", "chalk", "charm", "chase",
	"chess", "chief", "cider", "clamp", "clash",
	"clay", "cliff", "cloud", "clown", "coach",
	"cobra", "coral", "crane", "crisp", "crown",
	"crush", "cumin", "curve", "daisy", "dance",
	"delta", "denim", "depot", "derby", "diver",
	"dodge", "dove", "draft", "dream", "drift",
	"drum", "dune", "dwarf", "eagle", "ember",
	"epoch", "fairy", "fawn", "feast", "fence",
	"ferry", "field", "finch", "flake", "flame",
	"flask", "fleet", "flint", "flora", "focus",
	"forge", "frost", "fruit", "ghost", "giant",
	"glade", "gleam", "globe", "glove", "goose",
	"grain", "grape", "grove", "guard", "guild",
	"gypsy", "haven", "hazel", "heart", "hedge",
	"heron", "honey", "horse", "hound", "hover",
	"hyena", "ivory", "jewel", "jolly", "judge",
	"juice", "karma", "kayak", "kite", "knack",
	"kneel", "knoll", "koala", "lager", "lance",
	"larch", "laser", "latch", "lemon", "lever",
	"lilac", "linen", "llama", "lotus", "lucky",
	"lunar", "lunge", "mango", "maple", "march",
	"marsh", "mason", "medal", "melon", "midge",
	"mirth", "mocha", "moose", "mound", "mural",
	"nerve", "noble", "north", "novel", "nutmeg",
	"oasis", "olive", "onion", "opera", "orbit",
	"otter", "oxide", "panda", "pansy", "patch",
	"peach", "pearl", "penny", "perch", "petal",
	"pilot", "plank", "plaza", "plumb", "plume",
	"polar", "poppy", "pouch", "prism", "prose",
	"prowl", "pulse", "quail", "quake", "quest",
	"quiet", "raven", "realm", "ridge", "river",
	"roast", "robin", "rodeo", "rouge", "rover",
	"royal", "ruler", "rumba", "sable", "sage",
	"scarf", "scout", "shard", "shelf", "shine",
	"shoal", "siege", "silk", "siren", "skull",
	"slate", "sleet", "slope", "smoke", "snare",
	"solar", "spark", "spice", "spray", "stag",
	"stamp", "steel", "stew", "stone", "storm",
	"stork", "stove", "sugar", "surge", "swamp",
	"swift", "sword", "syrup", "table", "talon",
	"tango", "thorn", "tiger", "toast", "topaz",
	"torch", "tower", "trace", "trail", "trend",
	"trout", "tulip", "tunic", "ultra", "umbra",
	"union", "upper", "urban", "valor", "valve",
	"vapor", "vault", "venom", "verse", "vigor",
	"viper", "vivid", "vocal", "waltz", "whale",
	"wheat", "wheel", "whirl", "widen", "witch",
	"wrath", "yacht", "yeast", "yield", "zebra",
	"zephyr", "zippy",
}

// ScrambleMode mirrors tomb.ScrambleMode to avoid circular imports.
type ScrambleMode string

const (
	ScrambleFull           ScrambleMode = "full"
	ScrambleKeepExtensions ScrambleMode = "keep-extensions"
	ScrambleKeepFilenames  ScrambleMode = "keep-filenames"
)

// ScramblePath deterministically scrambles a file path using HMAC.
// Each path component (directory or filename) is scrambled independently,
// preserving the directory hierarchy structure.
//
// The mode controls how much scrambling is applied:
//   - "full": scramble everything, use .tomb extension
//   - "keep-extensions": scramble names, keep original file extension
//   - "keep-filenames": scramble directories only, keep original filenames
//
// Examples (mode=full):           "src/main.go" → "apple-banana/cedar-drift.tomb"
// Examples (mode=keep-extensions): "src/main.go" → "apple-banana/cedar-drift.go"
// Examples (mode=keep-filenames):  "src/main.go" → "apple-banana/main.go"
func ScramblePath(secret []byte, originalPath string, mode ScrambleMode) string {
	if mode == "" {
		mode = ScrambleFull
	}

	cleaned := path.Clean(originalPath)
	parts := strings.Split(cleaned, "/")

	scrambled := make([]string, len(parts))

	// Scramble directory components (all but last).
	// Directory names are scrambled based on the directory path up to that point,
	// so "src" always scrambles the same way regardless of what file is inside it.
	for i := 0; i < len(parts)-1; i++ {
		dirPath := strings.Join(parts[:i+1], "/")
		scrambled[i] = scrambleComponent(secret, dirPath, i, parts[i])
	}

	// Handle the filename (last component) based on mode.
	last := len(parts) - 1
	filename := parts[last]

	switch mode {
	case ScrambleKeepFilenames:
		// Keep the original filename as-is.
		scrambled[last] = filename
	case ScrambleKeepExtensions:
		// Scramble the name, keep the extension.
		ext := path.Ext(filename)
		scrambled[last] = scrambleComponent(secret, cleaned, last, filename) + ext
	default: // ScrambleFull
		scrambled[last] = scrambleComponent(secret, cleaned, last, filename) + ".tomb"
	}

	return strings.Join(scrambled, "/")
}

// scrambleComponent produces a deterministic word-pair name for one path component.
// We feed the FULL original path + component index into the HMAC to avoid collisions
// when two different directories contain files/dirs with the same name.
func scrambleComponent(secret []byte, fullPath string, index int, component string) string {
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(fullPath))
	// Mix in the component index so "a/b" and "a" at different positions don't collide.
	binary.Write(mac, binary.BigEndian, int64(index))
	mac.Write([]byte(component))
	sum := mac.Sum(nil)

	// Use first 8 bytes for two word indices.
	w1 := binary.BigEndian.Uint32(sum[0:4]) % uint32(len(Wordlist))
	w2 := binary.BigEndian.Uint32(sum[4:8]) % uint32(len(Wordlist))

	// Avoid same word twice.
	if w2 == w1 {
		w2 = (w2 + 1) % uint32(len(Wordlist))
	}

	return Wordlist[w1] + "-" + Wordlist[w2]
}

// ScrambleRef scrambles a git ref name (branch or tag) deterministically.
// "refs/heads/main" → "refs/heads/forge-lunar"
func ScrambleRef(secret []byte, ref string) string {
	// Don't scramble the refs/heads/ or refs/tags/ prefix.
	var prefix, name string
	if strings.HasPrefix(ref, "refs/heads/") {
		prefix = "refs/heads/"
		name = strings.TrimPrefix(ref, "refs/heads/")
	} else if strings.HasPrefix(ref, "refs/tags/") {
		prefix = "refs/tags/"
		name = strings.TrimPrefix(ref, "refs/tags/")
	} else {
		// HEAD or other special refs — don't scramble.
		return ref
	}

	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte("ref:"))
	mac.Write([]byte(name))
	sum := mac.Sum(nil)

	w1 := binary.BigEndian.Uint32(sum[0:4]) % uint32(len(Wordlist))
	w2 := binary.BigEndian.Uint32(sum[4:8]) % uint32(len(Wordlist))
	if w2 == w1 {
		w2 = (w2 + 1) % uint32(len(Wordlist))
	}

	return prefix + Wordlist[w1] + "-" + Wordlist[w2]
}

// ScrambleCommitMessage encrypts a commit message for storage on the remote.
// We use a deterministic HMAC-based approach so identical messages produce
// identical ciphertext (useful for merge commits with stock messages).
// The actual encryption uses age with the recipients, but that's done at call site.
// This function just wraps the message with a marker so we can identify it on decode.
const TombMessagePrefix = "tomb:"

// EncodeMessage wraps an encrypted (base64) message with the tomb prefix.
func EncodeMessage(encrypted string) string {
	return TombMessagePrefix + encrypted
}

// DecodeMessage checks if a commit message is tomb-encrypted and returns
// the encrypted payload. Returns ("", false) if not a tomb message.
func DecodeMessage(msg string) (string, bool) {
	if strings.HasPrefix(msg, TombMessagePrefix) {
		return strings.TrimPrefix(msg, TombMessagePrefix), true
	}
	return "", false
}
