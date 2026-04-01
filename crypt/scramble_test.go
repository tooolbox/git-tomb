package crypt

import (
	"testing"
)

func TestScramblePath_FullMode(t *testing.T) {
	secret := []byte("test-secret-key-1234567890abcdef")

	result := ScramblePath(secret, "src/main.go", ScrambleFull)

	// Should have two components: scrambled dir / scrambled file.tomb
	if result == "src/main.go" {
		t.Fatal("path was not scrambled")
	}
	if !contains(result, ".tomb") {
		t.Fatalf("expected .tomb extension, got %q", result)
	}
	if contains(result, ".go") {
		t.Fatalf("original extension should not be preserved in full mode, got %q", result)
	}

	// Should be deterministic.
	result2 := ScramblePath(secret, "src/main.go", ScrambleFull)
	if result != result2 {
		t.Fatalf("not deterministic: %q != %q", result, result2)
	}

	// Different path should produce different result.
	other := ScramblePath(secret, "src/util.go", ScrambleFull)
	if result == other {
		t.Fatalf("different paths produced same scramble: %q", result)
	}

	// Different secret should produce different result.
	other2 := ScramblePath([]byte("different-secret"), "src/main.go", ScrambleFull)
	if result == other2 {
		t.Fatalf("different secrets produced same scramble: %q", result)
	}

	t.Logf("src/main.go → %s", result)
}

func TestScramblePath_KeepExtensions(t *testing.T) {
	secret := []byte("test-secret-key-1234567890abcdef")

	result := ScramblePath(secret, "src/main.go", ScrambleKeepExtensions)

	if !contains(result, ".go") {
		t.Fatalf("expected .go extension preserved, got %q", result)
	}
	if result == "src/main.go" {
		t.Fatal("path was not scrambled")
	}

	// Directories should still be scrambled.
	parts := splitPath(result)
	if parts[0] == "src" {
		t.Fatalf("directory name should be scrambled, got %q", result)
	}

	t.Logf("src/main.go → %s", result)
}

func TestScramblePath_KeepFilenames(t *testing.T) {
	secret := []byte("test-secret-key-1234567890abcdef")

	result := ScramblePath(secret, "src/main.go", ScrambleKeepFilenames)

	// Filename should be preserved.
	parts := splitPath(result)
	if parts[len(parts)-1] != "main.go" {
		t.Fatalf("expected filename 'main.go' preserved, got %q", result)
	}

	// Directory should be scrambled.
	if parts[0] == "src" {
		t.Fatalf("directory name should be scrambled, got %q", result)
	}

	t.Logf("src/main.go → %s", result)
}

func TestScramblePath_WordFormat(t *testing.T) {
	secret := []byte("test-secret-key-1234567890abcdef")

	result := ScramblePath(secret, "README.md", ScrambleFull)

	// Single file (no directory) should be "word-word.tomb".
	parts := splitPath(result)
	if len(parts) != 1 {
		t.Fatalf("expected 1 component for root file, got %d: %q", len(parts), result)
	}

	t.Logf("README.md → %s", result)
}

func TestScrambleRef(t *testing.T) {
	secret := []byte("test-secret-key-1234567890abcdef")

	tests := []struct {
		input string
		prefix string
	}{
		{"refs/heads/main", "refs/heads/"},
		{"refs/heads/feature/foo", "refs/heads/"},
		{"refs/tags/v1.0", "refs/tags/"},
		{"HEAD", ""}, // Should not be scrambled.
	}

	for _, tt := range tests {
		result := ScrambleRef(secret, tt.input)

		if tt.prefix == "" {
			if result != tt.input {
				t.Errorf("expected %q unchanged, got %q", tt.input, result)
			}
			continue
		}

		if !hasPrefix(result, tt.prefix) {
			t.Errorf("expected prefix %q, got %q", tt.prefix, result)
		}

		// Should be deterministic.
		result2 := ScrambleRef(secret, tt.input)
		if result != result2 {
			t.Errorf("not deterministic for %q: %q != %q", tt.input, result, result2)
		}

		t.Logf("%s → %s", tt.input, result)
	}
}

func TestScramblePath_SameDirectory(t *testing.T) {
	secret := []byte("test-secret-key-1234567890abcdef")

	r1 := ScramblePath(secret, "src/main.go", ScrambleFull)
	r2 := ScramblePath(secret, "src/util.go", ScrambleFull)

	// Both files are in "src/", so the directory component must match.
	dir1 := splitPath(r1)[0]
	dir2 := splitPath(r2)[0]
	if dir1 != dir2 {
		t.Errorf("same directory 'src' scrambled differently: %q vs %q (from %q and %q)", dir1, dir2, r1, r2)
	}

	// But the filenames must differ.
	file1 := splitPath(r1)[1]
	file2 := splitPath(r2)[1]
	if file1 == file2 {
		t.Errorf("different files got same scrambled name: %q", file1)
	}

	t.Logf("src/main.go → %s", r1)
	t.Logf("src/util.go → %s", r2)
}

func TestWordlistNoDuplicates(t *testing.T) {
	seen := make(map[string]bool)
	for _, w := range Wordlist {
		if seen[w] {
			t.Errorf("duplicate word: %q", w)
		}
		seen[w] = true
	}
}

// helpers

func contains(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

func hasPrefix(s, prefix string) bool {
	return len(s) >= len(prefix) && s[:len(prefix)] == prefix
}

func splitPath(p string) []string {
	var parts []string
	current := ""
	for _, c := range p {
		if c == '/' {
			if current != "" {
				parts = append(parts, current)
			}
			current = ""
		} else {
			current += string(c)
		}
	}
	if current != "" {
		parts = append(parts, current)
	}
	return parts
}
