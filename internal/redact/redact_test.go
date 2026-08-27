package redact

import (
	"strings"
	"testing"
)

func TestSecretMasksValue(t *testing.T) {
	// Synthetic value assembled at runtime so no credential-shaped literal is
	// ever committed.
	secret := "ghp_" + strings.Repeat("Zq7", 12)
	masked := Secret(secret)
	if strings.Contains(masked, secret) {
		t.Fatal("masked output must not contain the original value")
	}
	if !strings.HasPrefix(masked, "ghp_") {
		t.Fatalf("mask should keep a short recognizable prefix, got %q", masked)
	}
	if !strings.Contains(masked, "40 chars") {
		t.Fatalf("mask should report the original length, got %q", masked)
	}
	if strings.Contains(masked, secret[4:12]) {
		t.Fatal("mask must not leak value bytes beyond the prefix")
	}
}

func TestSecretShortValues(t *testing.T) {
	if got := Secret(""); got != "" {
		t.Fatalf("Secret(\"\") = %q", got)
	}
	got := Secret("abcdefg")
	if got != "*******" {
		t.Fatalf("short values must be fully masked, got %q", got)
	}
}

func TestSecretUnicodeSafe(t *testing.T) {
	v := strings.Repeat("密", 12)
	masked := Secret(v)
	if strings.Contains(masked, strings.Repeat("密", 5)) {
		t.Fatalf("mask leaked wide runes: %q", masked)
	}
	if !strings.Contains(masked, "12 chars") {
		t.Fatalf("rune length wrong: %q", masked)
	}
}

func TestPathUser(t *testing.T) {
	got := PathUser(`C:\Users\ExampleUser\notes`, "ExampleUser")
	if got != `C:\Users\`+UserSegment+`\notes` {
		t.Fatalf("PathUser = %q", got)
	}
	if PathUser("x", "") != "x" {
		t.Fatal("empty username must leave the path unchanged")
	}
}
