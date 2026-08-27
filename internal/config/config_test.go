package config

import (
	"strings"
	"testing"
	"time"

	"github.com/Yakitori197/yolab-agent-skill-guard/internal/model"
)

var knownRules = []string{"ASG001", "ASG002", "ASG003", "ASG007", "ASG900"}
var detectionRules = []string{"ASG001", "ASG002", "ASG003", "ASG007"}

func parse(t *testing.T, yaml string) (*Config, error) {
	t.Helper()
	return Parse([]byte(yaml), "test.yml", knownRules, detectionRules)
}

func mustParse(t *testing.T, yaml string) *Config {
	t.Helper()
	cfg, err := parse(t, yaml)
	if err != nil {
		t.Fatalf("unexpected config error: %v", err)
	}
	return cfg
}

func mustFail(t *testing.T, yaml, wantSub string) {
	t.Helper()
	_, err := parse(t, yaml)
	if err == nil {
		t.Fatalf("expected error containing %q, got nil", wantSub)
	}
	if !strings.Contains(err.Error(), wantSub) {
		t.Fatalf("error %q does not contain %q", err.Error(), wantSub)
	}
}

func TestDefaultConfig(t *testing.T) {
	cfg := Default()
	if cfg.FailOn != model.FailOn(model.SeverityHigh) {
		t.Fatalf("default fail_on = %v", cfg.FailOn)
	}
	if cfg.MaxFileSize != DefaultFileSize {
		t.Fatalf("default max size = %d", cfg.MaxFileSize)
	}
	if len(cfg.Platforms) != len(model.Platforms) {
		t.Fatalf("default platforms = %v", cfg.Platforms)
	}
	if cfg.Source != DefaultSource {
		t.Fatalf("source = %q", cfg.Source)
	}
}

func TestParseFullConfig(t *testing.T) {
	cfg := mustParse(t, `
version: 1
fail_on: medium
platforms: [claude, cursor]
include:
  - "skills/**/*.md"
exclude:
  - "drafts/**"
max_file_size: 2048
allowed_domains:
  - "api.partner.example.io"
  - "*.trusted.example.io"
allowed_capabilities:
  - network
disabled_rules:
  - ASG002
severity_overrides:
  ASG003: low
suppressions:
  - rule: ASG001
    path: "docs/examples.md"
    reason: "Documented synthetic examples."
    expires: "2099-01-02"
`)
	if cfg.FailOn != model.FailOn(model.SeverityMedium) {
		t.Fatalf("fail_on = %v", cfg.FailOn)
	}
	if len(cfg.Platforms) != 2 || cfg.Platforms[0] != model.PlatformClaude {
		t.Fatalf("platforms = %v", cfg.Platforms)
	}
	if !cfg.IncludeMatch("skills/a/SKILL.md") || cfg.IncludeMatch("other/x.md") {
		t.Fatal("include matching wrong")
	}
	if !cfg.ExcludeMatch("drafts/x.md") || cfg.ExcludeMatch("skills/x.md") {
		t.Fatal("exclude matching wrong")
	}
	if cfg.MaxFileSize != 2048 {
		t.Fatalf("max_file_size = %d", cfg.MaxFileSize)
	}
	if !cfg.RuleDisabled("ASG002") || cfg.RuleDisabled("ASG001") {
		t.Fatal("disabled_rules wrong")
	}
	if cfg.SeverityOverrides["ASG003"] != model.SeverityLow {
		t.Fatalf("override = %v", cfg.SeverityOverrides)
	}
	if len(cfg.Suppressions) != 1 {
		t.Fatalf("suppressions = %v", cfg.Suppressions)
	}
}

func TestParseMinimalConfig(t *testing.T) {
	cfg := mustParse(t, "version: 1\n")
	if cfg.FailOn != model.FailOn(model.SeverityHigh) {
		t.Fatal("minimal config must keep defaults")
	}
}

func TestConfigErrors(t *testing.T) {
	mustFail(t, "", "empty")
	mustFail(t, "fail_on: high\n", "version")
	mustFail(t, "version: 2\n", "unsupported version")
	mustFail(t, "version: 1\nfail_on: sometimes\n", "fail_on")
	mustFail(t, "version: 1\nplatforms: [vim]\n", "platform")
	mustFail(t, "version: 1\nplatforms: []\n", "platforms must not be empty")
	mustFail(t, "version: 1\nmax_file_size: 10\n", "max_file_size")
	mustFail(t, "version: 1\nmax_file_size: 999999999\n", "max_file_size")
	mustFail(t, "version: 1\ndisabled_rules: [ASG999]\n", "unknown rule")
	mustFail(t, "version: 1\nseverity_overrides:\n  ASG999: low\n", "unknown rule")
	mustFail(t, "version: 1\nseverity_overrides:\n  ASG001: loud\n", "severity")
	mustFail(t, "version: 1\nallowed_domains: [\"\"]\n", "allowed_domains")
	mustFail(t, "version: 1\nunknown_field: true\n", "field unknown_field not found")
	mustFail(t, "version: 1\nversion: 1\n", "already defined")
	mustFail(t, "version: 1\ninclude: [\"../up/**\"]\n", "..")
	mustFail(t, "version: 1\nexclude: [\"C:/abs/**\"]\n", "relative")
}

func TestDisableEverythingRejected(t *testing.T) {
	mustFail(t, "version: 1\ndisabled_rules: [ASG001, ASG002, ASG003, ASG007]\n", "disabling everything is not allowed")
	// Disabling all but one is fine.
	mustParse(t, "version: 1\ndisabled_rules: [ASG001, ASG002, ASG003]\n")
}

func TestSuppressionValidation(t *testing.T) {
	mustFail(t, `
version: 1
suppressions:
  - path: "a.md"
    reason: "x"
`, "rule")
	mustFail(t, `
version: 1
suppressions:
  - rule: ASG999
    path: "a.md"
    reason: "x"
`, "unknown rule")
	mustFail(t, `
version: 1
suppressions:
  - rule: ASG001
    path: "a.md"
    reason: "   "
`, "reason")
	mustFail(t, `
version: 1
suppressions:
  - rule: ASG001
    reason: "x"
`, "either \"path\" or \"fingerprint\"")
	// Wildcards without a fingerprint are refused outright: the documented
	// scope is a specific file.
	for _, pattern := range []string{"**", "*", "**/*.md", "**/*.md*", "docs/**", "*/*.*", "docs/*.md", "docs/rule?.md"} {
		mustFail(t, `
version: 1
suppressions:
  - rule: ASG001
    path: "`+pattern+`"
    reason: "scope test"
`, "wildcard")
	}
	// Even with a fingerprint, patterns that could cover the whole supported
	// file set stay refused.
	for _, pattern := range []string{"**", "*", "**/*.md", "**/*.md*", "docs/**", "docs/*", "docs/*.md"} {
		mustFail(t, `
version: 1
suppressions:
  - rule: ASG001
    path: "`+pattern+`"
    fingerprint: "0123456789abcdef"
    reason: "scope test"
`, "path pattern")
	}
	// A narrowed pattern pinned to one finding is allowed.
	mustParse(t, `
version: 1
suppressions:
  - rule: ASG001
    path: "docs/rule?.md"
    fingerprint: "0123456789abcdef"
    reason: "one known finding in a generated file name"
`)
	// The normal form — a specific relative file — stays allowed.
	mustParse(t, `
version: 1
suppressions:
  - rule: ASG001
    path: "docs/rules.md"
    reason: "documented synthetic example"
`)
	mustFail(t, `
version: 1
suppressions:
  - rule: ASG001
    fingerprint: "zznotahash"
    reason: "x"
`, "fingerprint")
	mustFail(t, `
version: 1
suppressions:
  - rule: ASG001
    path: "a.md"
    reason: "x"
    expires: "01/02/2027"
`, "expires")
}

func TestSuppressionMatchingAndExpiry(t *testing.T) {
	cfg := mustParse(t, `
version: 1
suppressions:
  - rule: ASG001
    path: "docs/a.md"
    reason: "scoped"
  - rule: ASG002
    fingerprint: "0123456789abcdef"
    reason: "by fingerprint"
  - rule: ASG003
    path: "old.md"
    reason: "expired entry"
    expires: "2020-01-01"
`)
	f := model.Finding{RuleID: "ASG001", Path: "docs/a.md", Fingerprint: "ffffffffffffffff"}
	if !cfg.Suppressions[0].Matches(f) {
		t.Fatal("path suppression must match")
	}
	if cfg.Suppressions[0].Matches(model.Finding{RuleID: "ASG001", Path: "src/a.md"}) {
		t.Fatal("path suppression must not match other dirs")
	}
	if cfg.Suppressions[0].Matches(model.Finding{RuleID: "ASG002", Path: "docs/a.md"}) {
		t.Fatal("rule mismatch must not match")
	}
	fp := model.Finding{RuleID: "ASG002", Path: "any.md", Fingerprint: "0123456789abcdef"}
	if !cfg.Suppressions[1].Matches(fp) {
		t.Fatal("fingerprint suppression must match")
	}
	fp.Fingerprint = "aaaaaaaaaaaaaaaa"
	if cfg.Suppressions[1].Matches(fp) {
		t.Fatal("fingerprint mismatch must not match")
	}

	now := time.Date(2026, 8, 26, 12, 0, 0, 0, time.UTC)
	if cfg.Suppressions[0].Expired(now) {
		t.Fatal("no expiry must never expire")
	}
	if !cfg.Suppressions[2].Expired(now) {
		t.Fatal("2020 expiry must be expired in 2026")
	}
	onDay := time.Date(2020, 1, 1, 23, 0, 0, 0, time.UTC)
	if cfg.Suppressions[2].Expired(onDay) {
		t.Fatal("expiry date itself is inclusive")
	}
}

func TestCompileGlob(t *testing.T) {
	re, err := CompileGlob("skills/**/*.md")
	if err != nil {
		t.Fatal(err)
	}
	for _, match := range []string{"skills/a.md", "skills/a/b.md", "skills/a/b/c.md"} {
		if !re.MatchString(match) {
			t.Errorf("%q should match", match)
		}
	}
	for _, miss := range []string{"skills/a.txt", "other/a.md", "skills/a.md/x"} {
		if re.MatchString(miss) {
			t.Errorf("%q should not match", miss)
		}
	}
	re, err = CompileGlob("a?.md")
	if err != nil || !re.MatchString("ab.md") || re.MatchString("a/b.md") || re.MatchString("a.md") {
		t.Fatalf("? glob wrong: %v", err)
	}
	for _, bad := range []string{"", " ", `a\b`, "/abs", "C:x", "a/../b"} {
		if _, err := CompileGlob(bad); err == nil {
			t.Errorf("CompileGlob(%q) should fail", bad)
		}
	}
}

func TestDomainAllowed(t *testing.T) {
	cfg := mustParse(t, `
version: 1
allowed_domains:
  - "api.partner.example.io"
  - "*.wild.example.io"
`)
	cases := []struct {
		host string
		want bool
	}{
		{"api.partner.example.io", true},
		{"API.PARTNER.EXAMPLE.IO", true},
		{"sub.api.partner.example.io", true},
		{"evil-api.partner.example.io.attacker.net", false},
		{"a.wild.example.io", true},
		{"wild.example.io", false},
		{"unrelated.net", false},
	}
	for _, c := range cases {
		if got := cfg.DomainAllowed(c.host); got != c.want {
			t.Errorf("DomainAllowed(%q) = %v, want %v", c.host, got, c.want)
		}
	}
	if Default().DomainAllowed("anything.net") {
		t.Fatal("defaults must allow no domains")
	}
}

func TestCapabilityAllowed(t *testing.T) {
	cfg := mustParse(t, "version: 1\nallowed_capabilities: [Network]\n")
	if !cfg.CapabilityAllowed("network") {
		t.Fatal("capability match must be case-insensitive")
	}
	if cfg.CapabilityAllowed("exec") {
		t.Fatal("undeclared capability must not be allowed")
	}
}

func TestPlatformEnabled(t *testing.T) {
	cfg := mustParse(t, "version: 1\nplatforms: [codex]\n")
	if !cfg.PlatformEnabled(model.PlatformCodex) || cfg.PlatformEnabled(model.PlatformClaude) {
		t.Fatal("platform filter wrong")
	}
}

func TestIncludeEmptyMeansAll(t *testing.T) {
	cfg := mustParse(t, "version: 1\n")
	if !cfg.IncludeMatch("anything/anywhere.md") {
		t.Fatal("empty include must match everything")
	}
	if cfg.ExcludeMatch("anything.md") {
		t.Fatal("empty exclude must match nothing")
	}
}

func TestYAMLPanicGuard(t *testing.T) {
	// Deeply-nested aliases historically stressed yaml parsers; whatever
	// happens, Parse must return an error or a config, never panic.
	_, _ = parse(t, "version: 1\na: &a [*a, *a]\n")
}

// A configuration file must contain exactly one YAML document. A second
// document — even an empty one — is a policy the reader cannot see, so it is
// refused rather than silently ignored.
func TestSingleDocumentEnforced(t *testing.T) {
	cases := []string{
		"version: 1\n---\nversion: 999\n",
		"version: 1\n---\n",
		"version: 1\n---\nfail_on: none\n",
		"version: 1\n...\n---\nversion: 2\n",
		"version: 1\n---\ndisabled_rules: [ASG001, ASG002, ASG003, ASG007]\n",
	}
	for _, raw := range cases {
		if _, err := parse(t, raw); err == nil {
			t.Fatalf("multi-document config was accepted: %q", raw)
		}
	}
	// A single document with a leading separator remains valid.
	mustParse(t, "---\nversion: 1\nfail_on: none\n")
}
