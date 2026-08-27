package rules

import (
	"strings"
	"testing"

	"github.com/Yakitori197/yolab-agent-skill-guard/internal/model"
)

// Synthetic credentials are always assembled at runtime so that no
// credential-shaped literal is ever committed to the repository.
func synthGitHubToken() string { return "ghp_" + strings.Repeat("Ab1", 12) }        // 36 tail chars
func synthAWSKey() string      { return "AKIA" + strings.Repeat("Q7", 8) }          // 16 tail chars
func synthSlackToken() string  { return "xoxb-" + strings.Repeat("1234567890", 2) } // 20 tail chars
func synthJWT() string         { return "eyJ" + part(12) + "." + "eyJ" + part(9) + "." + part(12) }
func synthProviderKey() string { return "sk-ant-" + strings.Repeat("k9J", 8) } // 24 tail chars
func synthConnString() string  { return "postgres://admin:S3cr3tV4lueXY@db.host.fixture:5432/app" }
func part(n int) string        { return strings.Repeat("aZ", n) }

func TestASG001DetectsAndMasks(t *testing.T) {
	cases := []struct {
		name   string
		line   string
		secret string
	}{
		{"github token", "token: " + synthGitHubToken(), synthGitHubToken()},
		{"aws key", "key = " + synthAWSKey(), synthAWSKey()},
		{"slack token", "slack: " + synthSlackToken(), synthSlackToken()},
		{"jwt", "auth " + synthJWT(), synthJWT()},
		{"provider key", "use " + synthProviderKey(), synthProviderKey()},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			fs := runRule(t, "ASG001", skillDoc(c.line+"\n"), nil)
			assertCount(t, fs, 1)
			if strings.Contains(fs[0].Message, c.secret) {
				t.Fatalf("message leaks the raw secret: %s", fs[0].Message)
			}
			if fs[0].Line != 1 {
				t.Fatalf("line = %d", fs[0].Line)
			}
		})
	}
}

func TestASG001ConnectionString(t *testing.T) {
	fs := runRule(t, "ASG001", skillDoc("db: "+synthConnString()+"\n"), nil)
	assertCount(t, fs, 1)
	if strings.Contains(fs[0].Message, "S3cr3tV4lueXY") {
		t.Fatalf("password leaked: %s", fs[0].Message)
	}
	if fs[0].Severity != model.SeverityCritical {
		t.Fatalf("severity = %v", fs[0].Severity)
	}
}

func TestASG001PrivateKeyHeader(t *testing.T) {
	// Assembled at runtime so even the bare header never appears verbatim in
	// the repository.
	header := "-----BEGIN RSA PRIVATE" + " KEY-----"
	fs := runRule(t, "ASG001", skillDoc(header+"\n(omitted)\n"), nil)
	assertCount(t, fs, 1)
	if fs[0].Severity != model.SeverityCritical {
		t.Fatalf("severity = %v", fs[0].Severity)
	}
	fs = runRule(t, "ASG001", skillDoc("-----BEGIN OPENSSH PRIVATE"+" KEY-----\n"), nil)
	assertCount(t, fs, 1)
}

func TestASG001AssignedSecretEntropy(t *testing.T) {
	high := "api_key: \"" + "fJ3k9QpL2mXv8Rb1TzWq" + "\""
	fs := runRule(t, "ASG001", skillDoc(high+"\n"), nil)
	assertCount(t, fs, 1)
	if fs[0].Severity != model.SeverityHigh {
		t.Fatalf("severity = %v", fs[0].Severity)
	}
	// Low-entropy values are not flagged.
	fs = runRule(t, "ASG001", skillDoc("api_key: \"aaaaaaaaaaaaaaaaaaaa\"\n"), nil)
	assertCount(t, fs, 0)
}

func TestASG001PlaceholdersIgnored(t *testing.T) {
	lines := []string{
		"api_key: \"${SERVICE_API_KEY}\"",
		"password: \"your-password-goes-here\"",
		"secret_key: \"example-value-not-real\"",
		"token: \"<insert-token-here>\"",
		"db: postgres://user:${DB_PASSWORD}@db.example.com/app",
		"db: postgres://user:changeme-placeholder@db.example.com/app",
	}
	fs := runRule(t, "ASG001", skillDoc(strings.Join(lines, "\n")+"\n"), nil)
	assertCount(t, fs, 0)
}

func TestASG001FrontmatterScanned(t *testing.T) {
	fs := runRule(t, "ASG001", skillDoc("---\nname: x\ndescription: uses "+synthGitHubToken()+"\n---\n"), nil)
	assertCount(t, fs, 1)
	if fs[0].Context != model.ContextFrontmatter {
		t.Fatalf("context = %v", fs[0].Context)
	}
}

func TestASG001CleanContent(t *testing.T) {
	fs := runRule(t, "ASG001", skillDoc("# Title\n\nNormal prose about tokens in general.\n"), nil)
	assertCount(t, fs, 0)
}
