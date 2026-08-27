package rules

import (
	"strings"
	"testing"

	"github.com/Yakitori197/yolab-agent-skill-guard/internal/model"
)

func TestASG002WindowsUserPath(t *testing.T) {
	fs := runRule(t, "ASG002", skillDoc(`Read C:\Users\ExampleUser\Documents\notes.md first.`+"\n"), nil)
	assertCount(t, fs, 1)
	if strings.Contains(fs[0].Message, "ExampleUser") {
		t.Fatalf("username leaked: %s", fs[0].Message)
	}
	if !strings.Contains(fs[0].Message, "<redacted-user>") {
		t.Fatalf("expected redaction marker: %s", fs[0].Message)
	}
	if fs[0].Severity != model.SeverityMedium {
		t.Fatalf("severity = %v", fs[0].Severity)
	}
}

func TestASG002ForwardSlashDrive(t *testing.T) {
	fs := runRule(t, "ASG002", skillDoc("See C:/Users/ExampleUser/notes.md\n"), nil)
	assertCount(t, fs, 1)
}

func TestASG002UnixHome(t *testing.T) {
	fs := runRule(t, "ASG002", skillDoc("Cache lives in /home/exampleuser/.cache and /Users/exampleuser/Library.\n"), nil)
	assertCount(t, fs, 2)
	for _, f := range fs {
		if strings.Contains(f.Message, "exampleuser") {
			t.Fatalf("username leaked: %s", f.Message)
		}
	}
}

func TestASG002PlaceholdersIgnored(t *testing.T) {
	lines := []string{
		`Use %USERPROFILE%\Documents instead.`,
		`Use C:\Users\%USERNAME%\AppData when needed.`,
		`Use C:\Users\<username>\Downloads for examples.`,
		`Use /home/$USER/.config for config.`,
		`Use /home/${USER}/.config too.`,
		"Use ~/notes.md for personal notes.",
	}
	fs := runRule(t, "ASG002", skillDoc(strings.Join(lines, "\n")+"\n"), nil)
	assertCount(t, fs, 0)
}

func TestASG002URLNotFlagged(t *testing.T) {
	fs := runRule(t, "ASG002", skillDoc("Docs at https://site.fixture/Users/octocat/profile page.\n"), nil)
	assertCount(t, fs, 0)
}

func TestASG002UNC(t *testing.T) {
	fs := runRule(t, "ASG002", skillDoc(`Data on \\fileserver01\projects\shared.`+"\n"), nil)
	assertCount(t, fs, 1)
	if fs[0].Severity != model.SeverityLow {
		t.Fatalf("severity = %v", fs[0].Severity)
	}
}

func TestASG002CleanProse(t *testing.T) {
	fs := runRule(t, "ASG002", skillDoc("Relative paths like docs/setup.md are portable.\n"), nil)
	assertCount(t, fs, 0)
}
