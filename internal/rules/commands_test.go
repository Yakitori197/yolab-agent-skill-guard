package rules

import (
	"testing"

	"github.com/Yakitori197/yolab-agent-skill-guard/internal/model"
)

func fenced(lang, body string) string {
	return "```" + lang + "\n" + body + "\n```\n"
}

func TestASG003ShellPatterns(t *testing.T) {
	cases := []struct {
		name string
		body string
	}{
		{"rm -rf", "rm -rf build/"},
		{"rm -fr", "rm -fr build/"},
		{"rm split flags", "rm -r -f build/"},
		{"rm long flags", "rm --recursive --force build/"},
		{"remove-item", `Remove-Item -Recurse -Force C:\temp\x`},
		{"remove-item reversed", `Remove-Item C:\temp\x -Force -Recurse`},
		{"git clean", "git clean -xdf"},
		{"git reset hard", "git reset --hard HEAD~3"},
		{"git push force", "git push --force origin main"},
		{"git push -f", "git push -f origin main"},
		{"drop table", "DROP TABLE users;"},
		{"truncate table", "TRUNCATE TABLE audit_log;"},
		{"delete without where", "DELETE FROM sessions;"},
		{"cmd rd", "rd /s /q C:\\temp"},
		{"del /s", "del /s /q *.tmp"},
		{"mkfs", "mkfs.ext4 /dev/sdb1"},
		{"dd", "dd if=/dev/zero of=/dev/sda bs=1M"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			fs := runRule(t, "ASG003", skillDoc(fenced("bash", c.body)), nil)
			if len(fs) < 1 {
				t.Fatalf("expected a finding for %q", c.body)
			}
			if fs[0].Severity != model.SeverityHigh {
				t.Fatalf("severity in fence = %v", fs[0].Severity)
			}
			if fs[0].Context != model.ContextCodeFence {
				t.Fatalf("context = %v", fs[0].Context)
			}
		})
	}
}

func TestASG003ProseWordsNotFlagged(t *testing.T) {
	prose := []string{
		"We should reset the counter and force a clean build.",
		"The hard part is deleting stale entries from the docs.",
		"Truncate long lines when formatting output.",
		"Drop me a note when the database migration is ready.",
		"Push your branch and clean up afterwards.",
	}
	for _, p := range prose {
		fs := runRule(t, "ASG003", skillDoc(p+"\n"), nil)
		assertCount(t, fs, 0)
	}
}

// Prose is not a safety property — an instruction file *is* prose, and an
// agent acts on it either way. Only an explicit prohibition governing the
// same clause may lower the severity.
func TestASG003ProseCommandStaysHigh(t *testing.T) {
	fs := runRule(t, "ASG003", skillDoc("Then run git reset --hard to discard changes.\n"), nil)
	assertCount(t, fs, 1)
	if fs[0].Severity != model.SeverityHigh {
		t.Fatalf("prose severity = %v, want high", fs[0].Severity)
	}
	if fs[0].Context != model.ContextProse {
		t.Fatalf("context = %v", fs[0].Context)
	}
}

// A prohibition keeps full severity: the scanner cannot distinguish a lesson
// from a lure, so it reports and lets a reasoned suppression handle real
// documentation.
func TestASG003ProhibitionKeepsSeverity(t *testing.T) {
	fs := runRule(t, "ASG003", skillDoc("Never run git reset --hard on shared branches.\n"), nil)
	assertCount(t, fs, 1)
	if fs[0].Severity != model.SeverityHigh {
		t.Fatalf("prohibition severity = %v, want high", fs[0].Severity)
	}
}

func TestASG003SafeVariantsNotFlagged(t *testing.T) {
	safe := []string{
		fenced("bash", "rm build/output.txt"),                        // no recursive+force
		fenced("bash", "git push --force-with-lease origin main"),    // lease is exempt
		fenced("sql", "DELETE FROM sessions WHERE expired = true;"),  // conditional delete
		fenced("bash", "git clean -n"),                               // dry run
		fenced("powershell", "Remove-Item C:\\temp\\one.txt -Force"), // not recursive
	}
	for _, s := range safe {
		fs := runRule(t, "ASG003", skillDoc(s), nil)
		assertCount(t, fs, 0)
	}
}

func TestASG003InlineCode(t *testing.T) {
	fs := runRule(t, "ASG003", skillDoc("Use `git reset --hard` here.\n"), nil)
	assertCount(t, fs, 1)
	if fs[0].Context != model.ContextInlineCode {
		t.Fatalf("context = %v", fs[0].Context)
	}
}
