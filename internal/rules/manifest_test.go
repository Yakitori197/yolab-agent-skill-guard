package rules

import (
	"strings"
	"testing"

	"github.com/Yakitori197/yolab-agent-skill-guard/internal/model"
)

func TestASG009ValidSkillManifest(t *testing.T) {
	fs := runRule(t, "ASG009", skillDoc("---\nname: my-skill\ndescription: does things\nversion: \"1.0\"\n---\nbody\n"), nil)
	assertCount(t, fs, 0)
}

func TestASG009MissingFrontmatter(t *testing.T) {
	fs := runRule(t, "ASG009", skillDoc("# No frontmatter here\n"), nil)
	assertCount(t, fs, 1)
	if fs[0].Severity != model.SeverityHigh {
		t.Fatalf("severity = %v", fs[0].Severity)
	}
}

func TestASG009GenericFileWithoutFrontmatterOK(t *testing.T) {
	d := docFrom("README.md", model.PlatformGeneric, "", "# Readme\n")
	fs := runRule(t, "ASG009", d, nil)
	assertCount(t, fs, 0)
}

func TestASG009MissingFields(t *testing.T) {
	fs := runRule(t, "ASG009", skillDoc("---\nname: my-skill\n---\n"), nil)
	assertCount(t, fs, 1)
	if !hasMessage(fs, "description") {
		t.Fatalf("findings = %v", fs)
	}
	fs = runRule(t, "ASG009", skillDoc("---\ndescription: d\n---\n"), nil)
	assertCount(t, fs, 1)
	if !hasMessage(fs, "name") {
		t.Fatalf("findings = %v", fs)
	}
}

func TestASG009WrongTypes(t *testing.T) {
	fs := runRule(t, "ASG009", skillDoc("---\nname: 42\ndescription: d\n---\n"), nil)
	assertCount(t, fs, 1)
	if !hasMessage(fs, "non-empty string") {
		t.Fatalf("findings = %v", fs)
	}
	fs = runRule(t, "ASG009", skillDoc("---\nname: my-skill\ndescription: d\nallowed-tools: Bash\n---\n"), nil)
	assertCount(t, fs, 1)
	if !hasMessage(fs, "allowed-tools") {
		t.Fatalf("findings = %v", fs)
	}
	fs = runRule(t, "ASG009", skillDoc("---\nname: my-skill\ndescription: d\nversion: 2\n---\n"), nil)
	assertCount(t, fs, 1)
}

func TestASG009NameFormat(t *testing.T) {
	fs := runRule(t, "ASG009", skillDoc("---\nname: My Fancy Skill\ndescription: d\n---\n"), nil)
	assertCount(t, fs, 1)
	if fs[0].Severity != model.SeverityLow {
		t.Fatalf("severity = %v", fs[0].Severity)
	}
	long := strings.Repeat("a", 70)
	fs = runRule(t, "ASG009", skillDoc("---\nname: "+long+"\ndescription: d\n---\n"), nil)
	assertCount(t, fs, 1)
	if !hasMessage(fs, "64 characters") {
		t.Fatalf("findings = %v", fs)
	}
}

func TestASG009DuplicateKeys(t *testing.T) {
	fs := runRule(t, "ASG009", skillDoc("---\nname: a\nname: b\ndescription: d\n---\n"), nil)
	assertCount(t, fs, 1)
	if !hasMessage(fs, "Duplicate frontmatter key") {
		t.Fatalf("findings = %v", fs)
	}
	if fs[0].Line != 3 {
		t.Fatalf("line = %d, want 3", fs[0].Line)
	}
}

func TestASG009MalformedYAML(t *testing.T) {
	fs := runRule(t, "ASG009", skillDoc("---\nname: [unclosed\n---\n"), nil)
	assertCount(t, fs, 1)
	if !hasMessage(fs, "not valid YAML") {
		t.Fatalf("findings = %v", fs)
	}
	if fs[0].Severity != model.SeverityHigh {
		t.Fatalf("severity = %v", fs[0].Severity)
	}
}

func TestASG009NotMapping(t *testing.T) {
	fs := runRule(t, "ASG009", skillDoc("---\n- just\n- a list\n---\n"), nil)
	assertCount(t, fs, 1)
	if !hasMessage(fs, "mapping") {
		t.Fatalf("findings = %v", fs)
	}
}

func TestASG009PlatformsValidation(t *testing.T) {
	fs := runRule(t, "ASG009", skillDoc("---\nname: x\ndescription: d\nplatforms:\n  - claude\n  - vim\n---\n"), nil)
	assertCount(t, fs, 1)
	if !hasMessage(fs, "vim") {
		t.Fatalf("findings = %v", fs)
	}
	fs = runRule(t, "ASG009", skillDoc("---\nname: x\ndescription: d\nplatforms: everything\n---\n"), nil)
	assertCount(t, fs, 1)
	fs = runRule(t, "ASG009", skillDoc("---\nname: x\ndescription: d\nplatforms:\n  - 42\n---\n"), nil)
	assertCount(t, fs, 1)
}

func TestASG009SchemaVersion(t *testing.T) {
	fs := runRule(t, "ASG009", skillDoc("---\nname: x\ndescription: d\nschema_version: 1\n---\n"), nil)
	assertCount(t, fs, 0)
	fs = runRule(t, "ASG009", skillDoc("---\nname: x\ndescription: d\nschema_version: 9\n---\n"), nil)
	assertCount(t, fs, 1)
	if !hasMessage(fs, "schema_version") {
		t.Fatalf("findings = %v", fs)
	}
	fs = runRule(t, "ASG009", skillDoc("---\nname: x\ndescription: d\nschema_version: two\n---\n"), nil)
	assertCount(t, fs, 1)
}

func TestASG009CursorRule(t *testing.T) {
	d := docFrom(".cursor/rules/style.mdc", model.PlatformCursor, "", "---\ndescription: style rules\nglobs: \"src/**\"\nalwaysApply: true\n---\nbody\n")
	fs := runRule(t, "ASG009", d, nil)
	assertCount(t, fs, 0)

	d = docFrom(".cursor/rules/style.mdc", model.PlatformCursor, "", "---\ndescription: 42\nglobs:\n  a: b\nalwaysApply: sometimes\n---\n")
	fs = runRule(t, "ASG009", d, nil)
	assertCount(t, fs, 3)
}

func TestASG009OversizedFrontmatter(t *testing.T) {
	huge := "---\nk: " + strings.Repeat("a", 300000) + "\n---\n"
	fs := runRule(t, "ASG009", docFrom("SKILL.md", model.PlatformClaude, "", huge), nil)
	assertCount(t, fs, 1)
	if !hasMessage(fs, "parsing limit") {
		t.Fatalf("findings = %v", fs)
	}
}
