package platform

import (
	"testing"

	"github.com/Yakitori197/yolab-agent-skill-guard/internal/model"
)

func TestClassify(t *testing.T) {
	skillDirs := map[string]bool{
		".claude/skills/pdf": true,
		"packages/writer":    true,
	}
	cases := []struct {
		rel     string
		want    model.Platform
		pkgRoot string
	}{
		{"SKILL.md", model.PlatformClaude, ""},
		{".claude/skills/pdf/SKILL.md", model.PlatformClaude, ".claude/skills/pdf"},
		{".claude/skills/pdf/references/notes.md", model.PlatformClaude, ".claude/skills/pdf"},
		{"packages/writer/SKILL.md", model.PlatformClaude, "packages/writer"},
		{"packages/writer/extra.md", model.PlatformClaude, "packages/writer"},
		{"AGENTS.md", model.PlatformCodex, ""},
		{"agents.md", model.PlatformCodex, ""},
		{"CLAUDE.md", model.PlatformClaude, ""},
		{".cursor/rules/style.mdc", model.PlatformCursor, ""},
		{"notes/style.mdc", model.PlatformCursor, ""},
		{".claude/commands/deploy.md", model.PlatformClaude, ""},
		{".cursor/readme.md", model.PlatformCursor, ""},
		{"README.md", model.PlatformGeneric, ""},
		{"docs/guide.md", model.PlatformGeneric, ""},
	}
	for _, c := range cases {
		got, pkg := Classify(c.rel, skillDirs)
		if got != c.want || pkg != c.pkgRoot {
			t.Errorf("Classify(%q) = %v,%q want %v,%q", c.rel, got, pkg, c.want, c.pkgRoot)
		}
	}
}

func TestClassifyRootSkillDir(t *testing.T) {
	skillDirs := map[string]bool{"": true}
	got, pkg := Classify("helper.md", skillDirs)
	if got != model.PlatformClaude || pkg != "" {
		t.Fatalf("root skill package: got %v,%q", got, pkg)
	}
	got, pkg = Classify("SKILL.md", skillDirs)
	if got != model.PlatformClaude || pkg != "" {
		t.Fatalf("root SKILL.md: got %v,%q", got, pkg)
	}
}

func TestClassifyAgentsInsideSkillDir(t *testing.T) {
	// AGENTS.md keeps its codex identity even inside a skill package, but
	// inherits the package root for containment.
	skillDirs := map[string]bool{"pkg": true}
	got, pkg := Classify("pkg/AGENTS.md", skillDirs)
	if got != model.PlatformCodex || pkg != "pkg" {
		t.Fatalf("got %v,%q", got, pkg)
	}
}
