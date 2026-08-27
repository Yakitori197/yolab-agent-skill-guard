package rules

import (
	"strings"
	"testing"

	"github.com/Yakitori197/yolab-agent-skill-guard/internal/config"
	"github.com/Yakitori197/yolab-agent-skill-guard/internal/model"
	"github.com/Yakitori197/yolab-agent-skill-guard/internal/parser"
)

// docFrom builds a Document for rule tests.
func docFrom(relPath string, platform model.Platform, pkgRoot, content string) *parser.Document {
	return parser.Load(relPath, platform, pkgRoot, []byte(content))
}

// skillDoc is the common case: a SKILL.md at the scan root.
func skillDoc(content string) *parser.Document {
	return docFrom("SKILL.md", model.PlatformClaude, "", content)
}

// fakeCtx simulates a filesystem via a set of existing root-relative paths.
type fakeCtx struct {
	files   map[string]bool
	outside map[string]bool // paths whose symlink target leaves the root
}

func newCtx(cfg *config.Config, existing ...string) *Context {
	fc := &fakeCtx{files: map[string]bool{}, outside: map[string]bool{}}
	for _, f := range existing {
		fc.files[f] = true
	}
	if cfg == nil {
		cfg = config.Default()
	}
	return &Context{
		Config:     cfg,
		FoldCase:   false,
		FileExists: func(rel string) bool { return fc.files[rel] },
		ResolveReal: func(rel string) (bool, bool) {
			if fc.outside[rel] {
				return false, true
			}
			return true, fc.files[rel]
		},
	}
}

func cfgFrom(t *testing.T, yaml string) *config.Config {
	t.Helper()
	cfg, err := config.Parse([]byte(yaml), "test.yml", IDs(), DetectionIDs())
	if err != nil {
		t.Fatalf("config: %v", err)
	}
	return cfg
}

// ruleByID fetches a rule implementation.
func ruleByID(t *testing.T, id string) Rule {
	t.Helper()
	for _, r := range All() {
		if r.Meta().ID == id {
			return r
		}
	}
	t.Fatalf("rule %s not found", id)
	return nil
}

// runRule executes one rule against content with a default context.
func runRule(t *testing.T, id string, d *parser.Document, ctx *Context) []model.Finding {
	t.Helper()
	if ctx == nil {
		ctx = newCtx(nil)
	}
	return ruleByID(t, id).Check(d, ctx)
}

// assertCount fails unless exactly n findings were produced.
func assertCount(t *testing.T, fs []model.Finding, n int) {
	t.Helper()
	if len(fs) != n {
		var lines []string
		for _, f := range fs {
			lines = append(lines, f.RuleID+" "+f.Message)
		}
		t.Fatalf("findings = %d, want %d:\n%s", len(fs), n, strings.Join(lines, "\n"))
	}
}

// hasMessage reports whether any finding message contains sub.
func hasMessage(fs []model.Finding, sub string) bool {
	for _, f := range fs {
		if strings.Contains(f.Message, sub) {
			return true
		}
	}
	return false
}

func severities(fs []model.Finding) []model.Severity {
	var out []model.Severity
	for _, f := range fs {
		out = append(out, f.Severity)
	}
	return out
}
