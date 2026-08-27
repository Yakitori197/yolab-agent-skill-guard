package parser

import (
	"strings"
	"testing"

	"github.com/Yakitori197/yolab-agent-skill-guard/internal/model"
)

func load(content string) *Document {
	return Load("SKILL.md", model.PlatformClaude, "", []byte(content))
}

func TestFrontmatterNormal(t *testing.T) {
	d := load("---\nname: my-skill\ndescription: does things\n---\n\n# Body\n")
	fm := d.Frontmatter
	if !fm.Present || fm.ParseErr != nil || fm.NotMapping {
		t.Fatalf("unexpected frontmatter state: %+v", fm)
	}
	if fm.StartLine != 1 || fm.EndLine != 4 {
		t.Fatalf("marker lines = %d..%d", fm.StartLine, fm.EndLine)
	}
	n, ok := fm.Field("name")
	if !ok {
		t.Fatal("missing name field")
	}
	if v, isStr := ScalarString(n); !isStr || v != "my-skill" {
		t.Fatalf("name = %q (%v)", v, isStr)
	}
	if got := fm.Line(n); got != 2 {
		t.Fatalf("name line = %d, want 2", got)
	}
	if len(fm.Order) != 2 || fm.Order[0] != "name" || fm.Order[1] != "description" {
		t.Fatalf("order = %v", fm.Order)
	}
	if d.BodyStart() != 5 {
		t.Fatalf("BodyStart = %d", d.BodyStart())
	}
}

func TestFrontmatterAbsent(t *testing.T) {
	d := load("# Just a heading\n\ntext\n")
	if d.Frontmatter.Present {
		t.Fatal("no frontmatter expected")
	}
	if d.BodyStart() != 1 {
		t.Fatalf("BodyStart = %d", d.BodyStart())
	}
}

func TestFrontmatterUnclosedIsThematicBreak(t *testing.T) {
	d := load("---\ntitle: not frontmatter without a closer\n")
	if d.Frontmatter.Present {
		t.Fatal("unclosed --- must not count as frontmatter")
	}
}

func TestFrontmatterDotDotDotCloser(t *testing.T) {
	d := load("---\na: 1\n...\nbody\n")
	if !d.Frontmatter.Present || d.Frontmatter.EndLine != 3 {
		t.Fatalf("state: %+v", d.Frontmatter)
	}
}

func TestFrontmatterMalformedYAML(t *testing.T) {
	d := load("---\nname: [unclosed\n---\nbody\n")
	if d.Frontmatter.ParseErr == nil {
		t.Fatal("expected a parse error")
	}
}

func TestFrontmatterNotMapping(t *testing.T) {
	d := load("---\n- a\n- b\n---\n")
	if !d.Frontmatter.NotMapping {
		t.Fatal("expected NotMapping")
	}
}

func TestFrontmatterDuplicateKeys(t *testing.T) {
	d := load("---\nname: one\nname: two\nother: x\n---\n")
	fm := d.Frontmatter
	if len(fm.Duplicates) != 1 || fm.Duplicates[0].Key != "name" {
		t.Fatalf("duplicates = %v", fm.Duplicates)
	}
	if fm.Duplicates[0].Line != 3 {
		t.Fatalf("duplicate line = %d, want 3", fm.Duplicates[0].Line)
	}
	if v, _ := ScalarString(fm.Fields["name"]); v != "one" {
		t.Fatalf("first occurrence must win, got %q", v)
	}
}

func TestFrontmatterEmptyBlock(t *testing.T) {
	d := load("---\n---\nbody\n")
	fm := d.Frontmatter
	if !fm.Present || fm.ParseErr != nil || fm.NotMapping {
		t.Fatalf("state: %+v", fm)
	}
	if len(fm.Fields) != 0 {
		t.Fatalf("fields = %v", fm.Fields)
	}
}

func TestFrontmatterOversized(t *testing.T) {
	huge := "---\nk: " + strings.Repeat("a", MaxFrontmatterBytes+10) + "\n---\n"
	d := load(huge)
	if !d.Frontmatter.Oversized {
		t.Fatal("expected Oversized")
	}
}

func TestScalarStringTypes(t *testing.T) {
	d := load("---\ns: text\nn: 42\nb: true\nlist:\n  - a\n---\n")
	fm := d.Frontmatter
	if v, ok := ScalarString(fm.Fields["s"]); !ok || v != "text" {
		t.Fatalf("s = %q %v", v, ok)
	}
	if _, ok := ScalarString(fm.Fields["n"]); ok {
		t.Fatal("int must not be a string scalar")
	}
	if _, ok := ScalarString(fm.Fields["b"]); ok {
		t.Fatal("bool must not be a string scalar")
	}
	if _, ok := ScalarString(fm.Fields["list"]); ok {
		t.Fatal("sequence must not be a string scalar")
	}
	if _, ok := ScalarString(nil); ok {
		t.Fatal("nil node must not be a string scalar")
	}
}

func TestFieldOnAbsentFrontmatter(t *testing.T) {
	d := load("plain\n")
	if _, ok := d.Frontmatter.Field("name"); ok {
		t.Fatal("Field on absent frontmatter must return false")
	}
}

func TestCRLFNormalization(t *testing.T) {
	d := Load("a.md", model.PlatformGeneric, "", []byte("---\r\nname: x\r\n---\r\nbody\r\n"))
	if !d.Frontmatter.Present {
		t.Fatal("CRLF frontmatter must parse")
	}
	if len(d.Lines) != 4 {
		t.Fatalf("lines = %d, want 4", len(d.Lines))
	}
}
