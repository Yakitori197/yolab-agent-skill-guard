package parser

import (
	"testing"

	"github.com/Yakitori197/yolab-agent-skill-guard/internal/model"
)

func targets(refs []Ref) []string {
	var out []string
	for _, r := range refs {
		out = append(out, r.Kind+":"+r.Target)
	}
	return out
}

func TestExtractRefsKinds(t *testing.T) {
	d := load("See [guide](docs/guide.md) and ![logo](img/logo.png).\n\n[def]: shared/def.md\n\nVisit <https://site.example/page>.\n")
	got := targets(d.Refs())
	want := []string{
		"link:docs/guide.md",
		"image:img/logo.png",
		"refdef:shared/def.md",
		"autolink:https://site.example/page",
	}
	if len(got) != len(want) {
		t.Fatalf("refs = %v", got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("refs[%d] = %q, want %q (all: %v)", i, got[i], want[i], got)
		}
	}
}

func TestExtractRefsSkipsCodeContexts(t *testing.T) {
	d := load("```\n[not-a-ref](fenced.md)\n```\n\nInline `[also-not](inline.md)` code.\n\nReal [ref](real.md).\n")
	got := targets(d.Refs())
	if len(got) != 1 || got[0] != "link:real.md" {
		t.Fatalf("refs = %v", got)
	}
}

func TestExtractRefsAngleAndTitle(t *testing.T) {
	d := load("[a](<my file.md>) and [b](plain.md \"Title\")\n")
	got := targets(d.Refs())
	want := []string{"link:my file.md", "link:plain.md"}
	if len(got) != 2 || got[0] != want[0] || got[1] != want[1] {
		t.Fatalf("refs = %v", got)
	}
}

func TestExtractRefsAnchors(t *testing.T) {
	d := load("[sec](#section) stays anchored\n")
	got := d.Refs()
	if len(got) != 1 || got[0].Target != "#section" {
		t.Fatalf("refs = %v", targets(got))
	}
}

func TestExtractRefsPositions(t *testing.T) {
	d := load("pad [x](t.md)\n")
	refs := d.Refs()
	if len(refs) != 1 {
		t.Fatalf("refs = %v", targets(refs))
	}
	if refs[0].Line != 1 {
		t.Fatalf("line = %d", refs[0].Line)
	}
	if refs[0].ByteOff != len("pad [x](") {
		t.Fatalf("byteoff = %d", refs[0].ByteOff)
	}
}

func TestExtractRefsFrontmatterSkipped(t *testing.T) {
	d := load("---\nname: x\ndescription: '[link](fm.md)'\n---\n[real](body.md)\n")
	got := targets(d.Refs())
	if len(got) != 1 || got[0] != "link:body.md" {
		t.Fatalf("refs = %v", got)
	}
}

func TestRefsCached(t *testing.T) {
	d := load("[a](x.md)\n")
	first := d.Refs()
	second := d.Refs()
	if len(first) != 1 || len(second) != 1 {
		t.Fatal("refs must be stable across calls")
	}
}

func TestParenthesizedTarget(t *testing.T) {
	d := Load("n.md", model.PlatformGeneric, "", []byte("[f](file(1).md)\n"))
	refs := d.Refs()
	if len(refs) != 1 || refs[0].Target != "file(1).md" {
		t.Fatalf("refs = %v", targets(refs))
	}
}
