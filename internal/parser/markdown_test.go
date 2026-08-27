package parser

import (
	"testing"

	"github.com/Yakitori197/yolab-agent-skill-guard/internal/model"
)

func TestAnnotateFences(t *testing.T) {
	d := load("prose\n```bash\nrm x\n```\nafter\n~~~sql\nselect 1\n~~~\n")
	wantFence := []bool{false, true, true, true, false, true, true, true}
	wantLang := []string{"", "bash", "bash", "bash", "", "sql", "sql", "sql"}
	for i := range wantFence {
		if d.LineInfo[i].Fence != wantFence[i] || d.LineInfo[i].FenceLang != wantLang[i] {
			t.Errorf("line %d: %+v want fence=%v lang=%q", i+1, d.LineInfo[i], wantFence[i], wantLang[i])
		}
	}
}

func TestFenceLongerCloser(t *testing.T) {
	d := load("````\n```\nstill fenced\n````\nout\n")
	if !d.LineInfo[2].Fence {
		t.Fatal("shorter run must not close a longer fence")
	}
	if d.LineInfo[4].Fence {
		t.Fatal("fence must close at the matching-length run")
	}
}

func TestFenceInfoStringWithBacktickIsNotAFence(t *testing.T) {
	d := load("``` a`b\ntext\n")
	if d.LineInfo[0].Fence {
		t.Fatal("info strings containing backticks are not fences")
	}
}

func TestBlockquoteDetection(t *testing.T) {
	d := load("plain\n> quoted line\n  > indented quote\n")
	if d.LineInfo[0].Blockquote || !d.LineInfo[1].Blockquote || !d.LineInfo[2].Blockquote {
		t.Fatalf("blockquote flags: %+v", d.LineInfo)
	}
}

func TestFrontmatterLinesAnnotated(t *testing.T) {
	d := load("---\nname: x\n---\nbody\n")
	if !d.LineInfo[0].Frontmatter || !d.LineInfo[2].Frontmatter {
		t.Fatal("frontmatter markers must be annotated")
	}
	if d.LineInfo[3].Frontmatter {
		t.Fatal("body must not be frontmatter")
	}
}

func TestInlineSpans(t *testing.T) {
	spans := inlineSpans("a `x` and ``y`z`` end")
	if len(spans) != 2 {
		t.Fatalf("spans = %v", spans)
	}
	spans = inlineSpans("no code here")
	if len(spans) != 0 {
		t.Fatalf("spans = %v", spans)
	}
	spans = inlineSpans("unmatched ` tick")
	if len(spans) != 0 {
		t.Fatalf("unmatched spans = %v", spans)
	}
}

func TestContextAt(t *testing.T) {
	d := load("---\nname: x\n---\nprose `inline` more\n```sh\ncmd\n```\n")
	if got := d.ContextAt(2, 0); got != model.ContextFrontmatter {
		t.Fatalf("frontmatter ctx = %v", got)
	}
	if got := d.ContextAt(4, 0); got != model.ContextProse {
		t.Fatalf("prose ctx = %v", got)
	}
	inlineOff := len("prose ")
	if got := d.ContextAt(4, inlineOff); got != model.ContextInlineCode {
		t.Fatalf("inline ctx = %v", got)
	}
	if got := d.ContextAt(6, 0); got != model.ContextCodeFence {
		t.Fatalf("fence ctx = %v", got)
	}
	if got := d.ContextAt(99, 0); got != model.ContextProse {
		t.Fatalf("out-of-range ctx = %v", got)
	}
}

func TestColumnAt(t *testing.T) {
	line := "héllo wörld"
	if got := ColumnAt(line, 0); got != 1 {
		t.Fatalf("col(0) = %d", got)
	}
	// byte offset of 'w': h(1)+é(2)+l+l+o+space = 7 bytes
	if got := ColumnAt(line, 7); got != 7 {
		t.Fatalf("col(7 bytes) = %d, want rune col 7", got)
	}
	if got := ColumnAt(line, -5); got != 1 {
		t.Fatalf("negative offset = %d", got)
	}
	if got := ColumnAt(line, 1000); got != len([]rune(line))+1 {
		t.Fatalf("overflow offset = %d", got)
	}
}

func TestDirRel(t *testing.T) {
	d := Load("a/b/c.md", model.PlatformGeneric, "", []byte("x"))
	if d.DirRel() != "a/b" {
		t.Fatalf("DirRel = %q", d.DirRel())
	}
	d = Load("c.md", model.PlatformGeneric, "", []byte("x"))
	if d.DirRel() != "" {
		t.Fatalf("root DirRel = %q", d.DirRel())
	}
}
