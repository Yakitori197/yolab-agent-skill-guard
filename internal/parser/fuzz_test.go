package parser

import (
	"testing"

	"github.com/Yakitori197/yolab-agent-skill-guard/internal/model"
)

// FuzzLoad asserts the parser never panics on arbitrary bytes and always
// upholds its structural invariants. The scanner processes untrusted text,
// so crash-freedom is a security property, not a nicety.
func FuzzLoad(f *testing.F) {
	seeds := []string{
		"",
		"---\nname: x\n---\nbody\n",
		"---\nname: [unclosed\n---\n",
		"---\n- list\n---\n",
		"---\r\nname: x\r\n---\r\n",
		"```bash\nrm -rf /tmp/x\n```\n",
		"~~~\nfence\n~~~\n",
		"[a](b.md) ![c](d.png)\n[def]: e.md\n<https://example.com>\n",
		"---\nname: &a [*a]\n---\n", // aliasing shapes
		"\x00\x01\x02",
		"---\nk: v\nk: v2\nk: v3\n---\n",
		"```",
		"> quote `code` [ref](x.md)\n",
	}
	for _, s := range seeds {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		d := Load("fuzz.md", model.PlatformGeneric, "", data)
		if d == nil {
			t.Fatal("Load returned nil")
		}
		if len(d.LineInfo) != len(d.Lines) {
			t.Fatalf("LineInfo length %d != Lines length %d", len(d.LineInfo), len(d.Lines))
		}
		for _, r := range d.Refs() {
			if r.Line < 1 || r.Line > len(d.Lines) {
				t.Fatalf("ref line %d out of range", r.Line)
			}
			if r.ByteOff < 0 {
				t.Fatalf("ref byte offset %d negative", r.ByteOff)
			}
		}
		for i := range d.Lines {
			_ = d.ContextAt(i+1, 0)
		}
	})
}
