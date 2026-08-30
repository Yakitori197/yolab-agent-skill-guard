package termsafe

import (
	"strings"
	"testing"
	"unicode/utf8"
)

// Control and format characters are built from their code points here rather
// than pasted in: the test source itself must stay free of them, or opening
// this file in a terminal would demonstrate the bug instead of testing the fix.
// Expected escapes are spelled out as plain characters, not produced by the
// code under test, so the assertions are independent of the implementation.

func wrap(cp rune) string { return "a" + string(cp) + "b" }

func wrapWant(escape string) string { return "a" + escape + "b" }

// Printable text of any script must survive untouched, so ordinary reports do
// not change and non-Latin output stays readable.
func TestPrintableTextIsUnchanged(t *testing.T) {
	cases := []string{
		"",
		"pkg/SKILL.md",
		"skillguard 0.1.0",
		"Destructive command pattern (git-reset-hard) detected.",
		"繁體中文的檔名與訊息必須保持可讀",
		"日本語・한국어・Ελληνικά",
		"punctuation — · … “quoted” 'single' (parens) [brackets]",
		"spaces stay: a" + string(rune(0x00a0)) + "b" + string(rune(0x3000)) + "c",
		"back\\slash and %percent% and $dollar",
		"replacement char " + string(rune(0xfffd)) + " is ordinary text",
	}
	for _, c := range cases {
		if got := Sanitize(c); got != c {
			t.Fatalf("Sanitize(%q) = %q, want it unchanged", c, got)
		}
	}
}

func TestASCIIControlsBecomeVisibleEscapes(t *testing.T) {
	cases := []struct{ in, want string }{
		{"a\nb", "a\\nb"},
		{"a\rb", "a\\rb"},
		{"a\tb", "a\\tb"},
		{"a\x1bb", "a\\x1bb"},
		{"a\x00b", "a\\x00b"},
		{"a\x07b", "a\\x07b"},
		{"a\x7fb", "a\\x7fb"},
		{"\x1b[31mred\x1b[0m", "\\x1b[31mred\\x1b[0m"},
		{"\x1b]0;window title\x07", "\\x1b]0;window title\\x07"},
		{"line one\nline two\r\n", "line one\\nline two\\r\\n"},
	}
	for _, c := range cases {
		if got := Sanitize(c.in); got != c.want {
			t.Fatalf("Sanitize(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

// C1 controls, the bidirectional overrides and isolates, the zero-width
// characters, and the line and paragraph separators all become visible.
func TestNonASCIIControlAndFormatRunesAreEscaped(t *testing.T) {
	cases := []struct {
		name string
		cp   rune
		want string
	}{
		{"C1 next line", 0x0085, "\\u0085"},
		{"C1 control sequence introducer", 0x009b, "\\u009b"},
		{"soft hyphen", 0x00ad, "\\u00ad"},
		{"arabic letter mark", 0x061c, "\\u061c"},
		{"zero width space", 0x200b, "\\u200b"},
		{"zero width non-joiner", 0x200c, "\\u200c"},
		{"zero width joiner", 0x200d, "\\u200d"},
		{"left-to-right mark", 0x200e, "\\u200e"},
		{"right-to-left mark", 0x200f, "\\u200f"},
		{"left-to-right embedding", 0x202a, "\\u202a"},
		{"right-to-left override", 0x202e, "\\u202e"},
		{"line separator", 0x2028, "\\u2028"},
		{"paragraph separator", 0x2029, "\\u2029"},
		{"word joiner", 0x2060, "\\u2060"},
		{"first strong isolate", 0x2066, "\\u2066"},
		{"pop directional isolate", 0x2069, "\\u2069"},
		{"byte order mark", 0xfeff, "\\ufeff"},
		{"language tag above the BMP", 0xe0001, "\\U000e0001"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := Sanitize(wrap(c.cp)); got != wrapWant(c.want) {
				t.Fatalf("U+%04X: Sanitize = %q, want %q", c.cp, got, wrapWant(c.want))
			}
		})
	}
}

func TestInvalidUTF8IsEscapedByteByByte(t *testing.T) {
	cases := []struct{ in, want string }{
		{"a\xffb", "a\\xffb"},
		{"a\x80b", "a\\x80b"},
		{"\xed\xa0\x80", "\\xed\\xa0\\x80"}, // surrogate half, illegal in UTF-8
		{"good\xc3", "good\\xc3"},           // truncated two-byte sequence
	}
	for _, c := range cases {
		got := Sanitize(c.in)
		if got != c.want {
			t.Fatalf("Sanitize(%q) = %q, want %q", c.in, got, c.want)
		}
		if !utf8.ValidString(got) {
			t.Fatalf("Sanitize(%q) produced invalid UTF-8", c.in)
		}
	}
	// Byte escapes are always 0x80 or above and rune escapes always below it,
	// so the two forms can never be confused for one another.
	if Sanitize("\x7f") == Sanitize("\x80") {
		t.Fatal("a DEL control and a stray high byte must not escape identically")
	}
}

// The whole point: after sanitizing, nothing a terminal acts on is left.
func TestOutputCarriesNoActionableBytes(t *testing.T) {
	rtlOverride := string(rune(0x202e))
	popDirectional := string(rune(0x202c))
	lineSep := string(rune(0x2028))
	hostile := "\x1b[2J\x1b]0;pwn\x07root: /etc\npkg/x.md\r\n  1:1  critical  ASG001  " +
		rtlOverride + "evil" + popDirectional + " forged" + lineSep + "line\x00\xff\x7f"

	got := Sanitize(hostile)
	for _, bad := range []string{"\x1b", "\r", "\n", "\x07", "\x00", "\x7f",
		rtlOverride, popDirectional, lineSep} {
		if strings.Contains(got, bad) {
			t.Fatalf("sanitized output still contains %q: %q", bad, got)
		}
	}
	if !utf8.ValidString(got) {
		t.Fatal("sanitized output must be valid UTF-8")
	}
	// The text stays legible, it is only inert.
	if !strings.Contains(got, "pkg/x.md") || !strings.Contains(got, "ASG001") {
		t.Fatalf("readable content was lost: %q", got)
	}
}

func TestSanitizeIsDeterministicAndIdempotent(t *testing.T) {
	in := "\x1b[31m" + string(rune(0x202e)) + "\xff\n混合中文\t"
	first := Sanitize(in)
	for i := 0; i < 8; i++ {
		if got := Sanitize(in); got != first {
			t.Fatalf("run %d differs: %q vs %q", i, got, first)
		}
	}
	// Sanitizing already-sanitized text changes nothing: every escape it emits
	// is printable ASCII.
	if again := Sanitize(first); again != first {
		t.Fatalf("Sanitize is not idempotent: %q -> %q", first, again)
	}
}

func TestSanitizeAllCopies(t *testing.T) {
	in := []string{"clean", "dir\x1b[0m"}
	out := SanitizeAll(in)
	if in[1] != "dir\x1b[0m" {
		t.Fatal("the input slice must not be modified")
	}
	if out[0] != "clean" || out[1] != "dir\\x1b[0m" {
		t.Fatalf("out = %q", out)
	}
	if len(SanitizeAll(nil)) != 0 {
		t.Fatal("nil input must produce an empty slice")
	}
}

func TestNeedsEscapingMatchesSanitize(t *testing.T) {
	cases := []string{
		"plain", "中文", "with\x1besc", "bad\xffbyte", " ",
		string(rune(0x3000)), string(rune(0x202e)), string(rune(0x2029)),
	}
	for _, c := range cases {
		changed := Sanitize(c) != c
		if needsEscaping(c, false) != changed {
			t.Fatalf("needsEscaping(%q) = %v but Sanitize changed = %v", c, needsEscaping(c, false), changed)
		}
	}
}
