package pathsafe

import "testing"

func TestToSlash(t *testing.T) {
	if got := ToSlash(`a\b\c`); got != "a/b/c" {
		t.Fatalf("ToSlash = %q", got)
	}
	if got := ToSlash("a/b"); got != "a/b" {
		t.Fatalf("ToSlash identity = %q", got)
	}
}

func TestPercentDecode(t *testing.T) {
	cases := []struct {
		in      string
		want    string
		changed bool
	}{
		{"plain.md", "plain.md", false},
		{"%2e%2e/secret.md", "../secret.md", true},
		{"a%20b.md", "a b.md", true},
		{"bad%zz", "bad%zz", false}, // undecodable stays put
		{"%2E%2E%2Fx", "../x", true},
	}
	for _, c := range cases {
		got, changed := PercentDecode(c.in)
		if got != c.want || changed != c.changed {
			t.Errorf("PercentDecode(%q) = %q,%v want %q,%v", c.in, got, changed, c.want, c.changed)
		}
	}
}

func TestIsExternal(t *testing.T) {
	external := []string{"https://example.com/x", "http://e.com", "mailto:a@example.com", "data:text/plain;base64,AA==", "vscode://file"}
	for _, s := range external {
		if !IsExternal(s) {
			t.Errorf("IsExternal(%q) = false, want true", s)
		}
	}
	internal := []string{"C:/x/y.md", "c:\\x", "docs/a.md", "./a.md", "../a.md", "#anchor"}
	for _, s := range internal {
		if IsExternal(s) {
			t.Errorf("IsExternal(%q) = true, want false", s)
		}
	}
}

func TestIsAbsoluteLike(t *testing.T) {
	abs := []string{`C:\x\y.md`, "C:/x", `\\server\share\f.md`, "//server/share", "/etc/passwd", `\windows\x`, "~", "~/notes.md", `~\notes.md`}
	for _, s := range abs {
		if !IsAbsoluteLike(s) {
			t.Errorf("IsAbsoluteLike(%q) = false, want true", s)
		}
	}
	rel := []string{"a.md", "./a.md", "../a.md", "docs/a.md", "a~b.md"}
	for _, s := range rel {
		if IsAbsoluteLike(s) {
			t.Errorf("IsAbsoluteLike(%q) = true, want false", s)
		}
	}
}

func TestResolveWithin(t *testing.T) {
	cases := []struct {
		base, target string
		want         string
		escaped      bool
	}{
		{"", "a.md", "a.md", false},
		{"docs", "a.md", "docs/a.md", false},
		{"docs", "../a.md", "a.md", false},
		{"docs", "../../a.md", "../a.md", true},
		{"", "../x.md", "../x.md", true},
		{"", "..", "..", true},
		{"a/b", `..\..\c.md`, "c.md", false},
		{"a/b", `..\..\..\c.md`, "../c.md", true},
		{"docs", "./sub/./x.md", "docs/sub/x.md", false},
		{"docs", "sub/../x.md", "docs/x.md", false},
		{"", ".", "", false},
	}
	for _, c := range cases {
		got, escaped := ResolveWithin(c.base, c.target)
		if got != c.want || escaped != c.escaped {
			t.Errorf("ResolveWithin(%q,%q) = %q,%v want %q,%v", c.base, c.target, got, escaped, c.want, c.escaped)
		}
	}
}

func TestWithinDir(t *testing.T) {
	cases := []struct {
		dir, rel string
		fold     bool
		want     bool
	}{
		{"", "anything.md", false, true},
		{".", "anything.md", false, true},
		{"pkg", "pkg/a.md", false, true},
		{"pkg", "pkg", false, true},
		{"pkg", "pkgx/a.md", false, false},
		{"pkg", "other/a.md", false, false},
		{"PKG", "pkg/a.md", false, false},
		{"PKG", "pkg/a.md", true, true},
		{"a/b", "a/b/c/d.md", false, true},
		{"a/b", "a/c/d.md", false, false},
	}
	for _, c := range cases {
		if got := WithinDir(c.dir, c.rel, c.fold); got != c.want {
			t.Errorf("WithinDir(%q,%q,fold=%v) = %v, want %v", c.dir, c.rel, c.fold, got, c.want)
		}
	}
}

func TestHasDotDot(t *testing.T) {
	yes := []string{"..", "../a", `..\a`, "a/../../b"}
	for _, s := range yes {
		if !HasDotDot(s) {
			t.Errorf("HasDotDot(%q) = false, want true", s)
		}
	}
	no := []string{"a", "a/b", "a/../b", "./a", ""}
	for _, s := range no {
		if HasDotDot(s) {
			t.Errorf("HasDotDot(%q) = true, want false", s)
		}
	}
}
