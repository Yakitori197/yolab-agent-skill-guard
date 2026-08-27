package app

import (
	"path/filepath"
	"strings"
	"testing"
)

// leakyFragments returns the pieces of an absolute scan root that must never
// appear in output: the full path, its slash form, and its parent directory.
func leakyFragments(root string) []string {
	slash := filepath.ToSlash(root)
	return []string{root, slash, filepath.ToSlash(filepath.Dir(root))}
}

func assertNoLeak(t *testing.T, label, out, root string) {
	t.Helper()
	for _, frag := range leakyFragments(root) {
		if frag == "" || frag == "." || frag == "/" {
			continue
		}
		if strings.Contains(out, frag) {
			t.Fatalf("%s leaks the local path %q:\n%s", label, frag, out)
		}
	}
}

// Reports are shared artifacts: none of the four formats may carry the local
// directory layout of the machine that produced them.
func TestNoAbsolutePathInAnyFormat(t *testing.T) {
	root := t.TempDir()
	writeTree(t, root, riskySkill())
	for _, format := range []string{"text", "json", "sarif", "html"} {
		t.Run(format, func(t *testing.T) {
			a, out, errb := newTestApp()
			a.Run([]string{"scan", root, "--format", format})
			assertNoLeak(t, format+" stdout", out.String(), root)
			assertNoLeak(t, format+" stderr", errb.String(), root)
		})
	}
}

// The text header shows a placeholder rather than the absolute root, and the
// opt-in flag restores the full path for local debugging.
func TestTextRootRedactedByDefault(t *testing.T) {
	root := t.TempDir()
	writeTree(t, root, cleanSkill())

	a, out, _ := newTestApp()
	a.Run([]string{"scan", root})
	if !strings.Contains(out.String(), "root: "+RedactedRoot) {
		t.Fatalf("expected a redacted root header, got:\n%s", out.String())
	}
	assertNoLeak(t, "default text", out.String(), root)

	a2, out2, _ := newTestApp()
	a2.Run([]string{"scan", root, "--show-paths"})
	if !strings.Contains(out2.String(), filepath.ToSlash(root)) {
		t.Fatalf("--show-paths must print the real root, got:\n%s", out2.String())
	}
}

// A relative root is the user's own wording and stays as typed.
func TestRelativeRootShownAsTyped(t *testing.T) {
	root := t.TempDir()
	writeTree(t, root, map[string]string{"pkg/SKILL.md": "---\nname: x\ndescription: d\n---\n"})
	t.Chdir(root)

	a, out, _ := newTestApp()
	if code := a.Run([]string{"scan", "pkg"}); code != ExitOK {
		t.Fatalf("exit = %d\n%s", code, out.String())
	}
	if !strings.Contains(out.String(), "root: pkg") {
		t.Fatalf("relative root should be echoed as typed:\n%s", out.String())
	}
	assertNoLeak(t, "relative scan", out.String(), root)
}

// Error paths are the easiest place to leak a local layout, so every failing
// invocation is checked too.
func TestErrorMessagesDoNotLeakPaths(t *testing.T) {
	root := t.TempDir()
	writeTree(t, root, cleanSkill())
	cases := [][]string{
		{"scan", filepath.Join(root, "does-not-exist")},
		{"scan", root, "--config", filepath.Join(root, "no-such.yml")},
		{"scan", root, "--format", "json", "--output", filepath.Join(root, "no-dir", "sub", "r.json")},
		{"scan", root, "--format", "json", "--summary", filepath.Join(root, "no-dir", "sub", "s.txt")},
		{"scan", root, "--fail-on", "sometimes"},
	}
	for _, args := range cases {
		a, out, errb := newTestApp()
		code := a.Run(args)
		if code != ExitError {
			t.Fatalf("args %v: exit = %d, want 2", args, code)
		}
		assertNoLeak(t, "stderr for "+strings.Join(args, " "), errb.String(), root)
		assertNoLeak(t, "stdout for "+strings.Join(args, " "), out.String(), root)
	}
}

// A malformed configuration must fail closed without printing where it lives.
func TestConfigErrorDoesNotLeakPath(t *testing.T) {
	root := t.TempDir()
	files := cleanSkill()
	files[".skillguard.yml"] = "version: 1\nunknown_field: true\n"
	writeTree(t, root, files)
	a, _, errb := newTestApp()
	if code := a.Run([]string{"scan", root}); code != ExitError {
		t.Fatalf("exit = %d, want 2", code)
	}
	assertNoLeak(t, "config error", errb.String(), root)
	if !strings.Contains(errb.String(), ".skillguard.yml") {
		t.Fatalf("the error should still name the file: %s", errb.String())
	}
}
