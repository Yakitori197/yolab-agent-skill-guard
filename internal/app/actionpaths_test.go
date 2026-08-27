package app

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func actionWorkspace(t *testing.T) string {
	t.Helper()
	ws := t.TempDir()
	writeTree(t, ws, map[string]string{
		"pkg/SKILL.md":    "---\nname: x\ndescription: d\n---\n",
		".skillguard.yml": "version: 1\n",
	})
	if err := os.MkdirAll(filepath.Join(ws, "reports"), 0o755); err != nil {
		t.Fatal(err)
	}
	real, err := filepath.EvalSymlinks(ws)
	if err != nil {
		t.Fatal(err)
	}
	return real
}

func TestActionPathsSuccess(t *testing.T) {
	ws := actionWorkspace(t)
	a, out, errb := newTestApp()
	code := a.Run([]string{"action-paths", "--workspace", ws,
		"--path", "pkg", "--config", ".skillguard.yml", "--output", "reports/r.sarif"})
	if code != ExitOK {
		t.Fatalf("exit = %d (stderr: %s)", code, errb.String())
	}
	lines := strings.Split(strings.TrimRight(out.String(), "\n"), "\n")
	if len(lines) != 4 {
		t.Fatalf("expected 4 output lines, got %d:\n%s", len(lines), out.String())
	}
	for i, prefix := range []string{"path=", "config=", "output=", "report-path="} {
		if !strings.HasPrefix(lines[i], prefix) {
			t.Fatalf("line %d = %q, want prefix %q", i, lines[i], prefix)
		}
	}
	if lines[3] != "report-path=reports/r.sarif" {
		t.Fatalf("report-path = %q", lines[3])
	}
}

func TestActionPathsOptionalConfig(t *testing.T) {
	ws := actionWorkspace(t)
	a, out, errb := newTestApp()
	if code := a.Run([]string{"action-paths", "--workspace", ws, "--path", ".", "--output", "reports/r.json"}); code != ExitOK {
		t.Fatalf("exit = %d (stderr: %s)", code, errb.String())
	}
	if !strings.Contains(out.String(), "config=\n") {
		t.Fatalf("an omitted config must produce an empty config line:\n%q", out.String())
	}
}

func TestActionPathsRejections(t *testing.T) {
	ws := actionWorkspace(t)
	cases := []struct {
		name string
		args []string
	}{
		{"traversal path", []string{"--path", "../etc", "--output", "reports/r.sarif"}},
		{"absolute path", []string{"--path", "/etc", "--output", "reports/r.sarif"}},
		{"dash path", []string{"--path", "-rf", "--output", "reports/r.sarif"}},
		{"newline path", []string{"--path", "pkg\nrm", "--output", "reports/r.sarif"}},
		{"missing path", []string{"--path", "nope", "--output", "reports/r.sarif"}},
		{"bad config", []string{"--path", "pkg", "--config", "../evil.yml", "--output", "reports/r.sarif"}},
		{"missing config", []string{"--path", "pkg", "--config", "nope.yml", "--output", "reports/r.sarif"}},
		{"traversal output", []string{"--path", "pkg", "--output", "../escape.sarif"}},
		{"output over source", []string{"--path", "pkg", "--output", "pkg/SKILL.md"}},
		{"output is dir", []string{"--path", "pkg", "--output", "reports"}},
		{"output missing parent", []string{"--path", "pkg", "--output", "missing/r.sarif"}},
		{"output missing nested parents", []string{"--path", "pkg", "--output", "missing/a/b/r.json"}},
		{"output parent is a file", []string{"--path", "pkg", "--output", "pkg/SKILL.md/r.sarif"}},
		{"empty output", []string{"--path", "pkg", "--output", ""}},
		{"output equals input", []string{"--path", "pkg/SKILL.md", "--output", "pkg/SKILL.md"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			a, out, errb := newTestApp()
			args := append([]string{"action-paths", "--workspace", ws}, c.args...)
			if code := a.Run(args); code != ExitError {
				t.Fatalf("exit = %d, want 2 (stdout: %q)", code, out.String())
			}
			if out.Len() != 0 {
				t.Fatalf("a rejected invocation must print nothing to stdout: %q", out.String())
			}
			if strings.Contains(errb.String(), ws) {
				t.Fatalf("error leaks the workspace path: %s", errb.String())
			}
		})
	}
}

// The whole action contract for a missing parent directory: the helper refuses
// the input, the real write refuses it too, and neither step creates the
// directory or the report. The two layers are checked together because the
// earlier bug was exactly a disagreement between them — the helper accepted
// "new-dir/report.sarif" and the O_EXCL write then failed on the missing
// directory.
func TestActionOutputMissingParentRefusedByBothLayers(t *testing.T) {
	ws := actionWorkspace(t)
	const rel = "new-dir/report.sarif"
	abs := filepath.Join(ws, filepath.FromSlash(rel))

	helper, out, errb := newTestApp()
	if code := helper.Run([]string{"action-paths", "--workspace", ws, "--path", "pkg", "--output", rel}); code != ExitError {
		t.Fatalf("helper exit = %d, want 2 (stdout: %q)", code, out.String())
	}
	if out.Len() != 0 {
		t.Fatalf("a rejected invocation must print nothing to stdout: %q", out.String())
	}
	if strings.Contains(errb.String(), ws) {
		t.Fatalf("error leaks the workspace path: %s", errb.String())
	}

	scanner, _, scanErr := newTestApp()
	if code := scanner.Run([]string{"scan", filepath.Join(ws, "pkg"), "--format", "sarif", "--no-clobber", "--output", abs}); code != ExitError {
		t.Fatalf("scan exit = %d, want 2 (stderr: %s)", code, scanErr.String())
	}

	if _, err := os.Lstat(filepath.Join(ws, "new-dir")); err == nil {
		t.Fatal("neither layer may create the missing directory")
	}
	if _, err := os.Lstat(abs); err == nil {
		t.Fatal("no report may be written when the parent directory is missing")
	}
}

func TestActionPathsArgumentErrors(t *testing.T) {
	ws := actionWorkspace(t)
	cases := [][]string{
		{"action-paths", "--workspace", ws, "--path", "pkg", "--output", "reports/r.sarif", "extra"},
		{"action-paths", "--workspace", "", "--path", "pkg", "--output", "reports/r.sarif"},
		{"action-paths", "--bogus"},
	}
	for _, args := range cases {
		a, _, _ := newTestApp()
		if code := a.Run(args); code != ExitError {
			t.Fatalf("args %v: exit = %d, want 2", args, code)
		}
	}
}
