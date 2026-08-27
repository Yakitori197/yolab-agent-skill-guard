package app

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func hashOf(t *testing.T, p string) string {
	t.Helper()
	data, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// The write layer, not just the pre-flight validation, refuses to replace an
// existing file: the check and the write are one O_EXCL open, so a file that
// appears between validation and writing is still not truncated.
func TestNoClobberRefusesExistingOutput(t *testing.T) {
	root := t.TempDir()
	writeTree(t, root, cleanSkill())
	targets := map[string]string{
		"package.json": "{\n  \"name\": \"sentinel\"\n}\n",
		"LICENSE":      "MIT sentinel\n",
		"Makefile":     "all:\n\techo sentinel\n",
		"Dockerfile":   "FROM scratch\n",
		"Procfile":     "web: sentinel\n",
		"report.sarif": "{\"sentinel\":true}\n",
		"report.json":  "{\"sentinel\":1}\n",
		"notes":        "extensionless sentinel\n",
	}
	out := t.TempDir()
	for name, content := range targets {
		if err := os.WriteFile(filepath.Join(out, name), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	for name := range targets {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(out, name)
			before := hashOf(t, path)
			a, _, errb := newTestApp()
			code := a.Run([]string{"scan", root, "--format", "json", "--no-clobber", "--output", path})
			if code != ExitError {
				t.Fatalf("exit = %d, want 2", code)
			}
			if !strings.Contains(errb.String(), "refusing to overwrite") {
				t.Fatalf("stderr = %s", errb.String())
			}
			if after := hashOf(t, path); after != before {
				t.Fatalf("%s was modified by a refused run (%s -> %s)", name, before, after)
			}
		})
	}
}

// A hard link is another name for an existing file; O_EXCL refuses it and the
// linked content stays byte-identical.
func TestNoClobberRefusesHardLink(t *testing.T) {
	root := t.TempDir()
	writeTree(t, root, cleanSkill())
	out := t.TempDir()
	target := filepath.Join(out, "important.txt")
	if err := os.WriteFile(target, []byte("sentinel payload\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(out, "report.sarif")
	if err := os.Link(target, link); err != nil {
		t.Skipf("cannot create hard links in this environment: %v", err)
	}
	before := hashOf(t, target)
	a, _, _ := newTestApp()
	if code := a.Run([]string{"scan", root, "--format", "sarif", "--no-clobber", "--output", link}); code != ExitError {
		t.Fatalf("exit = %d, want 2", code)
	}
	if after := hashOf(t, target); after != before {
		t.Fatalf("hard-linked file changed (%s -> %s)", before, after)
	}
}

func TestNoClobberWritesFreshFile(t *testing.T) {
	root := t.TempDir()
	writeTree(t, root, cleanSkill())
	path := filepath.Join(t.TempDir(), "fresh.json")
	a, _, errb := newTestApp()
	if code := a.Run([]string{"scan", root, "--format", "json", "--no-clobber", "--output", path}); code != ExitOK {
		t.Fatalf("exit = %d (stderr: %s)", code, errb.String())
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("report not written: %v", err)
	}
}

// Without the flag the plain CLI keeps its ordinary overwrite behavior, so a
// re-run into the same report file still works.
func TestWithoutNoClobberOverwriteStillWorks(t *testing.T) {
	root := t.TempDir()
	writeTree(t, root, cleanSkill())
	path := filepath.Join(t.TempDir(), "report.json")
	if err := os.WriteFile(path, []byte("stale\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	a, _, errb := newTestApp()
	if code := a.Run([]string{"scan", root, "--format", "json", "--output", path}); code != ExitOK {
		t.Fatalf("exit = %d (stderr: %s)", code, errb.String())
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), "stale") {
		t.Fatal("the report should have replaced the previous file")
	}
}
