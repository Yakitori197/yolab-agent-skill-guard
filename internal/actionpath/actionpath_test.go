package actionpath

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

func workspace(t *testing.T) string {
	t.Helper()
	ws := t.TempDir()
	mkdir(t, filepath.Join(ws, "pkg"))
	mkdir(t, filepath.Join(ws, "reports"))
	write(t, filepath.Join(ws, "pkg", "SKILL.md"), "---\nname: x\ndescription: d\n---\n")
	write(t, filepath.Join(ws, ".skillguard.yml"), "version: 1\n")
	real, err := filepath.EvalSymlinks(ws)
	if err != nil {
		t.Fatal(err)
	}
	return real
}

func mkdir(t *testing.T, p string) {
	t.Helper()
	if err := os.MkdirAll(p, 0o755); err != nil {
		t.Fatal(err)
	}
}

func write(t *testing.T, p, content string) {
	t.Helper()
	mkdir(t, filepath.Dir(p))
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

// symlinkOrSkip creates a symlink, skipping the test where the OS forbids it
// (unprivileged Windows). Linux CI always exercises these paths.
func symlinkOrSkip(t *testing.T, target, link string) {
	t.Helper()
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("cannot create symlinks in this environment: %v", err)
	}
}

func TestRejectsHostileSyntax(t *testing.T) {
	ws := workspace(t)
	cases := []struct {
		name  string
		value string
		kind  Kind
	}{
		{"parent traversal", "../etc", KindScan},
		{"nested traversal", "pkg/../../outside", KindScan},
		{"any traversal segment", "pkg/../pkg", KindScan},
		{"windows traversal", `pkg\..\..\outside`, KindScan},
		{"posix absolute", "/etc", KindScan},
		{"posix absolute file", "/etc/passwd", KindConfig},
		{"windows drive", `C:\Windows\System32`, KindScan},
		{"windows drive slash", "C:/Windows", KindScan},
		{"unc share", `\\server\share`, KindScan},
		{"unc slash", "//server/share", KindScan},
		{"home relative", "~/secrets", KindScan},
		{"leading dash", "-rf", KindScan},
		{"leading dash flag", "--config=/etc/passwd", KindConfig},
		{"newline", "pkg\nrm -rf /", KindScan},
		{"carriage return", "pkg\rreport", KindOutput},
		{"crlf output injection", "report.sarif\r\nfindings=0", KindOutput},
		{"nul byte", "pkg\x00.md", KindScan},
		{"tab control", "pkg\treport", KindOutput},
		{"del control", "pkg\x7f", KindScan},
		{"empty", "", KindScan},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			res, err := Resolve(ws, c.value, c.kind)
			if err == nil {
				t.Fatalf("value %q was accepted as %s (resolved to a path)", c.value, res.Rel)
			}
			if strings.Contains(err.Error(), ws) {
				t.Fatalf("error message leaks the workspace path: %v", err)
			}
		})
	}
}

func TestAcceptsWorkspacePaths(t *testing.T) {
	ws := workspace(t)
	cases := []struct {
		value string
		kind  Kind
		rel   string
	}{
		{".", KindScan, "."},
		{"pkg", KindScan, "pkg"},
		{"pkg/SKILL.md", KindScan, "pkg/SKILL.md"},
		{"./pkg", KindScan, "pkg"},
		{".skillguard.yml", KindConfig, ".skillguard.yml"},
		{"reports/out.sarif", KindOutput, "reports/out.sarif"},
		{"reports/out.json", KindOutput, "reports/out.json"},
		{"out.html", KindOutput, "out.html"},
	}
	for _, c := range cases {
		t.Run(c.value, func(t *testing.T) {
			res, err := Resolve(ws, c.value, c.kind)
			if err != nil {
				t.Fatalf("value %q rejected: %v", c.value, err)
			}
			if res.Rel != c.rel {
				t.Fatalf("rel = %q, want %q", res.Rel, c.rel)
			}
			if !filepath.IsAbs(res.Abs) {
				t.Fatalf("abs = %q, want an absolute path", res.Abs)
			}
			if strings.ContainsAny(res.Rel, "\r\n\x00") {
				t.Fatalf("rel %q is not a single safe line", res.Rel)
			}
		})
	}
}

func TestMissingInputsRejected(t *testing.T) {
	ws := workspace(t)
	if _, err := Resolve(ws, "pkg/absent.md", KindScan); err == nil {
		t.Fatal("missing scan path must be rejected")
	}
	if _, err := Resolve(ws, "absent.yml", KindConfig); err == nil {
		t.Fatal("missing config must be rejected")
	}
	if _, err := Resolve(ws, "pkg", KindConfig); err == nil {
		t.Fatal("directory config must be rejected")
	}
	if _, err := Resolve("", "pkg", KindScan); err == nil {
		t.Fatal("empty workspace must be rejected")
	}
	if _, err := Resolve(filepath.Join(ws, "absent-workspace"), "pkg", KindScan); err == nil {
		t.Fatal("missing workspace must be rejected")
	}
	if _, err := Resolve(ws, "pkg", Kind("bogus")); err == nil {
		t.Fatal("unknown kind must be rejected")
	}
}

func TestPathSymlinkEscapeRejected(t *testing.T) {
	ws := workspace(t)
	outside := t.TempDir()
	write(t, filepath.Join(outside, "SKILL.md"), "---\nname: x\ndescription: d\n---\n")
	symlinkOrSkip(t, outside, filepath.Join(ws, "escape-dir"))
	if _, err := Resolve(ws, "escape-dir", KindScan); err == nil {
		t.Fatal("symlinked directory leaving the workspace must be rejected")
	}
	symlinkOrSkip(t, filepath.Join(outside, "SKILL.md"), filepath.Join(ws, "escape-file.md"))
	if _, err := Resolve(ws, "escape-file.md", KindScan); err == nil {
		t.Fatal("symlinked file leaving the workspace must be rejected")
	}
}

func TestConfigSymlinkEscapeRejected(t *testing.T) {
	ws := workspace(t)
	outside := t.TempDir()
	write(t, filepath.Join(outside, "evil.yml"), "version: 1\n")
	symlinkOrSkip(t, filepath.Join(outside, "evil.yml"), filepath.Join(ws, "linked.yml"))
	if _, err := Resolve(ws, "linked.yml", KindConfig); err == nil {
		t.Fatal("config symlink leaving the workspace must be rejected")
	}
}

func TestOutputSymlinkEscapeRejected(t *testing.T) {
	ws := workspace(t)
	outside := t.TempDir()

	// A symlinked parent directory must not redirect the report out.
	symlinkOrSkip(t, outside, filepath.Join(ws, "linked-dir"))
	if _, err := Resolve(ws, "linked-dir/report.sarif", KindOutput); err == nil {
		t.Fatal("output through a symlinked directory must be rejected")
	}

	// An existing symlink at the output path itself must not be written through.
	write(t, filepath.Join(outside, "target.sarif"), "{}")
	symlinkOrSkip(t, filepath.Join(outside, "target.sarif"), filepath.Join(ws, "report.sarif"))
	if _, err := Resolve(ws, "report.sarif", KindOutput); err == nil {
		t.Fatal("output that is an existing symlink must be rejected")
	}
}

// sha256Of returns the hash of a file, for proving a rejected run left it
// byte-identical.
func sha256Of(t *testing.T, p string) string {
	t.Helper()
	data, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// No-clobber is unconditional: any existing path is refused, whatever its
// name, extension, or content. There is no allow-list of "safe to overwrite"
// files, because such a list can never be complete.
func TestOutputNeverClobbersAnyExistingPath(t *testing.T) {
	ws := workspace(t)
	existing := map[string]string{
		"package.json":         "{\n  \"name\": \"sentinel\"\n}\n",
		"LICENSE":              "MIT sentinel\n",
		"Makefile":             "all:\n\techo sentinel\n",
		"Dockerfile":           "FROM scratch\n",
		"Procfile":             "web: sentinel\n",
		"reports/report.sarif": "{\"sentinel\":true}\n",
		"reports/report.json":  "{\"sentinel\":1}\n",
		"notes":                "extensionless sentinel\n",
		"pkg/SKILL.md":         "---\nname: x\ndescription: d\n---\n",
	}
	for rel, content := range existing {
		write(t, filepath.Join(ws, filepath.FromSlash(rel)), content)
	}
	// A directory is a path too.
	existingPaths := make([]string, 0, len(existing)+1)
	for rel := range existing {
		existingPaths = append(existingPaths, rel)
	}
	sort.Strings(existingPaths)

	before := map[string]string{}
	for _, rel := range existingPaths {
		before[rel] = sha256Of(t, filepath.Join(ws, filepath.FromSlash(rel)))
	}

	for _, rel := range append(existingPaths, "reports", "pkg") {
		t.Run(rel, func(t *testing.T) {
			if _, err := Resolve(ws, rel, KindOutput); err == nil {
				t.Fatalf("output %q already exists and must be refused", rel)
			}
		})
	}
	for _, rel := range existingPaths {
		if after := sha256Of(t, filepath.Join(ws, filepath.FromSlash(rel))); after != before[rel] {
			t.Fatalf("%s changed during rejected runs (%s -> %s)", rel, before[rel], after)
		}
	}
}

// A hard link is just another name for an existing file, and must be refused
// like any other existing path.
func TestOutputRefusesHardLink(t *testing.T) {
	ws := workspace(t)
	target := filepath.Join(ws, "important.txt")
	write(t, target, "sentinel payload\n")
	link := filepath.Join(ws, "reports", "report.sarif")
	if err := os.MkdirAll(filepath.Dir(link), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(target, link); err != nil {
		t.Skipf("cannot create hard links in this environment: %v", err)
	}
	before := sha256Of(t, target)
	if _, err := Resolve(ws, "reports/report.sarif", KindOutput); err == nil {
		t.Fatal("a hard link to an existing file must be refused")
	}
	if after := sha256Of(t, target); after != before {
		t.Fatalf("hard-linked file changed (%s -> %s)", before, after)
	}
}

// A destination that does not exist yet is accepted as long as its immediate
// parent directory already exists.
func TestOutputAcceptsFreshPaths(t *testing.T) {
	ws := workspace(t)
	// "nested" is created explicitly here, the way a workflow step would:
	// the action itself never creates directories.
	mkdir(t, filepath.Join(ws, "nested"))
	cases := []struct{ rel, why string }{
		{"reports/new.sarif", "reports/ already exists in the workspace"},
		{"fresh.json", "the workspace root always exists"},
		{"nested/report.html", "nested/ was created by the caller before the run"},
	}
	for _, c := range cases {
		t.Run(c.rel, func(t *testing.T) {
			res, err := Resolve(ws, c.rel, KindOutput)
			if err != nil {
				t.Fatalf("fresh output %q rejected (%s): %v", c.rel, c.why, err)
			}
			if res.Rel != c.rel {
				t.Fatalf("rel = %q, want %q", res.Rel, c.rel)
			}
			if _, err := os.Lstat(res.Abs); err == nil {
				t.Fatalf("validating %q must not create the file", c.rel)
			}
		})
	}
}

// The immediate parent must already exist. Walking up to the nearest existing
// ancestor and accepting the gap would promise a write that the O_EXCL open
// cannot perform, and the action must not silently create directories.
func TestOutputRequiresExistingImmediateParent(t *testing.T) {
	ws := workspace(t)
	cases := []string{
		"missing/report.sarif",
		"missing/a/b/report.json",
		"reports/missing/report.sarif",
	}
	for _, rel := range cases {
		t.Run(rel, func(t *testing.T) {
			_, err := Resolve(ws, rel, KindOutput)
			if err == nil {
				t.Fatalf("output %q has no existing parent directory and must be refused", rel)
			}
			if strings.Contains(err.Error(), ws) {
				t.Fatalf("error message leaks the workspace path: %v", err)
			}
		})
	}
	// Nothing above was created by the validation.
	for _, rel := range []string{"missing", "missing/a", "reports/missing"} {
		if _, err := os.Lstat(filepath.Join(ws, filepath.FromSlash(rel))); err == nil {
			t.Fatalf("validation created the directory %q", rel)
		}
	}
}

// A parent path that exists but is a regular file is not a directory to write
// into, and is refused before any open is attempted.
func TestOutputParentMustBeADirectory(t *testing.T) {
	ws := workspace(t)
	write(t, filepath.Join(ws, "notes"), "sentinel\n")
	before := sha256Of(t, filepath.Join(ws, "notes"))
	if _, err := Resolve(ws, "notes/report.sarif", KindOutput); err == nil {
		t.Fatal("a regular file used as a parent directory must be refused")
	}
	if _, err := Resolve(ws, "pkg/SKILL.md/report.sarif", KindOutput); err == nil {
		t.Fatal("a regular file used as a parent directory must be refused")
	}
	if after := sha256Of(t, filepath.Join(ws, "notes")); after != before {
		t.Fatalf("the refused run modified the file (%s -> %s)", before, after)
	}
}

// A symlinked parent directory is resolved: staying inside the workspace is
// acceptable, leaving it is not.
func TestOutputParentSymlinkIsResolved(t *testing.T) {
	ws := workspace(t)
	symlinkOrSkip(t, filepath.Join(ws, "reports"), filepath.Join(ws, "linked-reports"))
	res, err := Resolve(ws, "linked-reports/report.sarif", KindOutput)
	if err != nil {
		t.Fatalf("a parent symlink to a directory inside the workspace is acceptable: %v", err)
	}
	if res.Rel != "reports/report.sarif" {
		t.Fatalf("rel = %q, want the resolved workspace-relative path", res.Rel)
	}

	outside := t.TempDir()
	symlinkOrSkip(t, outside, filepath.Join(ws, "escape-reports"))
	if _, err := Resolve(ws, "escape-reports/report.sarif", KindOutput); err == nil {
		t.Fatal("a parent symlink leaving the workspace must be refused")
	}
	if _, err := os.Lstat(filepath.Join(outside, "report.sarif")); err == nil {
		t.Fatal("the refused run created a file outside the workspace")
	}
}

func TestSameTarget(t *testing.T) {
	ws := workspace(t)
	a, err := Resolve(ws, "pkg/SKILL.md", KindScan)
	if err != nil {
		t.Fatal(err)
	}
	b, err := Resolve(ws, "./pkg/SKILL.md", KindScan)
	if err != nil {
		t.Fatal(err)
	}
	if !SameTarget(a, b) {
		t.Fatal("equivalent paths must compare equal")
	}
	other, err := Resolve(ws, ".skillguard.yml", KindConfig)
	if err != nil {
		t.Fatal(err)
	}
	if SameTarget(a, other) {
		t.Fatal("different paths must not compare equal")
	}
	if SameTarget(Result{}, a) || SameTarget(a, Result{}) {
		t.Fatal("empty results must never match")
	}
}
