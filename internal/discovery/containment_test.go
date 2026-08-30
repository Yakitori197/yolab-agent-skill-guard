package discovery

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// realTempDir returns a temp directory with every symlink already resolved,
// the way production callers hand paths to WithinRootAbs. macOS temp roots go
// through /var -> /private/var, so skipping this would test the wrong path.
func realTempDir(t *testing.T) string {
	t.Helper()
	real, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return real
}

func mkdirT(t *testing.T, p string) string {
	t.Helper()
	if err := os.MkdirAll(p, 0o755); err != nil {
		t.Fatal(err)
	}
	return p
}

func writeT(t *testing.T, p, content string) string {
	t.Helper()
	mkdirT(t, filepath.Dir(p))
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func symlinkT(t *testing.T, target, link string) {
	t.Helper()
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("cannot create symlinks in this environment: %v", err)
	}
}

func mustWithin(t *testing.T, root, candidate string) bool {
	t.Helper()
	inside, err := WithinRootAbs(root, candidate)
	if err != nil {
		// Every error is "outside" for callers; make that explicit here too.
		return false
	}
	return inside
}

func TestContainmentAcceptsPathsInsideTheRoot(t *testing.T) {
	root := realTempDir(t)
	mkdirT(t, filepath.Join(root, "pkg", "references"))
	file := writeT(t, filepath.Join(root, "pkg", "SKILL.md"), "x\n")

	cases := []string{
		root,
		filepath.Join(root, "pkg"),
		filepath.Join(root, "pkg", "references"),
		file,
		// Not created yet: an output leaf under an existing parent.
		filepath.Join(root, "pkg", "report.sarif"),
	}
	for _, c := range cases {
		if !mustWithin(t, root, c) {
			t.Fatalf("%q must be inside the root", filepath.Base(c))
		}
	}
}

func TestContainmentRejectsPathsOutsideTheRoot(t *testing.T) {
	parent := realTempDir(t)
	root := mkdirT(t, filepath.Join(parent, "root"))
	sibling := writeT(t, filepath.Join(parent, "sibling", "secret.md"), "x\n")

	cases := []string{
		parent,
		filepath.Dir(parent),
		sibling,
		filepath.Join(parent, "sibling"),
		// Traversal that Clean cannot absorb inside the root.
		filepath.Join(root, "..", "sibling", "secret.md"),
		// A sibling whose name merely starts with the root's name.
		mkdirT(t, filepath.Join(parent, "root-extra")),
	}
	for _, c := range cases {
		if mustWithin(t, root, c) {
			t.Fatalf("%q must be outside the root", c)
		}
	}
}

// The regression this whole rewrite exists for: a directory whose name differs
// from the root's only by case is a different directory on a case-sensitive
// filesystem, and lowercasing both paths used to authorize it.
//
// The physical half of the test needs a filesystem that keeps the two names
// apart; where it does not, that half is skipped honestly and the portable
// half still runs: whatever the filesystem does, the verdict must agree with
// filesystem identity, never with string case.
func TestContainmentRejectsCaseOnlySiblingOutsideRoot(t *testing.T) {
	parent := realTempDir(t)
	root := mkdirT(t, filepath.Join(parent, "pkg"))
	rootInfo, err := os.Stat(root)
	if err != nil {
		t.Fatal(err)
	}

	upperName := filepath.Join(parent, "PKG")
	if err := os.Mkdir(upperName, 0o755); err != nil && !os.IsExist(err) {
		t.Fatalf("cannot create the case-only sibling: %v", err)
	}
	upperInfo, err := os.Stat(upperName)
	if err != nil {
		t.Fatal(err)
	}
	distinct := !os.SameFile(rootInfo, upperInfo)

	candidate := filepath.Join(upperName, "payload.md")
	writeT(t, candidate, "x\n")
	got := mustWithin(t, root, candidate)

	// Portable property: containment must equal what the filesystem says.
	if got != !distinct {
		t.Fatalf("PKG/payload.md: WithinRootAbs = %v, but PKG and pkg are the same directory = %v", got, !distinct)
	}
	if !distinct {
		t.Skip("this filesystem folds case, so pkg and PKG are one directory; the identity assertion above still ran")
	}
	if got {
		t.Fatal("a case-only sibling directory must never be treated as inside the root")
	}
	// And the root itself is still fine, so the fix did not fail closed on
	// everything.
	if !mustWithin(t, root, filepath.Join(root, "payload.md")) {
		t.Fatal("the real root content must still be inside")
	}
}

func TestContainmentFollowsSymlinkTargets(t *testing.T) {
	parent := realTempDir(t)
	root := mkdirT(t, filepath.Join(parent, "root"))
	mkdirT(t, filepath.Join(root, "real"))
	writeT(t, filepath.Join(root, "real", "doc.md"), "x\n")
	outside := writeT(t, filepath.Join(parent, "outside", "secret.md"), "x\n")

	symlinkT(t, filepath.Join(root, "real"), filepath.Join(root, "link-in"))
	symlinkT(t, filepath.Join(parent, "outside"), filepath.Join(root, "link-out"))

	inTarget, err := filepath.EvalSymlinks(filepath.Join(root, "link-in", "doc.md"))
	if err != nil {
		t.Fatal(err)
	}
	if !mustWithin(t, root, inTarget) {
		t.Fatal("a symlink resolving inside the root must be accepted")
	}
	outTarget, err := filepath.EvalSymlinks(filepath.Join(root, "link-out", "secret.md"))
	if err != nil {
		t.Fatal(err)
	}
	if mustWithin(t, root, outTarget) {
		t.Fatal("a symlink resolving outside the root must be rejected")
	}
	if mustWithin(t, root, outside) {
		t.Fatal("the outside target itself must be rejected")
	}
}

// A root reached through a symlink is still the same directory: identity, not
// spelling, decides.
func TestContainmentAcceptsSymlinkedRoot(t *testing.T) {
	parent := realTempDir(t)
	root := mkdirT(t, filepath.Join(parent, "real-root"))
	writeT(t, filepath.Join(root, "doc.md"), "x\n")
	alias := filepath.Join(parent, "alias-root")
	symlinkT(t, root, alias)

	if !mustWithin(t, alias, filepath.Join(root, "doc.md")) {
		t.Fatal("a root given through a symlink must contain its own files")
	}
}

func TestContainmentHandlesMissingLeavesAndParents(t *testing.T) {
	root := realTempDir(t)
	mkdirT(t, filepath.Join(root, "reports"))

	// A leaf that does not exist yet, under an existing contained parent.
	if !mustWithin(t, root, filepath.Join(root, "reports", "new.sarif")) {
		t.Fatal("a fresh leaf under an existing parent must be inside")
	}
	// Several missing levels are still inside the root; refusing to *create*
	// them is a separate rule, enforced in internal/actionpath.
	if !mustWithin(t, root, filepath.Join(root, "a", "b", "c.sarif")) {
		t.Fatal("a fresh nested path under the root must be inside")
	}
	// A fresh path outside the root stays outside.
	if mustWithin(t, root, filepath.Join(filepath.Dir(root), "elsewhere", "new.sarif")) {
		t.Fatal("a fresh path outside the root must be outside")
	}
}

func TestContainmentFailsClosedOnBadInput(t *testing.T) {
	root := realTempDir(t)

	if _, err := WithinRootAbs(filepath.Join(root, "does-not-exist"), filepath.Join(root, "x")); err == nil {
		t.Fatal("a missing root must be an error, not a pass")
	}
	inside, err := WithinRootAbs(root, "relative/path.md")
	if err == nil || inside {
		t.Fatal("a relative candidate cannot be proven contained and must fail closed")
	}
}

// The FoldsCase tests live in foldscase_test.go: the question it answers is
// about a directory's own contents, and it needs a deterministic fake to
// model the mixed parent/child case semantics Windows allows.

func TestFlipCase(t *testing.T) {
	cases := []struct {
		in      string
		out     string
		changed bool
	}{
		{"pkg", "PKG", true},
		{"PKG", "pkg", true},
		{"MiXeD", "mIxEd", true},
		{"123", "123", false},
		{"", "", false},
		{"_-.", "_-.", false},
		{"a1", "A1", true},
	}
	for _, c := range cases {
		got, changed := flipCase(c.in)
		if got != c.out || changed != c.changed {
			t.Fatalf("flipCase(%q) = %q,%v want %q,%v", c.in, got, changed, c.out, c.changed)
		}
	}
}

func TestWithTrailingSeparator(t *testing.T) {
	sep := string(filepath.Separator)
	if got := withTrailingSeparator(""); got != "" {
		t.Fatalf("empty = %q", got)
	}
	if got := withTrailingSeparator("dir"); got != "dir"+sep {
		t.Fatalf("dir = %q", got)
	}
	if got := withTrailingSeparator("dir" + sep); got != "dir"+sep {
		t.Fatalf("already separated = %q", got)
	}
}

func TestNearestExistingAncestor(t *testing.T) {
	root := realTempDir(t)
	mkdirT(t, filepath.Join(root, "here"))

	anchor, remaining, err := nearestExistingAncestor(filepath.Join(root, "here", "a", "b.md"))
	if err != nil {
		t.Fatal(err)
	}
	if anchor != filepath.Join(root, "here") {
		t.Fatalf("anchor = %q", anchor)
	}
	if strings.Join(remaining, "/") != "a/b.md" {
		t.Fatalf("remaining = %v", remaining)
	}

	anchor, remaining, err = nearestExistingAncestor(filepath.Join(root, "here"))
	if err != nil || anchor != filepath.Join(root, "here") || len(remaining) != 0 {
		t.Fatalf("existing path: %q %v %v", anchor, remaining, err)
	}
}

// A path on another volume can never be inside the root. Drive letters and UNC
// shares only exist on Windows, so the physical case is skipped elsewhere; the
// portable outside-the-root cases above cover the same property.
func TestContainmentRejectsOtherVolumes(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("drive-letter and UNC paths are a Windows concept")
	}
	root := realTempDir(t)
	vol := filepath.VolumeName(root)
	other := "Z:"
	if strings.EqualFold(vol, "Z:") {
		other = "Y:"
	}
	for _, candidate := range []string{
		other + `\somewhere\report.sarif`,
		`\server\share\report.sarif`,
	} {
		if mustWithin(t, root, candidate) {
			t.Fatalf("%q is on another volume and must be outside the root", candidate)
		}
	}
}

// kelvinSign is U+212A. strings.ToLower folds it to ASCII 'k', but every
// mainstream filesystem keeps the two names apart — which is what makes it a
// portable, physically reproducible instance of the bug this file exists for.
const kelvinSign = "K"

// The pre-Phase-0 implementation authorized any candidate whose *lowercased*
// string sat under the lowercased root. That is not the same question as "is
// this the same directory", and the gap is reachable without a case-sensitive
// filesystem: a directory named U+212A lowercases to "k" while remaining a
// different directory from one named "k".
//
// Old behavior on this exact input: WithinRootAbs returned true, so content in
// a sibling directory was treated as inside the scan root.
func TestContainmentRejectsCaseOnlyUnicodeFoldingSibling(t *testing.T) {
	parent := realTempDir(t)
	root := mkdirT(t, filepath.Join(parent, "k"))
	sibling := filepath.Join(parent, kelvinSign)
	if err := os.Mkdir(sibling, 0o755); err != nil && !os.IsExist(err) {
		t.Skipf("this filesystem cannot hold both names: %v", err)
	}

	rootInfo, err := os.Stat(root)
	if err != nil {
		t.Fatal(err)
	}
	siblingInfo, err := os.Stat(sibling)
	if err != nil {
		t.Fatal(err)
	}
	if os.SameFile(rootInfo, siblingInfo) {
		t.Skip("this filesystem merges U+212A with 'k', so there is no distinct sibling to reject")
	}
	// Sanity: the two names really do collide under lowercasing, which is what
	// the old implementation compared.
	if strings.ToLower(sibling) != strings.ToLower(root) {
		t.Fatalf("the two paths must collide under ToLower for this test to mean anything: %q vs %q",
			strings.ToLower(sibling), strings.ToLower(root))
	}

	payload := writeT(t, filepath.Join(sibling, "payload.md"), "outside content\n")
	if mustWithin(t, root, payload) {
		t.Fatal("a sibling directory that merely lowercases to the root's name is not the root")
	}
	// The real root is unaffected.
	if !mustWithin(t, root, filepath.Join(root, "payload.md")) {
		t.Fatal("the real root content must still be inside")
	}
}
