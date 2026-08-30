package discovery

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Yakitori197/yolab-agent-skill-guard/internal/config"
	"github.com/Yakitori197/yolab-agent-skill-guard/internal/model"
)

func write(t *testing.T, root, rel, content string) {
	t.Helper()
	p := filepath.Join(root, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func relPaths(cands []Candidate) []string {
	var out []string
	for _, c := range cands {
		out = append(out, c.RelPath)
	}
	return out
}

func skipMap(sk []model.SkippedFile) map[string]string {
	m := map[string]string{}
	for _, s := range sk {
		m[s.Path] = s.Reason
	}
	return m
}

func TestWalkBasics(t *testing.T) {
	root := t.TempDir()
	write(t, root, "SKILL.md", "---\nname: x\ndescription: y\n---\nbody\n")
	write(t, root, "references/guide.md", "# guide\n")
	write(t, root, "notes.txt", "not scanned\n")
	write(t, root, ".env", "SECRET=value\n")
	write(t, root, "certs/server.pem", "PEM CONTENT\n")
	write(t, root, "data/app.sqlite3", "not really a db\n")
	write(t, root, "bundle.tar.gz", "not really an archive\n")
	write(t, root, "node_modules/pkg/readme.md", "ignored\n")
	write(t, root, ".git/config.md", "ignored\n")

	res, err := Walk(root, config.Default())
	if err != nil {
		t.Fatal(err)
	}
	got := relPaths(res.Candidates)
	want := []string{"SKILL.md", "references/guide.md"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("candidates = %v, want %v", got, want)
	}
	sk := skipMap(res.Skipped)
	if sk[".env"] != ReasonEnvFile {
		t.Fatalf(".env skip = %q", sk[".env"])
	}
	if sk["certs/server.pem"] != ReasonKeyMaterial {
		t.Fatalf("pem skip = %q", sk["certs/server.pem"])
	}
	if sk["data/app.sqlite3"] != ReasonDatabase {
		t.Fatalf("sqlite skip = %q", sk["data/app.sqlite3"])
	}
	if sk["bundle.tar.gz"] != ReasonArchive {
		t.Fatalf("archive skip = %q", sk["bundle.tar.gz"])
	}
	if sk["node_modules/"] != ReasonExcludedDir {
		t.Fatalf("node_modules skip = %q", sk["node_modules/"])
	}
	if sk[".git/"] != ReasonExcludedDir {
		t.Fatalf(".git skip = %q", sk[".git/"])
	}
	// The plain text file is ignored silently.
	if _, present := sk["notes.txt"]; present {
		t.Fatal("unrelated file types must not clutter the skip list")
	}
}

func TestWalkEnvVariants(t *testing.T) {
	root := t.TempDir()
	write(t, root, ".env.local", "X=1\n")
	write(t, root, ".env.production", "X=1\n")
	write(t, root, "envy.md", "fine\n")
	res, err := Walk(root, config.Default())
	if err != nil {
		t.Fatal(err)
	}
	sk := skipMap(res.Skipped)
	if sk[".env.local"] != ReasonEnvFile || sk[".env.production"] != ReasonEnvFile {
		t.Fatalf("env variants: %v", sk)
	}
	if len(res.Candidates) != 1 || res.Candidates[0].RelPath != "envy.md" {
		t.Fatalf("candidates = %v", relPaths(res.Candidates))
	}
}

func TestWalkOversized(t *testing.T) {
	root := t.TempDir()
	write(t, root, "big.md", strings.Repeat("a", 4096))
	write(t, root, "small.md", "ok\n")
	cfg, err := config.Parse([]byte("version: 1\nmax_file_size: 2048\n"), "t", []string{"ASG001"}, []string{"ASG001"})
	if err != nil {
		t.Fatal(err)
	}
	res, err := Walk(root, cfg)
	if err != nil {
		t.Fatal(err)
	}
	sk := skipMap(res.Skipped)
	if sk["big.md"] != ReasonOversized {
		t.Fatalf("oversized skip = %v", sk)
	}
	if len(res.Candidates) != 1 || res.Candidates[0].RelPath != "small.md" {
		t.Fatalf("candidates = %v", relPaths(res.Candidates))
	}
}

func TestWalkIncludeExclude(t *testing.T) {
	root := t.TempDir()
	write(t, root, "skills/a.md", "x\n")
	write(t, root, "skills/b.md", "x\n")
	write(t, root, "drafts/c.md", "x\n")
	cfg, err := config.Parse([]byte("version: 1\ninclude: [\"skills/**\"]\nexclude: [\"skills/b.md\"]\n"), "t", []string{"ASG001"}, []string{"ASG001"})
	if err != nil {
		t.Fatal(err)
	}
	res, err := Walk(root, cfg)
	if err != nil {
		t.Fatal(err)
	}
	got := relPaths(res.Candidates)
	if len(got) != 1 || got[0] != "skills/a.md" {
		t.Fatalf("candidates = %v", got)
	}
	sk := skipMap(res.Skipped)
	if sk["skills/b.md"] != ReasonConfigExclude {
		t.Fatalf("exclude reason = %v", sk)
	}
	if sk["drafts/c.md"] != ReasonNotIncluded {
		t.Fatalf("include reason = %v", sk)
	}
}

func TestWalkPlatformFilter(t *testing.T) {
	root := t.TempDir()
	write(t, root, "AGENTS.md", "codex\n")
	write(t, root, "README.md", "generic\n")
	cfg, err := config.Parse([]byte("version: 1\nplatforms: [codex]\n"), "t", []string{"ASG001"}, []string{"ASG001"})
	if err != nil {
		t.Fatal(err)
	}
	res, err := Walk(root, cfg)
	if err != nil {
		t.Fatal(err)
	}
	got := relPaths(res.Candidates)
	if len(got) != 1 || got[0] != "AGENTS.md" {
		t.Fatalf("candidates = %v", got)
	}
}

func TestWalkSkillPackageClassification(t *testing.T) {
	root := t.TempDir()
	write(t, root, ".claude/skills/pdf/SKILL.md", "---\nname: pdf\ndescription: d\n---\n")
	write(t, root, ".claude/skills/pdf/steps/one.md", "step\n")
	res, err := Walk(root, config.Default())
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Candidates) != 2 {
		t.Fatalf("candidates = %v", relPaths(res.Candidates))
	}
	for _, c := range res.Candidates {
		if c.Platform != model.PlatformClaude {
			t.Fatalf("platform = %v", c.Platform)
		}
		if c.PackageRoot != ".claude/skills/pdf" {
			t.Fatalf("package root = %q", c.PackageRoot)
		}
	}
}

func TestSingleFile(t *testing.T) {
	root := t.TempDir()
	write(t, root, "SKILL.md", "---\nname: x\ndescription: y\n---\n")
	write(t, root, "other.md", "ignored in single mode\n")
	res, err := Single(root, "SKILL.md", config.Default())
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Candidates) != 1 || res.Candidates[0].RelPath != "SKILL.md" {
		t.Fatalf("candidates = %v", relPaths(res.Candidates))
	}
	if res.Candidates[0].Platform != model.PlatformClaude || res.Candidates[0].PackageRoot != "" {
		t.Fatalf("classification = %+v", res.Candidates[0])
	}
}

func TestSingleFileSensitive(t *testing.T) {
	root := t.TempDir()
	write(t, root, ".env", "SECRET=1\n")
	res, err := Single(root, ".env", config.Default())
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Candidates) != 0 {
		t.Fatal("sensitive single file must not become a candidate")
	}
	if len(res.Skipped) != 1 || res.Skipped[0].Reason != ReasonEnvFile {
		t.Fatalf("skipped = %v", res.Skipped)
	}
}

func TestSingleFileMissing(t *testing.T) {
	root := t.TempDir()
	if _, err := Single(root, "absent.md", config.Default()); err == nil {
		t.Fatal("missing single file must error")
	}
}

func TestSymlinkEscapeNotFollowed(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	write(t, outside, "secret.md", "outside content\n")
	link := filepath.Join(root, "leak.md")
	if err := os.Symlink(filepath.Join(outside, "secret.md"), link); err != nil {
		t.Skipf("cannot create symlinks in this environment: %v", err)
	}
	res, err := Walk(root, config.Default())
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Candidates) != 0 {
		t.Fatalf("escaping symlink must not be scanned: %v", relPaths(res.Candidates))
	}
	sk := skipMap(res.Skipped)
	if sk["leak.md"] != ReasonSymlinkEscape {
		t.Fatalf("skip = %v", sk)
	}
}

func TestSymlinkInsideRootIsScanned(t *testing.T) {
	root := t.TempDir()
	write(t, root, "real/target.md", "content\n")
	link := filepath.Join(root, "alias.md")
	if err := os.Symlink(filepath.Join(root, "real", "target.md"), link); err != nil {
		t.Skipf("cannot create symlinks in this environment: %v", err)
	}
	res, err := Walk(root, config.Default())
	if err != nil {
		t.Fatal(err)
	}
	got := relPaths(res.Candidates)
	if len(got) != 2 {
		t.Fatalf("candidates = %v", got)
	}
}

func TestSymlinkDirNotFollowed(t *testing.T) {
	root := t.TempDir()
	write(t, root, "real/inner.md", "content\n")
	link := filepath.Join(root, "dirlink")
	if err := os.Symlink(filepath.Join(root, "real"), link); err != nil {
		t.Skipf("cannot create symlinks in this environment: %v", err)
	}
	res, err := Walk(root, config.Default())
	if err != nil {
		t.Fatal(err)
	}
	sk := skipMap(res.Skipped)
	if sk["dirlink/"] != ReasonSymlinkDir {
		t.Fatalf("skip = %v", sk)
	}
}

func TestSymlinkCycleReported(t *testing.T) {
	root := t.TempDir()
	a := filepath.Join(root, "a.md")
	b := filepath.Join(root, "b.md")
	if err := os.Symlink(b, a); err != nil {
		t.Skipf("cannot create symlinks in this environment: %v", err)
	}
	if err := os.Symlink(a, b); err != nil {
		t.Skipf("cannot create symlinks in this environment: %v", err)
	}
	res, err := Walk(root, config.Default())
	if err != nil {
		t.Fatal(err)
	}
	sk := skipMap(res.Skipped)
	if sk["a.md"] != ReasonUnreadable || sk["b.md"] != ReasonUnreadable {
		t.Fatalf("cycle skips = %v", sk)
	}
}

func TestWithinRootAbs(t *testing.T) {
	root := t.TempDir()
	sub := filepath.Join(root, "sub")
	if err := os.MkdirAll(sub, 0o755); err != nil {
		t.Fatal(err)
	}
	// WithinRootAbs requires candidate to be symlink-resolved. Temp roots can
	// themselves contain platform aliases (for example /var -> /private/var on
	// macOS), so build every candidate from the resolved root as production
	// callers do.
	rootReal, err := filepath.EvalSymlinks(root)
	if err != nil {
		t.Fatal(err)
	}
	inside, err := WithinRootAbs(root, filepath.Join(rootReal, "sub", "x.md"))
	if err != nil || !inside {
		t.Fatalf("inside = %v, %v", inside, err)
	}
	outside, err := WithinRootAbs(root, filepath.Join(rootReal, "..", "elsewhere"))
	if err != nil {
		t.Fatal(err)
	}
	if outside {
		t.Fatal("parent path must be outside")
	}
	// A differently-cased spelling of the same subdirectory is accepted if and
	// only if the filesystem actually resolves it to that directory. The
	// verdict is compared against os.SameFile rather than against runtime.GOOS,
	// so the assertion holds on case-sensitive and case-insensitive volumes
	// alike, and on the case-sensitive APFS and per-directory-case-sensitive
	// Windows configurations a GOOS guess gets wrong.
	upper := strings.ToUpper(filepath.Join(rootReal, "sub"))
	got, err := WithinRootAbs(root, upper)
	if err != nil {
		got = false
	}
	subInfo, serr := os.Stat(sub)
	if serr != nil {
		t.Fatal(serr)
	}
	upperInfo, uerr := os.Stat(upper)
	wantSameDir := uerr == nil && os.SameFile(subInfo, upperInfo)
	if got != wantSameDir {
		t.Fatalf("upper-case spelling: WithinRootAbs = %v, but it is the same directory = %v", got, wantSameDir)
	}
}

func TestCandidateOrderDeterministic(t *testing.T) {
	root := t.TempDir()
	write(t, root, "z.md", "z\n")
	write(t, root, "a.md", "a\n")
	write(t, root, "m/inner.md", "m\n")
	res, err := Walk(root, config.Default())
	if err != nil {
		t.Fatal(err)
	}
	got := strings.Join(relPaths(res.Candidates), ",")
	if got != "a.md,m/inner.md,z.md" {
		t.Fatalf("order = %s", got)
	}
}

// findCandidate returns the candidate with the given relative path.
func findCandidate(t *testing.T, res *Result, rel string) Candidate {
	t.Helper()
	for _, c := range res.Candidates {
		if c.RelPath == rel {
			return c
		}
	}
	t.Fatalf("candidate %q not found in %v", rel, relPaths(res.Candidates))
	return Candidate{}
}

func TestReadCandidateBinaryContent(t *testing.T) {
	root := t.TempDir()
	// A .md file whose content is binary must be refused by content, not
	// trusted by extension. The NUL byte sits past the first 8 KiB to prove
	// detection covers every byte actually read, not a fixed prefix.
	bin := append([]byte(strings.Repeat("text ", 4000)), 0x00, 0x01)
	if err := os.WriteFile(filepath.Join(root, "fake.md"), bin, 0o644); err != nil {
		t.Fatal(err)
	}
	write(t, root, "real.md", "text\n")
	res, err := Walk(root, config.Default())
	if err != nil {
		t.Fatal(err)
	}
	if _, reason := ReadCandidate(root, findCandidate(t, res, "fake.md"), config.DefaultFileSize); reason != ReasonBinaryContent {
		t.Fatalf("binary read reason = %q, want %q", reason, ReasonBinaryContent)
	}
	content, reason := ReadCandidate(root, findCandidate(t, res, "real.md"), config.DefaultFileSize)
	if reason != "" || string(content) != "text\n" {
		t.Fatalf("text read = %q, %q", content, reason)
	}
}

func TestReadCandidateBounded(t *testing.T) {
	root := t.TempDir()
	write(t, root, "big.md", strings.Repeat("a", 4096))
	res, err := Walk(root, config.Default())
	if err != nil {
		t.Fatal(err)
	}
	cand := findCandidate(t, res, "big.md")
	content, reason := ReadCandidate(root, cand, 1024)
	if reason != ReasonOversized {
		t.Fatalf("reason = %q, want %q", reason, ReasonOversized)
	}
	if content != nil {
		t.Fatal("an oversized file must not return content")
	}
	// Exactly at the limit is allowed, one byte over is not.
	if _, reason := ReadCandidate(root, cand, 4096); reason != "" {
		t.Fatalf("file at the limit must be readable, got %q", reason)
	}
	if _, reason := ReadCandidate(root, cand, 4095); reason != ReasonOversized {
		t.Fatalf("file one byte over the limit must be refused, got %q", reason)
	}
}

func TestReadCandidateMissingFile(t *testing.T) {
	root := t.TempDir()
	_, reason := ReadCandidate(root, Candidate{AbsPath: filepath.Join(root, "gone.md"), RelPath: "gone.md"}, config.DefaultFileSize)
	if reason != ReasonUnreadable {
		t.Fatalf("reason = %q, want %q", reason, ReasonUnreadable)
	}
}

// A symlink named like a document must not become a way to read a file the
// sensitivity rules protect.
func TestSymlinkToSensitiveTargetRefused(t *testing.T) {
	root := t.TempDir()
	write(t, root, ".env", "DB_PASSWORD=fixture-only\n")
	write(t, root, "secrets/key.pem", "not a real key\n")
	write(t, root, "data/app.sqlite3", "not a real database\n")
	links := map[string]string{
		"alias.md": ".env",
		"keys.md":  "secrets/key.pem",
		"dbdoc.md": "data/app.sqlite3",
	}
	for link, target := range links {
		if err := os.Symlink(filepath.Join(root, filepath.FromSlash(target)), filepath.Join(root, link)); err != nil {
			t.Skipf("cannot create symlinks in this environment: %v", err)
		}
	}
	res, err := Walk(root, config.Default())
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range res.Candidates {
		if _, isLink := links[c.RelPath]; isLink {
			t.Fatalf("symlink %q to a protected file became a candidate", c.RelPath)
		}
	}
	sk := skipMap(res.Skipped)
	want := map[string]string{
		"alias.md": ReasonEnvFile,
		"keys.md":  ReasonKeyMaterial,
		"dbdoc.md": ReasonDatabase,
	}
	for link, reason := range want {
		if sk[link] != reason {
			t.Fatalf("skip[%s] = %q, want %q (all: %v)", link, sk[link], reason, sk)
		}
	}
	// Even if such a candidate were constructed directly, the read refuses it.
	if _, reason := ReadCandidate(root, Candidate{AbsPath: filepath.Join(root, "alias.md"), RelPath: "alias.md"}, config.DefaultFileSize); reason != ReasonEnvFile {
		t.Fatalf("direct read reason = %q, want %q", reason, ReasonEnvFile)
	}
}

// ReadCandidate re-checks containment, so a candidate whose link is swapped to
// point outside the root after discovery is still refused.
func TestReadCandidateSymlinkEscapeRefused(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	write(t, outside, "secret.md", "outside content\n")
	link := filepath.Join(root, "alias.md")
	if err := os.Symlink(filepath.Join(outside, "secret.md"), link); err != nil {
		t.Skipf("cannot create symlinks in this environment: %v", err)
	}
	content, reason := ReadCandidate(root, Candidate{AbsPath: link, RelPath: "alias.md"}, config.DefaultFileSize)
	if reason != ReasonSymlinkEscape {
		t.Fatalf("reason = %q, want %q", reason, ReasonSymlinkEscape)
	}
	if content != nil {
		t.Fatal("content outside the root must never be returned")
	}
}

func TestSingleFileSymlinkEscapeRefused(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	write(t, outside, "secret.md", "outside content\n")
	if err := os.Symlink(filepath.Join(outside, "secret.md"), filepath.Join(root, "alias.md")); err != nil {
		t.Skipf("cannot create symlinks in this environment: %v", err)
	}
	res, err := Single(root, "alias.md", config.Default())
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Candidates) != 0 {
		t.Fatalf("escaping symlink must not be scanned in single-file mode: %v", relPaths(res.Candidates))
	}
	if skipMap(res.Skipped)["alias.md"] != ReasonSymlinkEscape {
		t.Fatalf("skipped = %v", res.Skipped)
	}
}

func TestSingleFileRejectsDirectory(t *testing.T) {
	root := t.TempDir()
	write(t, root, "sub/inner.md", "x\n")
	if _, err := Single(root, "sub", config.Default()); err == nil {
		t.Fatal("single-file mode must reject a directory")
	}
}

func TestReadCandidateNonRegularTarget(t *testing.T) {
	root := t.TempDir()
	write(t, root, "sub/inner.md", "x\n")
	// A directory can never be read as a document.
	_, reason := ReadCandidate(root, Candidate{AbsPath: filepath.Join(root, "sub"), RelPath: "sub"}, config.DefaultFileSize)
	if reason != ReasonUnreadable {
		t.Fatalf("reason = %q, want %q", reason, ReasonUnreadable)
	}
}

func TestReadCandidateEmptyFile(t *testing.T) {
	root := t.TempDir()
	write(t, root, "empty.md", "")
	content, reason := ReadCandidate(root, Candidate{AbsPath: filepath.Join(root, "empty.md"), RelPath: "empty.md"}, config.DefaultFileSize)
	if reason != "" || len(content) != 0 {
		t.Fatalf("empty file read = %q, %q", content, reason)
	}
}
