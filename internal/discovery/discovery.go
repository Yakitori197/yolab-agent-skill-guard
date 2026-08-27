// Package discovery walks the scan root and selects candidate documents while
// enforcing the privacy rules: sensitive files are reported but never read,
// binaries are sniffed rather than trusted by extension, and symlinks that
// leave the root are never followed.
package discovery

import (
	"bytes"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"

	"github.com/Yakitori197/yolab-agent-skill-guard/internal/config"
	"github.com/Yakitori197/yolab-agent-skill-guard/internal/model"
	"github.com/Yakitori197/yolab-agent-skill-guard/internal/platform"
)

// Candidate is a scannable document.
type Candidate struct {
	AbsPath     string
	RelPath     string // slash form, relative to the scan root
	Platform    model.Platform
	PackageRoot string
	Size        int64
}

// Result is the outcome of discovery.
type Result struct {
	Candidates []Candidate
	Skipped    []model.SkippedFile
}

// DefaultExcludedDirs are directory names never entered, at any depth.
var DefaultExcludedDirs = []string{
	".git", "node_modules", "vendor", "dist", "build", "coverage",
	".next", "test-results", "playwright-report",
}

// Skip reason codes (stable strings used in reports).
const (
	ReasonExcludedDir   = "default-excluded-dir"
	ReasonConfigExclude = "config-exclude"
	ReasonNotIncluded   = "not-in-include-list"
	ReasonEnvFile       = "env-file-never-read"
	ReasonKeyMaterial   = "key-material-never-read"
	ReasonDatabase      = "database-file-never-read"
	ReasonArchive       = "archive-never-read"
	ReasonBinaryContent = "binary-content"
	ReasonOversized     = "exceeds-max-file-size"
	ReasonSymlinkEscape = "symlink-outside-root"
	ReasonSymlinkDir    = "symlink-dir-not-followed"
	ReasonUnreadable    = "unreadable"
)

// CaseInsensitiveFS reports whether path comparisons should fold case on the
// current platform.
func CaseInsensitiveFS() bool { return runtime.GOOS == "windows" || runtime.GOOS == "darwin" }

// Walk discovers candidates under rootAbs, applying default exclusions,
// configuration include/exclude patterns, size limits, and content sniffing.
func Walk(rootAbs string, cfg *config.Config) (*Result, error) {
	res := &Result{}
	skillDirs, err := findSkillDirs(rootAbs)
	if err != nil {
		return nil, err
	}
	err = filepath.WalkDir(rootAbs, func(p string, d fs.DirEntry, walkErr error) error {
		if p == rootAbs {
			return nil
		}
		rel := relSlash(rootAbs, p)
		if walkErr != nil {
			res.skip(rel, ReasonUnreadable)
			return nil
		}
		if d.IsDir() {
			if isDefaultExcluded(d.Name()) {
				res.skip(rel+"/", ReasonExcludedDir)
				return filepath.SkipDir
			}
			return nil
		}
		if d.Type()&fs.ModeSymlink != 0 {
			res.handleSymlink(rootAbs, p, rel, d.Name(), cfg, skillDirs)
			return nil
		}
		info, ierr := d.Info()
		if ierr != nil {
			res.skip(rel, ReasonUnreadable)
			return nil
		}
		res.handleFile(p, rel, d.Name(), info.Size(), cfg, skillDirs)
		return nil
	})
	if err != nil {
		return nil, err
	}
	res.finish()
	return res, nil
}

// Single builds a discovery result for one explicitly named file. rootAbs is
// the file's directory; the same sensitivity, size, and binary checks apply.
func Single(rootAbs, name string, cfg *config.Config) (*Result, error) {
	res := &Result{}
	skillDirs := map[string]bool{}
	entries, err := os.ReadDir(rootAbs)
	if err == nil {
		for _, e := range entries {
			if !e.IsDir() && strings.EqualFold(e.Name(), "SKILL.md") {
				skillDirs[""] = true
			}
		}
	}
	abs := filepath.Join(rootAbs, name)
	info, err := os.Lstat(abs)
	if err != nil {
		return nil, err
	}
	rel := filepath.ToSlash(name)
	switch {
	case info.Mode()&os.ModeSymlink != 0:
		// Same containment and sensitivity rules as a walked symlink.
		res.handleSymlink(rootAbs, abs, rel, name, cfg, skillDirs)
	case info.IsDir():
		return nil, fmt.Errorf("%q is a directory, not a file", name)
	default:
		res.handleFile(abs, rel, name, info.Size(), cfg, skillDirs)
	}
	res.finish()
	return res, nil
}

// findSkillDirs locates every directory containing a SKILL.md so package
// roots are known before classification.
func findSkillDirs(rootAbs string) (map[string]bool, error) {
	skillDirs := map[string]bool{}
	err := filepath.WalkDir(rootAbs, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil // unreadable entries are reported in the main pass
		}
		if d.IsDir() {
			if p != rootAbs && isDefaultExcluded(d.Name()) {
				return filepath.SkipDir
			}
			return nil
		}
		if strings.EqualFold(d.Name(), "SKILL.md") {
			rel := relSlash(rootAbs, p)
			dir := ""
			if idx := strings.LastIndex(rel, "/"); idx >= 0 {
				dir = rel[:idx]
			}
			skillDirs[dir] = true
		}
		return nil
	})
	return skillDirs, err
}

func (r *Result) handleSymlink(rootAbs, absPath, rel, name string, cfg *config.Config, skillDirs map[string]bool) {
	real, err := filepath.EvalSymlinks(absPath)
	if err != nil {
		// Broken links and cycles both land here; neither is followed.
		r.skip(rel, ReasonUnreadable)
		return
	}
	inside, err := WithinRootAbs(rootAbs, real)
	if err != nil || !inside {
		r.skip(rel, ReasonSymlinkEscape)
		return
	}
	ri, err := os.Stat(real)
	if err != nil {
		r.skip(rel, ReasonUnreadable)
		return
	}
	if ri.IsDir() {
		r.skip(rel+"/", ReasonSymlinkDir)
		return
	}
	// A link named alias.md may resolve to .env or key material; the
	// sensitivity rules apply to the resolved name as well as the link name.
	if reason, sensitive := sensitiveReason(filepath.Base(real)); sensitive {
		r.skip(rel, reason)
		return
	}
	r.handleFile(absPath, rel, name, ri.Size(), cfg, skillDirs)
}

func (r *Result) handleFile(absPath, rel, name string, size int64, cfg *config.Config, skillDirs map[string]bool) {
	if reason, sensitive := sensitiveReason(name); sensitive {
		r.skip(rel, reason)
		return
	}
	if !isCandidateName(name) {
		return // unrelated file types are ignored silently
	}
	if cfg.ExcludeMatch(rel) {
		r.skip(rel, ReasonConfigExclude)
		return
	}
	if !cfg.IncludeMatch(rel) {
		r.skip(rel, ReasonNotIncluded)
		return
	}
	if size > cfg.MaxFileSize {
		r.skip(rel, ReasonOversized)
		return
	}
	pf, pkgRoot := platform.Classify(rel, skillDirs)
	if !cfg.PlatformEnabled(pf) {
		return
	}
	r.Candidates = append(r.Candidates, Candidate{
		AbsPath: absPath, RelPath: rel, Platform: pf, PackageRoot: pkgRoot, Size: size,
	})
}

func (r *Result) skip(rel, reason string) {
	r.Skipped = append(r.Skipped, model.SkippedFile{Path: rel, Reason: reason})
}

func (r *Result) finish() {
	model.SortSkipped(r.Skipped)
	sort.SliceStable(r.Candidates, func(i, j int) bool {
		return r.Candidates[i].RelPath < r.Candidates[j].RelPath
	})
}

// ReadCandidate performs the one bounded, containment-checked read of a
// discovered candidate and returns either its bytes or a stable skip reason.
//
// Discovery deliberately does not open files, so this is the only place that
// reads content: a single open per file keeps the window between the checks and
// the read as small as the platform allows. The remaining TOCTOU exposure is
// documented in docs/file-discovery.md — an attacker who can rewrite the tree
// mid-scan can still swap a file between Lstat and open. Everything that can be
// decided after the handle exists (regular-file check, size, binary content) is
// decided from the opened handle rather than from the earlier stat.
func ReadCandidate(rootAbs string, c Candidate, maxSize int64) (content []byte, skipReason string) {
	info, err := os.Lstat(c.AbsPath)
	if err != nil {
		return nil, ReasonUnreadable
	}
	target := c.AbsPath
	if info.Mode()&os.ModeSymlink != 0 {
		target, err = filepath.EvalSymlinks(c.AbsPath)
		if err != nil {
			return nil, ReasonUnreadable
		}
		inside, cerr := WithinRootAbs(rootAbs, target)
		if cerr != nil || !inside {
			return nil, ReasonSymlinkEscape
		}
		// A link named alias.md may still point at .env or a private key; the
		// sensitivity rules apply to the resolved name as well as the link name.
		if reason, sensitive := sensitiveReason(filepath.Base(target)); sensitive {
			return nil, reason
		}
	}
	f, err := os.Open(target)
	if err != nil {
		return nil, ReasonUnreadable
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return nil, ReasonUnreadable
	}
	if !fi.Mode().IsRegular() {
		return nil, ReasonUnreadable
	}
	if fi.Size() > maxSize {
		return nil, ReasonOversized
	}
	// One byte past the limit is enough to prove the file outgrew it between
	// the stat and the read, so nothing unbounded is ever held in memory.
	data, err := io.ReadAll(io.LimitReader(f, maxSize+1))
	if err != nil {
		return nil, ReasonUnreadable
	}
	if int64(len(data)) > maxSize {
		return nil, ReasonOversized
	}
	// Binary detection covers every byte actually read, not a fixed prefix.
	if bytes.IndexByte(data, 0) >= 0 {
		return nil, ReasonBinaryContent
	}
	return data, ""
}

func isDefaultExcluded(name string) bool {
	for _, d := range DefaultExcludedDirs {
		if strings.EqualFold(name, d) {
			return true
		}
	}
	return false
}

// sensitiveReason classifies files whose contents must never be read.
// The classification is by name only because opening them at all is what the
// privacy model forbids.
func sensitiveReason(name string) (string, bool) {
	lower := strings.ToLower(name)
	if lower == ".env" || strings.HasPrefix(lower, ".env.") {
		return ReasonEnvFile, true
	}
	switch {
	case hasAnySuffix(lower, ".pem", ".key", ".p12", ".pfx", ".ppk", ".jks", ".keystore"):
		return ReasonKeyMaterial, true
	case hasAnySuffix(lower, ".db", ".sqlite", ".sqlite3", ".mdb"):
		return ReasonDatabase, true
	case hasAnySuffix(lower, ".zip", ".tar", ".gz", ".tgz", ".bz2", ".xz", ".7z", ".rar", ".jar", ".war"):
		return ReasonArchive, true
	}
	return "", false
}

func isCandidateName(name string) bool {
	lower := strings.ToLower(name)
	return strings.HasSuffix(lower, ".md") ||
		strings.HasSuffix(lower, ".mdc") ||
		strings.HasSuffix(lower, ".markdown")
}

func hasAnySuffix(s string, suffixes ...string) bool {
	for _, suf := range suffixes {
		if strings.HasSuffix(s, suf) {
			return true
		}
	}
	return false
}

// WithinRootAbs reports whether candidate (an absolute, symlink-resolved
// path) stays inside rootAbs. On case-insensitive filesystems the comparison
// folds case so that C:\ROOT and c:\root are the same boundary.
func WithinRootAbs(rootAbs, candidate string) (bool, error) {
	rootReal, err := filepath.EvalSymlinks(rootAbs)
	if err != nil {
		return false, err
	}
	if relInside(rootReal, candidate) {
		return true, nil
	}
	if CaseInsensitiveFS() && relInside(strings.ToLower(rootReal), strings.ToLower(candidate)) {
		return true, nil
	}
	return false, nil
}

func relInside(root, candidate string) bool {
	rel, err := filepath.Rel(root, candidate)
	if err != nil {
		return false
	}
	rel = filepath.ToSlash(rel)
	return rel != ".." && !strings.HasPrefix(rel, "../")
}

func relSlash(rootAbs, p string) string {
	rel, err := filepath.Rel(rootAbs, p)
	if err != nil {
		return filepath.ToSlash(filepath.Base(p))
	}
	return filepath.ToSlash(rel)
}
