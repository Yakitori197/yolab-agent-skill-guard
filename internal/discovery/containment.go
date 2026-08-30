package discovery

import (
	"errors"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"unicode"
)

// maxPathWalk bounds every ancestor walk in this file. Real paths are far
// shallower; the bound only exists so a pathological or hostile path cannot
// turn a containment check into an unbounded loop.
const maxPathWalk = 512

// errUnprovable is returned when containment cannot be established from what
// the filesystem is willing to tell us. Callers treat any error as "outside".
var errUnprovable = errors.New("containment could not be proven from the filesystem")

// WithinRootAbs reports whether candidate (an absolute path, normally already
// symlink-resolved by the caller) stays inside rootAbs.
//
// Security assumptions, stated explicitly because this is the function every
// escape check depends on:
//
//   - The answer is never derived from runtime.GOOS, and never from comparing
//     lowercased paths. A case-only sibling such as /tmp/PKG is a *different*
//     directory on a case-sensitive filesystem, and lowercasing would authorize
//     it against the root /tmp/pkg. Case semantics are a property of the
//     filesystem holding the path, not of the operating system.
//   - Two identical absolute canonical path strings denote the same directory
//     on every filesystem, so an exact prefix match is a sound fast path: it
//     can only ever under-approximate containment, never grant it wrongly.
//   - Anything the fast path does not settle is decided by filesystem
//     identity. os.SameFile compares device+inode on Unix and volume serial
//     number + file index on Windows, so it recognises the same directory
//     spelled with different case on a case-insensitive volume, and refuses
//     two genuinely distinct directories whose names differ only by case.
//   - Identity is unavailable on a few filesystems (some network and FAT
//     volumes report no stable file id). Every such failure, and every stat
//     or symlink-resolution error, returns an error and is therefore treated
//     as "outside": the check fails closed.
//   - candidate need not exist. Its nearest existing ancestor is what gets
//     proven, and the not-yet-existing tail is accepted only when it contains
//     no upward traversal, so it cannot climb back out of a contained parent.
//   - This does not close the TOCTOU window documented in
//     docs/file-discovery.md. The tree can still be rewritten between this
//     check and a later open; the check is about what the path denotes now.
func WithinRootAbs(rootAbs, candidate string) (bool, error) {
	rootReal, err := filepath.EvalSymlinks(rootAbs)
	if err != nil {
		return false, err
	}
	rootReal = filepath.Clean(rootReal)
	cand := filepath.Clean(candidate)
	if !filepath.IsAbs(cand) {
		return false, errUnprovable
	}
	// Sound fast path: byte-identical canonical prefix.
	if cand == rootReal || strings.HasPrefix(cand, withTrailingSeparator(rootReal)) {
		return true, nil
	}
	rootInfo, err := os.Stat(rootReal)
	if err != nil {
		return false, err
	}
	anchor, remaining, err := nearestExistingAncestor(cand)
	if err != nil {
		return false, err
	}
	for _, seg := range remaining {
		// Clean already collapsed traversal it could resolve; anything left
		// climbs above the anchor and must not be extended from it.
		if seg == ".." {
			return false, nil
		}
	}
	anchorReal, err := filepath.EvalSymlinks(anchor)
	if err != nil {
		return false, err
	}
	return hasAncestorSameAs(anchorReal, rootInfo)
}

// hasAncestorSameAs reports whether start, or any of its ancestors, is the
// same directory as want. A stat failure anywhere in the chain is an error,
// so an unreadable ancestor can never be silently treated as contained.
func hasAncestorSameAs(start string, want os.FileInfo) (bool, error) {
	cur := start
	for i := 0; i < maxPathWalk; i++ {
		info, err := os.Stat(cur)
		if err != nil {
			return false, err
		}
		if os.SameFile(info, want) {
			return true, nil
		}
		parent := filepath.Dir(cur)
		if parent == cur {
			return false, nil // reached the volume root without meeting want
		}
		cur = parent
	}
	return false, errUnprovable
}

// nearestExistingAncestor returns the deepest existing prefix of p together
// with the path segments below it that do not exist yet, outermost first.
// A path whose components cannot be examined at all yields an error rather
// than a guess.
func nearestExistingAncestor(p string) (anchor string, remaining []string, err error) {
	cur := p
	for i := 0; i < maxPathWalk; i++ {
		if _, lerr := os.Lstat(cur); lerr == nil {
			return cur, remaining, nil
		} else if !os.IsNotExist(lerr) {
			// Permission or I/O trouble: refuse rather than assume.
			return "", nil, lerr
		}
		parent := filepath.Dir(cur)
		if parent == cur {
			return "", nil, errUnprovable
		}
		remaining = append([]string{filepath.Base(cur)}, remaining...)
		cur = parent
	}
	return "", nil, errUnprovable
}

// withTrailingSeparator appends the platform separator unless dir already ends
// with one, so a volume root such as `C:\` or `/` is not doubled.
func withTrailingSeparator(dir string) string {
	if dir == "" {
		return dir
	}
	if os.IsPathSeparator(dir[len(dir)-1]) {
		return dir
	}
	return dir + string(filepath.Separator)
}

// dirProbe is the read-only slice of filesystem behaviour FoldsCase needs.
//
// It is an interface for one reason: Windows resolves names per directory, so a
// parent and the directory inside it can disagree, and that combination cannot
// be created on a volume that does not support the feature. A deterministic
// fake can model it; production always uses the real filesystem through
// osDirProbe.
type dirProbe interface {
	// EvalSymlinks canonicalizes a path.
	EvalSymlinks(path string) (string, error)
	// ReadDirNames returns the entry names directly inside dir.
	ReadDirNames(dir string) ([]string, error)
	// Lstat stats a path without following a final symlink.
	Lstat(path string) (os.FileInfo, error)
	// SameFile reports filesystem identity.
	SameFile(a, b os.FileInfo) bool
}

// osDirProbe is the real, read-only filesystem.
type osDirProbe struct{}

func (osDirProbe) EvalSymlinks(path string) (string, error) { return filepath.EvalSymlinks(path) }

func (osDirProbe) ReadDirNames(dir string) ([]string, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		names = append(names, e.Name())
	}
	return names, nil
}

func (osDirProbe) Lstat(path string) (os.FileInfo, error) { return os.Lstat(path) }

func (osDirProbe) SameFile(a, b os.FileInfo) bool { return os.SameFile(a, b) }

// FoldsCase reports whether dir resolves the names *inside it*
// case-insensitively.
//
// The question is deliberately about dir's own contents, not about how dir's
// parent spells dir. Windows case sensitivity is a per-directory attribute, so
// a case-insensitive parent can hold a case-sensitive directory and the two
// answers differ; asking the parent measures the wrong level and gets that
// combination backwards. macOS is the same story one volume up: it ships both
// case-insensitive and case-sensitive APFS. runtime.GOOS is not evidence about
// either, and is not consulted.
//
// The probe is read-only, as the whole scanner must be. Nothing is created,
// renamed or removed: it lists dir, takes the first entry whose name contains a
// cased letter, re-spells that name with its case flipped, and asks whether the
// flipped spelling resolves — inside dir — to the very same file. A spelling
// that does not resolve, or that resolves to a different file, proves the
// directory distinguishes names.
//
// Every uncertain outcome answers false, the stricter of the two: an unreadable
// directory, an unreadable entry, or no entry carrying a cased letter at all
// (an empty directory included).
//
// Scope, stated plainly: this describes dir itself. Because Windows allows the
// attribute to differ per directory, a nested directory under the same scan
// root may resolve names differently, and this single answer does not model
// that. It is used only for reporting — which reference paths count as leaving
// a skill package, and how missing references are de-duplicated (see
// internal/rules) — and never to authorize a filesystem access. Authorization
// is WithinRootAbs's job, and WithinRootAbs does not fold case at all.
func FoldsCase(dir string) bool { return foldsCase(osDirProbe{}, dir) }

func foldsCase(p dirProbe, dir string) bool {
	real, err := p.EvalSymlinks(dir)
	if err != nil {
		return false
	}
	names, err := p.ReadDirNames(real)
	if err != nil {
		return false
	}
	// os.ReadDir is already sorted; sorting again makes the choice of probe
	// entry deterministic whatever a dirProbe implementation returns.
	sort.Strings(names)

	// The exact spellings this directory actually holds. Membership is byte
	// equality, never strings.EqualFold: the whole question is whether this
	// directory treats two spellings as one name, so a case-insensitive
	// comparison would assume the answer.
	exact := make(map[string]bool, len(names))
	for _, name := range names {
		exact[name] = true
	}

	for _, name := range names {
		flipped, ok := flipCase(name)
		if !ok {
			continue // no cased letter: this entry cannot answer the question
		}
		if exact[flipped] {
			// Both spellings exist as separate directory entries, so this
			// directory plainly keeps them apart. This is checked before any
			// identity comparison on purpose: on a case-sensitive filesystem
			// "Skill.md" and "sKILL.MD" can be hard links to one inode, and
			// os.SameFile would then answer "same file" for a directory that
			// is not folding case at all.
			return false
		}
		original, oerr := p.Lstat(filepath.Join(real, name))
		if oerr != nil {
			return false
		}
		alternate, aerr := p.Lstat(filepath.Join(real, flipped))
		if aerr != nil {
			return false // the other spelling is not this entry
		}
		return p.SameFile(original, alternate)
	}
	return false
}

// flipCase swaps the case of every cased letter in name and reports whether
// the result actually differs from the input.
//
// "Actually" carries the weight. unicode.IsLower reporting true does not mean
// the simple uppercase mapping produces a different rune: U+00DF LATIN SMALL
// LETTER SHARP S is lowercase and maps to itself, because its uppercase form
// is the two-letter "SS" — a special casing, not a simple one. Go versions
// whose tables classify U+00AA FEMININE ORDINAL INDICATOR as lowercase behave
// the same way. Reporting changed=true for such a name would hand foldsCase an
// "alternative spelling" identical to the original, it would Lstat one path
// twice, and os.SameFile would trivially say yes — turning a case-sensitive
// directory into a case-folding verdict.
//
// So the per-rune flag only rises when the mapping moved the rune, and the
// whole string is compared as a final check.
func flipCase(name string) (string, bool) {
	var b strings.Builder
	b.Grow(len(name))
	changed := false
	for _, r := range name {
		mapped := r
		switch {
		case unicode.IsUpper(r):
			mapped = unicode.ToLower(r)
		case unicode.IsLower(r):
			mapped = unicode.ToUpper(r)
		}
		if mapped != r {
			changed = true
		}
		b.WriteRune(mapped)
	}
	flipped := b.String()
	if !changed || flipped == name {
		return name, false
	}
	return flipped, true
}
