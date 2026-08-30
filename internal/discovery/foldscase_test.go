package discovery

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"
)

// Windows resolves names per directory, so a case-insensitive parent can hold a
// case-sensitive directory. That combination decides whether FoldsCase asks the
// right question, and it cannot be created on a volume that does not support
// the feature — this machine's NTFS refuses `fsutil file setCaseSensitiveInfo`
// outright. So the mixed cases are modelled with a deterministic fake here, and
// the real filesystem is asserted separately below. Neither test consults
// runtime.GOOS, and neither creates, renames or removes a probe entry.

// fakeInfo is the minimum os.FileInfo the probe uses.
type fakeInfo struct {
	name string
	id   int
}

func (f fakeInfo) Name() string       { return f.name }
func (f fakeInfo) Size() int64        { return 0 }
func (f fakeInfo) Mode() fs.FileMode  { return 0 }
func (f fakeInfo) ModTime() time.Time { return time.Time{} }
func (f fakeInfo) IsDir() bool        { return false }
func (f fakeInfo) Sys() any           { return f.id }

// fakeFS models a filesystem where each directory decides for itself whether it
// resolves its entries case-insensitively.
type fakeFS struct {
	folds   map[string]bool           // directory -> resolves case-insensitively
	entries map[string]map[string]int // directory -> exact entry name -> file id
	lstats  []string                  // every path Lstat was asked about
	readDir []string                  // every directory ReadDirNames was asked about
	failDir string                    // ReadDirNames returns an error for this dir
}

func (f *fakeFS) EvalSymlinks(path string) (string, error) { return path, nil }

func (f *fakeFS) ReadDirNames(dir string) ([]string, error) {
	f.readDir = append(f.readDir, dir)
	if dir == f.failDir {
		return nil, errors.New("unreadable")
	}
	e, ok := f.entries[dir]
	if !ok {
		return nil, errors.New("no such directory")
	}
	names := make([]string, 0, len(e))
	for n := range e {
		names = append(names, n)
	}
	sort.Strings(names)
	return names, nil
}

func (f *fakeFS) Lstat(path string) (os.FileInfo, error) {
	f.lstats = append(f.lstats, path)
	dir, base := filepath.Split(path)
	dir = strings.TrimSuffix(dir, string(filepath.Separator))
	e, ok := f.entries[dir]
	if !ok {
		return nil, os.ErrNotExist
	}
	if id, ok := e[base]; ok {
		return fakeInfo{name: base, id: id}, nil
	}
	if f.folds[dir] {
		for name, id := range e {
			if strings.EqualFold(name, base) {
				return fakeInfo{name: name, id: id}, nil
			}
		}
	}
	return nil, os.ErrNotExist
}

func (f *fakeFS) SameFile(a, b os.FileInfo) bool {
	ai, aok := a.Sys().(int)
	bi, bok := b.Sys().(int)
	return aok && bok && ai == bi
}

// mixedFS builds a parent directory and a child directory whose case-resolution
// behaviours are set independently.
func mixedFS(parentFolds, dirFolds bool) (*fakeFS, string) {
	parent := filepath.Join(string(filepath.Separator)+"ws", "parent")
	dir := filepath.Join(parent, "pkg")
	return &fakeFS{
		folds: map[string]bool{parent: parentFolds, dir: dirFolds},
		entries: map[string]map[string]int{
			parent: {"pkg": 1},
			dir:    {"SKILL.md": 2, "notes.md": 3},
		},
	}, dir
}

// The case the old implementation got backwards: it flipped the *directory's
// own* name and looked it up in the parent, so a case-insensitive parent made
// it answer "folds" for a directory that in fact distinguishes its contents.
func TestFoldsCaseIgnoresTheParentsBehaviour(t *testing.T) {
	cases := []struct {
		name        string
		parentFolds bool
		dirFolds    bool
		want        bool
	}{
		{"insensitive parent, sensitive dir", true, false, false},
		{"sensitive parent, insensitive dir", false, true, true},
		{"both insensitive", true, true, true},
		{"both sensitive", false, false, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			fake, dir := mixedFS(c.parentFolds, c.dirFolds)
			if got := foldsCase(fake, dir); got != c.want {
				t.Fatalf("foldsCase = %v, want %v (dir folds = %v, parent folds = %v)",
					got, c.want, c.dirFolds, c.parentFolds)
			}
		})
	}
}

// The probe must look inside dir. A lookup in the parent would be measuring the
// wrong level, whatever answer it happened to produce.
func TestFoldsCaseProbesInsideTheDirectory(t *testing.T) {
	fake, dir := mixedFS(true, false)
	foldsCase(fake, dir)

	if len(fake.lstats) == 0 {
		t.Fatal("the probe made no lookup at all")
	}
	for _, p := range fake.lstats {
		if filepath.Dir(p) != dir {
			t.Fatalf("probe looked outside the directory under test: %q", p)
		}
	}
	if len(fake.readDir) != 1 || fake.readDir[0] != dir {
		t.Fatalf("the directory listed was %v, want exactly [%q]", fake.readDir, dir)
	}
}

// Everything uncertain answers false, the stricter choice.
func TestFoldsCaseFailsClosedWhenUncertain(t *testing.T) {
	dir := filepath.Join(string(filepath.Separator)+"ws", "pkg")

	t.Run("unreadable directory", func(t *testing.T) {
		fake := &fakeFS{
			folds:   map[string]bool{dir: true},
			entries: map[string]map[string]int{dir: {"SKILL.md": 1}},
			failDir: dir,
		}
		if foldsCase(fake, dir) {
			t.Fatal("an unreadable directory must answer false")
		}
	})

	t.Run("empty directory", func(t *testing.T) {
		fake := &fakeFS{
			folds:   map[string]bool{dir: true},
			entries: map[string]map[string]int{dir: {}},
		}
		if foldsCase(fake, dir) {
			t.Fatal("an empty directory carries no evidence and must answer false")
		}
	})

	t.Run("no cased entry", func(t *testing.T) {
		fake := &fakeFS{
			folds:   map[string]bool{dir: true},
			entries: map[string]map[string]int{dir: {"123": 1, "_-.": 2}},
		}
		if foldsCase(fake, dir) {
			t.Fatal("entries with no cased letter cannot answer the question")
		}
	})

	t.Run("both spellings exist as different files", func(t *testing.T) {
		fake := &fakeFS{
			folds:   map[string]bool{dir: false},
			entries: map[string]map[string]int{dir: {"a.md": 1, "A.MD": 2}},
		}
		if foldsCase(fake, dir) {
			t.Fatal("two different files cannot prove the directory folds case")
		}
	})

	t.Run("unresolvable directory", func(t *testing.T) {
		fake := &fakeFS{folds: map[string]bool{}, entries: map[string]map[string]int{}}
		if foldsCase(fake, filepath.Join(dir, "missing")) {
			t.Fatal("a directory that cannot be listed must answer false")
		}
	})
}

// The same question against the real filesystem: whatever this volume does,
// FoldsCase must agree with it — measured inside the directory, never in its
// parent.
func TestFoldsCaseAgreesWithTheRealFilesystem(t *testing.T) {
	dir := mkdirT(t, filepath.Join(realTempDir(t), "Probe"))
	entry := writeT(t, filepath.Join(dir, "Skill.md"), "x\n")

	got := FoldsCase(dir)

	entryInfo, err := os.Lstat(entry)
	if err != nil {
		t.Fatal(err)
	}
	flipped, ok := flipCase(filepath.Base(entry))
	if !ok {
		t.Fatal("the probe entry must contain a cased letter")
	}
	altInfo, aerr := os.Lstat(filepath.Join(dir, flipped))
	want := aerr == nil && os.SameFile(entryInfo, altInfo)

	if got != want {
		t.Fatalf("FoldsCase = %v, but this directory resolves %q to the same file = %v",
			got, flipped, want)
	}
}

// The probe changes nothing on disk.
func TestFoldsCaseIsReadOnly(t *testing.T) {
	dir := mkdirT(t, filepath.Join(realTempDir(t), "pkg"))
	writeT(t, filepath.Join(dir, "Skill.md"), "x\n")
	writeT(t, filepath.Join(dir, "notes.md"), "y\n")

	before := listNames(t, dir)
	FoldsCase(dir)
	FoldsCase(dir)
	after := listNames(t, dir)

	if strings.Join(before, ",") != strings.Join(after, ",") {
		t.Fatalf("the probe changed the directory: %v -> %v", before, after)
	}
}

func listNames(t *testing.T, dir string) []string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		names = append(names, e.Name())
	}
	sort.Strings(names)
	return names
}

func TestFoldsCaseFailsClosedOnMissingDir(t *testing.T) {
	root := realTempDir(t)
	if FoldsCase(filepath.Join(root, "absent")) {
		t.Fatal("an unreadable directory must answer false, the stricter choice")
	}
}

// Two directory entries whose names differ only by case can be hard links to a
// single inode. os.SameFile then reports "same file" for a directory that is
// plainly case-sensitive, because it is holding both spellings at once. The
// exact-name set has to settle this before identity is consulted.
func TestFoldsCaseHardLinkedCaseVariantsAreNotFolding(t *testing.T) {
	dir := filepath.Join(string(filepath.Separator)+"ws", "pkg")
	fake := &fakeFS{
		folds: map[string]bool{dir: false},
		entries: map[string]map[string]int{
			// Same file ID: one inode reached through two names.
			dir: {"Skill.md": 7, "sKILL.MD": 7},
		},
	}
	if foldsCase(fake, dir) {
		t.Fatal("a directory holding both spellings distinguishes them, whatever inode they share")
	}
	// And identity was never even consulted: the decision came from the names.
	for _, p := range fake.lstats {
		if filepath.Base(p) == "sKILL.MD" {
			t.Fatalf("the alternate spelling should not have been stat'ed: %v", fake.lstats)
		}
	}
}

// The same thing on a real filesystem: os.Link gives two case-different names
// for one inode, which only a case-sensitive filesystem can hold.
func TestFoldsCaseRealHardLinkedCaseVariantsAreNotFolding(t *testing.T) {
	dir := mkdirT(t, filepath.Join(realTempDir(t), "pkg"))
	original := writeT(t, filepath.Join(dir, "Skill.md"), "x\n")
	variant := filepath.Join(dir, "sKILL.MD")

	if err := os.Link(original, variant); err != nil {
		t.Skipf("this filesystem cannot hold both spellings as separate entries: %v", err)
	}
	oi, err := os.Lstat(original)
	if err != nil {
		t.Fatal(err)
	}
	vi, err := os.Lstat(variant)
	if err != nil {
		t.Fatal(err)
	}
	if !os.SameFile(oi, vi) {
		t.Fatalf("the two names must share one inode for this test to mean anything")
	}
	// Both names really are present as distinct entries.
	names := listNames(t, dir)
	if strings.Join(names, ",") != "Skill.md,sKILL.MD" {
		t.Skipf("this filesystem merged the two spellings: %v", names)
	}

	if FoldsCase(dir) {
		t.Fatal("a directory holding Skill.md and sKILL.MD side by side is case-sensitive")
	}
}

// A name whose runes report as cased but whose simple mapping does not move
// them yields no alternative spelling at all. Answering "changed" there would
// make foldsCase stat one path twice and let os.SameFile trivially agree.
func TestFlipCaseReportsUnchangedWhenTheMappingDoesNotMove(t *testing.T) {
	cases := []struct {
		name string
		cp   rune
	}{
		// Lowercase, and its uppercase form is the two-letter "SS", so the
		// simple mapping leaves it alone. This one reproduces on the Go
		// toolchain in .tools.
		{"sharp s", 0x00df},
		// Required by the review. Whether it reports as lowercase depends on
		// the Unicode tables the toolchain was built with; either way flipCase
		// must say "unchanged", because the mapping does not move it.
		{"feminine ordinal indicator", 0x00aa},
		{"masculine ordinal indicator", 0x00ba},
		{"latin small letter kra", 0x0138},
		{"latin small letter turned delta", 0x018d},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			in := string(c.cp)
			got, changed := flipCase(in)
			if got != in || changed {
				t.Fatalf("flipCase(U+%04X) = %q,%v want %q,false", c.cp, got, changed, in)
			}
		})
	}
	// Mixed: an unmoving rune next to one that does move still counts as
	// changed, because a genuine alternative spelling exists.
	if got, changed := flipCase(string(rune(0x00df)) + "a"); got != string(rune(0x00df))+"A" || !changed {
		t.Fatalf("flipCase = %q,%v want the ASCII half flipped", got, changed)
	}
}

// A directory whose only cased-looking entry has no alternative spelling must
// fail closed, and must not probe the identical path twice.
func TestFoldsCaseFailsClosedOnUnmappableEntry(t *testing.T) {
	dir := filepath.Join(string(filepath.Separator)+"ws", "pkg")
	for _, cp := range []rune{0x00df, 0x00aa} {
		fake := &fakeFS{
			folds:   map[string]bool{dir: true}, // even a folding directory
			entries: map[string]map[string]int{dir: {string(cp): 1}},
		}
		if foldsCase(fake, dir) {
			t.Fatalf("U+%04X yields no alternative spelling; the answer must be false", cp)
		}
		if len(fake.lstats) != 0 {
			t.Fatalf("U+%04X: no lookup should happen at all, got %v", cp, fake.lstats)
		}
	}
}
