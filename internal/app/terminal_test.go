package app

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// End-to-end counterparts to internal/termsafe and internal/report/text: the
// real CLI, driven through App.Run, must never write a raw control sequence to
// stdout or stderr, whatever the user typed or whatever is on disk.
//
// Control characters are built from code points rather than pasted in, so this
// source file stays safe to open in a terminal.

const (
	escByte = "\x1b"
	// Control characters and newlines are illegal in a Windows filename, so a
	// name built from them only exercises the failure branch there.
	hostileName = "ev\x1bil\nfake: line"
	// U+202E RIGHT-TO-LEFT OVERRIDE is a *legal* filename character on NTFS and
	// on POSIX alike, and a terminal acts on it, so a name built from it reaches
	// the success branch on every platform.
	bidiName = "report" + string(rune(0x202e)) + "gnp.json"
	// The six characters strconv.Quote emits for that override.
	quotedBidi = string(rune(0x5c)) + "u202e"
	// The four characters it emits for ESC.
	quotedESC = string(rune(0x5c)) + "x1b"
)

// terminalActionable lists sequences that must never reach a terminal raw.
func terminalActionable() []string {
	return []string{
		string(rune(0x1b)),   // ESC
		string(rune(0x07)),   // BEL
		string(rune(0x0d)),   // CR
		string(rune(0x00)),   // NUL
		string(rune(0x202e)), // RIGHT-TO-LEFT OVERRIDE
		string(rune(0x2028)), // LINE SEPARATOR
	}
}

func assertNoRawEscape(t *testing.T, label, s string) {
	t.Helper()
	for _, bad := range terminalActionable() {
		if strings.Contains(s, bad) {
			t.Fatalf("%s contains a raw terminal-actionable sequence %q: %q", label, bad, s)
		}
	}
}

// The destination the user typed is echoed back on stderr on the failure
// branch, where the write could not happen at all.
func TestHostileOutputPathNeverEscapesToStderr(t *testing.T) {
	root := t.TempDir()
	writeTree(t, root, cleanSkill())
	dest := filepath.Join(t.TempDir(), hostileName)

	a, out, errb := newTestApp()
	code := a.Run([]string{"scan", root, "--format", "json", "--output", dest})
	// Either the write succeeded (POSIX) or it failed (Windows rejects these
	// characters in a filename). Both branches print the path back.
	if code != ExitOK && code != ExitError {
		t.Fatalf("unexpected exit %d", code)
	}
	assertNoRawEscape(t, "stderr", errb.String())
	assertNoRawEscape(t, "stdout", out.String())
	if !strings.Contains(errb.String(), quotedESC) {
		t.Fatalf("the escape should be visible, not silently dropped: %q", errb.String())
	}
}

// The success branch prints "report written to <path>". A filename every
// platform accepts but a terminal still acts on proves that line is escaped
// too, rather than only the error branch being safe.
func TestHostileOutputPathNeverEscapesOnTheSuccessBranch(t *testing.T) {
	root := t.TempDir()
	writeTree(t, root, cleanSkill())
	dest := filepath.Join(t.TempDir(), bidiName)

	a, _, errb := newTestApp()
	if code := a.Run([]string{"scan", root, "--format", "json", "--output", dest}); code != ExitOK {
		t.Fatalf("exit = %d, want 0 (stderr: %q)", code, errb.String())
	}
	if _, err := os.Stat(dest); err != nil {
		t.Fatalf("the report should have been written: %v", err)
	}
	if !strings.Contains(errb.String(), "report written to") {
		t.Fatalf("expected the success line: %q", errb.String())
	}
	assertNoRawEscape(t, "stderr", errb.String())
	if !strings.Contains(errb.String(), quotedBidi) {
		t.Fatalf("the override should be visible, not silently dropped: %q", errb.String())
	}
}

// Leftover argv reaches an error message verbatim.
func TestHostileExtraArgumentNeverEscapesToStderr(t *testing.T) {
	root := t.TempDir()
	writeTree(t, root, cleanSkill())

	wiped := string(rune(0x1b)) + "[2Jwiped"
	title := string(rune(0x1b)) + "]0;title" + string(rune(0x07))

	a, _, errb := newTestApp()
	if code := a.Run([]string{"scan", root, wiped, title}); code != ExitError {
		t.Fatalf("exit = %d, want 2", code)
	}
	assertNoRawEscape(t, "stderr", errb.String())
	if !strings.Contains(errb.String(), "unexpected extra arguments") {
		t.Fatalf("stderr = %q", errb.String())
	}
}

// An unknown command name is echoed back too.
func TestHostileCommandNameNeverEscapesToStderr(t *testing.T) {
	a, _, errb := newTestApp()
	if code := a.Run([]string{string(rune(0x1b)) + "[31mscan"}); code != ExitError {
		t.Fatalf("exit = %d, want 2", code)
	}
	assertNoRawEscape(t, "stderr", errb.String())
}

// The two facts the hostile-filename test rests on, checked with ordinary
// names so they hold on every platform.
//
// Windows cannot create a file whose name contains ESC or a newline, so the
// hostile case below runs on POSIX only. That made it possible for the fixture
// to be wrong in a way nothing caught: an earlier version used a file ending in
// ".env" and expected it to be reported as skipped, but the rule matches a file
// *named* ".env" or starting with ".env.", so the file was silently ignored and
// never reached the report at all. Every assertion then passed vacuously.
func TestHostileFilenameFixturePremises(t *testing.T) {
	root := t.TempDir()
	writeTree(t, root, cleanSkill())
	nl := string(rune(0x0a))
	if err := os.WriteFile(filepath.Join(root, ".env.local"), []byte("SECRET=1"+nl), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "risky.md"), []byte(destructiveDoc()), 0o644); err != nil {
		t.Fatal(err)
	}

	a, out, errb := newTestApp()
	if code := a.Run([]string{"scan", root, "--format", "text", "--no-color"}); code != ExitFindings {
		t.Fatalf("exit = %d, want 1 (stderr: %s)", code, errb.String())
	}
	got := out.String()
	// A name the sensitivity rule really matches is reported as skipped.
	if !strings.Contains(got, ".env.local") || !strings.Contains(got, "env-file-never-read") {
		t.Fatalf("a .env.-prefixed file must appear in the skipped list:%s%s", nl, got)
	}
	// A document with a destructive command really produces a finding, so its
	// path is printed as a header line.
	if !strings.Contains(got, nl+"risky.md"+nl) {
		t.Fatalf("the risky document must appear as a finding path header:%s%s", nl, got)
	}
}

// destructiveDoc is a document that reliably triggers a finding, so a file
// carrying it is guaranteed to appear in the report by path.
func destructiveDoc() string {
	nl := string(rune(0x0a))
	return "# notes" + nl + nl + "```bash" + nl + "git reset --hard origin/main" + nl + "```" + nl
}

// The full pipeline with a hostile filename actually on disk: discovery reads
// the name, it becomes Finding.Path or SkippedFile.Path, and the text report
// must still be inert and structurally intact. Windows forbids these bytes in
// filenames, so the physical case runs on POSIX only; the assertions above and
// the renderer tests cover the same escaping portably.
func TestHostileFilenameOnDiskRendersInert(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows filenames cannot contain ESC or newline; Linux CI runs this case")
	}
	root := t.TempDir()
	writeTree(t, root, cleanSkill())
	esc := string(rune(0x1b))
	nl := string(rune(0x0a))
	quotedNL := string(rune(0x5c)) + "n"

	// A scanned document whose *name* tries to forge a finding line. Its
	// content triggers a real finding, so the name is printed as a path header
	// -- without that the test would assert nothing.
	evilName := "ev" + esc + "[2Kil" + nl + "  1:1  critical  ASG004  forged.md"
	if err := os.WriteFile(filepath.Join(root, evilName), []byte(destructiveDoc()), 0o644); err != nil {
		t.Skipf("this filesystem rejects the hostile filename: %v", err)
	}
	// A name the sensitivity rule matches, so it is reported but never read.
	evilEnvName := ".env." + esc + "[31mweird"
	if err := os.WriteFile(filepath.Join(root, evilEnvName), []byte("SECRET=1"+nl), 0o644); err != nil {
		t.Skipf("this filesystem rejects the hostile filename: %v", err)
	}

	a, out, errb := newTestApp()
	code := a.Run([]string{"scan", root, "--format", "text", "--no-color"})
	if code != ExitOK && code != ExitFindings {
		t.Fatalf("exit = %d (stderr: %s)", code, errb.String())
	}
	got := out.String()

	// Both hostile names must actually be in the output, or everything below
	// would pass without testing anything.
	wantFinding := "ev" + quotedESC + "[2Kil" + quotedNL + "  1:1  critical  ASG004  forged.md"
	if !strings.Contains(got, wantFinding) {
		t.Fatalf("the hostile document name must appear, escaped, as a path header:%s%s", nl, got)
	}
	wantSkipped := ".env." + quotedESC + "[31mweird"
	if !strings.Contains(got, wantSkipped) {
		t.Fatalf("the hostile sensitive name must appear, escaped, in the skipped list:%s%s", nl, got)
	}

	assertNoRawEscape(t, "text report", got)

	lines := strings.Split(strings.TrimRight(got, nl), nl)
	summaries, results := 0, 0
	for _, l := range lines {
		if strings.HasPrefix(l, "summary: ") {
			summaries++
		}
		if strings.HasPrefix(l, "result: ") {
			results++
		}
	}
	if summaries != 1 || results != 1 {
		t.Fatalf("hostile filename disturbed the report structure (summary=%d result=%d):%s%s", summaries, results, nl, got)
	}
	// The forged text stays inside one escaped line: no line of its own.
	for _, l := range lines {
		if strings.HasPrefix(strings.TrimSpace(l), "1:1  critical  ASG004  forged") {
			t.Fatalf("a filename forged a finding line:%s%s", nl, got)
		}
	}
}

// The machine formats keep their own escaping: no terminal escapes are applied
// to them, and the data still round-trips.
func TestMachineFormatsAreNotTerminalEscaped(t *testing.T) {
	root := t.TempDir()
	writeTree(t, root, cleanSkill())
	for _, format := range []string{"json", "sarif"} {
		a, out, errb := newTestApp()
		if code := a.Run([]string{"scan", root, "--format", format}); code != ExitOK {
			t.Fatalf("%s: exit = %d (stderr: %s)", format, code, errb.String())
		}
		if strings.Contains(out.String(), quotedESC) {
			t.Fatalf("%s output must not carry terminal escapes", format)
		}
	}
}
