package app

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// `action-paths` stdout is a machine protocol, not human text. Its values are
// filenames the caller then writes to, so they must come back byte for byte:
// escaping a legal path here would silently redirect the action's report to a
// different file. These tests are deliberately separate from the JSON/SARIF
// escaping tests — those are a different protocol with a different rule.

// bidiOverride is U+202E RIGHT-TO-LEFT OVERRIDE. It is a legal filename
// character on NTFS and on POSIX alike, and internal/actionpath accepts it, so
// it must survive the machine channel untouched.
var bidiOverride = string(rune(0x202e))

// escapedBidi is the six characters the *human* sanitizer would produce. It
// must never appear in machine output.
var escapedBidi = string(rune(0x5c)) + "u202e"

func machineWorkspace(t *testing.T) string {
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

// The reported counterexample, asserted directly.
func TestActionPathsKeepsBidiOverrideByteForByte(t *testing.T) {
	ws := machineWorkspace(t)
	rel := "reports/report" + bidiOverride + "gnp.json"

	a, out, errb := newTestApp()
	if code := a.Run([]string{"action-paths", "--workspace", ws, "--path", "pkg", "--output", rel}); code != ExitOK {
		t.Fatalf("exit = %d (stderr: %s)", code, errb.String())
	}
	stdout := out.String()
	if !strings.Contains(stdout, bidiOverride) {
		t.Fatalf("the raw override must survive in machine output: %q", stdout)
	}
	if strings.Contains(stdout, escapedBidi) {
		t.Fatalf("machine output must not carry the human escape %q: %q", escapedBidi, stdout)
	}
	if !strings.Contains(stdout, "report-path="+rel) {
		t.Fatalf("report-path must be exactly the requested value: %q", stdout)
	}
	// And the absolute path line ends with the same filename, unrewritten.
	for _, line := range strings.Split(strings.TrimRight(stdout, "\n"), "\n") {
		if strings.HasPrefix(line, "output=") {
			if !strings.HasSuffix(line, "report"+bidiOverride+"gnp.json") {
				t.Fatalf("output line was rewritten: %q", line)
			}
		}
	}
}

// A round trip over a range of legal, non-line-breaking Unicode.
func TestActionPathsRoundTripsLegalUnicodePaths(t *testing.T) {
	cases := []struct{ name, base string }{
		{"ascii", "report.json"},
		{"bidi override", "report" + bidiOverride + "gnp.json"},
		{"traditional chinese", "報告書.json"},
		{"emoji", "report-🛡️.json"},
		{"combining marks", "réport.json"},
		{"ideographic space", "report　one.json"},
		{"non breaking space", "report one.json"},
		{"zero width joiner", "report‍x.json"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ws := machineWorkspace(t)
			rel := "reports/" + c.base

			a, out, errb := newTestApp()
			if code := a.Run([]string{"action-paths", "--workspace", ws, "--path", "pkg", "--output", rel}); code != ExitOK {
				t.Fatalf("exit = %d (stderr: %s)", code, errb.String())
			}
			var reportPath string
			for _, line := range strings.Split(strings.TrimRight(out.String(), "\n"), "\n") {
				if strings.HasPrefix(line, "report-path=") {
					reportPath = strings.TrimPrefix(line, "report-path=")
				}
			}
			if reportPath != rel {
				t.Fatalf("report-path = %q, want the caller's value %q byte for byte", reportPath, rel)
			}
			// Writing to the value the protocol handed back must land on the
			// file the caller asked for.
			abs := filepath.Join(ws, filepath.FromSlash(reportPath))
			if err := os.WriteFile(abs, []byte("{}"), 0o644); err != nil {
				t.Fatal(err)
			}
			if _, err := os.Stat(filepath.Join(ws, filepath.FromSlash(rel))); err != nil {
				t.Fatalf("the report landed somewhere other than the requested path: %v", err)
			}
		})
	}
}

// Anything that would break the line-based protocol is refused, not rewritten,
// and nothing is written to stdout when it is.
func TestActionPathsRefusesControlCharactersInEveryInput(t *testing.T) {
	cr := string(rune(0x0d))
	lf := string(rune(0x0a))
	nul := string(rune(0x00))

	for _, payload := range []struct{ name, value string }{
		{"carriage return", cr},
		{"line feed", lf},
		{"NUL", nul},
		{"CRLF", cr + lf},
		{"escape", string(rune(0x1b))},
		{"C1 introducer", string(rune(0x9b))},
	} {
		t.Run(payload.name, func(t *testing.T) {
			ws := machineWorkspace(t)
			cases := [][]string{
				{"--workspace", ws + payload.value, "--path", "pkg", "--output", "reports/r.json"},
				{"--workspace", ws, "--path", "pkg" + payload.value, "--output", "reports/r.json"},
				{"--workspace", ws, "--path", "pkg", "--config", ".skillguard.yml" + payload.value, "--output", "reports/r.json"},
				{"--workspace", ws, "--path", "pkg", "--output", "reports/r" + payload.value + ".json"},
			}
			for i, args := range cases {
				a, out, errb := newTestApp()
				if code := a.Run(append([]string{"action-paths"}, args...)); code != ExitError {
					t.Fatalf("case %d: exit = %d, want 2 (stdout: %q)", i, code, out.String())
				}
				if out.Len() != 0 {
					t.Fatalf("case %d: a refused run must print no protocol lines: %q", i, out.String())
				}
				// The refusal is reported, and the payload never reaches the
				// terminal raw. Line terminators the message writes itself are
				// not payload, so the check runs per line.
				for _, line := range strings.Split(strings.TrimRight(errb.String(), lf), lf) {
					for _, raw := range []string{cr, nul, string(rune(0x1b)), string(rune(0x9b))} {
						if strings.Contains(line, raw) {
							t.Fatalf("case %d: stderr carries a raw control character: %q", i, errb.String())
						}
					}
				}
			}
		})
	}
}

// The writer itself: verbatim on the happy path, all-or-nothing on refusal.
func TestMachineWriterIsVerbatimAndAtomic(t *testing.T) {
	var buf bytes.Buffer
	a := &App{Stdout: &buf}
	mw := a.newMachineWriter()
	mw.Line("path", "/ws/pkg"+bidiOverride)
	mw.Line("report-path", "reports/r.json")
	if err := mw.Flush(); err != nil {
		t.Fatalf("flush: %v", err)
	}
	want := "path=/ws/pkg" + bidiOverride + "\nreport-path=reports/r.json\n"
	if buf.String() != want {
		t.Fatalf("got %q, want %q", buf.String(), want)
	}

	buf.Reset()
	mw = a.newMachineWriter()
	mw.Line("path", "/ws/ok")
	mw.Line("output", "bad"+string(rune(0x0a))+"value")
	mw.Line("report-path", "reports/r.json")
	err := mw.Flush()
	if err == nil {
		t.Fatal("a value with a line feed must be refused")
	}
	if buf.Len() != 0 {
		t.Fatalf("nothing may be written when a later value is refused: %q", buf.String())
	}
	if strings.Contains(err.Error(), "bad") {
		t.Fatalf("the error must name the key and code point, not echo the value: %v", err)
	}
	if !strings.Contains(err.Error(), "output") {
		t.Fatalf("the error should name the offending key: %v", err)
	}
}

func TestValidateMachineValueAcceptsLegalPaths(t *testing.T) {
	for _, v := range []string{
		"", "reports/r.json", "報告.json", "a" + bidiOverride + "b",
		"space here.json", "tab-free nbsp.json", "emoji-🛡️.json",
	} {
		if err := validateMachineValue("output", v); err != nil {
			t.Fatalf("validateMachineValue(%q) = %v, want nil", v, err)
		}
	}
	for _, v := range []string{
		"a" + string(rune(0x00)) + "b",
		"a" + string(rune(0x0a)) + "b",
		"a" + string(rune(0x0d)) + "b",
		"a" + string(rune(0x09)) + "b",
		"a" + string(rune(0x1b)) + "b",
		"a" + string(rune(0x7f)) + "b",
		"a" + string(rune(0x85)) + "b",
		"a" + string(rune(0x9b)) + "b",
	} {
		if err := validateMachineValue("output", v); err == nil {
			t.Fatalf("validateMachineValue(%q) must refuse a control character", v)
		}
	}
}
