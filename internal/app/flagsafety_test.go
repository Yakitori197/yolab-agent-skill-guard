package app

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The flag package prints "flag provided but not defined: -<name>" and then a
// usage block, with <name> copied verbatim from argv. Sending that straight to
// stderr let `skillguard scan --<ESC>[2J` clear the terminal, and no amount of
// %q at individual call sites could have covered it: the text is produced
// inside the standard library.
//
// These tests drive every command that owns a flag set, so a command added
// later cannot quietly lose the protection.

// Sequences a terminal acts on. Built from code points so this source file
// contains none of them.
func actionableRunes() map[string]string {
	return map[string]string{
		string(rune(0x1b)):   "ESC",
		string(rune(0x07)):   "BEL",
		string(rune(0x0d)):   "CR",
		string(rune(0x00)):   "NUL",
		string(rune(0x9b)):   "C1 CSI",
		string(rune(0x202e)): "RIGHT-TO-LEFT OVERRIDE",
		string(rune(0x2028)): "LINE SEPARATOR",
		string(rune(0x2029)): "PARAGRAPH SEPARATOR",
	}
}

// bs is a single backslash, the first character of every escape the sanitizer
// emits. Written as a code point so no escape sequence appears in this file.
var bs = string(rune(0x5c))

func assertStderrInert(t *testing.T, label, stderr string) {
	t.Helper()
	for seq, name := range actionableRunes() {
		if strings.Contains(stderr, seq) {
			t.Fatalf("%s: stderr carries a raw %s: %q", label, name, stderr)
		}
	}
}

// Every command that parses flags, given a flag name that is an ANSI clear
// screen. Nothing may reach stderr raw, and the payload must still be visible.
func TestUnknownFlagNeverReachesTheTerminalRaw(t *testing.T) {
	root := t.TempDir()
	writeTree(t, root, cleanSkill())
	esc := string(rune(0x1b))
	hostile := "--" + esc + "[2J"

	cases := []struct {
		name string
		args []string
	}{
		{"scan", []string{"scan", hostile}},
		// scan parses a second time for flags written after the path, so that
		// branch needs its own case.
		{"scan after path", []string{"scan", root, hostile}},
		{"validate", []string{"validate", hostile}},
		{"validate after path", []string{"validate", root, hostile}},
		{"rules", []string{"rules", hostile}},
		{"explain", []string{"explain", hostile}},
		{"init", []string{"init", hostile}},
		{"version", []string{"version", hostile}},
		{"action-paths", []string{"action-paths", hostile}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			a, out, errb := newTestApp()
			a.Workdir = t.TempDir()
			if code := a.Run(c.args); code != ExitError {
				t.Fatalf("exit = %d, want 2", code)
			}
			assertStderrInert(t, c.name, errb.String())
			assertStderrInert(t, c.name+" (stdout)", out.String())
			// Visible, not silently dropped.
			if !strings.Contains(errb.String(), bs+"x1b[2J") {
				t.Fatalf("%s: the payload must be shown as a visible escape: %q", c.name, errb.String())
			}
		})
	}
}

// The other shapes of hostile flag name.
func TestUnknownFlagShapesAreAllEscaped(t *testing.T) {
	cases := []struct {
		name string
		flag string
		want string
	}{
		{"escape", "--" + string(rune(0x1b)) + "[31m", bs + "x1b[31m"},
		{"bell", "--" + string(rune(0x07)), bs + "x07"},
		{"carriage return", "--x" + string(rune(0x0d)) + "y", bs + "r"},
		{"line feed", "--x" + string(rune(0x0a)) + "y", bs + "n"},
		{"crlf", "--x" + string(rune(0x0d)) + string(rune(0x0a)) + "y", bs + "r" + bs + "n"},
		{"bidi override", "--" + string(rune(0x202e)) + "evil", bs + "u202e"},
		{"C1 introducer", "--" + string(rune(0x9b)) + "2J", bs + "u009b"},
		{"line separator", "--x" + string(rune(0x2028)) + "y", bs + "u2028"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			a, _, errb := newTestApp()
			if code := a.Run([]string{"scan", c.flag}); code != ExitError {
				t.Fatalf("exit = %d, want 2", code)
			}
			assertStderrInert(t, c.name, errb.String())
			if !strings.Contains(errb.String(), c.want) {
				t.Fatalf("%s: expected the visible escape %q in %q", c.name, c.want, errb.String())
			}
		})
	}
}

// A newline in a flag name must not be able to add a line to the diagnostic.
func TestUnknownFlagCannotForgeAnOutputLine(t *testing.T) {
	forged := "--x" + string(rune(0x0a)) + "Usage of scan:" + string(rune(0x0a)) + "  -evil string"
	a, _, errb := newTestApp()
	if code := a.Run([]string{"scan", forged}); code != ExitError {
		t.Fatalf("exit = %d, want 2", code)
	}
	stderr := errb.String()
	assertStderrInert(t, "forged", stderr)

	usageLines := 0
	for _, l := range strings.Split(stderr, string(rune(0x0a))) {
		if strings.HasPrefix(l, "Usage of ") {
			usageLines++
		}
		// The payload may appear inside the (escaped) error line; what it must
		// not do is start a line of its own, which is what a forged usage
		// entry would look like.
		if strings.HasPrefix(strings.TrimSpace(l), "-evil string") {
			t.Fatalf("a flag name forged a usage entry:%s%s", string(rune(0x0a)), stderr)
		}
	}
	if usageLines != 1 {
		t.Fatalf("expected exactly one usage header, got %d:%s%s", usageLines, string(rune(0x0a)), stderr)
	}
	// The injected newlines survive as visible escapes on the error line.
	if !strings.Contains(stderr, bs+"nUsage of scan:"+bs+"n") {
		t.Fatalf("the injected newlines should be escaped in place: %q", stderr)
	}
}

// The protection must not have cost readability: the usage block keeps its own
// newlines and tabs.
func TestUsageStaysReadableAfterAnUnknownFlag(t *testing.T) {
	a, _, errb := newTestApp()
	if code := a.Run([]string{"scan", "--not-a-flag"}); code != ExitError {
		t.Fatalf("exit = %d, want 2", code)
	}
	stderr := errb.String()
	if !strings.Contains(stderr, "flag provided but not defined: -not-a-flag") {
		t.Fatalf("the ordinary error text must stay intact: %q", stderr)
	}
	lines := strings.Split(strings.TrimRight(stderr, string(rune(0x0a))), string(rune(0x0a)))
	if len(lines) < 5 {
		t.Fatalf("the usage block collapsed onto one line: %q", stderr)
	}
	for _, want := range []string{"Usage of scan:", "-format string", "-fail-on string"} {
		if !strings.Contains(stderr, want) {
			t.Fatalf("usage is missing %q:%s%s", want, string(rune(0x0a)), stderr)
		}
	}
	// No escape sequences got introduced into text that never needed any.
	if strings.Contains(stderr, bs+"n") || strings.Contains(stderr, bs+"t") {
		t.Fatalf("the usage block's own layout must not be escaped: %q", stderr)
	}
}

// The top-level usage and the rule table are multi-line blocks too.
func TestTopLevelUsageAndRuleTableKeepTheirLayout(t *testing.T) {
	a, out, errb := newTestApp()
	if code := a.Run(nil); code != ExitError {
		t.Fatalf("exit = %d, want 2", code)
	}
	if n := strings.Count(errb.String(), string(rune(0x0a))); n < 10 {
		t.Fatalf("top-level usage collapsed: %d newlines", n)
	}
	assertStderrInert(t, "top-level usage", errb.String())

	a, out, errb = newTestApp()
	if code := a.Run([]string{"rules"}); code != ExitOK {
		t.Fatalf("rules exit = %d (stderr: %s)", code, errb.String())
	}
	if n := strings.Count(out.String(), string(rune(0x0a))); n < 10 {
		t.Fatalf("rule table collapsed: %d newlines", n)
	}
	if !strings.Contains(out.String(), "ASG001") {
		t.Fatalf("rule table lost content: %q", out.String())
	}
}

// An unknown command name is argv too.
func TestUnknownCommandNameIsEscaped(t *testing.T) {
	a, _, errb := newTestApp()
	if code := a.Run([]string{string(rune(0x1b)) + "[2Jscan"}); code != ExitError {
		t.Fatalf("exit = %d, want 2", code)
	}
	assertStderrInert(t, "unknown command", errb.String())
	if !strings.Contains(errb.String(), bs+"x1b[2Jscan") {
		t.Fatalf("expected a visible escape: %q", errb.String())
	}
}

// A structural guard, so a command added later cannot bypass the boundary:
// outside safeout.go nothing in this package may build a flag set of its own or
// write to a.Stdout / a.Stderr directly. The one allowed direct write is the
// report body, which each format escapes at its own layer.
func TestEveryHumanFacingWriteGoesThroughTheSafeBoundary(t *testing.T) {
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	allowed := map[string]bool{
		// The human-facing boundary itself.
		"safeout.go": true,
		// The machine-output boundary. It writes verbatim on purpose: its
		// values are filenames the caller writes to, so escaping them would
		// hand back a different path. It validates and refuses instead.
		"machineout.go": true,
	}
	// Direct writes that are deliberately not human-readable text.
	allowedLines := map[string]bool{
		"if _, werr := a.Stdout.Write(buf.Bytes()); werr != nil {":       true, // report body
		"os.Getenv(NO_COLOR) ==  && a.IsTTY != nil && a.IsTTY(a.Stdout)": true,
	}
	checked := 0
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		if allowed[name] {
			continue
		}
		data, rerr := os.ReadFile(filepath.Join(".", name))
		if rerr != nil {
			t.Fatal(rerr)
		}
		checked++
		for i, line := range strings.Split(string(data), string(rune(0x0a))) {
			trimmed := strings.TrimSpace(line)
			if strings.HasPrefix(trimmed, "//") {
				continue
			}
			if strings.Contains(line, "flag.NewFlagSet") {
				t.Errorf("%s:%d builds a flag set directly; use a.newFlagSet so parser output is sanitized", name, i+1)
			}
			if !strings.Contains(line, "fmt.Fprint") {
				continue
			}
			if !strings.Contains(line, "a.Stdout") && !strings.Contains(line, "a.Stderr") {
				continue
			}
			t.Errorf("%s:%d writes to a stream directly; use a.errf/a.outf: %s", name, i+1, trimmed)
		}
		// The report body write is the only permitted direct stream use.
		for i, line := range strings.Split(string(data), string(rune(0x0a))) {
			trimmed := strings.TrimSpace(line)
			if strings.Contains(trimmed, "a.Stdout.Write(") && !allowedLines[trimmed] {
				t.Errorf("%s:%d writes to stdout directly: %s", name, i+1, trimmed)
			}
		}
	}
	if checked == 0 {
		t.Fatal("the guard scanned no files; it would pass vacuously")
	}
}

// action-paths prints a machine protocol. Routing it through the human-facing
// helpers is exactly the bug that made a legal path come back rewritten, so the
// command must use the machine writer and nothing else.
func TestActionPathsUsesTheMachineWriterNotHumanOutput(t *testing.T) {
	data, err := os.ReadFile(filepath.Join(".", "commands.go"))
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(string(data), string(rune(0x0a)))
	start := -1
	for i, l := range lines {
		if strings.HasPrefix(l, "func (a *App) cmdActionPaths(") {
			start = i
			break
		}
	}
	if start < 0 {
		t.Fatal("cmdActionPaths not found; this guard would pass vacuously")
	}
	sawMachineWriter := false
	for i := start; i < len(lines); i++ {
		line := lines[i]
		if i > start && strings.HasPrefix(line, "func ") {
			break // end of the function
		}
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "//") {
			continue
		}
		for _, banned := range []string{"a.outf(", "a.outln(", "a.Stdout"} {
			if strings.Contains(line, banned) {
				t.Errorf("commands.go:%d: action-paths must not write its protocol through %s: %s", i+1, banned, trimmed)
			}
		}
		if strings.Contains(line, "a.newMachineWriter()") {
			sawMachineWriter = true
		}
	}
	if !sawMachineWriter {
		t.Error("action-paths should emit its protocol through a.newMachineWriter()")
	}
}
