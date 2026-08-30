package app

import (
	"bytes"
	"errors"
	"flag"
	"fmt"
	"io"

	"github.com/Yakitori197/yolab-agent-skill-guard/internal/termsafe"
)

// This file is the single place in package app where human-readable text
// reaches the terminal.
//
// Almost everything the CLI prints for a human can carry text the tool did not
// author: a path the user typed, a filename read off disk, a configuration
// error quoting a key, and — the case that motivated this file — the flag
// package's own diagnostics, which echo an unknown flag name verbatim. Writing
// any of that straight to os.Stderr hands the terminal whatever bytes it
// contains: `skillguard scan --<ESC>[2J` used to clear the screen.
//
// Escaping at each call site with %q was not enough: it has to be remembered
// every time, it cannot reach text produced inside the standard library, and a
// command added later silently loses the protection.
//
// The rule here is a split, not a blanket:
//
//   - A *format string* is written in this repository. Its newlines and tabs
//     are layout and are kept.
//   - Every *argument* comes from somewhere else. Each one is escaped with
//     termsafe.Sanitize, which turns an injected newline into a visible escape
//     so it cannot forge a line.
//   - A multi-line block this tool composed in full (the usage text, a flag
//     default list, the rule table) goes through termsafe.SanitizeBlock, which
//     keeps the layout and still escapes everything a terminal acts on.
//
// Deliberately *not* routed through here:
//
//   - The report body written to stdout. Each format escapes at its own layer:
//     the text renderer already sanitizes, and JSON, SARIF and HTML must keep
//     their own encoding untouched.
//   - The `key=value` lines `action-paths` prints for the GitHub Action. That
//     is a machine protocol carrying filenames the caller then writes to, so
//     escaping would hand back a *different* path. It has its own writer in
//     machineout.go, which validates and refuses instead of rewriting.

// errf writes a human-readable line to standard error. format is this
// repository's own text; every argument is sanitized first.
func (a *App) errf(format string, args ...any) {
	writeFormatted(a.Stderr, format, args...)
}

// errln writes one human-readable line to standard error.
func (a *App) errln(s string) { writeFormatted(a.Stderr, "%s\n", s) }

// outf writes human-readable prose to standard output: the rule catalog,
// `explain`, `version`. Never a report body, and never a machine contract.
func (a *App) outf(format string, args ...any) {
	writeFormatted(a.Stdout, format, args...)
}

// outln writes one human-readable line to standard output.
func (a *App) outln(s string) { writeFormatted(a.Stdout, "%s\n", s) }

// writeFormatted is the choke point: no human-facing text leaves package app
// without passing through it.
func writeFormatted(w io.Writer, format string, args ...any) {
	if w == nil {
		return
	}
	fmt.Fprintf(w, format, sanitizeArgs(args)...)
}

// sanitizeArgs escapes everything that could carry outside text. Numbers and
// booleans are left alone; strings, errors and Stringers are escaped, so a
// value reaches the terminal visible but inert. A %q verb then quotes an
// already-safe string, which is harmless and keeps the familiar delimiters.
func sanitizeArgs(args []any) []any {
	if len(args) == 0 {
		return args
	}
	out := make([]any, len(args))
	for i, v := range args {
		switch t := v.(type) {
		case string:
			out[i] = termsafe.Sanitize(t)
		case error:
			out[i] = errors.New(termsafe.Sanitize(t.Error()))
		case fmt.Stringer:
			out[i] = termsafe.Sanitize(t.String())
		default:
			out[i] = v
		}
	}
	return out
}

// blockWriter wraps a writer so a multi-line block this tool composed keeps its
// layout while every terminal-actionable rune inside it is still escaped. It
// exists for the few places that hand a writer to another package: the usage
// text and the tabwriter behind `rules`.
//
// It must not be given text that embeds an outside value; that goes through
// errf/outf, where arguments are escaped individually.
type blockWriter struct{ w io.Writer }

func (b blockWriter) Write(p []byte) (int, error) {
	if b.w == nil {
		return len(p), nil
	}
	if _, err := io.WriteString(b.w, termsafe.SanitizeBlock(string(p))); err != nil {
		return 0, err
	}
	// Report the caller's length: the escaped form can be longer, and a short
	// write would look like an I/O failure.
	return len(p), nil
}

// flagSet is a flag.FlagSet whose diagnostics cannot reach the terminal raw.
//
// flag.ContinueOnError makes the parser print "flag provided but not defined:
// -<name>" followed by the usage block, and <name> is attacker-controlled. The
// parser writes into an in-memory buffer here, and parse() never forwards that
// buffer: it discards it and re-renders both halves itself, so the untrusted
// name appears only as a sanitized argument on a single line, and the usage
// block is regenerated from this tool's own flag definitions.
type flagSet struct {
	*flag.FlagSet
	buf *bytes.Buffer
	app *App
}

// newFlagSet builds the flag set for one command. Every command in this package
// must use it; nothing may call flag.NewFlagSet directly, which
// TestEveryHumanFacingWriteGoesThroughTheSafeBoundary enforces by reading this
// package's own source.
func (a *App) newFlagSet(name string) *flagSet {
	buf := &bytes.Buffer{}
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(buf)
	return &flagSet{FlagSet: fs, buf: buf, app: a}
}

// parse parses args, reporting any problem safely.
//
// scan parses twice (flags may appear before and after the path argument), so
// this must be safe to call repeatedly; the buffer is reset on every entry.
func (f *flagSet) parse(args []string) error {
	f.buf.Reset()
	err := f.FlagSet.Parse(args)
	// Whatever the parser wrote is dropped unread: it interleaves the
	// untrusted flag name with multi-line layout, and there is no reliable way
	// to escape one without destroying the other.
	f.buf.Reset()
	switch {
	case err == nil:
		return nil
	case errors.Is(err, flag.ErrHelp):
		f.printUsage()
		return err
	default:
		// One line, with the parser's message as a sanitized argument: an
		// injected newline becomes a visible escape instead of a new line.
		f.app.errf("skillguard %s: %v\n", f.Name(), err)
		f.printUsage()
		return err
	}
}

// printUsage renders the flag list from this tool's own definitions, so no
// outside text is present and the layout can be preserved.
func (f *flagSet) printUsage() {
	var b bytes.Buffer
	fmt.Fprintf(&b, "Usage of %s:\n", f.Name())
	f.FlagSet.SetOutput(&b)
	f.FlagSet.PrintDefaults()
	f.FlagSet.SetOutput(f.buf)
	if f.app.Stderr != nil {
		io.WriteString(f.app.Stderr, termsafe.SanitizeBlock(b.String()))
	}
}
