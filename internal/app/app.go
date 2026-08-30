// Package app wires the skillguard CLI: flag parsing, command dispatch, the
// scan engine, and exit codes. Exit code 0 means a clean run, 1 means the
// scan succeeded but findings met the fail-on threshold, and 2 means a
// configuration, input, or runtime error (always fail closed).
package app

import (
	"fmt"
	"io"
	"os"
	"strings"
	"time"
)

// Exit codes (stable API).
const (
	ExitOK       = 0
	ExitFindings = 1
	ExitError    = 2
)

// App carries injectable environment so every command is testable in-process.
type App struct {
	Stdout io.Writer
	Stderr io.Writer
	// Workdir is where `init` writes; empty means the process working dir.
	Workdir string
	// Now supplies the clock used for suppression expiry only. Reports never
	// contain timestamps.
	Now func() time.Time
	// IsTTY reports whether a writer is an interactive terminal.
	IsTTY func(io.Writer) bool
}

// New returns an App bound to the real process environment.
func New() *App {
	return &App{Stdout: os.Stdout, Stderr: os.Stderr, Now: time.Now, IsTTY: isTerminal}
}

// Run dispatches a command line (without the program name) and returns the
// process exit code.
func (a *App) Run(args []string) int {
	if len(args) == 0 {
		a.usage(a.Stderr)
		return ExitError
	}
	switch args[0] {
	case "scan":
		return a.cmdScan(args[1:], ModeFull)
	case "validate":
		return a.cmdScan(args[1:], ModeValidate)
	case "rules":
		return a.cmdRules(args[1:])
	case "explain":
		return a.cmdExplain(args[1:])
	case "init":
		return a.cmdInit(args[1:])
	case "version":
		return a.cmdVersion(args[1:])
	case "action-paths":
		return a.cmdActionPaths(args[1:])
	case "help", "-h", "--help":
		a.usage(a.Stdout)
		return ExitOK
	default:
		a.errf("skillguard: unknown command %q\n\n", args[0])
		a.usage(a.Stderr)
		return ExitError
	}
}

func (a *App) usage(w io.Writer) {
	fmt.Fprint(blockWriter{w}, strings.TrimLeft(`
skillguard — offline security, privacy, and compatibility auditor for
AI agent skills and instruction files.

Usage:
  skillguard scan [path] [flags]      full structure, security, and privacy scan
  skillguard validate [path] [flags]  structure, frontmatter, and reference checks only
  skillguard rules                    list every rule with severity and category
  skillguard explain RULE_ID          full description of one rule
  skillguard init                     create a .skillguard.yml template (never overwrites)
  skillguard version                  show version, commit, and build date

CI helper:
  skillguard action-paths --workspace DIR --path P --output O
                                      validate wrapper-supplied paths and print
                                      the resolved values (used by the Action)

Scan flags:
  --format text|json|sarif|html   output format (default text)
  --output FILE                   write the report to FILE instead of stdout
  --config FILE                   configuration file (default .skillguard.yml at the root)
  --fail-on LEVEL                 critical|high|medium|low|info|none (default high)
  --platform NAME                 restrict to codex|claude|cursor|generic (repeatable)
  --summary FILE                  also write key=value counters (for CI)
  --no-clobber                    refuse to overwrite an existing report file
                                  (the GitHub Action always sets this)
  --show-paths                    show the full local scan root in text output
                                  (off by default)
  --no-color                      disable ANSI colors
  --quiet                         findings and result only

Exit codes:
  0  scan succeeded, nothing at or above the fail-on threshold
  1  scan succeeded, findings at or above the fail-on threshold
  2  configuration, input, or runtime error
`, "\n"))
}

func isTerminal(w io.Writer) bool {
	f, ok := w.(*os.File)
	if !ok {
		return false
	}
	fi, err := f.Stat()
	if err != nil {
		return false
	}
	return fi.Mode()&os.ModeCharDevice != 0
}

// multiFlag collects a repeatable string flag.
type multiFlag []string

func (m *multiFlag) String() string { return strings.Join(*m, ",") }

func (m *multiFlag) Set(v string) error {
	*m = append(*m, v)
	return nil
}
