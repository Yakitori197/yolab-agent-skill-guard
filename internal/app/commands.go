package app

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"text/tabwriter"

	"github.com/Yakitori197/yolab-agent-skill-guard/internal/actionpath"
	"github.com/Yakitori197/yolab-agent-skill-guard/internal/rules"
	"github.com/Yakitori197/yolab-agent-skill-guard/internal/version"
)

func (a *App) cmdRules(args []string) int {
	fs := a.newFlagSet("rules")
	if err := fs.parse(args); err != nil {
		return ExitError
	}
	if len(fs.Args()) > 0 {
		a.errln("skillguard rules: this command takes no arguments")
		return ExitError
	}
	// The catalog is this tool's own text, but it goes out through the
	// same sanitizing writer as everything else a human reads.
	w := tabwriter.NewWriter(blockWriter{a.Stdout}, 2, 4, 2, ' ', 0)
	fmt.Fprintln(w, "ID\tSEVERITY\tCATEGORY\tHEURISTIC\tTITLE — SUMMARY")
	for _, m := range rules.Catalog() {
		h := "no"
		if m.Heuristic {
			h = "yes"
		}
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s — %s\n", m.ID, m.DefaultSeverity, m.Category, h, m.Title, m.Summary)
	}
	w.Flush()
	return ExitOK
}

func (a *App) cmdExplain(args []string) int {
	fs := a.newFlagSet("explain")
	if err := fs.parse(args); err != nil {
		return ExitError
	}
	rest := fs.Args()
	if len(rest) != 1 {
		a.errln("skillguard explain: exactly one RULE_ID argument is required (see `skillguard rules`)")
		return ExitError
	}
	id := strings.ToUpper(strings.TrimSpace(rest[0]))
	m, ok := rules.MetaByID(id)
	if !ok {
		a.errf("skillguard explain: unknown rule %q (see `skillguard rules` for the catalog)\n", rest[0])
		return ExitError
	}
	h := "no"
	if m.Heuristic {
		h = "yes — findings are risk signals requiring human review"
	}
	a.outf("%s — %s\n", m.ID, m.Title)
	a.outf("severity: %s · category: %s · heuristic: %s\n", m.DefaultSeverity, m.Category, h)
	a.outf("\nWHY IT MATTERS\n  %s\n", m.Rationale)
	a.outf("\nREMEDIATION\n  %s\n", m.Remediation)
	a.outf("\nSAFE EXAMPLE\n  %s\n", m.SafeExample)
	a.outf("\nRISKY EXAMPLE (synthetic)\n  %s\n", m.UnsafeExample)
	a.outf("\nSUPPORTED CONTEXTS\n  %s\n", strings.Join(m.Contexts, ", "))
	return ExitOK
}

const initTemplate = `# skillguard configuration — https://github.com/Yakitori197/yolab-agent-skill-guard
# Schema documentation: docs/configuration.md
version: 1

# Exit code 1 when findings at or above this severity exist:
# critical | high | medium | low | info | none
fail_on: high

# Restrict which platforms are scanned (default: all).
# platforms:
#   - claude
#   - codex
#   - cursor
#   - generic

# Glob patterns (relative to the scan root, forward slashes, ** supported).
# include:
#   - "skills/**/*.md"
# exclude:
#   - "drafts/**"

# Largest file the scanner will read, in bytes (default 1048576 = 1 MiB).
# max_file_size: 1048576

# Hosts that scanned content may legitimately contact (ASG005).
# allowed_domains:
#   - "api.example.com"

# Capabilities skills may declare in frontmatter (ASG005/ASG006).
# allowed_capabilities:
#   - "network"

# Rule IDs to disable entirely (disabling everything is rejected).
# disabled_rules:
#   - "ASG011"

# Per-rule severity overrides.
# severity_overrides:
#   ASG002: low

# Targeted, justified exceptions. reason is required; expired entries stop
# working and surface as ASG900 findings.
# suppressions:
#   - rule: ASG003
#     path: "docs/dangerous-examples.md"
#     reason: "Documented examples of destructive commands, fenced and annotated."
#     expires: "2027-01-01"
`

func (a *App) cmdInit(args []string) int {
	fs := a.newFlagSet("init")
	if err := fs.parse(args); err != nil {
		return ExitError
	}
	if len(fs.Args()) > 0 {
		a.errln("skillguard init: this command takes no arguments")
		return ExitError
	}
	dir := a.Workdir
	if dir == "" {
		wd, err := os.Getwd()
		if err != nil {
			a.errln("skillguard init: cannot determine the working directory")
			return ExitError
		}
		dir = wd
	}
	path := filepath.Join(dir, ".skillguard.yml")
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o644)
	if err != nil {
		if os.IsExist(err) {
			a.errln("skillguard init: .skillguard.yml already exists; refusing to overwrite")
		} else {
			a.errln("skillguard init: cannot create .skillguard.yml")
		}
		return ExitError
	}
	defer f.Close()
	if _, err := f.WriteString(initTemplate); err != nil {
		a.errln("skillguard init: writing .skillguard.yml failed")
		return ExitError
	}
	a.outln("created .skillguard.yml")
	return ExitOK
}

func (a *App) cmdVersion(args []string) int {
	fs := a.newFlagSet("version")
	if err := fs.parse(args); err != nil {
		return ExitError
	}
	a.outf("skillguard %s\ncommit: %s\nbuilt: %s\ngo: %s\n",
		version.Version, version.Commit, version.Date, runtime.Version())
	return ExitOK
}

// cmdActionPaths validates the untrusted path inputs a CI wrapper passes in and
// prints the resolved values as key=value lines. It exists so the GitHub Action
// entrypoint contains no security logic of its own: the shell script simply
// forwards three inputs and consumes three validated absolute paths.
func (a *App) cmdActionPaths(args []string) int {
	fs := a.newFlagSet("action-paths")
	var (
		workspace = fs.String("workspace", "", "absolute path of the CI workspace (required)")
		pathIn    = fs.String("path", ".", "scan path, relative to the workspace")
		configIn  = fs.String("config", "", "configuration file, relative to the workspace (optional)")
		outputIn  = fs.String("output", "", "report destination, relative to the workspace (required)")
	)
	if err := fs.parse(args); err != nil {
		return ExitError
	}
	if len(fs.Args()) > 0 {
		a.errln("skillguard action-paths: unexpected positional arguments")
		return ExitError
	}

	scan, err := actionpath.Resolve(*workspace, *pathIn, actionpath.KindScan)
	if err != nil {
		a.errf("skillguard action-paths: %v\n", err)
		return ExitError
	}
	var cfg actionpath.Result
	if strings.TrimSpace(*configIn) != "" {
		cfg, err = actionpath.Resolve(*workspace, *configIn, actionpath.KindConfig)
		if err != nil {
			a.errf("skillguard action-paths: %v\n", err)
			return ExitError
		}
	}
	out, err := actionpath.Resolve(*workspace, *outputIn, actionpath.KindOutput)
	if err != nil {
		a.errf("skillguard action-paths: %v\n", err)
		return ExitError
	}
	if actionpath.SameTarget(out, scan) || actionpath.SameTarget(out, cfg) {
		a.errln("skillguard action-paths: output would overwrite an input file")
		return ExitError
	}

	// Machine protocol, not human text: written verbatim through
	// machineWriter, which validates instead of escaping. Using a.outf here
	// would sanitize a legal path and hand the caller a different filename.
	mw := a.newMachineWriter()
	mw.Line("path", scan.Abs)
	mw.Line("config", cfg.Abs)
	mw.Line("output", out.Abs)
	mw.Line("report-path", out.Rel)
	if err := mw.Flush(); err != nil {
		a.errf("skillguard action-paths: %v\n", err)
		return ExitError
	}
	return ExitOK
}
