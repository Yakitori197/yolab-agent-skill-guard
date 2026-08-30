package app

import (
	"bytes"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/Yakitori197/yolab-agent-skill-guard/internal/model"
	htmlreport "github.com/Yakitori197/yolab-agent-skill-guard/internal/report/html"
	jsonreport "github.com/Yakitori197/yolab-agent-skill-guard/internal/report/json"
	sarifreport "github.com/Yakitori197/yolab-agent-skill-guard/internal/report/sarif"
	textreport "github.com/Yakitori197/yolab-agent-skill-guard/internal/report/text"
	"github.com/Yakitori197/yolab-agent-skill-guard/internal/rules"
)

var validFormats = map[string]bool{"text": true, "json": true, "sarif": true, "html": true}

func (a *App) cmdScan(args []string, mode ScanMode) int {
	name := "scan"
	if mode == ModeValidate {
		name = "validate"
	}
	fs := a.newFlagSet(name)
	var (
		format     = fs.String("format", "text", "output format: text, json, sarif, or html")
		output     = fs.String("output", "", "write the report to this file instead of stdout")
		configPath = fs.String("config", "", "configuration file (default: .skillguard.yml at the scan root)")
		failOnFlag = fs.String("fail-on", "", "exit-1 threshold: critical, high, medium, low, info, or none")
		noColor    = fs.Bool("no-color", false, "disable ANSI colors in text output")
		quiet      = fs.Bool("quiet", false, "reduce text output to findings and result")
		summary    = fs.String("summary", "", "also write key=value counters to this file (for CI)")
		noClobber  = fs.Bool("no-clobber", false, "refuse to write the report over an existing file (the GitHub Action always sets this)")
		showPaths  = fs.Bool("show-paths", false, "show the full local scan root in text output (off by default: reports stay free of local paths)")
	)
	var platforms multiFlag
	fs.Var(&platforms, "platform", "restrict scanning to a platform (repeatable): codex, claude, cursor, generic")

	rootArg, ok := a.parseWithPath(fs, args, name)
	if !ok {
		return ExitError
	}
	if !validFormats[*format] {
		a.errf("skillguard %s: unknown format %q (expected text, json, sarif, or html)\n", name, *format)
		return ExitError
	}

	rootAbs, _, err := resolveRoot(rootArg)
	if err != nil {
		a.errf("skillguard: %v\n", err)
		return ExitError
	}
	cfg, err := loadConfig(*configPath, rootAbs)
	if err != nil {
		a.errf("skillguard: %v\n", err)
		return ExitError
	}
	if len(platforms) > 0 {
		cfg.Platforms = cfg.Platforms[:0]
		for _, p := range platforms {
			pp, perr := model.ParsePlatform(p)
			if perr != nil {
				a.errf("skillguard %s: --platform: %v\n", name, perr)
				return ExitError
			}
			cfg.Platforms = append(cfg.Platforms, pp)
		}
	}
	effFailOn := cfg.FailOn
	if *failOnFlag != "" {
		fo, ferr := model.ParseFailOn(*failOnFlag)
		if ferr != nil {
			a.errf("skillguard %s: --fail-on: %v\n", name, ferr)
			return ExitError
		}
		effFailOn = fo
	}

	rep, err := runScan(ScanOptions{RootArg: rootArg, Config: cfg, Mode: mode, Now: a.Now(), ShowPaths: *showPaths})
	if err != nil {
		a.errf("skillguard: %v\n", err)
		return ExitError
	}

	useColor := *format == "text" && !*noColor && *output == "" &&
		os.Getenv("NO_COLOR") == "" && a.IsTTY != nil && a.IsTTY(a.Stdout)

	var buf bytes.Buffer
	switch *format {
	case "text":
		textreport.Render(&buf, rep, textreport.Options{Color: useColor, Quiet: *quiet, FailOn: effFailOn})
	case "json":
		err = jsonreport.Render(&buf, rep)
	case "sarif":
		err = sarifreport.Render(&buf, rep, rules.Catalog())
	case "html":
		err = htmlreport.Render(&buf, rep, rules.Catalog(), effFailOn)
	}
	if err != nil {
		a.errf("skillguard: rendering %s report failed: %v\n", *format, err)
		return ExitError
	}

	if *output != "" {
		if werr := writeReport(*output, buf.Bytes(), *noClobber); werr != nil {
			if os.IsExist(werr) {
				a.errf("skillguard: refusing to overwrite the existing file %q (--no-clobber)\n", displayPath(*output))
			} else {
				a.errf("skillguard: cannot write report to %q\n", displayPath(*output))
			}
			return ExitError
		}
		if !*quiet {
			// %q, not %s: the destination is user-supplied and may contain
			// ESC or a newline, which a terminal would act on.
			a.errf("skillguard: %s report written to %q\n", *format, displayPath(*output))
		}
	} else {
		if _, werr := a.Stdout.Write(buf.Bytes()); werr != nil {
			return ExitError
		}
	}
	if *summary != "" {
		if serr := writeSummary(*summary, rep); serr != nil {
			a.errf("skillguard: cannot write summary to %q\n", displayPath(*summary))
			return ExitError
		}
	}

	if th, thOK := effFailOn.Threshold(); thOK && rep.CountAtOrAbove(th) > 0 {
		return ExitFindings
	}
	return ExitOK
}

// parseWithPath parses flags that may appear before and/or after the single
// optional path argument (`skillguard scan pkg --format json` works).
func (a *App) parseWithPath(fs *flagSet, args []string, name string) (string, bool) {
	if err := fs.parse(args); err != nil {
		return "", false
	}
	rootArg := "."
	rest := fs.Args()
	if len(rest) >= 1 {
		rootArg = rest[0]
		if len(rest) > 1 {
			if err := fs.parse(rest[1:]); err != nil {
				return "", false
			}
			if len(fs.Args()) > 0 {
				// The leftovers are raw argv; quoting each one keeps a
				// crafted argument from writing escape sequences here.
				a.errf("skillguard %s: unexpected extra arguments: %s\n",
					name, quoteArgs(fs.Args()))
				return "", false
			}
		}
	}
	return rootArg, true
}

// quoteArgs renders argv values for a human-readable error line. strconv.Quote
// turns ESC, CR, LF, bidi overrides and malformed UTF-8 into visible escapes,
// so a crafted argument cannot drive the terminal from an error message.
func quoteArgs(args []string) string {
	quoted := make([]string, len(args))
	for i, a := range args {
		quoted[i] = strconv.Quote(a)
	}
	return strings.Join(quoted, " ")
}

// writeSummary emits deterministic key=value counters consumable by CI shells
// (and by the GitHub Action entrypoint) without a JSON parser.
func writeSummary(path string, rep *model.Report) error {
	counts := rep.CountBySeverity()
	var b strings.Builder
	fmt.Fprintf(&b, "findings=%d\n", len(rep.Findings))
	for _, s := range model.Severities {
		fmt.Fprintf(&b, "%s=%d\n", s, counts[s])
	}
	fmt.Fprintf(&b, "suppressed=%d\n", rep.Suppressed)
	fmt.Fprintf(&b, "files-scanned=%d\n", rep.FilesScanned)
	return os.WriteFile(path, []byte(b.String()), 0o644)
}

// writeReport writes the rendered report.
//
// With noClobber the file is created with O_EXCL, so an existing path is never
// truncated even if it appeared after an earlier validation pass — the check
// and the write are the same operation. The GitHub Action always runs in this
// mode; the plain CLI keeps its ordinary overwrite behavior so re-running a
// scan into the same report file still works.
func writeReport(path string, data []byte, noClobber bool) error {
	if !noClobber {
		return os.WriteFile(path, data, 0o644)
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
	if err != nil {
		return err
	}
	if _, werr := f.Write(data); werr != nil {
		f.Close()
		return werr
	}
	return f.Close()
}
