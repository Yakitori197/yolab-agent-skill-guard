// Package text renders the terminal report. Output is deterministic, uses
// only LF line endings, and colors are applied solely when explicitly enabled
// by the caller (never when writing to a non-TTY).
//
// This is the one renderer whose output a terminal interprets, so every string
// that did not originate in this package — the root label, paths taken from
// the filesystem, rule messages that quote scanned text — passes through
// termsafe.Sanitize before it is written. The ANSI codes below are added
// afterwards, so the only escape sequences that can reach the terminal are the
// ones this file emits.
package text

import (
	"fmt"
	"io"

	"github.com/Yakitori197/yolab-agent-skill-guard/internal/model"
	"github.com/Yakitori197/yolab-agent-skill-guard/internal/termsafe"
)

// Options controls text rendering.
type Options struct {
	Color  bool
	Quiet  bool
	FailOn model.FailOn
}

const (
	ansiReset  = "\x1b[0m"
	ansiBold   = "\x1b[1m"
	ansiDim    = "\x1b[2m"
	ansiRed    = "\x1b[31m"
	ansiYellow = "\x1b[33m"
	ansiCyan   = "\x1b[36m"
)

func sevColor(s model.Severity) string {
	switch s {
	case model.SeverityCritical:
		return ansiBold + ansiRed
	case model.SeverityHigh:
		return ansiRed
	case model.SeverityMedium:
		return ansiYellow
	case model.SeverityLow:
		return ansiCyan
	default:
		return ansiDim
	}
}

// Render writes the report. It never returns partial ANSI state: every
// colored token is individually reset.
func Render(w io.Writer, rep *model.Report, o Options) {
	// safe neutralizes text that came from outside this package; paint adds
	// this renderer's own ANSI afterwards, never before.
	safe := termsafe.Sanitize
	paint := func(code, s string) string {
		if !o.Color {
			return s
		}
		return code + s + ansiReset
	}

	if !o.Quiet {
		fmt.Fprintf(w, "%s %s — offline audit for agent skills and instruction files\n\n",
			paint(ansiBold, safe(rep.Tool.Name)), safe(rep.Tool.Version))
		fmt.Fprintf(w, "root: %s\n", safe(rep.RootLabel))
		fmt.Fprintf(w, "files scanned: %d · skipped: %d · suppressed: %d\n",
			rep.FilesScanned, len(rep.Skipped), rep.Suppressed)
	}

	lastPath := ""
	for _, f := range rep.Findings {
		if f.Path != lastPath {
			fmt.Fprintf(w, "\n%s\n", paint(ansiBold, safe(f.Path)))
			lastPath = f.Path
		}
		fmt.Fprintf(w, "  %d:%d  %s  %s  %s\n",
			f.Line, f.Column, paint(sevColor(f.Severity), safe(string(f.Severity))),
			safe(f.RuleID), safe(f.Message))
		if !o.Quiet && f.Remediation != "" {
			fmt.Fprintf(w, "        fix: %s\n", safe(f.Remediation))
		}
	}
	if len(rep.Findings) == 0 && !o.Quiet {
		fmt.Fprintf(w, "\nno findings\n")
	}

	if !o.Quiet && len(rep.Skipped) > 0 {
		fmt.Fprintf(w, "\nskipped (never read):\n")
		for _, s := range rep.Skipped {
			fmt.Fprintf(w, "  - %s — %s\n", safe(s.Path), safe(s.Reason))
		}
	}

	counts := rep.CountBySeverity()
	fmt.Fprintf(w, "\nsummary: critical %d · high %d · medium %d · low %d · info %d\n",
		counts[model.SeverityCritical], counts[model.SeverityHigh], counts[model.SeverityMedium],
		counts[model.SeverityLow], counts[model.SeverityInfo])

	if th, ok := o.FailOn.Threshold(); ok {
		n := rep.CountAtOrAbove(th)
		if n > 0 {
			fmt.Fprintf(w, "result: %s — %d finding(s) at or above fail-on threshold (%s)\n",
				paint(ansiBold+ansiRed, "FAIL"), n, safe(string(th)))
		} else {
			fmt.Fprintf(w, "result: %s — no findings at or above fail-on threshold (%s)\n",
				paint(ansiBold, "PASS"), safe(string(th)))
		}
	} else {
		fmt.Fprintf(w, "result: %s — fail-on is none (informational run)\n", paint(ansiBold, "PASS"))
	}
}
