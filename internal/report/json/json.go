// Package jsonreport renders the versioned machine-readable JSON report.
// Field order is fixed by struct definitions (never map iteration), all
// slices are initialized so empty collections serialize as [] rather than
// null, and no timestamps or absolute local paths are ever emitted, so
// identical inputs produce byte-identical output.
package jsonreport

import (
	"encoding/json"
	"io"

	"github.com/Yakitori197/yolab-agent-skill-guard/internal/model"
)

// Schema identifies the JSON report format version.
const Schema = "skillguard-report/v1"

type reportJSON struct {
	Schema   string        `json:"schema"`
	Tool     toolJSON      `json:"tool"`
	Summary  summaryJSON   `json:"summary"`
	Findings []findingJSON `json:"findings"`
	Skipped  []skippedJSON `json:"skipped"`
}

type toolJSON struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

type summaryJSON struct {
	FilesScanned  int `json:"files_scanned"`
	FilesSkipped  int `json:"files_skipped"`
	Suppressed    int `json:"suppressed"`
	TotalFindings int `json:"total_findings"`
	Critical      int `json:"critical"`
	High          int `json:"high"`
	Medium        int `json:"medium"`
	Low           int `json:"low"`
	Info          int `json:"info"`
}

type findingJSON struct {
	Rule        string `json:"rule"`
	Severity    string `json:"severity"`
	Path        string `json:"path"`
	Line        int    `json:"line"`
	Column      int    `json:"column"`
	Message     string `json:"message"`
	Remediation string `json:"remediation"`
	Fingerprint string `json:"fingerprint"`
	Context     string `json:"context"`
	Platform    string `json:"platform"`
}

type skippedJSON struct {
	Path   string `json:"path"`
	Reason string `json:"reason"`
}

// Render writes the JSON report (two-space indent, trailing newline).
func Render(w io.Writer, rep *model.Report) error {
	counts := rep.CountBySeverity()
	out := reportJSON{
		Schema: Schema,
		Tool:   toolJSON{Name: rep.Tool.Name, Version: rep.Tool.Version},
		Summary: summaryJSON{
			FilesScanned:  rep.FilesScanned,
			FilesSkipped:  len(rep.Skipped),
			Suppressed:    rep.Suppressed,
			TotalFindings: len(rep.Findings),
			Critical:      counts[model.SeverityCritical],
			High:          counts[model.SeverityHigh],
			Medium:        counts[model.SeverityMedium],
			Low:           counts[model.SeverityLow],
			Info:          counts[model.SeverityInfo],
		},
		Findings: make([]findingJSON, 0, len(rep.Findings)),
		Skipped:  make([]skippedJSON, 0, len(rep.Skipped)),
	}
	for _, f := range rep.Findings {
		out.Findings = append(out.Findings, findingJSON{
			Rule:        f.RuleID,
			Severity:    string(f.Severity),
			Path:        f.Path,
			Line:        f.Line,
			Column:      f.Column,
			Message:     f.Message,
			Remediation: f.Remediation,
			Fingerprint: f.Fingerprint,
			Context:     string(f.Context),
			Platform:    string(f.Platform),
		})
	}
	for _, s := range rep.Skipped {
		out.Skipped = append(out.Skipped, skippedJSON{Path: s.Path, Reason: s.Reason})
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(out)
}
