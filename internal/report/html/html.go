// Package htmlreport renders a single self-contained HTML report: no external
// resources, no JavaScript, no tracking, and a strict Content-Security-Policy.
// Every value passes through html/template's contextual escaping so scanned
// content can never inject markup, and identical inputs produce byte-identical
// output.
package htmlreport

import (
	_ "embed"
	"html/template"
	"io"

	"github.com/Yakitori197/yolab-agent-skill-guard/internal/model"
)

//go:embed template.gohtml
var templateSrc string

var tpl = template.Must(template.New("report").Parse(templateSrc))

type sevCount struct {
	Name  string
	Class string
	Count int
}

type ruleCount struct {
	ID    string
	Title string
	Count int
}

type platCount struct {
	Name  string
	Count int
}

type row struct {
	Line, Column                    int
	Severity, SevClass              string
	RuleID, Title                   string
	Message, Remediation, Rationale string
	Context, Platform, Fingerprint  string
	Heuristic                       bool
}

type fileGroup struct {
	Path string
	Rows []row
}

type page struct {
	ToolName      string
	ToolVersion   string
	FilesScanned  int
	FilesSkipped  int
	Suppressed    int
	TotalFindings int
	Result        string
	ResultClass   string
	FailOn        string
	Sev           []sevCount
	Rules         []ruleCount
	Platforms     []platCount
	Groups        []fileGroup
	Skipped       []model.SkippedFile
}

func sevClass(s model.Severity) string { return "sev-" + string(s) }

// Render writes the HTML report. failOn is used only for the verdict banner.
func Render(w io.Writer, rep *model.Report, catalog []model.RuleMeta, failOn model.FailOn) error {
	metaIdx := make(map[string]model.RuleMeta, len(catalog))
	for _, m := range catalog {
		metaIdx[m.ID] = m
	}

	counts := rep.CountBySeverity()
	p := page{
		ToolName:      rep.Tool.Name,
		ToolVersion:   rep.Tool.Version,
		FilesScanned:  rep.FilesScanned,
		FilesSkipped:  len(rep.Skipped),
		Suppressed:    rep.Suppressed,
		TotalFindings: len(rep.Findings),
		Skipped:       rep.Skipped,
	}
	for _, s := range model.Severities {
		p.Sev = append(p.Sev, sevCount{Name: string(s), Class: sevClass(s), Count: counts[s]})
	}

	if th, ok := failOn.Threshold(); ok {
		p.FailOn = string(th)
		if rep.CountAtOrAbove(th) > 0 {
			p.Result, p.ResultClass = "FAIL", "fail"
		} else {
			p.Result, p.ResultClass = "PASS", "pass"
		}
	} else {
		p.FailOn = "none"
		p.Result, p.ResultClass = "PASS", "pass"
	}

	ruleCounts := map[string]int{}
	platCounts := map[model.Platform]int{}
	for _, f := range rep.Findings {
		ruleCounts[f.RuleID]++
		platCounts[f.Platform]++
	}
	for _, m := range catalog {
		if n := ruleCounts[m.ID]; n > 0 {
			p.Rules = append(p.Rules, ruleCount{ID: m.ID, Title: m.Title, Count: n})
		}
	}
	for _, pf := range model.Platforms {
		if n := platCounts[pf]; n > 0 {
			p.Platforms = append(p.Platforms, platCount{Name: string(pf), Count: n})
		}
	}

	var group *fileGroup
	for _, f := range rep.Findings {
		if group == nil || group.Path != f.Path {
			p.Groups = append(p.Groups, fileGroup{Path: f.Path})
			group = &p.Groups[len(p.Groups)-1]
		}
		m := metaIdx[f.RuleID]
		group.Rows = append(group.Rows, row{
			Line: f.Line, Column: f.Column,
			Severity: string(f.Severity), SevClass: sevClass(f.Severity),
			RuleID: f.RuleID, Title: m.Title,
			Message: f.Message, Remediation: f.Remediation, Rationale: m.Rationale,
			Context: string(f.Context), Platform: string(f.Platform),
			Fingerprint: f.Fingerprint, Heuristic: m.Heuristic,
		})
	}
	return tpl.Execute(w, p)
}
