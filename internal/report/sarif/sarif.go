// Package sarif renders SARIF 2.1.0 output suitable for GitHub Code Scanning.
// URIs are always root-relative with forward slashes — absolute local paths
// never appear — and field order is fixed by struct definitions so identical
// inputs produce byte-identical output.
package sarif

import (
	"encoding/json"
	"io"
	"strings"

	"github.com/Yakitori197/yolab-agent-skill-guard/internal/model"
)

const (
	sarifVersion = "2.1.0"
	sarifSchema  = "https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/schemas/sarif-schema-2.1.0.json"
	infoURI      = "https://github.com/Yakitori197/yolab-agent-skill-guard"
)

type sarifLog struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool       sarifTool     `json:"tool"`
	ColumnKind string        `json:"columnKind"`
	Results    []sarifResult `json:"results"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name           string      `json:"name"`
	InformationURI string      `json:"informationUri"`
	Version        string      `json:"version"`
	Rules          []sarifRule `json:"rules"`
}

type sarifRule struct {
	ID                   string         `json:"id"`
	Name                 string         `json:"name"`
	ShortDescription     sarifText      `json:"shortDescription"`
	FullDescription      sarifText      `json:"fullDescription"`
	Help                 sarifText      `json:"help"`
	HelpURI              string         `json:"helpUri"`
	DefaultConfiguration sarifLevel     `json:"defaultConfiguration"`
	Properties           sarifRuleProps `json:"properties"`
}

type sarifText struct {
	Text string `json:"text"`
}

type sarifLevel struct {
	Level string `json:"level"`
}

type sarifRuleProps struct {
	Tags             []string `json:"tags"`
	SecuritySeverity string   `json:"security-severity"`
}

type sarifResult struct {
	RuleID              string            `json:"ruleId"`
	RuleIndex           int               `json:"ruleIndex"`
	Level               string            `json:"level"`
	Message             sarifText         `json:"message"`
	Locations           []sarifLocation   `json:"locations"`
	PartialFingerprints map[string]string `json:"partialFingerprints"`
	Properties          sarifResultProps  `json:"properties"`
}

type sarifResultProps struct {
	Context  string `json:"context"`
	Platform string `json:"platform"`
}

type sarifLocation struct {
	PhysicalLocation sarifPhysical `json:"physicalLocation"`
}

type sarifPhysical struct {
	ArtifactLocation sarifArtifact `json:"artifactLocation"`
	Region           sarifRegion   `json:"region"`
}

type sarifArtifact struct {
	URI string `json:"uri"`
}

type sarifRegion struct {
	StartLine   int `json:"startLine"`
	StartColumn int `json:"startColumn"`
}

func level(s model.Severity) string {
	switch s {
	case model.SeverityCritical, model.SeverityHigh:
		return "error"
	case model.SeverityMedium:
		return "warning"
	default:
		return "note"
	}
}

// securitySeverity maps to GitHub's buckets: >=9 critical, 7–8.9 high,
// 4–6.9 medium, <4 low.
func securitySeverity(s model.Severity) string {
	switch s {
	case model.SeverityCritical:
		return "9.5"
	case model.SeverityHigh:
		return "8.0"
	case model.SeverityMedium:
		return "5.5"
	case model.SeverityLow:
		return "3.0"
	default:
		return "0.0"
	}
}

func ruleName(title string) string {
	return strings.ReplaceAll(title, " ", "")
}

// Render writes the SARIF report. catalog must be ordered by rule ID (as
// rules.Catalog guarantees); result ruleIndex values point into it.
func Render(w io.Writer, rep *model.Report, catalog []model.RuleMeta) error {
	ruleIndex := make(map[string]int, len(catalog))
	sr := make([]sarifRule, 0, len(catalog))
	for i, m := range catalog {
		ruleIndex[m.ID] = i
		help := m.Remediation
		if m.Heuristic {
			help += " (Heuristic rule: findings are risk signals requiring human review.)"
		}
		sr = append(sr, sarifRule{
			ID:               m.ID,
			Name:             ruleName(m.Title),
			ShortDescription: sarifText{Text: m.Title},
			FullDescription:  sarifText{Text: m.Summary},
			Help:             sarifText{Text: help},
			HelpURI:          infoURI + "/blob/main/docs/rules.md#" + strings.ToLower(m.ID),
			DefaultConfiguration: sarifLevel{
				Level: level(m.DefaultSeverity),
			},
			Properties: sarifRuleProps{
				Tags:             []string{"security", m.Category},
				SecuritySeverity: securitySeverity(m.DefaultSeverity),
			},
		})
	}
	results := make([]sarifResult, 0, len(rep.Findings))
	for _, f := range rep.Findings {
		line := f.Line
		if line < 1 {
			line = 1
		}
		col := f.Column
		if col < 1 {
			col = 1
		}
		results = append(results, sarifResult{
			RuleID:    f.RuleID,
			RuleIndex: ruleIndex[f.RuleID],
			Level:     level(f.Severity),
			Message:   sarifText{Text: f.Message},
			Locations: []sarifLocation{{
				PhysicalLocation: sarifPhysical{
					ArtifactLocation: sarifArtifact{URI: f.Path},
					Region:           sarifRegion{StartLine: line, StartColumn: col},
				},
			}},
			PartialFingerprints: map[string]string{"skillguard/v1": f.Fingerprint},
			Properties:          sarifResultProps{Context: string(f.Context), Platform: string(f.Platform)},
		})
	}
	log := sarifLog{
		Schema:  sarifSchema,
		Version: sarifVersion,
		Runs: []sarifRun{{
			Tool: sarifTool{Driver: sarifDriver{
				Name:           rep.Tool.Name,
				InformationURI: infoURI,
				Version:        rep.Tool.Version,
				Rules:          sr,
			}},
			ColumnKind: "unicodeCodePoints",
			Results:    results,
		}},
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(log)
}
