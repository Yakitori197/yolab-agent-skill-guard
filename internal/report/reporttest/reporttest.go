// Package reporttest provides fixed, deterministic report fixtures shared by
// the formatter tests. It is test support code and is never imported by
// production packages.
package reporttest

import "github.com/Yakitori197/yolab-agent-skill-guard/internal/model"

// Sample returns a small report exercising every severity, several contexts,
// grouped files, skipped entries, and a suppression count.
func Sample() *model.Report {
	return &model.Report{
		SchemaVersion: "1",
		Tool:          model.ToolInfo{Name: "skillguard", Version: "test"},
		RootLabel:     "examples/pkg",
		FilesScanned:  3,
		Suppressed:    1,
		Findings: []model.Finding{
			{
				RuleID: "ASG001", Severity: model.SeverityCritical, Path: "SKILL.md",
				Line: 12, Column: 9,
				Message:     "Possible GitHub token detected (masked: ghp_******** (40 chars)).",
				Remediation: "Remove the credential and rotate it.",
				Fingerprint: "aaaaaaaaaaaaaaa1", Context: model.ContextCodeFence, Platform: model.PlatformClaude,
			},
			{
				RuleID: "ASG008", Severity: model.SeverityMedium, Path: "SKILL.md",
				Line: 20, Column: 5,
				Message:     "Referenced local resource \"steps/gone.md\" does not exist in the package.",
				Remediation: "Create the referenced file, fix the path, or delete the stale reference.",
				Fingerprint: "aaaaaaaaaaaaaaa2", Context: model.ContextProse, Platform: model.PlatformClaude,
			},
			{
				RuleID: "ASG010", Severity: model.SeverityHigh, Path: "notes/AGENTS.md",
				Line: 3, Column: 1,
				Message:     "Prompt-injection signal (override prior instructions).",
				Remediation: "Rewrite instructions to work with the host platform's rules.",
				Fingerprint: "aaaaaaaaaaaaaaa3", Context: model.ContextProse, Platform: model.PlatformCodex,
			},
			{
				RuleID: "ASG002", Severity: model.SeverityLow, Path: "notes/AGENTS.md",
				Line: 9, Column: 2,
				Message:     "UNC network path reference may leak internal infrastructure naming.",
				Remediation: "Use portable relative paths.",
				Fingerprint: "aaaaaaaaaaaaaaa4", Context: model.ContextInlineCode, Platform: model.PlatformCodex,
			},
			{
				RuleID: "ASG900", Severity: model.SeverityInfo, Path: ".skillguard.yml",
				Line: 1, Column: 1,
				Message:     "Suppression of ASG003 for docs/examples.md expired on 2026-01-01.",
				Remediation: "Remove or renew the suppression.",
				Fingerprint: "aaaaaaaaaaaaaaa5", Context: model.ContextConfig, Platform: model.PlatformGeneric,
			},
		},
		Skipped: []model.SkippedFile{
			{Path: ".env", Reason: "env-file-never-read"},
			{Path: "assets/bundle.zip", Reason: "archive-never-read"},
		},
	}
}

// Adversarial returns a report whose strings attempt HTML and JSON injection.
// Formatters must neutralize every one of them.
func Adversarial() *model.Report {
	return &model.Report{
		SchemaVersion: "1",
		Tool:          model.ToolInfo{Name: "skillguard", Version: "test"},
		RootLabel:     "pkg",
		FilesScanned:  1,
		Findings: []model.Finding{
			{
				RuleID: "ASG008", Severity: model.SeverityHigh,
				Path: "docs/<script>alert(1)</script>.md",
				Line: 1, Column: 1,
				Message:     "Referenced resource \"<img src=x onerror=alert(2)>\" does not exist. \"quotes\" & ampersands \\ backslashes.",
				Remediation: "</details><script>alert(3)</script>",
				Fingerprint: "bbbbbbbbbbbbbbb1", Context: model.ContextProse, Platform: model.PlatformGeneric,
			},
		},
		Skipped: []model.SkippedFile{
			{Path: "<b>bold.env</b>", Reason: "env-file-never-read\"><script>alert(4)</script>"},
		},
	}
}
