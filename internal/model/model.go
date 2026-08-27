// Package model defines the shared data types used across skillguard:
// severities, findings, rule metadata, and the report structure that every
// output format renders from.
package model

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
)

// Severity is the impact level assigned to a finding.
type Severity string

// Supported severities, from most to least severe.
const (
	SeverityCritical Severity = "critical"
	SeverityHigh     Severity = "high"
	SeverityMedium   Severity = "medium"
	SeverityLow      Severity = "low"
	SeverityInfo     Severity = "info"
)

// Severities lists all severities from most to least severe.
var Severities = []Severity{SeverityCritical, SeverityHigh, SeverityMedium, SeverityLow, SeverityInfo}

var severityRank = map[Severity]int{
	SeverityCritical: 4,
	SeverityHigh:     3,
	SeverityMedium:   2,
	SeverityLow:      1,
	SeverityInfo:     0,
}

// Rank returns a comparable rank; higher means more severe.
func (s Severity) Rank() int { return severityRank[s] }

// Valid reports whether s is a known severity.
func (s Severity) Valid() bool { _, ok := severityRank[s]; return ok }

// ParseSeverity parses a severity name (case-insensitive).
func ParseSeverity(raw string) (Severity, error) {
	s := Severity(strings.ToLower(strings.TrimSpace(raw)))
	if !s.Valid() {
		return "", fmt.Errorf("unknown severity %q (expected critical, high, medium, low, or info)", raw)
	}
	return s, nil
}

// FailOn is the exit-code threshold: a severity name or "none".
type FailOn string

// FailOnNone disables the findings-based exit code entirely.
const FailOnNone FailOn = "none"

// ParseFailOn parses a --fail-on / fail_on value.
func ParseFailOn(raw string) (FailOn, error) {
	v := strings.ToLower(strings.TrimSpace(raw))
	if v == string(FailOnNone) {
		return FailOnNone, nil
	}
	s, err := ParseSeverity(v)
	if err != nil {
		return "", fmt.Errorf("unknown fail-on value %q (expected critical, high, medium, low, info, or none)", raw)
	}
	return FailOn(s), nil
}

// Threshold returns the severity threshold, or ok=false when FailOn is "none".
func (f FailOn) Threshold() (Severity, bool) {
	if f == FailOnNone || f == "" {
		return "", false
	}
	return Severity(f), true
}

// MatchContext describes where in a document a finding matched.
type MatchContext string

// Match contexts, in decreasing execution likelihood.
const (
	ContextCodeFence   MatchContext = "code-fence"
	ContextInlineCode  MatchContext = "inline-code"
	ContextFrontmatter MatchContext = "frontmatter"
	ContextProse       MatchContext = "prose"
	ContextConfig      MatchContext = "config"
)

// Platform identifies the agent ecosystem a file belongs to.
type Platform string

// Supported platforms.
const (
	PlatformClaude  Platform = "claude"
	PlatformCodex   Platform = "codex"
	PlatformCursor  Platform = "cursor"
	PlatformGeneric Platform = "generic"
)

// Platforms lists all supported platforms in stable order.
var Platforms = []Platform{PlatformClaude, PlatformCodex, PlatformCursor, PlatformGeneric}

// ParsePlatform parses a platform name (case-insensitive).
func ParsePlatform(raw string) (Platform, error) {
	p := Platform(strings.ToLower(strings.TrimSpace(raw)))
	for _, known := range Platforms {
		if p == known {
			return p, nil
		}
	}
	return "", fmt.Errorf("unknown platform %q (expected codex, claude, cursor, or generic)", raw)
}

// Finding is a single reported issue. Paths always use forward slashes and
// are relative to the scan root; Line and Column are 1-based.
type Finding struct {
	RuleID      string
	Severity    Severity
	Path        string
	Line        int
	Column      int
	Message     string
	Remediation string
	Fingerprint string
	Context     MatchContext
	Platform    Platform

	// FingerprintSalt feeds fingerprint computation and never appears in any
	// report output.
	FingerprintSalt string
}

// ComputeFingerprint derives the stable identity of a finding. It is
// deliberately independent of line and column so that unrelated edits do not
// invalidate suppressions.
func ComputeFingerprint(ruleID, path, salt string) string {
	h := sha256.Sum256([]byte(ruleID + "\x00" + path + "\x00" + salt))
	return hex.EncodeToString(h[:8])
}

// SortFindings orders findings deterministically:
// normalized path, then line, then column, then rule ID.
func SortFindings(fs []Finding) {
	sort.SliceStable(fs, func(i, j int) bool {
		a, b := fs[i], fs[j]
		if a.Path != b.Path {
			return a.Path < b.Path
		}
		if a.Line != b.Line {
			return a.Line < b.Line
		}
		if a.Column != b.Column {
			return a.Column < b.Column
		}
		return a.RuleID < b.RuleID
	})
}

// SkippedFile records a file (or directory) that was noticed but deliberately
// not read, together with a stable reason code.
type SkippedFile struct {
	Path   string
	Reason string
}

// SortSkipped orders skipped entries deterministically by path then reason.
func SortSkipped(sk []SkippedFile) {
	sort.SliceStable(sk, func(i, j int) bool {
		if sk[i].Path != sk[j].Path {
			return sk[i].Path < sk[j].Path
		}
		return sk[i].Reason < sk[j].Reason
	})
}

// RuleMeta is the public metadata of one rule. Rule IDs are a stable API:
// once published they are never renamed or reused.
type RuleMeta struct {
	ID              string
	Title           string
	Summary         string
	DefaultSeverity Severity
	Category        string
	Heuristic       bool
	Rationale       string
	Remediation     string
	SafeExample     string
	UnsafeExample   string
	Contexts        []string
}

// ToolInfo identifies the producing tool inside reports.
type ToolInfo struct {
	Name    string
	Version string
}

// Report is the complete, format-independent result of one scan. It carries
// no timestamps so that identical inputs always produce identical reports.
type Report struct {
	SchemaVersion string
	Tool          ToolInfo
	// RootLabel is the scan root exactly as the user typed it (cleaned,
	// slash form). Only the text renderer may display it; machine-readable
	// formats never embed it, so absolute local paths cannot leak.
	RootLabel    string
	FilesScanned int
	Findings     []Finding
	Skipped      []SkippedFile
	Suppressed   int
}

// CountBySeverity returns finding counts for every severity (zeros included).
func (r *Report) CountBySeverity() map[Severity]int {
	counts := make(map[Severity]int, len(Severities))
	for _, s := range Severities {
		counts[s] = 0
	}
	for _, f := range r.Findings {
		counts[f.Severity]++
	}
	return counts
}

// CountAtOrAbove returns how many findings sit at or above the threshold.
func (r *Report) CountAtOrAbove(threshold Severity) int {
	n := 0
	for _, f := range r.Findings {
		if f.Severity.Rank() >= threshold.Rank() {
			n++
		}
	}
	return n
}
