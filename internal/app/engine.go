package app

import (
	"fmt"
	"os"
	"path"
	"path/filepath"
	"time"

	"github.com/Yakitori197/yolab-agent-skill-guard/internal/config"
	"github.com/Yakitori197/yolab-agent-skill-guard/internal/discovery"
	"github.com/Yakitori197/yolab-agent-skill-guard/internal/model"
	"github.com/Yakitori197/yolab-agent-skill-guard/internal/parser"
	"github.com/Yakitori197/yolab-agent-skill-guard/internal/pathsafe"
	"github.com/Yakitori197/yolab-agent-skill-guard/internal/rules"
	"github.com/Yakitori197/yolab-agent-skill-guard/internal/version"
)

// ReportSchemaVersion identifies the format-independent report model.
const ReportSchemaVersion = "1"

// ScanMode selects which rule subset runs.
type ScanMode int

// Scan modes.
const (
	ModeFull ScanMode = iota
	ModeValidate
)

// validate mode runs only the structural rules.
var validateRuleIDs = map[string]bool{"ASG007": true, "ASG008": true, "ASG009": true}

// ScanOptions parameterizes one engine run.
type ScanOptions struct {
	RootArg string
	Config  *config.Config
	Mode    ScanMode
	Now     time.Time
	// ShowPaths opts into printing the full local scan root in the text
	// report. Off by default so shared output never carries a local layout.
	ShowPaths bool
}

// RedactedRoot is what the text report shows instead of an absolute scan root.
const RedactedRoot = "<scan-root>"

// displayPath renders a user-supplied path for messages.
//
// Relative inputs are shown as typed (cleaned, slash form) because they carry
// no information about the machine. Absolute inputs are reduced to their last
// element so an error or a shared report never publishes a local directory
// layout; skillguard scan --show-paths opts back into full paths for local
// debugging.
func displayPath(p string) string {
	clean := pathsafe.ToSlash(filepath.Clean(p))
	if !isAbsoluteInput(p) {
		return clean
	}
	base := path.Base(clean)
	if base == "" || base == "." || base == "/" {
		return RedactedRoot
	}
	return ".../" + base
}

// displayRoot renders the scan root for the text report header.
func displayRoot(p string, showPaths bool) string {
	if showPaths {
		return pathsafe.ToSlash(filepath.Clean(p))
	}
	if isAbsoluteInput(p) {
		return RedactedRoot
	}
	return pathsafe.ToSlash(filepath.Clean(p))
}

// isAbsoluteInput reports whether the user typed an absolute (or home-relative)
// path in any platform spelling.
func isAbsoluteInput(p string) bool {
	if filepath.IsAbs(p) || pathsafe.IsAbsoluteLike(p) {
		return true
	}
	return false
}

// loadConfig resolves the effective configuration: an explicit --config file,
// else .skillguard.yml at the scan root, else built-in defaults. Any config
// error fails closed.
func loadConfig(flagPath, rootAbs string) (*config.Config, error) {
	known := rules.IDs()
	detection := rules.DetectionIDs()
	if flagPath != "" {
		raw, err := os.ReadFile(flagPath)
		if err != nil {
			return nil, fmt.Errorf("cannot read config file %q", displayPath(flagPath))
		}
		return config.Parse(raw, displayPath(flagPath), known, detection)
	}
	p := filepath.Join(rootAbs, ".skillguard.yml")
	raw, err := os.ReadFile(p)
	if err != nil {
		if os.IsNotExist(err) {
			return config.Default(), nil
		}
		return nil, fmt.Errorf("cannot read config file %q", ".skillguard.yml")
	}
	return config.Parse(raw, ".skillguard.yml", known, detection)
}

// resolveRoot turns the path argument into an absolute scan root, handling
// the single-file form.
func resolveRoot(rootArg string) (rootAbs, singleFile string, err error) {
	abs, err := filepath.Abs(rootArg)
	if err != nil {
		return "", "", fmt.Errorf("cannot resolve scan path %q", displayPath(rootArg))
	}
	info, err := os.Stat(abs)
	if err != nil {
		return "", "", fmt.Errorf("cannot access scan path %q", displayPath(rootArg))
	}
	if info.IsDir() {
		return abs, "", nil
	}
	return filepath.Dir(abs), filepath.Base(abs), nil
}

// runScan executes discovery, parsing, rules, and post-processing.
func runScan(opts ScanOptions) (*model.Report, error) {
	rootAbs, singleFile, err := resolveRoot(opts.RootArg)
	if err != nil {
		return nil, err
	}
	cfg := opts.Config

	var disc *discovery.Result
	if singleFile != "" {
		disc, err = discovery.Single(rootAbs, singleFile, cfg)
	} else {
		disc, err = discovery.Walk(rootAbs, cfg)
	}
	if err != nil {
		return nil, fmt.Errorf("discovery failed under %q", displayPath(opts.RootArg))
	}

	report := &model.Report{
		SchemaVersion: ReportSchemaVersion,
		Tool:          model.ToolInfo{Name: "skillguard", Version: version.Version},
		RootLabel:     displayRoot(opts.RootArg, opts.ShowPaths),
		Skipped:       disc.Skipped,
	}

	ctx := &rules.Context{
		Config: cfg,
		// Observed by listing the scan root and asking whether it resolves one
		// of its own entries under a differently-cased spelling — never
		// assumed from the operating system. It describes the root directory
		// itself; Windows lets a nested directory differ, which this single
		// answer does not model. It selects how reference paths are compared
		// for reporting and authorizes no filesystem access (see
		// discovery.FoldsCase and discovery.WithinRootAbs).
		FoldCase: discovery.FoldsCase(rootAbs),
		FileExists: func(rel string) bool {
			if pathsafe.HasDotDot(rel) {
				return false
			}
			_, statErr := os.Stat(filepath.Join(rootAbs, filepath.FromSlash(rel)))
			return statErr == nil
		},
		ResolveReal: func(rel string) (inside, exists bool) {
			if pathsafe.HasDotDot(rel) {
				return false, false
			}
			p := filepath.Join(rootAbs, filepath.FromSlash(rel))
			if _, statErr := os.Lstat(p); statErr != nil {
				return true, false
			}
			real, evalErr := filepath.EvalSymlinks(p)
			if evalErr != nil {
				return true, false
			}
			in, cErr := discovery.WithinRootAbs(rootAbs, real)
			if cErr != nil {
				return true, false
			}
			return in, true
		},
	}

	ruleSet := activeRules(cfg, opts.Mode)
	for _, cand := range disc.Candidates {
		// One bounded, containment-checked read per candidate; discovery
		// never opens files itself (see discovery.ReadCandidate).
		raw, skipReason := discovery.ReadCandidate(rootAbs, cand, cfg.MaxFileSize)
		if skipReason != "" {
			report.Skipped = append(report.Skipped, model.SkippedFile{Path: cand.RelPath, Reason: skipReason})
			continue
		}
		doc := parser.Load(cand.RelPath, cand.Platform, cand.PackageRoot, raw)
		for _, r := range ruleSet {
			report.Findings = append(report.Findings, r.Check(doc, ctx)...)
		}
		report.FilesScanned++
	}
	postProcess(report, cfg, opts.Now)
	return report, nil
}

func activeRules(cfg *config.Config, mode ScanMode) []rules.Rule {
	var out []rules.Rule
	for _, r := range rules.All() {
		id := r.Meta().ID
		if mode == ModeValidate && !validateRuleIDs[id] {
			continue
		}
		if cfg.RuleDisabled(id) {
			continue
		}
		out = append(out, r)
	}
	return out
}

// postProcess applies severity overrides, computes fingerprints, resolves
// suppressions, surfaces expired suppressions, and fixes the final order.
func postProcess(report *model.Report, cfg *config.Config, now time.Time) {
	for i := range report.Findings {
		f := &report.Findings[i]
		if sev, ok := cfg.SeverityOverrides[f.RuleID]; ok {
			f.Severity = sev
		}
		f.Fingerprint = model.ComputeFingerprint(f.RuleID, f.Path, f.FingerprintSalt)
	}

	kept := report.Findings[:0]
	for _, f := range report.Findings {
		suppressed := false
		for i := range cfg.Suppressions {
			s := &cfg.Suppressions[i]
			if s.Expired(now) {
				continue
			}
			if s.Matches(f) {
				suppressed = true
				break
			}
		}
		if suppressed {
			report.Suppressed++
		} else {
			kept = append(kept, f)
		}
	}
	report.Findings = kept

	meta, _ := rules.MetaByID("ASG900")
	for i := range cfg.Suppressions {
		s := &cfg.Suppressions[i]
		if !s.Expired(now) {
			continue
		}
		target := s.Path
		if target == "" {
			target = "fingerprint " + s.Fingerprint
		}
		f := model.Finding{
			RuleID:   meta.ID,
			Severity: meta.DefaultSeverity,
			Path:     cfg.Source,
			Line:     1,
			Column:   1,
			Message: fmt.Sprintf("Suppression of %s for %s expired on %s and no longer applies; remove it or extend the expiry after review.",
				s.Rule, target, s.Expires),
			Remediation:     meta.Remediation,
			Context:         model.ContextConfig,
			Platform:        model.PlatformGeneric,
			FingerprintSalt: "expired:" + s.Rule + ":" + s.Path + ":" + s.Fingerprint + ":" + s.Expires,
		}
		f.Fingerprint = model.ComputeFingerprint(f.RuleID, f.Path, f.FingerprintSalt)
		report.Findings = append(report.Findings, f)
	}

	model.SortFindings(report.Findings)
	model.SortSkipped(report.Skipped)
	for i := range report.Findings {
		report.Findings[i].FingerprintSalt = ""
	}
}
