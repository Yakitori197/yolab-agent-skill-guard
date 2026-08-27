package rules

import (
	"fmt"
	"strings"

	"github.com/Yakitori197/yolab-agent-skill-guard/internal/model"
	"github.com/Yakitori197/yolab-agent-skill-guard/internal/parser"
	"github.com/Yakitori197/yolab-agent-skill-guard/internal/pathsafe"
)

// ASG007 — Path Escape.
type asg007 struct{}

var asg007Meta = model.RuleMeta{
	ID:              "ASG007",
	Title:           "Path Escape",
	Summary:         "References that resolve outside the allowed package root.",
	DefaultSeverity: model.SeverityHigh,
	Category:        "structure",
	Heuristic:       false,
	Rationale: "A skill package must be self-contained. A reference that resolves above the package root — " +
		"via .., mixed separators, percent-encoding, absolute paths, or symlinks — can pull in files the " +
		"reviewer never saw, and on another machine it either breaks or reads something unintended.",
	Remediation: "Keep every referenced resource inside the package directory and reference it with a plain " +
		"relative path. Copy shared assets into the package instead of reaching outside it.",
	SafeExample:   "A link to references/guide.md inside the same skill directory.",
	UnsafeExample: "A link that climbs out of the package with ../../ or an absolute path.",
	Contexts:      []string{"prose"},
}

func (asg007) Meta() model.RuleMeta { return asg007Meta }

// ASG008 — Missing Reference.
type asg008 struct{}

var asg008Meta = model.RuleMeta{
	ID:              "ASG008",
	Title:           "Missing Reference",
	Summary:         "Declared local resources that do not exist.",
	DefaultSeverity: model.SeverityMedium,
	Category:        "structure",
	Heuristic:       false,
	Rationale: "Instruction files routinely tell an agent to open referenced resources. A missing file makes " +
		"the skill silently degrade, and in the worst case the agent improvises the missing content.",
	Remediation:   "Create the referenced file, fix the path, or delete the stale reference.",
	SafeExample:   "A link to checklist.md that exists next to the SKILL.md.",
	UnsafeExample: "A link to steps/setup.md that is absent from the package.",
	Contexts:      []string{"prose"},
}

func (asg008) Meta() model.RuleMeta { return asg008Meta }

// refOutcome captures the analysis of one reference.
type refOutcome struct {
	ref      parser.Ref
	escape   bool
	missing  bool
	sev      model.Severity
	msg      string
	salt     string
	resolved string
}

func analyzeRefs(d *parser.Document, ctx *Context) []refOutcome {
	var outcomes []refOutcome
	seenMissing := map[string]bool{}
	for _, ref := range d.Refs() {
		t := strings.TrimSpace(ref.Target)
		if t == "" || strings.HasPrefix(t, "#") {
			continue
		}
		lower := strings.ToLower(t)
		if strings.HasPrefix(lower, "file:") {
			outcomes = append(outcomes, refOutcome{ref: ref, escape: true, sev: model.SeverityMedium,
				msg:  "Reference uses a file: URL, which is machine-specific. Package resources must use relative paths.",
				salt: "abs:" + t})
			continue
		}
		if pathsafe.IsExternal(t) {
			continue
		}
		if pathsafe.IsAbsoluteLike(t) {
			outcomes = append(outcomes, refOutcome{ref: ref, escape: true, sev: model.SeverityMedium,
				msg:  "Absolute path reference points outside the package; skills must reference resources relatively.",
				salt: "abs:" + t})
			continue
		}
		noFrag := strings.SplitN(t, "#", 2)[0]
		noFrag = strings.SplitN(noFrag, "?", 2)[0]
		if noFrag == "" {
			continue
		}
		decoded, changed := pathsafe.PercentDecode(noFrag)
		norm := pathsafe.ToSlash(decoded)
		resolved, escapedRoot := pathsafe.ResolveWithin(d.DirRel(), norm)
		if escapedRoot {
			detail := ""
			if changed {
				detail = " The traversal was hidden behind percent-encoding."
			}
			outcomes = append(outcomes, refOutcome{ref: ref, escape: true, sev: model.SeverityHigh,
				msg:  fmt.Sprintf("Reference %q resolves outside the scan root.%s", t, detail),
				salt: "escape:" + resolved})
			continue
		}
		if d.PackageRoot != "" && !pathsafe.WithinDir(d.PackageRoot, resolved, ctx.FoldCase) {
			outcomes = append(outcomes, refOutcome{ref: ref, escape: true, sev: model.SeverityMedium,
				msg:  fmt.Sprintf("Reference %q leaves its skill package directory (%s/). Skills must be self-contained.", t, d.PackageRoot),
				salt: "pkg-escape:" + resolved})
			continue
		}
		inside, exists := ctx.ResolveReal(resolved)
		if !inside {
			outcomes = append(outcomes, refOutcome{ref: ref, escape: true, sev: model.SeverityHigh,
				msg:  fmt.Sprintf("Reference %q resolves outside the scan root through a symbolic link.", t),
				salt: "symlink-escape:" + resolved})
			continue
		}
		if !exists {
			key := resolved
			if ctx.FoldCase {
				key = strings.ToLower(key)
			}
			if seenMissing[key] {
				continue
			}
			seenMissing[key] = true
			outcomes = append(outcomes, refOutcome{ref: ref, missing: true, sev: model.SeverityMedium,
				msg:  fmt.Sprintf("Referenced local resource %q does not exist in the package.", t),
				salt: "missing:" + resolved, resolved: resolved})
		}
	}
	return outcomes
}

func (asg007) Check(d *parser.Document, ctx *Context) []model.Finding {
	var out []model.Finding
	for _, o := range analyzeRefs(d, ctx) {
		if !o.escape {
			continue
		}
		out = append(out, finding(asg007Meta, d, o.ref.Line, o.ref.ByteOff, o.sev, o.msg, o.salt))
	}
	return out
}

func (asg008) Check(d *parser.Document, ctx *Context) []model.Finding {
	var out []model.Finding
	for _, o := range analyzeRefs(d, ctx) {
		if !o.missing {
			continue
		}
		out = append(out, finding(asg008Meta, d, o.ref.Line, o.ref.ByteOff, o.sev, o.msg, o.salt))
	}
	return out
}
