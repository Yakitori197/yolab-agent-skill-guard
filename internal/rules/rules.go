// Package rules implements the skillguard rule catalog. Every rule is a pure
// text analysis: rules never execute commands, never resolve URLs, and never
// read files outside the scan root. Heuristic rules report risk signals that
// require human review; they never assert that content is malicious.
package rules

import (
	"sort"
	"strings"

	"github.com/Yakitori197/yolab-agent-skill-guard/internal/config"
	"github.com/Yakitori197/yolab-agent-skill-guard/internal/model"
	"github.com/Yakitori197/yolab-agent-skill-guard/internal/parser"
)

// maxLineScan caps how many bytes of a single line are pattern-matched, as a
// guard against pathological inputs. Findings past the cap on one line are
// deliberately traded for bounded work (documented limitation).
const maxLineScan = 64 * 1024

// Context supplies the environment rules may consult. Filesystem access is
// injected so rules never touch the disk directly and tests can simulate any
// layout.
type Context struct {
	Config *config.Config
	// FileExists reports whether the root-relative slash path exists.
	FileExists func(rel string) bool
	// ResolveReal resolves symlinks for a root-relative path. It reports
	// whether the final target stays inside the root and whether it exists.
	ResolveReal func(rel string) (inside bool, exists bool)
	// FoldCase selects how reference paths are compared for *reporting*:
	// whether a reference is judged to have left its skill package, and how
	// missing references are de-duplicated. It must come from an observation
	// of the directory actually holding the paths (discovery.FoldsCase), never
	// from runtime.GOOS — macOS ships both case-insensitive and case-sensitive
	// APFS, and Windows resolves names per directory. Folding is the more
	// permissive answer, so an unknown filesystem must pass false.
	//
	// It authorizes nothing. Filesystem access is gated by ResolveReal, which
	// is backed by discovery.WithinRootAbs and does not fold case at all.
	FoldCase bool
}

// Rule is one detection rule.
type Rule interface {
	Meta() model.RuleMeta
	Check(d *parser.Document, ctx *Context) []model.Finding
}

// All returns every rule ordered by ID.
func All() []Rule {
	rs := []Rule{
		asg001{}, asg002{}, asg003{}, asg004{}, asg005{}, asg006{},
		asg007{}, asg008{}, asg009{}, asg010{}, asg011{}, asg012{},
		asg900{},
	}
	sort.SliceStable(rs, func(i, j int) bool { return rs[i].Meta().ID < rs[j].Meta().ID })
	return rs
}

// Catalog returns metadata for every rule ordered by ID.
func Catalog() []model.RuleMeta {
	all := All()
	metas := make([]model.RuleMeta, 0, len(all))
	for _, r := range all {
		metas = append(metas, r.Meta())
	}
	return metas
}

// IDs returns all rule IDs including governance meta-rules.
func IDs() []string {
	all := All()
	ids := make([]string, 0, len(all))
	for _, r := range all {
		ids = append(ids, r.Meta().ID)
	}
	return ids
}

// DetectionIDs returns rule IDs excluding governance meta-rules (ASG900),
// which cannot be disabled because they report configuration hygiene.
func DetectionIDs() []string {
	var ids []string
	for _, r := range All() {
		if r.Meta().Category == "governance" {
			continue
		}
		ids = append(ids, r.Meta().ID)
	}
	return ids
}

// MetaByID looks up one rule's metadata (exact ID match).
func MetaByID(id string) (model.RuleMeta, bool) {
	for _, r := range All() {
		if r.Meta().ID == id {
			return r.Meta(), true
		}
	}
	return model.RuleMeta{}, false
}

// MetaIndex returns rule metadata keyed by ID.
func MetaIndex() map[string]model.RuleMeta {
	idx := make(map[string]model.RuleMeta)
	for _, r := range All() {
		idx[r.Meta().ID] = r.Meta()
	}
	return idx
}

// finding assembles a Finding with position, context, and fingerprint salt.
// line is 1-based; byteOff is the byte offset within that line.
func finding(meta model.RuleMeta, d *parser.Document, line, byteOff int, sev model.Severity, msg, salt string) model.Finding {
	col := 1
	ctx := model.ContextProse
	if line >= 1 && line <= len(d.Lines) {
		col = parser.ColumnAt(d.Lines[line-1], byteOff)
		ctx = d.ContextAt(line, byteOff)
	} else if line < 1 {
		line = 1
	}
	return model.Finding{
		RuleID:          meta.ID,
		Severity:        sev,
		Path:            d.RelPath,
		Line:            line,
		Column:          col,
		Message:         msg,
		Remediation:     meta.Remediation,
		Context:         ctx,
		Platform:        d.Platform,
		FingerprintSalt: salt,
	}
}

// scanLine returns the (possibly truncated) text used for pattern matching.
func scanLine(line string) string {
	if len(line) > maxLineScan {
		return line[:maxLineScan]
	}
	return line
}

// insideURL reports whether the byte offset sits inside a URL token
// (a whitespace-delimited token containing "://" before the offset).
func insideURL(line string, off int) bool {
	start := off
	for start > 0 && !isSpace(line[start-1]) {
		start--
	}
	return strings.Contains(line[start:off], "://")
}

func isSpace(b byte) bool { return b == ' ' || b == '\t' }
