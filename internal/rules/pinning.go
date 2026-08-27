package rules

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/Yakitori197/yolab-agent-skill-guard/internal/model"
	"github.com/Yakitori197/yolab-agent-skill-guard/internal/parser"
)

// ASG011 — Unpinned Remote Dependency.
type asg011 struct{}

var asg011Meta = model.RuleMeta{
	ID:              "ASG011",
	Title:           "Unpinned Remote Dependency",
	Summary:         "Remote scripts, actions, or refs addressed by mutable tag or branch.",
	DefaultSeverity: model.SeverityMedium,
	Category:        "supply-chain",
	Heuristic:       true,
	Rationale: "A tag or branch can be moved after review, so an instruction that fetches by mutable " +
		"reference may run different code tomorrow than it ran today. Immutable references (full commit " +
		"SHAs, checksummed artifacts) make the supply chain reviewable.",
	Remediation: "Pin GitHub Actions and raw-content URLs to full 40-character commit SHAs, and pin installed " +
		"tools to exact versions. Record why each pinned version was chosen.",
	SafeExample:   "uses: an action pinned to a full commit SHA with the version noted in a comment.",
	UnsafeExample: "uses: an action addressed by a floating tag, or installing a tool at @latest.",
	Contexts:      []string{"prose", "code-fence", "inline-code"},
}

func (asg011) Meta() model.RuleMeta { return asg011Meta }

var (
	usesRe           = regexp.MustCompile(`(?i)\buses:\s*([A-Za-z0-9._-]+/[A-Za-z0-9._/-]+)@([^\s#"']+)`)
	rawGHRe          = regexp.MustCompile(`https://raw\.githubusercontent\.com/([^/\s]+)/([^/\s]+)/([^/\s]+)/[^\s"'<>\)]+`)
	gitPlusRe        = regexp.MustCompile(`\bgit\+https?://[^\s@"']{1,300}@([A-Za-z0-9._/-]{1,100})`)
	goLatestRe       = regexp.MustCompile(`\bgo\s+(?:install|run)\s+[^\s@]{1,300}@latest\b`)
	npxLatestRe      = regexp.MustCompile(`\b(?:npm\s+(?:install|i|exec)|npx|pnpm\s+(?:add|dlx)|yarn\s+(?:add|dlx))\s+[^\s@]{0,300}@latest\b`)
	releasesLatestRe = regexp.MustCompile(`https://github\.com/[^/\s]+/[^/\s]+/releases/latest/download/[^\s"'<>\)]+`)
	hex40Re          = regexp.MustCompile(`^[0-9a-f]{40}$`)
	// Placeholder refs: <angle-placeholders>, ${{ expressions }} (possibly
	// truncated at whitespace by the ref capture), {{ templates }}, $VARS.
	placeholderRefRe = regexp.MustCompile(`^(<[^>]*>?|\$\{\{.*|\{\{.*|\$[A-Za-z_][A-Za-z0-9_]*)$`)
)

func (asg011) Check(d *parser.Document, _ *Context) []model.Finding {
	var out []model.Finding
	for i, raw := range d.Lines {
		line := scanLine(raw)
		num := i + 1
		for _, m := range usesRe.FindAllStringSubmatchIndex(line, -1) {
			target := line[m[2]:m[3]]
			ref := line[m[4]:m[5]]
			if strings.HasPrefix(target, "./") || strings.Contains(ref, "sha256:") ||
				hex40Re.MatchString(ref) || placeholderRefRe.MatchString(ref) {
				continue
			}
			out = append(out, finding(asg011Meta, d, num, m[0], model.SeverityMedium,
				fmt.Sprintf("GitHub Action %q is pinned to mutable ref %q; pin to a full commit SHA (with the version in a comment).", target, ref),
				"pin:uses:"+target+"@"+ref))
		}
		for _, m := range rawGHRe.FindAllStringSubmatchIndex(line, -1) {
			ref := line[m[6]:m[7]]
			if hex40Re.MatchString(ref) || placeholderRefRe.MatchString(ref) {
				continue
			}
			out = append(out, finding(asg011Meta, d, num, m[0], model.SeverityMedium,
				fmt.Sprintf("raw.githubusercontent.com URL addresses mutable ref %q; the served content can change after review. Pin to a full commit SHA.", ref),
				"pin:raw:"+line[m[0]:m[1]]))
		}
		for _, m := range gitPlusRe.FindAllStringSubmatchIndex(line, -1) {
			ref := line[m[2]:m[3]]
			if hex40Re.MatchString(ref) || placeholderRefRe.MatchString(ref) {
				continue
			}
			out = append(out, finding(asg011Meta, d, num, m[0], model.SeverityMedium,
				fmt.Sprintf("git+ dependency addresses mutable ref %q; tags and branches can move. Pin to a full commit SHA.", ref),
				"pin:git:"+line[m[0]:m[1]]))
		}
		for _, m := range goLatestRe.FindAllStringIndex(line, -1) {
			out = append(out, finding(asg011Meta, d, num, m[0], model.SeverityMedium,
				"Tool installation at @latest resolves to different code over time; pin an exact version.",
				"pin:golatest:"+strings.TrimSpace(line[m[0]:m[1]])))
		}
		for _, m := range npxLatestRe.FindAllStringIndex(line, -1) {
			out = append(out, finding(asg011Meta, d, num, m[0], model.SeverityMedium,
				"Package execution at @latest resolves to different code over time; pin an exact version.",
				"pin:npmlatest:"+strings.TrimSpace(line[m[0]:m[1]])))
		}
		for _, m := range releasesLatestRe.FindAllStringIndex(line, -1) {
			out = append(out, finding(asg011Meta, d, num, m[0], model.SeverityMedium,
				"Download from releases/latest changes content on every release; pin a specific release asset and verify its checksum.",
				"pin:releaselatest:"+line[m[0]:m[1]]))
		}
	}
	return out
}
