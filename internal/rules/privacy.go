package rules

import (
	"fmt"
	"regexp"

	"github.com/Yakitori197/yolab-agent-skill-guard/internal/model"
	"github.com/Yakitori197/yolab-agent-skill-guard/internal/parser"
	"github.com/Yakitori197/yolab-agent-skill-guard/internal/redact"
)

// ASG002 — Private Absolute Path.
type asg002 struct{}

var asg002Meta = model.RuleMeta{
	ID:              "ASG002",
	Title:           "Private Absolute Path",
	Summary:         "Absolute paths that may leak usernames or private directory layout.",
	DefaultSeverity: model.SeverityMedium,
	Category:        "privacy",
	Heuristic:       true,
	Rationale: "Home-directory paths embed the author's account name and machine layout. Shared instruction " +
		"files containing them leak personal information and break on every other machine, because the paths " +
		"only resolve for the original author.",
	Remediation: "Replace absolute personal paths with package-relative paths, or use placeholders such as " +
		"~, %USERPROFILE%, or ${HOME} when a home directory is genuinely meant.",
	SafeExample:   "Store the cache under ~/.cache/mytool (any user's home).",
	UnsafeExample: "Read the notes from C:\\Users\\ExampleUser\\Documents\\notes.md",
	Contexts:      []string{"prose", "code-fence", "inline-code", "frontmatter"},
}

func (asg002) Meta() model.RuleMeta { return asg002Meta }

var (
	winUserRe = regexp.MustCompile(`(?i)\b[A-Za-z]:[\\/](?:Users|Documents and Settings)[\\/]([^\\/:*?"<>|\s]{1,64})`)
	nixHomeRe = regexp.MustCompile(`/(?:home|Users)/([A-Za-z0-9._-]{1,64})`)
	uncRe     = regexp.MustCompile(`\\\\[A-Za-z0-9._-]{1,64}\\[A-Za-z0-9._$-]{1,64}`)
	// Placeholder syntaxes that clearly do not name a real account.
	placeholderUserRe = regexp.MustCompile(`^(<[^>]*>?|%[^%]*%?|\$\{?[A-Za-z_][A-Za-z0-9_]*\}?|\{\{.*|~)$`)
)

func (asg002) Check(d *parser.Document, _ *Context) []model.Finding {
	var out []model.Finding
	for i, raw := range d.Lines {
		line := scanLine(raw)
		num := i + 1
		for _, m := range winUserRe.FindAllStringSubmatchIndex(line, -1) {
			user := line[m[2]:m[3]]
			if placeholderUserRe.MatchString(user) {
				continue
			}
			match := line[m[0]:m[1]]
			out = append(out, finding(asg002Meta, d, num, m[0], model.SeverityMedium,
				fmt.Sprintf("Windows user-profile path \"%s\" may leak a real username and will not resolve on other machines.",
					redact.PathUser(match, user)),
				"winpath:"+match))
		}
		for _, m := range nixHomeRe.FindAllStringSubmatchIndex(line, -1) {
			if insideURL(line, m[0]) {
				continue
			}
			if m[0] > 0 && line[m[0]-1] == ':' {
				continue // drive-letter form (C:/Users/...) is winUserRe's match
			}
			user := line[m[2]:m[3]]
			if placeholderUserRe.MatchString(user) {
				continue
			}
			match := line[m[0]:m[1]]
			out = append(out, finding(asg002Meta, d, num, m[0], model.SeverityMedium,
				fmt.Sprintf("Home-directory path \"%s\" may leak a real username and will not resolve on other machines.",
					redact.PathUser(match, user)),
				"nixpath:"+match))
		}
		for _, m := range uncRe.FindAllStringIndex(line, -1) {
			match := line[m[0]:m[1]]
			out = append(out, finding(asg002Meta, d, num, m[0], model.SeverityLow,
				"UNC network path reference may leak internal infrastructure naming and is unreachable outside the original network.",
				"unc:"+match))
		}
	}
	return out
}
