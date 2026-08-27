package rules

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/Yakitori197/yolab-agent-skill-guard/internal/model"
	"github.com/Yakitori197/yolab-agent-skill-guard/internal/parser"
)

// ASG003 — Destructive Command.
type asg003 struct{}

var asg003Meta = model.RuleMeta{
	ID:              "ASG003",
	Title:           "Destructive Command",
	Summary:         "Commands that can irreversibly destroy files, history, or data.",
	DefaultSeverity: model.SeverityHigh,
	Category:        "dangerous-commands",
	Heuristic:       true,
	Rationale: "Instruction files are executed with high trust by agents. A destructive command embedded in a " +
		"step list can wipe working trees, rewrite git history, or drop database tables before a human reviews " +
		"it. Finding one is a risk signal that the step needs explicit guarding and consent — not proof of malice.",
	Remediation: "Prefer reversible operations (trash instead of rm -rf, git revert instead of reset --hard, " +
		"soft deletes instead of DROP). If a destructive step is genuinely required, gate it behind explicit " +
		"user confirmation and narrow its scope to named paths.",
	SafeExample:   "Ask the user before removing build output, and delete only the named directory.",
	UnsafeExample: "A setup step that tells the agent to run a recursive force delete over the repository root.",
	Contexts:      []string{"prose", "code-fence", "inline-code"},
}

func (asg003) Meta() model.RuleMeta { return asg003Meta }

type cmdPattern struct {
	name  string
	re    *regexp.Regexp
	check func(match string) bool // optional extra validation of the matched span
}

var (
	rmFlagRRe    = regexp.MustCompile(`(?:^|\s)-[A-Za-z]*[rR]|--recursive\b`)
	rmFlagFRe    = regexp.MustCompile(`(?:^|\s)-[A-Za-z]*f|--force\b`)
	gitCleanFRe  = regexp.MustCompile(`(?:^|\s)-[A-Za-z]*f|--force\b`)
	pushForceRe  = regexp.MustCompile(`--force\b|\s-f\b`)
	pushLeaseRe  = regexp.MustCompile(`--force-(with-lease|if-includes)\b`)
	whereRe      = regexp.MustCompile(`(?i)\bwhere\b`)
	recurseRe    = regexp.MustCompile(`(?i)-Recurse\b`)
	forceParamRe = regexp.MustCompile(`(?i)-Force\b`)
)

var destructivePatterns = []cmdPattern{
	{
		name: "recursive force delete (rm)",
		re:   regexp.MustCompile(`\brm\s+((?:-{1,2}[A-Za-z-]+\s+)+)`),
		check: func(m string) bool {
			return rmFlagRRe.MatchString(m) && rmFlagFRe.MatchString(m)
		},
	},
	{
		name: "recursive force delete (Remove-Item)",
		re:   regexp.MustCompile(`(?i)\bRemove-Item\b[^\n]{0,200}`),
		check: func(m string) bool {
			return recurseRe.MatchString(m) && forceParamRe.MatchString(m)
		},
	},
	{
		name:  "git clean with force",
		re:    regexp.MustCompile(`\bgit\s+clean\b([^\n]{0,80})`),
		check: func(m string) bool { return gitCleanFRe.MatchString(m) },
	},
	{
		name: "git reset --hard",
		re:   regexp.MustCompile(`\bgit\s+reset\s+--hard\b`),
	},
	{
		name: "git force push",
		re:   regexp.MustCompile(`\bgit\s+push\b[^\n]{0,120}`),
		check: func(m string) bool {
			return pushForceRe.MatchString(m) && !pushLeaseRe.MatchString(m)
		},
	},
	{
		name: "SQL DROP",
		re:   regexp.MustCompile(`(?i)\bDROP\s+(?:TABLE|DATABASE|SCHEMA)\b`),
	},
	{
		name: "SQL TRUNCATE TABLE",
		re:   regexp.MustCompile(`(?i)\bTRUNCATE\s+TABLE\b`),
	},
	{
		name:  "unconditional SQL DELETE",
		re:    regexp.MustCompile(`(?i)\bDELETE\s+FROM\s+[^\n;]{1,200};?`),
		check: func(m string) bool { return !whereRe.MatchString(m) },
	},
	{
		name: "recursive delete (cmd.exe)",
		re:   regexp.MustCompile(`(?i)\b(?:del|erase|rd|rmdir)\s+(?:/[a-z]\s+)*/s\b`),
	},
	{
		name: "filesystem format",
		re:   regexp.MustCompile(`(?i)\b(?:mkfs(?:\.[a-z0-9]+)?\s|format\s+[a-z]:(?:\s|$))`),
	},
	{
		name: "raw disk overwrite (dd)",
		re:   regexp.MustCompile(`\bdd\s+[^\n]{0,80}of=/dev/(?:sd[a-z]|nvme|disk)`),
	},
}

func (asg003) Check(d *parser.Document, _ *Context) []model.Finding {
	var out []model.Finding
	for i, raw := range d.Lines {
		line := scanLine(raw)
		num := i + 1
		for _, p := range destructivePatterns {
			for _, m := range p.re.FindAllStringIndex(line, -1) {
				match := line[m[0]:m[1]]
				if p.check != nil && !p.check(match) {
					continue
				}
				// Severity never depends on the scanned text around the match.
				// Any "this is only an example" signal is authored by the same
				// hand as the payload, so a document could otherwise rate its
				// own risk down. Documentation that legitimately shows these
				// commands declares a reasoned, expiring suppression instead.
				out = append(out, finding(asg003Meta, d, num, m[0], model.SeverityHigh,
					fmt.Sprintf("Destructive command pattern (%s) detected. This is a risk signal: verify the step is intentional, guarded, and consented — the scanner does not execute or judge intent.", p.name),
					"cmd:"+p.name+":"+strings.TrimSpace(match)))
			}
		}
	}
	return out
}
