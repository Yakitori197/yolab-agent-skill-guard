package rules

import (
	"fmt"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/Yakitori197/yolab-agent-skill-guard/internal/model"
	"github.com/Yakitori197/yolab-agent-skill-guard/internal/parser"
)

// ASG006 — Excessive Tool Permission.
type asg006 struct{}

var asg006Meta = model.RuleMeta{
	ID:              "ASG006",
	Title:           "Excessive Tool Permission",
	Summary:         "Skill declares or demands broader tool access than its task needs.",
	DefaultSeverity: model.SeverityHigh,
	Category:        "permissions",
	Heuristic:       true,
	Rationale: "Least privilege limits the blast radius of both bugs and prompt injection. A skill that " +
		"requests wildcard or unscoped shell access can be abused for anything at all if any of its " +
		"instructions are subverted, so breadth of permission is itself a risk signal.",
	Remediation: "Scope each tool grant to the narrowest pattern that still works (for example a single " +
		"command family instead of an unscoped shell), and declare only capabilities the configuration allows.",
	SafeExample:   "allowed-tools listing one scoped entry such as a read-only search tool.",
	UnsafeExample: "allowed-tools containing a bare wildcard entry granting every tool.",
	Contexts:      []string{"frontmatter", "prose"},
}

func (asg006) Meta() model.RuleMeta { return asg006Meta }

var (
	bareShellRe   = regexp.MustCompile(`(?i)^(bash|shell|powershell|sh|zsh|cmd|terminal|exec)$`)
	broadScopedRe = regexp.MustCompile(`(?i)^(bash|shell|powershell|sh|zsh|cmd)\((\*|\*:\*)\)$`)
	broadValueRe  = regexp.MustCompile(`(?i)^(all|full|unrestricted|\*)$`)
	broadProseRe  = regexp.MustCompile(`(?i)\b(unrestricted|full|unlimited|complete)\s+(shell|filesystem|file system|disk|system|network)\s+access\b` +
		`|\b(?:request|require|need|grant|give|enable|allow)\w*\s+(?:for\s+)?(?:all|every)\s+(?:the\s+)?(?:tool\s+|available\s+)?permissions?\b`)
)

var permissionListKeys = []string{"allowed-tools", "allowed_tools", "tools"}

func (asg006) Check(d *parser.Document, ctx *Context) []model.Finding {
	var out []model.Finding
	fm := d.Frontmatter
	if fm != nil && fm.Present && fm.Fields != nil {
		for _, key := range permissionListKeys {
			n, ok := fm.Field(key)
			if !ok || n.Kind != yaml.SequenceNode {
				continue
			}
			for _, item := range n.Content {
				v, isStr := parser.ScalarString(item)
				if !isStr {
					continue
				}
				entry := strings.TrimSpace(v)
				switch {
				case entry == "*":
					out = append(out, finding(asg006Meta, d, fm.Line(item), 0, model.SeverityCritical,
						fmt.Sprintf("%s grants a bare wildcard (*): every tool becomes available, which defeats least privilege.", key),
						"perm:wildcard:"+key))
				case broadScopedRe.MatchString(entry):
					out = append(out, finding(asg006Meta, d, fm.Line(item), 0, model.SeverityHigh,
						fmt.Sprintf("%s entry %q grants an effectively unscoped shell. Scope it to the specific command family the skill needs.", key, entry),
						"perm:broadscope:"+entry))
				case bareShellRe.MatchString(entry):
					out = append(out, finding(asg006Meta, d, fm.Line(item), 0, model.SeverityHigh,
						fmt.Sprintf("%s entry %q grants unscoped shell access. Scope it to the specific command family the skill needs.", key, entry),
						"perm:bareshell:"+entry))
				}
			}
		}
		for _, key := range []string{"permissions", "filesystem", "network"} {
			if n, ok := fm.Field(key); ok {
				if v, isStr := parser.ScalarString(n); isStr && broadValueRe.MatchString(strings.TrimSpace(v)) {
					out = append(out, finding(asg006Meta, d, fm.Line(n), 0, model.SeverityHigh,
						fmt.Sprintf("Frontmatter sets %s: %q, an unbounded grant. Declare the narrowest access that still works.", key, v),
						"perm:broadkey:"+key+":"+v))
				}
			}
		}
		if n, ok := fm.Field("capabilities"); ok && n.Kind == yaml.SequenceNode {
			for _, item := range n.Content {
				v, isStr := parser.ScalarString(item)
				if !isStr {
					continue
				}
				capName := strings.TrimSpace(v)
				if capName == "" || strings.EqualFold(capName, "network") {
					continue // network is ASG005's concern
				}
				if !ctx.Config.CapabilityAllowed(capName) {
					out = append(out, finding(asg006Meta, d, fm.Line(item), 0, model.SeverityMedium,
						fmt.Sprintf("Frontmatter declares capability %q, which the configuration does not include in allowed_capabilities.", capName),
						"perm:cap:"+capName))
				}
			}
		}
	}
	for i, raw := range d.Lines {
		line := scanLine(raw)
		num := i + 1
		for _, m := range broadProseRe.FindAllStringIndex(line, -1) {
			// Reported regardless of any disclaimer on the same line: the
			// request is in the file either way.
			out = append(out, finding(asg006Meta, d, num, m[0], model.SeverityMedium,
				fmt.Sprintf("Content requests %q; blanket access requests are a risk signal and should be narrowed.", line[m[0]:m[1]]),
				"perm:prose:"+strings.ToLower(line[m[0]:m[1]])))
		}
	}
	return out
}
