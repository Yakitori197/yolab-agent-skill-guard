package rules

import (
	"fmt"
	"math"
	"regexp"

	"github.com/Yakitori197/yolab-agent-skill-guard/internal/model"
	"github.com/Yakitori197/yolab-agent-skill-guard/internal/parser"
	"github.com/Yakitori197/yolab-agent-skill-guard/internal/redact"
)

// ASG001 — Hardcoded Secret.
type asg001 struct{}

var asg001Meta = model.RuleMeta{
	ID:              "ASG001",
	Title:           "Hardcoded Secret",
	Summary:         "High-confidence credential material embedded in scanned text.",
	DefaultSeverity: model.SeverityCritical,
	Category:        "secrets",
	Heuristic:       true,
	Rationale: "Skill and instruction files are shared, forked, and committed to public repositories. " +
		"A credential embedded in them is effectively published: it leaks to every consumer of the package " +
		"and to any model that reads the file. Even revoked tokens reveal naming schemes and infrastructure.",
	Remediation: "Remove the credential and rotate it if it was ever real. Load secrets from the environment " +
		"or a secret manager at runtime, and reference them as placeholders such as ${SERVICE_API_KEY}.",
	SafeExample:   "api_key: ${SERVICE_API_KEY}  # resolved at runtime, never committed",
	UnsafeExample: "api_key: \"<40-character provider token pasted verbatim>\"",
	Contexts:      []string{"prose", "code-fence", "inline-code", "frontmatter"},
}

func (asg001) Meta() model.RuleMeta { return asg001Meta }

type secretPattern struct {
	name    string
	re      *regexp.Regexp
	group   int // capture group holding the secret value; 0 = whole match
	sev     model.Severity
	entropy bool // additionally require high Shannon entropy
	filter  bool // apply the placeholder filter
}

var secretPatterns = []secretPattern{
	{name: "GitHub token", re: regexp.MustCompile(`\bgh[pousr]_[A-Za-z0-9]{36,251}\b`), sev: model.SeverityCritical},
	{name: "GitHub fine-grained token", re: regexp.MustCompile(`\bgithub_pat_[A-Za-z0-9_]{22,255}\b`), sev: model.SeverityCritical},
	{name: "AWS access key ID", re: regexp.MustCompile(`\b(?:AKIA|ASIA|ABIA|ACCA)[A-Z0-9]{16}\b`), sev: model.SeverityCritical},
	{name: "Slack token", re: regexp.MustCompile(`\bxox[baprs]-[A-Za-z0-9-]{10,64}\b`), sev: model.SeverityCritical},
	{name: "JWT", re: regexp.MustCompile(`\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b`), sev: model.SeverityHigh},
	{name: "provider API key", re: regexp.MustCompile(`\bsk-(?:ant-)?[A-Za-z0-9_-]{20,120}\b`), sev: model.SeverityCritical},
	{
		name:  "connection string with embedded password",
		re:    regexp.MustCompile(`\b(?:postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|redis|amqps?|mssql|ftp)://([^\s:@/]{1,64}):([^\s@/]{1,256})@`),
		group: 2, sev: model.SeverityCritical, filter: true,
	},
	{
		name:  "assigned secret value",
		re:    regexp.MustCompile(`(?i)["']?\b(?:api[_-]?key|apikey|api[_-]?secret|secret[_-]?key|client[_-]?secret|access[_-]?token|auth[_-]?token|password|passwd)\b["']?\s*[:=]\s*["']([A-Za-z0-9+/_.=-]{16,256})["']`),
		group: 1, sev: model.SeverityHigh, entropy: true, filter: true,
	},
}

var privateKeyRe = regexp.MustCompile(`-----BEGIN [A-Z ]{0,24}PRIVATE KEY(?: BLOCK)?-----`)

var placeholderValueRe = regexp.MustCompile(`(?i)(example|sample|placeholder|change-?me|your[_-]?|dummy|fake|xxxx|\.\.\.|<[^>]*>|\$\{|\{\{|%[A-Za-z_]+%|redacted|to-?do|not-?a-?real|insert)`)

func looksPlaceholder(v string) bool {
	if placeholderValueRe.MatchString(v) {
		return true
	}
	uniq := map[rune]bool{}
	for _, r := range v {
		uniq[r] = true
	}
	return len(uniq) <= 2
}

func shannonEntropy(v string) float64 {
	if v == "" {
		return 0
	}
	counts := map[rune]int{}
	total := 0
	for _, r := range v {
		counts[r]++
		total++
	}
	e := 0.0
	for _, c := range counts {
		p := float64(c) / float64(total)
		e -= p * math.Log2(p)
	}
	return e
}

func (asg001) Check(d *parser.Document, _ *Context) []model.Finding {
	var out []model.Finding
	for i, raw := range d.Lines {
		line := scanLine(raw)
		num := i + 1
		for _, m := range privateKeyRe.FindAllStringIndex(line, -1) {
			out = append(out, finding(asg001Meta, d, num, m[0], model.SeverityCritical,
				"Private key block header detected; key material must never ship inside a skill package.",
				"privkey:"+line[m[0]:m[1]]))
		}
		for _, sp := range secretPatterns {
			for _, m := range sp.re.FindAllStringSubmatchIndex(line, -1) {
				vs, ve := m[0], m[1]
				if sp.group > 0 {
					vs, ve = m[2*sp.group], m[2*sp.group+1]
				}
				if vs < 0 || ve < 0 {
					continue
				}
				secret := line[vs:ve]
				if sp.filter && looksPlaceholder(secret) {
					continue
				}
				if sp.entropy && shannonEntropy(secret) < 3.0 {
					continue
				}
				out = append(out, finding(asg001Meta, d, num, m[0], sp.sev,
					fmt.Sprintf("Possible %s detected (masked: %s). Treat this as a risk signal and rotate the credential if it is real.",
						sp.name, redact.Secret(secret)),
					"secret:"+sp.name+":"+secret))
			}
		}
	}
	return out
}
