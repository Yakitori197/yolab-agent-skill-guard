package rules

import (
	"fmt"
	"regexp"

	"github.com/Yakitori197/yolab-agent-skill-guard/internal/model"
	"github.com/Yakitori197/yolab-agent-skill-guard/internal/parser"
)

// ASG010 — Prompt Injection Signal.
type asg010 struct{}

var asg010Meta = model.RuleMeta{
	ID:              "ASG010",
	Title:           "Prompt Injection Signal",
	Summary:         "Phrases that try to override an agent's instructions or hide actions from the user.",
	DefaultSeverity: model.SeverityHigh,
	Category:        "injection",
	Heuristic:       true,
	Rationale: "Agents read instruction files with high trust. Phrases that tell the agent to ignore prior " +
		"instructions, bypass safety checks, act secretly, or exfiltrate data are the canonical shape of a " +
		"prompt-injection payload. Matching them is intrinsically heuristic — the rule flags language for " +
		"human review and never claims the file is malicious.",
	Remediation: "Rewrite instructions to work with the host platform's rules instead of against them. " +
		"Legitimate skills never need the agent to hide actions from the user or to abandon prior instructions.",
	SafeExample:   "Tell the agent to ignore generated files when reviewing a diff.",
	UnsafeExample: "Text instructing the agent to disregard all previous instructions and hide its actions.",
	Contexts:      []string{"prose", "code-fence", "inline-code"},
}

func (asg010) Meta() model.RuleMeta { return asg010Meta }

// The object nouns are deliberately restricted to instruction-like words so
// that everyday phrases ("ignore generated files") never match.
var injectionPatterns = []struct {
	name string
	re   *regexp.Regexp
}{
	{"override prior instructions", regexp.MustCompile(`(?i)\bignore\s+(?:all\s+|any\s+)?(?:previous|prior|earlier|above|preceding|system)\s+(?:instructions?|prompts?|rules?|messages?|directives?)`)},
	{"disregard guardrails", regexp.MustCompile(`(?i)\bdisregard\s+(?:the\s+|all\s+|your\s+)?(?:system\s+prompt|instructions?|safety|guidelines?|rules?|guardrails?)`)},
	{"bypass safety controls", regexp.MustCompile(`(?i)\b(?:override|bypass|circumvent|disable|turn\s+off)\s+(?:the\s+|all\s+|any\s+|your\s+)?(?:safety|security|permission|approval|confirmation|guardrails?|content\s+filters?|restrictions?)`)},
	{"hide actions from the user", regexp.MustCompile(`(?i)\bwithout\s+(?:telling|informing|asking|notifying|alerting)\s+the\s+user\b`)},
	{"conceal from the user", regexp.MustCompile(`(?i)\bdo\s+not\s+(?:tell|inform|reveal|show|mention)\s+(?:this\s+)?(?:to\s+)?the\s+user\b`)},
	{"conceal activity", regexp.MustCompile(`(?i)\b(?:hide|conceal)\s+(?:this|these|your)\s+(?:actions?|steps?|commands?|activity|changes?)\b`)},
	// Verb forms only: prose *discussing* "exfiltration" (noun) is normal in
	// security documentation and must not be flagged.
	{"exfiltration instruction", regexp.MustCompile(`(?i)\bexfiltrat(?:e|ing)\b|\bsend\s+[^\n]{0,80}?(?:credentials?|secrets?|tokens?|passwords?|api\s+keys?)\s+to\b`)},
	{"system prompt extraction", regexp.MustCompile(`(?i)\breveal\s+(?:your\s+)?(?:system\s+prompt|hidden\s+instructions)`)},
	{"authority impersonation", regexp.MustCompile(`(?i)\bpretend\s+(?:you\s+are|to\s+be)\s+(?:the\s+)?(?:system|administrator|admin|root)\b`)},
	{"instruction reset", regexp.MustCompile(`(?i)\bnew\s+system\s+prompt\s*:|\byou\s+are\s+no\s+longer\s+bound\b`)},
}

func (asg010) Check(d *parser.Document, _ *Context) []model.Finding {
	var out []model.Finding
	for i, raw := range d.Lines {
		line := scanLine(raw)
		num := i + 1
		for _, p := range injectionPatterns {
			for _, m := range p.re.FindAllStringIndex(line, -1) {
				// Neither quoting context nor a nearby prohibition lowers this
				// finding; both are written by whoever wrote the payload.
				out = append(out, finding(asg010Meta, d, num, m[0], model.SeverityHigh,
					fmt.Sprintf("Prompt-injection signal (%s): %q. This is a heuristic risk signal that requires human review.", p.name, line[m[0]:m[1]]),
					"inject:"+p.name+":"+line[m[0]:m[1]]))
			}
		}
	}
	return out
}
