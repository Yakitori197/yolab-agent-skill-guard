package rules

import (
	"fmt"
	"regexp"

	"github.com/Yakitori197/yolab-agent-skill-guard/internal/model"
	"github.com/Yakitori197/yolab-agent-skill-guard/internal/parser"
)

// ASG012 — Obfuscated Payload.
type asg012 struct{}

var asg012Meta = model.RuleMeta{
	ID:              "ASG012",
	Title:           "Obfuscated Payload",
	Summary:         "Large encoded blobs, especially near decode-and-execute instructions.",
	DefaultSeverity: model.SeverityHigh,
	Category:        "obfuscation",
	Heuristic:       true,
	Rationale: "Reviewers cannot audit what they cannot read. A large base64/hex blob hides its real content, " +
		"and when the surrounding text asks for it to be decoded and executed, the pattern matches how " +
		"malware ships payloads. The scanner never decodes or executes the blob — it only flags the shape.",
	Remediation: "Ship logic as reviewable plain text inside the package. If binary data is unavoidable, " +
		"distribute it as a separate checksummed artifact — never as an inline blob the agent must decode " +
		"and run.",
	SafeExample:   "A small data: URI image embedded in documentation.",
	UnsafeExample: "A 500-character base64 blob followed by an instruction to decode it and pipe it to a shell.",
	Contexts:      []string{"prose", "code-fence", "inline-code"},
}

func (asg012) Meta() model.RuleMeta { return asg012Meta }

const (
	b64AdjacencyLen  = 120 // blob length that counts when decode/execute is adjacent
	b64StandaloneLen = 400 // blob length that is reported even without adjacency
)

var (
	b64RunRe     = regexp.MustCompile(`[A-Za-z0-9+/]{120,}={0,2}`)
	hexEscRunRe  = regexp.MustCompile(`(?i)(?:\\x[0-9a-f]{2}){40,}`)
	hexRunRe     = regexp.MustCompile(`(?i)\b[0-9a-f]{120,}\b`)
	decodeExecRe = regexp.MustCompile(`(?i)base64\s+(?:-d|--decode)|FromBase64String|-EncodedCommand\b|\batob\s*\(|Invoke-Expression|\biex\b|\beval\b|\|\s*(?:ba|z)?sh\b|\|\s*python[0-9.]*\b`)
	encCmdRe     = regexp.MustCompile(`(?i)\b(?:powershell|pwsh)(?:\.exe)?\s+[^\n]{0,120}-(?:e|en|enc|encodedcommand)\s+[A-Za-z0-9+/=]{40,}`)
	charCodeRe   = regexp.MustCompile(`(?i)String\.fromCharCode\s*\(\s*(?:\d+\s*,\s*){15,}`)
	evalAtobRe   = regexp.MustCompile(`(?i)\beval\s*\(\s*atob\s*\(`)
	dataURIRe    = regexp.MustCompile(`(?i)data:[a-z0-9.+/-]+;base64,$`)
)

// nearDecodeExec reports whether a decode-or-execute marker appears within
// two lines of line index i.
func nearDecodeExec(d *parser.Document, i int) bool {
	lo, hi := i-2, i+2
	if lo < 0 {
		lo = 0
	}
	if hi > len(d.Lines)-1 {
		hi = len(d.Lines) - 1
	}
	for j := lo; j <= hi; j++ {
		if decodeExecRe.MatchString(scanLine(d.Lines[j])) {
			return true
		}
	}
	return false
}

func blobSalt(prefix, blob string) string {
	head := blob
	if len(head) > 24 {
		head = head[:24]
	}
	return fmt.Sprintf("%s:%s:%d", prefix, head, len(blob))
}

func (asg012) Check(d *parser.Document, _ *Context) []model.Finding {
	var out []model.Finding
	for i, raw := range d.Lines {
		line := scanLine(raw)
		num := i + 1
		for _, m := range encCmdRe.FindAllStringIndex(line, -1) {
			out = append(out, finding(asg012Meta, d, num, m[0], model.SeverityCritical,
				"PowerShell encoded command detected; the payload is unreadable to reviewers and executes on decode. The scanner did not decode it.",
				blobSalt("enccmd", line[m[0]:m[1]])))
		}
		for _, m := range evalAtobRe.FindAllStringIndex(line, -1) {
			out = append(out, finding(asg012Meta, d, num, m[0], model.SeverityCritical,
				"eval(atob(…)) decodes and executes hidden content in one step; ship reviewable plain code instead.",
				blobSalt("evalatob", line[m[0]:m[1]])))
		}
		for _, m := range charCodeRe.FindAllStringIndex(line, -1) {
			sev := model.SeverityHigh
			if decodeExecRe.MatchString(line) {
				sev = model.SeverityCritical
			}
			out = append(out, finding(asg012Meta, d, num, m[0], sev,
				"Long String.fromCharCode sequence assembles hidden text at runtime; this obfuscation is a risk signal requiring review.",
				blobSalt("charcode", line[m[0]:m[1]])))
		}
		for _, m := range b64RunRe.FindAllStringIndex(line, -1) {
			blob := line[m[0]:m[1]]
			if dataURIRe.MatchString(line[:m[0]]) && !nearDecodeExec(d, i) {
				continue // inline data: URIs (images) are normal in docs
			}
			switch {
			case nearDecodeExec(d, i):
				out = append(out, finding(asg012Meta, d, num, m[0], model.SeverityCritical,
					fmt.Sprintf("Base64-looking blob (%d chars) sits next to decode-and-execute instructions. The scanner did not decode it; review the payload before any use.", len(blob)),
					blobSalt("b64exec", blob)))
			case len(blob) >= b64StandaloneLen:
				out = append(out, finding(asg012Meta, d, num, m[0], model.SeverityMedium,
					fmt.Sprintf("Large opaque base64-looking blob (%d chars) cannot be reviewed as text; document its origin or ship it as a checksummed artifact.", len(blob)),
					blobSalt("b64", blob)))
			}
		}
		for _, re := range []*regexp.Regexp{hexEscRunRe, hexRunRe} {
			for _, m := range re.FindAllStringIndex(line, -1) {
				blob := line[m[0]:m[1]]
				switch {
				case nearDecodeExec(d, i):
					out = append(out, finding(asg012Meta, d, num, m[0], model.SeverityCritical,
						fmt.Sprintf("Hex-encoded blob (%d chars) sits next to decode-and-execute instructions. The scanner did not decode it; review the payload before any use.", len(blob)),
						blobSalt("hexexec", blob)))
				case len(blob) >= b64StandaloneLen:
					out = append(out, finding(asg012Meta, d, num, m[0], model.SeverityMedium,
						fmt.Sprintf("Large opaque hex blob (%d chars) cannot be reviewed as text; document its origin or ship it as a checksummed artifact.", len(blob)),
						blobSalt("hex", blob)))
				}
			}
		}
	}
	return out
}
