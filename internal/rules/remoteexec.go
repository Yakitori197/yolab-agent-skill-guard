package rules

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/Yakitori197/yolab-agent-skill-guard/internal/model"
	"github.com/Yakitori197/yolab-agent-skill-guard/internal/parser"
)

// ASG004 — Remote Pipe Execution.
type asg004 struct{}

var asg004Meta = model.RuleMeta{
	ID:              "ASG004",
	Title:           "Remote Pipe Execution",
	Summary:         "Content downloaded from the network and executed without review.",
	DefaultSeverity: model.SeverityCritical,
	Category:        "supply-chain",
	Heuristic:       true,
	Rationale: "Piping a download straight into a shell executes whatever the remote host serves at that " +
		"moment. The server can change the payload at any time, target specific victims, or be compromised — " +
		"and nothing on disk records what actually ran. In agent instructions this pattern hands remote " +
		"parties direct code execution.",
	Remediation: "Download to a file, review it, pin it by checksum or immutable reference, and only then " +
		"execute the reviewed copy.",
	SafeExample:   "Download the installer, verify its published SHA-256 checksum, then run the verified file.",
	UnsafeExample: "A setup step that pipes a curl download directly into a shell interpreter.",
	Contexts:      []string{"prose", "code-fence", "inline-code"},
}

func (asg004) Meta() model.RuleMeta { return asg004Meta }

var remoteExecPatterns = []struct {
	name string
	re   *regexp.Regexp
}{
	{"download piped to shell", regexp.MustCompile(`\b(?:curl|wget)\b[^\n|]{0,300}\|\s*(?:sudo\s+)?(?:ba|z|da|k)?sh\b`)},
	{"download piped to PowerShell", regexp.MustCompile(`(?i)\b(?:curl|wget|iwr|irm|Invoke-WebRequest|Invoke-RestMethod)\b[^\n|]{0,300}\|\s*(?:iex|Invoke-Expression|powershell|pwsh)\b`)},
	{"Invoke-Expression of downloaded content", regexp.MustCompile(`(?i)\b(?:iex|Invoke-Expression)\b[^\n]{0,300}\b(?:DownloadString|Invoke-WebRequest|Invoke-RestMethod|\birm\b|\biwr\b)`)},
	{"process-substitution download", regexp.MustCompile(`\b(?:ba|z)?sh\s+<\(\s*(?:curl|wget)\b`)},
	{"shell -c of downloaded content", regexp.MustCompile(`\b(?:ba|z|da)?sh\s+-c\s+["']?\$\((?:curl|wget)\b`)},
	{"download piped to Python", regexp.MustCompile(`\b(?:curl|wget)\b[^\n|]{0,300}\|\s*(?:sudo\s+)?python[0-9.]*\b`)},
}

func (asg004) Check(d *parser.Document, _ *Context) []model.Finding {
	var out []model.Finding
	for i, raw := range d.Lines {
		line := scanLine(raw)
		num := i + 1
		for _, p := range remoteExecPatterns {
			for _, m := range p.re.FindAllStringIndex(line, -1) {
				// Severity is fixed by the rule, never by the surrounding text:
				// a hostile file must not be able to argue its own risk down.
				out = append(out, finding(asg004Meta, d, num, m[0], model.SeverityCritical,
					fmt.Sprintf("Remote pipe-to-execute pattern (%s) detected. Whatever the remote host serves would run unreviewed; this is a supply-chain risk signal.", p.name),
					"pipe:"+p.name+":"+strings.TrimSpace(line[m[0]:m[1]])))
			}
		}
	}
	return out
}
