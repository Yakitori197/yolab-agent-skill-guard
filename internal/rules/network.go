package rules

import (
	"fmt"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/Yakitori197/yolab-agent-skill-guard/internal/model"
	"github.com/Yakitori197/yolab-agent-skill-guard/internal/parser"
)

// ASG005 — Undeclared Network Access.
type asg005 struct{}

var asg005Meta = model.RuleMeta{
	ID:              "ASG005",
	Title:           "Undeclared Network Access",
	Summary:         "Content instructs network access to hosts the configuration does not allow.",
	DefaultSeverity: model.SeverityMedium,
	Category:        "network",
	Heuristic:       true,
	Rationale: "Offline-first skills should declare every external endpoint they contact. An instruction that " +
		"reaches out to an undeclared host may exfiltrate context, fetch mutable payloads, or simply surprise " +
		"the operator. Requiring an allow-list makes the network surface reviewable.",
	Remediation: "List every legitimately required host under allowed_domains in .skillguard.yml, or remove " +
		"the network step. Declare a \"network\" capability in frontmatter only when configuration permits it.",
	SafeExample:   "allowed_domains lists api.example-partner.com, and the skill only calls that host.",
	UnsafeExample: "A code block that uploads scan results to an arbitrary host absent from allowed_domains.",
	Contexts:      []string{"prose", "code-fence", "inline-code", "frontmatter"},
}

func (asg005) Meta() model.RuleMeta { return asg005Meta }

var (
	urlHostRe   = regexp.MustCompile(`\bhttps?://([A-Za-z0-9._-]{1,255})(?::\d{1,5})?[^\s"'<>\)\]]*`)
	exfilVerbRe = regexp.MustCompile(`(?i)\b(send|upload|post|submit|transmit|forward|sync|report)\b`)
)

// reservedHost reports RFC 2606 / loopback hosts that are documentation-only
// or local, and therefore never count as external network access.
func reservedHost(host string) bool {
	h := strings.ToLower(host)
	switch h {
	case "localhost", "127.0.0.1", "0.0.0.0", "::1":
		return true
	}
	for _, suffix := range []string{".localhost", ".example", ".test", ".invalid"} {
		if strings.HasSuffix(h, suffix) {
			return true
		}
	}
	for _, doc := range []string{"example.com", "example.org", "example.net"} {
		if h == doc || strings.HasSuffix(h, "."+doc) {
			return true
		}
	}
	return false
}

func (asg005) Check(d *parser.Document, ctx *Context) []model.Finding {
	var out []model.Finding
	seenHosts := map[string]bool{}
	for i, raw := range d.Lines {
		line := scanLine(raw)
		num := i + 1
		for _, m := range urlHostRe.FindAllStringSubmatchIndex(line, -1) {
			host := line[m[2]:m[3]]
			if reservedHost(host) || ctx.Config.DomainAllowed(host) {
				continue
			}
			mctx := d.ContextAt(num, m[0])
			intent := mctx == model.ContextCodeFence || mctx == model.ContextInlineCode
			if !intent && exfilVerbRe.MatchString(line) {
				intent = true // prose that instructs sending data to the URL
			}
			if !intent {
				continue // plain documentation links are not network instructions
			}
			key := strings.ToLower(host)
			if seenHosts[key] {
				continue
			}
			seenHosts[key] = true
			out = append(out, finding(asg005Meta, d, num, m[0], model.SeverityMedium,
				fmt.Sprintf("Content references network access to host %q, which is not covered by allowed_domains. Declare the host or remove the network step.", host),
				"nethost:"+key))
		}
	}
	// Frontmatter capability declaration.
	if fm := d.Frontmatter; fm != nil && fm.Present && fm.Fields != nil {
		if n, ok := fm.Field("network"); ok {
			if v, isStr := parser.ScalarString(n); (isStr && v != "" && v != "false") || n.Tag == "!!bool" && n.Value == "true" {
				if !ctx.Config.CapabilityAllowed("network") {
					out = append(out, finding(asg005Meta, d, fm.Line(n), 0, model.SeverityMedium,
						"Frontmatter declares the \"network\" capability, but the configuration does not include it in allowed_capabilities.",
						"netcap:network"))
				}
			}
		}
		if n, ok := fm.Field("capabilities"); ok && n.Kind == yaml.SequenceNode {
			for _, item := range n.Content {
				if v, isStr := parser.ScalarString(item); isStr && strings.EqualFold(strings.TrimSpace(v), "network") {
					if !ctx.Config.CapabilityAllowed("network") {
						out = append(out, finding(asg005Meta, d, fm.Line(item), 0, model.SeverityMedium,
							"Frontmatter lists the \"network\" capability, but the configuration does not include it in allowed_capabilities.",
							"netcap:capabilities:network"))
					}
				}
			}
		}
	}
	return out
}
