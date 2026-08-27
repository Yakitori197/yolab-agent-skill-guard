package rules

import (
	"fmt"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/Yakitori197/yolab-agent-skill-guard/internal/model"
	"github.com/Yakitori197/yolab-agent-skill-guard/internal/parser"
)

// ASG009 — Invalid Manifest.
type asg009 struct{}

var asg009Meta = model.RuleMeta{
	ID:              "ASG009",
	Title:           "Invalid Manifest",
	Summary:         "Frontmatter that is missing, malformed, or of the wrong shape.",
	DefaultSeverity: model.SeverityMedium,
	Category:        "structure",
	Heuristic:       false,
	Rationale: "The frontmatter manifest is how platforms decide when and how to load a skill. Missing or " +
		"mistyped fields make loading unpredictable: some hosts refuse the package, others load it with " +
		"defaults the author never intended.",
	Remediation: "Give every SKILL.md a YAML frontmatter mapping with string name and description fields; " +
		"keep field types as documented and remove duplicate keys.",
	SafeExample:   "Frontmatter with name: my-skill and a one-line description.",
	UnsafeExample: "A SKILL.md with no frontmatter, or a name field holding a number.",
	Contexts:      []string{"frontmatter"},
}

func (asg009) Meta() model.RuleMeta { return asg009Meta }

var skillNameRe = regexp.MustCompile(`^[a-z0-9]+(?:-[a-z0-9]+)*$`)

func sanitizeYAMLErr(err error) string {
	msg := err.Error()
	if idx := strings.IndexByte(msg, '\n'); idx >= 0 {
		msg = msg[:idx]
	}
	if len(msg) > 160 {
		msg = msg[:160] + "…"
	}
	return msg
}

func (asg009) Check(d *parser.Document, _ *Context) []model.Finding {
	var out []model.Finding
	fm := d.Frontmatter
	base := strings.ToLower(d.RelPath)
	if idx := strings.LastIndex(base, "/"); idx >= 0 {
		base = base[idx+1:]
	}
	isSkill := base == "skill.md"
	isCursorRule := strings.HasSuffix(base, ".mdc")

	if fm == nil || !fm.Present {
		if isSkill {
			out = append(out, finding(asg009Meta, d, 1, 0, model.SeverityHigh,
				"SKILL.md requires YAML frontmatter declaring at least name and description.",
				"manifest:missing-frontmatter"))
		}
		return out
	}
	if fm.Oversized {
		out = append(out, finding(asg009Meta, d, 1, 0, model.SeverityMedium,
			fmt.Sprintf("Frontmatter exceeds the %d-byte parsing limit and was not validated.", parser.MaxFrontmatterBytes),
			"manifest:oversized"))
		return out
	}
	if fm.ParseErr != nil {
		out = append(out, finding(asg009Meta, d, 1, 0, model.SeverityHigh,
			fmt.Sprintf("Frontmatter is not valid YAML: %s.", sanitizeYAMLErr(fm.ParseErr)),
			"manifest:yaml-error"))
		return out
	}
	if fm.NotMapping {
		out = append(out, finding(asg009Meta, d, 1, 0, model.SeverityHigh,
			"Frontmatter must be a YAML mapping of fields, not a list or scalar.",
			"manifest:not-mapping"))
		return out
	}
	for _, dup := range fm.Duplicates {
		out = append(out, finding(asg009Meta, d, dup.Line, 0, model.SeverityMedium,
			fmt.Sprintf("Duplicate frontmatter key %q; only the first occurrence is honored, which invites drift.", dup.Key),
			"manifest:dup:"+dup.Key))
	}

	if isSkill {
		out = append(out, checkSkillManifest(d, fm)...)
	}
	if isCursorRule {
		out = append(out, checkCursorManifest(d, fm)...)
	}
	if n, ok := fm.Field("platforms"); ok {
		if n.Kind != yaml.SequenceNode {
			out = append(out, finding(asg009Meta, d, fm.Line(n), 0, model.SeverityMedium,
				"Frontmatter field \"platforms\" must be a list of platform names.",
				"manifest:platforms-type"))
		} else {
			for _, item := range n.Content {
				v, isStr := parser.ScalarString(item)
				if !isStr {
					out = append(out, finding(asg009Meta, d, fm.Line(item), 0, model.SeverityMedium,
						"Frontmatter \"platforms\" entries must be strings.",
						"manifest:platforms-item-type"))
					continue
				}
				if _, err := model.ParsePlatform(v); err != nil {
					out = append(out, finding(asg009Meta, d, fm.Line(item), 0, model.SeverityMedium,
						fmt.Sprintf("Frontmatter \"platforms\" lists unknown platform %q (expected codex, claude, cursor, or generic).", v),
						"manifest:platforms-value:"+v))
				}
			}
		}
	}
	if n, ok := fm.Field("schema_version"); ok {
		if n.Kind != yaml.ScalarNode || n.Tag != "!!int" || n.Value != "1" {
			out = append(out, finding(asg009Meta, d, fm.Line(n), 0, model.SeverityMedium,
				fmt.Sprintf("Frontmatter schema_version %q is not supported; this build supports schema_version 1.", n.Value),
				"manifest:schema-version:"+n.Value))
		}
	}
	return out
}

func checkSkillManifest(d *parser.Document, fm *parser.Frontmatter) []model.Finding {
	var out []model.Finding
	nameNode, hasName := fm.Field("name")
	if !hasName {
		out = append(out, finding(asg009Meta, d, fm.StartLine, 0, model.SeverityHigh,
			"SKILL.md frontmatter is missing the required \"name\" field.",
			"manifest:missing:name"))
	} else if v, isStr := parser.ScalarString(nameNode); !isStr || strings.TrimSpace(v) == "" {
		out = append(out, finding(asg009Meta, d, fm.Line(nameNode), 0, model.SeverityHigh,
			"SKILL.md frontmatter \"name\" must be a non-empty string.",
			"manifest:type:name"))
	} else {
		if !skillNameRe.MatchString(v) {
			out = append(out, finding(asg009Meta, d, fm.Line(nameNode), 0, model.SeverityLow,
				fmt.Sprintf("Skill name %q does not match the conventional lowercase-hyphen form (a-z, 0-9, hyphens).", v),
				"manifest:name-format:"+v))
		}
		if len(v) > 64 {
			out = append(out, finding(asg009Meta, d, fm.Line(nameNode), 0, model.SeverityLow,
				"Skill name is longer than 64 characters; long names are truncated or rejected by some hosts.",
				"manifest:name-length"))
		}
	}
	descNode, hasDesc := fm.Field("description")
	if !hasDesc {
		out = append(out, finding(asg009Meta, d, fm.StartLine, 0, model.SeverityHigh,
			"SKILL.md frontmatter is missing the required \"description\" field.",
			"manifest:missing:description"))
	} else if v, isStr := parser.ScalarString(descNode); !isStr || strings.TrimSpace(v) == "" {
		out = append(out, finding(asg009Meta, d, fm.Line(descNode), 0, model.SeverityHigh,
			"SKILL.md frontmatter \"description\" must be a non-empty string.",
			"manifest:type:description"))
	} else if len(v) > 4096 {
		out = append(out, finding(asg009Meta, d, fm.Line(descNode), 0, model.SeverityInfo,
			"Skill description is unusually long (over 4096 characters); hosts may truncate it.",
			"manifest:description-length"))
	}
	for _, key := range []string{"allowed-tools", "allowed_tools"} {
		if n, ok := fm.Field(key); ok && n.Kind != yaml.SequenceNode {
			out = append(out, finding(asg009Meta, d, fm.Line(n), 0, model.SeverityMedium,
				fmt.Sprintf("Frontmatter field %q must be a list of tool patterns.", key),
				"manifest:type:"+key))
		}
	}
	for _, key := range []string{"version", "license"} {
		if n, ok := fm.Field(key); ok {
			if _, isStr := parser.ScalarString(n); !isStr {
				out = append(out, finding(asg009Meta, d, fm.Line(n), 0, model.SeverityLow,
					fmt.Sprintf("Frontmatter field %q should be a string.", key),
					"manifest:type:"+key))
			}
		}
	}
	return out
}

func checkCursorManifest(d *parser.Document, fm *parser.Frontmatter) []model.Finding {
	var out []model.Finding
	if n, ok := fm.Field("globs"); ok {
		if n.Kind != yaml.ScalarNode && n.Kind != yaml.SequenceNode {
			out = append(out, finding(asg009Meta, d, fm.Line(n), 0, model.SeverityMedium,
				"Cursor rule field \"globs\" must be a string or a list of strings.",
				"manifest:type:globs"))
		}
	}
	if n, ok := fm.Field("alwaysApply"); ok {
		if n.Kind != yaml.ScalarNode || n.Tag != "!!bool" {
			out = append(out, finding(asg009Meta, d, fm.Line(n), 0, model.SeverityMedium,
				"Cursor rule field \"alwaysApply\" must be a boolean.",
				"manifest:type:alwaysApply"))
		}
	}
	if n, ok := fm.Field("description"); ok {
		if _, isStr := parser.ScalarString(n); !isStr {
			out = append(out, finding(asg009Meta, d, fm.Line(n), 0, model.SeverityMedium,
				"Cursor rule field \"description\" must be a string.",
				"manifest:type:description"))
		}
	}
	return out
}
