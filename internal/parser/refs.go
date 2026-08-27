package parser

import "regexp"

// Ref is a link-like reference extracted from Markdown. Only prose links are
// treated as real references: links inside code fences or inline code are
// examples, not resource declarations.
type Ref struct {
	Target  string
	Line    int // 1-based
	ByteOff int // byte offset of the target within the line
	Kind    string
}

// Ref kinds.
const (
	RefLink     = "link"
	RefImage    = "image"
	RefDef      = "refdef"
	RefAutolink = "autolink"
)

var (
	inlineLinkRe = regexp.MustCompile(`(!?)\[[^\]]{0,500}\]\(\s*(<[^<>\n]{1,1000}>|[^()\s]{1,1000}(?:\([^()\n]{0,200}\)[^()\s]{0,1000})?)\s*(?:"[^"\n]{0,500}")?\s*\)`)
	refDefRe     = regexp.MustCompile(`^ {0,3}\[[^\]]{1,500}\]:\s+(\S{1,1000})`)
	autolinkRe   = regexp.MustCompile(`<((?:https?|ftp)://[^<>\s]{1,1000})>`)
)

// ExtractRefs walks the document and returns references in document order.
func ExtractRefs(d *Document) []Ref {
	var refs []Ref
	for i, line := range d.Lines {
		num := i + 1
		info := d.LineInfo[i]
		if info.Frontmatter || info.Fence {
			continue
		}
		spans := d.inlineCache(num)
		inCode := func(off int) bool {
			for _, sp := range spans {
				if off >= sp[0] && off < sp[1] {
					return true
				}
			}
			return false
		}
		if m := refDefRe.FindStringSubmatchIndex(line); m != nil {
			refs = append(refs, Ref{Target: trimAngle(line[m[2]:m[3]]), Line: num, ByteOff: m[2], Kind: RefDef})
			continue
		}
		for _, m := range inlineLinkRe.FindAllStringSubmatchIndex(line, -1) {
			if inCode(m[0]) {
				continue
			}
			kind := RefLink
			if line[m[2]:m[3]] == "!" {
				kind = RefImage
			}
			refs = append(refs, Ref{Target: trimAngle(line[m[4]:m[5]]), Line: num, ByteOff: m[4], Kind: kind})
		}
		for _, m := range autolinkRe.FindAllStringSubmatchIndex(line, -1) {
			if inCode(m[0]) {
				continue
			}
			refs = append(refs, Ref{Target: line[m[2]:m[3]], Line: num, ByteOff: m[2], Kind: RefAutolink})
		}
	}
	return refs
}

func trimAngle(s string) string {
	if len(s) >= 2 && s[0] == '<' && s[len(s)-1] == '>' {
		return s[1 : len(s)-1]
	}
	return s
}
