package parser

import (
	"fmt"
	"strings"

	"gopkg.in/yaml.v3"
)

// MaxFrontmatterBytes bounds how much leading YAML the parser is willing to
// process; larger blocks are reported instead of parsed.
const MaxFrontmatterBytes = 256 * 1024

// DuplicateKey records a repeated top-level frontmatter key.
type DuplicateKey struct {
	Key  string
	Line int // 1-based line within the whole document
}

// Frontmatter is the parsed leading YAML block of a document. Parsing is
// strictly read-only and defensive: malformed input becomes structured error
// state, never a crash.
type Frontmatter struct {
	Present    bool
	Raw        string
	StartLine  int // line of the opening --- (always 1 when present)
	EndLine    int // line of the closing --- (or ...)
	ParseErr   error
	NotMapping bool
	Root       *yaml.Node            // mapping node; nil unless parsed cleanly
	Fields     map[string]*yaml.Node // first occurrence of each top-level key
	Order      []string              // top-level keys in document order (first occurrences)
	Duplicates []DuplicateKey
	Oversized  bool
}

// Line converts a yaml.Node position (relative to the YAML block) into a
// document line number.
func (f *Frontmatter) Line(n *yaml.Node) int {
	if n == nil {
		return f.StartLine
	}
	return f.StartLine + n.Line
}

// Field returns the node of a top-level key.
func (f *Frontmatter) Field(key string) (*yaml.Node, bool) {
	if f == nil || f.Fields == nil {
		return nil, false
	}
	n, ok := f.Fields[key]
	return n, ok
}

// ScalarString reports the value when n is a scalar resolved as a string.
func ScalarString(n *yaml.Node) (string, bool) {
	if n == nil || n.Kind != yaml.ScalarNode {
		return "", false
	}
	if n.Tag == "!!str" || n.Tag == "" {
		return n.Value, true
	}
	return "", false
}

// splitFrontmatter returns the raw YAML (without markers) plus marker lines.
// A document has frontmatter when line 1 is exactly "---" and a closing "---"
// (or "...") line exists further down. An unclosed leading "---" is treated
// as a Markdown thematic break, not as frontmatter.
func splitFrontmatter(lines []string) (raw string, start, end int, ok bool) {
	if len(lines) == 0 || strings.TrimRight(lines[0], " \t") != "---" {
		return "", 0, 0, false
	}
	for i := 1; i < len(lines); i++ {
		t := strings.TrimRight(lines[i], " \t")
		if t == "---" || t == "..." {
			return strings.Join(lines[1:i], "\n"), 1, i + 1, true
		}
	}
	return "", 0, 0, false
}

// parseFrontmatter parses the YAML block defensively. yaml.v3 can panic on
// some crafted inputs, and a scanner must never crash on untrusted text, so
// the unmarshal step runs behind a recover guard.
func parseFrontmatter(lines []string) *Frontmatter {
	raw, start, end, ok := splitFrontmatter(lines)
	if !ok {
		return &Frontmatter{Present: false}
	}
	fm := &Frontmatter{Present: true, Raw: raw, StartLine: start, EndLine: end}
	if len(raw) > MaxFrontmatterBytes {
		fm.Oversized = true
		return fm
	}
	var doc yaml.Node
	if err := safeUnmarshal([]byte(raw), &doc); err != nil {
		fm.ParseErr = err
		return fm
	}
	if len(doc.Content) == 0 {
		fm.Fields = map[string]*yaml.Node{}
		return fm
	}
	root := doc.Content[0]
	if root.Kind != yaml.MappingNode {
		fm.NotMapping = true
		return fm
	}
	fm.Root = root
	fm.Fields = make(map[string]*yaml.Node, len(root.Content)/2)
	for i := 0; i+1 < len(root.Content); i += 2 {
		k, v := root.Content[i], root.Content[i+1]
		if k.Kind != yaml.ScalarNode {
			continue
		}
		if _, seen := fm.Fields[k.Value]; seen {
			fm.Duplicates = append(fm.Duplicates, DuplicateKey{Key: k.Value, Line: fm.Line(k)})
			continue
		}
		fm.Fields[k.Value] = v
		fm.Order = append(fm.Order, k.Value)
	}
	return fm
}

func safeUnmarshal(data []byte, out *yaml.Node) (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("yaml parser failure: %v", r)
		}
	}()
	return yaml.Unmarshal(data, out)
}
