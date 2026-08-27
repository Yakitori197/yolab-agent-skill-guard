package parser

import (
	"strings"
	"unicode/utf8"

	"github.com/Yakitori197/yolab-agent-skill-guard/internal/model"
)

// LineInfo captures the structural context of one source line.
type LineInfo struct {
	Frontmatter bool
	Fence       bool
	FenceLang   string
	Blockquote  bool
}

// annotateLines computes per-line context. fmEnd is the closing frontmatter
// line (0 when absent). Fence marker lines themselves count as fenced lines.
func annotateLines(lines []string, fmEnd int) []LineInfo {
	infos := make([]LineInfo, len(lines))
	inFence := false
	fenceChar := byte(0)
	fenceLen := 0
	fenceLang := ""
	for i, line := range lines {
		if i < fmEnd {
			infos[i] = LineInfo{Frontmatter: true}
			continue
		}
		trimmed := strings.TrimLeft(line, " \t")
		if !inFence {
			if marker, lang, ok := fenceOpen(trimmed); ok {
				inFence = true
				fenceChar = marker[0]
				fenceLen = len(marker)
				fenceLang = lang
				infos[i] = LineInfo{Fence: true, FenceLang: fenceLang}
				continue
			}
			infos[i] = LineInfo{Blockquote: strings.HasPrefix(trimmed, ">")}
			continue
		}
		infos[i] = LineInfo{Fence: true, FenceLang: fenceLang}
		if isFenceClose(trimmed, fenceChar, fenceLen) {
			inFence = false
			fenceChar, fenceLen, fenceLang = 0, 0, ""
		}
	}
	return infos
}

func fenceOpen(trimmed string) (marker, lang string, ok bool) {
	for _, c := range []byte{'`', '~'} {
		n := runLen(trimmed, c)
		if n >= 3 {
			rest := strings.TrimSpace(trimmed[n:])
			if c == '`' && strings.ContainsRune(rest, '`') {
				return "", "", false // an info string may not contain backticks
			}
			if idx := strings.IndexAny(rest, " \t"); idx >= 0 {
				rest = rest[:idx]
			}
			return trimmed[:n], strings.ToLower(rest), true
		}
	}
	return "", "", false
}

func isFenceClose(trimmed string, c byte, minLen int) bool {
	n := runLen(trimmed, c)
	return n >= minLen && strings.TrimSpace(trimmed[n:]) == ""
}

func runLen(s string, c byte) int {
	n := 0
	for n < len(s) && s[n] == c {
		n++
	}
	return n
}

// inlineSpans returns half-open [start,end) byte ranges of inline code spans
// on a single line, honoring multi-backtick delimiters.
func inlineSpans(line string) [][2]int {
	var spans [][2]int
	i := 0
	for i < len(line) {
		if line[i] != '`' {
			i++
			continue
		}
		open := runLen(line[i:], '`')
		j := i + open
		matched := false
		for j < len(line) {
			if line[j] != '`' {
				j++
				continue
			}
			closeLen := runLen(line[j:], '`')
			if closeLen == open {
				spans = append(spans, [2]int{i, j + closeLen})
				i = j + closeLen
				matched = true
				break
			}
			j += closeLen
		}
		if !matched {
			i += open
		}
	}
	return spans
}

// ContextAt classifies the match context for a byte offset within a line.
func (d *Document) ContextAt(lineNum, byteOff int) model.MatchContext {
	if lineNum < 1 || lineNum > len(d.LineInfo) {
		return model.ContextProse
	}
	info := d.LineInfo[lineNum-1]
	if info.Frontmatter {
		return model.ContextFrontmatter
	}
	if info.Fence {
		return model.ContextCodeFence
	}
	for _, sp := range d.inlineCache(lineNum) {
		if byteOff >= sp[0] && byteOff < sp[1] {
			return model.ContextInlineCode
		}
	}
	return model.ContextProse
}

// ColumnAt converts a byte offset in a line into a 1-based rune column.
func ColumnAt(line string, byteOff int) int {
	if byteOff < 0 {
		byteOff = 0
	}
	if byteOff > len(line) {
		byteOff = len(line)
	}
	return utf8.RuneCountInString(line[:byteOff]) + 1
}
