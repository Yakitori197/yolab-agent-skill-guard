// Package parser turns raw Markdown/instruction bytes into an annotated,
// read-only document model. The parser never executes, renders, or resolves
// any of the content it reads.
package parser

import (
	"strings"

	"github.com/Yakitori197/yolab-agent-skill-guard/internal/model"
)

// Document is one scanned file, fully annotated for rule evaluation.
type Document struct {
	RelPath     string // slash-separated, relative to the scan root
	Platform    model.Platform
	PackageRoot string // slash-separated dir; "" when the scan root is the boundary
	Lines       []string
	LineInfo    []LineInfo
	Frontmatter *Frontmatter

	inlineSpansByLine map[int][][2]int
	refs              []Ref
	refsLoaded        bool
}

// Load normalizes raw bytes (CRLF and lone CR become LF) and computes all
// line-level structure.
func Load(relPath string, platform model.Platform, packageRoot string, raw []byte) *Document {
	text := strings.ReplaceAll(string(raw), "\r\n", "\n")
	text = strings.ReplaceAll(text, "\r", "\n")
	lines := strings.Split(text, "\n")
	if len(lines) > 0 && lines[len(lines)-1] == "" {
		lines = lines[:len(lines)-1]
	}
	fm := parseFrontmatter(lines)
	return &Document{
		RelPath:     relPath,
		Platform:    platform,
		PackageRoot: packageRoot,
		Lines:       lines,
		LineInfo:    annotateLines(lines, fm.EndLine),
		Frontmatter: fm,
	}
}

// DirRel returns the document's directory relative to the scan root
// ("" for files directly at the root).
func (d *Document) DirRel() string {
	idx := strings.LastIndex(d.RelPath, "/")
	if idx < 0 {
		return ""
	}
	return d.RelPath[:idx]
}

// BodyStart returns the first line number after the frontmatter block.
func (d *Document) BodyStart() int {
	if d.Frontmatter != nil && d.Frontmatter.Present {
		return d.Frontmatter.EndLine + 1
	}
	return 1
}

// Refs returns the extracted references, computed once per document.
func (d *Document) Refs() []Ref {
	if !d.refsLoaded {
		d.refs = ExtractRefs(d)
		d.refsLoaded = true
	}
	return d.refs
}

func (d *Document) inlineCache(lineNum int) [][2]int {
	if lineNum < 1 || lineNum > len(d.Lines) {
		return nil
	}
	if d.inlineSpansByLine == nil {
		d.inlineSpansByLine = make(map[int][][2]int)
	}
	if sp, ok := d.inlineSpansByLine[lineNum]; ok {
		return sp
	}
	sp := inlineSpans(d.Lines[lineNum-1])
	d.inlineSpansByLine[lineNum] = sp
	return sp
}
