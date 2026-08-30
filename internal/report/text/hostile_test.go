package text

import (
	"strings"
	"testing"

	"github.com/Yakitori197/yolab-agent-skill-guard/internal/model"
)

// A terminal report is the one output a terminal interprets. Everything below
// checks that hostile text reaching the renderer — from a filename on disk, a
// path the user typed, or a finding message quoting a scanned document — is
// printed inert.
//
// Control characters are built from code points rather than pasted in, so this
// source file stays safe to open in a terminal.

const (
	esc            = "\x1b"
	bel            = "\x07"
	osc            = "\x1b]0;pwned\x07"
	clearScreen    = "\x1b[2J"
	rtlOverride    = "\u202e"
	popDirectional = "\u202c"
	lineSeparator  = "\u2028"
	paraSeparator  = "\u2029"
	zeroWidthSpace = "\u200b"
	byteOrderMark  = "\ufeff"
	c1CSI          = "\u009b"
)

// hostileReport builds a report whose every human-readable string is hostile.
func hostileReport() *model.Report {
	return &model.Report{
		SchemaVersion: "1",
		Tool:          model.ToolInfo{Name: "skillguard", Version: "0.0.0-test"},
		RootLabel:     "root" + clearScreen + osc + "\nfiles scanned: 999",
		FilesScanned:  1,
		Findings: []model.Finding{
			{
				RuleID:      "ASG001",
				Severity:    model.SeverityHigh,
				Path:        "pkg/evil\n  1:1  critical  ASG004  forged finding\x1b[31m.md",
				Line:        1,
				Column:      1,
				Message:     "message with " + esc + "[5m blink, " + rtlOverride + "reversed" + popDirectional + " and a \r carriage return",
				Remediation: "fix with " + lineSeparator + paraSeparator + zeroWidthSpace + byteOrderMark + c1CSI + "31m",
			},
		},
		Skipped: []model.SkippedFile{
			{Path: "secrets/\x1b[2K.env" + "\ninjected: line", Reason: "env-file-never-read"},
		},
	}
}

// renderBoth renders with and without color so both paths are asserted.
func renderBoth(t *testing.T, rep *model.Report) (plain, colored string) {
	t.Helper()
	opts := Options{FailOn: model.FailOn(model.SeverityHigh)}
	plain = string(render(rep, opts))
	opts.Color = true
	colored = string(render(rep, opts))
	return plain, colored
}

func TestHostileTextNeverReachesTheTerminalRaw(t *testing.T) {
	plain, _ := renderBoth(t, hostileReport())

	forbidden := map[string]string{
		esc:            "ESC",
		bel:            "BEL",
		"\r":           "carriage return",
		rtlOverride:    "right-to-left override",
		popDirectional: "pop directional formatting",
		lineSeparator:  "line separator",
		paraSeparator:  "paragraph separator",
		zeroWidthSpace: "zero width space",
		byteOrderMark:  "byte order mark",
		c1CSI:          "C1 control sequence introducer",
	}
	for seq, name := range forbidden {
		if strings.Contains(plain, seq) {
			t.Fatalf("--no-color output still contains a raw %s", name)
		}
	}
}

// Without color there must be no ESC at all: the only ANSI this package emits
// is emitted by the color path.
func TestNoColorOutputContainsNoEscape(t *testing.T) {
	for _, quiet := range []bool{false, true} {
		got := string(render(hostileReport(), Options{Quiet: quiet, FailOn: model.FailOn(model.SeverityHigh)}))
		if strings.Contains(got, esc) {
			t.Fatalf("quiet=%v: --no-color output must contain no ESC byte", quiet)
		}
	}
}

// With color, the only escape sequences present are this package's own.
func TestColorOutputContainsOnlyRendererANSI(t *testing.T) {
	_, colored := renderBoth(t, hostileReport())

	allowed := map[string]bool{
		ansiReset: true, ansiBold: true, ansiDim: true,
		ansiRed: true, ansiYellow: true, ansiCyan: true,
	}
	// Every ESC in the output must begin one of the sequences above.
	for i := 0; i < len(colored); i++ {
		if colored[i] != 0x1b {
			continue
		}
		matched := false
		for seq := range allowed {
			if strings.HasPrefix(colored[i:], seq) {
				matched = true
				break
			}
		}
		if !matched {
			t.Fatalf("unexpected escape sequence at byte %d: %q", i, colored[i:min(i+12, len(colored))])
		}
	}
}

// A path containing a newline must not be able to add a line that looks like a
// finding, and must not disturb the summary or result lines.
func TestHostilePathCannotForgeReportLines(t *testing.T) {
	plain, _ := renderBoth(t, hostileReport())
	lines := strings.Split(strings.TrimRight(plain, "\n"), "\n")

	// One finding in, one finding line out.
	findingLines := 0
	for _, l := range lines {
		if strings.HasPrefix(l, "  1:1  ") {
			findingLines++
		}
	}
	if findingLines != 1 {
		t.Fatalf("expected exactly one finding line, got %d:\n%s", findingLines, plain)
	}
	if strings.Contains(plain, "forged finding") && strings.Contains(plain, "\n  1:1  critical") {
		t.Fatal("a path with an embedded newline forged a second finding line")
	}

	summaries, results, roots := 0, 0, 0
	for _, l := range lines {
		switch {
		case strings.HasPrefix(l, "summary: "):
			summaries++
		case strings.HasPrefix(l, "result: "):
			results++
		case strings.HasPrefix(l, "root: "):
			roots++
		}
	}
	if summaries != 1 || results != 1 || roots != 1 {
		t.Fatalf("summary=%d result=%d root=%d, want exactly one of each:\n%s", summaries, results, roots, plain)
	}
	if strings.Contains(plain, "\nfiles scanned: 999") {
		t.Fatal("a hostile root label forged a header line")
	}
}

// Skipped entries come straight from filenames on disk.
func TestHostileSkippedPathIsEscaped(t *testing.T) {
	rep := &model.Report{
		Tool:      model.ToolInfo{Name: "skillguard", Version: "t"},
		RootLabel: ".",
		Skipped: []model.SkippedFile{
			{Path: "a\x1b[2Kb\nc", Reason: "env-file-never-read"},
		},
	}
	got := string(render(rep, Options{FailOn: model.FailOn(model.SeverityHigh)}))
	if strings.Contains(got, esc) {
		t.Fatal("a skipped path must not carry an escape into the output")
	}
	if !strings.Contains(got, `a\x1b[2Kb\nc`) {
		t.Fatalf("the skipped path was not escaped visibly:\n%s", got)
	}
}

// Traditional Chinese and other printable scripts must stay exactly as they
// are: this fix must not damage ordinary output.
func TestPrintableNonLatinTextIsPreserved(t *testing.T) {
	rep := &model.Report{
		Tool:      model.ToolInfo{Name: "skillguard", Version: "t"},
		RootLabel: "專案/技能",
		Findings: []model.Finding{{
			RuleID: "ASG001", Severity: model.SeverityLow, Line: 3, Column: 5,
			Path:        "文件/技能說明.md",
			Message:     "偵測到破壞性指令：請人工確認",
			Remediation: "改用受限的指令範圍",
		}},
	}
	got := string(render(rep, Options{FailOn: model.FailOn(model.SeverityHigh)}))
	for _, want := range []string{"專案/技能", "文件/技能說明.md", "偵測到破壞性指令：請人工確認", "改用受限的指令範圍"} {
		if !strings.Contains(got, want) {
			t.Fatalf("%q is printable text and must survive unchanged:\n%s", want, got)
		}
	}
}

// Escaping must not introduce any run-to-run variation.
func TestHostileRenderIsDeterministic(t *testing.T) {
	a := string(render(hostileReport(), Options{FailOn: model.FailOn(model.SeverityHigh)}))
	b := string(render(hostileReport(), Options{FailOn: model.FailOn(model.SeverityHigh)}))
	if a != b {
		t.Fatal("hostile input must render byte-identically across runs")
	}
	c := string(render(hostileReport(), Options{Color: true, FailOn: model.FailOn(model.SeverityHigh)}))
	d := string(render(hostileReport(), Options{Color: true, FailOn: model.FailOn(model.SeverityHigh)}))
	if c != d {
		t.Fatal("hostile input must render byte-identically in color mode too")
	}
}
