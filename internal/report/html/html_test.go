package htmlreport

import (
	"bytes"
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Yakitori197/yolab-agent-skill-guard/internal/model"
	"github.com/Yakitori197/yolab-agent-skill-guard/internal/report/reporttest"
)

var update = flag.Bool("update", false, "rewrite golden files")

func catalog() []model.RuleMeta {
	return []model.RuleMeta{
		{ID: "ASG001", Title: "Hardcoded Secret", DefaultSeverity: model.SeverityCritical, Category: "secrets", Heuristic: true, Rationale: "why1", Remediation: "r1"},
		{ID: "ASG002", Title: "Private Absolute Path", DefaultSeverity: model.SeverityMedium, Category: "privacy", Heuristic: true, Rationale: "why2", Remediation: "r2"},
		{ID: "ASG008", Title: "Missing Reference", DefaultSeverity: model.SeverityMedium, Category: "structure", Rationale: "why8", Remediation: "r8"},
		{ID: "ASG010", Title: "Prompt Injection Signal", DefaultSeverity: model.SeverityHigh, Category: "injection", Heuristic: true, Rationale: "why10", Remediation: "r10"},
		{ID: "ASG900", Title: "Expired Suppression", DefaultSeverity: model.SeverityInfo, Category: "governance", Rationale: "why900", Remediation: "r900"},
	}
}

func render(t *testing.T, rep *model.Report) []byte {
	t.Helper()
	var buf bytes.Buffer
	if err := Render(&buf, rep, catalog(), model.FailOn(model.SeverityHigh)); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func checkGolden(t *testing.T, name string, got []byte) {
	t.Helper()
	p := filepath.Join("testdata", name)
	if *update {
		if err := os.MkdirAll("testdata", 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, got, 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(p)
	if err != nil {
		t.Fatalf("missing golden %s (run with -update): %v", p, err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("output differs from golden %s", p)
	}
}

func TestRenderGolden(t *testing.T) {
	checkGolden(t, "sample.html.golden", render(t, reporttest.Sample()))
}

func TestRenderDeterministic(t *testing.T) {
	if !bytes.Equal(render(t, reporttest.Sample()), render(t, reporttest.Sample())) {
		t.Fatal("HTML output must be byte-identical across runs")
	}
}

func TestSelfContainedAndCSP(t *testing.T) {
	out := string(render(t, reporttest.Sample()))
	if !strings.Contains(out, "Content-Security-Policy") || !strings.Contains(out, "default-src 'none'") {
		t.Fatal("missing strict CSP")
	}
	for _, banned := range []string{"<script", "http-equiv=\"refresh\"", "src=\"http", "href=\"http", "@import", "url(", "fonts.googleapis"} {
		if strings.Contains(out, banned) {
			t.Fatalf("HTML must be self-contained without scripts; found %q", banned)
		}
	}
	if !strings.Contains(out, "<html lang=\"en\">") {
		t.Fatal("missing lang attribute")
	}
	if !strings.Contains(out, "prefers-color-scheme: dark") {
		t.Fatal("missing dark-mode support")
	}
	if !strings.Contains(out, "<details") || !strings.Contains(out, "<summary") {
		t.Fatal("findings must be expandable via details/summary")
	}
}

func TestVerdictAndSummaries(t *testing.T) {
	out := string(render(t, reporttest.Sample()))
	for _, want := range []string{"FAIL", "Findings by rule", "Findings by platform", "Skipped files (never read)", "ASG001", "notes/AGENTS.md", "heuristic — requires review"} {
		if !strings.Contains(out, want) {
			t.Fatalf("output missing %q", want)
		}
	}
	rep := reporttest.Sample()
	rep.Findings = nil
	out = string(render(t, rep))
	if !strings.Contains(out, "PASS") || !strings.Contains(out, "No findings.") {
		t.Fatal("clean report must render PASS")
	}
}

func TestXSSNeutralized(t *testing.T) {
	out := string(render(t, reporttest.Adversarial()))
	for _, banned := range []string{"<script>alert(1)", "<script>alert(3)", "<script>alert(4)", "<img src=x", "</details><script>", "<b>bold"} {
		if strings.Contains(out, banned) {
			t.Fatalf("XSS payload survived escaping: %q", banned)
		}
	}
	if !strings.Contains(out, "&lt;script&gt;") {
		t.Fatal("expected escaped script tags in output")
	}
}

func TestNoRootLabelInHTML(t *testing.T) {
	out := string(render(t, reporttest.Sample()))
	if strings.Contains(out, "examples/pkg") {
		t.Fatal("HTML report must not embed the scan root path")
	}
}
