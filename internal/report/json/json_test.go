package jsonreport

import (
	"bytes"
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Yakitori197/yolab-agent-skill-guard/internal/model"
	"github.com/Yakitori197/yolab-agent-skill-guard/internal/report/reporttest"
)

var update = flag.Bool("update", false, "rewrite golden files")

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
		t.Fatalf("output differs from golden %s:\n--- got ---\n%s", p, got)
	}
}

func render(t *testing.T, rep *model.Report) []byte {
	t.Helper()
	var buf bytes.Buffer
	if err := Render(&buf, rep); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func TestRenderGolden(t *testing.T) {
	checkGolden(t, "sample.json.golden", render(t, reporttest.Sample()))
}

func TestRenderDeterministic(t *testing.T) {
	a := render(t, reporttest.Sample())
	b := render(t, reporttest.Sample())
	if !bytes.Equal(a, b) {
		t.Fatal("JSON output must be byte-identical across runs")
	}
}

func TestRenderValidJSONWithSchemaShape(t *testing.T) {
	var parsed struct {
		Schema  string `json:"schema"`
		Tool    struct{ Name, Version string }
		Summary struct {
			FilesScanned  int `json:"files_scanned"`
			TotalFindings int `json:"total_findings"`
			Critical      int `json:"critical"`
			Info          int `json:"info"`
		} `json:"summary"`
		Findings []map[string]any `json:"findings"`
		Skipped  []map[string]any `json:"skipped"`
	}
	out := render(t, reporttest.Sample())
	if err := json.Unmarshal(out, &parsed); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if parsed.Schema != Schema {
		t.Fatalf("schema = %q", parsed.Schema)
	}
	if parsed.Summary.TotalFindings != 5 || parsed.Summary.Critical != 1 || parsed.Summary.Info != 1 {
		t.Fatalf("summary = %+v", parsed.Summary)
	}
	if len(parsed.Findings) != 5 || len(parsed.Skipped) != 2 {
		t.Fatalf("findings=%d skipped=%d", len(parsed.Findings), len(parsed.Skipped))
	}
	for _, key := range []string{"rule", "severity", "path", "line", "column", "message", "remediation", "fingerprint", "context", "platform"} {
		if _, ok := parsed.Findings[0][key]; !ok {
			t.Fatalf("finding missing key %q", key)
		}
	}
}

func TestEmptyReportSerializesArrays(t *testing.T) {
	rep := &model.Report{Tool: model.ToolInfo{Name: "skillguard", Version: "test"}}
	out := string(render(t, rep))
	if strings.Contains(out, "null") {
		t.Fatalf("empty collections must be [], got:\n%s", out)
	}
}

func TestNoRootLabelInJSON(t *testing.T) {
	out := string(render(t, reporttest.Sample()))
	if strings.Contains(out, "examples/pkg") {
		t.Fatal("machine-readable output must not embed the scan root")
	}
}

func TestAdversarialStringsEscaped(t *testing.T) {
	out := render(t, reporttest.Adversarial())
	var parsed map[string]any
	if err := json.Unmarshal(out, &parsed); err != nil {
		t.Fatalf("adversarial strings broke JSON: %v", err)
	}
	if strings.Contains(string(out), "<script>") {
		t.Fatal("raw <script> must not appear (HTML-escaped encoding expected)")
	}
}
