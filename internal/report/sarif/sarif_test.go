package sarif

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

// catalog is a fixed rule catalog for tests, mirroring rules.Catalog's shape
// without importing it (keeps the formatter decoupled from the rule engine).
func catalog() []model.RuleMeta {
	return []model.RuleMeta{
		{ID: "ASG001", Title: "Hardcoded Secret", Summary: "s1", DefaultSeverity: model.SeverityCritical, Category: "secrets", Heuristic: true, Remediation: "r1"},
		{ID: "ASG002", Title: "Private Absolute Path", Summary: "s2", DefaultSeverity: model.SeverityMedium, Category: "privacy", Heuristic: true, Remediation: "r2"},
		{ID: "ASG008", Title: "Missing Reference", Summary: "s8", DefaultSeverity: model.SeverityMedium, Category: "structure", Remediation: "r8"},
		{ID: "ASG010", Title: "Prompt Injection Signal", Summary: "s10", DefaultSeverity: model.SeverityHigh, Category: "injection", Heuristic: true, Remediation: "r10"},
		{ID: "ASG900", Title: "Expired Suppression", Summary: "s900", DefaultSeverity: model.SeverityInfo, Category: "governance", Remediation: "r900"},
	}
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

func render(t *testing.T, rep *model.Report) []byte {
	t.Helper()
	var buf bytes.Buffer
	if err := Render(&buf, rep, catalog()); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func TestRenderGolden(t *testing.T) {
	checkGolden(t, "sample.sarif.golden", render(t, reporttest.Sample()))
}

func TestRenderDeterministic(t *testing.T) {
	if !bytes.Equal(render(t, reporttest.Sample()), render(t, reporttest.Sample())) {
		t.Fatal("SARIF output must be byte-identical across runs")
	}
}

func TestSARIFStructure(t *testing.T) {
	var log struct {
		Schema  string `json:"$schema"`
		Version string `json:"version"`
		Runs    []struct {
			Tool struct {
				Driver struct {
					Name  string `json:"name"`
					Rules []struct {
						ID         string `json:"id"`
						HelpURI    string `json:"helpUri"`
						Properties struct {
							SecuritySeverity string `json:"security-severity"`
						} `json:"properties"`
					} `json:"rules"`
				} `json:"driver"`
			} `json:"tool"`
			ColumnKind string `json:"columnKind"`
			Results    []struct {
				RuleID    string `json:"ruleId"`
				RuleIndex int    `json:"ruleIndex"`
				Level     string `json:"level"`
				Locations []struct {
					PhysicalLocation struct {
						ArtifactLocation struct {
							URI string `json:"uri"`
						} `json:"artifactLocation"`
						Region struct {
							StartLine   int `json:"startLine"`
							StartColumn int `json:"startColumn"`
						} `json:"region"`
					} `json:"physicalLocation"`
				} `json:"locations"`
				PartialFingerprints map[string]string `json:"partialFingerprints"`
			} `json:"results"`
		} `json:"runs"`
	}
	out := render(t, reporttest.Sample())
	if err := json.Unmarshal(out, &log); err != nil {
		t.Fatalf("invalid SARIF JSON: %v", err)
	}
	if log.Version != "2.1.0" || !strings.Contains(log.Schema, "sarif-schema-2.1.0") {
		t.Fatalf("version=%q schema=%q", log.Version, log.Schema)
	}
	run := log.Runs[0]
	if run.Tool.Driver.Name != "skillguard" || run.ColumnKind != "unicodeCodePoints" {
		t.Fatalf("driver=%q columnKind=%q", run.Tool.Driver.Name, run.ColumnKind)
	}
	if len(run.Results) != 5 {
		t.Fatalf("results = %d", len(run.Results))
	}
	for _, res := range run.Results {
		if run.Tool.Driver.Rules[res.RuleIndex].ID != res.RuleID {
			t.Fatalf("ruleIndex mismatch for %s", res.RuleID)
		}
		uri := res.Locations[0].PhysicalLocation.ArtifactLocation.URI
		if strings.Contains(uri, "\\") || strings.Contains(uri, ":") {
			t.Fatalf("URI %q must be a relative slash path", uri)
		}
		if res.Locations[0].PhysicalLocation.Region.StartLine < 1 ||
			res.Locations[0].PhysicalLocation.Region.StartColumn < 1 {
			t.Fatalf("region must be 1-based")
		}
		if res.PartialFingerprints["skillguard/v1"] == "" {
			t.Fatal("missing partial fingerprint")
		}
	}
	// Level mapping.
	byRule := map[string]string{}
	for _, res := range run.Results {
		byRule[res.RuleID] = res.Level
	}
	if byRule["ASG001"] != "error" || byRule["ASG010"] != "error" ||
		byRule["ASG008"] != "warning" || byRule["ASG002"] != "note" || byRule["ASG900"] != "note" {
		t.Fatalf("level mapping = %v", byRule)
	}
	for _, r := range run.Tool.Driver.Rules {
		if r.HelpURI == "" || r.Properties.SecuritySeverity == "" {
			t.Fatalf("rule %s missing metadata", r.ID)
		}
	}
}

func TestNoAbsolutePathsOrRoot(t *testing.T) {
	out := string(render(t, reporttest.Sample()))
	for _, banned := range []string{"examples/pkg\"", "C:\\", "file:///"} {
		if strings.Contains(out, banned) {
			t.Fatalf("SARIF must not contain %q", banned)
		}
	}
}

func TestAdversarialEscaped(t *testing.T) {
	var buf bytes.Buffer
	if err := Render(&buf, reporttest.Adversarial(), catalog()); err != nil {
		t.Fatal(err)
	}
	var any map[string]any
	if err := json.Unmarshal(buf.Bytes(), &any); err != nil {
		t.Fatalf("adversarial strings broke SARIF: %v", err)
	}
}
