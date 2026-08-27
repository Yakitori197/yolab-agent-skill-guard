package text

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
		t.Fatalf("output differs from golden %s:\n--- got ---\n%s\n--- want ---\n%s", p, got, want)
	}
}

func render(rep *model.Report, o Options) []byte {
	var buf bytes.Buffer
	Render(&buf, rep, o)
	return buf.Bytes()
}

func TestRenderGolden(t *testing.T) {
	got := render(reporttest.Sample(), Options{FailOn: model.FailOn(model.SeverityHigh)})
	checkGolden(t, "sample.golden", got)
}

func TestRenderQuietGolden(t *testing.T) {
	got := render(reporttest.Sample(), Options{Quiet: true, FailOn: model.FailOn(model.SeverityHigh)})
	checkGolden(t, "sample-quiet.golden", got)
}

func TestRenderDeterministic(t *testing.T) {
	a := render(reporttest.Sample(), Options{FailOn: model.FailOn(model.SeverityHigh)})
	b := render(reporttest.Sample(), Options{FailOn: model.FailOn(model.SeverityHigh)})
	if !bytes.Equal(a, b) {
		t.Fatal("text output must be byte-identical across runs")
	}
}

func TestRenderNoColorByDefault(t *testing.T) {
	got := string(render(reporttest.Sample(), Options{FailOn: model.FailOn(model.SeverityHigh)}))
	if strings.Contains(got, "\x1b[") {
		t.Fatal("no ANSI codes without Color option")
	}
}

func TestRenderColor(t *testing.T) {
	got := string(render(reporttest.Sample(), Options{Color: true, FailOn: model.FailOn(model.SeverityHigh)}))
	if !strings.Contains(got, "\x1b[") {
		t.Fatal("expected ANSI codes with Color option")
	}
	if !strings.HasSuffix(got, "\n") {
		t.Fatal("output must end with a newline")
	}
	if strings.Count(got, "\x1b[0m") < strings.Count(got, "\x1b[1")-1 {
		t.Fatal("colored tokens must be reset")
	}
}

func TestRenderPassResult(t *testing.T) {
	rep := reporttest.Sample()
	rep.Findings = nil
	got := string(render(rep, Options{FailOn: model.FailOn(model.SeverityHigh)}))
	if !strings.Contains(got, "PASS") || !strings.Contains(got, "no findings") {
		t.Fatalf("output = %s", got)
	}
	got = string(render(rep, Options{FailOn: model.FailOnNone}))
	if !strings.Contains(got, "informational run") {
		t.Fatalf("output = %s", got)
	}
}

func TestRenderFailBelowThreshold(t *testing.T) {
	rep := reporttest.Sample()
	got := string(render(rep, Options{FailOn: model.FailOn(model.SeverityCritical)}))
	if !strings.Contains(got, "FAIL — 1 finding(s)") {
		t.Fatalf("output = %s", got)
	}
}

func TestQuietOmitsSkippedAndFixes(t *testing.T) {
	got := string(render(reporttest.Sample(), Options{Quiet: true, FailOn: model.FailOn(model.SeverityHigh)}))
	if strings.Contains(got, "skipped (never read)") || strings.Contains(got, "fix:") {
		t.Fatalf("quiet output too verbose:\n%s", got)
	}
	if !strings.Contains(got, "summary:") {
		t.Fatal("quiet output must keep the summary")
	}
}
