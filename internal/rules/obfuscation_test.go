package rules

import (
	"strings"
	"testing"

	"github.com/Yakitori197/yolab-agent-skill-guard/internal/model"
)

// blob returns a synthetic base64-alphabet run of n characters.
func blob(n int) string { return strings.Repeat("QWer", n/4) }

func TestASG012Base64WithExecution(t *testing.T) {
	body := "echo \"" + blob(160) + "\" | base64 -d | sh"
	fs := runRule(t, "ASG012", skillDoc(fenced("bash", body)), nil)
	if len(fs) < 1 {
		t.Fatal("expected a finding")
	}
	if fs[0].Severity != model.SeverityCritical {
		t.Fatalf("severity = %v", fs[0].Severity)
	}
	if strings.Contains(fs[0].Message, blob(160)) {
		t.Fatal("message must not embed the blob")
	}
}

func TestASG012StandaloneLargeBlob(t *testing.T) {
	fs := runRule(t, "ASG012", skillDoc("payload: "+blob(480)+"\n"), nil)
	assertCount(t, fs, 1)
	if fs[0].Severity != model.SeverityMedium {
		t.Fatalf("severity = %v", fs[0].Severity)
	}
}

func TestASG012SmallBlobIgnored(t *testing.T) {
	fs := runRule(t, "ASG012", skillDoc("checksum: "+blob(80)+"\n"), nil)
	assertCount(t, fs, 0)
}

func TestASG012DataURIIgnored(t *testing.T) {
	fs := runRule(t, "ASG012", skillDoc("![img](data:image/png;base64,"+blob(200)+")\n"), nil)
	assertCount(t, fs, 0)
}

func TestASG012EncodedCommand(t *testing.T) {
	fs := runRule(t, "ASG012", skillDoc(fenced("powershell", "powershell -enc "+blob(80))), nil)
	if len(fs) < 1 {
		t.Fatal("expected a finding")
	}
	if fs[0].Severity != model.SeverityCritical {
		t.Fatalf("severity = %v", fs[0].Severity)
	}
}

func TestASG012EvalAtob(t *testing.T) {
	fs := runRule(t, "ASG012", skillDoc(fenced("js", "eval(atob('QUJD'))")), nil)
	assertCount(t, fs, 1)
	if fs[0].Severity != model.SeverityCritical {
		t.Fatalf("severity = %v", fs[0].Severity)
	}
}

func TestASG012CharCode(t *testing.T) {
	nums := strings.TrimSuffix(strings.Repeat("104,", 20), ",")
	fs := runRule(t, "ASG012", skillDoc(fenced("js", "var s = String.fromCharCode("+nums+");")), nil)
	assertCount(t, fs, 1)
	if fs[0].Severity != model.SeverityHigh {
		t.Fatalf("severity = %v", fs[0].Severity)
	}
}

func TestASG012HexBlobAdjacent(t *testing.T) {
	hex := strings.Repeat("4a6b", 40) // 160 hex chars
	body := "printf '" + hex + "' | xxd -r -p | sh"
	fs := runRule(t, "ASG012", skillDoc(fenced("bash", body)), nil)
	if len(fs) < 1 {
		t.Fatal("expected a finding")
	}
	if fs[0].Severity != model.SeverityCritical {
		t.Fatalf("severity = %v", fs[0].Severity)
	}
}

func TestASG012GitSHAsNotFlagged(t *testing.T) {
	body := "Pin to commit " + strings.Repeat("ab", 20) + " for stability.\n" +
		"sha256: " + strings.Repeat("cd", 32) + "\n"
	fs := runRule(t, "ASG012", skillDoc(body), nil)
	assertCount(t, fs, 0)
}

func TestASG012NeverDecodes(t *testing.T) {
	// The message reports length only; even with execution adjacency the blob
	// content must never appear decoded or verbatim.
	body := "echo " + blob(200) + " | base64 --decode | bash"
	fs := runRule(t, "ASG012", skillDoc(fenced("bash", body)), nil)
	if len(fs) < 1 {
		t.Fatal("expected a finding")
	}
	for _, f := range fs {
		if strings.Contains(f.Message, "QWerQWerQWerQWerQWer") {
			t.Fatalf("blob leaked into message: %s", f.Message)
		}
	}
}
