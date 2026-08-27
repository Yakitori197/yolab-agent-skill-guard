package model

import (
	"strings"
	"testing"
)

func TestParseSeverity(t *testing.T) {
	cases := []struct {
		in      string
		want    Severity
		wantErr bool
	}{
		{"critical", SeverityCritical, false},
		{"HIGH", SeverityHigh, false},
		{" medium ", SeverityMedium, false},
		{"low", SeverityLow, false},
		{"info", SeverityInfo, false},
		{"none", "", true},
		{"", "", true},
		{"fatal", "", true},
	}
	for _, c := range cases {
		got, err := ParseSeverity(c.in)
		if (err != nil) != c.wantErr {
			t.Errorf("ParseSeverity(%q) error = %v, wantErr %v", c.in, err, c.wantErr)
			continue
		}
		if err == nil && got != c.want {
			t.Errorf("ParseSeverity(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestSeverityRankOrdering(t *testing.T) {
	if !(SeverityCritical.Rank() > SeverityHigh.Rank() &&
		SeverityHigh.Rank() > SeverityMedium.Rank() &&
		SeverityMedium.Rank() > SeverityLow.Rank() &&
		SeverityLow.Rank() > SeverityInfo.Rank()) {
		t.Fatal("severity ranks are not strictly ordered")
	}
	if Severity("bogus").Valid() {
		t.Fatal("bogus severity must not be valid")
	}
	if !SeverityHigh.Valid() {
		t.Fatal("high must be valid")
	}
}

func TestParseFailOn(t *testing.T) {
	if fo, err := ParseFailOn("none"); err != nil || fo != FailOnNone {
		t.Fatalf("ParseFailOn(none) = %v, %v", fo, err)
	}
	fo, err := ParseFailOn("Medium")
	if err != nil || fo != FailOn(SeverityMedium) {
		t.Fatalf("ParseFailOn(Medium) = %v, %v", fo, err)
	}
	if _, err := ParseFailOn("everything"); err == nil {
		t.Fatal("expected error for unknown fail-on value")
	}
	if th, ok := fo.Threshold(); !ok || th != SeverityMedium {
		t.Fatalf("Threshold() = %v, %v", th, ok)
	}
	if _, ok := FailOnNone.Threshold(); ok {
		t.Fatal("none must have no threshold")
	}
	if _, ok := FailOn("").Threshold(); ok {
		t.Fatal("empty fail-on must have no threshold")
	}
}

func TestParsePlatform(t *testing.T) {
	for _, p := range Platforms {
		got, err := ParsePlatform(strings.ToUpper(string(p)))
		if err != nil || got != p {
			t.Errorf("ParsePlatform(%q) = %v, %v", p, got, err)
		}
	}
	if _, err := ParsePlatform("emacs"); err == nil {
		t.Fatal("expected error for unknown platform")
	}
}

func TestSortFindingsOrder(t *testing.T) {
	fs := []Finding{
		{Path: "b.md", Line: 1, Column: 1, RuleID: "ASG002"},
		{Path: "a.md", Line: 2, Column: 1, RuleID: "ASG001"},
		{Path: "a.md", Line: 1, Column: 5, RuleID: "ASG009"},
		{Path: "a.md", Line: 1, Column: 5, RuleID: "ASG003"},
		{Path: "a.md", Line: 1, Column: 2, RuleID: "ASG012"},
	}
	SortFindings(fs)
	got := []string{}
	for _, f := range fs {
		got = append(got, f.Path+":"+f.RuleID)
	}
	want := []string{"a.md:ASG012", "a.md:ASG003", "a.md:ASG009", "a.md:ASG001", "b.md:ASG002"}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("order[%d] = %s, want %s (full: %v)", i, got[i], want[i], got)
		}
	}
}

func TestSortSkipped(t *testing.T) {
	sk := []SkippedFile{
		{Path: "b", Reason: "x"},
		{Path: "a", Reason: "z"},
		{Path: "a", Reason: "a"},
	}
	SortSkipped(sk)
	if sk[0].Path != "a" || sk[0].Reason != "a" || sk[2].Path != "b" {
		t.Fatalf("unexpected order: %v", sk)
	}
}

func TestComputeFingerprint(t *testing.T) {
	a := ComputeFingerprint("ASG001", "x.md", "salt")
	b := ComputeFingerprint("ASG001", "x.md", "salt")
	if a != b {
		t.Fatal("fingerprint must be deterministic")
	}
	if len(a) != 16 {
		t.Fatalf("fingerprint length = %d, want 16", len(a))
	}
	if ComputeFingerprint("ASG001", "x.md", "other") == a {
		t.Fatal("different salt must change the fingerprint")
	}
	if ComputeFingerprint("ASG002", "x.md", "salt") == a {
		t.Fatal("different rule must change the fingerprint")
	}
	if ComputeFingerprint("ASG001", "y.md", "salt") == a {
		t.Fatal("different path must change the fingerprint")
	}
}

func TestReportCounts(t *testing.T) {
	r := &Report{Findings: []Finding{
		{Severity: SeverityCritical},
		{Severity: SeverityHigh},
		{Severity: SeverityHigh},
		{Severity: SeverityInfo},
	}}
	counts := r.CountBySeverity()
	if counts[SeverityCritical] != 1 || counts[SeverityHigh] != 2 || counts[SeverityInfo] != 1 {
		t.Fatalf("unexpected counts: %v", counts)
	}
	if counts[SeverityMedium] != 0 {
		t.Fatal("zero severities must be present in the map")
	}
	if got := r.CountAtOrAbove(SeverityHigh); got != 3 {
		t.Fatalf("CountAtOrAbove(high) = %d, want 3", got)
	}
	if got := r.CountAtOrAbove(SeverityInfo); got != 4 {
		t.Fatalf("CountAtOrAbove(info) = %d, want 4", got)
	}
}
