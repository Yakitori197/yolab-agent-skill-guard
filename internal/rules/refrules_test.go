package rules

import (
	"strings"
	"testing"

	"github.com/Yakitori197/yolab-agent-skill-guard/internal/model"
)

func TestASG007DotDotEscape(t *testing.T) {
	d := skillDoc("See [helpers](../shared/helpers.md).\n")
	fs := runRule(t, "ASG007", d, nil)
	assertCount(t, fs, 1)
	if fs[0].Severity != model.SeverityHigh {
		t.Fatalf("severity = %v", fs[0].Severity)
	}
}

func TestASG007MixedSlashEscape(t *testing.T) {
	d := docFrom("pkg/SKILL.md", model.PlatformClaude, "pkg", `See [x](..\..\outside.md).`+"\n")
	fs := runRule(t, "ASG007", d, nil)
	assertCount(t, fs, 1)
	if !strings.Contains(fs[0].Message, "outside the scan root") {
		t.Fatalf("message = %s", fs[0].Message)
	}
}

func TestASG007PercentEncodedEscape(t *testing.T) {
	d := skillDoc("See [x](%2e%2e/%2e%2e/etc/passwd).\n")
	fs := runRule(t, "ASG007", d, nil)
	assertCount(t, fs, 1)
	if !strings.Contains(fs[0].Message, "percent-encoding") {
		t.Fatalf("message = %s", fs[0].Message)
	}
}

func TestASG007AbsolutePaths(t *testing.T) {
	for _, target := range []string{`C:\notes\x.md`, "/etc/hosts", `\\server\share\x.md`, "~/notes.md", "file:///C:/x.md"} {
		d := skillDoc("See [x](" + target + ").\n")
		fs := runRule(t, "ASG007", d, nil)
		if len(fs) != 1 {
			t.Fatalf("target %q: findings = %d", target, len(fs))
		}
		if fs[0].Severity != model.SeverityMedium {
			t.Fatalf("target %q severity = %v", target, fs[0].Severity)
		}
	}
}

func TestASG007PackageEscape(t *testing.T) {
	// Reference stays inside the scan root but leaves the skill package.
	d := docFrom("skills/a/SKILL.md", model.PlatformClaude, "skills/a", "See [shared](../shared/util.md).\n")
	ctx := newCtx(nil, "skills/shared/util.md")
	fs := runRule(t, "ASG007", d, ctx)
	assertCount(t, fs, 1)
	if fs[0].Severity != model.SeverityMedium {
		t.Fatalf("severity = %v", fs[0].Severity)
	}
	if !strings.Contains(fs[0].Message, "skills/a/") {
		t.Fatalf("message = %s", fs[0].Message)
	}
}

func TestASG007SymlinkEscape(t *testing.T) {
	d := skillDoc("See [alias](alias.md).\n")
	ctx := newCtx(nil)
	fc := ctx
	fc.ResolveReal = func(rel string) (bool, bool) {
		if rel == "alias.md" {
			return false, true // exists but resolves outside the root
		}
		return true, false
	}
	fs := runRule(t, "ASG007", d, ctx)
	assertCount(t, fs, 1)
	if !strings.Contains(fs[0].Message, "symbolic link") {
		t.Fatalf("message = %s", fs[0].Message)
	}
}

func TestASG007CaseFoldPackageContainment(t *testing.T) {
	d := docFrom("PKG/SKILL.md", model.PlatformClaude, "PKG", "See [x](../pkg/inner.md).\n")
	ctx := newCtx(nil, "pkg/inner.md")
	ctx.FoldCase = true
	fs := runRule(t, "ASG007", d, ctx)
	assertCount(t, fs, 0) // on case-insensitive filesystems PKG == pkg
	ctx2 := newCtx(nil, "pkg/inner.md")
	ctx2.FoldCase = false
	fs = runRule(t, "ASG007", d, ctx2)
	assertCount(t, fs, 1)
}

func TestASG007CleanRefs(t *testing.T) {
	d := docFrom("pkg/SKILL.md", model.PlatformClaude, "pkg", "See [a](references/a.md) and [site](https://docs.example.com/x) and [sec](#anchor).\n")
	ctx := newCtx(nil, "pkg/references/a.md")
	fs := runRule(t, "ASG007", d, ctx)
	assertCount(t, fs, 0)
}

func TestASG008MissingReference(t *testing.T) {
	d := skillDoc("See [a](present.md) and [b](absent.md).\n")
	ctx := newCtx(nil, "present.md")
	fs := runRule(t, "ASG008", d, ctx)
	assertCount(t, fs, 1)
	if !strings.Contains(fs[0].Message, "absent.md") {
		t.Fatalf("message = %s", fs[0].Message)
	}
}

func TestASG008DuplicateReferenceReportedOnce(t *testing.T) {
	d := skillDoc("See [a](gone.md) and again [b](gone.md) and [c](./gone.md).\n")
	fs := runRule(t, "ASG008", d, newCtx(nil))
	assertCount(t, fs, 1)
}

func TestASG008AnchorAndQueryStripped(t *testing.T) {
	d := skillDoc("See [a](present.md#section) and [b](present.md?raw=1).\n")
	ctx := newCtx(nil, "present.md")
	fs := runRule(t, "ASG008", d, ctx)
	assertCount(t, fs, 0)
}

func TestASG008ExternalAndAnchorIgnored(t *testing.T) {
	d := skillDoc("See [x](https://site.example/missing) and [y](#local) and [m](mailto:a@example.com).\n")
	fs := runRule(t, "ASG008", d, newCtx(nil))
	assertCount(t, fs, 0)
}

func TestASG008ImageAndRefdef(t *testing.T) {
	d := skillDoc("![logo](img/logo.png)\n\n[spec]: specs/format.md\n")
	fs := runRule(t, "ASG008", d, newCtx(nil, "img/logo.png"))
	assertCount(t, fs, 1)
	if !strings.Contains(fs[0].Message, "specs/format.md") {
		t.Fatalf("message = %s", fs[0].Message)
	}
}
