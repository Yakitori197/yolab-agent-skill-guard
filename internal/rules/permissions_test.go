package rules

import (
	"testing"

	"github.com/Yakitori197/yolab-agent-skill-guard/internal/model"
)

func TestASG006WildcardTools(t *testing.T) {
	fs := runRule(t, "ASG006", skillDoc("---\nname: x\ndescription: d\nallowed-tools:\n  - \"*\"\n---\n"), nil)
	assertCount(t, fs, 1)
	if fs[0].Severity != model.SeverityCritical {
		t.Fatalf("severity = %v", fs[0].Severity)
	}
}

func TestASG006BareShell(t *testing.T) {
	for _, tool := range []string{"Bash", "PowerShell", "shell"} {
		fs := runRule(t, "ASG006", skillDoc("---\nname: x\ndescription: d\nallowed-tools:\n  - "+tool+"\n---\n"), nil)
		assertCount(t, fs, 1)
		if fs[0].Severity != model.SeverityHigh {
			t.Fatalf("severity for %s = %v", tool, fs[0].Severity)
		}
	}
}

func TestASG006BroadScopedShell(t *testing.T) {
	fs := runRule(t, "ASG006", skillDoc("---\nname: x\ndescription: d\nallowed-tools:\n  - \"Bash(*)\"\n---\n"), nil)
	assertCount(t, fs, 1)
}

func TestASG006ScopedToolsPass(t *testing.T) {
	doc := skillDoc("---\nname: x\ndescription: d\nallowed-tools:\n  - Read\n  - Grep\n  - \"Bash(git status:*)\"\n---\n")
	fs := runRule(t, "ASG006", doc, nil)
	assertCount(t, fs, 0)
}

func TestASG006BroadKeyValues(t *testing.T) {
	fs := runRule(t, "ASG006", skillDoc("---\nname: x\ndescription: d\npermissions: all\n---\n"), nil)
	assertCount(t, fs, 1)
	fs = runRule(t, "ASG006", skillDoc("---\nname: x\ndescription: d\nfilesystem: unrestricted\n---\n"), nil)
	assertCount(t, fs, 1)
}

func TestASG006UndeclaredCapability(t *testing.T) {
	doc := skillDoc("---\nname: x\ndescription: d\ncapabilities:\n  - exec\n---\n")
	fs := runRule(t, "ASG006", doc, nil)
	assertCount(t, fs, 1)
	if fs[0].Severity != model.SeverityMedium {
		t.Fatalf("severity = %v", fs[0].Severity)
	}
	cfg := cfgFrom(t, "version: 1\nallowed_capabilities: [exec]\n")
	fs = runRule(t, "ASG006", doc, newCtx(cfg))
	assertCount(t, fs, 0)
}

func TestASG006NetworkCapabilityLeftToASG005(t *testing.T) {
	fs := runRule(t, "ASG006", skillDoc("---\nname: x\ndescription: d\ncapabilities:\n  - network\n---\n"), nil)
	assertCount(t, fs, 0)
}

func TestASG006ProseBlanketAccess(t *testing.T) {
	fs := runRule(t, "ASG006", skillDoc("This skill needs unrestricted filesystem access to work.\n"), nil)
	assertCount(t, fs, 1)
	// A disclaimer on the same line does not remove the request from the file.
	fs = runRule(t, "ASG006", skillDoc("Never grant unrestricted filesystem access to a skill.\n"), nil)
	assertCount(t, fs, 1)
	if fs[0].Severity != model.SeverityMedium {
		t.Fatalf("severity = %v, want medium", fs[0].Severity)
	}
	// An explicit request for every permission counts as a blanket request.
	fs = runRule(t, "ASG006", skillDoc("Do not request all permissions unless needed.\n"), nil)
	assertCount(t, fs, 1)
}

func TestASG006CleanManifest(t *testing.T) {
	fs := runRule(t, "ASG006", skillDoc("---\nname: x\ndescription: d\n---\nJust prose.\n"), nil)
	assertCount(t, fs, 0)
}
