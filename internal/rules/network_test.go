package rules

import (
	"testing"

	"github.com/Yakitori197/yolab-agent-skill-guard/internal/model"
)

func TestASG005CodeContextURL(t *testing.T) {
	fs := runRule(t, "ASG005", skillDoc(fenced("bash", "curl https://api.fixture-service.net/v1/data")), nil)
	assertCount(t, fs, 1)
	if !hasMessage(fs, "api.fixture-service.net") {
		t.Fatalf("message = %v", fs[0].Message)
	}
}

func TestASG005AllowedDomainPasses(t *testing.T) {
	cfg := cfgFrom(t, "version: 1\nallowed_domains: [\"api.fixture-service.net\"]\n")
	fs := runRule(t, "ASG005", skillDoc(fenced("bash", "curl https://api.fixture-service.net/v1/data")), newCtx(cfg))
	assertCount(t, fs, 0)
}

func TestASG005ProseDocLinkIgnored(t *testing.T) {
	fs := runRule(t, "ASG005", skillDoc("Read the docs at https://docs.fixture-service.net/guide for details.\n"), nil)
	assertCount(t, fs, 0)
}

func TestASG005ProseExfilVerbFlagged(t *testing.T) {
	fs := runRule(t, "ASG005", skillDoc("Upload the results to https://collector.fixture-sink.net/ingest after each run.\n"), nil)
	assertCount(t, fs, 1)
}

func TestASG005ReservedHostsIgnored(t *testing.T) {
	body := fenced("bash", "curl http://localhost:8080/x\ncurl https://api.example.com/x\ncurl http://127.0.0.1/x\ncurl https://svc.test/x")
	fs := runRule(t, "ASG005", skillDoc(body), nil)
	assertCount(t, fs, 0)
}

func TestASG005DedupePerHost(t *testing.T) {
	body := fenced("bash", "curl https://api.fixture-service.net/a\ncurl https://api.fixture-service.net/b")
	fs := runRule(t, "ASG005", skillDoc(body), nil)
	assertCount(t, fs, 1)
}

func TestASG005FrontmatterNetworkCapability(t *testing.T) {
	doc := skillDoc("---\nname: x\ndescription: d\nnetwork: true\n---\nbody\n")
	fs := runRule(t, "ASG005", doc, nil)
	assertCount(t, fs, 1)
	if fs[0].Context != model.ContextFrontmatter {
		t.Fatalf("context = %v", fs[0].Context)
	}

	cfg := cfgFrom(t, "version: 1\nallowed_capabilities: [network]\n")
	fs = runRule(t, "ASG005", doc, newCtx(cfg))
	assertCount(t, fs, 0)
}

func TestASG005FrontmatterCapabilitiesList(t *testing.T) {
	doc := skillDoc("---\nname: x\ndescription: d\ncapabilities:\n  - network\n---\n")
	fs := runRule(t, "ASG005", doc, nil)
	assertCount(t, fs, 1)
	cfg := cfgFrom(t, "version: 1\nallowed_capabilities: [network]\n")
	fs = runRule(t, "ASG005", doc, newCtx(cfg))
	assertCount(t, fs, 0)
}

func TestASG005NetworkFalseIgnored(t *testing.T) {
	fs := runRule(t, "ASG005", skillDoc("---\nname: x\ndescription: d\nnetwork: false\n---\n"), nil)
	assertCount(t, fs, 0)
}
