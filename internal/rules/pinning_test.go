package rules

import (
	"strings"
	"testing"
)

func TestASG011UnpinnedUses(t *testing.T) {
	fs := runRule(t, "ASG011", skillDoc(fenced("yaml", "steps:\n  - uses: fixture-org/tool-action@v4")), nil)
	assertCount(t, fs, 1)
	if !hasMessage(fs, "fixture-org/tool-action") {
		t.Fatalf("message = %v", fs[0].Message)
	}
}

func TestASG011PinnedUsesPasses(t *testing.T) {
	sha := strings.Repeat("a1b2", 10) // 40 hex chars
	body := "steps:\n  - uses: fixture-org/tool-action@" + sha + "  # v4.2.2\n  - uses: ./local-action\n  - uses: docker://img@sha256:" + strings.Repeat("ab", 32)
	fs := runRule(t, "ASG011", skillDoc(fenced("yaml", body)), nil)
	assertCount(t, fs, 0)
}

func TestASG011PlaceholderRefPasses(t *testing.T) {
	body := "steps:\n  - uses: fixture-org/tool-action@<pinned-commit-sha>\n  - uses: fixture-org/tool-action@${{ env.PIN }}"
	fs := runRule(t, "ASG011", skillDoc(fenced("yaml", body)), nil)
	assertCount(t, fs, 0)
}

func TestASG011RawGitHubMutableRef(t *testing.T) {
	fs := runRule(t, "ASG011", skillDoc(fenced("bash", "curl -O https://raw.githubusercontent.com/fixture-org/repo/main/setup.sh")), nil)
	assertCount(t, fs, 1)
	sha := strings.Repeat("ab12", 10)
	fs = runRule(t, "ASG011", skillDoc(fenced("bash", "curl -O https://raw.githubusercontent.com/fixture-org/repo/"+sha+"/setup.sh")), nil)
	assertCount(t, fs, 0)
}

func TestASG011GitPlusRef(t *testing.T) {
	fs := runRule(t, "ASG011", skillDoc(fenced("bash", "pip install git+https://github.com/fixture-org/lib.git@main")), nil)
	assertCount(t, fs, 1)
}

func TestASG011LatestInstalls(t *testing.T) {
	fs := runRule(t, "ASG011", skillDoc(fenced("bash", "go install fixture.dev/tool@latest")), nil)
	assertCount(t, fs, 1)
	fs = runRule(t, "ASG011", skillDoc(fenced("bash", "npx create-fixture@latest")), nil)
	assertCount(t, fs, 1)
	fs = runRule(t, "ASG011", skillDoc(fenced("bash", "go install fixture.dev/tool@v1.4.2")), nil)
	assertCount(t, fs, 0)
}

func TestASG011ReleasesLatest(t *testing.T) {
	fs := runRule(t, "ASG011", skillDoc(fenced("bash", "curl -LO https://github.com/fixture-org/tool/releases/latest/download/tool.tar.gz")), nil)
	assertCount(t, fs, 1)
}

func TestASG011DocLinksNotDependencies(t *testing.T) {
	body := "See the project at https://github.com/fixture-org/tool and its docs.\n" +
		"The repository [fixture-org/tool](https://github.com/fixture-org/tool) is popular.\n"
	fs := runRule(t, "ASG011", skillDoc(body), nil)
	assertCount(t, fs, 0)
}
