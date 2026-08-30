package app

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The GitHub Action entrypoint is a POSIX shell script, and the shell it runs
// under is not the one this repository is developed on: the action image is
// Alpine, whose /bin/sh is BusyBox ash, and Debian runners provide dash. Both
// ship an XSI `echo`, which interprets backslash escapes *inside its argument*.
//
// A backslash is a legal character in a POSIX filename, and skillguard accepts
// one, so `report-path=reports/a\tb.json` emitted with echo becomes a real tab;
// `a\nb.json` splits into two lines and forges an extra GITHUB_OUTPUT entry;
// `a\cb.json` truncates the line at the "a". None of that is visible from Go,
// and the physical shell cases in scripts/test-action.sh cannot run on a
// filesystem that treats a backslash as a separator — so this guard reads the
// script itself and runs everywhere.

func entrypointPath(t *testing.T) string {
	t.Helper()
	p := filepath.Join("..", "..", "scripts", "action-entrypoint.sh")
	if _, err := os.Stat(p); err != nil {
		t.Fatalf("the entrypoint script must exist for this guard to mean anything: %v", err)
	}
	return p
}

// Nothing in the entrypoint may emit through echo. printf with a literal format
// string copies a %s argument verbatim on every shell.
func TestActionEntrypointNeverUsesEcho(t *testing.T) {
	data, err := os.ReadFile(entrypointPath(t))
	if err != nil {
		t.Fatal(err)
	}
	nl := string(rune(0x0a))
	checked := 0
	for i, raw := range strings.Split(string(data), nl) {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		checked++
		// Only the command position matters; "echo" inside a quoted message
		// would be harmless, but the script has none, so a plain scan is
		// enough and stays obvious.
		for _, form := range []string{"echo ", "echo\t", ") echo", "; echo", "| echo"} {
			if strings.Contains(line, form) {
				t.Errorf("action-entrypoint.sh:%d uses echo; use printf with a literal format string, because the XSI echo on Alpine and Debian interprets backslash escapes in a filename: %s", i+1, line)
			}
		}
	}
	if checked == 0 {
		t.Fatal("the guard scanned no executable lines; it would pass vacuously")
	}
}

// The one line that carries the machine value must use a literal format string
// and pass the value as a %s argument, so a % or a backslash in the filename is
// data rather than syntax.
func TestActionEntrypointEmitsReportPathVerbatim(t *testing.T) {
	data, err := os.ReadFile(entrypointPath(t))
	if err != nil {
		t.Fatal(err)
	}
	text := string(data)
	if !strings.Contains(text, `printf 'report-path=%s\n' "$report_rel"`) {
		t.Fatalf("the report-path line must be printf with a literal format and the value as %%s; got:\n%s", text)
	}
	// And the value must never be interpolated into the format string itself.
	if strings.Contains(text, `printf "report-path=$report_rel`) {
		t.Fatal("the report path must not be part of the printf format string")
	}
}
