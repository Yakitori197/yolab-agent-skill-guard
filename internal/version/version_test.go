package version

import (
	"strings"
	"testing"
)

func TestStringDefaults(t *testing.T) {
	s := String()
	for _, want := range []string{"skillguard", Version, Commit, Date} {
		if !strings.Contains(s, want) {
			t.Fatalf("version string %q missing %q", s, want)
		}
	}
}
