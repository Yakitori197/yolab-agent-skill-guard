// Package version carries build metadata injected at link time via -ldflags.
// Local builds honestly report "dev"/"unknown" instead of fabricating values.
package version

import "fmt"

// Injected at build time with:
//
//	-ldflags "-X .../internal/version.Version=v1.2.3 ..."
var (
	// Version is the semantic version of this build.
	Version = "dev"
	// Commit is the VCS commit of this build.
	Commit = "unknown"
	// Date is the build date of this build.
	Date = "unknown"
)

// String renders the full human-readable version line.
func String() string {
	return fmt.Sprintf("skillguard %s (commit %s, built %s)", Version, Commit, Date)
}
