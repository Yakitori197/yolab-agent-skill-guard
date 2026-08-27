// Package redact centralizes masking of sensitive values so that no report
// format can accidentally emit a raw secret or a private path segment.
package redact

import (
	"fmt"
	"strings"
)

// Secret masks a suspected credential. At most the first four characters are
// kept (usually a recognizable prefix such as "ghp_"); the remainder is
// replaced and the original length is appended so a human can still locate
// the value in the file. The full value never appears in any output.
func Secret(v string) string {
	runes := []rune(v)
	n := len(runes)
	if n == 0 {
		return ""
	}
	if n <= 8 {
		return strings.Repeat("*", n)
	}
	return fmt.Sprintf("%s******** (%d chars)", string(runes[:4]), n)
}

// UserSegment is the display replacement for a username path segment.
const UserSegment = "<redacted-user>"

// PathUser masks the first occurrence of the username segment inside a
// home-directory style path, e.g. C:\Users\alice\x -> C:\Users\<redacted-user>\x.
func PathUser(match, username string) string {
	if username == "" {
		return match
	}
	return strings.Replace(match, username, UserSegment, 1)
}
