// Package pathsafe implements the path normalization and containment logic
// that keeps every reference and file access inside the scanned root.
// All functions are pure string operations so they can be tested exhaustively
// without touching a real filesystem.
package pathsafe

import (
	"net/url"
	"path"
	"regexp"
	"strings"
)

var (
	driveRe = regexp.MustCompile(`^[A-Za-z]:[/\\]`)
	// Requires at least two characters before the colon so that Windows
	// drive letters (C:) are not mistaken for URL schemes.
	schemeRe = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9+.-]+:`)
)

// ToSlash converts Windows separators to forward slashes.
func ToSlash(p string) string { return strings.ReplaceAll(p, "\\", "/") }

// PercentDecode decodes percent-escapes; changed reports whether decoding
// altered the input. Undecodable input is returned unchanged so that a
// malformed escape cannot be used to smuggle a path past the checks.
func PercentDecode(p string) (decoded string, changed bool) {
	if !strings.Contains(p, "%") {
		return p, false
	}
	d, err := url.PathUnescape(p)
	if err != nil {
		return p, false
	}
	return d, d != p
}

// IsExternal reports whether target carries a URL scheme (http:, mailto:, …).
// Windows drive paths like C:/x are NOT considered external, and file: URLs
// are treated as absolute local references by callers, not as external links.
func IsExternal(target string) bool {
	if driveRe.MatchString(target) {
		return false
	}
	return schemeRe.MatchString(target)
}

// IsAbsoluteLike reports whether target is an absolute filesystem reference:
// drive-letter paths, UNC paths, rooted slashes, or home-relative (~) paths.
func IsAbsoluteLike(target string) bool {
	t := target
	if driveRe.MatchString(t) {
		return true
	}
	if strings.HasPrefix(t, "\\\\") || strings.HasPrefix(t, "//") {
		return true
	}
	if strings.HasPrefix(t, "/") || strings.HasPrefix(t, "\\") {
		return true
	}
	if t == "~" || strings.HasPrefix(t, "~/") || strings.HasPrefix(t, "~\\") {
		return true
	}
	return false
}

// ResolveWithin resolves target against baseDir (both slash-separated and
// relative to the same root; baseDir "" means the root itself). It returns
// the root-relative resolved path and whether the resolution escapes the
// root through upward traversal.
func ResolveWithin(baseDir, target string) (resolved string, escaped bool) {
	joined := path.Join(baseDir, ToSlash(target))
	if joined == ".." || strings.HasPrefix(joined, "../") {
		return joined, true
	}
	if joined == "." {
		joined = ""
	}
	return joined, false
}

// WithinDir reports whether rel (root-relative, slash form) lies inside dir
// (also root-relative; "" means the root itself). Comparison optionally folds
// case, which matches Windows and macOS filesystem semantics.
func WithinDir(dir, rel string, foldCase bool) bool {
	if dir == "" || dir == "." {
		return true
	}
	d, r := dir, rel
	if foldCase {
		d, r = strings.ToLower(d), strings.ToLower(r)
	}
	return r == d || strings.HasPrefix(r, d+"/")
}

// HasDotDot reports whether the cleaned slash path still contains an upward
// traversal segment.
func HasDotDot(p string) bool {
	clean := path.Clean(ToSlash(p))
	return clean == ".." || strings.HasPrefix(clean, "../") || strings.Contains(clean, "/../")
}
