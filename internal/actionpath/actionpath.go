// Package actionpath validates the untrusted path inputs a CI wrapper (the
// GitHub Action) hands to skillguard, and resolves them to absolute paths that
// are provably inside the workspace.
//
// The rules deliberately live in Go rather than in the entrypoint shell script:
// containment, symlink resolution, and control-character handling are exactly
// the checks that shell quoting gets wrong, and here they are unit-testable on
// every platform.
package actionpath

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/Yakitori197/yolab-agent-skill-guard/internal/discovery"
)

// Kind selects the validation profile for one input.
type Kind string

// Input kinds.
const (
	// KindScan is the path to scan: must exist, file or directory.
	KindScan Kind = "path"
	// KindConfig is a configuration file: must exist and be a regular file.
	KindConfig Kind = "config"
	// KindOutput is a report destination: it must not exist yet, and its
	// immediate parent directory must already exist inside the workspace.
	KindOutput Kind = "output"
)

// Result is a validated input.
type Result struct {
	// Abs is the absolute path to pass to the scanner.
	Abs string
	// Rel is the workspace-relative slash path: a single line, safe to write
	// into GITHUB_OUTPUT and free of local absolute path information.
	Rel string
}

// Resolve validates one input against the workspace.
//
// Error messages quote only the caller-supplied value (which is required to be
// workspace-relative) and never a resolved local absolute path.
func Resolve(workspace, value string, kind Kind) (Result, error) {
	if strings.TrimSpace(workspace) == "" {
		return Result{}, errors.New("workspace directory is not set")
	}
	if err := checkSyntax(value, kind); err != nil {
		return Result{}, err
	}
	wsReal, err := filepath.EvalSymlinks(workspace)
	if err != nil {
		return Result{}, errors.New("workspace directory does not exist or is not readable")
	}
	wsInfo, err := os.Stat(wsReal)
	if err != nil || !wsInfo.IsDir() {
		return Result{}, errors.New("workspace path is not a directory")
	}

	candidate := filepath.Join(wsReal, filepath.FromSlash(value))
	if err := requireInside(wsReal, candidate, value); err != nil {
		return Result{}, err
	}

	var final string
	switch kind {
	case KindScan, KindConfig:
		final, err = resolveExisting(wsReal, candidate, value, kind)
	case KindOutput:
		final, err = resolveOutput(wsReal, candidate, value)
	default:
		return Result{}, fmt.Errorf("unknown input kind %q", string(kind))
	}
	if err != nil {
		return Result{}, err
	}

	rel, err := relSlash(wsReal, final)
	if err != nil {
		return Result{}, fmt.Errorf("%s %q resolves outside the workspace", string(kind), value)
	}
	return Result{Abs: final, Rel: rel}, nil
}

// checkSyntax rejects everything that must never reach the filesystem layer.
func checkSyntax(value string, kind Kind) error {
	if value == "" {
		return fmt.Errorf("%s input must not be empty", string(kind))
	}
	for _, r := range value {
		if r < 0x20 || r == 0x7f || (r >= 0x80 && r <= 0x9f) {
			return fmt.Errorf("%s input contains a control character (0x%02x); newlines, carriage returns, and NUL bytes are not allowed", string(kind), r)
		}
	}
	if strings.HasPrefix(value, "-") {
		return fmt.Errorf("%s input must not start with a dash, which would be parsed as a command-line flag", string(kind))
	}
	if isAbsoluteLike(value) {
		return fmt.Errorf("%s input must be a relative path inside the workspace (absolute, drive-letter, UNC, and home-relative paths are rejected)", string(kind))
	}
	for _, seg := range strings.FieldsFunc(value, isSeparator) {
		if seg == ".." {
			return fmt.Errorf("%s input %q must not contain upward traversal", string(kind), value)
		}
	}
	return nil
}

// isSeparator treats both slash flavors as separators so a Windows-style
// value is split the same way on a Linux runner.
func isSeparator(r rune) bool { return r == '/' || r == '\\' }

// isAbsoluteLike reports absolute references however they are spelled, so a
// Windows-style value is rejected on Linux runners too.
func isAbsoluteLike(v string) bool {
	switch {
	case strings.HasPrefix(v, "/"), strings.HasPrefix(v, "\\"):
		return true
	case strings.HasPrefix(v, "~"):
		return true
	case len(v) >= 2 && v[1] == ':' && isDriveLetter(v[0]):
		return true
	}
	return false
}

func isDriveLetter(b byte) bool {
	return (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z')
}

// resolveExisting resolves an input that must already exist, following symlinks
// and re-checking containment on the real target.
func resolveExisting(wsReal, candidate, value string, kind Kind) (string, error) {
	realPath, err := filepath.EvalSymlinks(candidate)
	if err != nil {
		return "", fmt.Errorf("%s %q does not exist in the workspace", string(kind), value)
	}
	if err := requireInside(wsReal, realPath, value); err != nil {
		return "", fmt.Errorf("%s %q resolves outside the workspace through a symbolic link", string(kind), value)
	}
	info, err := os.Stat(realPath)
	if err != nil {
		return "", fmt.Errorf("%s %q is not readable", string(kind), value)
	}
	if kind == KindConfig && !info.Mode().IsRegular() {
		return "", fmt.Errorf("config %q is not a regular file", value)
	}
	if kind == KindScan && !info.IsDir() && !info.Mode().IsRegular() {
		return "", fmt.Errorf("path %q is neither a file nor a directory", value)
	}
	return realPath, nil
}

// resolveOutput validates a destination that must not exist yet but whose
// immediate parent directory must already exist.
//
// No-clobber is unconditional: if anything already exists at the path — a
// regular file, a previous report, a directory, a symlink, or a hard link to
// something else — the run is refused. An allow-list of "safe to overwrite"
// names could never be complete (package.json, LICENSE, Makefile, Dockerfile,
// extensionless files, …), so nothing is overwritten at all.
//
// Only the immediate parent is consulted, and it is never created. Accepting a
// path whose intermediate directories are missing would either promise a write
// that the O_EXCL open cannot perform, or oblige the action to create folders
// the user never asked for; both are worse than refusing the input. The parent
// is resolved through symlinks and containment-checked, so a symlinked
// directory cannot redirect the report outside the workspace.
func resolveOutput(wsReal, candidate, value string) (string, error) {
	if _, err := os.Lstat(candidate); err == nil {
		return "", fmt.Errorf("output %q already exists; the action never overwrites an existing path", value)
	}

	dir := filepath.Dir(candidate)
	if _, err := os.Lstat(dir); err != nil {
		return "", fmt.Errorf("output %q needs an existing parent directory; the action does not create directories", value)
	}
	realDir, err := filepath.EvalSymlinks(dir)
	if err != nil {
		return "", fmt.Errorf("output %q has an unreadable parent directory", value)
	}
	info, err := os.Stat(realDir)
	if err != nil {
		return "", fmt.Errorf("output %q has an unreadable parent directory", value)
	}
	if !info.IsDir() {
		return "", fmt.Errorf("output %q has a parent path that is not a directory", value)
	}
	if err := requireInside(wsReal, realDir, value); err != nil {
		return "", fmt.Errorf("output %q resolves outside the workspace through a symbolic link", value)
	}
	final := filepath.Join(realDir, filepath.Base(candidate))
	if err := requireInside(wsReal, final, value); err != nil {
		return "", err
	}
	return final, nil
}

func requireInside(wsReal, p, value string) error {
	inside, err := discovery.WithinRootAbs(wsReal, p)
	if err != nil || !inside {
		return fmt.Errorf("%q resolves outside the workspace", value)
	}
	return nil
}

// relSlash renders a workspace-relative slash path, rejecting any residual
// traversal so the value written to GITHUB_OUTPUT is always contained.
func relSlash(wsReal, p string) (string, error) {
	rel, err := filepath.Rel(wsReal, p)
	if err != nil {
		return "", err
	}
	rel = filepath.ToSlash(rel)
	if rel == ".." || strings.HasPrefix(rel, "../") {
		return "", errors.New("path escapes the workspace")
	}
	if strings.ContainsAny(rel, "\r\n\x00") {
		return "", errors.New("path contains a control character")
	}
	return rel, nil
}

// SameTarget reports whether two validated results point at the same file, so a
// caller can refuse to write a report over its own input.
func SameTarget(a, b Result) bool {
	if a.Abs == "" || b.Abs == "" {
		return false
	}
	if a.Abs == b.Abs {
		return true
	}
	if discovery.CaseInsensitiveFS() {
		return strings.EqualFold(a.Abs, b.Abs)
	}
	return false
}
