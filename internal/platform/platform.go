// Package platform classifies scanned files into agent ecosystems and
// determines each file's package root for containment checks.
package platform

import (
	"strings"

	"github.com/Yakitori197/yolab-agent-skill-guard/internal/model"
)

// Classify determines the platform of a file and its package root directory.
// relPath is slash-separated and relative to the scan root. skillDirs holds
// every directory (root-relative; "" for the root itself) that directly
// contains a SKILL.md; such directories form self-contained skill packages.
func Classify(relPath string, skillDirs map[string]bool) (p model.Platform, packageRoot string) {
	dir, base := splitPath(relPath)
	lowerBase := strings.ToLower(base)

	packageRoot = nearestSkillDir(dir, skillDirs)

	switch {
	case lowerBase == "skill.md":
		return model.PlatformClaude, dir
	case lowerBase == "agents.md":
		return model.PlatformCodex, packageRoot
	case lowerBase == "claude.md":
		return model.PlatformClaude, packageRoot
	case strings.HasSuffix(lowerBase, ".mdc"):
		return model.PlatformCursor, packageRoot
	}
	segments := strings.Split(relPath, "/")
	for _, seg := range segments[:len(segments)-1] {
		switch strings.ToLower(seg) {
		case ".claude":
			return model.PlatformClaude, packageRoot
		case ".cursor":
			return model.PlatformCursor, packageRoot
		}
	}
	if packageRoot != "" || skillDirs[dir] {
		return model.PlatformClaude, packageRoot
	}
	return model.PlatformGeneric, packageRoot
}

func splitPath(relPath string) (dir, base string) {
	idx := strings.LastIndex(relPath, "/")
	if idx < 0 {
		return "", relPath
	}
	return relPath[:idx], relPath[idx+1:]
}

// nearestSkillDir walks upward from dir to the root, returning the first
// directory that is a skill package. "" doubles as "no package boundary" and
// "the scan root itself"; both meanings make the scan root the containment
// boundary, which is the intended behavior.
func nearestSkillDir(dir string, skillDirs map[string]bool) string {
	d := dir
	for {
		if skillDirs[d] {
			return d
		}
		if d == "" {
			return ""
		}
		idx := strings.LastIndex(d, "/")
		if idx < 0 {
			d = ""
		} else {
			d = d[:idx]
		}
	}
}
