// Package config loads and validates .skillguard.yml. Configuration errors
// always fail closed: the scan refuses to run (exit code 2) rather than
// silently skipping checks.
package config

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"regexp"
	"sort"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/Yakitori197/yolab-agent-skill-guard/internal/model"
)

// SchemaVersion is the only supported configuration schema version.
const SchemaVersion = 1

// Bounds for max_file_size (bytes).
const (
	MinFileSize     = 1024
	MaxFileSizeCap  = 16 * 1024 * 1024
	DefaultFileSize = 1024 * 1024
)

// DefaultSource is the display name used when no config file exists.
const DefaultSource = "built-in defaults"

var fingerprintRe = regexp.MustCompile(`^[0-9a-f]{16}$`)

// Suppression silences one known finding. Every suppression must carry a
// non-empty reason; expired suppressions stop matching and are surfaced as
// informational findings by the engine.
type Suppression struct {
	Rule        string
	Path        string
	Fingerprint string
	Reason      string
	Expires     string // YYYY-MM-DD, inclusive

	pathRe *regexp.Regexp
}

// Config is the fully validated runtime configuration.
type Config struct {
	Version             int
	FailOn              model.FailOn
	Platforms           []model.Platform
	Include             []string
	Exclude             []string
	MaxFileSize         int64
	AllowedDomains      []string
	AllowedCapabilities []string
	DisabledRules       []string
	SeverityOverrides   map[string]model.Severity
	Suppressions        []Suppression

	// Source is the display name of the config file (root-relative when
	// auto-discovered) or DefaultSource.
	Source string

	includeRe []*regexp.Regexp
	excludeRe []*regexp.Regexp
}

type fileConfig struct {
	Version             *int              `yaml:"version"`
	FailOn              *string           `yaml:"fail_on"`
	Platforms           []string          `yaml:"platforms"`
	Include             []string          `yaml:"include"`
	Exclude             []string          `yaml:"exclude"`
	MaxFileSize         *int64            `yaml:"max_file_size"`
	AllowedDomains      []string          `yaml:"allowed_domains"`
	AllowedCapabilities []string          `yaml:"allowed_capabilities"`
	DisabledRules       []string          `yaml:"disabled_rules"`
	SeverityOverrides   map[string]string `yaml:"severity_overrides"`
	Suppressions        []fileSuppression `yaml:"suppressions"`
}

type fileSuppression struct {
	Rule        string `yaml:"rule"`
	Path        string `yaml:"path"`
	Fingerprint string `yaml:"fingerprint"`
	Reason      string `yaml:"reason"`
	Expires     string `yaml:"expires"`
}

// Default returns the built-in configuration.
func Default() *Config {
	return &Config{
		Version:     SchemaVersion,
		FailOn:      model.FailOn(model.SeverityHigh),
		Platforms:   append([]model.Platform(nil), model.Platforms...),
		MaxFileSize: DefaultFileSize,
		Source:      DefaultSource,
	}
}

// Parse builds a Config from raw YAML. source is the display name used in
// error messages; knownRules and detectionRules validate rule references.
func Parse(raw []byte, source string, knownRules, detectionRules []string) (*Config, error) {
	cfg := Default()
	cfg.Source = source

	dec := yaml.NewDecoder(bytes.NewReader(raw))
	dec.KnownFields(true)
	var fc fileConfig
	if err := decodeStrict(dec, &fc); err != nil {
		return nil, fmt.Errorf("config %s: %w", source, err)
	}

	if fc.Version == nil {
		return nil, fmt.Errorf("config %s: missing required field %q", source, "version")
	}
	if *fc.Version != SchemaVersion {
		return nil, fmt.Errorf("config %s: unsupported version %d (this build supports version %d)", source, *fc.Version, SchemaVersion)
	}
	cfg.Version = *fc.Version

	if fc.FailOn != nil {
		fo, err := model.ParseFailOn(*fc.FailOn)
		if err != nil {
			return nil, fmt.Errorf("config %s: fail_on: %w", source, err)
		}
		cfg.FailOn = fo
	}
	if fc.Platforms != nil {
		if len(fc.Platforms) == 0 {
			return nil, fmt.Errorf("config %s: platforms must not be empty when present", source)
		}
		cfg.Platforms = cfg.Platforms[:0]
		for _, p := range fc.Platforms {
			pp, err := model.ParsePlatform(p)
			if err != nil {
				return nil, fmt.Errorf("config %s: platforms: %w", source, err)
			}
			cfg.Platforms = append(cfg.Platforms, pp)
		}
	}
	cfg.Include = fc.Include
	cfg.Exclude = fc.Exclude
	if fc.MaxFileSize != nil {
		if *fc.MaxFileSize < MinFileSize || *fc.MaxFileSize > MaxFileSizeCap {
			return nil, fmt.Errorf("config %s: max_file_size must be between %d and %d bytes", source, MinFileSize, MaxFileSizeCap)
		}
		cfg.MaxFileSize = *fc.MaxFileSize
	}
	for _, d := range fc.AllowedDomains {
		if strings.TrimSpace(d) == "" {
			return nil, fmt.Errorf("config %s: allowed_domains entries must not be empty", source)
		}
	}
	cfg.AllowedDomains = fc.AllowedDomains
	cfg.AllowedCapabilities = fc.AllowedCapabilities

	known := toSet(knownRules)
	for _, id := range fc.DisabledRules {
		if !known[id] {
			return nil, fmt.Errorf("config %s: disabled_rules references unknown rule %q", source, id)
		}
	}
	cfg.DisabledRules = fc.DisabledRules
	if allDisabled(fc.DisabledRules, detectionRules) {
		return nil, fmt.Errorf("config %s: disabled_rules disables every detection rule; disabling everything is not allowed", source)
	}

	if fc.SeverityOverrides != nil {
		cfg.SeverityOverrides = make(map[string]model.Severity, len(fc.SeverityOverrides))
		ids := make([]string, 0, len(fc.SeverityOverrides))
		for id := range fc.SeverityOverrides {
			ids = append(ids, id)
		}
		sort.Strings(ids)
		for _, id := range ids {
			if !known[id] {
				return nil, fmt.Errorf("config %s: severity_overrides references unknown rule %q", source, id)
			}
			sev, err := model.ParseSeverity(fc.SeverityOverrides[id])
			if err != nil {
				return nil, fmt.Errorf("config %s: severity_overrides[%s]: %w", source, id, err)
			}
			cfg.SeverityOverrides[id] = sev
		}
	}

	for i, s := range fc.Suppressions {
		sup := Suppression{Rule: s.Rule, Path: s.Path, Fingerprint: s.Fingerprint, Reason: s.Reason, Expires: s.Expires}
		if err := sup.validate(known); err != nil {
			return nil, fmt.Errorf("config %s: suppressions[%d]: %w", source, i, err)
		}
		if sup.Path != "" {
			re, err := CompileGlob(sup.Path)
			if err != nil {
				return nil, fmt.Errorf("config %s: suppressions[%d]: path: %w", source, i, err)
			}
			sup.pathRe = re
		}
		cfg.Suppressions = append(cfg.Suppressions, sup)
	}

	for i, pat := range cfg.Include {
		re, err := CompileGlob(pat)
		if err != nil {
			return nil, fmt.Errorf("config %s: include[%d]: %w", source, i, err)
		}
		cfg.includeRe = append(cfg.includeRe, re)
	}
	for i, pat := range cfg.Exclude {
		re, err := CompileGlob(pat)
		if err != nil {
			return nil, fmt.Errorf("config %s: exclude[%d]: %w", source, i, err)
		}
		cfg.excludeRe = append(cfg.excludeRe, re)
	}
	return cfg, nil
}

// decodeStrict reads exactly one YAML document with unknown-field rejection.
//
// A second document in the stream is refused rather than ignored: a file whose
// visible top half says "fail_on: high" and whose second document says
// something else must never be accepted, because the reader and the tool would
// disagree about what the policy is.
func decodeStrict(dec *yaml.Decoder, out *fileConfig) (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("yaml parser failure: %v", r)
		}
	}()
	err = dec.Decode(out)
	if errors.Is(err, io.EOF) {
		return errors.New("configuration file is empty")
	}
	if err != nil {
		return err
	}
	var extra yaml.Node
	if next := dec.Decode(&extra); !errors.Is(next, io.EOF) {
		if next != nil {
			return fmt.Errorf("trailing content after the first YAML document: %w", next)
		}
		return errors.New("configuration must contain exactly one YAML document (a second document was found after a \"---\" separator)")
	}
	return nil
}

func (s *Suppression) validate(known map[string]bool) error {
	if s.Rule == "" {
		return errors.New("missing required field \"rule\"")
	}
	if !known[s.Rule] {
		return fmt.Errorf("unknown rule %q", s.Rule)
	}
	if strings.TrimSpace(s.Reason) == "" {
		return errors.New("a non-empty \"reason\" is required for every suppression")
	}
	if s.Path == "" && s.Fingerprint == "" {
		return errors.New("either \"path\" or \"fingerprint\" is required")
	}
	if s.Fingerprint != "" && !fingerprintRe.MatchString(s.Fingerprint) {
		return fmt.Errorf("fingerprint %q is not a valid finding fingerprint (16 hex characters)", s.Fingerprint)
	}
	if s.Path != "" {
		if err := validateSuppressionPath(s.Path, s.Fingerprint != ""); err != nil {
			return err
		}
	}
	if s.Expires != "" {
		if _, err := time.Parse("2006-01-02", s.Expires); err != nil {
			return fmt.Errorf("expires %q is not a valid YYYY-MM-DD date", s.Expires)
		}
	}
	return nil
}

// validateSuppressionPath keeps suppression scope as narrow as the
// documentation promises.
//
// A plain relative file path is the normal, encouraged form. Wildcards are
// accepted only alongside a fingerprint — which pins the exception to one
// specific finding — and even then a pattern that could cover the whole
// supported file set is refused, so no exception can silently grow to cover
// findings nobody reviewed.
func validateSuppressionPath(pattern string, hasFingerprint bool) error {
	if !strings.ContainsAny(pattern, "*?") {
		return nil
	}
	if !hasFingerprint {
		return fmt.Errorf("path pattern %q contains a wildcard; suppressions must name a specific file, or pair the pattern with a fingerprint", pattern)
	}
	segments := strings.Split(pattern, "/")
	last := segments[len(segments)-1]
	switch {
	case segments[0] == "**" || segments[0] == "*":
		return fmt.Errorf("path pattern %q is unanchored and could match the whole repository; anchor it to a directory", pattern)
	case last == "**" || last == "*":
		return fmt.Errorf("path pattern %q matches every file below it; name the file the exception applies to", pattern)
	case wildcardNameRe.MatchString(last):
		return fmt.Errorf("path pattern %q wildcards the entire file name; name the file the exception applies to", pattern)
	}
	return nil
}

// Expired reports whether the suppression has lapsed at the given time.
// The expiry date itself is still valid (inclusive).
func (s *Suppression) Expired(now time.Time) bool {
	if s.Expires == "" {
		return false
	}
	return now.UTC().Format("2006-01-02") > s.Expires
}

// Matches reports whether the suppression applies to the finding. When both
// a path pattern and a fingerprint are present, both must match.
func (s *Suppression) Matches(f model.Finding) bool {
	if s.Rule != f.RuleID {
		return false
	}
	if s.Fingerprint != "" && s.Fingerprint != f.Fingerprint {
		return false
	}
	if s.pathRe != nil && !s.pathRe.MatchString(f.Path) {
		return false
	}
	return true
}

// IncludeMatch reports whether relPath passes the include list (an empty
// list includes every supported file).
func (c *Config) IncludeMatch(relPath string) bool {
	if len(c.includeRe) == 0 {
		return true
	}
	for _, re := range c.includeRe {
		if re.MatchString(relPath) {
			return true
		}
	}
	return false
}

// ExcludeMatch reports whether relPath is excluded by configuration.
func (c *Config) ExcludeMatch(relPath string) bool {
	for _, re := range c.excludeRe {
		if re.MatchString(relPath) {
			return true
		}
	}
	return false
}

// PlatformEnabled reports whether findings for platform p are in scope.
func (c *Config) PlatformEnabled(p model.Platform) bool {
	for _, x := range c.Platforms {
		if x == p {
			return true
		}
	}
	return false
}

// DomainAllowed reports whether host is covered by allowed_domains: exact
// match, subdomain of an entry, or wildcard entries like "*.example.com".
func (c *Config) DomainAllowed(host string) bool {
	h := strings.ToLower(strings.TrimSuffix(host, "."))
	for _, d := range c.AllowedDomains {
		dd := strings.ToLower(strings.TrimSpace(d))
		if dd == "" {
			continue
		}
		if strings.HasPrefix(dd, "*.") {
			if strings.HasSuffix(h, dd[1:]) {
				return true
			}
			continue
		}
		if h == dd || strings.HasSuffix(h, "."+dd) {
			return true
		}
	}
	return false
}

// CapabilityAllowed reports whether a declared capability is permitted.
func (c *Config) CapabilityAllowed(capability string) bool {
	for _, a := range c.AllowedCapabilities {
		if strings.EqualFold(strings.TrimSpace(a), strings.TrimSpace(capability)) {
			return true
		}
	}
	return false
}

// RuleDisabled reports whether the rule is disabled by configuration.
func (c *Config) RuleDisabled(id string) bool {
	for _, d := range c.DisabledRules {
		if d == id {
			return true
		}
	}
	return false
}

// CompileGlob converts a limited glob (*, ?, **) into an anchored regexp.
// Patterns are matched against root-relative slash paths. Absolute patterns,
// backslashes, and upward traversal are rejected so configuration cannot
// widen the scan beyond the root.
func CompileGlob(pattern string) (*regexp.Regexp, error) {
	if strings.TrimSpace(pattern) == "" {
		return nil, errors.New("empty pattern")
	}
	if strings.Contains(pattern, "\\") {
		return nil, fmt.Errorf("pattern %q must use forward slashes", pattern)
	}
	if strings.HasPrefix(pattern, "/") || driveGlobRe.MatchString(pattern) {
		return nil, fmt.Errorf("pattern %q must be relative to the scan root", pattern)
	}
	for _, seg := range strings.Split(pattern, "/") {
		if seg == ".." {
			return nil, fmt.Errorf("pattern %q must not contain %q", pattern, "..")
		}
	}
	var b strings.Builder
	b.WriteString("^")
	i := 0
	for i < len(pattern) {
		c := pattern[i]
		switch c {
		case '*':
			switch {
			case strings.HasPrefix(pattern[i:], "**/"):
				b.WriteString(`(?:[^/]+/)*`)
				i += 3
			case strings.HasPrefix(pattern[i:], "**"):
				b.WriteString(`.*`)
				i += 2
			default:
				b.WriteString(`[^/]*`)
				i++
			}
		case '?':
			b.WriteString(`[^/]`)
			i++
		default:
			b.WriteString(regexp.QuoteMeta(string(c)))
			i++
		}
	}
	b.WriteString("$")
	return regexp.Compile(b.String())
}

var driveGlobRe = regexp.MustCompile(`^[A-Za-z]:`)

// wildcardNameRe matches file names made entirely of wildcards, with or
// without a wildcarded extension: *, *.*, *.md, *.md*.
var wildcardNameRe = regexp.MustCompile(`^[*?]+(\.[A-Za-z0-9*?]*)?$`)

func toSet(ss []string) map[string]bool {
	m := make(map[string]bool, len(ss))
	for _, s := range ss {
		m[s] = true
	}
	return m
}

func allDisabled(disabled, detection []string) bool {
	if len(detection) == 0 {
		return false
	}
	set := toSet(disabled)
	for _, id := range detection {
		if !set[id] {
			return false
		}
	}
	return true
}
