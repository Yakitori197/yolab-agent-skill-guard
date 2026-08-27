#!/bin/sh
# Entrypoint for the skillguard GitHub Action (POSIX sh).
#
# Every security decision about the untrusted inputs is made by
# "skillguard action-paths", a unit-tested Go helper: it rejects absolute,
# UNC, drive-letter, traversal, dash-leading and control-character values,
# resolves symlinks, and proves that each resulting path stays inside
# GITHUB_WORKSPACE. This script only forwards values and consumes the
# validated ones, so no containment logic lives in shell quoting.
set -eu

path="${1:-.}"
config="${2:-}"
fail_on="${3:-high}"
format="${4:-sarif}"
output="${5:-skillguard-report.sarif}"
workspace="${GITHUB_WORKSPACE:-$(pwd)}"

case "$fail_on" in
  critical|high|medium|low|info|none) ;;
  *) echo "skillguard-action: invalid fail-on value" >&2; exit 2 ;;
esac
case "$format" in
  text|json|sarif|html) ;;
  *) echo "skillguard-action: invalid format value" >&2; exit 2 ;;
esac

# Validate and resolve path/config/output. Any violation exits 2 here.
if ! resolved="$(skillguard action-paths --workspace "$workspace" \
    --path "$path" --config "$config" --output "$output")"; then
  echo "skillguard-action: refusing to run with the supplied path inputs" >&2
  exit 2
fi

scan_path="$(printf '%s\n' "$resolved" | sed -n 's/^path=//p')"
scan_config="$(printf '%s\n' "$resolved" | sed -n 's/^config=//p')"
scan_output="$(printf '%s\n' "$resolved" | sed -n 's/^output=//p')"
report_rel="$(printf '%s\n' "$resolved" | sed -n 's/^report-path=//p')"

if [ -z "$scan_path" ] || [ -z "$scan_output" ] || [ -z "$report_rel" ]; then
  echo "skillguard-action: path validation produced no usable result" >&2
  exit 2
fi

summary_file="$(mktemp)"

# "--" terminates flag parsing so a validated path can never be read as a flag.
set +e
if [ -n "$scan_config" ]; then
  skillguard scan --config "$scan_config" --fail-on "$fail_on" \
    --format "$format" --output "$scan_output" --summary "$summary_file" \
    --no-clobber --no-color -- "$scan_path"
else
  skillguard scan --fail-on "$fail_on" \
    --format "$format" --output "$scan_output" --summary "$summary_file" \
    --no-clobber --no-color -- "$scan_path"
fi
rc=$?
set -e

if [ "$rc" -eq 2 ]; then
  echo "skillguard-action: scan failed with a configuration or runtime error" >&2
  exit 2
fi

if [ -n "${GITHUB_OUTPUT:-}" ]; then
  # Counters are plain key=value integers produced by the scanner, and
  # report-path is the validated single-line workspace-relative path.
  cat "$summary_file" >> "$GITHUB_OUTPUT"
  echo "report-path=$report_rel" >> "$GITHUB_OUTPUT"
fi

echo "skillguard-action: report written to $report_rel (exit $rc)"
exit "$rc"
