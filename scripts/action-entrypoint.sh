#!/bin/sh
# Entrypoint for the skillguard GitHub Action (POSIX sh).
#
# Every security decision about the untrusted inputs is made by
# "skillguard action-paths", a unit-tested Go helper: it rejects absolute,
# UNC, drive-letter, traversal, dash-leading and control-character values,
# resolves symlinks, and proves that each resulting path stays inside
# GITHUB_WORKSPACE. This script only forwards values and consumes the
# validated ones, so no containment logic lives in shell quoting.
#
# Output rule, without exception: printf with a literal format string, never
# echo. A backslash is a legal character in a POSIX filename, so skillguard
# rightly accepts one -- but the XSI echo that /bin/sh provides on Alpine
# (BusyBox ash) and Debian (dash) interprets backslash escapes inside its
# argument. A report named a\tb.json would be reported with a real tab,
# a\nb.json would split into two lines and forge an extra GITHUB_OUTPUT
# entry, and a\cb.json would truncate the line at the "a". printf copies a
# %s argument verbatim, and keeping the format string a literal means a % in
# the value is data too.
set -eu

path="${1:-.}"
config="${2:-}"
fail_on="${3:-high}"
format="${4:-sarif}"
output="${5:-skillguard-report.sarif}"
workspace="${GITHUB_WORKSPACE:-$(pwd)}"

case "$fail_on" in
  critical|high|medium|low|info|none) ;;
  *) printf 'skillguard-action: invalid fail-on value\n' >&2; exit 2 ;;
esac
case "$format" in
  text|json|sarif|html) ;;
  *) printf 'skillguard-action: invalid format value\n' >&2; exit 2 ;;
esac

# Validate and resolve path/config/output. Any violation exits 2 here.
if ! resolved="$(skillguard action-paths --workspace "$workspace" \
    --path "$path" --config "$config" --output "$output")"; then
  printf 'skillguard-action: refusing to run with the supplied path inputs\n' >&2
  exit 2
fi

scan_path="$(printf '%s\n' "$resolved" | sed -n 's/^path=//p')"
scan_config="$(printf '%s\n' "$resolved" | sed -n 's/^config=//p')"
scan_output="$(printf '%s\n' "$resolved" | sed -n 's/^output=//p')"
report_rel="$(printf '%s\n' "$resolved" | sed -n 's/^report-path=//p')"

if [ -z "$scan_path" ] || [ -z "$scan_output" ] || [ -z "$report_rel" ]; then
  printf 'skillguard-action: path validation produced no usable result\n' >&2
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
  printf 'skillguard-action: scan failed with a configuration or runtime error\n' >&2
  exit 2
fi

if [ -n "${GITHUB_OUTPUT:-}" ]; then
  # Counters are plain key=value integers produced by the scanner, and
  # report-path is the validated single-line workspace-relative path. Both go
  # out through printf for the reason given at the top of this file.
  cat "$summary_file" >> "$GITHUB_OUTPUT"
  printf 'report-path=%s\n' "$report_rel" >> "$GITHUB_OUTPUT"
fi

# The report path is a machine value: it is a filename exactly as the caller
# asked for it, and it may legally contain characters a terminal acts on. It
# goes to GITHUB_OUTPUT verbatim above and is deliberately not printed here --
# escaping it for display would show something that is not the real path, and
# printing it raw would hand the runner log whatever the name contains.
printf 'skillguard-action: report created (exit %s)\n' "$rc"
exit "$rc"
