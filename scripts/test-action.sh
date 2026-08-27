#!/bin/sh
# Contract tests for the GitHub Action entrypoint.
#
# Runs the real scripts/action-entrypoint.sh against a throw-away workspace
# with a locally built binary (no Docker, no network, no secrets), asserting
# both the happy paths and the hostile-input rejections. The path rules
# themselves are unit-tested in internal/actionpath; this file proves the
# entrypoint actually enforces them end to end.
set -eu

cd "$(dirname "$0")/.."
REPO="$(pwd)"

ext=""
if [ "$(go env GOOS)" = "windows" ]; then
  ext=".exe"
fi

BIN_DIR="$(mktemp -d)"
WS="$(mktemp -d)"
OUTSIDE="$(mktemp -d)"
trap 'rm -rf "$BIN_DIR" "$WS" "$OUTSIDE"' EXIT

echo "test-action: building skillguard..."
go build -o "$BIN_DIR/skillguard$ext" ./cmd/skillguard
PATH="$BIN_DIR:$PATH"
export PATH

# Throw-away workspace so symlink cases never touch the repository.
mkdir -p "$WS/safe-skill/references" "$WS/risky-skill/setup" "$WS/reports"
cp -R "$REPO/examples/safe-skill/." "$WS/safe-skill/"
cp -R "$REPO/examples/risky-skill/." "$WS/risky-skill/"
printf 'version: 1\nfail_on: high\n' > "$WS/ci.yml"
printf 'outside content\n' > "$OUTSIDE/secret.md"
printf 'version: 1\n' > "$OUTSIDE/evil.yml"

export GITHUB_WORKSPACE="$WS"

fail=0
run_case() {
  desc="$1"; want="$2"; shift 2
  GITHUB_OUTPUT="$WS/gh-output.txt"
  : > "$GITHUB_OUTPUT"
  export GITHUB_OUTPUT
  set +e
  sh scripts/action-entrypoint.sh "$@" >/dev/null 2>&1
  rc=$?
  set -e
  if [ "$rc" -ne "$want" ]; then
    echo "FAIL: $desc exited $rc, want $want"
    fail=1
  else
    echo "ok: $desc (exit $rc)"
  fi
}

# Backslashes are produced without embedding literal escapes in this script.
BS="$(awk 'BEGIN{printf "%c", 92}')"
WIN_DRIVE="C:${BS}Windows${BS}System32"
UNC="${BS}${BS}server${BS}share"
CRLF_VALUE="$(awk 'BEGIN{printf "report.sarif%c%cfindings=999", 13, 10}')"

echo "--- happy paths ---"
run_case "safe fixture"            0 "safe-skill"  ""        "high" "sarif" "reports/safe.sarif"
run_case "safe fixture w/ config"  0 "safe-skill"  "ci.yml"  "high" "json"  "reports/safe.json"
run_case "risky fixture fails"     1 "risky-skill" ""        "high" "json"  "reports/risky.json"

echo "--- hostile path inputs ---"
run_case "parent traversal"        2 "../"                     "" "high" "sarif" "reports/x.sarif"
run_case "posix absolute"          2 "/etc"                    "" "high" "sarif" "reports/x.sarif"
run_case "windows drive"           2 "$WIN_DRIVE"              "" "high" "sarif" "reports/x.sarif"
run_case "unc share"               2 "$UNC"                    "" "high" "sarif" "reports/x.sarif"
run_case "dash-leading path"       2 "-rf"                     "" "high" "sarif" "reports/x.sarif"
run_case "absolute outside dir"    2 "$OUTSIDE"                "" "high" "sarif" "reports/x.sarif"
run_case "missing path"            2 "no-such-dir"             "" "high" "sarif" "reports/x.sarif"

echo "--- hostile config inputs ---"
run_case "config traversal"        2 "safe-skill" "../../etc/passwd" "high" "sarif" "reports/x.sarif"
run_case "config absolute"         2 "safe-skill" "/etc/passwd"      "high" "sarif" "reports/x.sarif"

echo "--- hostile output inputs ---"
run_case "output traversal"        2 "safe-skill" "" "high" "sarif" "../escape.sarif"
run_case "output absolute"         2 "safe-skill" "" "high" "sarif" "/tmp/escape.sarif"
run_case "output CR/LF injection"  2 "safe-skill" "" "high" "sarif" "$CRLF_VALUE"
run_case "output is a directory"   2 "safe-skill" "" "high" "sarif" "reports"

echo "--- output parent directory must already exist ---"
# The action never creates directories: a missing immediate parent is refused
# by the helper, so the O_EXCL write is never reached and nothing is created.
printf 'parent sentinel\n' > "$WS/plain-file"
run_case "output missing parent"     2 "safe-skill" "" "high" "sarif" "missing/report.sarif"
run_case "output missing parents"    2 "safe-skill" "" "high" "json"  "missing/a/b/report.json"
run_case "output parent is a file"   2 "safe-skill" "" "high" "sarif" "plain-file/report.sarif"
for leftover in "missing" "missing/a" "missing/a/b" "missing/report.sarif" "missing/a/b/report.json"; do
  if [ -e "$WS/$leftover" ]; then
    echo "FAIL: a refused run created $leftover"
    fail=1
  fi
done
[ "$(cat "$WS/plain-file")" = "parent sentinel" ] || { echo "FAIL: parent-is-a-file case modified the file"; fail=1; }
# A fresh report under a directory that does exist still works.
mkdir -p "$WS/prepared"
run_case "output under existing dir" 0 "safe-skill" "" "high" "sarif" "prepared/report.sarif"
[ -s "$WS/prepared/report.sarif" ] || { echo "FAIL: report not written under an existing directory"; fail=1; }

echo "--- no-clobber: any existing output is refused, byte-for-byte ---"
printf '{\n  "name": "sentinel"\n}\n' > "$WS/package.json"
printf 'MIT sentinel\n'              > "$WS/LICENSE"
printf 'all:\n\techo sentinel\n'     > "$WS/Makefile"
printf 'FROM scratch\n'              > "$WS/Dockerfile"
printf 'web: sentinel\n'             > "$WS/Procfile"
printf 'extensionless sentinel\n'    > "$WS/notes"
printf '{"sentinel":true}\n'         > "$WS/reports/report.sarif"
printf '{"sentinel":1}\n'            > "$WS/reports/report.json"
printf 'sentinel payload\n'          > "$WS/important.txt"
SENTINELS="package.json LICENSE Makefile Dockerfile Procfile notes reports/report.sarif reports/report.json important.txt"
hash_sentinels() {
  for s in $SENTINELS; do
    printf '%s ' "$(cksum < "$WS/$s")"
  done
}
before_hashes="$(hash_sentinels)"

run_case "output over package.json"  2 "safe-skill" "" "high" "json"  "package.json"
run_case "output over LICENSE"       2 "safe-skill" "" "high" "sarif" "LICENSE"
run_case "output over Makefile"      2 "safe-skill" "" "high" "sarif" "Makefile"
run_case "output over Dockerfile"    2 "safe-skill" "" "high" "sarif" "Dockerfile"
run_case "output over Procfile"      2 "safe-skill" "" "high" "sarif" "Procfile"
run_case "output over extensionless" 2 "safe-skill" "" "high" "sarif" "notes"
run_case "output over old sarif"     2 "safe-skill" "" "high" "sarif" "reports/report.sarif"
run_case "output over old json"      2 "safe-skill" "" "high" "json"  "reports/report.json"

# A hard link is another name for an existing file.
if ln "$WS/important.txt" "$WS/reports/linked.sarif" 2>/dev/null; then
  run_case "output over hard link"   2 "safe-skill" "" "high" "sarif" "reports/linked.sarif"
else
  if [ -n "${SKILLGUARD_REQUIRE_HARDLINKS:-}" ]; then
    echo "FAIL: hard-link case skipped but SKILLGUARD_REQUIRE_HARDLINKS is set"
    fail=1
  fi
  echo "SKIPPED: hard links are not available here; Linux CI runs this case."
fi

after_hashes="$(hash_sentinels)"
if [ "$before_hashes" = "$after_hashes" ]; then
  echo "ok: every refused run left the existing files byte-identical"
else
  echo "FAIL: a refused run modified an existing file"
  fail=1
fi

echo "--- invalid enumerations ---"
run_case "invalid fail-on"         2 "safe-skill" "" "sometimes" "sarif" "reports/x.sarif"
run_case "invalid format"          2 "safe-skill" "" "high"      "xml"   "reports/x.sarif"

echo "--- symlink escapes ---"
# Some environments (unprivileged Windows shells) silently copy instead of
# linking, which would assert nothing - require a real symlink first.
ln -s "$OUTSIDE" "$WS/linked-dir" 2>/dev/null || true
if [ -L "$WS/linked-dir" ]; then
  ln -s "$OUTSIDE/secret.md" "$WS/linked-file.md"
  ln -s "$OUTSIDE/evil.yml" "$WS/linked-config.yml"
  ln -s "$OUTSIDE/secret.md" "$WS/reports/linked-report.sarif"
  run_case "path symlink escape"   2 "linked-dir"  ""                   "high" "sarif" "reports/x.sarif"
  run_case "file symlink escape"   2 "linked-file.md" ""                "high" "sarif" "reports/x.sarif"
  run_case "config symlink escape" 2 "safe-skill" "linked-config.yml"   "high" "sarif" "reports/x.sarif"
  run_case "output symlink dir"    2 "safe-skill" ""                    "high" "sarif" "linked-dir/out.sarif"
  run_case "output symlink file"   2 "safe-skill" ""                    "high" "sarif" "reports/linked-report.sarif"
else
  rm -rf "$WS/linked-dir"
  if [ -n "${SKILLGUARD_REQUIRE_SYMLINKS:-}" ]; then
    echo "FAIL: symlink cases were skipped but SKILLGUARD_REQUIRE_SYMLINKS is set"
    exit 1
  fi
  echo "SKIPPED: real symlinks are not available here; Linux CI runs these cases."
fi

echo "--- output contract on the happy path ---"
GITHUB_OUTPUT="$WS/gh-output.txt"
: > "$GITHUB_OUTPUT"
export GITHUB_OUTPUT
set +e
sh scripts/action-entrypoint.sh "risky-skill" "" "high" "json" "reports/final.json" >/dev/null 2>&1
rc=$?
set -e
[ "$rc" -eq 1 ] || { echo "FAIL: risky run exited $rc, want 1"; fail=1; }
grep -q '^critical=[1-9]' "$GITHUB_OUTPUT" || { echo "FAIL: outputs missing critical>0"; fail=1; }
grep -q '^report-path=reports/final.json$' "$GITHUB_OUTPUT" || { echo "FAIL: report-path output wrong"; cat "$GITHUB_OUTPUT"; fail=1; }
[ "$(grep -c '' "$GITHUB_OUTPUT")" -eq 9 ] || { echo "FAIL: GITHUB_OUTPUT has unexpected line count"; cat "$GITHUB_OUTPUT"; fail=1; }
[ -s "$WS/reports/final.json" ] || { echo "FAIL: report not written"; fail=1; }
if grep -q 'Fak3Passw0rdForDemo' "$WS/reports/final.json"; then
  echo "FAIL: report leaked an unmasked synthetic secret"
  fail=1
fi
if [ -e "$OUTSIDE/escape.sarif" ] || [ -e "$WS/../escape.sarif" ]; then
  echo "FAIL: a rejected output value still wrote a file"
  fail=1
fi
# Source files must be untouched by every rejected run above.
grep -q 'name: release-notes-writer' "$WS/safe-skill/SKILL.md" || { echo "FAIL: source file was overwritten"; fail=1; }

if [ "$fail" -eq 0 ]; then
  echo "test-action: PASS"
else
  echo "test-action: FAILURES PRESENT"
  exit 1
fi
