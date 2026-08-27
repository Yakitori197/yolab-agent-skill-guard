#!/bin/sh
# Full local verification pipeline (POSIX shell).
#
# Mirrors CI: format, vet, tests, race detector, coverage gate, build,
# module verification, CLI smoke tests, determinism checks, self-scan, and
# the action contract test. Everything runs offline.
#
# On platforms where the race detector needs cgo and no C compiler exists
# (common on Windows), the race step reports SKIPPED with the reason instead
# of pretending to pass; CI always runs it on Linux.
set -eu

cd "$(dirname "$0")/.."
fail=0

step() { printf '\n== %s ==\n' "$1"; }

step "go version"
go version

step "gofmt"
unformatted="$(gofmt -l cmd internal tools)"
if [ -n "$unformatted" ]; then
  echo "FAIL: gofmt needed on:"; echo "$unformatted"; fail=1
else
  echo "OK"
fi

step "go vet ./..."
go vet ./... && echo "OK" || fail=1

step "go test ./..."
go test ./... || fail=1

step "go test -race ./..."
race_out="$(go test -race ./... 2>&1)" && race_rc=0 || race_rc=$?
if [ "$race_rc" -eq 0 ]; then
  echo "OK"
elif echo "$race_out" | grep -qi "requires cgo\|C compiler"; then
  echo "SKIPPED: race detector needs cgo and no C compiler is available here."
  echo "         CI runs 'go test -race ./...' on Linux (see .github/workflows/ci.yml)."
else
  echo "$race_out"
  fail=1
fi

step "coverage gate (internal >= 90%)"
go test -coverprofile=cover.out -coverpkg=./internal/... ./... >/dev/null || fail=1
go run ./tools/covercheck -profile cover.out -min 90 || fail=1

step "go build ./cmd/skillguard"
ext=""
[ "$(go env GOOS)" = "windows" ] && ext=".exe"
go build -trimpath -o "skillguard$ext" ./cmd/skillguard && echo "OK" || fail=1

step "go mod verify"
go mod verify || fail=1

step "CLI smoke"
"./skillguard$ext" version >/dev/null || fail=1
"./skillguard$ext" rules >/dev/null || fail=1
"./skillguard$ext" explain ASG001 >/dev/null || fail=1

step "scan fixtures (safe=0, risky=1)"
"./skillguard$ext" scan examples/safe-skill --no-color >/dev/null; rc=$?
[ "$rc" -eq 0 ] && echo "safe: OK" || { echo "FAIL: safe fixture exited $rc"; fail=1; }
set +e
"./skillguard$ext" scan examples/risky-skill --no-color --quiet >/dev/null
rc=$?
set -e
[ "$rc" -eq 1 ] && echo "risky: OK" || { echo "FAIL: risky fixture exited $rc"; fail=1; }

step "determinism (json/sarif/html byte-identical across runs)"
# Not named TMP: on Windows that is an inherited environment variable Go uses
# for its work directory, and removing it would break later steps.
DET_DIR="$(mktemp -d)"
for fmt in json sarif html; do
  set +e
  "./skillguard$ext" scan examples/risky-skill --format "$fmt" --output "$DET_DIR/a.$fmt" --quiet
  "./skillguard$ext" scan examples/risky-skill --format "$fmt" --output "$DET_DIR/b.$fmt" --quiet
  set -e
  if cmp -s "$DET_DIR/a.$fmt" "$DET_DIR/b.$fmt"; then
    echo "$fmt: deterministic"
  else
    echo "FAIL: $fmt output differs between runs"; fail=1
  fi
done
rm -rf "$DET_DIR"

step "self-scan (fail-on high)"
"./skillguard$ext" scan . --fail-on high --no-color >/dev/null && echo "OK" || { echo "FAIL: self-scan"; fail=1; }

step "action contract test"
sh scripts/test-action.sh || fail=1

step "result"
if [ "$fail" -eq 0 ]; then
  echo "verify: ALL CHECKS PASSED"
else
  echo "verify: FAILURES PRESENT (see above)"
  exit 1
fi
