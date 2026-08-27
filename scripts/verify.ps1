# Full local verification pipeline for Windows PowerShell 5.1+.
#
# Mirrors scripts/verify.sh: format, vet, tests, race (honestly skipped when
# cgo has no C compiler — CI runs it on Linux), coverage gate, build, module
# verification, CLI smoke tests, determinism checks, self-scan, and the
# action contract test (via Git Bash sh when available).
$ErrorActionPreference = 'Continue'
Set-Location (Join-Path $PSScriptRoot '..')
$fail = $false

function Step($name) { Write-Host "`n== $name ==" }

Step 'go version'
go version
if ($LASTEXITCODE -ne 0) { $fail = $true }

Step 'gofmt'
$unformatted = gofmt -l cmd internal tools
if ($unformatted) { Write-Host 'FAIL: gofmt needed on:'; $unformatted; $fail = $true } else { Write-Host 'OK' }

Step 'go vet ./...'
go vet ./...
if ($LASTEXITCODE -ne 0) { $fail = $true } else { Write-Host 'OK' }

Step 'go test ./...'
go test ./...
if ($LASTEXITCODE -ne 0) { $fail = $true }

Step 'go test -race ./...'
$raceOut = go test -race ./... 2>&1 | Out-String
if ($LASTEXITCODE -eq 0) {
    Write-Host 'OK'
} elseif ($raceOut -match 'requires cgo' -or $raceOut -match 'C compiler') {
    Write-Host 'SKIPPED: race detector needs cgo and no C compiler is available here.'
    Write-Host "         CI runs 'go test -race ./...' on Linux (see .github/workflows/ci.yml)."
} else {
    Write-Host $raceOut
    $fail = $true
}

Step 'coverage gate (internal >= 90%)'
go test '-coverprofile=cover.out' '-coverpkg=./internal/...' ./... | Out-Null
if ($LASTEXITCODE -ne 0) { $fail = $true }
go run ./tools/covercheck -profile cover.out -min 90
if ($LASTEXITCODE -ne 0) { $fail = $true }

Step 'go build ./cmd/skillguard'
go build -trimpath -o skillguard.exe ./cmd/skillguard
if ($LASTEXITCODE -ne 0) { $fail = $true } else { Write-Host 'OK' }

Step 'go mod verify'
go mod verify
if ($LASTEXITCODE -ne 0) { $fail = $true }

Step 'CLI smoke'
.\skillguard.exe version | Out-Null; if ($LASTEXITCODE -ne 0) { $fail = $true }
.\skillguard.exe rules | Out-Null; if ($LASTEXITCODE -ne 0) { $fail = $true }
.\skillguard.exe explain ASG001 | Out-Null; if ($LASTEXITCODE -ne 0) { $fail = $true }
if (-not $fail) { Write-Host 'OK' }

Step 'scan fixtures (safe=0, risky=1)'
.\skillguard.exe scan examples/safe-skill --no-color | Out-Null
if ($LASTEXITCODE -eq 0) { Write-Host 'safe: OK' } else { Write-Host "FAIL: safe fixture exited $LASTEXITCODE"; $fail = $true }
.\skillguard.exe scan examples/risky-skill --no-color --quiet | Out-Null
if ($LASTEXITCODE -eq 1) { Write-Host 'risky: OK' } else { Write-Host "FAIL: risky fixture exited $LASTEXITCODE"; $fail = $true }

Step 'determinism (json/sarif/html byte-identical across runs)'
$tmp = Join-Path $env:TEMP ("skillguard-verify-" + [System.Guid]::NewGuid().ToString('n'))
New-Item -ItemType Directory -Force $tmp | Out-Null
foreach ($fmt in @('json', 'sarif', 'html')) {
    .\skillguard.exe scan examples/risky-skill --format $fmt --output "$tmp\a.$fmt" --quiet | Out-Null
    .\skillguard.exe scan examples/risky-skill --format $fmt --output "$tmp\b.$fmt" --quiet | Out-Null
    $h1 = (Get-FileHash "$tmp\a.$fmt" -Algorithm SHA256).Hash
    $h2 = (Get-FileHash "$tmp\b.$fmt" -Algorithm SHA256).Hash
    if ($h1 -eq $h2) { Write-Host "${fmt}: deterministic" } else { Write-Host "FAIL: $fmt output differs between runs"; $fail = $true }
}
Remove-Item -Recurse -Force $tmp

Step 'self-scan (fail-on high)'
.\skillguard.exe scan . --fail-on high --no-color | Out-Null
if ($LASTEXITCODE -eq 0) { Write-Host 'OK' } else { Write-Host "FAIL: self-scan exited $LASTEXITCODE"; $fail = $true }

Step 'action contract test'
$shPath = $null
$sh = Get-Command sh -ErrorAction SilentlyContinue
if ($sh) {
    $shPath = $sh.Source
} else {
    # Fall back to the sh bundled with Git for Windows.
    $git = Get-Command git -ErrorAction SilentlyContinue
    if ($git) {
        $candidate = Join-Path (Split-Path (Split-Path $git.Source)) 'bin\sh.exe'
        if (Test-Path $candidate) { $shPath = $candidate }
    }
}
if ($shPath) {
    & $shPath scripts/test-action.sh
    if ($LASTEXITCODE -ne 0) { $fail = $true }
} else {
    Write-Host 'SKIPPED: POSIX sh not found (install Git for Windows to run scripts/test-action.sh).'
}

Step 'result'
if (-not $fail) {
    Write-Host 'verify: ALL CHECKS PASSED'
    exit 0
} else {
    Write-Host 'verify: FAILURES PRESENT (see above)'
    exit 1
}
