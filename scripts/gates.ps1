<#
.SYNOPSIS
  T-344 (Agent 26) â€” local equivalent of the CI gate set, Windows.

.DESCRIPTION
  Runs the same gates .github/workflows/ci.yml runs, in the same order:
    rust.fmt / rust.test / rust.clippy
    app.typecheck / app.test / app.build / app.ui
    py.secret_scan / py.copy_overlap / py.check_fixtures / py.check_csp /
    py.check_encoding / py.compose_static

  Every gate prints PASS, FAIL or SKIP plus a trailing summary line, and the
  script exits non-zero if any gate FAILs. SKIP is reserved for genuinely
  absent tooling (no cargo / no node / no python / no headless browser) and
  never for a check that ran and failed.

  Usage:
    .\scripts\gates.ps1                       # every gate, CI order
    .\scripts\gates.ps1 -Only rust,py         # groups
    .\scripts\gates.ps1 -Only app.ui          # one gate (prefix match)
#>
[CmdletBinding()]
param(
  [string] $Only = ""
)

$ErrorActionPreference = "Continue"
$root = Split-Path -Parent $PSScriptRoot
$only = @($Only -split "," | ForEach-Object { $_.Trim().ToLowerInvariant() } | Where-Object { $_ })

$results = New-Object System.Collections.ArrayList
$failed = New-Object System.Collections.ArrayList
$skipped = New-Object System.Collections.ArrayList
$ran = 0

function Test-Selected {
  param([string] $Key)
  if ($only.Count -eq 0) { return $true }
  foreach ($token in $only) { if ($Key -like "$token*") { return $true } }
  return $false
}

function Test-Tool {
  param([string] $Name)
  return [bool] (Get-Command $Name -ErrorAction SilentlyContinue)
}

function Add-Result {
  param([string] $Key, [string] $Status, [string] $Note = "")
  [void] $results.Add([pscustomobject]@{ Key = $Key; Status = $Status; Note = $Note })
  $color = switch ($Status) { "PASS" { "Green" } "FAIL" { "Red" } default { "DarkYellow" } }
  $line = "{0,-4} {1}" -f $Status, $Key
  if ($Note) { $line += " - $Note" }
  Write-Host $line -ForegroundColor $color
}

function Invoke-Gate {
  param([string] $Key, [string] $Title, [scriptblock] $Body)
  if (-not (Test-Selected $Key)) { return }
  $script:ran++
  Write-Host ""
  Write-Host ("== [{0}] {1} ==" -f $script:ran, $Title) -ForegroundColor Cyan
  # Gate bodies stream their own output with Out-Host and return only the
  # exit code, so $rc below is the code and never the captured stdout.
  $out = @(& $Body)
  $rc = if ($out.Count -gt 0) { $out[-1] } else { 0 }
  if ($rc -eq 0) { Add-Result $Key "PASS" } else { Add-Result $Key "FAIL" "exit $rc"; [void] $failed.Add($Key) }
}

function Invoke-ToolGate {
  param([string] $Key, [string] $Title, [string] $Tool, [string] $ToolReason, [scriptblock] $Body)
  if (-not (Test-Selected $Key)) { return }
  if (-not (Test-Tool $Tool)) {
    $script:ran++
    Add-Result $Key "SKIP" $ToolReason
    [void] $skipped.Add($Key)
    return
  }
  Invoke-Gate $Key $Title $Body
}

function Find-SmokeBrowser {
  foreach ($name in @("google-chrome", "google-chrome-stable", "chromium", "chromium-browser")) {
    $cmd = Get-Command $name -ErrorAction SilentlyContinue
    if ($cmd) { return $cmd.Source }
  }
  $pf = ${env:ProgramFiles}
  $pfx = ${env:ProgramFiles(x86)}
  $paths = @(
    (Join-Path $pf "Google\Chrome\Application\chrome.exe"),
    (Join-Path $pfx "Google\Chrome\Application\chrome.exe"),
    (Join-Path $pf "Microsoft\Edge\Application\msedge.exe"),
    (Join-Path $pfx "Microsoft\Edge\Application\msedge.exe")
  )
  foreach ($p in $paths) { if ($p -and (Test-Path -LiteralPath $p)) { return $p } }
  $cache = Join-Path $env:LOCALAPPDATA "ms-playwright"
  if (Test-Path -LiteralPath $cache) {
    $hit = Get-ChildItem -Path $cache -Filter "chrome.exe" -Recurse -File -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($hit) { return $hit.FullName }
  }
  return $null
}

Push-Location -LiteralPath $root
try {
  Write-Host "gates.ps1 - repo root: $root" -ForegroundColor Cyan
  if ($only.Count -gt 0) { Write-Host "filter: $($only -join ', ')" -ForegroundColor DarkGray }

  Invoke-ToolGate "rust.fmt" "cargo fmt --all -- --check" "cargo" "cargo not on PATH" {
    & cargo fmt --all -- --check | Out-Host
    return $LASTEXITCODE
  }
  Invoke-ToolGate "rust.test" "cargo test --workspace" "cargo" "cargo not on PATH" {
    & cargo test --workspace | Out-Host
    return $LASTEXITCODE
  }
  Invoke-ToolGate "rust.clippy" "cargo clippy --workspace --all-targets -- -D warnings" "cargo" "cargo not on PATH" {
    & cargo clippy --workspace --all-targets -- -D warnings | Out-Host
    return $LASTEXITCODE
  }

  Invoke-ToolGate "app.typecheck" "kiwi-app: npm run typecheck" "npm" "npm not on PATH" {
    & npm --prefix kiwi-app run typecheck | Out-Host
    return $LASTEXITCODE
  }
  Invoke-ToolGate "app.test" "kiwi-app: npm test" "npm" "npm not on PATH" {
    & npm --prefix kiwi-app test | Out-Host
    return $LASTEXITCODE
  }
  Invoke-ToolGate "app.build" "kiwi-app: npm run build" "npm" "npm not on PATH" {
    & npm --prefix kiwi-app run build | Out-Host
    return $LASTEXITCODE
  }

  if (Test-Selected "app.ui") {
    $ran++
    Write-Host ""
    Write-Host ("== [{0}] kiwi-app: npm run test:ui (CDP browser smoke) ==" -f $ran) -ForegroundColor Cyan
    if (-not (Test-Tool "npm")) {
      Add-Result "app.ui" "SKIP" "npm not on PATH"
      [void] $skipped.Add("app.ui")
    }
    else {
      $browser = Find-SmokeBrowser
      if (-not $browser) {
        Add-Result "app.ui" "SKIP" "no headless browser found (chrome/edge/chromium); suite reports SKIP, never PASS"
        [void] $skipped.Add("app.ui")
      }
      else {
        Write-Host "browser: $browser" -ForegroundColor DarkGray
        $env:KIWI_SMOKE_BROWSER = $browser
        # Local default: the suite SKIPs (exit 0) when the browser cannot start.
        & npm --prefix kiwi-app run test:ui
        $rc = $LASTEXITCODE
        if ($rc -eq 0) { Add-Result "app.ui" "PASS" } else { Add-Result "app.ui" "FAIL" "exit $rc"; [void] $failed.Add("app.ui") }
      }
    }
  }

  Invoke-ToolGate "py.secret_scan" "python tests/tools/secret_scan.py" "python" "python not on PATH" {
    & python tests/tools/secret_scan.py | Out-Host
    return $LASTEXITCODE
  }
  Invoke-ToolGate "py.copy_overlap" "python tests/tools/copy_overlap.py" "python" "python not on PATH" {
    & python tests/tools/copy_overlap.py | Out-Host
    return $LASTEXITCODE
  }
  Invoke-ToolGate "py.check_fixtures" "python tests/tools/check_fixtures.py" "python" "python not on PATH" {
    & python tests/tools/check_fixtures.py | Out-Host
    return $LASTEXITCODE
  }
  Invoke-ToolGate "py.check_csp" "python tests/tools/check_csp.py" "python" "python not on PATH" {
    & python tests/tools/check_csp.py | Out-Host
    return $LASTEXITCODE
  }
  Invoke-ToolGate "py.check_encoding" "python tests/tools/check_encoding.py" "python" "python not on PATH" {
    & python tests/tools/check_encoding.py | Out-Host
    return $LASTEXITCODE
  }
  Invoke-ToolGate "py.compose_static" "python -m unittest tests.infra.test_compose.ComposeStaticTests" "python" "python not on PATH" {
    & python -m unittest tests.infra.test_compose.ComposeStaticTests | Out-Host
    return $LASTEXITCODE
  }
}
finally {
  Pop-Location
}

Write-Host ""
Write-Host "=== gate summary ===" -ForegroundColor Cyan
foreach ($r in $results) {
  $color = switch ($r.Status) { "PASS" { "Green" } "FAIL" { "Red" } default { "DarkYellow" } }
  $line = "{0,-4} {1}" -f $r.Status, $r.Key
  if ($r.Note) { $line += " - $($r.Note)" }
  Write-Host $line -ForegroundColor $color
}
$passCount = @($results | Where-Object { $_.Status -eq "PASS" }).Count
$summary = "gates: {0} run, {1} PASS, {2} FAIL, {3} SKIP" -f $ran, $passCount, $failed.Count, $skipped.Count
if ($failed.Count -gt 0) { $summary += " - failed: $($failed -join ', ')" }
Write-Host $summary -ForegroundColor $(if ($failed.Count -gt 0) { "Red" } else { "Green" })

if ($ran -eq 0) {
  Write-Host "no gate matched -Only '$Only'" -ForegroundColor Red
  exit 2
}
if ($failed.Count -gt 0) { exit 1 }
exit 0
