# Watcher — simplified cycle, v2`r`n$ErrorActionPreference = "Continue"


$workerMap = @{
  "term_3c90ea4d" = "A5"
  "term_9e70fa6f" = "A6"
  "term_9a1e77c8" = "A7"
  "term_14f69e68" = "A8"
  "term_c1785574" = "A9"
  "term_77011ae4" = "A10"
}
$excludeTerms = @("term_a262bc09","term_44b5ff08","term_ef9a3e46","term_e4041dc3")

$agentFiles = @(
  "docs/agents/agent-5-status.md",

# 1. Parse terminal list, filter to workers only
$workerTerms = @()
try {
  $json = orca terminal list --json 2>$null
  if ($json -and $json.Trim().Length -gt 2) {
    $parsed = $json | ConvertFrom-Json -EA SilentlyContinue
    if ($parsed.result.terminals) {
      $ta = $parsed.result.terminals
      for ($i = 0; $i -lt $ta.Count; $i++) {
        $t = $ta[$i]
        if ($workerMap.ContainsKey($t.handle)) {
          $workerTerms += @{
            handle  = $t.handle
            la      = $t.lastOutputAt
            idleSec = ($now - $t.lastOutputAt) / 1000
            title   = $t.title
            preview = $t.preview
          }
        }

# 3. Done detection (status file changes)
$curFiles = @()
for ($i = 0; $i -lt $agentFiles.Count; $i++) {
  $f  = $agentFiles[$i]
  $tag = $short[$f]
  if (Test-Path $f) {
    $it = Get-Item $f -EA SilentlyContinue
    if ($it) {
      $curFiles += @{ path=$f; tag=$tag; lw=$it.LastWriteTimeUtc.ToString("u") }
    } else {
      $curFiles += @{ path=$f; tag=$tag; lw="MISSING" }
    }
  } else {
    $curFiles += @{ path=$f; tag=$tag; lw="MISSING" }
  }
}

$prevFiles = @()
if (Test-Path $stateFile) {
  try {
    $p = Get-Content $stateFile -Raw | ConvertFrom-Json -EA SilentlyContinue
    if ($p.files) { $prevFiles = @($p.files) }

# 4. Error detection (watched terminals only; "bypass permissions" NOT error)
$termErr = @()
$errKw = @("limit reached", "timed out", "model selector")
for ($i = 0; $i -lt $workerTerms.Count; $i++) {
  $wt  = $workerTerms[$i]
  $tag = $workerMap[$wt.handle]
  $hay = "$($wt.title) $($wt.preview)" -replace "`n"," " -replace "`r"," "
  for ($k = 0; $k -lt $errKw.Count; $k++) {
    if ($hay -like "*$($errKw[$k])*") {
      $termErr += "$tag unverified: $($errKw[$k])"
      break
    }
  }
}

# 5. Build report line
$parts = @()
if ($working.Count -gt 0) { $parts += "working=[$($working -join ', ')]" }
if ($idle.Count    -gt 0) { $parts += "idle=[$($idle -join ', ')]" }
if ($done.Count    -gt 0) { $parts += "done=[$($done -join ', ')]" }
if ($termErr.Count -gt 0) { $parts += "error=[$($termErr -join ', ')]" }
if ($parts.Count -eq 0)   { $parts += "working=[] idle=[] done=[] error=[]" }
$line = "WATCHER: $($parts -join ' ')"

# 6. Send to Lead via orca
$accepted = "not-run"; $prov = "not-run"
try {
  $cmd = "orca terminal send --terminal " + $leadTerm + " --text `"$line`" --enter"
  $out = Invoke-Expression $cmd 2>&1
  $accepted = if ($out -match "input_accepted") { "accepted" } else { "no-accept" }
  $prov     = if ($out -match "unsupported")   { "unsupported-provider" } else { "ok" }
} catch {
  $line    = "WATCHER: script broken"
  $accepted = "error"
  $prov     = "n/a"
}

# 7. Log
$logEntry = "---`nCYCLE | $ts`nLINE: $line`nDELIVERY: $accepted ($prov)`nWORKING: $($working -join '; ')`nIDLE: $($idle -join '; ')`nDONE: $($done -join '; ')`nERR: $($termErr -join '; ')`n`n"
try { Add-Content -Path $logFile -Value $logEntry -EA Stop } catch {}

# 8. Save state
$stateObj = @{
  files = $curFiles
  terms = $workerTerms
}
try {
  $stateObj | ConvertTo-Json -Depth 5 | Set-Content -Path $stateFile -EA Stop
} catch {}

# 9. Stdout
Write-Output "AUTO $ts"
Write-Output "LINE: $line"
Write-Output "DELIVERY: $accepted ($prov)"
if ($working.Count -gt 0) { Write-Output "WORKING: $($working -join '; ')" }
if ($idle.Count    -gt 0) { Write-Output "IDLE: $($idle -join '; ')" }
if ($done.Count    -gt 0) { Write-Output "DONE: $($done -join '; ')" }
if ($termErr.Count -gt 0) { Write-Output "ERR: $($termErr -join '; ')" }

  } catch {}
}

$done = @()
for ($i = 0; $i -lt $curFiles.Count; $i++) {
  $cf  = $curFiles[$i]
  $tag = $cf.tag
  $plw = "INIT"
  for ($j = 0; $j -lt $prevFiles.Count; $j++) {
    if ($prevFiles[$j].path -eq $cf.path) { $plw = $prevFiles[$j].lw; break }
  }
  if ($cf.lw -ne $plw) {
    if ($cf.lw -eq "MISSING") {
      $done += "$tag status-file MISSING"
    } elseif ($plw -eq "INIT" -or $plw -eq "MISSING") {
      $done += "$tag status-file now-present"
    } else {
      $a = $plw.Substring(0, [Math]::Min(16, $plw.Length))
      $b = $cf.lw.Substring(0, [Math]::Min(16, $cf.lw.Length))
      $done += "$tag $a->$b"
    }
  }
}

      }
    }
  }
} catch {
  $workerTerms = @()
}

# 2. Compute idle per worker
$working = @()
$idle    = @()
for ($i = 0; $i -lt $workerTerms.Count; $i++) {
  $wt  = $workerTerms[$i]
  $tag = $workerMap[$wt.handle]
  $s  = $wt.idleSec
  $sR = [math]::Round($s, 0)
  if ($s -lt 300) {
    $working += "$tag idle<$sR`s"
  } else {
    $idle += "$tag idle>$sR`s"
  }
}

  "docs/agents/agent-6-status.md",
  "docs/agents/agent-7-status.md",
  "docs/agents/agent-8-status.md",
  "docs/agents/agent-9-status.md",
  "docs/agents/agent-10-status.md"
)
$short = @{
  "docs/agents/agent-5-status.md"  = "A5"
  "docs/agents/agent-6-status.md"  = "A6"
  "docs/agents/agent-7-status.md"  = "A7"
  "docs/agents/agent-8-status.md"  = "A8"
  "docs/agents/agent-9-status.md"  = "A9"
  "docs/agents/agent-10-status.md" = "A10"
}
