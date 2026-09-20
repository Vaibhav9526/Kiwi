$now = [int](Get-Date -UFormat %s) * 1000
$json = orca terminal list --json 2>$null
Write-Output "JSON_LEN:$($json.Length)"
if ($json -and $json.Trim().Length -gt 2) {
  $p = $json | ConvertFrom-Json -EA SilentlyContinue
  if ($p.result.terminals) {
    $ta = $p.result.terminals
    Write-Output "COUNT:$($ta.Count)"
    for ($i = 0; $i -lt $ta.Count; $i++) {
      $t = $ta[$i]
      Write-Output "HANDLE:$($t.handle)"
    }
    $workers = @("term_3c90ea4d","term_9e70fa6f","term_9a1e77c8","term_14f69e68","term_c1785574","term_77011ae4")
    $tags   = @("A5","A6","A7","A8","A9","A10")
    for ($i = 0; $i -lt $ta.Count; $i++) {
      $t = $ta[$i]
      for ($j = 0; $j -lt $workers.Count; $j++) {
        if ($t.handle -eq $workers[$j]) {
          $s = ($now - $t.lastOutputAt) / 1000
          $sRound = [math]::Round($s, 0)
          Write-Output "IDLE:$($tags[$j]):$sRound"
        }
      }
    }
  }
} else {
  Write-Output "NO_JSON"
}

$now = [int](Get-Date -UFormat %s) * 1000
$json = orca terminal list --json 2>$null
if ($json -and $json.Trim().Length -gt 2) {
  $p = $json | ConvertFrom-Json -EA SilentlyContinue
  if ($p.result.terminals) {
    $ta = $p.result.terminals
    Write-Output "TERMINAL_COUNT:$($ta.Count)"
    $targets = @("term_3c90ea4d","term_9e70fa6f","term_9a1e77c8","term_14f69e68","term_c1785574","term_77011ae4")
    $tags   = @("A5","A6","A7","A8","A9","A10")
    for ($i = 0; $i -lt $ta.Count; $i++) {
      $t = $ta[$i]
      for ($j = 0; $j -lt $targets.Count; $j++) {
        if ($t.handle -eq $targets[$j]) {
          $s = ($now - $t.lastOutputAt) / 1000
          $sRound = [math]::Round($s, 0)
          Write-Output "IDLE:$($tags[$j]):$sRound"
        }
      }
    }
  }
} else {
  Write-Output "NO_TERMINALS"
}
