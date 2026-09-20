# Watcher — tight loop launcher
# Calls watcher-poll.ps1 repeatedly with 55s sleep between cycles
# Each cycle: check files + terminals → orca send to Lead → log
# Continue until you tell me to stop.

$script = "docs/agents/watcher-poll.ps1"
$maxCycles = 999
$cycle = 0

while ($cycle -lt $maxCycles) {
  $cycle++
  $start = Get-Date
  Write-Output "===== LOOP CYCLE $cycle @ $($start.ToString('HH:mm:ss UTC')) ====="
  $out = & powershell -NoProfile -ExecutionPolicy Bypass -File $script 2>&1
  Write-Output $out
  $elapsed = (Get-Date) - $start
  $sleep = [Math]::Max(0, 58 - $elapsed.TotalSeconds)
  if ($sleep -gt 0) { Start-Sleep -Seconds $sleep }
  # Check if assistant runtime is still alive; stop if not
  if (-not (Get-Process -Id $PID -ErrorAction SilentlyContinue)) { break }
}
Write-Output "===== LOOP DONE after $cycle cycles ====="
