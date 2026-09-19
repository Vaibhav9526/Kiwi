# KIWI T-132 -- sandbox lifecycle PoC (WSL2 tier, works on this Windows Home host)
#
# Proves the contract lifecycle with real commands:
#   create  = docker-export a pristine busybox rootfs, bake policy
#             (wsl.conf: automount+interop off) into the image -> wsl --import
#   analyze = run a bounded command inside, capture report data
#   revert  = unregister + re-import -> marker file written pre-revert is gone
#   teardown= wsl --unregister (VHDX destroyed)
#
# Interim tier: real hypervisor boundary vs host, shared WSL2 kernel caveat
# documented in docs/sandbox.md. QEMU/WHPX is the dedicated-kernel target.
#
# Usage: powershell -ExecutionPolicy Bypass -File tests/infra/sandbox-wsl-poc.ps1

$ErrorActionPreference = 'Stop'
$distro   = "kiwi-sbx-poc-$PID"
$workdir  = Join-Path $env:TEMP "kiwi-sbx-poc-$PID"
$rootfs   = Join-Path $workdir 'rootfs.tar'
$imageDir = Join-Path $workdir 'vhdx'

function Step($msg) { Write-Host "`n=== $msg ===" -ForegroundColor Cyan }
function Cleanup {
    wsl --unregister $distro 2>&1 | Out-Null
    if (docker ps -a -q -f 'name=kiwi-sbx-src') { docker rm -f kiwi-sbx-src 2>&1 | Out-Null }
    Remove-Item -Recurse -Force $workdir -ErrorAction SilentlyContinue
}

try {
    Step '0. Preconditions'
    if (-not (Get-Command wsl.exe -ErrorAction SilentlyContinue)) { throw 'wsl.exe missing' }
    if (-not (Get-Command docker -ErrorAction SilentlyContinue)) { throw 'docker missing' }
    New-Item -ItemType Directory -Force $workdir, $imageDir | Out-Null
    Write-Host "workdir: $workdir"

    Step '1. Build pristine base rootfs (docker export busybox) + bake policy'
    docker pull -q busybox:latest | Out-Null
    docker create --name kiwi-sbx-src busybox:latest sh -c 'true' | Out-Null
    docker export kiwi-sbx-src -o $rootfs
    docker rm kiwi-sbx-src | Out-Null
    Write-Host "rootfs: $((Get-Item $rootfs).Length) bytes"

    # Bake wsl.conf INTO the image -- policy ships with the base, not runtime.
    New-Item -ItemType Directory -Force "$workdir/etc" | Out-Null
    "[automount]`nenabled=false`n`n[interop]`nenabled=false`n" |
        Out-File -Encoding ascii -NoNewline "$workdir/etc/wsl.conf"
    Push-Location $workdir
    tar -rf rootfs.tar etc/wsl.conf   # relative paths: tar parses 'C:' as a host
    if ($LASTEXITCODE -ne 0) { Pop-Location; throw 'tar append failed' }
    Pop-Location
    Write-Host 'baked /etc/wsl.conf: automount=off, interop=off'

    Step '2. CREATE -- wsl --import pristine instance'
    wsl --import $distro $imageDir $rootfs | Out-Null
    wsl -d $distro -e sh -c 'echo alive; uname -r'

    Step '3. ANALYZE -- bounded command, isolation evidence'
    Write-Host '-- inside-guest identity/fs view:'
    wsl -d $distro -e sh -c 'id; hostname; ls /'
    Write-Host '-- /mnt contents (automount=off -> must show NO host drives):'
    $mnt = wsl -d $distro -e sh -c 'ls -A /mnt'
    Write-Host "  /mnt entries: [$($mnt -join ', ')]"
    if ($mnt -match '^[cd]$') { throw 'FAIL: host drives visible in guest' }
    else { Write-Host 'PASS: no host FS mounted' -ForegroundColor Green }
    Write-Host '-- simulated payload run (writes a marker):'
    wsl -d $distro -e sh -c 'echo PAYLOAD > /marker; ps aux | head -4'

    Step '4. REVERT -- destroy instance, re-import pristine rootfs'
    wsl --unregister $distro | Out-Null
    New-Item -ItemType Directory -Force $imageDir | Out-Null
    wsl --import $distro $imageDir $rootfs | Out-Null
    Write-Host '-- marker must be absent (instance reverted to base):'
    wsl -d $distro -e test -f /marker
    if ($LASTEXITCODE -eq 0) { throw 'FAIL: marker persisted' }
    else { Write-Host 'PASS: marker gone, base state restored' -ForegroundColor Green }

    Step '5. TEARDOWN -- unregister, destroy VHDX'
    wsl --unregister $distro | Out-Null
    if (wsl --list --quiet | Select-String $distro) { throw 'distro still present' }
    Write-Host 'PASS: instance destroyed' -ForegroundColor Green

    Write-Host "`n=== PoC complete: create/analyze/revert/teardown verified ===" -ForegroundColor Green
} catch {
    Write-Host "`nFAILED: $_" -ForegroundColor Red
    Cleanup
    exit 1
}
Cleanup
