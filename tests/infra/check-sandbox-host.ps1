# KIWI T-132 — host virtualization capability probe (read-only).
# Reports what this machine can support for the attachment sandbox.
$results = [ordered]@{}

# Optional Windows features relevant to sandboxing.
foreach ($f in @(
    'VirtualMachinePlatform',        # base for WSL2 utility VM
    'HypervisorPlatform',            # WHPX user-mode API (WinHvPlatform.dll)
    'Microsoft-Hyper-V-All',         # full Hyper-V role (Pro/Enterprise only)
    'Microsoft-Hyper-V-Management-PowerShell',
    'Microsoft-Windows-Subsystem-Linux',
    'Containers'
)) {
    try {
        $results[$f] = (Get-WindowsOptionalFeature -Online -FeatureName $f -ErrorAction Stop).State.ToString()
    } catch {
        $results[$f] = 'not-present'
    }
}

$cs = Get-CimInstance Win32_ComputerSystem
$results['HypervisorPresent']       = $cs.HypervisorPresent
$results['OS']                      = (Get-CimInstance Win32_OperatingSystem).Caption
$results['WinHvPlatform.dll']       = Test-Path "$env:WINDIR\System32\WinHvPlatform.dll"
$results['vmcompute (HCS service)'] = (Get-Service vmcompute -ErrorAction SilentlyContinue).Status
$results['vmms (Hyper-V Mgr)']      = (Get-Service vmms -ErrorAction SilentlyContinue).Status
$results['hvix64 (WHPX driver)']    = Test-Path "$env:WINDIR\System32\hvix64.exe"
$results['qemu-system-x86_64']      = [bool](Get-Command qemu-system-x86_64 -ErrorAction SilentlyContinue)
$results['wsl.exe']                 = [bool](Get-Command wsl.exe -ErrorAction SilentlyContinue)
$results['docker']                  = [bool](Get-Command docker -ErrorAction SilentlyContinue)

$results.GetEnumerator() | ForEach-Object { "{0,-42} {1}" -f $_.Key, $_.Value }
