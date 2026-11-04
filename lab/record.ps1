<#
.SYNOPSIS
    Record every scenario in the lab VM and import the result into data\.

.DESCRIPTION
    1. Restore snapshot "agents" (see build_agent_snapshot.ps1) and start the VM headless.
    2. Run guest\scenarios.ps1, which exports each scenario's Sysmon and Security events.
    3. Copy the evidence to lab-runs\<timestamp>\, stop the VM and restore the snapshot.
    4. Refuse to import if the lab password appears anywhere in the recording, then copy each
       scenario folder into data\.
#>
param([string] $VmName = "DFIR-Win11", [switch] $NoImport)

. "$PSScriptRoot\common.ps1"
$repo = Split-Path $PSScriptRoot -Parent
$run = Join-Path $repo ("lab-runs\" + (Get-Date -Format "yyyyMMdd-HHmmss"))
New-Item -ItemType Directory -Force $run | Out-Null

try {
    if ((Get-VmState $VmName) -eq "saved") { Invoke-VBox discardstate $VmName | Out-Null }
    Stop-Vm -VmName $VmName
    Invoke-VBox snapshot $VmName restore agents | Out-Null
    Invoke-VBox startvm $VmName --type headless | Out-Null
    Wait-GuestReady -VmName $VmName
    Copy-ToGuest -VmName $VmName -HostPath (Join-Path $PSScriptRoot "guest\scenarios.ps1") -GuestDir "C:\lab"
    Write-Host "Recording scenarios..."
    Invoke-GuestScript -VmName $VmName -GuestPath "C:\lab\scenarios.ps1" -TimeoutSeconds 2400 | Write-Host
    Copy-FromGuest -VmName $VmName -GuestDir "C:\evidence" -HostDir $run
}
finally {
    Stop-Vm -VmName $VmName
    try { Invoke-VBox snapshot $VmName restore agents | Out-Null } catch { Write-Warning "Could not restore snapshot: $_" }
}

# Never publish a recording that contains the lab password (ASCII or UTF-16).
$password = Get-LabPassword
$needles = @([Text.Encoding]::ASCII.GetBytes($password), [Text.Encoding]::Unicode.GetBytes($password))
foreach ($file in Get-ChildItem -Recurse -File (Join-Path $run "evidence")) {
    $hex = [BitConverter]::ToString([IO.File]::ReadAllBytes($file.FullName))
    foreach ($n in $needles) {
        if ($hex.Contains([BitConverter]::ToString($n))) { throw "Lab password found in $($file.FullName); not importing." }
    }
}

if (-not $NoImport) {
    foreach ($dir in Get-ChildItem -Directory (Join-Path $run "evidence")) {
        $dest = Join-Path $repo "data\$($dir.Name)"
        Remove-Item -Recurse -Force $dest -ErrorAction SilentlyContinue
        Copy-Item -Recurse $dir.FullName $dest
    }
    Write-Host "Imported $((Get-ChildItem -Directory (Join-Path $run 'evidence')).Count) scenarios into data\"
}
