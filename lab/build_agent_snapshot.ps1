<#
.SYNOPSIS
    Prepare the "agents" snapshot of the lab VM: Sysmon, Node.js and the agent CLIs.

.DESCRIPTION
    Starts from the "clean" snapshot made by dfir-triage-automator's lab\build_vm.ps1
    (Windows 11 with process-creation auditing and command-line logging), runs
    guest\install_agents.ps1, copies the recorded versions and --help output back to
    lab-runs\agents-install, and saves the result as snapshot "agents".
    No API key or account is ever placed in the VM.
#>
param([string] $VmName = "DFIR-Win11")

. "$PSScriptRoot\common.ps1"
$repo = Split-Path $PSScriptRoot -Parent
$outDir = Join-Path $repo "lab-runs\agents-install"

if ((Get-VmState $VmName) -eq "saved") { Invoke-VBox discardstate $VmName | Out-Null }
Stop-Vm -VmName $VmName
Invoke-VBox snapshot $VmName restore clean | Out-Null
Invoke-VBox startvm $VmName --type headless | Out-Null
try {
Wait-GuestReady -VmName $VmName

Copy-ToGuest -VmName $VmName -HostPath (Join-Path $PSScriptRoot "sysmon-config.xml") -GuestDir "C:\lab"
Copy-ToGuest -VmName $VmName -HostPath (Join-Path $PSScriptRoot "guest\install_agents.ps1") -GuestDir "C:\lab"
Write-Host "Installing Sysmon, Node.js and the agent CLIs in the guest..."
Invoke-GuestScript -VmName $VmName -GuestPath "C:\lab\install_agents.ps1" -TimeoutSeconds 2400 | Write-Host
Copy-FromGuest -VmName $VmName -GuestDir "C:\lab\agents" -HostDir $outDir
}
catch {
    # Keep whatever the guest recorded, leave the VM off, and leave "clean" untouched.
    try { Copy-FromGuest -VmName $VmName -GuestDir "C:\lab\agents" -HostDir $outDir } catch { }
    Stop-Vm -VmName $VmName
    throw
}

Stop-Vm -VmName $VmName
try { Invoke-VBox snapshot $VmName delete agents | Out-Null } catch { }
Invoke-VBox snapshot $VmName take agents --description "clean + Sysmon + Node.js + Claude Code and Codex CLIs (not logged in)" | Out-Null
Write-Host "Done. Snapshot 'agents' saved. Versions and --help output: $outDir"
