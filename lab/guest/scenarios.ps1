# Runs inside the lab VM (snapshot "agents") on each recording.
# Reproduces, with HARMLESS payloads, the ways attackers have abused AI coding agent CLIs, plus
# benign baselines. The agents are not logged in, so no prompt ever reaches a model: what is
# recorded is the launch, the command line, the parent process and the files written.
# Every prompt used is "Reply with the single word OK."
#
# For each scenario, the Sysmon and Security events of its time window are exported to
# C:\evidence\<scenario>\ and described in C:\evidence\<scenario>\scenario.json.
# "Continue": native programs (npm, wevtutil, schtasks) write to stderr, which Windows
# PowerShell 5.1 would treat as fatal under "Stop".
$ErrorActionPreference = "Continue"
$npmBin = Join-Path $env:APPDATA "npm"
$env:Path = "C:\Program Files\nodejs;$npmBin;$env:Path"
$Prompt = "Reply with the single word OK."
$Evidence = "C:\evidence"
$Work = "C:\lab\work"
New-Item -ItemType Directory -Force $Evidence, $Work | Out-Null

function Utc { (Get-Date).ToUniversalTime() }

function Invoke-Timed([string] $File, [string] $Arguments, [string] $Dir = $Work, [int] $Seconds = 60) {
    # Run a command and kill its whole process tree if it is still running after $Seconds.
    $p = Start-Process -FilePath $File -ArgumentList $Arguments -WorkingDirectory $Dir -WindowStyle Hidden -PassThru
    if (-not $p.WaitForExit($Seconds * 1000)) { & taskkill.exe /PID $p.Id /T /F 2>&1 | Out-Null }
}

function Export-Window([string] $Name, [datetime] $Start, [datetime] $End) {
    $dir = Join-Path $Evidence $Name
    New-Item -ItemType Directory -Force $dir | Out-Null
    $s = $Start.AddSeconds(-1).ToString("yyyy-MM-ddTHH:mm:ss.fffZ")
    $e = $End.AddSeconds(2).ToString("yyyy-MM-ddTHH:mm:ss.fffZ")
    $q = "*[System[TimeCreated[@SystemTime>='$s' and @SystemTime<='$e']]]"
    wevtutil epl Microsoft-Windows-Sysmon/Operational (Join-Path $dir "Sysmon.evtx") "/q:$q"
    wevtutil epl Security (Join-Path $dir "Security.evtx") "/q:$q"
}

function Scenario([string] $Name, [string] $Kind, [string[]] $ExpectedRules, [string] $Description, [scriptblock] $Body) {
    $start = Utc
    & $Body
    Start-Sleep -Seconds 5   # let Sysmon and the Security log flush
    $end = Utc
    Export-Window $Name $start $end
    [ordered]@{
        name = $Name
        kind = $Kind                       # "attack-technique" or "benign"
        description = $Description
        expected_rules = $ExpectedRules
        start_utc = $start.ToString("o")
        end_utc = $end.ToString("o")
        prompt = $Prompt
        agents_logged_in = $false
    } | ConvertTo-Json | Out-File (Join-Path $Evidence "$Name\scenario.json") -Encoding utf8
    Write-Output "recorded $Name"
}

function Reset-AgentState {
    Remove-Item -Recurse -Force "$env:USERPROFILE\.claude", "$env:USERPROFILE\.codex", "$env:USERPROFILE\.claude.json" -ErrorAction SilentlyContinue
}

# A local npm package whose install script launches both agents, like the s1ngularity attack
# on the Nx packages (August 2025). The prompt here is harmless.
function New-Package([string] $Name, [string] $PostinstallJs) {
    $dir = Join-Path $Work "pkgs\$Name"
    New-Item -ItemType Directory -Force $dir | Out-Null
    Set-Content (Join-Path $dir "package.json") -Encoding ascii -Value (@{
        name = $Name; version = "1.0.0"; description = "agent-attack-samples lab package"
        scripts = @{ postinstall = "node postinstall.js" }
    } | ConvertTo-Json)
    Set-Content (Join-Path $dir "postinstall.js") -Encoding ascii -Value $PostinstallJs
    Push-Location $dir; & npm.cmd pack --silent 2>&1 | Out-Null; Pop-Location
    return (Join-Path $dir "$Name-1.0.0.tgz")
}

function Install-Package([string] $Tarball, [string] $AppName) {
    $app = Join-Path $Work $AppName
    New-Item -ItemType Directory -Force $app | Out-Null
    Push-Location $app
    & npm.cmd init -y 2>&1 | Out-Null
    Pop-Location
    Invoke-Timed "C:\Program Files\nodejs\npm.cmd" "install --foreground-scripts --no-audit --no-fund `"$Tarball`"" $app 240
}

$jsPrompt = $Prompt.Replace("'", "\'")

# ------------------------------------------------------------------ attack techniques

Reset-AgentState
$tgz = New-Package "helper-utils" @"
// Harmless reproduction of an install script that launches AI coding agents with their
// safety checks disabled. Both agents are logged out, so nothing reaches a model.
const { spawnSync } = require('child_process');
const prompt = '$jsPrompt';
const runs = [
  ['claude', ['--dangerously-skip-permissions', '-p', JSON.stringify(prompt)]],
  ['codex', ['exec', '--dangerously-bypass-approvals-and-sandbox', JSON.stringify(prompt)]],
];
for (const [cmd, args] of runs) {
  spawnSync(cmd, args, { shell: true, timeout: 60000, stdio: 'ignore', windowsHide: true });
}
"@
Scenario "npm-postinstall-launches-agents" "attack-technique" @("AAS-001", "AAS-002") `
    "An npm package's postinstall script launches Claude Code and Codex with permission-bypass flags (s1ngularity technique)." {
    Install-Package $tgz "app-postinstall"
}

Reset-AgentState
Scenario "agent-bypass-flags-from-script" "attack-technique" @("AAS-001") `
    "A script runs the agents headless with each permission or sandbox bypass flag." {
    Invoke-Timed "cmd.exe" "/c claude --dangerously-skip-permissions -p `"$Prompt`""
    Invoke-Timed "cmd.exe" "/c claude --permission-mode bypassPermissions -p `"$Prompt`""
    Invoke-Timed "cmd.exe" "/c claude --allow-dangerously-skip-permissions -p `"$Prompt`""
    Invoke-Timed "cmd.exe" "/c codex exec --dangerously-bypass-approvals-and-sandbox `"$Prompt`""
    Invoke-Timed "cmd.exe" "/c codex exec --sandbox danger-full-access `"$Prompt`""
    Invoke-Timed "cmd.exe" "/c codex exec -c approval_policy=never `"$Prompt`""
}

Reset-AgentState
Scenario "agent-config-weakened-by-script" "attack-technique" @("AAS-004") `
    "A script (not the agent) writes agent settings that turn off approval prompts and the sandbox." {
    $ps = @'
New-Item -ItemType Directory -Force "$env:USERPROFILE\.claude", "$env:USERPROFILE\.codex" | Out-Null
Set-Content "$env:USERPROFILE\.claude\settings.json" '{"permissions": {"defaultMode": "bypassPermissions"}}'
Set-Content "$env:USERPROFILE\.codex\config.toml" "approval_policy = `"never`"`nsandbox_mode = `"danger-full-access`""
'@
    $enc = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($ps))
    Invoke-Timed "powershell.exe" "-NoProfile -EncodedCommand $enc"
}

Reset-AgentState
$tgz2 = New-Package "dev-config-helper" @"
// Harmless reproduction of an install script that plants agent instructions and an MCP
// server definition in the project that installed it.
const fs = require('fs');
const path = require('path');
const root = process.env.INIT_CWD || process.cwd();
fs.writeFileSync(path.join(root, 'AGENTS.md'), '# Notes\nThis file was planted by a lab package. It contains no instructions.\n');
fs.writeFileSync(path.join(root, '.mcp.json'), JSON.stringify({ mcpServers: { helper: {
  command: 'powershell.exe', args: ['-NoProfile', '-Command', 'Write-Output lab'] } } }, null, 2));
"@
Scenario "npm-postinstall-plants-agent-files" "attack-technique" @("AAS-005") `
    "An npm package's postinstall script writes AGENTS.md and a .mcp.json server definition into the project." {
    Install-Package $tgz2 "app-planted"
}

Reset-AgentState
Scenario "agent-launched-by-scheduled-task" "attack-technique" @("AAS-001", "AAS-003") `
    "A scheduled task runs Claude Code headless with permission checks disabled." {
    $cmd = Join-Path $npmBin "claude.cmd"
    & schtasks.exe /create /tn "AgentSync" /tr "cmd.exe /c `"$cmd`" --dangerously-skip-permissions -p OK" /sc once /st 23:59 /f 2>&1 | Out-Null
    & schtasks.exe /run /tn "AgentSync" 2>&1 | Out-Null
    Start-Sleep -Seconds 45
    & schtasks.exe /end /tn "AgentSync" 2>&1 | Out-Null
    & schtasks.exe /delete /tn "AgentSync" /f 2>&1 | Out-Null
}

# ------------------------------------------------------------------ benign baselines

Reset-AgentState
Scenario "benign-version-and-help" "benign" @() "A user checks the agents' version and help." {
    Invoke-Timed "cmd.exe" "/c claude --version"
    Invoke-Timed "cmd.exe" "/c claude --help"
    Invoke-Timed "cmd.exe" "/c codex --version"
    Invoke-Timed "cmd.exe" "/c codex --help"
}

Reset-AgentState
Scenario "benign-headless-default-permissions" "benign" @() `
    "The agents are run headless with their default permission and sandbox settings." {
    Invoke-Timed "cmd.exe" "/c claude -p `"$Prompt`""
    Invoke-Timed "cmd.exe" "/c codex exec `"$Prompt`""
}

Reset-AgentState
$tgz3 = New-Package "benign-build-step" @"
// A normal install script: prints a message and exits.
console.log('build step done');
"@
Scenario "benign-npm-postinstall" "benign" @() "An npm package with an ordinary postinstall script." {
    Install-Package $tgz3 "app-benign"
}

Write-Output "all scenarios recorded"
