# Runs ONCE inside the lab VM to prepare the "agents" snapshot.
# Installs Sysmon (from Microsoft Sysinternals), Node.js LTS (from nodejs.org) and the
# Claude Code and OpenAI Codex command-line agents (from npm). The agents are NOT logged in:
# no API key or account ever enters the VM. Writes versions and --help output to C:\lab\agents.
# "Continue": Windows PowerShell 5.1 treats any stderr line from a native program as a fatal
# error under "Stop". Native programs are judged by their exit code instead, and cmdlets that
# must not fail use -ErrorAction Stop.
$ErrorActionPreference = "Continue"
$ProgressPreference = "SilentlyContinue"
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
$out = "C:\lab\agents"
New-Item -ItemType Directory -Force $out, "C:\lab\tools" | Out-Null

# 1. Sysmon with this project's config.
$zip = "C:\lab\tools\Sysmon.zip"
Invoke-WebRequest "https://download.sysinternals.com/files/Sysmon.zip" -OutFile $zip -UseBasicParsing -ErrorAction Stop
Expand-Archive $zip -DestinationPath "C:\lab\tools\Sysmon" -Force -ErrorAction Stop
& "C:\lab\tools\Sysmon\Sysmon64.exe" -accepteula -i "C:\lab\sysmon-config.xml" 2>&1 | Out-File "$out\sysmon-install.txt"
if (-not (Get-Service Sysmon64 -ErrorAction SilentlyContinue)) { throw "Sysmon did not install" }
wevtutil sl Microsoft-Windows-Sysmon/Operational /ms:268435456

# 2. Node.js: newest LTS release, verified against the published SHA-256.
$index = Invoke-RestMethod "https://nodejs.org/dist/index.json" -UseBasicParsing -ErrorAction Stop
$lts = $index | Where-Object { $_.lts } | Select-Object -First 1
$msiName = "node-$($lts.version)-x64.msi"
$msi = "C:\lab\tools\$msiName"
Invoke-WebRequest "https://nodejs.org/dist/$($lts.version)/$msiName" -OutFile $msi -UseBasicParsing -ErrorAction Stop
$sums = (Invoke-WebRequest "https://nodejs.org/dist/$($lts.version)/SHASUMS256.txt" -UseBasicParsing -ErrorAction Stop).Content
$expected = ($sums -split "`n" | Where-Object { $_ -match [regex]::Escape($msiName) }) -split "\s+" | Select-Object -First 1
$actual = (Get-FileHash $msi -Algorithm SHA256).Hash.ToLower()
if ($actual -ne $expected) { throw "Node.js MSI hash mismatch: $actual vs $expected" }
$p = Start-Process msiexec.exe -ArgumentList "/i `"$msi`" /qn /norestart" -Wait -PassThru
if ($p.ExitCode -ne 0) { throw "Node.js install failed: $($p.ExitCode)" }
$env:Path = "C:\Program Files\nodejs;$env:APPDATA\npm;$env:Path"

# 3. The two agent CLIs, installed globally for the lab user.
& "C:\Program Files\nodejs\npm.cmd" install -g "@anthropic-ai/claude-code" "@openai/codex" 2>&1 | Out-File "$out\npm-install.txt"
if ($LASTEXITCODE -ne 0) { throw "npm install failed; see npm-install.txt" }
& "C:\Program Files\nodejs\npm.cmd" ls -g --depth=0 --json 2>&1 | Out-File "$out\npm-ls.json" -Encoding utf8

# 4. Record versions and flags. Output is kept short; nothing here is interactive.
@{
    node = (& "C:\Program Files\nodejs\node.exe" --version)
    windows_build = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion").CurrentBuild
    sysmon = (Get-Item "C:\lab\tools\Sysmon\Sysmon64.exe").VersionInfo.FileVersion
} | ConvertTo-Json | Out-File "$out\versions.json" -Encoding utf8
foreach ($cli in "claude", "codex") {
    $cmd = Join-Path $env:APPDATA "npm\$cli.cmd"
    if (-not (Test-Path $cmd)) { throw "$cli was not installed" }
    cmd /c "`"$cmd`" --version" 2>&1 | Out-File "$out\$cli-version.txt"
    cmd /c "`"$cmd`" --help" 2>&1 | Out-File "$out\$cli-help.txt"
}
cmd /c "`"$env:APPDATA\npm\codex.cmd`" exec --help" 2>&1 | Out-File "$out\codex-exec-help.txt"

# 5. Start every recording from empty logs and no agent state.
Remove-Item -Recurse -Force "$env:USERPROFILE\.claude", "$env:USERPROFILE\.codex", "$env:USERPROFILE\.claude.json" -ErrorAction SilentlyContinue
wevtutil cl Microsoft-Windows-Sysmon/Operational
"installed"
