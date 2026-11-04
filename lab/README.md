# Lab

Records the scenarios in a disposable Windows 11 VirtualBox VM.

1. Build a clean Windows 11 VM with snapshot `clean`. This project uses the unattended build from
   [dfir-triage-automator](https://github.com/yug3009p/dfir-triage-automator/tree/main/lab)
   (`build_vm.ps1`), which also turns on process-creation auditing with command lines.
2. `.\lab\build_agent_snapshot.ps1` installs Sysmon (with `sysmon-config.xml`), Node.js and the
   Claude Code and Codex CLIs, and saves snapshot `agents`. No account or API key is ever placed
   in the VM.
3. `.\lab\record.ps1` restores `agents`, runs `guest\scenarios.ps1`, exports each scenario's
   Sysmon and Security events, stops if the lab password appears anywhere in them, and copies the
   result into `data\`.

Keep the host awake while recording: if Windows sleeps or VirtualBox saves the VM mid-run, the
guest stops answering Guest Additions commands. `lab-runs\` and `lab\.secrets\` are git-ignored.
