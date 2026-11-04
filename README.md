# agent-attack-samples

Windows event logs of the ways attackers abuse **AI coding agents**, recorded in a lab VM, and
**Sigma rules** that are tested against those recordings in CI.

AI coding agents such as Claude Code and the OpenAI Codex CLI can run shell commands on a
developer's machine. That makes them a target. In the **s1ngularity** attack (malicious Nx
packages on npm, August 2025), an install script ran the agents already installed on the
victim's machine with their safety checks turned off and asked them to find secrets. Most
detection content does not cover this yet, and there was no public, labelled telemetry to
build it from. This repository provides both.

> Claude Code and the Codex CLI appear here only as **detection targets**. Every scenario is
> harmless: the agents are **not logged in**, so no prompt ever reaches a model, and the only
> prompt used is `Reply with the single word OK.`

## What's inside

| Path | Contents |
|---|---|
| `data/<scenario>/` | `Sysmon.evtx` and `Security.evtx` for one scenario, plus `scenario.json` (what happened, when, and which rules should fire) |
| `rules/` | 5 Sigma rules (AAS-001 to AAS-005) |
| `lab/` | VirtualBox automation that builds the lab and records every scenario |
| `tools/`, `tests/` | The checks that run in CI |

## Scenarios

| Scenario | Kind | What happens | Expected rules |
|---|---|---|---|
| `npm-postinstall-launches-agents` | technique | An npm package's postinstall script runs `claude --dangerously-skip-permissions -p …` and `codex exec --dangerously-bypass-approvals-and-sandbox …` (s1ngularity technique) | AAS-001, AAS-002 |
| `agent-bypass-flags-from-script` | technique | A script runs the agents headless with each bypass option: `--dangerously-skip-permissions`, `--allow-dangerously-skip-permissions`, `--permission-mode bypassPermissions`, `--dangerously-bypass-approvals-and-sandbox`, `--sandbox danger-full-access`, `-c approval_policy=never` | AAS-001 |
| `agent-config-weakened-by-script` | technique | Encoded PowerShell writes `~/.claude/settings.json` (`bypassPermissions`) and `~/.codex/config.toml` (`approval_policy = "never"`, `sandbox_mode = "danger-full-access"`) | AAS-004 |
| `npm-postinstall-plants-agent-files` | technique | An install script writes `AGENTS.md` and a `.mcp.json` server definition into the project | AAS-005 |
| `agent-launched-by-scheduled-task` | technique | `schtasks /create` registers a task that runs Claude Code with `--dangerously-skip-permissions`; the task is run | AAS-001, AAS-003 |
| `benign-version-and-help` | benign | `--version` and `--help` for both agents | none |
| `benign-headless-default-permissions` | benign | `claude -p …` and `codex exec …` with default permissions and sandbox | none |
| `benign-npm-postinstall` | benign | An npm package with an ordinary postinstall script | none |

Only options confirmed in each CLI's own `--help` output were recorded. For example, `--yolo`
is not an option of Codex CLI 0.166.0, so it is not in the data.

## Rules

| ID | Rule | Log source | Level |
|---|---|---|---|
| AAS-001 | [Agent CLI launched with permission or sandbox bypass](rules/aas_001_agent_cli_permission_bypass.yml) | process creation (Sysmon 1 or Security 4688) | medium |
| AAS-002 | [Agent launched from an npm package install script](rules/aas_002_agent_cli_from_package_install.yml) (its working directory is inside `node_modules`) | Sysmon 1 | high |
| AAS-003 | [Scheduled task created to run an agent](rules/aas_003_agent_cli_scheduled_task.yml) | process creation | medium |
| AAS-004 | [Agent settings file created by another process](rules/aas_004_agent_config_written_by_other_process.yml) | Sysmon 11 | medium |
| AAS-005 | [Agent instruction or MCP config file created by Node.js](rules/aas_005_agent_instructions_or_mcp_written_by_node.yml) | Sysmon 11 | low |

ATT&CK tags use ATT&CK v20 (for example T1685 *Disable or Modify Tools* under the
*Defense Impairment* tactic).

### How the rules are tested

On every push, CI checks that **each recording fires exactly its expected rules, no more and no
fewer**, and that the benign baselines fire nothing. It does this with two independent engines:

1. `tools/sigma_eval.py`: a small evaluator with its own unit tests (`pytest`).
2. [Chainsaw](https://github.com/WithSecureLabs/chainsaw) v2.17.1 with its standard Sigma
   mapping (`tools/chainsaw_check.py`).

pySigma's validators also check every rule (valid Sigma, valid ATT&CK tags).

Things the recordings taught us:

- Claude Code 2.1.318 runs as a native `claude.exe`. Codex CLI 0.166.0 runs as
  `node …\@openai\codex\bin\codex.js` and then a native `codex.exe`.
- npm runs install scripts with the working directory set to the package's folder in
  `node_modules`, and Sysmon records it (`CurrentDirectory`). That is a strong, low-noise
  signal for AAS-002.
- The process started by the scheduled task was logged by Sysmon **without a parent**, so
  AAS-003 looks at the task creation instead of the parent process.

## Use the data

```bash
# Chainsaw
chainsaw hunt data/ -s rules/ --mapping mappings/sigma-event-logs-all.yml

# Hayabusa, or any tool that reads .evtx
```

Each `scenario.json` gives the exact time window and the expected rules, so the folders work as
test cases for your own detections.

## Recording environment

| | |
|---|---|
| Guest | Windows 11 Pro 26H2, build 26300 (disposable VirtualBox 7.2.14 VM) |
| Logging | Sysmon 15.22 with [`lab/sysmon-config.xml`](lab/sysmon-config.xml), plus Security 4688 with command lines |
| Node.js | v26.13.0 (SHA-256 checked against nodejs.org) |
| Agents | Claude Code 2.1.318, OpenAI Codex CLI 0.166.0, installed from npm, **not logged in** |
| Recorded | 2026-11-04 |

To reproduce it, see [`lab/`](lab/): `build_agent_snapshot.ps1` installs Sysmon, Node.js and
the agents on top of a clean Windows 11 VM snapshot, and `record.ps1` runs every scenario,
exports each one's events, refuses to import anything that contains the lab password, and copies
the result into `data/`.

## Limitations

- **Launch and file telemetry only.** Because the agents are not logged in, these recordings
  show how an agent is started and configured, not what it does after a model answers (commands
  it runs, files it reads, network calls to the model). Behaviour-level scenarios such as prompt
  injection through a web page or a poisoned MCP tool are planned and need a model.
- **Windows only.** The original s1ngularity payload targeted macOS and Linux; these recordings
  reproduce the technique on Windows.
- AAS-002, AAS-004 and AAS-005 need Sysmon. AAS-004 and AAS-005 see file **creation** only;
  edits to an existing file are not logged by Sysmon event 11.
- One recording per scenario, from one agent version each. Command-line options change between
  releases, so rules keyed on options need maintenance.
- AAS-005 is low-confidence by design: Node.js scaffolding tools can create the same files.

## License

Code (`lab/`, `tools/`, `tests/`): [MIT](LICENSE). Recordings and rules (`data/`, `rules/`):
[CC BY 4.0](LICENSE-DATA.md).
