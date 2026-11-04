# Changelog

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### Added
- 8 recorded scenarios (5 attack techniques, 3 benign baselines) from a Windows 11 26H2 lab VM
  with Claude Code 2.1.318 and OpenAI Codex CLI 0.166.0, not logged in.
- Sigma rules AAS-001 to AAS-005.
- Lab automation (`lab/`) that builds the recording snapshot and records every scenario.
- CI that checks each recording fires exactly its expected rules, with a small evaluator and with
  Chainsaw.
