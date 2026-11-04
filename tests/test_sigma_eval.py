"""Unit tests for the small Sigma evaluator in tools/sigma_eval.py."""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

from sigma_eval import SECURITY, SYSMON, Event, Rule, matches, to_event  # noqa: E402


def rule(detection: dict, condition: str, category: str = "process_creation") -> Rule:
    return Rule("id", "title", category, detection, condition, Path("x.yml"))


def proc(cmd: str, image: str = r"C:\Windows\System32\cmd.exe", **extra) -> Event:
    return Event("process_creation", {"Image": image, "CommandLine": cmd, **extra}, "test")


def test_modifiers_are_case_insensitive():
    r = rule({"sel": {"CommandLine|contains": "--Dangerously-Skip"}}, "sel")
    assert matches(r, proc("claude --dangerously-skip-permissions -p x"))
    assert not matches(r, proc("claude --version"))
    assert matches(rule({"sel": {"Image|endswith": "\\CMD.exe"}}, "sel"), proc("x"))
    assert matches(rule({"sel": {"CommandLine|startswith": "CLAUDE"}}, "sel"), proc("claude -p"))


def test_list_values_are_or_unless_all():
    any_of = rule({"sel": {"CommandLine|contains": ["--yolo", "--trust-all-tools"]}}, "sel")
    all_of = rule({"sel": {"CommandLine|contains|all": ["codex", "--yolo"]}}, "sel")
    assert matches(any_of, proc("gemini --yolo"))
    assert matches(all_of, proc("codex --yolo exec"))
    assert not matches(all_of, proc("gemini --yolo"))


def test_conditions_and_or_not_parentheses_and_quantifiers():
    det = {
        "sel_agent": {"CommandLine|contains": "claude"},
        "sel_flag": {"CommandLine|contains": "--dangerously"},
        "filter": {"Image|endswith": "\\node.exe"},
    }
    guarded = rule(det, "sel_agent and sel_flag and not filter")
    assert matches(guarded, proc("claude --dangerously-x"))
    assert not matches(guarded, proc("claude --dangerously-x", image="C:\\node.exe"))
    assert matches(rule(det, "(sel_flag or filter) and sel_agent"), proc("claude --dangerously"))
    assert matches(rule(det, "1 of sel_*"), proc("claude --version"))
    assert not matches(rule(det, "all of sel_*"), proc("claude --version"))


def test_missing_field_never_matches_and_category_must_match():
    r = rule({"sel": {"ParentCommandLine|contains": "Schedule"}}, "sel")
    assert not matches(r, proc("x"))  # Security 4688 has no ParentCommandLine
    file_rule = rule({"sel": {"TargetFilename|endswith": "AGENTS.md"}}, "sel", "file_event")
    assert not matches(file_rule, proc("AGENTS.md"))


def test_event_mapping():
    sysmon = to_event(SYSMON, 1, "t", {"Image": "a", "CommandLine": "b"})
    assert sysmon.category == "process_creation" and sysmon.fields["CommandLine"] == "b"
    sec = to_event(SECURITY, 4688, "t", {"NewProcessName": "a", "CommandLine": "b",
                                         "ParentProcessName": "c"})
    assert sec.fields == {"Image": "a", "CommandLine": "b", "ParentImage": "c", "User": ""}
    assert to_event(SYSMON, 11, "t", {"TargetFilename": "f"}).category == "file_event"
    assert to_event(SYSMON, 3, "t", {}) is None
