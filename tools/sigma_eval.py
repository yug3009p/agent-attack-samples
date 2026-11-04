"""Minimal Sigma evaluator used to test this project's rules against its recordings.

Supports only what the rules in rules/ use:
  - logsources: windows process_creation (Sysmon 1, Security 4688) and file_event (Sysmon 11)
  - modifiers: contains, startswith, endswith, all, re (case-insensitive except re)
  - conditions: selection names, and / or / not, parentheses, "1 of x*", "all of x*"

CI also runs the rules with Chainsaw, an independent Sigma engine, so the tests do not
depend only on this file.
"""

from __future__ import annotations

import fnmatch
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path
from xml.etree import ElementTree

import yaml
from Evtx.Evtx import Evtx

NS = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}
SYSMON = "Microsoft-Windows-Sysmon"
SECURITY = "Microsoft-Windows-Security-Auditing"


@dataclass
class Event:
    category: str  # process_creation | file_event
    fields: dict[str, str]
    source: str  # e.g. "Sysmon 1"
    time: str = ""


@dataclass
class Rule:
    id: str
    title: str
    category: str
    detection: dict
    condition: str
    path: Path
    raw: dict = field(repr=False, default_factory=dict)


# ------------------------------------------------------------------ events


def _event_data(record_xml: str) -> tuple[str, int, str, dict[str, str]]:
    root = ElementTree.fromstring(record_xml)
    system = root.find("e:System", NS)
    provider = system.find("e:Provider", NS).get("Name", "")
    event_id = int(system.find("e:EventID", NS).text)
    created = system.find("e:TimeCreated", NS).get("SystemTime", "")
    data = {}
    for d in root.iter(f"{{{NS['e']}}}Data"):
        name = d.get("Name")
        if name:
            data[name] = d.text or ""
    return provider, event_id, created, data


def to_event(provider: str, event_id: int, created: str, data: dict[str, str]) -> Event | None:
    if provider == SYSMON and event_id == 1:
        return Event("process_creation", data, "Sysmon 1", created)
    if provider == SECURITY and event_id == 4688:
        fields = {
            "Image": data.get("NewProcessName", ""),
            "CommandLine": data.get("CommandLine", ""),
            "ParentImage": data.get("ParentProcessName", ""),
            "User": data.get("SubjectUserName", ""),
        }
        return Event("process_creation", fields, "Security 4688", created)
    if provider == SYSMON and event_id == 11:
        return Event("file_event", data, "Sysmon 11", created)
    return None


def load_events(folder: Path) -> list[Event]:
    events = []
    for evtx in sorted(folder.glob("*.evtx")):
        with Evtx(str(evtx)) as log:
            for record in log.records():
                event = to_event(*_event_data(record.xml()))
                if event:
                    events.append(event)
    return events


# ------------------------------------------------------------------ rules


def load_rule(path: Path) -> Rule:
    raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    detection = dict(raw["detection"])
    condition = detection.pop("condition")
    category = raw["logsource"]["category"]
    return Rule(raw["id"], raw["title"], category, detection, condition, path, raw)


def load_rules(folder: Path) -> list[Rule]:
    return [load_rule(p) for p in sorted(folder.glob("*.yml"))]


def _match_value(actual: str, expected, modifiers: list[str]) -> bool:
    if expected is None:
        return actual == ""
    expected = str(expected)
    if "re" in modifiers:
        return re.search(expected, actual) is not None
    a, e = actual.lower(), expected.lower()
    if "contains" in modifiers:
        return e in a
    if "startswith" in modifiers:
        return a.startswith(e)
    if "endswith" in modifiers:
        return a.endswith(e)
    return a == e


def _match_field(event: Event, key: str, expected) -> bool:
    name, *modifiers = key.split("|")
    actual = event.fields.get(name)
    if actual is None:
        return False
    values = expected if isinstance(expected, list) else [expected]
    results = [_match_value(actual, v, modifiers) for v in values]
    return all(results) if "all" in modifiers else any(results)


def _match_selection(event: Event, selection) -> bool:
    if isinstance(selection, list):  # list of maps: any of them
        return any(_match_selection(event, s) for s in selection)
    return all(_match_field(event, k, v) for k, v in selection.items())


def _tokens(condition: str) -> list[str]:
    return re.findall(r"\(|\)|[^\s()]+", condition)


def _eval_condition(rule: Rule, event: Event) -> bool:
    tokens = _tokens(rule.condition)
    pos = 0

    def sel(name: str) -> bool:
        return _match_selection(event, rule.detection[name])

    def names(pattern: str) -> list[str]:
        if pattern == "them":
            return list(rule.detection)
        return [n for n in rule.detection if fnmatch.fnmatch(n, pattern)]

    def primary() -> bool:
        nonlocal pos
        tok = tokens[pos]
        if tok == "(":
            pos += 1
            value = expr()
            pos += 1  # ")"
            return value
        if tok == "not":
            pos += 1
            return not primary()
        if tok in ("1", "all") and pos + 2 < len(tokens) and tokens[pos + 1] == "of":
            quantifier, pattern = tok, tokens[pos + 2]
            pos += 3
            results = [sel(n) for n in names(pattern)]
            return any(results) if quantifier == "1" else all(results)
        pos += 1
        return sel(tok)

    def term() -> bool:
        nonlocal pos
        value = primary()
        while pos < len(tokens) and tokens[pos] == "and":
            pos += 1
            right = primary()
            value = value and right
        return value

    def expr() -> bool:
        nonlocal pos
        value = term()
        while pos < len(tokens) and tokens[pos] == "or":
            pos += 1
            right = term()
            value = value or right
        return value

    return expr()


def matches(rule: Rule, event: Event) -> bool:
    return rule.category == event.category and _eval_condition(rule, event)


def evaluate(rules: list[Rule], events: list[Event]) -> dict[str, list[Event]]:
    hits: dict[str, list[Event]] = {}
    for rule in rules:
        for event in events:
            if matches(rule, event):
                hits.setdefault(rule.id, []).append(event)
    return hits


def main(argv: list[str]) -> int:
    rules = load_rules(Path(argv[1]))
    for folder in sorted(Path(argv[2]).iterdir()):
        if folder.is_dir():
            hits = evaluate(rules, load_events(folder))
            ids = {r.id: r.raw.get("name", r.id) for r in rules}
            print(f"{folder.name}: {sorted(ids[i] for i in hits) or '-'}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
