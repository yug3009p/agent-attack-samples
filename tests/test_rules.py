"""Every rule must be valid Sigma, fire on the recordings it was written for, and stay quiet on
everything else, including the benign baselines."""

from __future__ import annotations

import json
import re
import sys
import uuid
from pathlib import Path

import pytest
from sigma.collection import SigmaCollection
from sigma.validation import SigmaValidator
from sigma.validators.core import validators

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

import sigma_eval  # noqa: E402

RULES_DIR = ROOT / "rules"
DATA_DIR = ROOT / "data"
RULES = sigma_eval.load_rules(RULES_DIR)
SCENARIOS = sorted(p for p in DATA_DIR.iterdir() if (p / "scenario.json").exists())


def aas_id(rule: sigma_eval.Rule) -> str:
    """rules/aas_001_something.yml -> AAS-001"""
    match = re.match(r"aas_(\d{3})_", rule.path.name)
    assert match, f"{rule.path.name} must be named aas_NNN_<name>.yml"
    return f"AAS-{match.group(1)}"


def scenario(path: Path) -> dict:
    return json.loads(path.joinpath("scenario.json").read_text(encoding="utf-8-sig"))


def test_rules_and_scenarios_exist():
    assert RULES, "no rules found"
    assert SCENARIOS, "no recordings found"
    assert any(scenario(s)["kind"] == "benign" for s in SCENARIOS), "need benign baselines"


@pytest.mark.parametrize("rule", RULES, ids=lambda r: r.path.name)
def test_rule_is_valid_sigma(rule):
    collection = SigmaCollection.from_yaml(rule.path.read_text(encoding="utf-8"))
    assert not collection.errors
    issues = SigmaValidator(validators.values()).validate_rules(collection)
    assert not issues, [str(i) for i in issues]
    uuid.UUID(rule.raw["id"])
    required = (
        "title", "description", "references", "author", "date", "tags", "falsepositives", "level"
    )
    for key in required:
        assert rule.raw.get(key), f"{rule.path.name}: missing {key}"
    assert any(t.startswith("attack.t") for t in rule.raw["tags"]), "needs an ATT&CK technique tag"


def test_rule_ids_are_unique():
    assert len({r.raw["id"] for r in RULES}) == len(RULES)
    assert len({aas_id(r) for r in RULES}) == len(RULES)


@pytest.mark.parametrize("folder", SCENARIOS, ids=lambda p: p.name)
def test_rules_fire_exactly_as_expected(folder):
    meta = scenario(folder)
    hits = sigma_eval.evaluate(RULES, sigma_eval.load_events(folder))
    fired = {aas_id(r) for r in RULES if r.id in hits}
    assert fired == set(meta["expected_rules"]), (
        f"{folder.name}: fired {sorted(fired)}, expected {sorted(meta['expected_rules'])}"
    )


def test_every_rule_has_a_positive_recording():
    expected = {r for s in SCENARIOS for r in scenario(s)["expected_rules"]}
    missing = {aas_id(r) for r in RULES} - expected
    assert not missing, f"rules without a recording that should trigger them: {sorted(missing)}"


def test_recordings_never_had_a_logged_in_agent():
    for folder in SCENARIOS:
        assert scenario(folder)["agents_logged_in"] is False
