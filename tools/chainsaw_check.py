"""Run every rule over every recording with Chainsaw (an independent Sigma engine) and check
that exactly the expected rules fire. Used in CI next to the pytest suite.

Usage: python tools/chainsaw_check.py <path-to-chainsaw> <path-to-mapping.yml>
"""

from __future__ import annotations

import json
import re
import subprocess
import sys
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]


def rule_titles() -> dict[str, str]:
    titles = {}
    for path in sorted((ROOT / "rules").glob("aas_*.yml")):
        number = re.match(r"aas_(\d{3})_", path.name).group(1)
        titles[yaml.safe_load(path.read_text(encoding="utf-8"))["title"]] = f"AAS-{number}"
    return titles


def main(chainsaw: str, mapping: str) -> int:
    titles = rule_titles()
    failures = 0
    for folder in sorted((ROOT / "data").iterdir()):
        meta_file = folder / "scenario.json"
        if not meta_file.exists():
            continue
        meta = json.loads(meta_file.read_text(encoding="utf-8-sig"))
        out = subprocess.run(
            [chainsaw, "hunt", str(folder), "-s", str(ROOT / "rules"), "--mapping", mapping,
             "--json", "-q"],
            capture_output=True, text=True, check=True,
        ).stdout
        hits = json.loads(out) if out.strip() else []
        fired = {titles[h["name"]] for h in hits if h.get("name") in titles}
        expected = set(meta["expected_rules"])
        status = "ok  " if fired == expected else "FAIL"
        failures += fired != expected
        print(f"{status} {folder.name}: fired {sorted(fired)}, expected {sorted(expected)}")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1], sys.argv[2]))
