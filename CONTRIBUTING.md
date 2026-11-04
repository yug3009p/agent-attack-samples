# Contributing

Contributions of new scenarios, recordings and rules are welcome.

1. Scenarios must be **harmless**: no real secrets, no real exfiltration, no network targets
   outside the lab VM, and no logged-in agent accounts.
2. Record in a disposable VM with `lab/record.ps1` (or document your own setup in the PR), and
   include the `scenario.json` describing what happened and which rules should fire.
3. Every rule needs at least one recording where it fires and must not fire on the benign
   baselines. `pytest` checks both.
4. Run `ruff check .` and `pytest` before opening a pull request.
