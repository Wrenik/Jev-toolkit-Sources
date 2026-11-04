# Contributing

Thanks for looking. This is a small learning project, so the bar is "clear and honest", not "enterprise".

1. `python -m venv .venv`, then `.venv/Scripts/python -m pip install -e ../Jev-toolkit-usage`, `-e ../Jev-toolkit-FactCheck --no-deps` and `-e ".[dev]" --no-deps` (use `.venv/bin/python` on Linux/macOS).
2. Run the tests: `python -m pytest`. They are offline and need no API key or network (`JEV_JUDGE=fake` in CI). Tests marked `live` call the real Jev API and are skipped by default.
3. New behaviour comes with a test. A URL trick that gets through comes with a regression test that fails without the fix.
4. Keep documentation claims measured: say what was tested, on how many cases, and what the limits are.
5. Never use the Jev SDK directly (it lives in Jev-toolkit-usage, `jev_core`); talk to the `Judge` interface. Import from `jev_factcheck` only through its modules `checker`, `fetch`, `htmltext`, `netguard`, `judging`, `loop`, `schema`, `verdict`, `demojudge`.
6. Evaluation: add new scenarios to a **new** held-out set; never tune rules on a set you report on. `evalset/heldout.json` was run once before any fix; if you change rules because of it, say so and make a fresh set.
