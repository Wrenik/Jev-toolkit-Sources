# End to end: FactCheck + Sources

`examples/end_to_end.py` joins the two libraries without network or key:

1. `examples/policy.toml` allows `lagen.example` (and subdomains) and denies `forum.example` (rule `no-forums`).
2. `examples/claims.json` has four claims; c1 to c3 cite approved pages, c4 cites `forum.example`.
3. `run_round` (Sources) judges each cited URL before any connection, then uses the guarded fetcher on a fake web, FactCheck's quote matcher and the offline word-overlap judge.
4. `render_report` (Sources wrapper over FactCheck's `render_html`) writes the HTML.

Result: three claims supported, c4 `forbidden_source`: "Rejected by rule no-forums: domain forum.example (and its subdomains) is denied." The forum host is neither contacted nor resolved (the script prints both lists). Saved output: [end_to_end_report.html](end_to_end_report.html) (no scripts, no remote resources).

Needed in Jev-toolkit-FactCheck (not edited here): `render.LABELS` and its CSS should know `forbidden_source` and `untraceable`; `report.py` patches them in at run time until then.
