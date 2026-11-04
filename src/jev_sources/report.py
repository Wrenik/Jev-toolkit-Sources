"""HTML report for a policy-checked answer: FactCheck's renderer plus the two states only Sources produces.

Jev-toolkit-FactCheck's renderer does not know `forbidden_source` or `untraceable`. Until it does, this wrapper adds
their labels and styling to the renderer's tables (idempotent) and calls it; the rule that rejected a source is
already in each result's flags and explanation, which the renderer prints.
"""

from __future__ import annotations

from typing import Any

from jev_factcheck import render as _render

_LABELS = {
    "forbidden_source": ("⛔", "Source not approved by the policy"),
    "untraceable": ("?", "No source given (not approved)"),
}
_CSS = (".s-forbidden_source{border-color:var(--bad);border-bottom-style:solid;border-bottom-width:4px}"
        ".s-untraceable{border-color:var(--na);border-bottom-style:dotted;border-bottom-width:3px}")


def render_report(text: str, results: list[Any], **kwargs: Any) -> str:
    for k, v in _LABELS.items():
        _render.LABELS.setdefault(k, v)
    if _CSS not in _render.CSS:
        _render.CSS += "\n" + _CSS
    return _render.render_html(text, results, **kwargs)
