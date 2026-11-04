# Round 2 held-out URL tricks: first-run record

64 URLs (`tests/test_sources_round2.py`) were written before any round-2 code change, from the WHATWG URL Standard (tab/newline removal, backslash as slash, extra slashes, IPv6 zone ids, forbidden host code points), UTS #46 (ideographic and fullwidth dots; soft hyphen and zero-width characters are mapped or dropped), CSP/redirect behaviour and the earlier lists. Expected outcome per row: allow, a named rule, or "rejected as an unusable URL form".

First run against the round-1 engine: **60 passed, 4 failed** (all four were wrongly ALLOWED).

| URL trick | Why it matters | Generic fix |
|---|---|---|
| `/%C0%AFprivate` | overlong UTF-8 slash; legacy servers read it as `/` | percent-decoding is strict UTF-8; invalid sequences are rejected (`bad_encoding`) |
| `/<U+202E>etavirp` (bidi override) | reorders what a reader sees | any Cc/Cf/Zs/Zl/Zp/Co/Cs character in the URL, raw or percent-encoded, is rejected (`bad_characters`) |
| `/pri<U+200B>vate` (zero-width space) | evades a deny prefix visually | same rule |
| `?u=%2568ttps://evil` | double-encoded embedded URL; a proxy that decodes twice forwards it | query values are percent-decoded up to three more times before the embedded-URL check |

Everything else already held, including backslash forms, tab/newline inside the URL, `lagen.example%40evil.test`, IPv6 zone ids, fullwidth and ideographic dots, soft hyphen, and all non-http schemes. One deliberate difference from browsers: a tab or newline inside a URL is rejected, not removed (a browser would silently reach a different string than the one that was judged). A redirect to an off-policy host (also from a `suffix` rule) is covered in `test_sources_guarded.py` and `test_sources_suffix_docset.py`.
