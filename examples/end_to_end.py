"""FactCheck + Sources end to end, offline: python examples/end_to_end.py [out.html]

claims.json has four claims; the fourth cites a host the policy denies. The fetcher is the policy-guarded one on a
FAKE web (invented pages), so the forum is never contacted, and the HTML report (made by Jev-toolkit-FactCheck's
renderer) names the rule that rejected it. The judge is the offline word-overlap heuristic, not a model."""

import json
import sys
from pathlib import Path

from jev_factcheck.demojudge import DemoJudge
from jev_factcheck.loop import LoopState

from jev_sources.check import parse_lenient, run_round, summarize, uncovered_sentences
from jev_sources.guarded import FakeWeb
from jev_sources.policy import load_policy
from jev_sources.report import render_report

HERE = Path(__file__).resolve().parent
PAGE = "<html><body><p>{}</p></body></html>"
WEB = {
    "https://lagen.example/semester": PAGE.format("Employees are entitled to 25 days of paid holiday per year."),
    "https://www.lagen.example/foraldraledighet": PAGE.format("Parental leave is 480 days per child."),
    "https://lagen.example/uppsagning": PAGE.format("The notice period is three months."),
    "https://forum.example/t/holiday-days": PAGE.format("Most employers allow 30 days in practice."),
}


def main(out: str) -> int:
    policy = load_policy(HERE / "policy.toml")
    cf, untraceable = parse_lenient(json.loads((HERE / "claims.json").read_text(encoding="utf-8")))
    web = FakeWeb(WEB)
    state = LoopState()
    result = run_round(cf, untraceable, policy, web.fetcher(policy), DemoJudge(), state)
    print(summarize(result.results, state, uncovered_sentences(cf)))
    print("Contacted:", web.contacted, "| forum resolved:", "forum.example" in web.resolved)
    html = render_report(
        cf.text,
        result.results,
        title="Sources + FactCheck end to end",
        rounds=[result.corrections],
        judge_note="Offline demo: invented pages, word-overlap judge (not a model).",
    )
    Path(out).write_text(html, encoding="utf-8")
    print("Report:", out)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1] if len(sys.argv) > 1 else "end_to_end_report.html"))
