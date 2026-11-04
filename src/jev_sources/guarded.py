"""A fetcher that only reads what the policy approves, on every hop, and a fake web for tests and the demo.

`GuardedFetcher` wraps jev_factcheck's `Fetcher` (same `.fetch(url) -> FetchResult` interface):

1. the URL is judged BEFORE any connection; a forbidden URL is never contacted;
2. the host of every redirect hop is judged before DNS, and the full hop URL before the connection, so a redirect
   from an approved page to a forbidden site is stopped without contacting the forbidden site;
3. after the fetch, the whole redirect chain and the final URL are judged again (this also covers cached results);
4. `docset:` references are read from local files whose sha256 matches the policy manifest.

A blocked fetch returns `FetchResult(ok=False, status="policy_blocked")`; the decision is in `decision_for(url)`.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from jev_factcheck.fetch import Fetcher, FetchResult, real_transport
from jev_factcheck.htmltext import extract_text
from jev_factcheck.netguard import BlockedURL, Target, system_resolver

from .engine import Decision, evaluate
from .policy import Policy
from .urlcanon import WRAPPER_HOSTS, canonicalize


def host_possible(policy: Policy, host: str) -> bool:
    """Could ANY approved URL live on this host? Used before DNS so forbidden hosts are not even resolved."""
    for r in policy.allows:
        if not policy.active(r):
            continue
        if (r.kind == "domain" and (host == r.host or (r.subdomains and host.endswith("." + r.host)))) or (r.kind == "url_prefix" and host == r.host):
            return True
    return policy.allow_archives and host in WRAPPER_HOSTS


class PolicyBlocked(OSError):
    """Raised inside the transport when a hop is not approved; the fetcher then gives up on the URL."""


class GuardedFetcher:
    def __init__(self, policy: Policy, cache_dir: str | Path | None = None, *, transport=real_transport,
                 resolver=system_resolver, **kwargs: Any):
        self.policy = policy
        self._block: Decision | None = None
        self.decisions: dict[str, Decision] = {}
        self._inner = Fetcher(cache_dir, transport=self._guard_transport(transport), resolver=self._guard_resolver(resolver), **kwargs)

    # -- hop checks inside the fetcher ----------------------------------------------------------------
    def _guard_resolver(self, resolver):
        def guarded(host: str, port: int) -> list[str]:
            if not host_possible(self.policy, host):
                d = evaluate(self.policy, f"https://{host}/")
                self._block = d
                raise BlockedURL("policy", d.message)
            return resolver(host, port)

        return guarded

    def _guard_transport(self, transport):
        def guarded(target: Target, ip: str, timeout: float):
            d = evaluate(self.policy, target.url)
            if not d.allowed:
                self._block = d
                raise PolicyBlocked(d.message)
            return transport(target, ip, timeout)

        return guarded

    # -- public ---------------------------------------------------------------------------------------
    def decision_for(self, url: str) -> Decision | None:
        return self.decisions.get(url.strip())

    def _blocked(self, url: str, d: Decision, redirects: list[str] | None = None) -> FetchResult:
        self.decisions[url.strip()] = d
        return FetchResult(url, False, "policy_blocked", d.message, redirects=redirects or [])

    def fetch(self, url: str) -> FetchResult:
        url = url.strip()
        first = evaluate(self.policy, url)
        self.decisions[url] = first
        if not first.allowed:
            return self._blocked(url, first)
        if first.content is not None:
            return self._docset(url, first)
        self._block = None
        res = self._inner.fetch(url)
        if self._block is not None:
            return self._blocked(url, self._block, res.redirects)
        for hop in [*res.redirects, res.final_url]:  # cached results, and a belt-and-braces re-check
            if hop and hop != url:
                d = evaluate(self.policy, hop)
                if not d.allowed:
                    d.message = f"Redirect from {url} led to a source that is not approved. " + d.message
                    return self._blocked(url, d, res.redirects)
        return res

    def _docset(self, url: str, d: Decision) -> FetchResult:
        ctype = "text/html" if url.lower().endswith((".html", ".htm")) else "text/plain"
        page = extract_text((d.content or b"").decode("utf-8", errors="replace"), ctype)
        if not page.text.strip():
            return FetchResult(url, False, "empty", "the approved document has no readable text", url, 200, ctype)
        return FetchResult(url, True, "ok", "", url, 200, ctype, page.text, page.title, page.dropped_chars)


# ---- a fake web, so tests and the demo run the REAL redirect/transport code without a network ------------


class FakeResp:
    def __init__(self, status: int = 200, headers: dict[str, str] | None = None, body: bytes = b""):
        self.status = status
        self.headers = {k.lower(): v for k, v in (headers or {}).items()}
        self._body = body

    def read(self, n: int) -> bytes:
        out, self._body = self._body[:n], self._body[n:]
        return out

    def close(self) -> None:
        pass


class FakeWeb:
    """`pages`: url -> html string, or ("redirect", location[, status]). `contacted` records every URL a connection was made to."""

    def __init__(self, pages: dict[str, Any]):
        self.pages = pages
        self.contacted: list[str] = []
        self.resolved: list[str] = []

    def resolver(self, host: str, port: int) -> list[str]:
        self.resolved.append(host)
        return ["93.184.216.34"]

    def transport(self, target: Target, ip: str, timeout: float) -> FakeResp:
        self.contacted.append(target.url)
        entry = self.pages.get(target.url) or self.pages.get(canonicalize(target.url).text())  # fixtures are keyed by canonical URL
        if entry is None:
            return FakeResp(404, {"content-type": "text/html"}, b"not found")
        if isinstance(entry, tuple):
            return FakeResp(entry[2] if len(entry) > 2 else 302, {"location": entry[1]})
        return FakeResp(200, {"content-type": "text/html; charset=utf-8"}, entry.encode("utf-8"))

    def fetcher(self, policy: Policy | None) -> Any:
        kw = dict(transport=self.transport, resolver=self.resolver, per_host_delay=0)
        return GuardedFetcher(policy, **kw) if policy is not None else Fetcher(**kw)

