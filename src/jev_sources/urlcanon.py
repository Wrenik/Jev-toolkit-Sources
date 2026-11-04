"""Turn a URL (written by an LLM, so attacker-influenced) into one canonical form before any rule is applied.

Rules are never matched against the raw string. A URL is either rejected with a stable code, or becomes a `Canon`
with a punycode host, a normalised path and, for archive/cache/translate wrappers, the wrapped inner URL.

Handled: scheme (only http/https and `docset:`), userinfo (`https://allowed.example@evil.example/`), uppercase,
trailing dot, default ports, fragments (dropped), IDN/homoglyph hosts (shown as punycode), IP-literal hosts,
backslashes, control characters, percent-encoded dots and slashes (`%2e`, `%2f`, `%5c`, also double-encoded),
dot segments, archive/cache/translate wrappers, and URLs embedded in query parameters (open redirectors).
"""

from __future__ import annotations

import ipaddress
import re
import unicodedata
from dataclasses import dataclass, field
from urllib.parse import parse_qsl, unquote, urlsplit

MAX_URL = 2000

# Hosts that serve a COPY of, or a REDIRECT to, another URL. A policy approves the original, not the copy.
WRAPPER_HOSTS = {
    "web.archive.org": "archive",
    "archive.org": "archive",
    "archive.ph": "archive",
    "archive.is": "archive",
    "archive.today": "archive",
    "archive.li": "archive",
    "archive.vn": "archive",
    "archive.md": "archive",
    "webcache.googleusercontent.com": "cache",
    "cache.google.com": "cache",
    "cachedview.nl": "cache",
    "translate.google.com": "translate",
    "translate.goog": "translate",
    "translate.googleusercontent.com": "translate",
    "bing.com": "cache",
    "r.jina.ai": "proxy",
    "12ft.io": "proxy",
    "outline.com": "proxy",
    "google.com": "redirect",
    "www.google.com": "redirect",
    "l.facebook.com": "redirect",
    "t.co": "redirect",
    "bit.ly": "shortener",
    "tinyurl.com": "shortener",
    "goo.gl": "shortener",
    "ow.ly": "shortener",
    "is.gd": "shortener",
}
_WRAPPER_PATH = re.compile(
    r"^/(?:web/)?(?:\d{1,14}[a-z_]{0,3}/)?(https?:/{1,2}.+)$", re.I
)  # web.archive.org/web/2020/https://x
_URLISH = re.compile(r"^(?:https?:)?//", re.I)
_ENCODED_SEP = re.compile(r"%(?:2f|5c)", re.I)
_ENCODED_DOT = re.compile(r"%2e", re.I)


def _invisible(text: str) -> bool:
    """Control, format (zero-width, bidi override, soft hyphen), separator, private-use or surrogate characters.
    They are invisible or reorder what a reader sees, and UTS #46 silently drops many of them, so a browser may
    reach a different name or path than the one shown."""
    return any(unicodedata.category(c) in ("Cc", "Cf", "Zs", "Zl", "Zp", "Co", "Cs") for c in text)


def _strict_unquote(text: str) -> str:
    try:
        return unquote(text, errors="strict")
    except UnicodeDecodeError as exc:
        raise UrlRejected(
            "bad_encoding",
            "a percent-encoded byte sequence that is not valid UTF-8 (overlong forms such as %C0%AF are used to hide slashes)",
        ) from exc


class UrlRejected(Exception):
    """The URL cannot be turned into a safe canonical form. `code` is a stable identifier, `detail` is for humans."""

    def __init__(self, code: str, detail: str = ""):
        super().__init__(f"{code}: {detail}" if detail else code)
        self.code, self.detail = code, detail


@dataclass(frozen=True)
class Canon:
    kind: str  # web | docset
    scheme: str = ""
    host: str = ""
    port: int = 0
    path: str = "/"  # decoded, dot-segments resolved, always starts with "/"
    query: str = ""
    docset: str = ""
    relpath: str = ""
    wrapper: str = ""  # archive | cache | translate | proxy | redirect | shortener
    inner: Canon | None = None  # the wrapped URL, when `wrapper` is set
    embedded: tuple[Canon, ...] = field(default_factory=tuple)  # URLs found in query values (open-redirector check)
    non_ascii_host: str = ""  # the original Unicode host, kept to explain a lookalike

    def text(self) -> str:
        if self.kind == "docset":
            return f"docset:{self.docset}/{self.relpath}"
        port = "" if self.port == (443 if self.scheme == "https" else 80) else f":{self.port}"
        return f"{self.scheme}://{self.host}{port}{self.path}" + (f"?{self.query}" if self.query else "")


def canonical_host(host: str) -> str:
    """Lowercase, strip a trailing dot, IDNA to punycode. Raises UrlRejected for IP literals and malformed names."""
    h = host.strip().lower()
    if h.endswith("."):
        h = h[:-1]  # one trailing dot is the DNS root; more than one is not a host
    if not h:
        raise UrlRejected("no_host", "empty host")
    try:
        ipaddress.ip_address(h.strip("[]"))
        is_ip = True
    except ValueError:
        is_ip = h.startswith("[") or h.startswith("0x") or h.replace(".", "").isdigit()
    if is_ip:
        raise UrlRejected(
            "ip_literal_host", f"{h} is an IP address or number-style host; policies match domain names only"
        )
    if not h.isascii():
        try:
            ascii_h = h.encode("idna").decode("ascii")
        except UnicodeError as exc:
            raise UrlRejected("bad_idna_host", str(exc)) from exc
        # Python's codec is IDNA 2003: it maps "straße" to "strasse", a DIFFERENT domain from the one a browser
        # (IDNA 2008) reaches. If the name does not survive a round trip, we cannot say which host is meant.
        if ascii_h.encode("ascii").decode("idna") != unicodedata.normalize("NFC", h):
            raise UrlRejected(
                "ambiguous_idna_host",
                f"{h!r} is mapped to a different name by IDNA 2003 ({ascii_h}); write the xn-- form of the host you mean",
            )
        h = ascii_h
    if any(not label or len(label) > 63 for label in h.split(".")):
        raise UrlRejected("malformed_host", h)
    if not re.fullmatch(r"[a-z0-9._-]+", h):
        raise UrlRejected("malformed_host", f"unexpected characters in host {h!r}")
    return h


def _norm_path(raw_path: str) -> str:
    # Decode %2e and look for encoded separators at any nesting level (%252e, %252f ...).
    path = raw_path
    for _ in range(3):
        if _ENCODED_SEP.search(path):
            raise UrlRejected("encoded_slash", "a percent-encoded slash or backslash in the path is ambiguous")
        nxt = _ENCODED_DOT.sub(".", path)
        nxt = re.sub(r"%25(?=2[eEfF]|5[cC])", "%", nxt)  # %252e -> %2e, then handled on the next round
        if nxt == path:
            break
        path = nxt
    if "\\" in path:
        raise UrlRejected("backslash", "backslashes are read as slashes by browsers; use forward slashes")
    decoded = _strict_unquote(path)
    if _invisible(decoded.replace(" ", "")):  # %20 is an ordinary space
        raise UrlRejected(
            "bad_characters",
            "a control, zero-width or bidi-override character (possibly percent-encoded, such as %00) in the path",
        )
    out: list[str] = []
    for seg in path.split("/")[1:] if path.startswith("/") else path.split("/"):
        if seg == "..":
            if out:
                out.pop()
        elif seg not in ("", "."):
            out.append(_strict_unquote(seg))
    trailing = path.endswith("/") or path.endswith("/.") or path.endswith("/..")
    return "/" + "/".join(out) + ("/" if trailing and out else "")


def canonicalize(url: str, *, allow_wrappers: bool = False, _depth: int = 0) -> Canon:
    """Canonical form of `url`. Raises UrlRejected. With allow_wrappers=False a wrapper URL is returned with
    `wrapper` and `inner` set so the caller can decide; nothing here approves or denies anything."""
    if not isinstance(url, str) or not url.strip():
        raise UrlRejected("empty_url")
    url = url.strip()
    if len(url) > MAX_URL:
        raise UrlRejected("url_too_long")
    if any(ord(c) < 33 or ord(c) == 127 for c in url) or _invisible(url):
        raise UrlRejected("bad_characters", "whitespace, control, zero-width or bidi-override characters in the URL")
    low = url.lower()
    if low.startswith("docset:"):
        rest = url[len("docset:") :]
        ds, _, rel = rest.partition("/")
        if not ds or not rel or "\\" in rel or _ENCODED_SEP.search(rel) or "%" in rel:
            raise UrlRejected("bad_docset_ref", "expected docset:<id>/<relative/path>")
        segs = rel.split("/")
        if any(p in ("", ".", "..") for p in segs):
            raise UrlRejected("bad_docset_ref", "no empty, '.' or '..' path segments")
        return Canon(kind="docset", docset=ds, relpath="/".join(segs))
    if "\\" in url:
        raise UrlRejected("backslash", "backslashes are read as slashes by browsers; use forward slashes")
    try:
        parts = urlsplit(url)
        port = parts.port
    except ValueError as exc:
        raise UrlRejected("malformed_url", str(exc)) from exc
    scheme = parts.scheme.lower()
    if not scheme:
        raise UrlRejected("no_scheme", "a URL must start with https://")
    if scheme not in ("http", "https"):
        raise UrlRejected("bad_scheme", f"{scheme}: URLs are not sources (only http, https and docset: are)")
    if parts.username is not None or parts.password is not None or "@" in parts.netloc:
        raise UrlRejected(
            "userinfo_in_url", "text before '@' is not the host; this form is used to impersonate a trusted site"
        )
    raw_host = parts.hostname or ""
    host = canonical_host(raw_host)
    non_ascii = raw_host.lower() if not raw_host.isascii() else ""
    if port == 0:
        raise UrlRejected("bad_port", "port 0 is not a web port")
    port = port or (443 if scheme == "https" else 80)
    path = _norm_path(parts.path or "/")
    query = parts.query
    wrapper = WRAPPER_HOSTS.get(host, "")
    inner = None
    if (
        wrapper in ("archive", "cache", "translate", "proxy")
        or (wrapper == "redirect" and parts.path in ("/url", "/amp"))
        or wrapper in ("shortener",)
    ):
        inner = _unwrap(host, parts.path, query, _depth)
    elif host.endswith(".translate.goog"):
        wrapper = "translate"
    elif host.startswith("cdn.ampproject.org") or host.endswith(".cdn.ampproject.org") or host == "cdn.ampproject.org":
        wrapper = "cache"
        inner = _unwrap(host, parts.path, query, _depth)
    embedded: list[Canon] = []
    for _k, v in parse_qsl(query, keep_blank_values=False):
        v = _peel(v.strip())
        if _URLISH.match(v) and _depth < 2:
            try:
                embedded.append(canonicalize("https:" + v if v.startswith("//") else v, _depth=_depth + 1))
            except UrlRejected:
                embedded.append(Canon(kind="web", scheme="https", host="unparseable.invalid"))
    return Canon(
        kind="web",
        scheme=scheme,
        host=host,
        port=port,
        path=path,
        query=query,
        wrapper=wrapper,
        inner=inner,
        embedded=tuple(embedded),
        non_ascii_host=non_ascii,
    )


def _peel(v: str) -> str:
    """Decode a query value up to three more times: a server behind a proxy may decode twice (%2568 -> %68 -> h)."""
    for _ in range(3):
        n = unquote(v).strip()
        if n == v:
            break
        v = n
    return v


def _unwrap(host: str, path: str, query: str, depth: int) -> Canon | None:
    if depth >= 2:
        return None
    for _k, v in parse_qsl(query):
        m = re.search(r"(?:^|:)((?:https?:)?//.+)$", v.strip(), re.I)  # also "cache:https://x" style values
        if m:
            try:
                return canonicalize(m.group(1), _depth=depth + 1)
            except UrlRejected:
                return None
    m = _WRAPPER_PATH.match(path)
    if m:
        cand = m.group(1)
        cand = re.sub(r"^(https?):/(?!/)", r"\1://", cand, flags=re.I)  # archive.org collapses '//' to '/'
        try:
            return canonicalize(cand, _depth=depth + 1)
        except UrlRejected:
            return None
    return None
