"""Public-suffix awareness without a dependency or a network call.

A rule `host = "github.io", subdomains = true` approves every GitHub Pages site in the world; `co.uk` approves every
British company. Browsers solve this with the Public Suffix List (publicsuffix.org). This module is a deliberately small,
offline approximation, used only to warn or refuse when a policy is WRITTEN (never to decide a URL):

* `is_public_suffix(host)`: ICANN-style suffixes by pattern (`co.uk`, `com.au`, `ac.jp`: a generic label plus a two-letter
  country code) and a short list of private multi-tenant suffixes where unrelated people get a subdomain (`github.io`).
* `user_content_host(host)`: well-known hosts where anyone can publish under the same name (so a bare host rule is coarse).

It is not the full list; `explain` and `validate` say so. The list errs towards the platforms people actually put in policies.
"""

from __future__ import annotations

_GENERIC = {"co", "com", "org", "net", "ac", "gov", "edu", "or", "ne", "go", "mil", "nom", "sch", "ltd", "plc", "gv", "ed", "ad"}

# Private suffixes: the owner hands subdomains to unrelated customers. A subdomains=true rule on one of these is refused.
MULTI_TENANT = {
    "github.io", "githubusercontent.com", "gitlab.io", "blogspot.com", "blogspot.se", "wordpress.com", "herokuapp.com",
    "netlify.app", "vercel.app", "pages.dev", "workers.dev", "appspot.com", "web.app", "firebaseapp.com", "azurewebsites.net",
    "cloudfront.net", "s3.amazonaws.com", "amazonaws.com", "onrender.com", "fly.dev", "glitch.me", "repl.co", "replit.app",
    "notion.site", "substack.com", "wixsite.com", "weebly.com", "squarespace.com", "myshopify.com", "bitbucket.io",
    "surge.sh", "ngrok.io", "ngrok-free.app", "trycloudflare.com", "cloudfunctions.net", "run.app", "itch.io", "neocities.org",
    "000webhostapp.com", "tumblr.com", "livejournal.com", "typepad.com", "hashnode.dev", "dev.to", "medium.com",
}

# One host, many authors: allowing the bare host approves every user's content on it.
USER_CONTENT = {
    "github.com", "gist.github.com", "raw.githubusercontent.com", "gitlab.com", "bitbucket.org", "medium.com", "reddit.com",
    "old.reddit.com", "youtube.com", "youtu.be", "x.com", "twitter.com", "facebook.com", "linkedin.com", "pastebin.com",
    "drive.google.com", "docs.google.com", "sites.google.com", "dropbox.com", "quora.com", "stackoverflow.com",
    "stackexchange.com", "wikipedia.org", "en.wikipedia.org", "wikia.com", "fandom.com", "scribd.com", "slideshare.net",
    "archive.org", "huggingface.co", "kaggle.com", "npmjs.com", "pypi.org", "hackmd.io", "notion.so", "substack.com",
}


def is_multi_tenant(host: str) -> bool:
    return host in MULTI_TENANT


def is_public_suffix(host: str) -> bool:
    """True for a registry-controlled suffix (heuristic) or a known multi-tenant suffix."""
    if host in MULTI_TENANT:
        return True
    parts = host.split(".")
    return len(parts) == 2 and len(parts[1]) == 2 and parts[0] in _GENERIC


def user_content_host(host: str) -> bool:
    return host in USER_CONTENT
