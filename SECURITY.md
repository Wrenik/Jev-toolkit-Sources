# Security policy

This is an experimental learning project about restricting where an answer may get its sources. It is **not a security product**: read "Limits" in [docs/SOURCE_RESTRICTION.md](docs/SOURCE_RESTRICTION.md) before relying on it (it cannot prove a model did not use other knowledge; the hook only sees tool calls).

## Reporting a problem

* A **URL the policy wrongly allows** (a lookalike host, an encoding trick, a redirect or wrapper that gets past the rules) is welcome as a normal issue, with an inert example (`.test`/`.invalid` hosts, no real secrets). It is exactly the feedback this project wants.
* A vulnerability in the code itself that you would rather not describe publicly: use GitHub's **private vulnerability reporting** (the repository's Security tab). If that button is missing, open an issue that says only that you have a security report, without details.
* Bugs in the shared fetcher or checker belong to [Jev-toolkit-FactCheck](https://github.com/Wrenik/Jev-toolkit-FactCheck); redaction and the judge layer to [Jev-toolkit-usage](https://github.com/Wrenik/Jev-toolkit-usage).

## Scope

In scope: the Python package in `src/` and the claims in the documentation. Out of scope: TypeSafe's service, Claude Code, and attackers who already control your machine or your policy file (policy files are data you trust).

## Secrets

Never put your `TYPESAFE_API_KEY` in an issue, a log excerpt or a policy file. `.env` and `var/` are git-ignored; by default data is kept outside any repository in `~/.jev-toolkit` (`JEV_HOME`).
