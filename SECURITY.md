# Security Policy

## Reporting a Vulnerability

Found a vulnerability in the BoarNet agent? Please report it privately.

- **Email**: security@boarnet.io
- **GitHub**: open a [private security advisory](https://github.com/Bino97/boarnet/security/advisories/new)

Please **do not** open a public issue for security reports.

## What to Include

- A clear description of the vulnerability
- Steps to reproduce, or a proof-of-concept
- Impact: who's affected, what the worst-case is
- (Optional) suggested mitigations

## Response Targets

- **Acknowledgement**: within 48 hours
- **Initial triage**: within 5 business days
- **Patched release**: priority-dependent, but agent-side issues are
  treated as P0 — typically a same-week patch release with a coordinated
  disclosure once operators have had time to update.

## Scope

In scope:
- The Go agent code in this repository
- Release artifacts (binaries, install.sh, SHA256SUMS)
- The wire format / envelope spec

Out of scope (handled by BoarNet platform team separately):
- The www.boarnet.io ingest endpoint or dashboard
- Authentication / API key issues unrelated to agent code

## Public Disclosure

We coordinate disclosure timing with reporters. Default window is 90 days
from the initial report or until a patched release is broadly deployed,
whichever is sooner.
