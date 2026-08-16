# Security policy

## Supported versions

The latest published minor version receives security fixes. This project is
pre-1.0, so older minors are not backported.

## Reporting a vulnerability

Report privately through GitHub Security Advisories:
https://github.com/agentborder/agentborder/security/advisories/new

Please do not open a public issue for a vulnerability.

Expect a first response within 3 working days. If a report is confirmed, a fix
and a published advisory follow, and you are credited unless you ask otherwise.

## What counts as a vulnerability here

This project sits in the request path of other people's applications, so the
severity model is shaped by that.

Highest severity, treat as urgent:

- Anything that makes the gate fail closed. The middleware is required to let a
  request through when it errors. A crash, an unhandled rejection, or a hang
  that blocks or breaks a request is the most serious class of bug in this
  codebase, more serious than a missed bot.
- A signature verification bypass. If a forged or altered Web Bot Auth signature
  can be made to verify, that breaks the one claim this project makes with
  cryptography behind it.
- Remote code execution or path traversal reachable from log contents, a
  User-Agent string, a robots.txt file, or a config file.
- Injection into generated reports. The HTML report escapes every value taken
  from a log. An escape that can be broken out of is a real finding, because
  reports get shared.

Also in scope:

- Denial of service in the parser or the analyzer from crafted input, for
  example a line that causes catastrophic backtracking.
- Leaking log contents anywhere off the machine. The analyzer makes no network
  calls by design, and any path that breaks that is a bug.

Not vulnerabilities:

- A bot that evades detection by changing its User-Agent. A User-Agent is a
  claim, not an identity, and the documentation says so. Cryptographic
  verification is the separate mechanism for that problem.
- Volumetric attacks. This is not DDoS protection.
- An out of date entry in the bundled bot catalog. That is a data correction,
  and a normal issue or pull request is the right place for it.

## Supply chain

Releases are published from GitHub Actions using npm trusted publishing, which
records a provenance attestation linking the published tarball to this
repository and to the workflow run that built it. Verify a release with:

    npm audit signatures

The package has zero runtime dependencies, so there is no transitive dependency
surface to audit.
