# Contributing to Agentborder Core

Thanks for your interest. A few ground rules keep the project healthy.

## Developer Certificate of Origin (DCO)

All contributions require a DCO sign-off. Add `-s` to your commits:

```bash
git commit -s -m "fix: ..."
```

This certifies you wrote the contribution (or have the right to submit it)
and that it may be distributed under the project license (Apache-2.0).
Pull requests without sign-off cannot be merged.

## Design principles (contributions must preserve these)

1. **Fail-open.** No code path may cause a customer request to fail because the gate failed.
2. **Monitor-first.** Default behavior must never block.
3. **Humans untouched.** Requests not classified as bots pass immediately and are not individually logged.
4. **Zero dependencies.** The core must run on Node 18+ built-ins only.
5. **No unverifiable claims.** Never label an identity "verified" without cryptographic verification.

## Scope

In scope: classification, policy evaluation, enforcement, local telemetry, report CLI.
Out of scope for this repo: the live catalog pipeline, signature verification service,
hosted console. Those are operated services.

## Bots catalog

`catalog.json` is a snapshot. Corrections (wrong pattern, wrong category, new major bot)
are welcome via PR with a link to the vendor's official crawler documentation.
