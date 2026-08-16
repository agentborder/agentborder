# agentborder

[![ci](https://github.com/agentborder/agentborder/actions/workflows/ci.yml/badge.svg)](https://github.com/agentborder/agentborder/actions/workflows/ci.yml)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/agentborder/agentborder/badge)](https://scorecard.dev/viewer/?uri=github.com/agentborder/agentborder)
[![npm](https://img.shields.io/npm/v/agentborder)](https://www.npmjs.com/package/agentborder)

See what AI bots and agents do on your site. Then control it, by action.

```bash
npx agentborder analyze ./access.log
```

One command reads the access log you already have and reports which AI crawlers,
search bots, and agents hit you, what they took, what that cost, and who ignored
your robots.txt. No signup. No install on your servers. The log never leaves your
machine, the analyzer makes zero network calls.

No log handy? Try the bundled demo:

```bash
npx agentborder analyze --sample
```

```
  AGENTBORDER ANALYZE  ·  bot & AI-agent traffic report
  period: 2026-08-04 → 2026-08-10  (7.0 days, 2,407 requests)

  TRAFFIC COMPOSITION
  Humans             ██████████░░░░░░░░░░░░░░  40.7%   980 req · 20.0 MB
  Bots & AI agents   ██████████████░░░░░░░░░░  59.3%  1,427 req · 26.2 MB

  TOP BOTS  (identity = self-declared User-Agent)
  bytespider   ai-crawler   475 req  6.5 MB  peak 90/min  ⚠ 475 robots.txt violations
  gptbot       ai-crawler   315 req  9.5 MB  ⚠ 58 robots.txt violations

  ROBOTS.TXT COMPLIANCE  (per RFC 9309)
  533 violations out of 1,427 bot requests checked (37.4%)

  AI EXPOSURE SCORE   64 / 100
```

## What the analyzer tells you

| question | how it answers |
|---|---|
| who is really visiting | 51 documented bots matched by User-Agent, grouped into ai-crawler / ai-search / ai-assistant / ai-agent / search-engine / seo-tool / scraper / unknown. Cross-checked against the community [ai.robots.txt](https://github.com/ai-robots-txt/ai.robots.txt) list. |
| who ignores robots.txt | pass `--robots ./robots.txt` and every bot request is checked against your rules per [RFC 9309](https://www.rfc-editor.org/rfc/rfc9309): group selection, longest-match, wildcards. Violations counted per bot. |
| what it costs | `--provider vercel-pro` (or `netlify-pro`, `cloudfront`, `generic`) converts bot bytes with the host's published unit price. The formula and source print next to the number. Estimates say they are estimates. |
| bursts and abuse | peak requests per minute per bot, 404 crawl waste, POST attempts by bots. |
| what changed | `--compare last.json` shows week-over-week deltas and new bots. |

Outputs: terminal summary, `--html report.html` (self-contained, dark mode, every
judgment traced to a source), `--json data.json`, `--card card.html` (a 1200x630
share image you can screenshot).

Supported formats: nginx/apache combined, JSON lines (Caddy and common shapes).
Streaming parser, about 390k lines/sec, malformed lines are counted and skipped,
never guessed.

## Then control it: the middleware

Same package. Three lines, zero dependencies, Node 18+.

```js
const { createAgentborder } = require('agentborder');
const config = require('./agentborder.config.json');   // the analyzer drafts this for you

app.use(createAgentborder(config));                     // Express
// or: http.createServer((req, res) => gate(req, res, () => yourApp(req, res)))
```

Right after install, nothing happens. That is deliberate. In monitor mode no
request is ever blocked, bot events just accumulate in a local file. After a week
you have measured numbers instead of guesses, and the config the analyzer drafted.

Rules are who × what, not just allow or deny:

```json
{ "category": "ai-search",    "action": "product.read", "effect": "allow" }
{ "category": "ai-search",    "action": "price.check",  "effect": "ratelimit", "limit": 60 }
{ "category": "ai-crawler",   "action": "*",            "effect": "block" }
{ "category": "ai-assistant", "action": "checkout",     "effect": "block" }
```

Enforcement starts at 1% of bot traffic and rolls back with one env var:

```bash
AGENTBORDER_MODE=enforce AGENTBORDER_ENFORCE_PERCENT=1   # start careful
AGENTBORDER_MODE=monitor                               # instant rollback, no redeploy
```

Design rules, non-negotiable:

- **fail open**: any error inside the gate lets the request through. Breaking your
  site is the one thing this tool is not allowed to do. Try it: break `index.js`
  on the demo, the site still serves 200.
- **humans untouched**: requests not classified as bots pass immediately and are
  not individually logged.
- **zero dependencies**: Node built-ins only.
- **no claim without proof**: a User-Agent is a claim. Nothing is labeled
  verified without cryptographic verification.

## Cryptographic agent identity (Web Bot Auth, RFC 9421)

The core ships a working verifier. Pass one in and signed requests are checked
with Ed25519: a valid signature classifies as `verified`, a bad one as `spoofed`.
Verification runs in about 0.13ms, only on requests that carry a signature, with
key directories cached and refreshed in the background. A cache miss classifies
as `signature-presented`, never blocked.

```js
const { createAgentborder, createVerifier, createDirectoryResolver } = require('agentborder');

const verifier = createVerifier({
  resolver: createDirectoryResolver({
    directories: [{ url: 'https://vendor.example/.well-known/http-message-signatures-directory',
                    agent: { vendor: 'vendor' } }],
  }),
});
app.use(createAgentborder({ ...config, verifier }));
```

## Try it locally in two minutes

```bash
git clone https://github.com/agentborder/agentborder.git && cd agentborder
npm test                     # 96 tests
node example/server.js       # demo shop with the gate (localhost:8787)
node example/simulate.js     # fire 200 synthetic bot requests at it
node analyze/cli.js --sample # the analyzer on bundled data
```

## What this project does not do

- It does not proxy your traffic. Nothing ever routes through our servers.
- It does not phone home. The analyzer is fully offline. The middleware sends
  nothing unless you explicitly configure the optional aggregated telemetry sink
  (counts only, no URLs, no IPs, about 500 bytes per 100k events).
- It does not estimate what it cannot see. Cost figures carry their formula and
  source. The bundled bot catalog is a snapshot with a version and a date.
- It is not DDoS protection. Volumetric attacks are a CDN's job. This runs inside
  your app, where it can see what edge networks cannot: your routes, your
  actions, and eventually your sessions.

## Data

`analyze/data/bots.json` is the bot catalog: 51 entries, each with vendor,
category, robots.txt token, documentation link where the vendor publishes one,
and a retrieval date. `pricing.json` carries hosting unit prices with sources.
Corrections welcome, every entry needs a source.

## License

Apache-2.0. See [LICENSE](./LICENSE) and [NOTICE](./NOTICE). The name
"agentborder" is trademark protected, forks should rename, see
[TRADEMARKS.md](./TRADEMARKS.md). Contributions need a DCO sign-off, see
[CONTRIBUTING.md](./CONTRIBUTING.md). The five design rules above are not up
for debate in PRs.
