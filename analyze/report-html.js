/**
 * agentborder analyze — HTML 전체 리포트 (④)
 * 자체 완결 1파일: 외부 스크립트/폰트/CSS 없음. 로그 유래 문자열은 전부 이스케이프(XSS).
 * 시각 규격: dataviz 레퍼런스 팔레트(라이트/다크), 카테고리 고정 순서, 상태색은 아이콘+라벨 동반.
 */
'use strict';

const esc = s => String(s ?? '').replace(/[&<>"']/g,
  ch => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[ch]));

const fmtN = n => Number(n || 0).toLocaleString('en-US');
function fmtBytes(n) {
  if (n >= 1024 ** 3) return (n / 1024 ** 3).toFixed(2) + ' GB';
  if (n >= 1024 ** 2) return (n / 1024 ** 2).toFixed(1) + ' MB';
  if (n >= 1024) return (n / 1024).toFixed(1) + ' KB';
  return (n || 0) + ' B';
}
const pct = (n, d) => d ? ((n / d) * 100).toFixed(1) + '%' : '0%';

/** 간단 정책 초안 — "시작점"임을 명시, monitor 모드 고정 */
function draftConfig(res) {
  const rules = [];
  if (res.categories['ai-crawler']) rules.push({ category: 'ai-crawler', action: '*', effect: 'block' });
  if (res.categories['ai-search']) rules.push({ category: 'ai-search', action: '*', effect: 'ratelimit', limit: 60 });
  if (res.categories['ai-assistant']) rules.push({ category: 'ai-assistant', action: '*', effect: 'allow' });
  if (res.categories['search-engine']) rules.push({ category: 'search-engine', action: '*', effect: 'allow' });
  if (res.categories['unknown-bot']) rules.push({ category: 'unknown-bot', action: '*', effect: 'ratelimit', limit: 10 });
  return { $draft: 'generated from your log. review before enforcing. monitor mode blocks nothing', mode: 'monitor', rules };
}

function renderHtml(res, opts = {}) {
  const { cost = null, datasetVersion = '?', pricingVersion = '?', inputStats = null,
          warnings = [], botDocs = [] } = opts;
  const T = res.total.requests;
  const B = res.botTotals.requests;
  const maxBotReq = Math.max(1, ...res.bots.map(b => b.requests));
  const s = res.score;
  const sev = s.value >= 60 ? ['critical', '⛔', 'High exposure'] :
              s.value >= 30 ? ['warning', '⚠️', 'Moderate exposure'] : ['good', '✅', 'Low exposure'];

  const compRows = [
    ['Humans', res.human.requests, res.human.bytes, 'var(--series-1)'],
    ['Bots & AI agents', B, res.botTotals.bytes, 'var(--series-2)'],
    ['No user-agent', res.noUa.requests, res.noUa.bytes, 'var(--series-3)'],
  ];

  const catOrder = Object.entries(res.categories).sort((a, b) => b[1].requests - a[1].requests);
  const maxCatReq = Math.max(1, ...catOrder.map(([, c]) => c.requests));

  return `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Agentborder AI and Bot Traffic Report</title>
<style>
.viz-root{color-scheme:light;
 --surface-1:#fcfcfb;--page:#f9f9f7;--ink-1:#0b0b0b;--ink-2:#52514e;--muted:#898781;
 --grid:#e1e0d9;--border:rgba(11,11,11,.10);
 --series-1:#2a78d6;--series-2:#eb6834;--series-3:#1baf7a;
 --seq:#256abf;--good:#0ca30c;--warning:#fab219;--serious:#ec835a;--critical:#d03b3b}
@media (prefers-color-scheme:dark){:root:where(:not([data-theme="light"])) .viz-root{color-scheme:dark;
 --surface-1:#1a1a19;--page:#0d0d0d;--ink-1:#ffffff;--ink-2:#c3c2b7;--muted:#898781;
 --grid:#2c2c2a;--border:rgba(255,255,255,.10);
 --series-1:#3987e5;--series-2:#d95926;--series-3:#199e70;--seq:#3987e5}}
*{box-sizing:border-box;margin:0}
body{font:15px/1.55 system-ui,-apple-system,"Segoe UI",sans-serif;background:var(--page);color:var(--ink-1);padding:0}
.wrap{max-width:900px;margin:0 auto;padding:32px 20px 64px}
header h1{font-size:20px;letter-spacing:.02em}
header .sub{color:var(--ink-2);font-size:13px;margin-top:4px}
.card{background:var(--surface-1);border:1px solid var(--border);border-radius:10px;padding:20px;margin-top:20px}
h2{font-size:12px;text-transform:uppercase;letter-spacing:.08em;color:var(--muted);margin-bottom:14px}
.kpis{display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:12px}
.kpi{background:var(--surface-1);border:1px solid var(--border);border-radius:10px;padding:16px}
.kpi .v{font-size:26px;font-weight:650}
.kpi .l{font-size:12px;color:var(--ink-2);margin-top:2px}
.kpi .note{font-size:11px;color:var(--muted);margin-top:4px}
.stack{display:flex;height:22px;border-radius:5px;overflow:hidden;background:var(--grid)}
.stack>div{height:100%;border-right:2px solid var(--surface-1)}
.stack>div:last-child{border-right:0}
.legend{display:flex;gap:18px;flex-wrap:wrap;margin-top:10px;font-size:13px;color:var(--ink-2)}
.legend .sw{display:inline-block;width:10px;height:10px;border-radius:3px;margin-right:6px;vertical-align:-1px}
table{width:100%;border-collapse:collapse;font-size:13.5px}
th{color:var(--muted);font-weight:500;text-align:left;padding:6px 8px;border-bottom:1px solid var(--grid);font-size:11.5px;text-transform:uppercase;letter-spacing:.05em}
td{padding:8px;border-bottom:1px solid var(--grid);vertical-align:middle;font-variant-numeric:tabular-nums}
.meter{height:8px;background:var(--grid);border-radius:4px;min-width:70px}
.meter>i{display:block;height:100%;background:var(--seq);border-radius:4px}
.chip{display:inline-block;font-size:11px;padding:2px 8px;border-radius:99px;border:1px solid var(--border);color:var(--ink-2)}
.viol{color:var(--critical);font-weight:600}
.status{display:inline-flex;align-items:center;gap:6px;font-weight:600}
.hero{display:flex;align-items:baseline;gap:14px}
.hero .num{font-size:44px;font-weight:700}
.hero .max{color:var(--muted);font-size:18px}
.formula{font-size:12px;color:var(--ink-2);margin-top:8px}
pre{background:var(--page);border:1px solid var(--grid);border-radius:8px;padding:14px;font-size:12.5px;overflow:auto;line-height:1.5}
.ev p,.ev li{font-size:13px;color:var(--ink-2)}
.ev ul{padding-left:18px;margin-top:6px}
.warn{color:var(--serious);font-size:13px;margin-top:8px}
a{color:var(--seq)}
.cta{margin-top:28px;text-align:center}
.cta code{background:var(--surface-1);border:1px solid var(--border);border-radius:8px;padding:10px 16px;font-size:14px;display:inline-block}
.cta .sub{font-size:12px;color:var(--muted);margin-top:8px}
details{margin-top:8px}summary{cursor:pointer;font-size:13px;color:var(--ink-2)}
footer{margin-top:26px;font-size:11.5px;color:var(--muted);text-align:center}
</style></head>
<body class="viz-root"><div class="wrap">

<header>
  <h1>AGENTBORDER ANALYZE · AI &amp; Bot Traffic Report</h1>
  <div class="sub">${res.timeRange.from
    ? `${esc(res.timeRange.from.toISOString().slice(0, 10))} → ${esc(res.timeRange.to.toISOString().slice(0, 10))} · ${res.timeRange.days.toFixed(1)} days · ${fmtN(T)} requests`
    : `${fmtN(T)} requests (no timestamps in log)`} · dataset v${esc(datasetVersion)}</div>
</header>

<div class="kpis" style="margin-top:20px">
  <div class="kpi"><div class="v">${pct(B, T)}</div><div class="l">of traffic is bots &amp; AI agents</div><div class="note">${fmtN(B)} of ${fmtN(T)} requests</div></div>
  <div class="kpi"><div class="v">${fmtBytes(res.botTotals.bytes)}</div><div class="l">bandwidth consumed by bots</div><div class="note">humans: ${fmtBytes(res.human.bytes)}</div></div>
  <div class="kpi"><div class="v">${res.compliance.hasRobots ? fmtN(res.compliance.violations) : '-'}</div><div class="l">robots.txt violations</div><div class="note">${res.compliance.hasRobots ? `of ${fmtN(res.compliance.checked)} checked · RFC 9309` : 'run with --robots to check'}</div></div>
  <div class="kpi"><div class="v">${cost ? '~$' + cost.usd : '-'}</div><div class="l">est. bot bandwidth cost</div><div class="note">${cost ? esc(cost.formula) + ' · ' + esc(cost.label) : 'run with --provider for estimate'}</div></div>
</div>

<div class="card">
  <h2>AI Exposure Score</h2>
  <div class="hero"><span class="num">${s.value}</span><span class="max">/ ${s.max}</span>
    <span class="status" style="color:var(--${sev[0]})">${sev[1]} ${sev[2]}</span></div>
  <div class="formula">= bot share ${s.parts.botShare} (max 40) + ai-crawler ${s.parts.aiCrawler} (max 20) + robots ${s.parts.robots ?? 'N/A'} (max 20) + unknown ${s.parts.unknown} (max 10) + bot-writes ${s.parts.botWrites} (max 10)${s.max === 80 ? ' (robots.txt not provided, scored out of 80)' : ''}</div>
</div>

<div class="card">
  <h2>Traffic Composition</h2>
  <div class="stack">
    ${compRows.map(([l, n, , c]) => n > 0 ? `<div style="width:${(n / (T || 1)) * 100}%;background:${c}" title="${esc(l)}: ${fmtN(n)}"></div>` : '').join('')}
  </div>
  <div class="legend">
    ${compRows.map(([l, n, bytes, c]) => `<span><span class="sw" style="background:${c}"></span>${esc(l)}: ${pct(n, T)} (${fmtN(n)} req · ${fmtBytes(bytes)})</span>`).join('')}
  </div>
</div>

<div class="card">
  <h2>Bots &amp; agents: full list <span style="text-transform:none;letter-spacing:0">(identity = self-declared User-Agent, not cryptographically verified)</span></h2>
  <table>
    <thead><tr><th>Bot</th><th>Category</th><th style="width:26%">Requests</th><th>Bytes</th><th>Peak/min</th><th>404s</th><th>Writes</th><th>Violations</th></tr></thead>
    <tbody>
    ${res.bots.map(b => `<tr>
      <td><strong>${esc(b.id)}</strong>${b.vendor ? ` <span class="chip">${esc(b.vendor)}</span>` : ''}</td>
      <td><span class="chip">${esc(b.category)}</span></td>
      <td><div class="meter" title="${fmtN(b.requests)} requests"><i style="width:${(b.requests / maxBotReq) * 100}%"></i></div>
          <span style="font-size:12px;color:var(--ink-2)">${fmtN(b.requests)} · ${pct(b.requests, T)} of total</span></td>
      <td>${fmtBytes(b.bytes)}</td>
      <td>${b.peakRpm || '-'}</td>
      <td>${b.s404 || '-'}</td>
      <td>${b.post || '-'}</td>
      <td>${b.violations ? `<span class="viol">⚠ ${fmtN(b.violations)}</span>` : (res.compliance.hasRobots ? '0' : '-')}</td>
    </tr>`).join('')}
    </tbody>
  </table>
</div>

<div class="card">
  <h2>By Category</h2>
  <table><thead><tr><th>Category</th><th style="width:34%">Requests</th><th>Bytes</th><th>Bots</th><th>Violations</th></tr></thead><tbody>
  ${catOrder.map(([name, c]) => `<tr>
    <td><span class="chip">${esc(name)}</span></td>
    <td><div class="meter"><i style="width:${(c.requests / maxCatReq) * 100}%"></i></div>
        <span style="font-size:12px;color:var(--ink-2)">${fmtN(c.requests)} · ${pct(c.requests, T)}</span></td>
    <td>${fmtBytes(c.bytes)}</td><td>${c.bots}</td>
    <td>${c.violations ? `<span class="viol">${fmtN(c.violations)}</span>` : '-'}</td></tr>`).join('')}
  </tbody></table>
</div>

${res.unknownUaTop.length ? `<div class="card">
  <h2>Unknown automation: top user-agents</h2>
  <table><thead><tr><th>Requests</th><th>User-Agent (as claimed)</th></tr></thead><tbody>
  ${res.unknownUaTop.map(([ua, n]) => `<tr><td>${fmtN(n)}</td><td style="word-break:break-all">${esc(ua)}</td></tr>`).join('')}
  </tbody></table>
</div>` : ''}

<div class="card">
  <h2>Where bots go: top paths per bot</h2>
  ${res.bots.slice(0, 8).map(b => `<details><summary><strong>${esc(b.id)}</strong> · top ${b.topPaths.length} paths</summary>
    <table><tbody>${b.topPaths.map(([p, n]) => `<tr><td style="width:90px">${fmtN(n)}</td><td style="word-break:break-all">${esc(p)}</td></tr>`).join('')}</tbody></table>
  </details>`).join('')}
</div>

<div class="card">
  <h2>Draft policy (a starting point, not a recommendation to enforce)</h2>
  <p style="font-size:13px;color:var(--ink-2);margin-bottom:10px">Generated from the categories seen in <em>your</em> log. Review each line. In <code>monitor</code> mode nothing is blocked; it only records what <em>would</em> happen.</p>
  <pre>${esc(JSON.stringify(draftConfig(res), null, 2))}</pre>
</div>

<div class="card ev">
  <h2>Evidence &amp; Methodology: how every number was produced</h2>
  <ul>
    <li><strong>Bot identity</strong>: User-Agent string matching against dataset v${esc(datasetVersion)} (${botDocs.length} documented bots; cross-checked with the community-maintained <a href="https://github.com/ai-robots-txt/ai.robots.txt">ai.robots.txt</a> list). A User-Agent is a claim, so this report never labels identity as "verified" without cryptographic proof.</li>
    <li><strong>robots.txt evaluation</strong>: per <a href="https://www.rfc-editor.org/rfc/rfc9309">RFC 9309</a> (group selection by longest agent match, longest-path rule precedence, allow wins ties, <code>*</code>/<code>$</code> wildcards). Limitation: percent-encoding normalization not applied in v1.</li>
    <li><strong>Cost estimate</strong>: ${cost ? `${esc(cost.formula)}, unit price from <a href="${esc(cost.source || '#')}">${esc(cost.label)}</a> (pricing dataset v${esc(pricingVersion)}). Assumes logged response bytes ≈ billed transfer; actual bills differ by caching, headers, and plan.` : 'not computed (no --provider given).'}</li>
    <li><strong>Exposure Score</strong>: published formula: bot share ×0.4 (cap 40) + ai-crawler share ×0.5 (cap 20) + violation rate ×0.2 (cap 20) + unknown share ×0.5 (cap 10) + bot write-attempts ×1.0 (cap 10).</li>
    ${inputStats ? `<li><strong>Input</strong>: ${fmtN(inputStats.parsed)} lines parsed, ${fmtN(inputStats.malformed)} unparseable (${esc(inputStats.format || '?')} format)${inputStats.malformed ? ' (unparseable lines are excluded, not guessed)' : ''}.</li>` : ''}
    <li><strong>What this tool does not do</strong>: no network calls (fully offline), no log upload, no IP geolocation, no identity verification without signatures.</li>
  </ul>
  ${warnings.map(w => `<p class="warn">⚠ ${esc(w)}</p>`).join('')}
</div>

<div class="cta">
  <code>npm install agentborder</code>
  <div class="sub">Watch it live, per request, with 3 lines of middleware. Monitor mode observes everything and blocks nothing until you say so.</div>
</div>

<footer>agentborder analyze · report generated ${esc(new Date().toISOString().slice(0, 10))} · Apache-2.0 · all data stayed on your machine</footer>
</div></body></html>`;
}

module.exports = { renderHtml, draftConfig };
