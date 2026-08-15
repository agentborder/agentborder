/**
 * agentborder analyze — 공유 카드 (⑤-2)
 * 1200×630 (OG 이미지 규격) 스크린샷 최적화 HTML. 자체 완결, 전부 이스케이프.
 * 목적: "내 숫자"를 공유하게 만드는 바이럴 장치 — 카드가 곧 유통 채널.
 */
'use strict';

const esc = s => String(s ?? '').replace(/[&<>"']/g,
  ch => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[ch]));
const fmtN = n => Number(n || 0).toLocaleString('en-US');

function renderCard(res, opts = {}) {
  const { site = null, cost = null } = opts;
  const T = res.total.requests || 1;
  const botPct = ((res.botTotals.requests / T) * 100).toFixed(1);
  const top = res.bots[0];
  const vio = res.compliance.hasRobots
    ? `${((res.compliance.violations / Math.max(1, res.compliance.checked)) * 100).toFixed(0)}% of bot requests ignored robots.txt`
    : null;
  const period = res.timeRange.days ? `${res.timeRange.days.toFixed(0)} days` : `${fmtN(T)} requests`;

  return `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><title>AI bot traffic card</title>
<style>
*{box-sizing:border-box;margin:0}
body{width:1200px;height:630px;overflow:hidden;background:#0d0d0d;color:#fff;
 font-family:system-ui,-apple-system,"Segoe UI",sans-serif;display:flex;align-items:center;justify-content:center}
.card{width:1200px;height:630px;padding:70px 80px;display:flex;flex-direction:column;justify-content:space-between;
 background:linear-gradient(135deg,#0d0d0d 0%,#1a1a19 100%)}
.eyebrow{font-size:22px;letter-spacing:.14em;text-transform:uppercase;color:#898781}
.big{font-size:120px;font-weight:750;line-height:1.05;letter-spacing:-.01em}
.big .accent{color:#d95926}
.sub{font-size:30px;color:#c3c2b7;margin-top:10px}
.facts{display:flex;gap:56px;margin-top:8px}
.fact .v{font-size:40px;font-weight:650}
.fact .l{font-size:19px;color:#898781;margin-top:2px}
.viol{color:#e66767}
.foot{display:flex;justify-content:space-between;align-items:baseline;border-top:1px solid rgba(255,255,255,.12);padding-top:26px}
.foot .cmd{font-family:ui-monospace,Menlo,monospace;font-size:24px;color:#3987e5}
.foot .brand{font-size:20px;color:#898781}
</style></head>
<body><div class="card">
  <div>
    <div class="eyebrow">${esc(site || 'my site')} · last ${esc(period)} · measured from access logs</div>
    <div class="big"><span class="accent">${esc(botPct)}%</span> of my traffic<br>is AI bots &amp; crawlers</div>
    <div class="sub">${top ? `Top: ${esc(top.id)}, ${fmtN(top.requests)} requests` : ''}${vio ? ` · <span class="viol">${esc(vio)}</span>` : ''}</div>
  </div>
  <div class="facts">
    <div class="fact"><div class="v">${fmtN(res.botTotals.requests)}</div><div class="l">bot requests</div></div>
    <div class="fact"><div class="v">${(res.botTotals.bytes / (1024 ** 2)).toFixed(0)} MB</div><div class="l">bot bandwidth</div></div>
    ${cost ? `<div class="fact"><div class="v">~$${esc(cost.usd)}</div><div class="l">est. cost (${esc(cost.provider)})</div></div>` : ''}
    <div class="fact"><div class="v">${res.score.value}/${res.score.max}</div><div class="l">AI exposure score</div></div>
  </div>
  <div class="foot">
    <span class="cmd">npx agentborder analyze ./access.log</span>
    <span class="brand">agentborder · free · open source · offline</span>
  </div>
</div></body></html>`;
}

module.exports = { renderCard };
