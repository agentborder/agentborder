/**
 * agentborder public exposure scanner (Cloudflare Worker / edge function).
 *
 * Reads ONLY public surfaces of the target site, the same ones any agent can
 * reach: robots.txt, sitemap.xml, security.txt, and the homepage HTML. It never
 * authenticates, never submits a form, never mutates anything, and caps how much
 * it fetches. It reports what is publicly discoverable, and says plainly what a
 * public scan cannot know. No number here is invented; every value is derived
 * from a fetched surface.
 *
 * Storage: each successful scan is recorded to a D1 database (binding `DB`) so
 * the operator can later publish AGGREGATE, ANONYMIZED research. Individual
 * sites are never exposed by the public endpoint and must never be named in any
 * published report (see /admin note). Storage is best-effort: a storage failure
 * never affects the scan response.
 *
 * Deploy: `wrangler deploy`. Then set SCAN_API in docs/index.html to this URL.
 */
'use strict';

const UA = 'agentborder-scanner/1.0 (+https://agentborder.com; public exposure scan)';
const TIMEOUT_MS = 6000;
const MAX_HTML_BYTES = 600 * 1024;

const CORS = {
  'access-control-allow-origin': '*',
  'access-control-allow-methods': 'GET, OPTIONS',
  'access-control-allow-headers': 'content-type',
};

export default {
  async fetch(request, env, ctx) {
    if (request.method === 'OPTIONS') return new Response(null, { headers: CORS });
    const u = new URL(request.url);

    // Operator-only aggregate view. Gated by a shared secret (env.ADMIN_KEY).
    if (u.pathname === '/admin') return admin(u, env);

    const target = u.searchParams.get('url');
    const origin = normalizeOrigin(target);
    if (!origin) return json({ error: 'bad url' }, 400);
    try {
      const result = await scan(origin);
      // Record for aggregate research, but only a meaningful scan, and never
      // let a storage error break the user's result. Runs after the response.
      if (env && env.DB && result.signals && result.signals.homepageReadable) {
        const store = record(env.DB, result).catch(() => {});
        if (ctx && ctx.waitUntil) ctx.waitUntil(store);
      }
      return json(result);
    } catch (e) {
      return json({ error: 'scan failed' }, 502);
    }
  },
};

function json(obj, status) {
  return new Response(JSON.stringify(obj), {
    status: status || 200,
    headers: { 'content-type': 'application/json', ...CORS },
  });
}

function normalizeOrigin(v) {
  if (!v) return null;
  v = v.trim();
  if (!/^https?:\/\//i.test(v)) v = 'https://' + v;
  let url;
  try { url = new URL(v); } catch { return null; }
  if (url.protocol !== 'https:' && url.protocol !== 'http:') return null;
  const host = url.hostname;
  // Never scan private or loopback hosts.
  if (/^(localhost|127\.|10\.|192\.168\.|169\.254\.|::1)/i.test(host)) return null;
  if (!host.includes('.')) return null;
  return url.protocol + '//' + host + (url.port ? ':' + url.port : '');
}

async function get(url, asText) {
  const ctrl = new AbortController();
  const t = setTimeout(() => ctrl.abort(), TIMEOUT_MS);
  try {
    const res = await fetch(url, {
      method: 'GET',
      redirect: 'follow',
      signal: ctrl.signal,
      headers: { 'user-agent': UA, 'accept': asText ? 'text/html,text/plain,*/*' : '*/*' },
    });
    clearTimeout(t);
    if (!res.ok) return { ok: false, status: res.status, body: '' };
    let body = '';
    if (asText) {
      const reader = res.body && res.body.getReader ? res.body.getReader() : null;
      if (reader) {
        let received = 0; const chunks = []; const dec = new TextDecoder();
        while (received < MAX_HTML_BYTES) {
          const { done, value } = await reader.read();
          if (done) break;
          received += value.length; chunks.push(dec.decode(value, { stream: true }));
        }
        body = chunks.join('');
        try { reader.cancel(); } catch {}
      } else {
        body = await res.text();
      }
    }
    return { ok: true, status: res.status, body };
  } catch {
    clearTimeout(t);
    return { ok: false, status: 0, body: '' };
  }
}

async function scan(origin) {
  const host = origin.replace(/^https?:\/\//, '');
  // Fetch public surfaces, in parallel, all read-only GET.
  const [robotsR, sitemapR, secR, homeR] = await Promise.all([
    get(origin + '/robots.txt', true),
    get(origin + '/sitemap.xml', true),
    get(origin + '/.well-known/security.txt', true),
    get(origin + '/', true),
  ]);

  const disallow = robotsR.ok ? parseDisallow(robotsR.body) : [];
  const sitemapPaths = sitemapR.ok ? parseSitemap(sitemapR.body) : [];
  const html = homeR.ok ? homeR.body : '';

  const surfaces = classify(html, sitemapPaths, origin);

  const evidence = {
    discoverable: surfaces.discoverable,
    interactive: surfaces.interactive,
    actions: surfaces.actions,
    transaction: surfaces.transaction,
  };

  const score = exposureScore(evidence, disallow, robotsR.ok, !!secR.ok);

  return {
    host,
    scannedAt: new Date().toISOString(),
    score,
    evidence,
    disallow,
    signals: {
      robotsFound: robotsR.ok,
      sitemapFound: sitemapR.ok,
      securityTxtFound: !!secR.ok,
      homepageReadable: homeR.ok,
    },
  };
}

// robots.txt: collect Disallow paths (any user-agent group). De-duplicated.
function parseDisallow(text) {
  const out = new Set();
  const lines = text.split(/\r?\n/);
  for (const raw of lines) {
    const line = raw.split('#')[0].trim();
    const m = /^disallow:\s*(\S.*)$/i.exec(line);
    if (m) {
      const path = m[1].trim();
      if (path && path !== '/') out.add(path.slice(0, 60));
    }
  }
  return [...out].slice(0, 12);
}

function parseSitemap(xml) {
  const paths = new Set();
  const re = /<loc>\s*([^<\s]+)\s*<\/loc>/gi;
  let m; let n = 0;
  while ((m = re.exec(xml)) && n < 300) {
    try { paths.add(new URL(m[1]).pathname); n++; } catch {}
  }
  return [...paths];
}

// Classify public surfaces from homepage HTML + sitemap paths.
// Counts are observations (links, forms) or clearly-labeled inferences (action/txn).
function classify(html, sitemapPaths, origin) {
  const lower = html.toLowerCase();

  // discoverable: internal links + sitemap paths (unique)
  const linkPaths = new Set(sitemapPaths);
  const hrefRe = /href\s*=\s*["']([^"']+)["']/gi;
  let m;
  while ((m = hrefRe.exec(html))) {
    let href = m[1];
    if (href.startsWith('#') || href.startsWith('mailto:') || href.startsWith('tel:')) continue;
    try {
      const abs = new URL(href, origin);
      if (abs.origin === origin) linkPaths.add(abs.pathname);
    } catch {}
  }
  const discoverable = Math.min(linkPaths.size, 999);

  // interactive: forms + search + login affordances
  const forms = (html.match(/<form\b/gi) || []).length;
  const inputs = (html.match(/<input\b/gi) || []).length;
  let interactive = forms;
  if (/type\s*=\s*["']?search/i.test(html) || /name\s*=\s*["']?q["']?/i.test(html)) interactive += 1;
  if (inputs > 0 && forms === 0) interactive += 1;

  // action surfaces (INFERRED): non-GET forms, login/subscribe/add-to-cart affordances, write-ish API links
  let actions = (html.match(/<form[^>]+method\s*=\s*["']?post/gi) || []).length;
  if (/(add\s*to\s*cart|add-to-cart|addtocart)/i.test(lower)) actions += 1;
  if (/(sign\s*in|log\s*in|login|sign\s*up|register)/i.test(lower)) actions += 1;
  if (/(subscribe|newsletter)/i.test(lower)) actions += 1;

  // transaction paths (INFERRED): checkout / cart / payment / order paths seen publicly
  const txnRe = /(checkout|\/cart|\/basket|\/payment|\/order|\/billing)/i;
  let transaction = 0;
  const seen = new Set();
  [...linkPaths].forEach((p) => { if (txnRe.test(p)) { const k = p.split('/')[1] || p; if (!seen.has(k)) { seen.add(k); transaction += 1; } } });
  if (transaction === 0 && txnRe.test(lower)) transaction = 1;

  return {
    discoverable,
    interactive: Math.min(interactive, 99),
    actions: Math.min(actions, 99),
    transaction: Math.min(transaction, 20),
  };
}

/**
 * Published exposure formula (0-100). Higher = more publicly reachable surface
 * for an autonomous agent. Every term is derived from a fetched surface.
 *   discoverable breadth  -> up to 25
 *   interactive surfaces  -> up to 25
 *   inferred action surfaces -> up to 30
 *   transaction paths     -> up to 20
 * A published robots.txt with real Disallow rules slightly lowers the score
 * (the site at least signals intent); a missing robots.txt raises the floor.
 */
function exposureScore(ev, disallow, robotsFound, securityTxtFound) {
  let s = 0;
  s += Math.min(25, Math.round((ev.discoverable / 60) * 25));
  s += Math.min(25, ev.interactive * 6);
  s += Math.min(30, ev.actions * 8);
  s += Math.min(20, ev.transaction * 10);
  if (robotsFound && disallow.length > 0) s -= 6;
  if (!robotsFound) s += 6;
  if (securityTxtFound) s -= 2;
  return Math.max(1, Math.min(100, s));
}

/* -------------------------------------------------------------------------
 * Storage (D1). Records one row per meaningful scan. Best-effort: any error
 * here is swallowed by the caller so it can never affect the user's result.
 * ---------------------------------------------------------------------- */
async function record(db, r) {
  const ev = r.evidence || {};
  const s = r.signals || {};
  await db
    .prepare(
      'INSERT INTO scans (host, scanned_at, score, discoverable, interactive, actions, transaction_paths, robots_found, sitemap_found, security_txt_found) ' +
      'VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)'
    )
    .bind(
      r.host,
      r.scannedAt,
      r.score | 0,
      ev.discoverable | 0,
      ev.interactive | 0,
      ev.actions | 0,
      ev.transaction | 0,
      s.robotsFound ? 1 : 0,
      s.sitemapFound ? 1 : 0,
      s.securityTxtFound ? 1 : 0
    )
    .run();
}

/* -------------------------------------------------------------------------
 * Admin. Operator-only. Returns AGGREGATES for building anonymized research,
 * plus a raw CSV export for the operator's own analysis.
 *
 * Reporting rule, non-negotiable: published research is aggregate and never
 * names an individual scanned site. The host column exists here only so the
 * operator can de-duplicate and audit; it must not appear in anything public.
 * ---------------------------------------------------------------------- */
async function admin(u, env) {
  const key = u.searchParams.get('key');
  // No key at all: serve the operator dashboard shell (holds no data, no secret).
  if (key == null) {
    return new Response(ADMIN_HTML, { headers: { 'content-type': 'text/html; charset=utf-8', ...CORS } });
  }
  if (!env || !env.ADMIN_KEY || !safeEqual(key, env.ADMIN_KEY)) {
    return json({ error: 'unauthorized' }, 401);
  }
  if (!env.DB) return json({ error: 'no database bound' }, 500);

  const format = (u.searchParams.get('format') || 'json').toLowerCase();

  if (format === 'csv') {
    const rows = (await env.DB.prepare(
      'SELECT host, scanned_at, score, discoverable, interactive, actions, transaction_paths, robots_found, sitemap_found, security_txt_found FROM scans ORDER BY id DESC LIMIT 5000'
    ).all()).results || [];
    const head = 'host,scanned_at,score,discoverable,interactive,actions,transaction_paths,robots_found,sitemap_found,security_txt_found';
    const body = rows.map((r) => [
      csvCell(r.host), r.scanned_at, r.score, r.discoverable, r.interactive,
      r.actions, r.transaction_paths, r.robots_found, r.sitemap_found, r.security_txt_found,
    ].join(',')).join('\n');
    return new Response(head + '\n' + body + '\n', {
      headers: { 'content-type': 'text/csv; charset=utf-8', ...CORS },
    });
  }

  const agg = await env.DB.prepare(
    'SELECT ' +
    'COUNT(*) AS total, ' +
    'COUNT(DISTINCT host) AS unique_hosts, ' +
    'SUM(CASE WHEN score >= 67 THEN 1 ELSE 0 END) AS band_high, ' +
    'SUM(CASE WHEN score >= 34 AND score < 67 THEN 1 ELSE 0 END) AS band_medium, ' +
    'SUM(CASE WHEN score < 34 THEN 1 ELSE 0 END) AS band_low, ' +
    'AVG(score) AS avg_score, ' +
    'AVG(discoverable) AS avg_discoverable, ' +
    'AVG(interactive) AS avg_interactive, ' +
    'AVG(actions) AS avg_actions, ' +
    'AVG(transaction_paths) AS avg_transaction, ' +
    'AVG(robots_found) AS robots_coverage, ' +
    'AVG(security_txt_found) AS security_txt_coverage ' +
    'FROM scans'
  ).first();

  const recent = (await env.DB.prepare(
    'SELECT host, score, scanned_at FROM scans ORDER BY id DESC LIMIT 50'
  ).all()).results || [];

  return json({
    note: 'Aggregate view for operator use. Do not publish any individual host. Publish aggregates only.',
    totals: {
      scans: agg.total || 0,
      uniqueHosts: agg.unique_hosts || 0,
    },
    bands: {
      low: agg.band_low || 0,
      medium: agg.band_medium || 0,
      high: agg.band_high || 0,
    },
    averages: round2({
      score: agg.avg_score,
      discoverable: agg.avg_discoverable,
      interactive: agg.avg_interactive,
      actions: agg.avg_actions,
      transaction: agg.avg_transaction,
    }),
    coverage: round2({
      robotsTxt: agg.robots_coverage,
      securityTxt: agg.security_txt_coverage,
    }),
    recent,
  });
}

function round2(obj) {
  const out = {};
  for (const k in obj) out[k] = obj[k] == null ? null : Math.round(obj[k] * 100) / 100;
  return out;
}

function csvCell(v) {
  const s = String(v == null ? '' : v);
  return /[",\n]/.test(s) ? '"' + s.replace(/"/g, '""') + '"' : s;
}

// Length-stable comparison so the secret check does not short-circuit on the
// first differing byte. Not a hard security boundary, just good hygiene.
function safeEqual(a, b) {
  a = String(a); b = String(b);
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}

/* Operator dashboard served at GET /admin (no key). Holds no data and no secret.
   The operator pastes the key; the page fetches /admin?key=... and renders. */
const ADMIN_HTML = `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>agentborder scans</title>
<style>
body{background:#0c0c0d;color:#eaeae4;font:15px/1.6 system-ui,-apple-system,sans-serif;margin:0;padding:40px 20px}
.w{max-width:760px;margin:0 auto}
h1{font-size:20px;margin:0 0 4px}.sub{color:#8a8a92;font-size:13px;margin-bottom:22px}
.row{display:flex;gap:8px;flex-wrap:wrap;margin-bottom:16px}
input{flex:1;min-width:220px;background:#161617;border:1px solid #2a2a2c;border-radius:8px;padding:11px 13px;color:#eaeae4;font:14px ui-monospace,Menlo,monospace}
button{background:#c9f83a;color:#0b0b0c;border:0;border-radius:8px;padding:0 20px;font-weight:650;cursor:pointer}
a.csv{color:#c9f83a}
.err{color:#e66767;font-size:14px}
.grid{display:grid;grid-template-columns:repeat(3,1fr);gap:10px;margin:6px 0 6px}
@media(max-width:560px){.grid{grid-template-columns:repeat(2,1fr)}}
.card{background:#161617;border:1px solid #26262a;border-radius:10px;padding:14px}
.card .n{font-size:25px;font-weight:750}.card .l{color:#8a8a92;font-size:12px;margin-top:2px}
table{width:100%;border-collapse:collapse;font-size:13px;margin-top:6px}
td,th{text-align:left;padding:7px 8px;border-bottom:1px solid #202024}
th{color:#8a8a92;font-weight:500}
h2{font-size:12px;color:#8a8a92;text-transform:uppercase;letter-spacing:.1em;margin:22px 0 4px}
</style></head><body><div class="w">
<h1>agentborder scans</h1>
<div class="sub">Operator view. Aggregates only. Never publish an individual host.</div>
<div class="row">
<input id="k" type="password" placeholder="admin key" autocomplete="off">
<button onclick="load()">Load</button>
</div>
<div id="out"></div>
</div>
<script>
var K='';
function esc(s){return String(s==null?'':s).replace(/[&<>]/g,function(c){return{'&':'&amp;','<':'&lt;','>':'&gt;'}[c]})}
function card(n,l){return '<div class="card"><div class="n">'+n+'</div><div class="l">'+l+'</div></div>'}
function pct(x){return x==null?'-':Math.round(x*100)+'%'}
function num(x){return x==null?'-':x}
function load(){
  K=document.getElementById('k').value.trim();
  var out=document.getElementById('out');
  if(!K){out.innerHTML='<div class="err">Enter the admin key.</div>';return}
  out.innerHTML='<div class="sub">Loading...</div>';
  fetch('?key='+encodeURIComponent(K)).then(function(r){if(!r.ok)throw 0;return r.json()}).then(render).catch(function(){out.innerHTML='<div class="err">Wrong key, or no data yet.</div>'});
}
function render(d){
  var a=d.averages||{},c=d.coverage||{},b=d.bands||{},t=d.totals||{};
  var h='';
  h+='<div class="grid">'+card(num(t.scans),'scans')+card(num(t.uniqueHosts),'unique hosts')+card(num(a.score),'avg score')+'</div>';
  h+='<h2>Exposure bands</h2><div class="grid">'+card(num(b.low),'low')+card(num(b.medium),'medium')+card(num(b.high),'high')+'</div>';
  h+='<h2>Averages</h2><div class="grid">'+card(num(a.discoverable),'discoverable')+card(num(a.interactive),'interactive')+card(num(a.actions),'actions')+card(num(a.transaction),'transaction')+card(pct(c.robotsTxt),'has robots.txt')+card(pct(c.securityTxt),'has security.txt')+'</div>';
  var rec=d.recent||[];
  h+='<h2>Recent</h2><table><tr><th>host</th><th>score</th><th>when</th></tr>';
  for(var i=0;i<rec.length;i++){h+='<tr><td>'+esc(rec[i].host)+'</td><td>'+esc(rec[i].score)+'</td><td>'+esc(rec[i].scanned_at)+'</td></tr>'}
  h+='</table>';
  h+='<p style="margin-top:18px"><a class="csv" href="?key='+encodeURIComponent(K)+'&format=csv">Download CSV</a></p>';
  document.getElementById('out').innerHTML=h;
}
</script></body></html>`;
