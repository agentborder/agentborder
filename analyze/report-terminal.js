/**
 * agentborder analyze — 터미널 리포트 (③-2)
 * 경영자용 A섹션 중심 ~40줄. 모든 판정에 근거 표기, 추정은 공식 노출.
 */
'use strict';

const C = {
  reset: '\x1b[0m', bold: '\x1b[1m', dim: '\x1b[2m',
  red: '\x1b[31m', green: '\x1b[32m', yellow: '\x1b[33m',
  cyan: '\x1b[36m', magenta: '\x1b[35m',
};

function fmtBytes(n) {
  if (n >= 1024 ** 3) return (n / 1024 ** 3).toFixed(2) + ' GB';
  if (n >= 1024 ** 2) return (n / 1024 ** 2).toFixed(1) + ' MB';
  if (n >= 1024) return (n / 1024).toFixed(1) + ' KB';
  return n + ' B';
}
const fmtN = n => n.toLocaleString('en-US');
const pct = (n, d) => d ? ((n / d) * 100).toFixed(1) + '%' : '0%';

function bar(ratio, width = 24) {
  const filled = Math.round(Math.max(0, Math.min(1, ratio)) * width);
  return '█'.repeat(filled) + '░'.repeat(width - filled);
}

function render(res, opts = {}) {
  const { cost = null, datasetVersion = '?', warnings = [], color = true } = opts;
  const c = color ? C : new Proxy({}, { get: () => '' });
  const L = [];
  const T = res.total.requests;

  L.push('');
  L.push(`${c.bold}  AGENTBORDER ANALYZE${c.reset}${c.dim}  ·  bot & AI-agent traffic report${c.reset}`);
  if (res.timeRange.from) {
    L.push(`${c.dim}  period: ${res.timeRange.from.toISOString().slice(0, 10)} → ${res.timeRange.to.toISOString().slice(0, 10)}  (${res.timeRange.days.toFixed(1)} days, ${fmtN(T)} requests)${c.reset}`);
  } else {
    L.push(`${c.dim}  ${fmtN(T)} requests (no timestamps)${c.reset}`);
  }
  L.push('');

  // ── 구성비
  const rows = [
    ['Humans', res.human.requests, c.green],
    ['Bots & AI agents', res.botTotals.requests, c.red],
    ['No user-agent', res.noUa.requests, c.dim],
  ];
  L.push(`${c.bold}  TRAFFIC COMPOSITION${c.reset}`);
  for (const [label, n, col] of rows) {
    L.push(`  ${label.padEnd(18)} ${col}${bar(n / (T || 1))}${c.reset} ${pct(n, T).padStart(6)}  ${c.dim}${fmtN(n)} req · ${fmtBytes(label === 'Humans' ? res.human.bytes : label === 'No user-agent' ? res.noUa.bytes : res.botTotals.bytes)}${c.reset}`);
  }
  L.push('');

  // ── 상위 봇
  L.push(`${c.bold}  TOP BOTS${c.reset}  ${c.dim}(identity = self-declared User-Agent; cryptographic verification is a separate step)${c.reset}`);
  for (const b of res.bots.slice(0, 6)) {
    const vio = b.violations ? `  ${c.red}⚠ ${b.violations} robots.txt violations${c.reset}` : '';
    const peak = b.peakRpm > 1 ? `  ${c.dim}peak ${b.peakRpm}/min${c.reset}` : '';
    L.push(`  ${(b.id).padEnd(18)} ${c.cyan}${b.category.padEnd(13)}${c.reset} ${fmtN(b.requests).padStart(9)} req  ${fmtBytes(b.bytes).padStart(10)}${peak}${vio}`);
  }
  if (res.bots.length > 6) L.push(`  ${c.dim}… ${res.bots.length - 6} more (see --json for full list)${c.reset}`);
  L.push('');

  // ── robots.txt 준수
  L.push(`${c.bold}  ROBOTS.TXT COMPLIANCE${c.reset}  ${c.dim}(per RFC 9309)${c.reset}`);
  if (res.compliance.hasRobots) {
    const vr = pct(res.compliance.violations, res.compliance.checked);
    const col = res.compliance.violations > 0 ? c.red : c.green;
    L.push(`  ${col}${fmtN(res.compliance.violations)} violations${c.reset} out of ${fmtN(res.compliance.checked)} bot requests checked (${vr})`);
  } else {
    L.push(`  ${c.dim}not checked. pass your robots.txt with --robots ./robots.txt${c.reset}`);
  }
  L.push('');

  // ── 비용 추정
  L.push(`${c.bold}  ESTIMATED BOT BANDWIDTH COST${c.reset}`);
  if (cost) {
    L.push(`  ${c.yellow}~$${cost.usd}${c.reset}  ${c.dim}= ${cost.formula}  [${cost.label}]${c.reset}`);
    L.push(`  ${c.dim}estimate only. assumes logged bytes ≈ billed transfer; source: ${cost.source || 'neutral assumption'}${c.reset}`);
  } else {
    L.push(`  ${c.dim}add --provider vercel-pro|netlify-pro|cloudfront|generic for an estimate${c.reset}`);
  }
  L.push('');

  // ── 미상 봇
  if (res.unknownUaTop.length) {
    L.push(`${c.bold}  UNKNOWN AUTOMATION (top)${c.reset}`);
    for (const [ua, n] of res.unknownUaTop.slice(0, 3)) {
      L.push(`  ${c.dim}${fmtN(n).padStart(7)} req${c.reset}  ${ua.slice(0, 70)}`);
    }
    L.push('');
  }

  // ── 점수
  const s = res.score;
  const scol = s.value >= 60 ? c.red : s.value >= 30 ? c.yellow : c.green;
  L.push(`${c.bold}  AI EXPOSURE SCORE   ${scol}${s.value} / ${s.max}${c.reset}`);
  L.push(`  ${c.dim}= bot share ${s.parts.botShare} + ai-crawler ${s.parts.aiCrawler} + robots ${s.parts.robots ?? 'N/A'} + unknown ${s.parts.unknown} + bot-writes ${s.parts.botWrites}${c.reset}`);
  L.push(`  ${c.dim}weights are documented in the html report${c.reset}`);
  L.push('');

  for (const w of warnings) L.push(`  ${c.yellow}⚠ ${w}${c.reset}`);
  if (warnings.length) L.push('');

  // ── 다음 단계 + 근거
  L.push(`${c.bold}  NEXT${c.reset}  see it live: ${c.cyan}npm install agentborder${c.reset} (3 lines of middleware, monitor mode, blocks nothing)`);
  L.push(`${c.dim}  dataset v${datasetVersion} · identities are UA claims (not verified) · robots.txt per RFC 9309 · costs are estimates${c.reset}`);
  L.push('');
  return L.join('\n');
}

module.exports = { render, fmtBytes };
