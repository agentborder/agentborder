/**
 * agentborder analyze — 기간 비교 (⑤-3)
 * 이전 `--json` 산출물과 현재 결과의 증감. 재사용 루프(매주 돌릴 이유)의 엔진.
 * 원칙: 이전 파일이 깨졌어도 crash 없이 경고만.
 */
'use strict';

function loadPrev(json) {
  try {
    const o = typeof json === 'string' ? JSON.parse(json) : json;
    const r = o && o.report;
    if (!r || !r.total || typeof r.total.requests !== 'number') return null;
    return r;
  } catch { return null; }
}

function pctShare(rep) {
  return rep.total.requests ? (rep.botTotals.requests / rep.total.requests) * 100 : 0;
}

/** diff 객체 생성 — 계산만, 출력 없음 (테스트 용이) */
function diff(prevReport, cur) {
  const prev = prevReport;
  const prevBots = new Set((prev.bots || []).map(b => b.id));
  const curBots = new Set(cur.bots.map(b => b.id));
  return {
    requests: { prev: prev.total.requests, cur: cur.total.requests },
    botShare: { prev: +pctShare(prev).toFixed(1), cur: +pctShare(cur).toFixed(1) },
    botBytes: { prev: prev.botTotals.bytes, cur: cur.botTotals.bytes },
    violations: { prev: prev.compliance ? prev.compliance.violations : 0, cur: cur.compliance.violations },
    score: { prev: prev.score ? prev.score.value : null, cur: cur.score.value },
    newBots: [...curBots].filter(id => !prevBots.has(id)),
    goneBots: [...prevBots].filter(id => !curBots.has(id)),
  };
}

function arrow(prev, cur, goodWhenDown = true) {
  if (prev === null || prev === undefined) return '';
  if (cur === prev) return '→ unchanged';
  const up = cur > prev;
  const mark = up ? '▲' : '▼';
  const tone = (up === !goodWhenDown) ? 'good' : 'bad';
  return `${mark} ${tone === 'bad' ? 'worse' : 'better'}`;
}

/** 터미널용 비교 블록 렌더 */
function renderCompare(d, { color = true } = {}) {
  const c = color ? { b: '\x1b[1m', dim: '\x1b[2m', r: '\x1b[0m', red: '\x1b[31m', grn: '\x1b[32m' }
                  : { b: '', dim: '', r: '', red: '', grn: '' };
  const L = [];
  const row = (label, prev, cur, unit, goodWhenDown) => {
    const a = arrow(prev, cur, goodWhenDown);
    const col = a.includes('worse') ? c.red : a.includes('better') ? c.grn : c.dim;
    L.push(`  ${label.padEnd(16)} ${String(prev ?? '—').padStart(10)}${unit} → ${String(cur).padStart(10)}${unit}  ${col}${a}${c.r}`);
  };
  L.push(`${c.b}  VS PREVIOUS REPORT${c.r}`);
  row('bot share', d.botShare.prev, d.botShare.cur, '%', true);
  row('total requests', d.requests.prev, d.requests.cur, '', true);
  row('bot bytes', Math.round(d.botBytes.prev / 1048576), Math.round(d.botBytes.cur / 1048576), 'MB', true);
  row('violations', d.violations.prev, d.violations.cur, '', true);
  if (d.score.prev !== null) row('exposure score', d.score.prev, d.score.cur, '', true);
  if (d.newBots.length) L.push(`  ${c.red}new bots since last report: ${d.newBots.join(', ')}${c.r}`);
  if (d.goneBots.length) L.push(`  ${c.dim}no longer seen: ${d.goneBots.join(', ')}${c.r}`);
  L.push('');
  return L.join('\n');
}

module.exports = { loadPrev, diff, renderCompare };
