#!/usr/bin/env node
/**
 * Agentborder 리포트 CLI
 * 사용법: node report.js [이벤트파일] [--days 7]
 * 이벤트 로그(JSONL)를 읽어 "무엇을 걸렀다면 무엇이 남았을지"를 요약한다.
 * 비용 환산은 하지 않는다: 트래픽 데이터만으로 금액을 추정하지 않는 것이 원칙이며,
 * 금액 환산은 고객이 단가·청구액을 입력하는 호스티드 콘솔(유료)의 역할이다.
 */
'use strict';
const fs = require('node:fs');

const file = process.argv[2] || './agentborder-events.jsonl';
const daysArg = process.argv.indexOf('--days');
const days = daysArg > -1 ? Number(process.argv[daysArg + 1]) : 7;
const since = Date.now() - days * 86_400_000;

if (!fs.existsSync(file)) {
  console.error(`이벤트 파일이 없습니다: ${file}\n미들웨어를 설치하고 트래픽을 받은 뒤 다시 실행하세요.`);
  process.exit(1);
}

const rows = fs.readFileSync(file, 'utf8').split('\n').filter(Boolean)
  .map(l => { try { return JSON.parse(l); } catch { return null; } })
  .filter(e => e && !e.error && Date.parse(e.t) >= since);

const count = (keyFn) => {
  const m = new Map();
  for (const e of rows) { const k = keyFn(e); m.set(k, (m.get(k) || 0) + 1); }
  return [...m.entries()].sort((a, b) => b[1] - a[1]);
};

const total = rows.length;
const wouldFilter = rows.filter(e => ['would-block','would-limit','blocked','limited'].includes(e.outcome)).length;
const enforcedFilter = rows.filter(e => ['blocked','limited'].includes(e.outcome)).length;

console.log('');
console.log(`AGENTBORDER 리포트 · 최근 ${days}일`);
console.log('─'.repeat(46));
console.log(`봇 요청 합계            ${total.toLocaleString()}건`);
console.log(`정책상 필터 대상        ${wouldFilter.toLocaleString()}건 (${total ? Math.round(wouldFilter/total*100) : 0}%)`);
console.log(`실제 차단·제한(enforce) ${enforcedFilter.toLocaleString()}건`);
console.log('');
console.log('카테고리별');
for (const [k, v] of count(e => e.category)) console.log(`  ${String(k).padEnd(14)} ${v.toLocaleString()}건`);
console.log('');
console.log('상위 봇');
for (const [k, v] of count(e => e.bot).slice(0, 8)) console.log(`  ${String(k).padEnd(14)} ${v.toLocaleString()}건`);
console.log('');
console.log('행위별 필터 대상');
for (const [k, v] of count(e => e.action + '|' + e.outcome)
  .filter(([k]) => k.includes('would-') || k.includes('blocked') || k.includes('limited'))) {
  const [a, o] = k.split('|');
  console.log(`  ${a.padEnd(14)} ${o.padEnd(12)} ${v.toLocaleString()}건`);
}
console.log('');
console.log(`다음 단계: 이 수치가 7일 이상 쌓였다면, enforce 전환은 카나리로 시작하세요.`);
console.log(`  AGENTBORDER_MODE=enforce AGENTBORDER_ENFORCE_PERCENT=1 로 1%부터. 롤백은 환경변수 원복이면 끝.`);
console.log('');
