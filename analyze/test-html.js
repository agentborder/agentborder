/**
 * ④ HTML 리포트 테스트 — node analyze/test-html.js
 * 핵심: 자체 완결(외부 리소스 0), XSS 이스케이프, 전 섹션 존재, CLI 통합.
 */
'use strict';

const assert = require('node:assert');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { execFileSync } = require('node:child_process');
const { buildClassifier } = require('./classify.js');
const { buildComplianceChecker } = require('./robots.js');
const { createAggregator, estimateCost } = require('./aggregate.js');
const { renderHtml, draftConfig } = require('./report-html.js');
const { parseCombined } = require('./parse.js');
const PRICING = require('./data/pricing.json');

let pass = 0, fail = 0;
function t(name, fn) {
  try { fn(); console.log('  ✓ ' + name); pass++; }
  catch (e) { console.log('  ✗ ' + name + '\n      ' + e.message); fail++; }
}

/* 픽스처: XSS 시도 UA/경로 포함 */
function line(min, ua, method, p, status, bytes) {
  return `1.2.3.4 - - [10/Aug/2026:10:${String(min).padStart(2, '0')}:00 +0000] "${method} ${p} HTTP/1.1" ${status} ${bytes} "-" "${ua}"`;
}
const XSS_UA = '<script>alert(1)</script>Bot/1.0 crawler';
const XSS_PATH = '/search?q=<img src=x onerror=alert(2)>';
const lines = [
  ...Array.from({ length: 20 }, (_, i) => line(i, 'Mozilla/5.0 Chrome/126', 'GET', '/p/' + i, 200, 1024)),
  ...Array.from({ length: 10 }, (_, i) => line(i, 'GPTBot/1.2', 'GET', '/private/' + i, 200, 2048)),
  line(30, XSS_UA, 'GET', '/x', 200, 100),
  line(31, 'SomethingBot crawler', 'GET', XSS_PATH.split(' ')[0], 200, 100),
];
const ROBOTS = 'User-agent: GPTBot\nDisallow: /private/\n';

const classify = buildClassifier();
const agg = createAggregator({ classify, compliance: buildComplianceChecker(ROBOTS) });
for (const l of lines) { const r = parseCombined(l); if (r) agg.onRecord(r); }
const res = agg.result();
const html = renderHtml(res, {
  cost: estimateCost(res.botTotals.bytes, 'vercel-pro', PRICING),
  datasetVersion: '2026.08.15', pricingVersion: '2026.08.15',
  inputStats: { parsed: lines.length, malformed: 0, format: 'combined' },
  warnings: ['test warning'], botDocs: [],
});

console.log('\nHTML 리포트');

t('전 섹션 존재 (KPI/Score/Composition/봇 테이블/카테고리/경로/정책초안/근거)', () => {
  for (const sec of ['AI Exposure Score', 'Traffic Composition', 'full list', 'By Category',
                     'top paths per bot', 'Draft policy', 'Evidence &amp; Methodology', 'RFC 9309']) {
    assert.ok(html.includes(sec), '누락: ' + sec);
  }
});

t('자체 완결: 외부 script/link/img 리소스 0', () => {
  assert.ok(!/<script[^>]+src=/i.test(html), '외부 스크립트 발견');
  assert.ok(!/<link[^>]+href=/i.test(html), '외부 스타일시트 발견');
  assert.ok(!/<img[^>]+src=["']https?:/i.test(html), '외부 이미지 발견');
});

t('XSS: 악성 UA가 이스케이프되어 실행 불가', () => {
  assert.ok(!html.includes('<script>alert(1)</script>'), '스크립트 원문 노출!');
  assert.ok(html.includes('&lt;script&gt;alert(1)&lt;/script&gt;'), '이스케이프 형태 미포함');
});

t('정직 고지: self-declared / 오프라인 / 추정 명시', () => {
  for (const claim of ['self-declared', 'no network calls', 'Assumes logged response bytes']) {
    assert.ok(html.includes(claim), '누락: ' + claim);
  }
});

t('다크모드 정의 포함 (prefers-color-scheme)', () => {
  assert.ok(html.includes('prefers-color-scheme:dark'));
});

t('위반 수치 정확 반영 (GPTBot 10건)', () => {
  assert.ok(html.includes('⚠ 10'));
});

t('카피 규칙: 렌더 산출물에 em/en dash 없음', () => {
  assert.ok(!/[\u2014\u2013]/.test(html), 'em/en dash 발견');
});

console.log('\n정책 초안 생성기');

t('본 카테고리만 규칙 생성 + monitor 고정 + draft 명시', () => {
  const d = draftConfig(res);
  assert.strictEqual(d.mode, 'monitor');
  assert.ok(d.$draft.includes('review'));
  assert.ok(d.rules.some(r => r.category === 'ai-crawler' && r.effect === 'block'));
  assert.ok(d.rules.some(r => r.category === 'unknown-bot'));
  assert.ok(!d.rules.some(r => r.category === 'ai-search'), '없는 카테고리 규칙 생성됨');
});

console.log('\nCLI 통합 (--html)');

t('CLI --html: 파일 생성 + 안내 출력', () => {
  const fix = path.join(os.tmpdir(), 'ag-html-fix.log');
  fs.writeFileSync(fix, lines.join('\n') + '\n');
  const rob = path.join(os.tmpdir(), 'ag-html-rob.txt');
  fs.writeFileSync(rob, ROBOTS);
  const out = path.join(os.tmpdir(), 'ag-html-out.html');
  const stdout = execFileSync(process.execPath,
    [path.join(__dirname, 'cli.js'), fix, '--robots', rob, '--provider', 'vercel-pro', '--html', out, '--no-color'],
    { encoding: 'utf8' });
  assert.ok(stdout.includes('full report written'));
  const f = fs.readFileSync(out, 'utf8');
  assert.ok(f.startsWith('<!doctype html>'));
  assert.ok(f.length > 5000);
});

console.log(`\n${pass} passed, ${fail} failed\n`);
process.exit(fail ? 1 : 0);
