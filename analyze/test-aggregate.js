/**
 * ③ 집계·리포트·CLI 테스트 — node analyze/test-aggregate.js
 * 픽스처는 구성비가 수기로 계산된 합성 로그(100줄) — 모든 수치를 정확 대조.
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
const { render } = require('./report-terminal.js');
const PRICING = require('./data/pricing.json');

let pass = 0, fail = 0;
function t(name, fn) {
  try { fn(); console.log('  ✓ ' + name); pass++; }
  catch (e) { console.log('  ✗ ' + name + '\n      ' + e.message); fail++; }
}

/* ── 픽스처: 100줄, 수기 계산된 구성 ──
 * humans 40 (1KB) | gptbot 30 (2KB; 20×/products, 10×/private→위반) 같은 분에 10건 몰림
 * claudebot 10 (4KB, /docs) | curl 10 (100B; 5 GET, 5 POST) | oai-searchbot 10 (1KB)
 * 봇 60 req · 113,640 bytes · 위반 10 · ai-crawler 40 req
 */
function line(min, ua, method, p, status, bytes) {
  const mm = String(min).padStart(2, '0');
  return `1.2.3.4 - - [10/Aug/2026:10:${mm}:00 +0000] "${method} ${p} HTTP/1.1" ${status} ${bytes} "-" "${ua}"`;
}
const CHROME = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/126.0';
const GPT = 'Mozilla/5.0 (compatible; GPTBot/1.2; +https://openai.com/gptbot)';
const CLA = 'ClaudeBot/1.0; +claudebot@anthropic.com';
const OAI = 'OAI-SearchBot/1.0';
const CURL = 'curl/8.4.0';

const lines = [];
for (let i = 0; i < 40; i++) lines.push(line(i % 50, CHROME, 'GET', '/page/' + i, 200, 1024));
for (let i = 0; i < 20; i++) lines.push(line(5, GPT, 'GET', '/products/' + i, 200, 2048)); // 같은 분 → peak
for (let i = 0; i < 10; i++) lines.push(line(6 + i, GPT, 'GET', '/private/doc' + i, 200, 2048));
for (let i = 0; i < 10; i++) lines.push(line(20 + i, CLA, 'GET', '/docs/' + i, 200, 4096));
for (let i = 0; i < 5; i++) lines.push(line(30 + i, CURL, 'GET', '/api/health', 200, 100));
for (let i = 0; i < 5; i++) lines.push(line(35 + i, CURL, 'POST', '/api/comment', 403, 100));
for (let i = 0; i < 10; i++) lines.push(line(40 + i, OAI, 'GET', '/products/' + i, 200, 1024));

const ROBOTS = `User-agent: GPTBot\nDisallow: /private/\n\nUser-agent: *\nDisallow: /admin/\n`;

const FIX = path.join(os.tmpdir(), 'ag-fix-100.log');
fs.writeFileSync(FIX, lines.join('\n') + '\n');
const ROB = path.join(os.tmpdir(), 'ag-fix-robots.txt');
fs.writeFileSync(ROB, ROBOTS);

const classify = buildClassifier();
const agg = createAggregator({ classify, compliance: buildComplianceChecker(ROBOTS) });
for (const l of lines) {
  const rec = require('./parse.js').parseCombined(l);
  agg.onRecord(rec);
}
const res = agg.result();

console.log('\n집계 엔진 (수기 계산 대조)');

t('총량: 100 req, 봇 60 req', () => {
  assert.strictEqual(res.total.requests, 100);
  assert.strictEqual(res.human.requests, 40);
  assert.strictEqual(res.botTotals.requests, 60);
});

t('봇 바이트 합계 = 113,640', () => {
  assert.strictEqual(res.botTotals.bytes, 30 * 2048 + 10 * 4096 + 10 * 100 + 10 * 1024);
});

t('robots 위반: GPTBot /private 10건, 검사 60건', () => {
  assert.strictEqual(res.compliance.violations, 10);
  assert.strictEqual(res.compliance.checked, 60);
  const gpt = res.bots.find(b => b.id === 'gptbot');
  assert.strictEqual(gpt.violations, 10);
});

t('카테고리 롤업: ai-crawler 40 req (gptbot+claudebot)', () => {
  assert.strictEqual(res.categories['ai-crawler'].requests, 40);
  assert.strictEqual(res.categories['ai-search'].requests, 10);
  assert.strictEqual(res.categories['unknown-bot'].requests, 10);
});

t('피크 검출: gptbot 같은 분 20건 → peakRpm 20', () => {
  const gpt = res.bots.find(b => b.id === 'gptbot');
  assert.strictEqual(gpt.peakRpm, 20);
});

t('봇 쓰기 시도: POST 5건 집계', () => {
  assert.strictEqual(res.botTotals.post, 5);
  const unk = res.bots.find(b => b.id === 'unknown-bot');
  assert.strictEqual(unk.post, 5);
  assert.strictEqual(unk.s4xx, 5);
});

t('미상 UA 샘플에 curl 포함', () => {
  assert.ok(res.unknownUaTop.some(([ua]) => ua.includes('curl')));
});

t('Exposure Score = 61 (공식 수기 검산: 24+20+3.33+5+8.33)', () => {
  assert.strictEqual(res.score.value, 61);
  assert.strictEqual(res.score.max, 100);
  assert.strictEqual(res.score.parts.botShare, 24);
  assert.strictEqual(res.score.parts.aiCrawler, 20);
});

t('robots 미제공 시 score max=80, robots part=null', () => {
  const a2 = createAggregator({ classify });
  a2.onRecord(require('./parse.js').parseCombined(lines[0]));
  a2.onRecord(require('./parse.js').parseCombined(lines[45]));
  const r2 = a2.result();
  assert.strictEqual(r2.score.max, 80);
  assert.strictEqual(r2.score.parts.robots, null);
});

console.log('\n비용 추정');

t('10GB × vercel-pro($0.15) = $1.50, 공식·출처 포함', () => {
  const c = estimateCost(10 * 1024 ** 3, 'vercel-pro', PRICING);
  assert.strictEqual(c.usd, 1.5);
  assert.strictEqual(c.gb, 10);
  assert.ok(c.formula.includes('$0.15'));
  assert.ok(c.source.includes('vercel.com'));
});

t('미지 프로바이더 → null', () => {
  assert.strictEqual(estimateCost(1, 'nope', PRICING), null);
});

console.log('\n터미널 리포트');

t('핵심 섹션 전부 포함 + 정직 고지 문구', () => {
  const out = render(res, { cost: estimateCost(res.botTotals.bytes, 'vercel-pro', PRICING), datasetVersion: 'test', color: false });
  for (const s of ['TRAFFIC COMPOSITION', 'TOP BOTS', 'ROBOTS.TXT COMPLIANCE', 'EXPOSURE SCORE', 'RFC 9309',
                   'self-declared', 'estimate']) {
    assert.ok(out.includes(s), '누락: ' + s);
  }
  assert.ok(out.includes('10 robots.txt violations') || out.includes('10 violations'));
});

t('리포트가 60줄 이하 (첫 화면 원칙)', () => {
  const out = render(res, { datasetVersion: 'test', color: false });
  assert.ok(out.split('\n').length <= 60, '줄수: ' + out.split('\n').length);
});

t('카피 규칙: 터미널 리포트에 em/en dash 없음', () => {
  const out = render(res, { datasetVersion: 'test', color: false });
  assert.ok(!/[\u2014\u2013]/.test(out), 'em/en dash 발견');
});

console.log('\nCLI 통합 (실제 프로세스 실행)');

t('정상 실행: exit 0, 리포트 + JSON 산출', () => {
  const jsonOut = path.join(os.tmpdir(), 'ag-fix-out.json');
  const stdout = execFileSync(process.execPath,
    [path.join(__dirname, 'cli.js'), FIX, '--robots', ROB, '--provider', 'vercel-pro', '--json', jsonOut, '--no-color'],
    { encoding: 'utf8' });
  assert.ok(stdout.includes('TRAFFIC COMPOSITION'));
  const j = JSON.parse(fs.readFileSync(jsonOut, 'utf8'));
  assert.strictEqual(j.report.total.requests, 100);
  assert.strictEqual(j.report.compliance.violations, 10);
  assert.ok(j.notes.length >= 3);
});

t('없는 파일 → exit 1, 스택트레이스 없음', () => {
  try {
    execFileSync(process.execPath, [path.join(__dirname, 'cli.js'), '/no/such.log'], { encoding: 'utf8', stdio: 'pipe' });
    assert.fail('should exit 1');
  } catch (e) {
    assert.strictEqual(e.status, 1);
    assert.ok(!String(e.stderr).includes('at '), '스택트레이스 노출');
  }
});

t('인자 없음 → usage 안내 + exit 1', () => {
  try {
    execFileSync(process.execPath, [path.join(__dirname, 'cli.js')], { encoding: 'utf8', stdio: 'pipe' });
    assert.fail('should exit 1');
  } catch (e) {
    assert.strictEqual(e.status, 1);
    assert.ok(String(e.stderr).includes('usage'));
  }
});

console.log(`\n${pass} passed, ${fail} failed\n`);
process.exit(fail ? 1 : 0);
