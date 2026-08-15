/**
 * ⑤ 깔때기 장치 테스트 — node analyze/test-funnel.js
 * --sample(체험 품질까지 검증) / --card(자체완결·이스케이프) / --compare(증감·불량 파일 내성)
 */
'use strict';

const assert = require('node:assert');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { execFileSync } = require('node:child_process');
const { readLog } = require('./reader.js');
const { buildClassifier } = require('./classify.js');
const { buildComplianceChecker } = require('./robots.js');
const { createAggregator } = require('./aggregate.js');
const { renderCard } = require('./card.js');
const { loadPrev, diff, renderCompare } = require('./compare.js');

let pass = 0, fail = 0;
function t(name, fn) {
  return Promise.resolve().then(fn)
    .then(() => { console.log('  ✓ ' + name); pass++; })
    .catch(e => { console.log('  ✗ ' + name + '\n      ' + e.message); fail++; });
}
const CLI = path.join(__dirname, 'cli.js');
const SAMPLE = path.join(__dirname, 'data', 'sample.log');
const SROBOTS = path.join(__dirname, 'data', 'sample-robots.txt');

(async () => {
  console.log('\n--sample (동봉 데모)');

  // 샘플을 직접 집계해 "체험 품질" 검증
  const classify = buildClassifier();
  const agg = createAggregator({ classify, compliance: buildComplianceChecker(fs.readFileSync(SROBOTS, 'utf8')) });
  const stats = await readLog(SAMPLE, { onRecord: agg.onRecord });
  const res = agg.result();

  await t('샘플 로그: 전 줄 파싱 성공 (malformed 0)', () => {
    assert.strictEqual(stats.fatal, null);
    assert.strictEqual(stats.malformed, 0);
    assert.ok(stats.parsed >= 2000, 'lines: ' + stats.parsed);
  });

  await t('체험 품질: 봇 비중 30~70% (흥미로운 결과 보장)', () => {
    const share = res.botTotals.requests / res.total.requests;
    assert.ok(share > 0.3 && share < 0.7, 'share: ' + share.toFixed(2));
  });

  await t('체험 품질: 위반·피크·POST·미상봇 전부 존재 (데모 볼거리)', () => {
    assert.ok(res.compliance.violations > 50, 'violations: ' + res.compliance.violations);
    const byte = res.bots.find(b => b.id === 'bytespider');
    assert.ok(byte.peakRpm >= 60, 'peak: ' + byte.peakRpm);       // 폭주 분 감지
    assert.ok(byte.violations > 100, 'Bytespider Disallow:/ 전면 위반');
    assert.ok(res.botTotals.post > 0);
    assert.ok(res.unknownUaTop.length >= 2);
  });

  await t('CLI --sample: 인자 없이 전체 흐름 실행 + 안내 문구', () => {
    const out = execFileSync(process.execPath, [CLI, '--sample', '--no-color'], { encoding: 'utf8' });
    assert.ok(out.includes('sample mode'));
    assert.ok(out.includes('TRAFFIC COMPOSITION'));
    assert.ok(out.includes('violations'));
    assert.ok(out.includes('try your own'));
  });

  console.log('\n--card (공유 카드)');

  const card = renderCard(res, { site: 'demo.example <script>x</script>', cost: { usd: 1.23, provider: 'generic' } });

  await t('OG 규격(1200×630) + 핵심 숫자 + 명령어 CTA 포함', () => {
    assert.ok(card.includes('1200px') && card.includes('630px'));
    assert.ok(card.includes('of my traffic'));
    assert.ok(card.includes('npx agentborder analyze'));
    assert.ok(card.includes('exposure score') || card.includes('AI exposure'));
  });

  await t('카드 XSS 이스케이프 + 외부 리소스 0', () => {
    assert.ok(!card.includes('<script>x</script>'));
    assert.ok(!/<script[^>]+src=/i.test(card));
    assert.ok(!/<link[^>]+href=/i.test(card));
  });

  await t('CLI --card: 파일 생성', () => {
    const out = path.join(os.tmpdir(), 'ag-card.html');
    execFileSync(process.execPath, [CLI, '--sample', '--card', out, '--no-color'], { encoding: 'utf8' });
    assert.ok(fs.readFileSync(out, 'utf8').startsWith('<!doctype html>'));
  });

  await t('카피 규칙: 카드에 em/en dash 없음', () => {
    assert.ok(!/[\u2014\u2013]/.test(card), 'em/en dash 발견');
  });

  console.log('\n--compare (기간 비교)');

  await t('diff: 증감·신규 봇 계산 정확', () => {
    const prev = { total: { requests: 1000 }, botTotals: { requests: 300, bytes: 100 * 1048576 },
                   compliance: { violations: 5 }, score: { value: 40 },
                   bots: [{ id: 'gptbot' }, { id: 'oldbot' }] };
    const cur = { total: { requests: 1200 }, botTotals: { requests: 480, bytes: 200 * 1048576 },
                  compliance: { violations: 12 }, score: { value: 55 },
                  bots: [{ id: 'gptbot' }, { id: 'bytespider' }] };
    const d = diff(prev, cur);
    assert.strictEqual(d.botShare.prev, 30);
    assert.strictEqual(d.botShare.cur, 40);
    assert.deepStrictEqual(d.newBots, ['bytespider']);
    assert.deepStrictEqual(d.goneBots, ['oldbot']);
    const txt = renderCompare(d, { color: false });
    assert.ok(txt.includes('worse'));
    assert.ok(txt.includes('new bots since last report: bytespider'));
  });

  await t('CLI --compare: json 산출 → 재입력 → 비교 블록 출력', () => {
    const j = path.join(os.tmpdir(), 'ag-prev.json');
    execFileSync(process.execPath, [CLI, '--sample', '--json', j, '--no-color'], { encoding: 'utf8' });
    const out = execFileSync(process.execPath, [CLI, '--sample', '--compare', j, '--no-color'], { encoding: 'utf8' });
    assert.ok(out.includes('VS PREVIOUS REPORT'));
    assert.ok(out.includes('unchanged')); // 같은 샘플끼리 비교 → 변화 없음
  });

  await t('불량 비교 파일 → 경고만, crash 없음 (exit 0)', () => {
    const bad = path.join(os.tmpdir(), 'ag-bad.json');
    fs.writeFileSync(bad, '{not json');
    const out = execFileSync(process.execPath, [CLI, '--sample', '--compare', bad, '--no-color'], { encoding: 'utf8' });
    assert.ok(out.includes('cannot read previous report'));
  });

  await t('loadPrev: 형식 불일치 → null', () => {
    assert.strictEqual(loadPrev('{"hello":1}'), null);
    assert.strictEqual(loadPrev('broken'), null);
  });

  console.log(`\n${pass} passed, ${fail} failed\n`);
  process.exit(fail ? 1 : 0);
})();
