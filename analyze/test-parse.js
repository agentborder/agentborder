/**
 * ① 파서 코어 테스트 — node analyze/test-parse.js
 * 완료 조건: 전부 통과 + 200k줄 성능 스모크 (<10s)
 */
'use strict';

const assert = require('node:assert');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { parseCombined, parseJsonLine, parseClfTime, detectFormat } = require('./parse.js');
const { readLog } = require('./reader.js');

let pass = 0, fail = 0;
function t(name, fn) {
  return Promise.resolve()
    .then(fn)
    .then(() => { console.log('  ✓ ' + name); pass++; })
    .catch(e => { console.log('  ✗ ' + name + '\n      ' + e.message); fail++; });
}
const tmp = (name, content) => {
  const p = path.join(os.tmpdir(), 'ag-test-' + name);
  fs.writeFileSync(p, content);
  return p;
};

/* ── 픽스처 ── */
const NGINX = [
  '66.249.66.1 - - [10/Aug/2026:13:55:36 +0000] "GET /products/1 HTTP/1.1" 200 5120 "-" "Mozilla/5.0 (compatible; GPTBot/1.2; +https://openai.com/gptbot)"',
  '40.77.167.1 - - [10/Aug/2026:13:56:01 +0000] "GET /docs/intro?ref=x HTTP/1.1" 200 20480 "https://example.com" "Mozilla/5.0 (compatible; ClaudeBot/1.0; +claudebot@anthropic.com)"',
  '10.0.0.5 - alice [10/Aug/2026:13:57:12 -0500] "POST /api/v1/cart HTTP/1.1" 201 310 "-" "Mozilla/5.0 (Windows NT 10.0) Chrome/126.0"',
  '203.0.113.9 - - [10/Aug/2026:14:00:00 +0000] "GET /missing HTTP/1.1" 404 - "-" "Bytespider; spider-feedback@bytedance.com"',
  '198.51.100.7 - - [10/Aug/2026:14:01:00 +0000] "-" 400 0 "-" "-"',
].join('\n');
const MALFORMED = 'this is not a log line at all\n<<<garbage>>>\n';
const COMMON = '1.2.3.4 - - [10/Aug/2026:13:55:36 +0000] "GET / HTTP/1.1" 200 512\n';
const CADDY = [
  '{"ts":1786713600.123,"request":{"remote_ip":"66.249.66.1","method":"GET","uri":"/products/2?x=1","headers":{"User-Agent":["GPTBot/1.2"]}},"status":200,"size":4096}',
  '{"time":"2026-08-10T14:00:00Z","method":"post","path":"/api/checkout","status":403,"bytes":128,"user_agent":"ShopAgent/2.0"}',
  '{"not":"a log line"}',
].join('\n');

(async () => {
  console.log('\ncombined 파서');

  await t('정상 줄 → 전 필드 정확', () => {
    const r = parseCombined(NGINX.split('\n')[0]);
    assert.strictEqual(r.ip, '66.249.66.1');
    assert.strictEqual(r.method, 'GET');
    assert.strictEqual(r.path, '/products/1');
    assert.strictEqual(r.status, 200);
    assert.strictEqual(r.bytes, 5120);
    assert.ok(r.ua.includes('GPTBot'));
    assert.strictEqual(r.ts.toISOString(), '2026-08-10T13:55:36.000Z');
  });

  await t('쿼리 분리 + referer', () => {
    const r = parseCombined(NGINX.split('\n')[1]);
    assert.strictEqual(r.path, '/docs/intro');
    assert.strictEqual(r.query, 'ref=x');
    assert.strictEqual(r.referer, 'https://example.com');
  });

  await t('음수 타임존 보정 (-0500 → UTC)', () => {
    const r = parseCombined(NGINX.split('\n')[2]);
    assert.strictEqual(r.ts.toISOString(), '2026-08-10T18:57:12.000Z');
    assert.strictEqual(r.method, 'POST');
  });

  await t('bytes "-" → 0', () => {
    const r = parseCombined(NGINX.split('\n')[3]);
    assert.strictEqual(r.bytes, 0);
    assert.strictEqual(r.status, 404);
  });

  await t('불량 요청("-") 줄도 레코드로 살림', () => {
    const r = parseCombined(NGINX.split('\n')[4]);
    assert.ok(r);
    assert.strictEqual(r.method, null);
    assert.strictEqual(r.ua, null); // "-" → null
    assert.strictEqual(r._hasUaField, true);
  });

  await t('common 포맷: UA 그룹 없음 → _hasUaField=false', () => {
    const r = parseCombined(COMMON.trim());
    assert.ok(r);
    assert.strictEqual(r._hasUaField, false);
  });

  await t('쓰레기 줄 → null (throw 없음)', () => {
    assert.strictEqual(parseCombined('garbage'), null);
  });

  await t('CLF 시간 파서 불량 입력 → null', () => {
    assert.strictEqual(parseClfTime('not-a-date'), null);
  });

  console.log('\njsonl 파서');

  await t('Caddy 구조 (중첩 request/headers)', () => {
    const r = parseJsonLine(CADDY.split('\n')[0]);
    assert.strictEqual(r.ip, '66.249.66.1');
    assert.strictEqual(r.path, '/products/2');
    assert.strictEqual(r.query, 'x=1');
    assert.strictEqual(r.ua, 'GPTBot/1.2');
    assert.strictEqual(r.bytes, 4096);
    assert.ok(r.ts instanceof Date && !isNaN(r.ts));
  });

  await t('평평한 키 + ISO 시간 + method 대문자화', () => {
    const r = parseJsonLine(CADDY.split('\n')[1]);
    assert.strictEqual(r.method, 'POST');
    assert.strictEqual(r.status, 403);
    assert.strictEqual(r.ua, 'ShopAgent/2.0');
    assert.strictEqual(r.ts.toISOString(), '2026-08-10T14:00:00.000Z');
  });

  await t('로그가 아닌 JSON → null', () => {
    assert.strictEqual(parseJsonLine('{"not":"a log line"}'), null);
  });

  await t('깨진 JSON → null (throw 없음)', () => {
    assert.strictEqual(parseJsonLine('{broken'), null);
  });

  console.log('\n포맷 감지');

  await t('combined/jsonl/unknown 감지', () => {
    assert.strictEqual(detectFormat(NGINX.split('\n')[0]), 'combined');
    assert.strictEqual(detectFormat(CADDY.split('\n')[0]), 'jsonl');
    assert.strictEqual(detectFormat('random text'), 'unknown');
  });

  console.log('\n스트리밍 리더');

  await t('nginx 픽스처: 5줄 전부 파싱, 카운트 정확', async () => {
    const recs = [];
    const s = await readLog(tmp('nginx.log', NGINX), { onRecord: r => recs.push(r) });
    assert.strictEqual(s.fatal, null);
    assert.strictEqual(s.format, 'combined');
    assert.strictEqual(s.totalLines, 5);
    assert.strictEqual(s.parsed, 5);
    assert.strictEqual(s.malformed, 0);
    assert.strictEqual(recs.length, 5);
  });

  await t('불량 줄 섞임: 카운트 분리 + 샘플 보존 + 크래시 없음', async () => {
    const s = await readLog(tmp('mixed.log', NGINX + '\n' + MALFORMED + NGINX), {});
    assert.strictEqual(s.fatal, null);
    assert.strictEqual(s.parsed, 10);
    assert.strictEqual(s.malformed, 2);
    assert.ok(s.errorSamples.length >= 1);
  });

  await t('빈 파일 → fatal, throw 없음', async () => {
    const s = await readLog(tmp('empty.log', ''), {});
    assert.ok(s.fatal && s.fatal.includes('empty'));
  });

  await t('없는 파일 → fatal, throw 없음', async () => {
    const s = await readLog('/nonexistent/x.log', {});
    assert.ok(s.fatal && s.fatal.includes('not found'));
  });

  await t('전부 쓰레기 → 10줄 내 포맷 판정 실패 fatal', async () => {
    const s = await readLog(tmp('garbage.log', Array(20).fill('garbage line').join('\n')), {});
    assert.ok(s.fatal && s.fatal.includes('unrecognized'));
  });

  await t('common 포맷 → UA 부재 경고', async () => {
    const s = await readLog(tmp('common.log', COMMON.repeat(20)), {});
    assert.strictEqual(s.fatal, null);
    assert.ok(s.warnings.some(w => w.includes('User-Agent')));
  });

  await t('onRecord 소비자 오류가 리더를 죽이지 않음', async () => {
    const s = await readLog(tmp('nginx2.log', NGINX), { onRecord: () => { throw new Error('consumer bug'); } });
    assert.strictEqual(s.fatal, null);
    assert.strictEqual(s.parsed, 5);
  });

  console.log('\n성능 스모크');

  await t('20만 줄 스트리밍 < 10초', async () => {
    const line = NGINX.split('\n')[0] + '\n';
    const p = path.join(os.tmpdir(), 'ag-test-big.log');
    const w = fs.createWriteStream(p);
    for (let i = 0; i < 200; i++) w.write(line.repeat(1000));
    await new Promise(res => w.end(res));
    const start = Date.now();
    let n = 0;
    const s = await readLog(p, { onRecord: () => n++ });
    const ms = Date.now() - start;
    assert.strictEqual(s.parsed, 200000);
    assert.strictEqual(n, 200000);
    assert.ok(ms < 10000, `took ${ms}ms`);
    console.log(`      (200,000줄 → ${ms}ms, ${Math.round(200000 / (ms / 1000)).toLocaleString()} lines/sec)`);
  });

  console.log(`\n${pass} passed, ${fail} failed\n`);
  process.exit(fail ? 1 : 0);
})();
