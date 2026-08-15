/**
 * ② 분류기 + robots.txt(RFC 9309) 테스트 — node analyze/test-classify.js
 */
'use strict';

const assert = require('node:assert');
const { buildClassifier, DATASET } = require('./classify.js');
const { parseRobots, isAllowed, buildComplianceChecker } = require('./robots.js');

let pass = 0, fail = 0;
function t(name, fn) {
  try { fn(); console.log('  ✓ ' + name); pass++; }
  catch (e) { console.log('  ✗ ' + name + '\n      ' + e.message); fail++; }
}

const classify = buildClassifier();

console.log('\nUA 분류기');

t('GPTBot → openai/ai-crawler', () => {
  const c = classify('Mozilla/5.0 (compatible; GPTBot/1.2; +https://openai.com/gptbot)');
  assert.strictEqual(c.botId, 'gptbot');
  assert.strictEqual(c.vendor, 'openai');
  assert.strictEqual(c.category, 'ai-crawler');
  assert.strictEqual(c.robotsToken, 'GPTBot');
});

t('OAI-SearchBot → ai-search / ChatGPT-User → ai-assistant', () => {
  assert.strictEqual(classify('OAI-SearchBot/1.0; +https://openai.com/searchbot').category, 'ai-search');
  assert.strictEqual(classify('Mozilla/5.0 ChatGPT-User/1.0').category, 'ai-assistant');
});

t('Claude 3형제 구분 (Bot/SearchBot/User)', () => {
  assert.strictEqual(classify('ClaudeBot/1.0; +claudebot@anthropic.com').category, 'ai-crawler');
  assert.strictEqual(classify('Claude-SearchBot/1.0').category, 'ai-search');
  assert.strictEqual(classify('Claude-User/1.0').category, 'ai-assistant');
});

t('Applebot vs Applebot-Extended 분리 (부정 전방탐색)', () => {
  assert.strictEqual(classify('Applebot/0.1; +http://www.apple.com/go/applebot').botId, 'applebot');
});

t('robots 전용 토큰(Google-Extended)은 UA 매칭 안 됨', () => {
  const c = classify('Google-Extended');
  assert.notStrictEqual(c.botId, 'google-extended');
});

t('PerplexityBot → ai-search, Bytespider → ai-crawler, SemrushBot → seo-tool', () => {
  assert.strictEqual(classify('PerplexityBot/1.0').category, 'ai-search');
  assert.strictEqual(classify('Bytespider; spider-feedback@bytedance.com').category, 'ai-crawler');
  assert.strictEqual(classify('SemrushBot/7~bl').category, 'seo-tool');
});

t('일반 브라우저 → human', () => {
  assert.strictEqual(classify('Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36').kind, 'human');
  assert.strictEqual(classify('Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) AppleWebKit/605.1.15 Version/17.5 Mobile/15E148 Safari/604.1').kind, 'human');
});

t('미상 자동화(curl, python-requests, SomethingBot) → unknown-bot', () => {
  assert.strictEqual(classify('curl/8.4.0').category, 'unknown-bot');
  assert.strictEqual(classify('python-requests/2.32').category, 'unknown-bot');
  assert.strictEqual(classify('SomethingBot/1.0 (+http://example.com)').category, 'unknown-bot');
});

t('UA 없음 → no-ua', () => {
  assert.strictEqual(classify(null).kind, 'no-ua');
  assert.strictEqual(classify('').kind, 'no-ua');
});

t('데이터셋 무결성: 전 항목 정규식 컴파일 + 필수 필드', () => {
  for (const b of DATASET.bots) {
    new RegExp(b.match, 'i'); // throw 시 실패
    assert.ok(b.id && b.vendor && b.category && b.robotsToken, b.id + ' 필수 필드');
  }
  assert.ok(DATASET.bots.length >= 40, '항목 수 ' + DATASET.bots.length);
});

console.log('\nrobots.txt 파서 (RFC 9309)');

const ROBOTS = `
# comment
User-agent: GPTBot
Disallow: /private/
Allow: /private/public-page
Disallow: /*.pdf$

User-agent: ClaudeBot
User-agent: CCBot
Disallow: /

User-agent: *
Disallow: /admin/
Allow: /admin/help
Disallow:
Sitemap: https://example.com/sitemap.xml
`;

const robots = parseRobots(ROBOTS);

t('그룹·사이트맵 파싱', () => {
  assert.strictEqual(robots.groups.length, 3);
  assert.deepStrictEqual(robots.groups[1].agents, ['claudebot', 'ccbot']);
  assert.strictEqual(robots.sitemaps.length, 1);
});

t('그룹 선택: 특정 토큰 > *', () => {
  assert.strictEqual(isAllowed(robots, 'GPTBot', '/private/x').allowed, false);
  assert.strictEqual(isAllowed(robots, 'RandomBot', '/private/x').allowed, true); // *그룹엔 /private 규칙 없음
});

t('최장 일치: Allow /private/public-page > Disallow /private/', () => {
  assert.strictEqual(isAllowed(robots, 'GPTBot', '/private/public-page').allowed, true);
});

t('와일드카드 + $ 앵커: /*.pdf$', () => {
  assert.strictEqual(isAllowed(robots, 'GPTBot', '/docs/file.pdf').allowed, false);
  assert.strictEqual(isAllowed(robots, 'GPTBot', '/docs/file.pdfx').allowed, true);
});

t('전체 차단 그룹: Disallow / (다중 UA 그룹)', () => {
  assert.strictEqual(isAllowed(robots, 'ClaudeBot', '/anything').allowed, false);
  assert.strictEqual(isAllowed(robots, 'CCBot', '/').allowed, false);
});

t('* 그룹 폴백 + 빈 Disallow 무시', () => {
  assert.strictEqual(isAllowed(robots, 'UnknownBot', '/admin/secret').allowed, false);
  assert.strictEqual(isAllowed(robots, 'UnknownBot', '/admin/help').allowed, true);
  assert.strictEqual(isAllowed(robots, 'UnknownBot', '/normal').allowed, true);
});

t('동률 시 allow 우선 (RFC least-restrictive)', () => {
  const r = parseRobots('User-agent: *\nAllow: /folder\nDisallow: /folder');
  assert.strictEqual(isAllowed(r, 'AnyBot', '/folder/x').allowed, true);
});

t('부분 토큰 일치: "googlebot" 그룹이 "Googlebot-Image"에 적용', () => {
  const r = parseRobots('User-agent: Googlebot\nDisallow: /img/');
  assert.strictEqual(isAllowed(r, 'Googlebot-Image', '/img/a.png').allowed, false);
});

t('robots.txt 없는 봇/그룹 → 허용', () => {
  const r = parseRobots('');
  assert.strictEqual(isAllowed(r, 'GPTBot', '/x').allowed, true);
});

t('쓰레기 입력도 throw 없음', () => {
  const r = parseRobots('%%%%\nnot a rule\nDisallow: /orphan');
  assert.ok(r.parseErrors >= 1);
});

console.log('\n준수 검사 통합');

t('분류 결과 → 위반 판정 연결', () => {
  const check = buildComplianceChecker(ROBOTS);
  const gpt = classify('GPTBot/1.2');
  const human = classify('Mozilla/5.0 Chrome/126');
  assert.strictEqual(check(gpt, '/private/data'), 'violation');
  assert.strictEqual(check(gpt, '/products/1'), 'allowed');
  assert.strictEqual(check(human, '/private/data'), 'not-applicable');
});

t('unknown-bot은 * 그룹 기준 판정', () => {
  const check = buildComplianceChecker(ROBOTS);
  const unk = classify('SomethingBot/1.0');
  assert.strictEqual(check(unk, '/admin/secret'), 'violation');
  assert.strictEqual(check(unk, '/public'), 'allowed');
});

console.log(`\n${pass} passed, ${fail} failed\n`);
process.exit(fail ? 1 : 0);
