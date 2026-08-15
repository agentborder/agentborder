/**
 * 동봉 샘플 로그 생성기 (개발 도구 — 패키지엔 산출물만 포함)
 * 결정적 시드 PRNG → 같은 입력이면 항상 같은 sample.log (재현 가능성).
 * 사용: node analyze/dev/gen-sample.js
 *
 * 구성 의도: "30초 체험"에서 흥미로운 결과가 나오도록 —
 *  봇 비중 ~45%, GPTBot의 /private 위반, Bytespider 폭주 분(burst)·404 낭비,
 *  봇 POST 시도, 미상 자동화(curl/python) 포함. 7일치.
 */
'use strict';

const fs = require('node:fs');
const path = require('node:path');

function mulberry32(seed) {
  return function () {
    seed |= 0; seed = (seed + 0x6D2B79F5) | 0;
    let t = Math.imul(seed ^ (seed >>> 15), 1 | seed);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}
const rnd = mulberry32(20260815);
const pick = arr => arr[Math.floor(rnd() * arr.length)];
const int = (a, b) => a + Math.floor(rnd() * (b - a + 1));

const MONTH = 'Aug'; const YEAR = 2026;
function clf(day, h, m, s) {
  return `[${String(day).padStart(2, '0')}/${MONTH}/${YEAR}:${String(h).padStart(2, '0')}:${String(m).padStart(2, '0')}:${String(s).padStart(2, '0')} +0000]`;
}
function line(ip, t, method, p, status, bytes, ua, ref = '-') {
  return `${ip} - - ${t} "${method} ${p} HTTP/1.1" ${status} ${bytes} "${ref}" "${ua}"`;
}

const HUMAN_UAS = [
  'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36',
  'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Safari/605.1.15',
  'Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Mobile/15E148 Safari/604.1',
  'Mozilla/5.0 (X11; Linux x86_64; rv:127.0) Gecko/20100101 Firefox/127.0',
];
const PAGES = ['/', '/pricing', '/docs/getting-started', '/docs/api', '/blog/launch', '/products/widget-a', '/products/widget-b', '/about', '/changelog', '/docs/faq'];
const ASSETS = ['/assets/app.js', '/assets/style.css', '/img/hero.png'];

const out = [];

for (let day = 4; day <= 10; day++) {
  // 사람 트래픽 (~140/일)
  for (let i = 0; i < 140; i++) {
    const t = clf(day, int(0, 23), int(0, 59), int(0, 59));
    const p = rnd() < 0.75 ? pick(PAGES) : pick(ASSETS);
    out.push(line(`73.${int(1, 254)}.${int(1, 254)}.${int(1, 254)}`, t, 'GET', p, 200, int(800, 42000), pick(HUMAN_UAS), rnd() < 0.3 ? 'https://www.google.com/' : '-'));
  }
  // GPTBot (~45/일, 그중 /private 위반 ~8)
  for (let i = 0; i < 45; i++) {
    const t = clf(day, int(0, 23), int(0, 59), int(0, 59));
    const viol = rnd() < 0.18;
    const p = viol ? `/private/reports/${int(1, 40)}` : pick(PAGES);
    out.push(line(`52.230.${int(1, 254)}.${int(1, 254)}`, t, 'GET', p, 200, int(4000, 60000), 'Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko); compatible; GPTBot/1.2; +https://openai.com/gptbot'));
  }
  // ClaudeBot (~30/일)
  for (let i = 0; i < 30; i++) {
    out.push(line(`160.79.${int(1, 254)}.${int(1, 254)}`, clf(day, int(0, 23), int(0, 59), int(0, 59)), 'GET', pick(PAGES), 200, int(4000, 50000), 'Mozilla/5.0; ClaudeBot/1.0; +claudebot@anthropic.com'));
  }
  // Bytespider (~55/일, 404 낭비 30%, POST 시도 소량)
  for (let i = 0; i < 55; i++) {
    const t = clf(day, int(0, 23), int(0, 59), int(0, 59));
    if (rnd() < 0.06) {
      out.push(line(`110.249.${int(1, 254)}.${int(1, 254)}`, t, 'POST', '/api/comments', 403, 120, 'Mozilla/5.0 (Linux; Android 5.0) Bytespider; spider-feedback@bytedance.com'));
    } else {
      const notFound = rnd() < 0.3;
      out.push(line(`110.249.${int(1, 254)}.${int(1, 254)}`, t, 'GET', notFound ? `/old-page-${int(1, 900)}` : pick(PAGES), notFound ? 404 : 200, notFound ? 350 : int(3000, 45000), 'Mozilla/5.0 (Linux; Android 5.0) Bytespider; spider-feedback@bytedance.com'));
    }
  }
  // OAI-SearchBot / PerplexityBot / ChatGPT-User (가벼움)
  for (let i = 0; i < 12; i++) out.push(line(`20.42.${int(1, 254)}.${int(1, 254)}`, clf(day, int(0, 23), int(0, 59), int(0, 59)), 'GET', pick(PAGES), 200, int(3000, 30000), 'OAI-SearchBot/1.0; +https://openai.com/searchbot'));
  for (let i = 0; i < 8; i++) out.push(line(`107.20.${int(1, 254)}.${int(1, 254)}`, clf(day, int(0, 23), int(0, 59), int(0, 59)), 'GET', pick(PAGES), 200, int(3000, 30000), 'Mozilla/5.0; PerplexityBot/1.0; +https://perplexity.ai/perplexitybot'));
  for (let i = 0; i < 6; i++) out.push(line(`23.98.${int(1, 254)}.${int(1, 254)}`, clf(day, int(0, 23), int(0, 59), int(0, 59)), 'GET', pick(PAGES), 200, int(2000, 20000), 'Mozilla/5.0 ChatGPT-User/1.0; +https://openai.com/bot'));
  // Googlebot (~20/일)
  for (let i = 0; i < 20; i++) out.push(line(`66.249.${int(64, 95)}.${int(1, 254)}`, clf(day, int(0, 23), int(0, 59), int(0, 59)), 'GET', pick(PAGES), 200, int(2000, 30000), 'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)'));
  // 미상 자동화 (~15/일)
  for (let i = 0; i < 15; i++) {
    const ua = pick(['curl/8.4.0', 'python-requests/2.32.0', 'Go-http-client/2.0', 'ScrapeMaster crawler 3.1']);
    out.push(line(`45.155.${int(1, 254)}.${int(1, 254)}`, clf(day, int(0, 23), int(0, 59), int(0, 59)), 'GET', pick([...PAGES, '/wp-login.php', '/.env']), pick([200, 200, 404, 403]), int(200, 5000), ua));
  }
}

// 8/09 14:05 — Bytespider 폭주 분 (분당 90건 burst): "피크 감지" 데모
for (let i = 0; i < 90; i++) {
  out.push(line(`110.249.8.${int(1, 254)}`, clf(9, 14, 5, int(0, 59)), 'GET', `/products/widget-${pick(['a', 'b'])}?page=${i}`, 200, int(3000, 20000), 'Mozilla/5.0 (Linux; Android 5.0) Bytespider; spider-feedback@bytedance.com'));
}

// 시간순 정렬(리얼함)
out.sort((a, b) => a.slice(a.indexOf('[')) < b.slice(b.indexOf('[')) ? -1 : 1);

const dest = path.join(__dirname, '..', 'data', 'sample.log');
fs.writeFileSync(dest, out.join('\n') + '\n');

const robots = `# sample robots.txt (bundled with agentborder analyze --sample)
User-agent: GPTBot
Disallow: /private/

User-agent: Bytespider
Disallow: /

User-agent: *
Disallow: /admin/
Sitemap: https://example.com/sitemap.xml
`;
fs.writeFileSync(path.join(__dirname, '..', 'data', 'sample-robots.txt'), robots);

console.log(`generated: ${out.length} lines → data/sample.log + data/sample-robots.txt`);
