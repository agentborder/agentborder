/**
 * 데모: 봇 트래픽 시뮬레이터. 실행 중인 example/server.js 에 가짜 봇 요청을 보낸다.
 * 실행: node example/simulate.js [요청수=200]
 */
'use strict';
const N = Number(process.argv[2] || 200);
const BASE = 'http://localhost:8787';

const TRAFFIC = [
  ['Mozilla/5.0 (compatible; GPTBot/1.0)',              'GET',  '/products/101'],
  ['Mozilla/5.0 (compatible; GPTBot/1.0)',              'GET',  '/api/v1/inventory/101'],
  ['Mozilla/5.0 (compatible; Bytespider)',              'GET',  '/products/202'],
  ['Mozilla/5.0 (compatible; CCBot/2.0)',               'GET',  '/products/303'],
  ['Mozilla/5.0 (compatible; OAI-SearchBot/1.0)',       'GET',  '/products/404'],
  ['Mozilla/5.0 (compatible; OAI-SearchBot/1.0)',       'GET',  '/api/v1/inventory/404'],
  ['Mozilla/5.0 (compatible; ChatGPT-User/1.0)',        'GET',  '/products/505'],
  ['Mozilla/5.0 (compatible; ChatGPT-User/1.0)',        'POST', '/api/v1/cart'],
  ['Mozilla/5.0 (compatible; ChatGPT-User/1.0)',        'POST', '/api/v1/checkout'],
  ['Mozilla/5.0 (compatible; Claude-SearchBot/1.0)',    'GET',  '/products/606'],
  ['SomeRandomScraper/0.3 (spider)',                    'GET',  '/sitemap.xml'],
  ['Mozilla/5.0 (Macintosh) Chrome/126 Safari/537.36',  'GET',  '/products/1'],  // 인간
];

(async () => {
  let done = 0;
  for (let i = 0; i < N; i++) {
    const [ua, method, p] = TRAFFIC[i % TRAFFIC.length];
    try {
      const r = await fetch(BASE + p, { method, headers: { 'User-Agent': ua } });
      done++;
      if (i < 12) console.log(`${method.padEnd(4)} ${p.padEnd(24)} ${ua.split('(')[0].trim().padEnd(20)} → ${r.status} ${r.headers.get('x-agentborder') || ''}`);
    } catch (e) { console.error('요청 실패:', e.message); process.exit(1); }
  }
  console.log(`\n${done}건 전송 완료. 이제 실행: node report.js --days 1`);
})();
