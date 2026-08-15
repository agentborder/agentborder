/**
 * 데모: 가상 쇼핑몰 서버에 Agentborder를 붙인 예시 (의존성 0개, Node 내장 http 사용)
 * 실행: node example/server.js  →  http://localhost:8787
 * Express 사용 시에는 app.use(gate) 한 줄이면 동일하게 동작한다.
 */
'use strict';
const http = require('node:http');
const { createAgentborder } = require('../index.js');
const config = require('../agentborder.config.example.json');

const gate = createAgentborder({ ...config, eventLog: './agentborder-events.jsonl' });

const server = http.createServer((req, res) => {
  gate(req, res, () => {
    // ── 여기부터가 "원래의 사이트". 게이트를 통과한 요청만 도달한다 ──
    res.setHeader('Content-Type', 'application/json; charset=utf-8');
    res.end(JSON.stringify({ ok: true, path: req.url, shop: 'demo-shop' }));
  });
});

server.listen(8787, () => {
  console.log('demo-shop with Agentborder → http://localhost:8787');
  console.log(`mode=${process.env.AGENTBORDER_MODE || config.mode}, enforcePercent=${process.env.AGENTBORDER_ENFORCE_PERCENT || config.enforcePercent}`);
});
