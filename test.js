/**
 * Agentborder test suite — zero-dependency, run with: node test.js
 * Covers: signature verification (round-trip, tamper, expiry, unknown key,
 * wrong tag, missing headers), classifier identity mapping, telemetry rollup.
 */
'use strict';

const assert = require('node:assert');
const { generateKeyPair, signRequest } = require('./sign.js');
const { createVerifier, createStaticResolver } = require('./verify.js');
const { createTelemetry } = require('./telemetry.js');
const { createAgentborder } = require('./index.js');

let pass = 0, fail = 0;
function t(name, fn) {
  try { fn(); console.log('  ✓ ' + name); pass++; }
  catch (e) { console.log('  ✗ ' + name + '\n      ' + e.message); fail++; }
}

console.log('\nWeb Bot Auth signature verification');

const kp = generateKeyPair();
const resolver = createStaticResolver([kp.publicJwk], { [kp.kid]: { vendor: 'testvendor' } });
const verifier = createVerifier({ resolver });

function reqWith(sigHeaders, extra = {}) {
  return { method: 'GET', url: '/products/1',
    headers: { host: 'shop.example.com', 'user-agent': 'GPTBot/1.0', ...sigHeaders, ...extra } };
}

t('valid signature verifies', () => {
  const h = signRequest({ method: 'GET', authority: 'shop.example.com', path: '/products/1', privateJwk: kp.privateJwk });
  const r = verifier.verifySync(reqWith(h));
  assert.strictEqual(r.status, 'verified');
  assert.strictEqual(r.agent.vendor, 'testvendor');
});

t('tampered path fails (invalid)', () => {
  const h = signRequest({ method: 'GET', authority: 'shop.example.com', path: '/products/1', privateJwk: kp.privateJwk });
  const r = verifier.verifySync(reqWith(h, { }));   // sign for /products/1 ...
  const bad = reqWith(h); bad.url = '/admin';        // ... but request /admin
  assert.strictEqual(verifier.verifySync(bad).status, 'invalid');
  assert.strictEqual(r.status, 'verified');          // control
});

t('tampered signature bytes fail', () => {
  const h = signRequest({ method: 'GET', authority: 'shop.example.com', path: '/products/1', privateJwk: kp.privateJwk });
  // corrupt the base64 payload between the colons (flip one byte deterministically)
  const flipped = h.signature.replace(/:([A-Za-z0-9+/=]+):/, (_, b64) => {
    const buf = Buffer.from(b64, 'base64'); buf[0] ^= 0xff;
    return ':' + buf.toString('base64') + ':';
  });
  const r = verifier.verifySync(reqWith({ 'signature-input': h['signature-input'], 'signature': flipped }));
  assert.strictEqual(r.status, 'invalid');
});

t('expired signature → expired', () => {
  const h = signRequest({ method: 'GET', authority: 'shop.example.com', path: '/products/1',
    privateJwk: kp.privateJwk, created: Math.floor(Date.now()/1000) - 100000, expiresInSec: 10 });
  assert.strictEqual(verifier.verifySync(reqWith(h)).status, 'expired');
});

t('unknown key → unknown-key', () => {
  const other = generateKeyPair();
  const h = signRequest({ method: 'GET', authority: 'shop.example.com', path: '/products/1', privateJwk: other.privateJwk });
  assert.strictEqual(verifier.verifySync(reqWith(h)).status, 'unknown-key');
});

t('wrong tag → not-wba', () => {
  const h = signRequest({ method: 'GET', authority: 'shop.example.com', path: '/products/1', privateJwk: kp.privateJwk });
  const si = h['signature-input'].replace('web-bot-auth', 'something-else');
  assert.strictEqual(verifier.verifySync(reqWith({ 'signature-input': si, 'signature': h.signature })).status, 'not-wba');
});

t('no signature headers → none', () => {
  assert.strictEqual(verifier.verifySync({ method: 'GET', url: '/', headers: { host: 'x' } }).status, 'none');
});

t('signature over headers (signature-agent) verifies', () => {
  const h = signRequest({ method: 'GET', authority: 'shop.example.com', path: '/products/1',
    privateJwk: kp.privateJwk, components: ['@authority', '@method', '@path', 'signature-agent'],
    headers: { 'signature-agent': 'https://agent.example' } });
  const r = verifier.verifySync(reqWith(h, { 'signature-agent': 'https://agent.example' }));
  assert.strictEqual(r.status, 'verified');
});

t('unsupported component → unsupported (honest)', () => {
  // hand-craft an input referencing an unsupported derived component
  const created = Math.floor(Date.now()/1000);
  const inner = `("@query-param");created=${created};expires=${created+3600};keyid="${kp.kid}";tag="web-bot-auth"`;
  const r = verifier.verifySync(reqWith({ 'signature-input': `sig1=${inner}`, 'signature': 'sig1=:AAAA:' }));
  assert.strictEqual(r.status, 'unsupported');
});

console.log('\nClassifier identity mapping');

t('verified signature → identity verified', () => {
  const gate = createAgentborder({ verifier });
  const h = signRequest({ method: 'GET', authority: 'shop.example.com', path: '/products/1', privateJwk: kp.privateJwk });
  const cls = gate.classify(reqWith(h));
  assert.strictEqual(cls.identity, 'verified');
});

t('invalid signature → identity spoofed', () => {
  const gate = createAgentborder({ verifier });
  const h = signRequest({ method: 'GET', authority: 'shop.example.com', path: '/products/1', privateJwk: kp.privateJwk });
  const bad = reqWith(h); bad.url = '/admin';
  assert.strictEqual(gate.classify(bad).identity, 'spoofed');
});

t('no verifier → signature-presented (never falsely verified)', () => {
  const gate = createAgentborder({});   // free mode, no verifier
  const h = signRequest({ method: 'GET', authority: 'shop.example.com', path: '/products/1', privateJwk: kp.privateJwk });
  assert.strictEqual(gate.classify(reqWith(h)).identity, 'signature-presented');
});

t('human (no UA hint, no signature) → human', () => {
  const gate = createAgentborder({ verifier });
  const cls = gate.classify({ method: 'GET', url: '/', headers: { host: 'x', 'user-agent': 'Mozilla/5.0 Chrome/126' } });
  assert.strictEqual(cls.kind, 'human');
});

console.log('\nAggregating telemetry');

t('rollup aggregates counts, carries no URLs', () => {
  const tel = createTelemetry({ flushIntervalMs: 0, site: 'shop.example.com' });
  for (let i = 0; i < 500; i++) tel.bump({ bot: 'gptbot', category: 'ai-crawler', identity: 'declared', action: 'product.read', outcome: 'would-block', path: '/secret/' + i });
  for (let i = 0; i < 120; i++) tel.bump({ bot: 'oai-searchbot', category: 'ai-search', identity: 'verified', action: 'price.check', outcome: 'pass' });
  const snap = tel.snapshot();
  assert.strictEqual(snap.total, 620);
  const row = snap.rows.find(r => r.bot === 'gptbot');
  assert.strictEqual(row.n, 500);
  assert.ok(!JSON.stringify(snap).includes('/secret/'), 'rollup must not contain URLs');
});

t('rollup compresses many events into few rows', () => {
  const tel = createTelemetry({ flushIntervalMs: 0, site: 's' });
  for (let i = 0; i < 100000; i++) tel.bump({ bot: 'gptbot', category: 'ai-crawler', identity: 'declared', action: 'product.read', outcome: 'would-block' });
  const bytes = Buffer.byteLength(JSON.stringify(tel.snapshot()));
  assert.ok(bytes < 500, `100k events rolled up to ${bytes} bytes (<500)`);
});

console.log(`\n${pass} passed, ${fail} failed\n`);
process.exit(fail ? 1 : 0);
