/**
 * Agentborder Core (OSS) v0.1.0
 * AI 봇·에이전트 트래픽을 "행위 단위"로 관찰하고 제어하는 제로 의존성 미들웨어.
 *
 * 설계 원칙 (README 참조):
 *  1. fail-open  : 게이트 내부 오류는 절대 사이트를 막지 않는다. 모든 평가는 try/catch로 감싼다.
 *  2. monitor 우선: 기본 모드는 관찰(monitor). 아무것도 차단하지 않고 기록만 한다.
 *  3. 인간 무간섭 : 봇으로 분류되지 않은 요청은 즉시 통과하며 개별 로그도 남기지 않는다.
 *  4. 카나리 다이얼: enforce 전환도 트래픽의 N%부터. 언제든 monitor로 즉시 롤백.
 *
 * 의존성 0개. Node 18+ 의 내장 모듈만 사용한다.
 */

'use strict';

const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');

const DEFAULT_CATALOG = require('./catalog.json');
const verify = require('./verify.js');
const { createTelemetry } = require('./telemetry.js');

/* ── 유틸 ─────────────────────────────────────────────── */

function globToRegex(glob) {
  // "GET /api/v1/products/*" 형태의 매치 문자열을 정규식으로.
  const esc = glob.replace(/[.+?^${}()|[\]\\]/g, '\\$&').replace(/\*/g, '.*');
  return new RegExp('^' + esc + '$', 'i');
}

function bucketOf(str, salt) {
  // 카나리 배정용 결정적 해시 버킷(0-99). 같은 클라이언트는 항상 같은 버킷.
  const h = crypto.createHash('sha1').update(salt + '|' + str).digest();
  return h.readUInt16BE(0) % 100;
}

/* ── 분류기 ───────────────────────────────────────────── */

function buildClassifier(catalog, verifier) {
  const bots = catalog.bots.map(b => ({ ...b, re: new RegExp(b.match, 'i') }));
  const hints = (catalog.botHints || []).map(h => new RegExp(h, 'i'));

  // 신원 계층: Web Bot Auth 서명(RFC 9421)을 실제로 암호 검증한다.
  // verifier가 없으면(무료 스냅샷 모드) 서명 "제시됨"까지만 표시한다.
  // 검증 없이 'verified'를 표기하지 않는다(정직성 원칙).
  function identityOf(req) {
    const hasSig = !!(req.headers['signature'] && req.headers['signature-input']);
    if (!hasSig) return { identity: 'declared', verified: null };
    if (!verifier) return { identity: 'signature-presented', verified: null };
    const v = verifier.verifySync(req);
    switch (v.status) {
      case 'verified':    return { identity: 'verified', verified: v };
      case 'invalid':     return { identity: 'spoofed', verified: v };   // 서명 실패 = 사칭
      case 'expired':     return { identity: 'signature-presented', verified: v };
      case 'unknown-key': return { identity: 'signature-presented', verified: v };
      case 'none':        return { identity: 'declared', verified: null };
      default:            return { identity: 'signature-presented', verified: v };
    }
  }

  return function classify(req) {
    const ua = String(req.headers['user-agent'] || '');
    const id = identityOf(req);

    for (const b of bots) {
      if (b.re.test(ua)) {
        return { kind: 'bot', botId: b.id, vendor: b.vendor, category: b.category,
                 identity: id.identity, verified: id.verified };
      }
    }
    for (const h of hints) {
      if (h.test(ua)) {
        return { kind: 'bot', botId: null, vendor: null, category: 'unknown-bot',
                 identity: id.identity, verified: id.verified };
      }
    }
    // UA에 봇 힌트가 없어도, 유효 서명을 제시하면 봇으로 취급(정직한 자기신고 에이전트).
    if (id.identity === 'verified' || id.identity === 'spoofed')
      return { kind: 'bot', botId: null, vendor: id.verified?.agent?.vendor || null,
               category: 'signed-agent', identity: id.identity, verified: id.verified };
    return { kind: 'human' };
  };
}

/* ── 정책 평가 (캐스케이드) ───────────────────────────── */
/* 우선순위: 개별 봇 > 벤더 > 카테고리 > 기본값(monitor)   */

function buildPolicy(config) {
  const actions = (config.actions || []).map(a => ({
    ...a, res: (a.match || []).map(globToRegex),
  }));

  function matchAction(req) {
    const key = req.method + ' ' + (req.url || '').split('?')[0];
    for (const a of actions) if (a.res.some(re => re.test(key))) return a;
    return { id: 'unmatched', label: '(미정의 행위)' };
  }

  function decide(cls, action) {
    const rules = config.rules || [];
    const pick = (pred) => rules.find(r =>
      pred(r) && (r.action === '*' || r.action === action.id ||
        (Array.isArray(r.action) && r.action.includes(action.id))));

    const rule =
      (cls.botId && pick(r => r.bot === cls.botId)) ||
      (cls.vendor && pick(r => r.vendor === cls.vendor)) ||
      pick(r => r.category === cls.category) ||
      null;

    return rule ? { effect: rule.effect, limit: rule.limit || null, ruleFrom: rule }
                : { effect: config.defaultEffect || 'monitor', limit: null, ruleFrom: null };
  }

  return { matchAction, decide };
}

/* ── 속도 제한 (메모리 슬라이딩 윈도우) ────────────────── */

function buildLimiter() {
  const windows = new Map(); // key -> [timestamps]
  return function exceeded(key, perMinute) {
    const now = Date.now();
    let arr = windows.get(key);
    if (!arr) { arr = []; windows.set(key, arr); }
    while (arr.length && now - arr[0] > 60_000) arr.shift();
    arr.push(now);
    if (windows.size > 10_000) windows.clear(); // 메모리 상한 안전장치
    return arr.length > perMinute;
  };
}

/* ── 텔레메트리 (로컬 JSONL, 비동기·베스트에포트) ─────── */

function buildLogger(config) {
  const file = config.eventLog === false ? null
    : path.resolve(config.eventLog || './agentborder-events.jsonl');
  return function log(event) {
    if (!file) return;
    fs.appendFile(file, JSON.stringify(event) + '\n', () => { /* 실패해도 무시: fail-open */ });
  };
}

/* ── 메인 팩토리 ──────────────────────────────────────── */

function createAgentborder(userConfig = {}) {
  const config = { mode: 'monitor', enforcePercent: 100, ...userConfig };
  const catalog = config.catalog || DEFAULT_CATALOG;
  const classify = buildClassifier(catalog, config.verifier || null);  // config.verifier: Web Bot Auth 검증 엔진(유료). 없으면 서명 제시 표시만.
  const { matchAction, decide } = buildPolicy(config);
  const exceeded = buildLimiter();
  const log = buildLogger(config);
  const telemetry = config.telemetry || null;                          // config.telemetry: 집계 텔레메트리(선택). 있으면 rollup으로 전송.
  const salt = crypto.randomBytes(8).toString('hex');

  function middleware(req, res, next) {
    try {
      const cls = classify(req);

      /* 원칙 3: 인간은 즉시 통과, 개별 로그 없음 */
      if (cls.kind !== 'bot') return next();

      const action = matchAction(req);
      const d = decide(cls, action);

      /* 모드·카나리: 실제 집행 여부 결정 */
      const mode = process.env.AGENTBORDER_MODE || config.mode; // 환경변수로 즉시 롤백 가능
      const inCanary = bucketOf(String(req.headers['user-agent']), salt) <
                       (Number(process.env.AGENTBORDER_ENFORCE_PERCENT || config.enforcePercent));
      const enforce = mode === 'enforce' && inCanary;

      let outcome = 'pass';
      if (d.effect === 'block') outcome = enforce ? 'blocked' : 'would-block';
      else if (d.effect === 'ratelimit') {
        const over = exceeded(cls.botId + '|' + action.id, d.limit || 60);
        outcome = over ? (enforce ? 'limited' : 'would-limit') : 'pass';
      } else if (d.effect === 'allow') outcome = 'pass';

      const event = {
        t: new Date().toISOString(), bot: cls.botId || 'unknown', vendor: cls.vendor,
        category: cls.category, identity: cls.identity,
        action: action.id, path: (req.url || '').split('?')[0], method: req.method,
        effect: d.effect, outcome, enforced: enforce,
      };
      log(event);                                   // 원본 이벤트 로컬 기록(무료 리포트용)
      if (telemetry) telemetry.bump(event);         // 집계 카운터에만 반영(경로 밖에서 rollup 전송)

      res.setHeader?.('X-Agentborder', outcome);

      if (outcome === 'blocked') {
        res.statusCode = 403;
        res.setHeader('Content-Type', 'text/plain; charset=utf-8');
        return res.end('Forbidden by site policy (agentborder)');
      }
      if (outcome === 'limited') {
        res.statusCode = 429;
        res.setHeader('Retry-After', '60');
        return res.end('Rate limited by site policy (agentborder)');
      }
      return next();
    } catch (err) {
      /* 원칙 1: 게이트의 어떤 오류도 사이트를 막지 않는다 */
      try { log({ t: new Date().toISOString(), error: String(err), outcome: 'fail-open' }); } catch {}
      return next();
    }
  }

  middleware.classify = classify;   // 테스트·WASM 리플레이용 노출
  middleware.config = config;
  return middleware;
}

module.exports = {
  createAgentborder,
  createVerifier: verify.createVerifier,
  createStaticResolver: verify.createStaticResolver,
  createDirectoryResolver: verify.createDirectoryResolver,
  createTelemetry,
};
