/**
 * agentborder analyze — 집계 엔진 (③-1)
 *
 * 레코드 스트림을 소비해 리포트에 필요한 모든 수치를 만든다.
 * 메모리 상한: 경로 top-K 캡, 미상 UA 샘플 캡, 분 단위 카운터 캡.
 *
 * Exposure Score (0–100, 공식 공개 — 리포트 각주에 그대로 출력):
 *   A. 봇 트래픽 비중        = min(40, 봇비중% × 0.4 × 100)   … 최대 40
 *   B. AI 학습 크롤러 비중   = min(20, ai-crawler비중% × 0.5 × 100) … 최대 20
 *   C. robots.txt 위반률     = min(20, 위반률% × 0.2 × 100)   … 최대 20 (robots 미제공 시 N/A → 만점 80 기준)
 *   D. 미상 봇 비중          = min(10, unknown비중% × 0.5 × 100) … 최대 10
 *   E. 봇의 쓰기 시도        = min(10, 봇 POST 비중% × 1.0 × 100) … 최대 10
 */
'use strict';

const PATH_CAP = 300;        // 봇별 경로 top-K 추적 상한
const UA_SAMPLE_CAP = 50;    // 미상 UA 샘플 상한
const MINUTE_CAP = 200000;   // 분 카운터 전체 상한 (약 138일×봇 여유)

function newBotStat(cls) {
  return {
    id: cls.botId || 'unknown-bot',
    vendor: cls.vendor || null,
    category: cls.category,
    requests: 0, bytes: 0,
    get: 0, post: 0, otherMethod: 0,
    s2xx: 0, s3xx: 0, s404: 0, s4xx: 0, s5xx: 0,
    violations: 0, complianceChecked: 0,
    paths: new Map(),
    minuteCounts: new Map(),
    peakRpm: 0,
  };
}

function createAggregator({ classify, compliance = null }) {
  const agg = {
    total: { requests: 0, bytes: 0 },
    human: { requests: 0, bytes: 0 },
    noUa: { requests: 0, bytes: 0 },
    bots: new Map(),            // botId|'unknown-bot' → stat
    unknownUaSamples: new Map(),// ua → count (cap)
    tsMin: null, tsMax: null,
    minuteEntries: 0,
  };

  function onRecord(r) {
    agg.total.requests++;
    agg.total.bytes += r.bytes;
    if (r.ts) {
      if (!agg.tsMin || r.ts < agg.tsMin) agg.tsMin = r.ts;
      if (!agg.tsMax || r.ts > agg.tsMax) agg.tsMax = r.ts;
    }

    const cls = classify(r.ua);
    if (cls.kind === 'human') { agg.human.requests++; agg.human.bytes += r.bytes; return; }
    if (cls.kind === 'no-ua') { agg.noUa.requests++; agg.noUa.bytes += r.bytes; return; }

    // bot
    const key = cls.botId || 'unknown-bot';
    let b = agg.bots.get(key);
    if (!b) { b = newBotStat(cls); agg.bots.set(key, b); }
    b.requests++; b.bytes += r.bytes;

    if (r.method === 'GET' || r.method === 'HEAD') b.get++;
    else if (r.method === 'POST' || r.method === 'PUT' || r.method === 'DELETE' || r.method === 'PATCH') b.post++;
    else b.otherMethod++;

    if (r.status >= 500) b.s5xx++;
    else if (r.status === 404) { b.s404++; b.s4xx++; }
    else if (r.status >= 400) b.s4xx++;
    else if (r.status >= 300) b.s3xx++;
    else if (r.status >= 200) b.s2xx++;

    if (r.path) {
      if (b.paths.has(r.path)) b.paths.set(r.path, b.paths.get(r.path) + 1);
      else if (b.paths.size < PATH_CAP) b.paths.set(r.path, 1);
    }

    if (r.ts && agg.minuteEntries < MINUTE_CAP) {
      const mk = Math.floor(r.ts.getTime() / 60000);
      const c = (b.minuteCounts.get(mk) || 0) + 1;
      if (!b.minuteCounts.has(mk)) agg.minuteEntries++;
      b.minuteCounts.set(mk, c);
      if (c > b.peakRpm) b.peakRpm = c;
    }

    if (key === 'unknown-bot' && r.ua) {
      if (agg.unknownUaSamples.has(r.ua)) agg.unknownUaSamples.set(r.ua, agg.unknownUaSamples.get(r.ua) + 1);
      else if (agg.unknownUaSamples.size < UA_SAMPLE_CAP) agg.unknownUaSamples.set(r.ua, 1);
    }

    if (compliance && r.path) {
      const verdict = compliance(cls, r.path);
      if (verdict === 'violation') { b.violations++; b.complianceChecked++; }
      else if (verdict === 'allowed') b.complianceChecked++;
    }
  }

  function result() {
    const bots = [...agg.bots.values()].sort((a, b) => b.requests - a.requests);
    const botReq = bots.reduce((s, b) => s + b.requests, 0);
    const botBytes = bots.reduce((s, b) => s + b.bytes, 0);
    const violations = bots.reduce((s, b) => s + b.violations, 0);
    const checked = bots.reduce((s, b) => s + b.complianceChecked, 0);
    const botPost = bots.reduce((s, b) => s + b.post, 0);

    const categories = {};
    for (const b of bots) {
      const c = categories[b.category] || (categories[b.category] = { requests: 0, bytes: 0, bots: 0, violations: 0 });
      c.requests += b.requests; c.bytes += b.bytes; c.bots++; c.violations += b.violations;
    }

    const T = agg.total.requests || 1;
    const share = n => n / T;
    const aiCrawlerReq = categories['ai-crawler'] ? categories['ai-crawler'].requests : 0;
    const unknownReq = agg.bots.get('unknown-bot') ? agg.bots.get('unknown-bot').requests : 0;

    // Exposure Score — 공식은 파일 상단 주석과 동일 (리포트에 노출)
    const sA = Math.min(40, share(botReq) * 0.4 * 100);
    const sB = Math.min(20, share(aiCrawlerReq) * 0.5 * 100);
    const hasRobots = checked > 0;
    const sC = hasRobots ? Math.min(20, (violations / checked) * 0.2 * 100) : null;
    const sD = Math.min(10, share(unknownReq) * 0.5 * 100);
    const sE = Math.min(10, (botReq ? botPost / botReq : 0) * 1.0 * 100);
    const score = Math.round(sA + sB + (sC ?? 0) + sD + sE);
    const scoreMax = hasRobots ? 100 : 80;

    const days = agg.tsMin && agg.tsMax
      ? Math.max(1, (agg.tsMax - agg.tsMin) / 86400000) : null;

    return {
      total: agg.total, human: agg.human, noUa: agg.noUa,
      botTotals: { requests: botReq, bytes: botBytes, post: botPost },
      bots: bots.map(b => ({
        ...b,
        paths: undefined, minuteCounts: undefined,
        topPaths: [...b.paths.entries()].sort((x, y) => y[1] - x[1]).slice(0, 5),
      })),
      categories,
      compliance: { checked, violations, hasRobots },
      unknownUaTop: [...agg.unknownUaSamples.entries()].sort((x, y) => y[1] - x[1]).slice(0, 5),
      timeRange: { from: agg.tsMin, to: agg.tsMax, days },
      score: { value: score, max: scoreMax,
               parts: { botShare: +sA.toFixed(1), aiCrawler: +sB.toFixed(1),
                        robots: sC === null ? null : +sC.toFixed(1),
                        unknown: +sD.toFixed(1), botWrites: +sE.toFixed(1) } },
    };
  }

  return { onRecord, result };
}

/** 비용 추정: 봇 전송량 × 프리셋 단가. 항상 공식·전제를 함께 반환 */
function estimateCost(botBytes, providerKey, pricing) {
  const p = pricing.providers[providerKey];
  if (!p) return null;
  const gb = botBytes / (1024 ** 3);
  return {
    provider: providerKey, label: p.label, usdPerGb: p.usdPerGb,
    gb: +gb.toFixed(2),
    usd: +(gb * p.usdPerGb).toFixed(2),
    formula: `${gb.toFixed(2)} GB × $${p.usdPerGb}/GB`,
    source: p.source, basis: p.basis,
  };
}

module.exports = { createAggregator, estimateCost };
