/**
 * agentborder analyze — UA 분류기 (②-1)
 *
 * classify(ua) →
 *   { kind: 'human' }
 *   { kind: 'bot', botId, vendor, category, robotsToken }
 *   { kind: 'bot', botId: null, vendor: null, category: 'unknown-bot', robotsToken: null }
 *   { kind: 'no-ua' }   — UA 문자열 자체가 없음
 *
 * 원칙: UA는 자기주장이다. 이 분류는 "declared identity"이며 암호 검증이 아니다.
 * (사칭 검증은 --verify-ips 옵트인 기능 — 별도 모듈, 기본 오프라인 원칙 유지)
 */
'use strict';

const DATA = require('./data/bots.json');

function buildClassifier(data = DATA) {
  const bots = data.bots
    .filter(b => b.uaVisible !== false) // robots 전용 토큰은 UA 매칭에서 제외
    .map(b => ({ ...b, re: new RegExp(b.match, 'i') }));
  const hints = data.botHints.map(h => new RegExp(h, 'i'));

  function classify(ua) {
    if (ua === null || ua === undefined || ua === '') return { kind: 'no-ua' };
    for (const b of bots) {
      if (b.re.test(ua)) {
        return { kind: 'bot', botId: b.id, vendor: b.vendor,
                 category: b.category, robotsToken: b.robotsToken };
      }
    }
    for (const h of hints) {
      if (h.test(ua)) {
        return { kind: 'bot', botId: null, vendor: null,
                 category: 'unknown-bot', robotsToken: null };
      }
    }
    return { kind: 'human' };
  }

  classify.datasetVersion = data.version;
  classify.botCount = bots.length;
  return classify;
}

module.exports = { buildClassifier, DATASET: DATA };
