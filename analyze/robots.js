/**
 * agentborder analyze — robots.txt 파서·준수 판정 (②-2)
 *
 * 근거 표준: RFC 9309 (Robots Exclusion Protocol, 2022-09)
 *  - 그룹 선택: product token과 가장 길게 일치하는 user-agent 그룹, 없으면 "*" 그룹
 *  - 규칙 선택: path와 매칭되는 규칙 중 패턴이 가장 긴(most specific) 것
 *  - 동률: allow 우선 (least restrictive)
 *  - 와일드카드 "*", 끝 고정 "$" 지원. 빈 Disallow = 제한 없음
 *  - user-agent 비교는 대소문자 무시, path 비교는 대소문자 구분
 *
 * v1 한계(문서화): percent-encoding 정규화 미지원.
 */
'use strict';

/** robots.txt 원문 → { groups, sitemaps, parseErrors } */
function parseRobots(text) {
  const groups = [];      // { agents: [lowercase], rules: [{type, pattern}] }
  const sitemaps = [];
  let cur = null;         // 현재 그룹
  let lastWasAgent = false;
  let parseErrors = 0;

  for (let raw of String(text).split(/\r?\n/)) {
    const hash = raw.indexOf('#');
    if (hash !== -1) raw = raw.slice(0, hash);
    const line = raw.trim();
    if (!line) continue;

    const ci = line.indexOf(':');
    if (ci === -1) { parseErrors++; continue; }
    const field = line.slice(0, ci).trim().toLowerCase();
    const value = line.slice(ci + 1).trim();

    if (field === 'user-agent') {
      if (!lastWasAgent) { cur = { agents: [], rules: [] }; groups.push(cur); }
      cur.agents.push(value.toLowerCase());
      lastWasAgent = true;
    } else if (field === 'allow' || field === 'disallow') {
      lastWasAgent = false;
      if (!cur) { parseErrors++; continue; } // 그룹 없는 규칙 줄
      cur.rules.push({ type: field, pattern: value });
    } else if (field === 'sitemap') {
      sitemaps.push(value);
      lastWasAgent = false;
    } else {
      // crawl-delay 등 비표준/기타 필드 — 그룹 경계만 갱신
      lastWasAgent = false;
    }
  }
  return { groups, sitemaps, parseErrors };
}

/** 패턴("*", "$" 지원) → 경로 선두 매칭 정규식 */
function patternToRegex(pattern) {
  let p = pattern;
  let anchored = false;
  if (p.endsWith('$')) { anchored = true; p = p.slice(0, -1); }
  const esc = p.replace(/[.+?^${}()|[\]\\]/g, '\\$&').replace(/\*/g, '.*');
  return new RegExp('^' + esc + (anchored ? '$' : ''));
}

/** product token에 해당하는 그룹 선택 (RFC 9309: 가장 긴 일치, 폴백 "*") */
function selectGroup(groups, productToken) {
  const token = String(productToken || '').toLowerCase();
  let best = null, bestLen = -1, star = null;
  for (const g of groups) {
    for (const a of g.agents) {
      if (a === '*') { if (!star) star = g; continue; }
      if (token.includes(a) && a.length > bestLen) { best = g; bestLen = a.length; }
    }
  }
  return best || star || null;
}

/**
 * 판정: 이 봇(product token)이 이 path에 접근해도 되는가
 * @returns { allowed: boolean, rule: {type,pattern}|null, group: 'specific'|'star'|null }
 */
function isAllowed(robots, productToken, path) {
  const g = selectGroup(robots.groups, productToken);
  if (!g) return { allowed: true, rule: null, group: null };

  let best = null, bestLen = -1;
  for (const r of g.rules) {
    if (r.pattern === '') continue;               // 빈 Disallow/Allow = 무제한/무의미
    if (patternToRegex(r.pattern).test(path)) {
      const len = r.pattern.length;
      if (len > bestLen || (len === bestLen && r.type === 'allow' && best && best.type === 'disallow')) {
        best = r; bestLen = len;
      }
    }
  }
  if (!best) return { allowed: true, rule: null, group: g.agents.includes('*') ? 'star' : 'specific' };
  return {
    allowed: best.type === 'allow',
    rule: best,
    group: g.agents.includes('*') && g.agents.length === 1 ? 'star' : 'specific',
  };
}

/**
 * 준수 검사기: 분류 결과 + path → 'allowed' | 'violation' | 'not-applicable'
 * (robotsToken 없는 unknown-bot은 "*" 그룹 기준으로 판정)
 */
function buildComplianceChecker(robotsText) {
  const robots = parseRobots(robotsText);
  function check(classification, path) {
    if (!classification || classification.kind !== 'bot' || !path) return 'not-applicable';
    const token = classification.robotsToken || classification.botId || '*unknown*';
    const v = isAllowed(robots, token, path);
    return v.allowed ? 'allowed' : 'violation';
  }
  check.robots = robots;
  return check;
}

module.exports = { parseRobots, isAllowed, selectGroup, patternToRegex, buildComplianceChecker };
