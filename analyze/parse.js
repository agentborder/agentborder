/**
 * agentborder analyze — 로그 라인 파서 (①-1)
 *
 * 지원 포맷:
 *  - combined : nginx/apache Combined Log Format (UA 포함)
 *  - common   : apache Common Log Format (UA 없음 — 파싱은 되지만 봇 분석 불가 경고)
 *  - jsonl    : JSON Lines (Caddy 및 일반 키 매핑)
 *
 * 원칙: 어떤 입력에서도 throw 하지 않는다. 파싱 실패는 null 반환 → 호출측이 카운트.
 * 정규화 레코드: { ts, ip, method, path, query, status, bytes, referer, ua }
 *   ts: Date|null, bytes: number(불명=0), ua: string|null
 */
'use strict';

const MONTHS = { Jan: 0, Feb: 1, Mar: 2, Apr: 3, May: 4, Jun: 5,
  Jul: 6, Aug: 7, Sep: 8, Oct: 9, Nov: 10, Dec: 11 };

// 1.2.3.4 - user [10/Aug/2026:13:55:36 +0000] "GET /p?q=1 HTTP/1.1" 200 1234 "ref" "ua"
// referer/ua 블록은 옵션(없으면 common 포맷)
const COMBINED_RE = /^(\S+) (\S+) (\S+) \[([^\]]+)\] "([^"]*)" (\d{3}) (\S+)(?: "((?:[^"\\]|\\.)*)" "((?:[^"\\]|\\.)*)")?/;

/** CLF 시간 "10/Aug/2026:13:55:36 +0000" → Date | null */
function parseClfTime(s) {
  const m = /^(\d{2})\/([A-Za-z]{3})\/(\d{4}):(\d{2}):(\d{2}):(\d{2}) ([+-])(\d{2})(\d{2})$/.exec(s);
  if (!m) return null;
  const mon = MONTHS[m[2]];
  if (mon === undefined) return null;
  const utc = Date.UTC(+m[3], mon, +m[1], +m[4], +m[5], +m[6]);
  const offMin = (+m[8]) * 60 + (+m[9]);
  const off = (m[7] === '-' ? -1 : 1) * offMin * 60000;
  return new Date(utc - off);
}

/** "GET /p?q=1 HTTP/1.1" → { method, path, query } (불량 요청 문자열 허용) */
function splitRequest(req) {
  if (!req || req === '-') return { method: null, path: null, query: null };
  const parts = req.split(' ');
  if (parts.length < 2) return { method: null, path: req.slice(0, 200), query: null };
  const method = /^[A-Z]{3,10}$/.test(parts[0]) ? parts[0] : null;
  const target = parts[1] || '';
  const qi = target.indexOf('?');
  return {
    method,
    path: qi === -1 ? target : target.slice(0, qi),
    query: qi === -1 ? null : target.slice(qi + 1),
  };
}

/** combined/common 한 줄 → record | null */
function parseCombined(line) {
  const m = COMBINED_RE.exec(line);
  if (!m) return null;
  const { method, path, query } = splitRequest(m[5]);
  const bytes = m[7] === '-' ? 0 : Number(m[7]);
  return {
    ts: parseClfTime(m[4]),
    ip: m[1],
    method, path, query,
    status: Number(m[6]),
    bytes: Number.isFinite(bytes) ? bytes : 0,
    referer: m[8] !== undefined && m[8] !== '-' ? m[8] : null,
    ua: m[9] !== undefined ? (m[9] === '-' ? null : m[9]) : null, // undefined 그룹 = common 포맷
    _hasUaField: m[9] !== undefined,
  };
}

/* ── JSON Lines ──────────────────────────────────────────── */

function pick(obj, keys) {
  for (const k of keys) if (obj[k] !== undefined && obj[k] !== null) return obj[k];
  return undefined;
}

function parseTsValue(v) {
  if (v === undefined) return null;
  if (typeof v === 'number') {
    // 초/밀리초 자동 판별 (1e12 미만 = 초 단위로 간주)
    const ms = v < 1e12 ? v * 1000 : v;
    const d = new Date(ms);
    return isNaN(d) ? null : d;
  }
  if (typeof v === 'string') {
    const d = new Date(v);
    return isNaN(d) ? null : d;
  }
  return null;
}

/** JSON 한 줄 → record | null. Caddy 구조와 평평한 일반 키를 모두 지원 */
function parseJsonLine(line) {
  let o;
  try { o = JSON.parse(line); } catch { return null; }
  if (typeof o !== 'object' || o === null) return null;

  const req = (typeof o.request === 'object' && o.request) || null; // Caddy
  const headers = (req && typeof req.headers === 'object' && req.headers) || null;

  let ua = pick(o, ['ua', 'user_agent', 'userAgent', 'agent', 'http_user_agent']);
  if (ua === undefined && headers) {
    const h = headers['User-Agent'] || headers['user-agent'];
    ua = Array.isArray(h) ? h[0] : h;
  }
  let referer = pick(o, ['referer', 'referrer', 'http_referer']);
  if (referer === undefined && headers) {
    const h = headers['Referer'] || headers['referer'];
    referer = Array.isArray(h) ? h[0] : h;
  }

  const rawTarget = pick(o, ['path', 'url', 'uri', 'request_path']) ??
                    (req ? pick(req, ['uri', 'url', 'path']) : undefined);
  let path = null, query = null;
  if (typeof rawTarget === 'string') {
    const qi = rawTarget.indexOf('?');
    path = qi === -1 ? rawTarget : rawTarget.slice(0, qi);
    query = qi === -1 ? null : rawTarget.slice(qi + 1);
  }

  const method = pick(o, ['method', 'verb']) ?? (req ? req.method : undefined) ?? null;
  const statusRaw = pick(o, ['status', 'status_code', 'statusCode', 'response_code']);
  const bytesRaw = pick(o, ['bytes', 'size', 'body_bytes_sent', 'bytes_sent', 'response_size']);
  const ip = pick(o, ['ip', 'remote_addr', 'remote_ip', 'client_ip']) ??
             (req ? pick(req, ['remote_ip', 'remote_addr', 'client_ip']) : undefined) ?? null;

  // 로그 레코드로 볼 최소 조건: 경로나 상태 중 하나는 있어야 함
  if (path === null && statusRaw === undefined) return null;

  const status = Number(statusRaw);
  const bytes = Number(bytesRaw);
  return {
    ts: parseTsValue(pick(o, ['ts', 'time', 'timestamp', '@timestamp', 'date'])),
    ip: typeof ip === 'string' ? ip : null,
    method: typeof method === 'string' ? method.toUpperCase() : null,
    path, query,
    status: Number.isFinite(status) ? status : 0,
    bytes: Number.isFinite(bytes) ? bytes : 0,
    referer: typeof referer === 'string' && referer !== '-' ? referer : null,
    ua: typeof ua === 'string' && ua !== '-' ? ua : null,
    _hasUaField: ua !== undefined,
  };
}

/* ── 포맷 감지 ───────────────────────────────────────────── */

/** 첫 유효 줄로 포맷 판정: 'jsonl' | 'combined' | 'unknown' */
function detectFormat(line) {
  const t = line.trimStart();
  if (t.startsWith('{')) return 'jsonl';
  if (COMBINED_RE.test(line)) return 'combined';
  return 'unknown';
}

function parseLine(line, format) {
  return format === 'jsonl' ? parseJsonLine(line) : parseCombined(line);
}

module.exports = { parseCombined, parseJsonLine, parseLine, detectFormat, parseClfTime, splitRequest, COMBINED_RE };
