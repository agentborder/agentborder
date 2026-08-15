/**
 * agentborder analyze — 스트리밍 로그 리더 (①-2)
 *
 * 원칙:
 *  - 스트리밍: 파일 전체를 메모리에 올리지 않는다 (GB급 로그 대응)
 *  - 제로 크래시: 어떤 줄에서도 throw 하지 않는다. 불량 줄은 카운트 + 샘플 보존
 *  - 오프라인: 네트워크 호출 없음
 *
 * 사용:
 *   const { readLog } = require('./reader');
 *   const stats = await readLog('./access.log', { onRecord: r => {...} });
 */
'use strict';

const fs = require('node:fs');
const readline = require('node:readline');
const { parseLine, detectFormat } = require('./parse.js');

const MAX_ERROR_SAMPLES = 5;
const MAX_LINE_LEN = 32 * 1024; // 비정상 초장문 줄 방어

/**
 * @param {string} filePath
 * @param {object} opts
 *   format: 'auto'|'combined'|'jsonl' (기본 auto)
 *   onRecord: (record) => void  — 파싱 성공한 레코드마다 호출
 * @returns {Promise<stats>} — 실패 시에도 reject 하지 않고 stats.fatal 에 사유 기록
 */
async function readLog(filePath, opts = {}) {
  const { format: wantFormat = 'auto', onRecord = () => {} } = opts;

  const stats = {
    file: filePath,
    format: wantFormat === 'auto' ? null : wantFormat,
    totalLines: 0,      // 빈 줄 제외 전체 줄 수
    parsed: 0,          // 정상 파싱 레코드 수
    malformed: 0,       // 파싱 실패 줄 수
    noUaRecords: 0,     // UA 필드 자체가 없는 레코드 수 (common 포맷 감지용)
    errorSamples: [],   // 불량 줄 샘플 (최대 5)
    bytesRead: 0,
    fatal: null,        // 파일 열기 실패 / 포맷 판정 불가 등
    warnings: [],
  };

  // 파일 존재·크기 확인 (throw 대신 fatal 기록)
  let st;
  try { st = fs.statSync(filePath); }
  catch { stats.fatal = `file not found or unreadable: ${filePath}`; return stats; }
  if (st.isDirectory()) { stats.fatal = `path is a directory: ${filePath}`; return stats; }
  if (st.size === 0) { stats.fatal = 'file is empty'; return stats; }
  stats.bytesRead = st.size;

  const stream = fs.createReadStream(filePath, { encoding: 'utf8' });
  const rl = readline.createInterface({ input: stream, crlfDelay: Infinity });

  try {
    for await (let line of rl) {
      if (line.length === 0 || /^\s*$/.test(line)) continue;
      stats.totalLines++;
      if (line.length > MAX_LINE_LEN) line = line.slice(0, MAX_LINE_LEN);

      // 첫 유효 줄에서 포맷 자동 감지
      if (stats.format === null) {
        const detected = detectFormat(line);
        if (detected === 'unknown') {
          // 다음 몇 줄 더 시도해볼 수 있게, 감지 실패 줄은 malformed 처리 후 계속
          stats.malformed++;
          if (stats.errorSamples.length < MAX_ERROR_SAMPLES) stats.errorSamples.push(line.slice(0, 200));
          if (stats.malformed >= 10 && stats.parsed === 0) {
            stats.fatal = 'unrecognized log format (supported: nginx/apache combined, JSON lines)';
            rl.close();
            break;
          }
          continue;
        }
        stats.format = detected;
      }

      const rec = parseLine(line, stats.format);
      if (rec === null) {
        stats.malformed++;
        if (stats.errorSamples.length < MAX_ERROR_SAMPLES) stats.errorSamples.push(line.slice(0, 200));
        continue;
      }
      if (!rec._hasUaField) stats.noUaRecords++;
      stats.parsed++;
      try { onRecord(rec); } catch { /* 소비자 오류도 리더를 죽이지 않는다 */ }
    }
  } catch (err) {
    stats.fatal = `read error: ${String(err && err.message || err)}`;
  } finally {
    rl.close();
    stream.destroy();
  }

  // 경고 생성
  if (!stats.fatal) {
    if (stats.parsed === 0) {
      stats.fatal = 'no parseable log lines found';
    } else {
      const uaMissingRatio = stats.noUaRecords / stats.parsed;
      if (uaMissingRatio > 0.9) {
        stats.warnings.push(
          'log has no User-Agent field (Common Log Format?) — bot analysis requires combined format');
      }
      const malformedRatio = stats.malformed / stats.totalLines;
      if (malformedRatio > 0.05) {
        stats.warnings.push(
          `${(malformedRatio * 100).toFixed(1)}% of lines could not be parsed (${stats.malformed}/${stats.totalLines})`);
      }
    }
  }
  return stats;
}

module.exports = { readLog };
