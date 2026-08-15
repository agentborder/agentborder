/**
 * Agentborder — aggregating telemetry.
 *
 * WHY: sending raw per-request events to a hosted collector does not scale
 * (a busy site can emit 100k+ bot events/day). Instead we keep an in-memory
 * counter keyed by (bot, category, identity, action, outcome) and flush a
 * COMPACT rollup once per interval. A site emitting millions of bot requests
 * produces a few KB/hour — the fleet stays cheap at thousands of domains.
 *
 * The rollup carries counts only — no URLs, no IPs, no user data — which also
 * keeps it out of most privacy-regulation scope (still: legal review before GA).
 * The hosted console consumes these rollups to power benchmarks and the D+7
 * savings report; the OSS core can also just write them to disk.
 */
'use strict';

const fs = require('node:fs');

function createTelemetry({
  flushIntervalMs = 3600_000,        // 1 hour
  onFlush = null,                    // async (rollup) => void  (POST to collector)
  file = null,                       // optional local JSONL sink
  site = 'unknown',
} = {}) {
  let counts = new Map();            // key -> n
  let windowStart = null;            // ISO; set lazily (no Date.now at construct in some envs)

  function bump(ev) {
    if (!windowStart) windowStart = new Date().toISOString();
    const key = [ev.bot || 'unknown', ev.category || 'unknown',
                 ev.identity || 'na', ev.action || 'na', ev.outcome || 'na'].join('|');
    counts.set(key, (counts.get(key) || 0) + 1);
  }

  function snapshot() {
    const rows = [];
    for (const [k, n] of counts) {
      const [bot, category, identity, action, outcome] = k.split('|');
      rows.push({ bot, category, identity, action, outcome, n });
    }
    return {
      site,
      window_start: windowStart,
      window_end: new Date().toISOString(),
      total: rows.reduce((a, r) => a + r.n, 0),
      rows,
    };
  }

  async function flush() {
    if (counts.size === 0) return null;
    const rollup = snapshot();
    counts = new Map(); windowStart = null;
    if (file) { try { fs.appendFileSync(file, JSON.stringify(rollup) + '\n'); } catch {} }
    if (onFlush) { try { await onFlush(rollup); } catch { /* fail-open: drop, don't crash */ } }
    return rollup;
  }

  let timer = null;
  if (flushIntervalMs > 0) {
    timer = setInterval(() => { flush(); }, flushIntervalMs);
    if (timer.unref) timer.unref();               // never keep the process alive for telemetry
  }

  return { bump, flush, snapshot, stop: () => timer && clearInterval(timer) };
}

module.exports = { createTelemetry };
