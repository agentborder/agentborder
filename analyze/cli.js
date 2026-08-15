#!/usr/bin/env node
/**
 * agentborder analyze — CLI 진입점 (③-3)
 * 사용: node analyze/cli.js <access.log> [--robots robots.txt] [--provider vercel-pro] [--json out.json] [--no-color]
 * 원칙: 100% 오프라인 · 읽기 전용 · 어떤 입력에도 스택트레이스를 사용자에게 던지지 않는다.
 */
'use strict';

const fs = require('node:fs');
const { readLog } = require('./reader.js');
const { buildClassifier, DATASET } = require('./classify.js');
const { buildComplianceChecker } = require('./robots.js');
const { createAggregator, estimateCost } = require('./aggregate.js');
const { render } = require('./report-terminal.js');
const PRICING = require('./data/pricing.json');

function parseArgs(argv) {
  const a = { file: null, robots: null, provider: null, json: null, html: null,
              card: null, compare: null, sample: false, site: null, color: true };
  for (let i = 0; i < argv.length; i++) {
    const v = argv[i];
    if (v === '--robots') a.robots = argv[++i];
    else if (v === '--provider') a.provider = argv[++i];
    else if (v === '--json') a.json = argv[++i];
    else if (v === '--html') a.html = argv[++i];
    else if (v === '--card') a.card = argv[++i];
    else if (v === '--compare') a.compare = argv[++i];
    else if (v === '--site') a.site = argv[++i];
    else if (v === '--sample') a.sample = true;
    else if (v === '--no-color') a.color = false;
    else if (!v.startsWith('-') && !a.file) a.file = v;
  }
  return a;
}

async function main() {
  const args = parseArgs(process.argv.slice(2));

  if (args.sample) {
    // 동봉 샘플로 30초 체험 — 내 로그 없이도 전체 흐름을 본다
    const path = require('node:path');
    args.file = path.join(__dirname, 'data', 'sample.log');
    if (!args.robots) args.robots = path.join(__dirname, 'data', 'sample-robots.txt');
    if (!args.provider) args.provider = 'generic';
    console.log('\n  (sample mode: bundled demo log. try your own next: agentborder analyze ./access.log)');
  }

  if (!args.file) {
    console.error('usage: agentborder analyze <access.log> [--sample] [--robots robots.txt] [--provider vercel-pro|netlify-pro|cloudfront|generic] [--html out.html] [--json out.json] [--card card.html] [--compare prev.json] [--site name] [--no-color]');
    process.exit(1);
  }

  let compliance = null;
  if (args.robots) {
    try { compliance = buildComplianceChecker(fs.readFileSync(args.robots, 'utf8')); }
    catch { console.error(`error: cannot read robots file: ${args.robots}`); process.exit(1); }
  }
  if (args.provider && !PRICING.providers[args.provider]) {
    console.error(`error: unknown provider "${args.provider}" (available: ${Object.keys(PRICING.providers).join(', ')})`);
    process.exit(1);
  }

  const classify = buildClassifier();
  const agg = createAggregator({ classify, compliance });
  const stats = await readLog(args.file, { onRecord: agg.onRecord });

  if (stats.fatal) { console.error(`error: ${stats.fatal}`); process.exit(1); }

  const res = agg.result();
  const cost = args.provider ? estimateCost(res.botTotals.bytes, args.provider, PRICING) : null;

  console.log(render(res, {
    cost, datasetVersion: DATASET.version, warnings: stats.warnings, color: args.color && process.stdout.isTTY !== false,
  }));

  if (args.compare) {
    const { loadPrev, diff, renderCompare } = require('./compare.js');
    let prev = null;
    try { prev = loadPrev(fs.readFileSync(args.compare, 'utf8')); } catch { /* 아래 경고 */ }
    if (prev) console.log(renderCompare(diff(prev, res), { color: args.color && process.stdout.isTTY !== false }));
    else console.log(`  ⚠ cannot read previous report (${args.compare}), expected a --json output file. skipping comparison\n`);
  }

  if (args.card) {
    const { renderCard } = require('./card.js');
    try {
      fs.writeFileSync(args.card, renderCard(res, { cost, site: args.site }));
      console.log(`  share card written: ${args.card}  (open → screenshot → post)\n`);
    } catch (e) { console.error(`error: cannot write ${args.card}: ${e.message}`); process.exit(1); }
  }

  if (args.html) {
    const { renderHtml } = require('./report-html.js');
    const html = renderHtml(res, {
      cost, datasetVersion: DATASET.version, pricingVersion: PRICING.version,
      inputStats: { parsed: stats.parsed, malformed: stats.malformed, format: stats.format },
      warnings: stats.warnings, botDocs: DATASET.bots,
    });
    try { fs.writeFileSync(args.html, html); console.log(`  full report written: ${args.html}\n`); }
    catch (e) { console.error(`error: cannot write ${args.html}: ${e.message}`); process.exit(1); }
  }

  if (args.json) {
    const out = {
      generatedAt: new Date().toISOString(),
      dataset: { bots: DATASET.version, pricing: PRICING.version },
      input: { file: stats.file, format: stats.format, totalLines: stats.totalLines,
               parsed: stats.parsed, malformed: stats.malformed, warnings: stats.warnings },
      report: res, cost,
      notes: [
        'bot identity = self-declared User-Agent (not cryptographically verified)',
        'robots.txt evaluation per RFC 9309',
        'cost figures are estimates; formula and source included in `cost`',
      ],
    };
    try { fs.writeFileSync(args.json, JSON.stringify(out, null, 2)); console.log(`  full data written: ${args.json}\n`); }
    catch (e) { console.error(`error: cannot write ${args.json}: ${e.message}`); process.exit(1); }
  }
}

main().catch(e => { console.error('error: ' + (e && e.message || e)); process.exit(1); });
