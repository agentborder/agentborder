#!/usr/bin/env node
/** agentborder CLI dispatcher: `npx agentborder analyze ./access.log` */
'use strict';

const sub = process.argv[2];

if (sub === 'analyze') {
  process.argv.splice(2, 1); // cli.js가 나머지 인자를 그대로 읽도록
  require('../analyze/cli.js');
} else {
  console.log(`agentborder

usage:
  agentborder analyze <access.log>     analyze bots and AI agents in an existing log
  agentborder analyze --sample         try it on a bundled demo log, no setup

middleware (observe live traffic, 3 lines):
  const { createAgentborder } = require('agentborder');
  app.use(createAgentborder(require('./agentborder.config.json')));

docs: https://agentborder.com  ·  Apache-2.0`);
  process.exit(sub ? 1 : 0);
}
