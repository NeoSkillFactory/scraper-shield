'use strict';

const { analyzeRequest, createMiddleware } = require('../index');
const { loadConfig } = require('../config');

let passed = 0;
let failed = 0;

function assert(condition, msg) {
  if (condition) {
    passed++;
    console.log(`  PASS: ${msg}`);
  } else {
    failed++;
    console.error(`  FAIL: ${msg}`);
  }
}

console.log('=== integration tests ===\n');

// Test: analyzeRequest with scraper
{
  const result = analyzeRequest({ ip: '10.0.0.1', ua: 'python-requests/2.28' });
  assert(result.blocked === true, 'analyzeRequest blocks python-requests');
  assert(result.threat === 'high', 'threat level is high');
}

// Test: analyzeRequest with normal browser
{
  const result = analyzeRequest({
    ip: '10.0.0.2',
    ua: 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Safari/537.36',
    headers: {
      'user-agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Safari/537.36',
      'accept-language': 'en-US',
      'accept-encoding': 'gzip',
      'accept': 'text/html'
    }
  });
  assert(result.blocked === false, 'normal browser not blocked');
  assert(result.threat === 'none', 'normal browser no threat');
}

// Test: middleware creation
{
  const mw = createMiddleware({ endpoints: { '/api/*': { mode: 'strict', rateLimit: 100 } } });
  assert(typeof mw === 'function', 'createMiddleware returns a function');
}

// Test: middleware blocks scrapers in strict mode
{
  const mw = createMiddleware({ endpoints: { '/api/*': { mode: 'strict', rateLimit: 100 } }, logBlocked: false });

  let statusCode = null;
  let jsonBody = null;
  let nextCalled = false;

  const req = {
    path: '/api/data',
    url: '/api/data',
    ip: '10.0.0.3',
    headers: { 'user-agent': 'python-requests/2.28.1' },
    connection: { remoteAddress: '10.0.0.3' }
  };
  const res = {
    status(code) { statusCode = code; return this; },
    json(body) { jsonBody = body; }
  };
  const next = () => { nextCalled = true; };

  mw(req, res, next);
  assert(statusCode === 403, 'scraper gets 403 in strict mode');
  assert(nextCalled === false, 'next not called for blocked request');
}

// Test: middleware allows normal users
{
  const mw = createMiddleware({ endpoints: { '/api/*': { mode: 'strict', rateLimit: 100 } }, logBlocked: false });

  let nextCalled = false;

  const req = {
    path: '/api/data',
    url: '/api/data',
    ip: '10.0.0.4',
    headers: {
      'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0 Safari/537.36',
      'accept-language': 'en-US',
      'accept-encoding': 'gzip',
      'accept': 'text/html'
    },
    connection: { remoteAddress: '10.0.0.4' }
  };
  const res = {
    status() { return this; },
    json() {}
  };
  const next = () => { nextCalled = true; };

  mw(req, res, next);
  assert(nextCalled === true, 'normal user passes through middleware');
}

// Test: config loading with custom values
{
  const config = loadConfig({
    endpoints: { '/custom/*': { mode: 'strict', rateLimit: 50 } },
    allowedBots: ['MyBot']
  });
  assert(config.allowedBots.includes('MyBot'), 'custom allowedBots applied');
  assert(config.endpoints['/custom/*'].rateLimit === 50, 'custom endpoint config applied');
}

// Test: rate limiting via middleware
{
  const mw = createMiddleware({
    endpoints: { '/*': { mode: 'medium', rateLimit: 3 } },
    logBlocked: false
  });

  let lastStatus = null;
  const req = {
    path: '/page',
    url: '/page',
    ip: '10.0.0.99',
    headers: {
      'user-agent': 'Mozilla/5.0 Chrome/120.0.0.0',
      'accept-language': 'en',
      'accept-encoding': 'gzip',
      'accept': 'text/html'
    },
    connection: { remoteAddress: '10.0.0.99' }
  };
  const res = {
    status(code) { lastStatus = code; return this; },
    json() {}
  };

  for (let i = 0; i < 5; i++) {
    lastStatus = null;
    mw(req, res, () => {});
  }
  assert(lastStatus === 429, 'rate limiting kicks in after capacity exceeded');
}

console.log(`\n=== integration results: ${passed} passed, ${failed} failed ===`);
if (failed > 0) process.exit(1);
