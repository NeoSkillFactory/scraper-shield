'use strict';

const { TokenBucket, RateLimiter } = require('../limiter');

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

console.log('=== limiter tests ===\n');

// Test: TokenBucket allows requests within capacity
{
  const bucket = new TokenBucket(5, 5, 60000);
  const r1 = bucket.record('10.0.0.1');
  assert(r1.allowed === true, 'first request allowed');
  assert(r1.remaining === 4, 'remaining is 4 after first request');
}

// Test: TokenBucket blocks after exhaustion
{
  const bucket = new TokenBucket(3, 3, 60000);
  bucket.record('10.0.0.1');
  bucket.record('10.0.0.1');
  bucket.record('10.0.0.1');
  const r4 = bucket.record('10.0.0.1');
  assert(r4.allowed === false, 'fourth request blocked after capacity 3');
  assert(r4.remaining === 0, 'remaining is 0');
}

// Test: Different IPs have separate buckets
{
  const bucket = new TokenBucket(2, 2, 60000);
  bucket.record('10.0.0.1');
  bucket.record('10.0.0.1');
  const r = bucket.record('10.0.0.2');
  assert(r.allowed === true, 'different IP still has tokens');
}

// Test: check without consuming
{
  const bucket = new TokenBucket(5, 5, 60000);
  const c1 = bucket.check('10.0.0.1');
  const c2 = bucket.check('10.0.0.1');
  assert(c1.remaining === 5, 'check does not consume tokens');
  assert(c2.remaining === 5, 'second check still 5 tokens');
}

// Test: getStats returns correct info
{
  const bucket = new TokenBucket(10, 10, 60000);
  bucket.record('10.0.0.1');
  bucket.record('10.0.0.1');
  const stats = bucket.getStats('10.0.0.1');
  assert(stats.totalRequests === 2, 'totalRequests is 2');
  assert(stats.tokens === 8, 'tokens is 8');
}

// Test: getStats returns null for unknown IP
{
  const bucket = new TokenBucket(10, 10, 60000);
  const stats = bucket.getStats('99.99.99.99');
  assert(stats === null, 'unknown IP returns null stats');
}

// Test: RateLimiter record and report
{
  const limiter = new RateLimiter({ rateLimitWindowMs: 60000 });
  const bucket = limiter._getOrCreateBucket(2);
  limiter.record('10.0.0.1', 2);
  limiter.record('10.0.0.1', 2);
  const r = limiter.record('10.0.0.1', 2);
  assert(r.allowed === false, 'rate limiter blocks after capacity');

  const report = limiter.getReport();
  assert(report.blockedCount === 1, 'report shows 1 blocked');
}

// Test: RateLimiter reset
{
  const limiter = new RateLimiter();
  limiter.record('10.0.0.1', 2);
  limiter.record('10.0.0.1', 2);
  limiter.record('10.0.0.1', 2);
  limiter.reset();
  const report = limiter.getReport();
  assert(report.blockedCount === 0, 'reset clears blocked log');
}

// Test: cleanup removes old buckets
{
  const bucket = new TokenBucket(10, 10, 60000);
  bucket.record('10.0.0.1');
  // Manually set lastRefill to the past
  bucket._getBucket('10.0.0.1').lastRefill = Date.now() - 400000;
  bucket.cleanup(300000);
  assert(bucket.getStats('10.0.0.1') === null, 'old bucket cleaned up');
}

console.log(`\n=== limiter results: ${passed} passed, ${failed} failed ===`);
if (failed > 0) process.exit(1);
