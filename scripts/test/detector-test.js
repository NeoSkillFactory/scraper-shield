'use strict';

const detector = require('../detector');

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

console.log('=== detector tests ===\n');

// Test: known scraper UA detected
{
  const result = detector.analyze({ headers: { 'user-agent': 'python-requests/2.28.1' }, ip: '10.0.0.1' });
  assert(result.threat === 'high', 'python-requests detected as high threat');
  assert(result.blocked === true, 'python-requests is blocked');
  assert(result.reason.includes('known_scraper_ua'), 'reason includes known_scraper_ua');
}

// Test: normal browser passes
{
  const result = detector.analyze({
    headers: {
      'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36',
      'accept-language': 'en-US,en;q=0.9',
      'accept-encoding': 'gzip, deflate, br',
      'accept': 'text/html'
    },
    ip: '10.0.0.2'
  });
  assert(result.threat === 'none', 'normal browser is no threat');
  assert(result.blocked === false, 'normal browser not blocked');
}

// Test: empty UA is suspicious
{
  const result = detector.analyze({ headers: {}, ip: '10.0.0.3' });
  assert(result.score >= 5, 'empty UA gets score >= 5');
  assert(result.reason.includes('missing_or_short_ua'), 'reason includes missing UA');
}

// Test: Googlebot is allowed
{
  const result = detector.analyze({
    headers: { 'user-agent': 'Googlebot/2.1 (+http://www.google.com/bot.html)' },
    ip: '10.0.0.4'
  });
  assert(result.threat === 'none', 'Googlebot is no threat');
  assert(result.reason === 'legitimate_bot', 'Googlebot identified as legitimate');
}

// Test: allowed IP bypasses checks
{
  const result = detector.analyze(
    { headers: { 'user-agent': 'python-requests/2.28.1' }, ip: '10.0.0.5' },
    { allowedIPs: ['10.0.0.5'] }
  );
  assert(result.blocked === false, 'allowed IP is not blocked');
  assert(result.reason === 'allowed_ip', 'reason is allowed_ip');
}

// Test: curl detected
{
  const result = detector.analyze({ headers: { 'user-agent': 'curl/7.86.0' }, ip: '10.0.0.6' });
  assert(result.threat === 'high', 'curl detected as high threat');
  assert(result.reason.includes('known_scraper_ua'), 'curl matches known scraper pattern');
}

// Test: Scrapy detected
{
  const result = detector.analyze({ headers: { 'user-agent': 'Scrapy/2.7.0' }, ip: '10.0.0.7' });
  assert(result.threat === 'high', 'Scrapy detected as high threat');
}

// Test: custom allowed bots
{
  const result = detector.analyze(
    { headers: { 'user-agent': 'MyCustomBot/1.0' }, ip: '10.0.0.8' },
    { allowedBots: ['MyCustomBot'] }
  );
  assert(result.reason === 'legitimate_bot', 'custom bot in allowedBots is legitimate');
}

console.log(`\n=== detector results: ${passed} passed, ${failed} failed ===`);
if (failed > 0) process.exit(1);
