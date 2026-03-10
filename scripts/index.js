'use strict';

const detector = require('./detector');
const { RateLimiter } = require('./limiter');
const { loadConfig, getEndpointConfig, getRateLimitForMode } = require('./config');
const { normalizeIP, createResponse, formatTimestamp } = require('./utils');

function createMiddleware(userConfig) {
  const config = loadConfig(userConfig);
  const limiter = new RateLimiter(config);

  return function scraperShieldMiddleware(req, res, next) {
    const path = req.path || req.url || '/';
    const ip = normalizeIP(req.ip || req.connection?.remoteAddress || '0.0.0.0');

    const endpointConfig = getEndpointConfig(config, path);
    const rateLimit = getRateLimitForMode(endpointConfig, config);

    const analysis = detector.analyze({
      headers: req.headers || {},
      ip: ip,
      ua: (req.headers && req.headers['user-agent']) || ''
    }, config);

    if (analysis.blocked && endpointConfig.mode === 'strict') {
      if (config.logBlocked) {
        console.log(`[scraper-shield] BLOCKED ${ip} - ${analysis.reason}`);
      }
      res.status(403).json(createResponse(403, { blocked: true, reason: analysis.reason }));
      return;
    }

    const limitResult = limiter.record(ip, rateLimit, analysis);

    if (!limitResult.allowed) {
      if (config.logBlocked) {
        console.log(`[scraper-shield] RATE LIMITED ${ip} - ${limitResult.reason}`);
      }
      res.status(429).json(createResponse(429, {
        blocked: true,
        reason: 'rate_limit_exceeded',
        retryAfter: Math.ceil((config.rateLimitWindowMs || 60000) / 1000)
      }));
      return;
    }

    if (endpointConfig.mode === 'light' && analysis.threat !== 'none') {
      if (config.logBlocked) {
        console.log(`[scraper-shield] LOGGED ${ip} - ${analysis.reason} (light mode, not blocked)`);
      }
    }

    next();
  };
}

function analyzeRequest(options, userConfig) {
  const config = loadConfig(userConfig);
  return detector.analyze({
    headers: options.headers || { 'user-agent': options.ua || '' },
    ip: options.ip || '0.0.0.0',
    ua: options.ua || ''
  }, config);
}

function runCLI(args) {
  const flags = {};
  for (let i = 0; i < args.length; i++) {
    if (args[i].startsWith('--')) {
      const key = args[i].slice(2);
      if (i + 1 < args.length && !args[i + 1].startsWith('--')) {
        flags[key] = args[i + 1];
        i++;
      } else {
        flags[key] = true;
      }
    }
  }

  if (flags.check || flags.analyze) {
    const result = analyzeRequest({
      ip: flags.ip || '0.0.0.0',
      ua: flags.ua || '',
      headers: { 'user-agent': flags.ua || '' }
    });
    console.log(JSON.stringify(result, null, 2));
    return result;
  }

  if (flags.report) {
    const limiter = new RateLimiter();
    const report = limiter.getReport();
    console.log(JSON.stringify(report, null, 2));
    return report;
  }

  if (flags.demo) {
    console.log('=== scraper-shield demo ===\n');

    const testCases = [
      { ip: '10.0.0.1', ua: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36', label: 'Normal browser' },
      { ip: '10.0.0.2', ua: 'python-requests/2.28.1', label: 'Python requests' },
      { ip: '10.0.0.3', ua: 'Googlebot/2.1 (+http://www.google.com/bot.html)', label: 'Googlebot' },
      { ip: '10.0.0.4', ua: 'Scrapy/2.7.0', label: 'Scrapy bot' },
      { ip: '10.0.0.5', ua: '', label: 'Empty user-agent' },
      { ip: '10.0.0.6', ua: 'curl/7.86.0', label: 'curl' },
      { ip: '10.0.0.7', ua: 'Mozilla/5.0 (compatible; Bingbot/2.0)', label: 'Bingbot' }
    ];

    const results = [];
    for (const tc of testCases) {
      const result = analyzeRequest(tc);
      console.log(`[${tc.label}]`);
      console.log(`  UA: ${tc.ua || '(empty)'}`);
      console.log(`  Threat: ${result.threat} | Score: ${result.score} | Blocked: ${result.blocked}`);
      console.log(`  Reason: ${result.reason}\n`);
      results.push(result);
    }

    console.log('=== demo complete ===');
    return results;
  }

  console.log('scraper-shield - Malicious web scraper detection and blocking\n');
  console.log('Usage:');
  console.log('  node index.js --demo                    Run demo with sample requests');
  console.log('  node index.js --check --ip IP --ua UA   Analyze a single request');
  console.log('  node index.js --report                  Show blocking report');
  console.log('\nOptions:');
  console.log('  --ip    IP address to check');
  console.log('  --ua    User-Agent string to check');
}

if (require.main === module) {
  runCLI(process.argv.slice(2));
}

module.exports = { createMiddleware, analyzeRequest, runCLI };
