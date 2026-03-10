'use strict';

const { parseUserAgent, matchesAny, normalizeIP } = require('./utils');

const KNOWN_SCRAPER_UAS = [
  'python-requests', 'python-urllib', 'scrapy', 'httpclient',
  'java/', 'apache-httpclient', 'okhttp', 'go-http-client',
  'php/', 'guzzlehttp', 'curl/', 'wget/', 'libwww-perl',
  'mechanize', 'phantom', 'headlesschrome', 'puppeteer',
  'selenium', 'webdriver', 'httrack', 'nikto', 'sqlmap',
  'nmap', 'masscan', 'zgrab'
];

const LEGITIMATE_BOTS = [
  'googlebot', 'bingbot', 'slurp', 'duckduckbot', 'baiduspider',
  'yandexbot', 'facebot', 'twitterbot', 'linkedinbot',
  'applebot', 'msnbot'
];

const SUSPICIOUS_HEADERS = [
  { header: 'accept-language', absent: true, weight: 2 },
  { header: 'accept-encoding', absent: true, weight: 1 },
  { header: 'accept', value: '*/*', weight: 1 },
  { header: 'connection', value: 'close', weight: 1 }
];

function analyze(request, config) {
  const ua = (request.headers && request.headers['user-agent']) || request.ua || '';
  const ip = normalizeIP(request.ip || (request.headers && request.headers['x-forwarded-for']) || '0.0.0.0');
  const headers = request.headers || {};

  const allowedBots = (config && config.allowedBots) || [];
  const allowedIPs = (config && config.allowedIPs) || [];

  if (allowedIPs.includes(ip)) {
    return { threat: 'none', blocked: false, reason: 'allowed_ip', ip, ua, score: 0 };
  }

  if (matchesAny(ua, [...LEGITIMATE_BOTS, ...allowedBots])) {
    return { threat: 'none', blocked: false, reason: 'legitimate_bot', ip, ua, score: 0 };
  }

  let score = 0;
  const reasons = [];

  if (matchesAny(ua, KNOWN_SCRAPER_UAS)) {
    score += 8;
    reasons.push('known_scraper_ua');
  }

  if (!ua || ua.length < 10) {
    score += 5;
    reasons.push('missing_or_short_ua');
  }

  const parsed = parseUserAgent(ua);
  if (parsed.isBot && !matchesAny(ua, LEGITIMATE_BOTS)) {
    score += 3;
    reasons.push('bot_indicator_in_ua');
  }

  for (const check of SUSPICIOUS_HEADERS) {
    if (check.absent && !headers[check.header]) {
      score += check.weight;
      reasons.push(`missing_${check.header}`);
    } else if (check.value && headers[check.header] === check.value) {
      score += check.weight;
      reasons.push(`suspicious_${check.header}`);
    }
  }

  let threat;
  if (score >= 8) threat = 'high';
  else if (score >= 4) threat = 'medium';
  else if (score >= 2) threat = 'low';
  else threat = 'none';

  const blocked = threat === 'high';

  return {
    threat,
    blocked,
    reason: reasons.length ? reasons.join(', ') : 'clean',
    ip,
    ua,
    score
  };
}

module.exports = { analyze, KNOWN_SCRAPER_UAS, LEGITIMATE_BOTS };
