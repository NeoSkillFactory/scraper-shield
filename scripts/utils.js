'use strict';

function parseUserAgent(ua) {
  if (!ua) return { raw: '', tokens: [], isBot: false };

  const tokens = ua.split(/[\s/;()]+/).filter(Boolean).map(t => t.toLowerCase());
  const botIndicators = ['bot', 'crawler', 'spider', 'scraper', 'fetch', 'http', 'curl', 'wget', 'python', 'java', 'php', 'perl', 'ruby', 'go-http'];
  const isBot = tokens.some(t => botIndicators.some(b => t.includes(b)));

  return { raw: ua, tokens, isBot };
}

function normalizeIP(ip) {
  if (!ip) return '0.0.0.0';
  if (ip === '::1' || ip === '::ffff:127.0.0.1') return '127.0.0.1';
  if (ip.startsWith('::ffff:')) return ip.slice(7);
  return ip;
}

function formatTimestamp(date) {
  return (date || new Date()).toISOString();
}

function matchesAny(value, patterns) {
  if (!value || !patterns || !patterns.length) return false;
  const lower = value.toLowerCase();
  return patterns.some(p => lower.includes(p.toLowerCase()));
}

function createResponse(statusCode, body) {
  return { statusCode, body, timestamp: formatTimestamp() };
}

module.exports = { parseUserAgent, normalizeIP, formatTimestamp, matchesAny, createResponse };
