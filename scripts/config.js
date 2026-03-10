'use strict';

const DEFAULT_CONFIG = {
  endpoints: {
    '/*': { mode: 'medium', rateLimit: 200 }
  },
  allowedBots: ['Googlebot', 'Bingbot', 'Slurp', 'DuckDuckBot', 'Baiduspider'],
  allowedIPs: [],
  rateLimitWindowMs: 60000,
  strictMultiplier: 0.5,
  mediumMultiplier: 1.0,
  lightMultiplier: 2.0,
  alertWebhook: process.env.SCRAPER_SHIELD_WEBHOOK || null,
  logBlocked: true
};

function loadConfig(userConfig) {
  if (!userConfig) return { ...DEFAULT_CONFIG };

  const config = { ...DEFAULT_CONFIG, ...userConfig };

  if (userConfig.endpoints) {
    config.endpoints = { ...DEFAULT_CONFIG.endpoints, ...userConfig.endpoints };
  }
  if (userConfig.allowedBots) {
    config.allowedBots = userConfig.allowedBots;
  }
  if (userConfig.allowedIPs) {
    config.allowedIPs = userConfig.allowedIPs;
  }

  return config;
}

function getEndpointConfig(config, path) {
  const endpoints = config.endpoints || {};

  // Sort patterns by specificity (longest prefix first) to match most specific route
  const patterns = Object.keys(endpoints).sort((a, b) => b.length - a.length);

  for (const pattern of patterns) {
    if (matchPattern(pattern, path)) {
      return endpoints[pattern];
    }
  }

  return { mode: 'medium', rateLimit: 200 };
}

function matchPattern(pattern, path) {
  if (pattern === path) return true;
  if (pattern.endsWith('/*')) {
    const prefix = pattern.slice(0, -2);
    return path.startsWith(prefix);
  }
  if (pattern.endsWith('*')) {
    const prefix = pattern.slice(0, -1);
    return path.startsWith(prefix);
  }
  return false;
}

function getRateLimitForMode(endpointConfig, config) {
  const baseRate = endpointConfig.rateLimit || 200;
  const mode = endpointConfig.mode || 'medium';

  switch (mode) {
    case 'strict':
      return Math.floor(baseRate * (config.strictMultiplier || 0.5));
    case 'medium':
      return Math.floor(baseRate * (config.mediumMultiplier || 1.0));
    case 'light':
      return Math.floor(baseRate * (config.lightMultiplier || 2.0));
    default:
      return baseRate;
  }
}

module.exports = { loadConfig, getEndpointConfig, matchPattern, getRateLimitForMode, DEFAULT_CONFIG };
