'use strict';

const { normalizeIP, formatTimestamp } = require('./utils');

class TokenBucket {
  constructor(capacity, refillRate, windowMs) {
    this.capacity = capacity;
    this.refillRate = refillRate;
    this.windowMs = windowMs || 60000;
    this.buckets = new Map();
  }

  _getBucket(key) {
    if (!this.buckets.has(key)) {
      this.buckets.set(key, {
        tokens: this.capacity,
        lastRefill: Date.now(),
        totalRequests: 0,
        blockedRequests: 0
      });
    }
    return this.buckets.get(key);
  }

  _refill(bucket) {
    const now = Date.now();
    const elapsed = now - bucket.lastRefill;
    const tokensToAdd = Math.floor((elapsed / this.windowMs) * this.refillRate);

    if (tokensToAdd > 0) {
      bucket.tokens = Math.min(this.capacity, bucket.tokens + tokensToAdd);
      bucket.lastRefill = now;
    }
  }

  check(ip) {
    const key = normalizeIP(ip);
    const bucket = this._getBucket(key);
    this._refill(bucket);

    return {
      allowed: bucket.tokens > 0,
      remaining: bucket.tokens,
      total: this.capacity,
      ip: key
    };
  }

  record(ip) {
    const key = normalizeIP(ip);
    const bucket = this._getBucket(key);
    this._refill(bucket);

    bucket.totalRequests++;

    if (bucket.tokens > 0) {
      bucket.tokens--;
      return { allowed: true, remaining: bucket.tokens, ip: key };
    }

    bucket.blockedRequests++;
    return { allowed: false, remaining: 0, ip: key, reason: 'rate_limit_exceeded' };
  }

  getStats(ip) {
    const key = normalizeIP(ip);
    if (!this.buckets.has(key)) return null;
    const bucket = this.buckets.get(key);
    return {
      ip: key,
      tokens: bucket.tokens,
      capacity: this.capacity,
      totalRequests: bucket.totalRequests,
      blockedRequests: bucket.blockedRequests
    };
  }

  cleanup(maxAgeMs) {
    const cutoff = Date.now() - (maxAgeMs || 300000);
    for (const [key, bucket] of this.buckets) {
      if (bucket.lastRefill < cutoff) {
        this.buckets.delete(key);
      }
    }
  }

  reset() {
    this.buckets.clear();
  }
}

class RateLimiter {
  constructor(config) {
    this.config = config || {};
    this.windowMs = this.config.rateLimitWindowMs || 60000;
    this.defaultCapacity = 200;
    this.buckets = new Map();
    this.blockedLog = [];
  }

  _getOrCreateBucket(capacity) {
    const key = `cap_${capacity}`;
    if (!this.buckets.has(key)) {
      this.buckets.set(key, new TokenBucket(capacity, capacity, this.windowMs));
    }
    return this.buckets.get(key);
  }

  check(ip, rateLimit) {
    const capacity = rateLimit || this.defaultCapacity;
    const bucket = this._getOrCreateBucket(capacity);
    return bucket.check(ip);
  }

  record(ip, rateLimit, threatInfo) {
    const capacity = rateLimit || this.defaultCapacity;
    const bucket = this._getOrCreateBucket(capacity);
    const result = bucket.record(ip);

    if (!result.allowed) {
      this.blockedLog.push({
        ip: normalizeIP(ip),
        timestamp: formatTimestamp(),
        reason: 'rate_limit_exceeded',
        threatInfo: threatInfo || null
      });
    }

    return result;
  }

  getReport() {
    return {
      blockedCount: this.blockedLog.length,
      recentBlocked: this.blockedLog.slice(-20),
      generatedAt: formatTimestamp()
    };
  }

  reset() {
    for (const bucket of this.buckets.values()) {
      bucket.reset();
    }
    this.blockedLog = [];
  }
}

module.exports = { TokenBucket, RateLimiter };
