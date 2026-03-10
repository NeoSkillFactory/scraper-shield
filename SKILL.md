---
name: scraper-shield
description: "Detect and block malicious web scrapers using pattern analysis and adaptive rate limiting. Use when: protect website from scrapers, block bot attacks, implement adaptive rate limiting, detect malicious traffic patterns, prevent automated data theft."
version: 1.0.0
metadata: {"openclaw": {"emoji": "🛡️", "requires": {"bins": ["node"]}}}
---

# scraper-shield

Analyzes HTTP request patterns to identify and block malicious web scrapers. Supports three protection modes (strict/medium/light) and uses a token bucket algorithm for adaptive rate limiting. Deploys as Express middleware or runs as a standalone CLI tool.

## Usage

### Express Middleware

```javascript
const { createMiddleware } = require('./scripts/index');

app.use(createMiddleware({
  endpoints: {
    "/api/*": { mode: "strict", rateLimit: 100 },
    "/search": { mode: "medium", rateLimit: 500 }
  },
  allowedBots: ["Googlebot", "Bingbot"]
}));
```

### CLI Analysis

```bash
node scripts/index.js --check --ip 10.0.0.1 --ua "python-requests/2.28"
node scripts/index.js --demo
node scripts/index.js --report
```

## When to Use / When NOT to Use

| Use when | Do NOT use when |
|----------|-----------------|
| Protecting API endpoints from automated scraping | You need a full WAF solution |
| Adding rate limiting to Express applications | Blocking DDoS attacks (use infrastructure-level protection) |
| Detecting known scraper user-agents | You need IP reputation databases |
| Logging suspicious traffic for analysis | Handling authentication or authorization |
| Whitelisting legitimate search engine bots | You need geo-blocking or CAPTCHA integration |

## Edge Cases

- **False positives in CLI tools**: Legitimate API clients using `curl` or `python-requests` will be flagged. Add their IPs to `allowedIPs` to bypass detection.
- **Header-only detection**: Requests missing `Accept-Language` or `Accept-Encoding` headers get a low threat score even with valid user-agents. Use `medium` or `light` mode for public endpoints to avoid blocking these.
- **Evasion by spoofing**: Scrapers mimicking real browser user-agents will evade UA detection. Rate limiting still applies and catches high-frequency access patterns.
- **In-memory state**: Rate limit state is stored in memory and resets on process restart. Not suitable for multi-process or clustered deployments without external state storage.
