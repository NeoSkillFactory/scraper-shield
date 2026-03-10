# Rate Limiting Strategies

## Token Bucket Algorithm

scraper-shield uses the token bucket algorithm for rate limiting:

1. Each IP gets a bucket with a fixed capacity (e.g., 100 tokens)
2. Each request consumes one token
3. Tokens refill at a constant rate over the configured window
4. When the bucket is empty, requests are rejected with HTTP 429

### Configuration

- **capacity**: Maximum burst size (requests allowed before limiting)
- **refillRate**: Tokens added per window period
- **windowMs**: Time window in milliseconds (default: 60000ms = 1 minute)

## Protection Modes

### Strict Mode
- Rate limit set to 50% of base rate
- Immediately blocks known scraper patterns
- Best for: API endpoints, authenticated routes

### Medium Mode
- Rate limit at 100% of base rate
- Blocks only on rate limit violation
- Logs suspicious patterns for review
- Best for: Public pages, search endpoints

### Light Mode
- Rate limit at 200% of base rate
- No blocking, logging only
- Best for: Static assets, low-value pages

## Adaptive Behavior

The rate limiter adjusts based on detected threat level:
- High threat IPs get reduced token capacity
- Repeated violations extend the cooldown period
- Clean IPs accumulate trust over time
