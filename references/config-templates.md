# Configuration Templates

## Basic API Protection

```json
{
  "endpoints": {
    "/api/*": { "mode": "strict", "rateLimit": 100 }
  },
  "allowedBots": ["Googlebot", "Bingbot"]
}
```

## E-commerce Site

```json
{
  "endpoints": {
    "/api/*": { "mode": "strict", "rateLimit": 60 },
    "/product/*": { "mode": "medium", "rateLimit": 200 },
    "/search": { "mode": "medium", "rateLimit": 100 },
    "/static/*": { "mode": "light", "rateLimit": 1000 }
  },
  "allowedBots": ["Googlebot", "Bingbot", "DuckDuckBot"],
  "allowedIPs": []
}
```

## Public Content Site

```json
{
  "endpoints": {
    "/api/*": { "mode": "medium", "rateLimit": 300 },
    "/*": { "mode": "light", "rateLimit": 500 }
  },
  "allowedBots": ["Googlebot", "Bingbot", "Slurp", "DuckDuckBot", "Baiduspider"]
}
```
