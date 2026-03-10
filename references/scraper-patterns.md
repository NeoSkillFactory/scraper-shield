# Known Scraper Patterns

## Malicious User-Agents

These user-agent strings are commonly associated with automated scraping tools:

| Pattern | Tool | Threat |
|---------|------|--------|
| `python-requests/` | Python Requests library | High |
| `python-urllib/` | Python urllib | High |
| `Scrapy/` | Scrapy framework | High |
| `curl/` | cURL command line | Medium |
| `wget/` | Wget downloader | Medium |
| `Java/` | Java HTTP client | Medium |
| `Go-http-client/` | Go HTTP client | Medium |
| `PhantomJS` | Headless browser | High |
| `HeadlessChrome` | Headless Chrome | High |
| `Puppeteer` | Puppeteer automation | High |
| `Selenium` | Selenium WebDriver | High |
| `HTTrack` | Website copier | High |

## Legitimate Bots (Allow by Default)

| Bot | Owner |
|-----|-------|
| Googlebot | Google Search |
| Bingbot | Microsoft Bing |
| Slurp | Yahoo |
| DuckDuckBot | DuckDuckGo |
| Baiduspider | Baidu |
| YandexBot | Yandex |
| facebot | Facebook |
| Twitterbot | Twitter |
| LinkedInBot | LinkedIn |
| Applebot | Apple |

## Suspicious Header Patterns

- Missing `Accept-Language` header (most browsers send this)
- Missing `Accept-Encoding` header
- `Accept: */*` without other headers (generic client default)
- `Connection: close` (unusual for modern browsers)
- Missing or very short `User-Agent` (< 10 characters)
