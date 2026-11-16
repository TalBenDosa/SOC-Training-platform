# urlscan.io: scan result (Result API JSON)

Category: Threat intelligence / URL sandbox · Vendor: urlscan GmbH · Product: urlscan.io · Card version: 2026-11-15
Registry vendor: `urlscan-io` (aliases `urlscan.io`, `urlscan`).

## 1. Official sources

| Source | What it confirmed |
|---|---|
| Result API reference: https://docs.urlscan.io/pages/result-api-reference and the legacy page https://urlscan.io/docs/result/ (checked 2026-11-15) | Top-level keys `task`, `page`, `lists`, `verdicts`, `stats`, `meta`, `data`. `task.uuid`, `task.time` (ISO-8601), `task.url`, `task.visibility`, `task.method` (`api`, `manual`, `automatic`), `task.tags`, `task.apexDomain`, `task.options`. `page.url` (final URL after redirects), `page.domain`, `page.apexDomain`, `page.ip`, `page.asn`, `page.asnname`, `page.country`, `page.city`, `page.server`, `page.title`, `page.status`, `page.mimeType`, `page.tlsIssuer`, `page.tlsValidDays`, `page.tlsAgeDays`, `page.tlsValidFrom`, `page.redirected`, `page.umbrellaRank`, `page.ptr`. `verdicts` subkeys `urlscan`, `engines`, `community`; `verdicts.urlscan.score` (-100 legitimate … 100 malicious), `.categories` (e.g. phishing), `.brands`. `lists.ips/domains/urls/countries/asns/certificates/hashes/linkDomains/server`. `data.requests/cookies/console/links/timing/globals`, `data.redirects` (redirect chain, added 2026-04-02). `meta.processors.*` (asn, download, geoip, rdns, umbrella, wappa). |
| Search API reference: https://docs.urlscan.io/pages/search-api-reference (checked 2026-11-15) | `page.redirected` values: `same-domain`, `sub-domain`, `parent-domain`, `sibling-domain`, `off-domain`, `https-only`. `page.tlsAgeDays`: certificate age in days at scan time. `task.visibility`: `public`, `unlisted`, `private`. `verdicts.malicious` (bool) and `verdicts.score` in search results (paid tiers). |
| API changelog: https://docs.urlscan.io/changelog.md | `verdicts.overall.brands` is a flat array of brand identifiers (2022-04-20); verdict scores are integers -100…100. |

## 2. Native format and delivery

1. `POST https://urlscan.io/api/v1/scan/` with `{"url": "...", "visibility": "private"}` and an API key → returns a `uuid`.
2. `GET https://urlscan.io/api/v1/result/<uuid>/` → the result JSON (HTTP 404 until the scan finishes).
3. The web report is `https://urlscan.io/result/<uuid>/`.

The platform shows the JSON object as returned, nested, trimmed to the keys a lab needs (never renamed or flattened). If a raw block must be flat, keys are the dotted paths (`page.apexDomain`).

## 3. Core field reference

| Field | Meaning | SOC use |
|---|---|---|
| `task.url` | What was submitted (e.g. the short link) | |
| `task.visibility` | `public` / `unlisted` / `private` | Scan suspicious links `private` so the operator cannot see the hit |
| `task.time` | When the scan ran | |
| `page.url`, `page.domain`, `page.apexDomain` | Where the browser ended after redirects; registered domain | The real landing domain behind a shortener |
| `page.redirected` | Kind of redirect (see values above) | `off-domain` = sent to a different registered domain |
| `page.ip`, `page.asn`, `page.asnname`, `page.country`, `page.ptr` | Server that served the final page | Block / AbuseIPDB / whois pivot |
| `page.title`, `page.status`, `page.server`, `page.mimeType` | Page facts | A title can say anything |
| `page.tlsIssuer`, `page.tlsAgeDays`, `page.tlsValidDays`, `page.tlsValidFrom` | Certificate of the final page | Age 0-2 days on a "bank" page is a strong sign; a valid padlock proves nothing |
| `page.umbrellaRank` | Popularity rank of the host | Absent for new or rare hosts |
| `verdicts.urlscan.score`, `.categories`, `.brands` | urlscan's own verdict | `phishing` + a brand = brand impersonation |
| `verdicts.overall` | Combined verdict object | see §7 |
| `lists.*` | Everything the page contacted | Second-stage hosts, IPs, certificate list |
| `data.redirects` | Redirect chain, task URL → page URL | Each hop's domain |

## 4. Samples

Phishing kit behind a short link (trimmed; documentation addresses; private scan):

```json
{
  "task": {
    "uuid": "3f6c1e2a-8b4d-4c7e-9a10-5d2b7e8f9c41",
    "time": "2026-11-04T02:03:41.112Z",
    "url": "https://bit.ly/3nWq7Rk",
    "visibility": "private",
    "method": "api",
    "apexDomain": "bit.ly"
  },
  "page": {
    "url": "https://northwind-bank.secure-auth.example/logon/?u=j.amari%40yourco.example",
    "domain": "northwind-bank.secure-auth.example",
    "apexDomain": "secure-auth.example",
    "redirected": "off-domain",
    "ip": "203.0.113.214",
    "asn": "AS64511",
    "asnname": "EXAMPLE-VPS-HOSTING, NL",
    "country": "NL",
    "title": "Northwind Online Banking | Log on",
    "status": "200",
    "mimeType": "text/html",
    "tlsIssuer": "R11",
    "tlsValidFrom": "2026-11-04T00:00:00.000Z",
    "tlsValidDays": 89,
    "tlsAgeDays": 0
  },
  "verdicts": {
    "urlscan": { "score": 100, "categories": ["phishing"] }
  }
}
```

Benign redirect for contrast:

```json
{
  "task": { "url": "https://go.vendor.example/q4-report", "visibility": "private", "time": "2026-11-04T09:12:05.448Z" },
  "page": {
    "url": "https://www.vendor.example/reports/q4",
    "domain": "www.vendor.example",
    "apexDomain": "vendor.example",
    "redirected": "sub-domain",
    "ip": "198.51.100.40",
    "tlsAgeDays": 211,
    "tlsValidDays": 397,
    "status": "200"
  },
  "verdicts": { "urlscan": { "score": 0, "categories": [] } }
}
```

## 5. Investigation notes

- The answer to "where does this link really go" is `page.apexDomain`, not `task.url` and not `page.title`.
- `page.redirected` `off-domain` from a shortener is normal for shorteners; it matters when the landing apex is new, unrelated to the brand in the title, or has a 0-day certificate.
- A recipient address already filled in the landing URL (`?u=`, `#email=`) means the kit was built per target: search the mail logs for every recipient of that campaign.
- Next steps: `page.ip` and `page.apexDomain` to proxy / DNS / firewall logs and block lists; `UrlClickEvents` for who clicked; sign-in logs from the landing IP (AiTM kits sign in from their own server).
- Always submit `private` (or use the organisation's sandbox); a `public` scan of a targeted link can tip off the operator and expose the victim's address.

## 6. Common mistakes

- Inventing `page.finalUrl`, `page.redirectUrl`, `page.certAge`, `task.reportURL` as documented fields, or `verdict` (singular). The final URL is `page.url`; certificate age is `page.tlsAgeDays`.
- Treating `verdicts.urlscan.score` as a percentage: it runs -100 (legitimate) to 100 (malicious).
- `page.redirected: true`: it is a string from the list above, not a boolean.
- Reading `task.apexDomain` (the submitted link's domain, e.g. the shortener) as the landing domain.

## 7. UNVERIFIED

- `verdicts.overall.score`, `verdicts.overall.malicious`, `verdicts.overall.categories`, `verdicts.overall.hasVerdicts`: present in live Result API responses but not in the field table of the reference pages read (only `verdicts.overall.brands` is in the changelog). Prefer `verdicts.urlscan.*` in labs; if `verdicts.overall` is shown, do not hang a graded answer on its exact keys.
- Type of `page.status` (string `"200"` in live responses; the reference only says "HTTP response code") and of `page.asn` (`"AS64511"` string form).
- `task.reportURL`, `task.screenshotURL`, `task.domURL`: the docs say `task` includes links to the screenshot and DOM but do not name the keys.
