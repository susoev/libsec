# WebSec API

https://websec.in tracks vulnerabilities in 50 web-server products: PHP, Python, MySQL/MariaDB,
PostgreSQL, nginx, Apache, Tomcat, OpenSSL, Docker, Laravel, Django, WordPress and others.
Records come from CVE List V5, OSV/GitHub Advisory, CISA KEV and EPSS. Duplicates are merged into one
record with aliases, and each record gets a priority. Most records also get an AI summary with the fix.

- Base URL: `https://websec.in/api`. The API only runs on the main domain, and all text is in English.
  Requests to language subdomains (`ru.websec.in/api/...`) get a 301 redirect to `websec.in`.
- Read-only, no key, no sign-up. CORS is open. Responses are cached for 60 s.
- Sources are checked every 10–60 minutes. Polling every 15–60 minutes is enough.
  Please do not poll more often than once a minute.

## Response format

Every response is JSON. The same fields always come first:

```json
{
  "result": true,
  "doc": "https://websec.in/api/doc",
  "about": "WebSec (websec.in): vulnerabilities in ...",
  "generated": "2026-11-20T12:00:00Z",
  ...data...
}
```

On error, `result` is `false`, `error` holds the reason, and the HTTP status is 400 or 404:

```json
{"result": false, "doc": "https://websec.in/api/doc", "about": "...", "error": "n: Input should be less than or equal to 50"}
```

## Endpoints

| Request | What it returns |
|---|---|
| `GET /api` | Endpoint list (the same as this page, in short) |
| `GET /api/high10` | **The 10 newest CRITICAL and HIGH vulnerabilities, with full detail** |
| `GET /api/v1/vulns` | The feed: a short list with filters |
| `GET /api/v1/vulns/{id}` | One record by CVE id or any alias, with its full history |
| `GET /api/v1/products` | Product catalog: slugs for the `product=` filter |
| `GET /api/doc` | This page |
| `GET /api/openapi.json`, `/api/docs` | OpenAPI schema and interactive docs |

### GET /api/high10 — what to fix now

This endpoint is for scheduled jobs and DevOps agents. It returns the newest vulnerabilities with priority
CRITICAL or HIGH, newest first (by `feed_at`). Each item already includes what is affected, which versions
fix it and what to do.

Parameters (all optional):

| Parameter | Default | Meaning |
|---|---|---|
| `product` | all | Only these products, comma-separated slugs: `product=php,nginx,mysql` (slugs: `/api/v1/products`) |
| `priority` | `CRITICAL,HIGH` | `CRITICAL` returns only critical records |
| `kev` | `0` | `1` returns only vulnerabilities exploited in the wild (CISA KEV) |
| `n` | `10` | How many records, 1–50 |

Examples:

```
curl -s https://websec.in/api/high10
curl -s 'https://websec.in/api/high10?product=php,nginx,mysql,openssl&n=20'
curl -s 'https://websec.in/api/high10?priority=CRITICAL&kev=1'
```

Top-level fields: `count`, `total` (how many records match the filter overall), `filter`, `latest_feed_at`
(the `feed_at` of the newest item, for checking whether anything is new), `items`.

### One item (`items[]` in high10, `item` in /api/v1/vulns/{id})

| Field | Meaning |
|---|---|
| `id` | Main id, usually a CVE (`CVE-2024-4577`), otherwise GHSA/PYSEC |
| `aliases` | Other ids of the same vulnerability |
| `title` | Title from the source |
| `headline` | Short AI headline, or `null` |
| `url`, `api` | Page on the site; JSON of this record |
| `products` | Product slugs from the catalog (`php`, `nginx`, ...) |
| `priority` | `CRITICAL`, `HIGH`, `MEDIUM`, `LOW` or `UNRATED`, with the reason in `priority_reason` |
| `exploited` | `true` if CISA lists the vulnerability as exploited in the wild (KEV) |
| `kev` | `{added, due, ransomware}` or `null` |
| `cvss` | `{score, severity, vector, version, source}` from the vendor/CNA or NVD, or `null`. CVSS is never guessed |
| `epss` | `{score, percentile, date}`: probability of exploitation in the next 30 days (0–1) |
| `published` | When the vulnerability was published (UTC, ISO 8601) |
| `modified` | When the source last changed the record |
| `feed_at` | When the record entered our feed or its priority went up. Track new items by this field |
| `fixed_versions` | Versions with the fix. They come from the AI analysis, where they are checked against the sources in code; if there is no analysis yet, they are taken from the source ranges |
| `action` | What to do, in plain words (AI), or `null` |
| `ai` | Full AI analysis, or `null` if it is not ready yet (usually ready within an hour): `summary`, `affects`, `preconditions`, `attack_vector`, `auth_required`, `typical_server_impact`, `our_score`, `score_reasoning`, `vuln_type`, `sources_used` |
| `description` | Original description from the source |
| `cwes` | Weakness types (CWE) |
| `affected` | Per source: `product`, `package` (ecosystem:name for libraries), `ranges` (vulnerable versions), `fixed` |
| `references` | Links: advisories, patches, changelogs |
| `events` | Record history: when it appeared, when the priority changed, when it entered KEV (only in /api/v1/vulns/{id}) |

### GET /api/v1/vulns — the feed

A short list (no `description`, `affected` or `references`). By default it covers the last 45 days.

Parameters: `product` (comma-separated slugs), `priority` (`CRITICAL,HIGH`), `kev=1`, `q` (text search),
`since=2026-11-01` (by `feed_at`), `all=1` (whole history, not just 45 days), `limit` (up to 200), `offset`.

```
curl -s 'https://websec.in/api/v1/vulns?product=nginx&priority=CRITICAL,HIGH&since=2026-11-01'
```

### GET /api/v1/vulns/{id}

Accepts a CVE id or any alias (`GHSA-...`, `PYSEC-...`). Returns `item` with all fields, including `events`.
Returns 404 if the record is unknown.

## Example: an agent that patches servers

1. Every 30 minutes, request `GET /api/high10?product=<your stack>&n=20`.
2. Keep the largest `feed_at` you have processed. New work is every item whose `feed_at` is greater.
3. For each new item, compare the installed version (`php -v`, `nginx -v`, `dpkg -l`, `pip show`, ...)
   with `affected[].ranges` and `fixed_versions`. Check `ai.preconditions`: often the vulnerability
   only applies with a specific module or setting.
4. Update to a version from `fixed_versions` or newer, or apply the workaround from `action`.
   Do `exploited: true` (KEV) items first, then those with the highest `epss.score`.
5. If `ai` is `null`, the analysis is not ready yet. Use `description` and `affected`, or check the item
   again on the next run.

Do not trust a version only from the AI fields: `fixed_versions` is checked against the sources, but the
sources themselves (`references`) are what counts. Distribution packages (Debian, Ubuntu, RHEL) often fix
the issue without changing the upstream version, so check the distribution's security tracker as well.

## Terms

The data is free to use. Facts: CVE List (CVE Terms of Use), OSV/GitHub Advisory (CC-BY 4.0), CISA KEV
and NVD (public domain), EPSS (FIRST.org, free use with attribution). Summaries: WebSec, AI-assisted,
and they can be wrong. Source code: https://github.com/susoev/libsec
