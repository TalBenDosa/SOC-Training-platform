# Microsoft IIS: W3C extended access log

Category: Web server · Vendor: Microsoft · Module: `iis`

## 1. Official sources

| Source | What it confirmed |
|---|---|
| Configure Logging in IIS: https://learn.microsoft.com/en-us/iis/manage/provisioning-and-managing-iis/configure-logging-in-iis | W3C fields and their meaning, UTC timestamps, per-site files under `%SystemDrive%\inetpub\logs\LogFiles` |
| Azure Application Gateway overview of how requests reach the backend, and the monitoring reference: https://learn.microsoft.com/en-us/azure/application-gateway/monitor-application-gateway-reference | A gateway is the TCP client of the backend, so the client is carried in a header |

## 2. Native format and delivery

A text file per site and day. Header lines start with `#` (`#Software`, `#Version`, `#Date`, `#Fields`). Each request is one line of space-separated fields in `#Fields` order, a hyphen for an empty field, and `+` for a space inside a value. `date` and `time` are UTC. The platform shows a flat JSON object keyed by the `#Fields` names, plus `rawLine`.

The estate's `#Fields`:

```text
#Fields: date time s-sitename s-computername s-ip cs-method cs-uri-stem cs-uri-query s-port cs-username c-ip cs-version cs(User-Agent) cs(Referer) cs-host sc-status sc-substatus sc-win32-status sc-bytes cs-bytes time-taken X-Forwarded-For
```

`X-Forwarded-For` is a custom field (IIS Manager, Logging, Select Fields, Add Field, request header). The administrator names it, and IIS writes such a site's log to a file with `_x` in its name (`u_ex260317_x.log`). Without it, a server behind a gateway logs only the gateway.

## 3. Core field reference

| Field | Meaning |
|---|---|
| `date`, `time` | UTC |
| `s-sitename`, `s-computername`, `s-ip`, `s-port` | Site instance, server name, server address, port |
| `cs-method`, `cs-uri-stem`, `cs-uri-query` | Method, path, query string (`-` when none) |
| `cs-username` | Authenticated user; `-` for anonymous |
| `c-ip` | TCP client: **the gateway**, when there is one |
| `cs(User-Agent)`, `cs(Referer)`, `cs-host`, `cs-version` | Request headers and protocol |
| `sc-status`, `sc-substatus`, `sc-win32-status` | Status, sub-status, Windows status |
| `sc-bytes`, `cs-bytes` | Bytes sent to and received from the client |
| `time-taken` | Milliseconds |
| `X-Forwarded-For` | Custom field: the real client |

## 4. Samples

```text
2026-03-17 09:21:40 W3SVC1 WEB-PORTAL-02 10.20.40.22 GET /download file=..%2F..%2F...%2Fweb.config 443 - 10.20.40.9 HTTP/1.1 python-requests/2.31.0 - portal.example.com 200 0 0 3122 412 41 203.0.113.41
```

```json
{
  "date": "2026-03-17", "time": "09:21:40", "s-sitename": "W3SVC1", "s-computername": "WEB-PORTAL-02", "s-ip": "10.20.40.22",
  "cs-method": "GET", "cs-uri-stem": "/download", "cs-uri-query": "file=..%2F..%2F...%2Fweb.config", "s-port": 443, "cs-username": "-", "c-ip": "10.20.40.9",
  "cs-version": "HTTP/1.1", "cs(User-Agent)": "python-requests/2.31.0", "cs(Referer)": "-", "cs-host": "portal.example.com",
  "sc-status": 200, "sc-substatus": 0, "sc-win32-status": 0, "sc-bytes": 3122, "cs-bytes": 412, "time-taken": 41, "X-Forwarded-For": "203.0.113.41"
}
```

```text
2026-03-17 09:44:12 W3SVC1 WEB-PORTAL-02 10.20.40.22 POST /human2.aspx - 443 - 10.20.40.9 HTTP/1.1 Mozilla/5.0+(Windows+NT+10.0;+Win64;+x64) - files.example.com 200 0 0 912 1408 118 198.51.100.77
```

```json
{
  "date": "2026-03-17", "time": "09:44:12", "s-sitename": "W3SVC1", "s-computername": "WEB-PORTAL-02", "s-ip": "10.20.40.22",
  "cs-method": "POST", "cs-uri-stem": "/human2.aspx", "cs-uri-query": "-", "s-port": 443, "cs-username": "-", "c-ip": "10.20.40.9",
  "cs-version": "HTTP/1.1", "cs(User-Agent)": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)", "cs(Referer)": "-", "cs-host": "files.example.com",
  "sc-status": 200, "sc-substatus": 0, "sc-win32-status": 0, "sc-bytes": 912, "cs-bytes": 1408, "time-taken": 118, "X-Forwarded-For": "198.51.100.77"
}
```

A script answering from a folder users write to:

```json
{
  "date": "2026-03-17", "time": "10:02:51", "s-sitename": "W3SVC1", "s-computername": "WEB-PORTAL-02", "s-ip": "10.20.40.22",
  "cs-method": "POST", "cs-uri-stem": "/uploads/avatars/7731/avatar.aspx", "cs-uri-query": "-", "s-port": 443, "cs-username": "-", "c-ip": "10.20.40.9",
  "cs-version": "HTTP/1.1", "cs(User-Agent)": "python-requests/2.31.0", "cs(Referer)": "-", "cs-host": "portal.example.com",
  "sc-status": 200, "sc-substatus": 0, "sc-win32-status": 0, "sc-bytes": 1902, "cs-bytes": 512, "time-taken": 63, "X-Forwarded-For": "203.0.113.54"
}
```

## 5. Investigation notes

- Pivot on `X-Forwarded-For`, not `c-ip`.
- `sc-bytes` is the fastest test of success: the page's normal size against the suspicious row's.
- A web shell leaves few lines: one client, one script, small POSTs, no Referer.
- The log never holds a POST body or a cookie unless `cs(Cookie)` is enabled. A request's content is proven from what it caused on the host.

## 6. Common mistakes and fields that do not exist

- `time` is UTC, not server local time.
- The header spelling is `cs(User-Agent)` and `cs(Referer)`, not the ECS `user_agent.original` or `http.request.referrer`.
- `sc-win32-status` 0 means no error, not "no data".

## 7. UNVERIFIED

- The wire spelling of a custom field in `#Fields`. Microsoft's page does not show it; the name used here follows the configured log field name.
