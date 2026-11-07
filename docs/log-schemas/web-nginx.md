# nginx: access log

Category: Web server · Vendor: F5 / nginx · Module: `nginx`

## 1. Official sources

| Source | What it confirmed |
|---|---|
| ngx_http_log_module: https://nginx.org/en/docs/http/ngx_http_log_module.html | The predefined `combined` format, `log_format`, `$request_time`, escaping of `"`, `\` and control characters as `\xXX`, `-` for an empty variable |
| ngx_http_core_module variables: https://nginx.org/en/docs/http/ngx_http_core_module.html#variables | `$hostname`, `$server_addr`, `$host`, `$request_length`, `$http_<name>` |
| ngx_http_realip_module: https://nginx.org/en/docs/http/ngx_http_realip_module.html | Without it, `$remote_addr` is the immediate peer |

## 2. Native format and delivery

A text file, one line per request (`/var/log/nginx/access.log`), in the `log_format` the site configures. `$time_local` is the server's local time with its UTC offset. The platform shows a flat JSON object keyed by the variable names, plus `rawLine`.

The estate's format is `combined` extended with core variables, so a line names its server and its sizes:

```text
log_format soc '$remote_addr - $remote_user [$time_local] "$request" $status $body_bytes_sent "$http_referer" "$http_user_agent" "$http_x_forwarded_for" $hostname $server_addr $host $request_length $request_time';
```

## 3. Core field reference

| Field | Meaning |
|---|---|
| `remote_addr` | TCP peer: **the load balancer**, when there is one |
| `remote_user` | HTTP basic auth user; a cookie session logs `-` |
| `time_local` | `17/Mar/2026:09:21:40 +0000` |
| `request` | The request line: method, URI with query string, protocol |
| `status`, `body_bytes_sent` | Status; response body size |
| `http_referer`, `http_user_agent` | Request headers, as sent |
| `http_x_forwarded_for` | The client, as the balancer reported it |
| `hostname`, `server_addr`, `host` | Server name, server address, the request's Host |
| `request_length` | Request size including headers and body |
| `request_time` | Seconds, millisecond resolution |

## 4. Samples

```text
10.20.40.9 - - [17/Mar/2026:09:21:40 +0000] "GET /uploads/avatars/7731/avatar.php HTTP/1.1" 200 43 "-" "python-requests/2.31.0" "203.0.113.54" web-app-01 10.20.40.21 portal.example.com 214 0.031
```

```json
{
  "remote_addr": "10.20.40.9", "remote_user": "-", "time_local": "17/Mar/2026:09:21:40 +0000", "request": "GET /uploads/avatars/7731/avatar.php HTTP/1.1",
  "status": "200", "body_bytes_sent": "43", "http_referer": "-", "http_user_agent": "python-requests/2.31.0", "http_x_forwarded_for": "203.0.113.54",
  "hostname": "web-app-01", "server_addr": "10.20.40.21", "host": "portal.example.com", "request_length": "214", "request_time": "0.031"
}
```

```text
10.20.40.9 - - [17/Mar/2026:10:02:11 +0000] "GET /api/v2/customers/48244/statements HTTP/1.1" 200 18442 "-" "okhttp/4.12.0" "203.0.113.90" web-api-01 10.20.40.31 api.example.com 388 0.102
```

```json
{
  "remote_addr": "10.20.40.9", "remote_user": "-", "time_local": "17/Mar/2026:10:02:11 +0000", "request": "GET /api/v2/customers/48244/statements HTTP/1.1",
  "status": "200", "body_bytes_sent": "18442", "http_referer": "-", "http_user_agent": "okhttp/4.12.0", "http_x_forwarded_for": "203.0.113.90",
  "hostname": "web-api-01", "server_addr": "10.20.40.31", "host": "api.example.com", "request_length": "388", "request_time": "0.102"
}
```

```text
10.20.40.14 - - [17/Mar/2026:11:15:03 +0000] "POST /graphql HTTP/1.1" 200 1204 "-" "CustomerApp/5.2.0 (Android 14)" "-" web-api-01 10.20.40.31 api.example.com 18774 0.244
```

```json
{
  "remote_addr": "10.20.40.14", "remote_user": "-", "time_local": "17/Mar/2026:11:15:03 +0000", "request": "POST /graphql HTTP/1.1",
  "status": "200", "body_bytes_sent": "1204", "http_referer": "-", "http_user_agent": "CustomerApp/5.2.0 (Android 14)", "http_x_forwarded_for": "-",
  "hostname": "web-api-01", "server_addr": "10.20.40.31", "host": "api.example.com", "request_length": "18774", "request_time": "0.244"
}
```

## 5. Investigation notes

- Group on `http_x_forwarded_for` when the first column is always the balancer.
- `body_bytes_sent` proves success better than the status: many applications answer 200 with an error page.
- `request_length` is the only trace of a large POST body: the body itself is not logged, so a GraphQL batch and a single query differ here and nowhere else.
- A form or cookie sign-in never fills `remote_user`. The account behind a request is in the application's own log.

## 6. Common mistakes and fields that do not exist

- `$time_local` is local time. Convert before correlating with a UTC source.
- nginx has no user field for cookie sessions, and no POST body field.
- `ip`, `method`, `url` are not variables: the request line is one field.

## 7. UNVERIFIED

- None for the fields used. The `soc` format is this estate's configuration, not a default: only `combined` is predefined.
