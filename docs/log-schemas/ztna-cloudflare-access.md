# Cloudflare Zero Trust — Access requests (Logpush dataset `access_requests`)

Category: ZTNA / identity-aware access proxy. Vendor: Cloudflare. Native format: JSON (NDJSON) records written by Logpush (JSON-native).
Platform representation: **the Logpush JSON object exactly as delivered** (PascalCase keys, flat).

---

## 1. Official sources

| Source | What it confirmed |
|---|---|
| https://developers.cloudflare.com/logs/logpush/logpush-job/datasets/account/access_requests/ | Complete field list and types: `Action` (string, `login` \| `logout`), `Allowed` (bool), `AppDomain`, `AppUUID`, `Connection` (IdP used), `Country`, `CreatedAt` (int or string), `Email`, `IPAddress`, `PurposeJustificationPrompt`, `PurposeJustificationResponse`, `RayID`, `TemporaryAccessApprovers` (array[string]), `TemporaryAccessDuration` (int), `UserUID`. |
| https://developers.cloudflare.com/logs/logpush/logpush-job/log-output-options/ | Output options: field list, `timestamp_format` (`unixnano` / `unix` / `rfc3339`), NDJSON vs CSV, sampling. |
| https://github.com/elastic/integrations/blob/main/packages/cloudflare_logpush/data_stream/access_request/_dev/test/pipeline/test-pipeline-access-request.log | Real record shape; `Country` lowercase ISO-2 (`"us"`); `Connection` example `"onetimepin"`; `CreatedAt` seen as RFC3339 string, unix seconds and unix nanoseconds depending on job option; `RayID` 16 hex chars. |
| https://developers.cloudflare.com/cloudflare-one/insights/logs/audit-logs/ (Access authentication logs) | The dashboard/API "Access authentication logs" are the same events; per-request (post-login) traffic is a different dataset. |

## 2. Native format and delivery

- Account-scoped Logpush job with `dataset: "access_requests"` pushes batched, gzip'd NDJSON files to R2, S3, Azure Blob, GCS, Splunk HEC, Datadog, HTTP endpoint, etc. One JSON object per line, flat.
- Each record = one Access **authentication event** (login or logout) to an Access application — not every HTTP request. (HTTP traffic is in `http_requests` / Gateway HTTP datasets.)
- `CreatedAt` format depends on the job's `timestamp_format`: `rfc3339` -> `"2026-10-01T05:02:11Z"`, `unix` -> `1790830931`, `unixnano` -> `1790830931000000000`.
- **We standardise on:** the full 15-field object, `timestamp_format=rfc3339` (UTC, `Z`). Empty strings / empty arrays / `0` when a feature (purpose justification, temporary access) is not configured.

## 3. Core field reference

| Field | Type | Meaning | Values / notes |
|---|---|---|---|
| `Action` | string | Record type | `login`, `logout` |
| `Allowed` | bool | Whether Access allowed the login | `true` / `false` |
| `AppDomain` | string | Hostname (and optional path) of the protected app | `finance.nexacorp.co.il`, `nexacorp.cloudflareaccess.com/warp` (WARP enrollment) |
| `AppUUID` | string | Access application UUID | |
| `Connection` | string | IdP / login method used | `azureAD`, `okta`, `saml`, `oidc`, `github`, `google`, `onetimepin`, `warp`; exact strings for each IdP type UNVERIFIED except `onetimepin` |
| `Country` | string | Request country (ISO-2, lowercase) | `il`, `nl`, `de` |
| `CreatedAt` | int or string | Event time | see delivery |
| `Email` | string | User email (identity) | |
| `IPAddress` | string | Client IP as seen by Cloudflare | IPv4 or IPv6 |
| `PurposeJustificationPrompt` | string | Prompt shown when "purpose justification" is required | |
| `PurposeJustificationResponse` | string | Text the user typed | |
| `RayID` | string | Cloudflare request identifier | 16 hex chars |
| `TemporaryAccessApprovers` | array[string] | Approvers for temporary-auth requests | |
| `TemporaryAccessDuration` | int | Approved duration (seconds) | |
| `UserUID` | string | Cloudflare Access user UID | UUID |

## 4. Realistic samples

### 4.1 Normal SSO login to the finance portal from Israel
```json
{"Action":"login","Allowed":true,"AppDomain":"finance.nexacorp.co.il","AppUUID":"5f2c8e14-3a9b-4d71-b0e6-2c4a7f9d1e38","Connection":"azureAD","Country":"il","CreatedAt":"2026-10-01T05:02:11Z","Email":"dana.levi@nexacorp.co.il","IPAddress":"203.0.113.24","PurposeJustificationPrompt":"","PurposeJustificationResponse":"","RayID":"8c1f4a27b3e95d02","TemporaryAccessApprovers":[],"TemporaryAccessDuration":0,"UserUID":"0b6e2f9a-7c41-5d38-a1e2-94f3c6b8d071"}
```

### 4.2 Repeated denied logins (policy: Israel-only + managed device) — burst from one IP
```ndjson
{"Action":"login","Allowed":false,"AppDomain":"finance.nexacorp.co.il","AppUUID":"5f2c8e14-3a9b-4d71-b0e6-2c4a7f9d1e38","Connection":"azureAD","Country":"ru","CreatedAt":"2026-10-01T23:14:07Z","Email":"j.cohen@nexacorp.co.il","IPAddress":"198.51.100.77","PurposeJustificationPrompt":"","PurposeJustificationResponse":"","RayID":"8c1fd02e6a4b7c11","TemporaryAccessApprovers":[],"TemporaryAccessDuration":0,"UserUID":"7a3d9c10-2e58-5b44-9f61-d0c2a8e4b357"}
{"Action":"login","Allowed":false,"AppDomain":"finance.nexacorp.co.il","AppUUID":"5f2c8e14-3a9b-4d71-b0e6-2c4a7f9d1e38","Connection":"azureAD","Country":"ru","CreatedAt":"2026-10-01T23:14:41Z","Email":"j.cohen@nexacorp.co.il","IPAddress":"198.51.100.77","PurposeJustificationPrompt":"","PurposeJustificationResponse":"","RayID":"8c1fd104f2c3a908","TemporaryAccessApprovers":[],"TemporaryAccessDuration":0,"UserUID":"7a3d9c10-2e58-5b44-9f61-d0c2a8e4b357"}
{"Action":"login","Allowed":false,"AppDomain":"hr.nexacorp.co.il","AppUUID":"c94e1b72-6d03-4f2a-8b5e-1a7d3c9f0e64","Connection":"azureAD","Country":"ru","CreatedAt":"2026-10-01T23:15:02Z","Email":"j.cohen@nexacorp.co.il","IPAddress":"198.51.100.77","PurposeJustificationPrompt":"","PurposeJustificationResponse":"","RayID":"8c1fd1878e0b2d45","TemporaryAccessApprovers":[],"TemporaryAccessDuration":0,"UserUID":"7a3d9c10-2e58-5b44-9f61-d0c2a8e4b357"}
```
(An `Email` is present on a denied record because the IdP step succeeded and Access policy then denied — i.e. the attacker already holds valid IdP credentials/session. Pure password guessing happens at the IdP and is logged there.)

### 4.3 One-time-PIN login from a foreign hosting-provider IP to a contractor app
```json
{"Action":"login","Allowed":true,"AppDomain":"vendors.nexacorp.co.il","AppUUID":"e1a7b3c9-0f24-4d6e-9a85-37c2d1f8b406","Connection":"onetimepin","Country":"nl","CreatedAt":"2026-10-01T00:41:52Z","Email":"r.mizrahi@nexacorp.co.il","IPAddress":"192.0.2.140","PurposeJustificationPrompt":"","PurposeJustificationResponse":"","RayID":"8c1e9b3d57f0a2c6","TemporaryAccessApprovers":[],"TemporaryAccessDuration":0,"UserUID":"3e8b1d47-9a06-5c2f-b7d3-6f0e2a9c4b18"}
```

### 4.4 Sensitive app with purpose justification + temporary (approved) access
```json
{"Action":"login","Allowed":true,"AppDomain":"prod-db-admin.nexacorp.co.il","AppUUID":"9b0d4f61-2c7e-4a83-b5f1-8e3a6c2d7f95","Connection":"azureAD","Country":"il","CreatedAt":"2026-10-01T07:30:15Z","Email":"oren.katz@nexacorp.co.il","IPAddress":"203.0.113.57","PurposeJustificationPrompt":"State the change ticket number for production DB access.","PurposeJustificationResponse":"CHG0031877 - index rebuild on billing DB","RayID":"8c205e19a4d7b380","TemporaryAccessApprovers":["it-dba-leads@nexacorp.co.il"],"TemporaryAccessDuration":3600,"UserUID":"a51c7e03-8d92-5f46-b0a3-2e9d6f1c8b74"}
```

### 4.5 Concurrent use — same identity logs in from Germany 20 minutes after the Israeli login
```json
{"Action":"login","Allowed":true,"AppDomain":"finance.nexacorp.co.il","AppUUID":"5f2c8e14-3a9b-4d71-b0e6-2c4a7f9d1e38","Connection":"azureAD","Country":"de","CreatedAt":"2026-10-01T05:22:40Z","Email":"dana.levi@nexacorp.co.il","IPAddress":"198.51.100.203","PurposeJustificationPrompt":"","PurposeJustificationResponse":"","RayID":"8c1f6833cb21e7d9","TemporaryAccessApprovers":[],"TemporaryAccessDuration":0,"UserUID":"0b6e2f9a-7c41-5d38-a1e2-94f3c6b8d071"}
```

### 4.6 Logout
```json
{"Action":"logout","Allowed":true,"AppDomain":"finance.nexacorp.co.il","AppUUID":"5f2c8e14-3a9b-4d71-b0e6-2c4a7f9d1e38","Connection":"azureAD","Country":"il","CreatedAt":"2026-10-01T14:45:02Z","Email":"dana.levi@nexacorp.co.il","IPAddress":"203.0.113.24","PurposeJustificationPrompt":"","PurposeJustificationResponse":"","RayID":"8c2392aa0e5f4b17","TemporaryAccessApprovers":[],"TemporaryAccessDuration":0,"UserUID":"0b6e2f9a-7c41-5d38-a1e2-94f3c6b8d071"}
```

## 5. Investigation notes

- **Identity pivot:** `Email` / `UserUID` -> IdP sign-in logs (`Connection` tells you which IdP to query). Correlate `IPAddress` + time with the IdP sign-in to see MFA details (not present here).
- **Foreign / hosting IP:** `Country` + `IPAddress` (ASN via enrichment). `onetimepin` logins bypass the corporate IdP (and its MFA/conditional access) — treat OTP from unusual countries as high risk.
- **Denied after IdP success:** `Allowed:false` with a populated `Email` = credentials worked at the IdP but Access policy (geo, device posture, group) blocked — strong compromise indicator.
- **Concurrent sessions:** same `UserUID`, `Allowed:true`, different `Country`/`IPAddress` within a short window.
- **Privileged access justification:** `PurposeJustificationResponse` should reference a real change ticket — verify it in ITSM (ServiceNow `change_request.number`).
- **RayID** links the event to Cloudflare HTTP / Gateway logs and to Cloudflare support.
- After login, what the user did in the app is **not** here — use `http_requests` (zone) or Gateway HTTP logs, and the origin's own logs (origin sees Cloudflare egress IPs / `Cf-Connecting-IP` header).

## 6. Common mistakes / fields that do NOT exist

- No `UserAgent`, `DeviceID`, `DevicePosture`, `Groups`, `MFA`, `Reason`, `PolicyName`, `ClientIP`, `Timestamp` fields in this dataset. Client IP is `IPAddress`; time is `CreatedAt`.
- `Allowed` is a JSON boolean, not `"allowed"`/`"blocked"` strings; `Action` is only `login`/`logout` (not `allow`/`block`).
- `Country` is lowercase ISO-2 (`"il"`), not a country name.
- These are not Gateway logs (no `URL`, `Policy`, `Category`), and not WAF/Firewall events (no `RuleID`).
- No SIEM envelope (`cloudflare_logpush.access_request.*`, `data.*`).
