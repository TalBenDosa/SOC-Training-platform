# Google Workspace — Admin SDK Reports API `activities` (native schema card)

Category: Email & Collaboration · Vendor: Google · Applications covered: `login`, `user_accounts`, `drive`, `token`, `admin`, `saml`, `gmail`
Rule reminder: each log is ONE `admin#reports#activity` resource exactly as `activities.list` returns it — nested
`id{}`, `actor{}`, `events[]`, `events[].parameters[]` with typed value keys. No Elastic `google_workspace.*` flattening
(Elastic fixtures even turn `events` into an object and numbers into ints — that is NOT native), no Wazuh `data.gcp.*`,
no Sentinel `GWorkspace_ReportsAPI_*_CL` flattening (`event_name`, `scope`, `app_name` lifted to top level, `_s` suffixes).

---

## 1. Official sources

| URL | What it confirmed |
|---|---|
| https://developers.google.com/workspace/admin/reports/reference/rest/v1/activities/list | Response = `{kind, etag, items[], nextPageToken}`; Activity resource keys `kind`, `etag`, `ownerDomain`, `ipAddress`, `id{time, uniqueQualifier, applicationName, customerId}`, `actor{profileId, email, callerType, key, applicationInfo{oauthClientId, applicationName, impersonation}}`, `events[{type, name, parameters[{name, value, intValue, boolValue, multiValue, multiIntValue, messageValue{parameter[]}, multiMessageValue[{parameter[]}]}]}]`, `networkInfo{ipAsn[], regionCode, subdivisionCode}`, `resourceDetails[]`; full `applicationName` enum. |
| https://developers.google.com/workspace/admin/reports/v1/appendix/activity/login | `login` event types/names/params: `login` (login_success, login_failure, login_challenge, login_verification, logout, risky_sensitive_action_allowed/blocked), `account_warning` (suspicious_login, suspicious_login_less_secure_app, suspicious_programmatic_login, account_disabled_*), `attack_warning` (gov_attack_warning), `2sv_change`, `password_change`, `recovery_info_change`, `titanium_change`, `email_forwarding_change` (email_forwarding_out_of_domain), `blocked_sender_change`; enum values for `login_type`, `login_challenge_method`, `login_failure_type`. |
| https://developers.google.com/workspace/admin/reports/v1/appendix/activity/user-accounts | `user_accounts` events: `2sv_disable`/`2sv_enroll` (type `2sv_change`), `password_edit`, `recovery_*_edit`, `titanium_*`, `email_forwarding_out_of_domain` (param `email_forwarding_destination_address`). |
| https://developers.google.com/workspace/admin/reports/v1/appendix/activity/drive | `drive` types `access` (download, view, edit, copy, create, delete, ...) and `acl_change` (change_user_access, change_document_visibility, change_document_access_scope, ...); common params `doc_id`, `doc_title`, `doc_type`, `owner`, `owner_is_shared_drive`, `primary_event`, `billable`, `visibility`, `originating_app_id`, `actor_is_collaborator_account`, `is_encrypted`, `shared_drive_id`; ACL params `target_user`, `target_domain`, `old_value`, `new_value`, `old_visibility`, `visibility_change`; enums for visibility, roles, visibility_change. |
| https://developers.google.com/workspace/admin/reports/v1/appendix/activity/token | `token` type `auth`: `authorize`, `revoke`, `deny`, `request`, `activity`; params `app_name`, `client_id`, `client_type`, `scope`, `scope_data`, `api_name`, `method_name`, `num_response_bytes`, `product_bucket`. |
| https://developers.google.com/workspace/admin/reports/v1/appendix/activity/admin-user-settings | type `USER_SETTINGS`: `GRANT_ADMIN_PRIVILEGE`, `REVOKE_ADMIN_PRIVILEGE`, `CHANGE_PASSWORD`, `CREATE_USER`, `SUSPEND_USER`, `TURN_OFF_2_STEP_VERIFICATION`, `RESET_SIGNIN_COOKIES`, `GRANT_DELEGATED_ADMIN_PRIVILEGES` (param `USER_EMAIL`, some `NEW_VALUE`/`OLD_VALUE`). |
| https://developers.google.com/workspace/admin/reports/v1/appendix/activity/admin-delegated-admin-settings | type `DELEGATED_ADMIN_SETTINGS`: `ASSIGN_ROLE`/`UNASSIGN_ROLE` (`ROLE_NAME`, `USER_EMAIL`, `ORG_UNIT_NAME`), `CREATE_ROLE`, `ADD_PRIVILEGE` (`PRIVILEGE_NAME`, `ROLE_ID`, `ROLE_NAME`). |
| https://developers.google.com/workspace/admin/reports/v1/appendix/activity/admin-gmail-settings | type `EMAIL_SETTINGS`: `CHANGE_GMAIL_SETTING`, `CREATE_GMAIL_SETTING`, `DELETE_GMAIL_SETTING`, `CHANGE_EMAIL_SETTING` (`SETTING_NAME`, `NEW_VALUE`, `OLD_VALUE`, `ORG_UNIT_NAME`, ...). No dedicated "admin set forwarding for user" event documented. |
| https://developers.google.com/workspace/admin/reports/v1/appendix/activity/gmail | `gmail` app: single event `delivery` (type `delivery_type`), params `event_info` (nested; `event_info.mail_event_type` int 0–35) and `message_info` (nested, not expanded on the page); start/end time required, max 30-day window. |
| https://knowledge.workspace.google.com/admin/reports/schema-for-gmail-logs-in-bigquery | Names of nested Gmail message fields (`message_info.rfc2822_message_id`, `subject`, `source.address`, `source.from_header_address`, `connection_info.client_ip`, `destination[]`, `is_spam`, `link_domain`, `attachment[]`, `triggered_rule_info[]`). |
| https://github.com/Azure/Azure-Sentinel/tree/master/Sample%20Data/Custom (`GWorkspace_ReportsAPI_*_CL.json`) and https://github.com/elastic/integrations/tree/main/packages/google_workspace | Real value shapes: `id.time` with milliseconds `2020-11-10T07:26:03.025Z`, `uniqueQualifier` as signed int64 **string** (`"-8365551478938402017"`), `customerId` like `C015t6bdl`, `profileId` 21-digit **string**, `etag` quoted string, `kind:"admin#reports#activity"`; token `scope` = `multiValue` array, `scope_data` = `multiMessageValue` of `{parameter:[scope_name, product_bucket(multiValue)]}`; drive `change_document_visibility` params incl. `visibility_change`, `target_domain:"all"`. |

---

## 2. Native format & delivery

- **Transport**: `GET https://admin.googleapis.com/admin/reports/v1/activity/users/all/applications/{applicationName}?startTime=...` (OAuth, scope `admin.reports.audit.readonly`). Response page:
  ```json
  { "kind": "admin#reports#activities", "etag": "\"Qm9vX3BhZ2VfZXRhZw/x1\"", "items": [ { "kind": "admin#reports#activity" } ], "nextPageToken": "A:1790667672418000:-4821936017452283615:login:C03k8x2pq" }
  ```
  (`items` abridged; `nextPageToken` is opaque — its format here is illustrative only.) Push alternative: `activities.watch` channel notifications carry the same activity object.
- **We standardise on**: one log = one item of `items[]` (the Activity resource), keys and nesting exactly as below.
- Value typing (important, this is how the API serialises):
  - `intValue` and `multiIntValue` are **int64 encoded as JSON strings** (`"intValue": "1790667672418000"`).
  - `boolValue` is a real JSON boolean.
  - `uniqueQualifier` and `profileId` are strings.
  - Exactly ONE value key is present per parameter (`value` | `intValue` | `boolValue` | `multiValue` | `multiIntValue` | `messageValue` | `multiMessageValue`).
- `id.time`: RFC 3339 UTC with milliseconds, `2026-09-29T07:41:12.345Z`.
- `ipAddress` may be IPv4 or IPv6 and can be absent (system events). `networkInfo` (ASN/region) is newer and may be absent.

---

## 3. Core field reference

### 3.1 Activity envelope

| Path | Type | Notes |
|---|---|---|
| `kind` | string | always `admin#reports#activity` |
| `id.time` | string RFC 3339 | event time |
| `id.uniqueQualifier` | string (int64) | unique per activity when combined with time; **pivot id** |
| `id.applicationName` | string | `login`, `user_accounts`, `drive`, `token`, `admin`, `saml`, `gmail`, `groups`, `calendar`, `meet`, `chat`, `mobile`, `rules`, `context_aware_access`, `chrome`, `vault`, `gemini_in_workspace_apps`, ... |
| `id.customerId` | string | e.g. `C03k8x2pq` |
| `etag` | string | quoted, e.g. `"\"d7Rk.../AbC...\""` |
| `actor.email` | string | acting user (absent for some system actors) |
| `actor.profileId` | string | Google account id |
| `actor.callerType` | string | `USER` or `KEY` (with `actor.key`, e.g. `SYSTEM`) |
| `actor.applicationInfo` | object | `oauthClientId`, `applicationName`, `impersonation` — when an app acted on behalf of the user |
| `ownerDomain` | string | domain affected |
| `ipAddress` | string | actor IP |
| `networkInfo.ipAsn` | int[] | ASN(s) |
| `networkInfo.regionCode` / `subdivisionCode` | string | `IL`, `US`, `US-CA` ... |
| `events[]` | array | usually 1 element; `type`, `name`, `parameters[]` |
| `resourceDetails[]` | array | `id`, `title`, `type`, `relation`, `appliedLabels`, `ownerDetails` (Drive, newer) |

### 3.2 `login` application (selected)

| events[].type | events[].name | parameters |
|---|---|---|
| `login` | `login_success` | `login_type`, `login_challenge_method`, `login_challenge_status`, `is_suspicious` (bool) |
| `login` | `login_failure` | `login_type`, `login_challenge_method`, `login_failure_type` (deprecated) |
| `login` | `login_challenge`, `login_verification` | `login_challenge_method`, `login_challenge_status`, `is_second_factor` (verification) |
| `login` | `logout` | `login_type` |
| `login` | `risky_sensitive_action_allowed/_blocked` | `sensitive_action_name`, `is_suspicious`, ... |
| `account_warning` | `suspicious_login`, `suspicious_login_less_secure_app`, `suspicious_programmatic_login` | `affected_email_address`, `login_timestamp` (intValue, epoch **microseconds**) |
| `account_warning` | `account_disabled_password_leak`, `account_disabled_hijacked`, `account_disabled_spamming`, `user_signed_out_due_to_suspicious_session_cookie` | `affected_email_address` (+ `login_timestamp` for hijacked) |
| `attack_warning` | `gov_attack_warning` | — |
| `2sv_change` | `2sv_disable`, `2sv_enroll` | — |
| `email_forwarding_change` | `email_forwarding_out_of_domain` | `email_forwarding_destination_address` |
| `password_change` | `password_edit` | — |
| `recovery_info_change` | `recovery_email_edit`, `recovery_phone_edit`, `recovery_secret_qa_edit` | — |

Enums: `login_type` ∈ `exchange`, `google_password`, `reauth`, `saml`, `unknown`.
`login_challenge_method` (subset) ∈ `password`, `google_prompt`, `google_authenticator`, `idv_preregistered_phone`, `security_key`, `passkey`, `backup_code`, `none`, `saml`, `login_location`, `captcha`, `internal_two_factor`, `offline_otp`.
`login_failure_type` ∈ `login_failure_invalid_password`, `login_failure_account_disabled`, `login_failure_access_code_disallowed`, `login_failure_unknown`.
Doc types `login_challenge_method` as string; real exports commonly carry it as `multiValue` (several methods in one login) — we emit `multiValue`; consumers must accept `value` too.

### 3.3 `user_accounts` application
Same event names as the user-self-service subset of `login`: `2sv_disable`, `2sv_enroll`, `password_edit`, `recovery_email_edit`, `recovery_phone_edit`, `recovery_secret_qa_edit`, `titanium_enroll`, `titanium_unenroll`, `email_forwarding_out_of_domain`.

### 3.4 `drive` application

| type | names | key parameters |
|---|---|---|
| `access` | `download`, `view`, `edit`, `copy`, `create`, `upload`, `delete`, `trash`, `print`, `preview`, `add_to_folder`, `request_access` ... | common: `doc_id`, `doc_title`, `doc_type`, `owner`, `owner_is_shared_drive`, `primary_event`, `billable`, `visibility`, `originating_app_id`, `actor_is_collaborator_account`, `is_encrypted`, `shared_drive_id` |
| `acl_change` | `change_user_access` | + `target_user`, `old_value`, `new_value`, `old_visibility`, `visibility_change` |
| `acl_change` | `change_document_visibility` | + `target_domain`, `old_value`, `new_value`, `old_visibility`, `visibility_change` |
| `acl_change` | `change_document_access_scope`, `change_acl_editors`, `shared_drive_membership_change` ... | |

Enums: `visibility` / `old_visibility` ∈ `people_with_link`, `people_within_domain_with_link`, `private`, `public_in_the_domain`, `public_on_the_web`, `shared_externally`, `shared_internally`, `unknown`.
`change_user_access` `old_value`/`new_value` ∈ `none`, `can_view`, `can_comment`, `can_edit`, `can_view_published`, `can_respond`, `organizer`, `owner`.
`change_document_visibility` `old_value`/`new_value` ∈ `people_with_link`, `people_within_domain_with_link`, `private`, `public_in_the_domain`, `public_on_the_web`. Real data often carries these two as `multiValue` (UNVERIFIED; doc says string) — we use `multiValue` for `change_document_visibility`, `value` for `change_user_access`.
`visibility_change` ∈ `external`, `internal`, `none`. `target_domain` may be the alias `all`.
`doc_type` ∈ `document`, `spreadsheet`, `presentation`, `pdf`, `msword`, `msexcel`, `mspowerpoint`, `folder`, `txt`, `jpeg`, `png`, `mp4`, `shared_drive`, `unknown` ...

### 3.5 `token` application (type `auth`)
`authorize` / `revoke` / `deny` / `request`: `app_name`, `client_id`, `client_type` (`WEB`, `NATIVE_DESKTOP`, `NATIVE_ANDROID`, `NATIVE_IOS`, ...), `scope` (**multiValue**), `scope_data` (**multiMessageValue**: each `{ "parameter": [ {name:"scope_name", value}, {name:"product_bucket", multiValue:[...]} ] }`); `activity`: `api_name`, `method_name`, `num_response_bytes`, `product_bucket`.
`product_bucket` examples: `GMAIL`, `DRIVE`, `IDENTITY`, `CALENDAR`, `APPS_SCRIPT_RUNTIME`, `OTHER`.

### 3.6 `admin` application (selected)
- `USER_SETTINGS`: `GRANT_ADMIN_PRIVILEGE` (`USER_EMAIL`) — makes a user super admin; `REVOKE_ADMIN_PRIVILEGE`; `CHANGE_PASSWORD`; `TURN_OFF_2_STEP_VERIFICATION`; `SUSPEND_USER`; `RESET_SIGNIN_COOKIES`; `GRANT_DELEGATED_ADMIN_PRIVILEGES` (`NEW_VALUE`, `USER_EMAIL`).
- `DELEGATED_ADMIN_SETTINGS`: `ASSIGN_ROLE` (`ROLE_NAME`, `USER_EMAIL`, `ORG_UNIT_NAME`) — `ROLE_NAME` like `_SEED_ADMIN_ROLE` (Super Admin), `_HELP_DESK_ADMIN_ROLE`, `_GROUPS_ADMIN_ROLE`, `_USER_MANAGEMENT_ADMIN_ROLE`.
- `EMAIL_SETTINGS`: `CHANGE_GMAIL_SETTING` / `CREATE_GMAIL_SETTING` (`SETTING_NAME`, `ORG_UNIT_NAME`, `NEW_VALUE`, `OLD_VALUE`, ...), `CHANGE_EMAIL_SETTING`.
- Admin parameter names are UPPER_SNAKE_CASE; login/drive/token parameter names are lower_snake_case.

### 3.7 `gmail` application (Enterprise/Education Plus) — UNVERIFIED nested layout
One event name `delivery` (type `delivery_type`). Parameters `event_info` (messageValue; `mail_event_type` intValue 0–35: 1 sent, 2 received, 5 quarantined, 7 opened first time, 10 forwarded, 11 auto-forwarded, 15 link clicked, 17 attachment downloaded, 31 viewed, 33 app accessed message ...) and `message_info` (messageValue; sub-parameter names taken from the BigQuery Gmail schema: `rfc2822_message_id`, `subject`, `source` {`address`, `from_header_address`}, `connection_info` {`client_ip`}, `destination` (multiMessageValue {`address`}), `is_spam`, `link_domain`, `attachment` (multiMessageValue {`file_name`, `sha256`})). The exact Reports-API nesting of `message_info` is **not expanded in Google's reference** — treat G10 below as UNVERIFIED.

---

## 4. Realistic samples (fictitious customer `C03k8x2pq`, domain `globallogis.com`)

Story: `noa.friedman@globallogis.com` is phished; attacker signs in from `203.0.113.91`, disables 2SV, sets out-of-domain
forwarding, authorizes a broad-scope OAuth app, mass-downloads Drive files and opens a sensitive file to the web;
a compromised admin grants super-admin to an attacker-controlled account.

### G1 — Successful login flagged suspicious (`login` / `login_success`)
```json
{
  "kind": "admin#reports#activity",
  "id": {
    "time": "2026-09-29T07:41:12.418Z",
    "uniqueQualifier": "-4821936017452283615",
    "applicationName": "login",
    "customerId": "C03k8x2pq"
  },
  "etag": "\"Qm9vX2xvZ2luX2V0YWc/7xK2pV9dLr4sT0bWnE1yHc3uZaM\"",
  "actor": {
    "callerType": "USER",
    "email": "noa.friedman@globallogis.com",
    "profileId": "104729385610473829156"
  },
  "ownerDomain": "globallogis.com",
  "ipAddress": "203.0.113.91",
  "networkInfo": {
    "ipAsn": [64500],
    "regionCode": "NL",
    "subdivisionCode": "NL-NH"
  },
  "events": [
    {
      "type": "login",
      "name": "login_success",
      "parameters": [
        { "name": "login_type", "value": "google_password" },
        { "name": "login_challenge_method", "multiValue": ["password"] },
        { "name": "is_suspicious", "boolValue": true }
      ]
    }
  ]
}
```

### G2 — Google flags the login (`login` / `account_warning` / `suspicious_login`)
```json
{
  "kind": "admin#reports#activity",
  "id": {
    "time": "2026-09-29T07:43:30.902Z",
    "uniqueQualifier": "7390214658837120441",
    "applicationName": "login",
    "customerId": "C03k8x2pq"
  },
  "etag": "\"Qm9vX2xvZ2luX2V0YWc/Lp0aC8mWq3eR5tY7uI9oP1sD2fG\"",
  "actor": {
    "callerType": "USER",
    "email": "noa.friedman@globallogis.com",
    "profileId": "104729385610473829156"
  },
  "ownerDomain": "globallogis.com",
  "ipAddress": "203.0.113.91",
  "events": [
    {
      "type": "account_warning",
      "name": "suspicious_login",
      "parameters": [
        { "name": "affected_email_address", "value": "noa.friedman@globallogis.com" },
        { "name": "login_timestamp", "intValue": "1790667672418000" }
      ]
    }
  ]
}
```
(`login_timestamp` = epoch **microseconds** of the sign-in in G1 — `1790667672418000` = 2026-09-29T07:41:12.418Z. Always compute it from the scenario's own login time.)

### G3 — 2-Step Verification disabled by the (compromised) user (`user_accounts` / `2sv_disable`)
```json
{
  "kind": "admin#reports#activity",
  "id": {
    "time": "2026-09-29T07:47:05.137Z",
    "uniqueQualifier": "2056473918204736158",
    "applicationName": "user_accounts",
    "customerId": "C03k8x2pq"
  },
  "etag": "\"Qm9vX3VhX2V0YWc/Zx8cV6bN4mQ2wE0rT8yU6iO4pA2sD\"",
  "actor": {
    "callerType": "USER",
    "email": "noa.friedman@globallogis.com",
    "profileId": "104729385610473829156"
  },
  "ownerDomain": "globallogis.com",
  "ipAddress": "203.0.113.91",
  "events": [
    { "type": "2sv_change", "name": "2sv_disable" }
  ]
}
```
(Events with no parameters omit `parameters` entirely.)

### G4 — Out-of-domain auto-forwarding enabled (`user_accounts` / `email_forwarding_out_of_domain`)
```json
{
  "kind": "admin#reports#activity",
  "id": {
    "time": "2026-09-29T07:51:44.560Z",
    "uniqueQualifier": "-1187364520973841206",
    "applicationName": "user_accounts",
    "customerId": "C03k8x2pq"
  },
  "etag": "\"Qm9vX3VhX2V0YWc/Hn3jK5lM7nB9vC1xZ3aS5dF7gH9jK\"",
  "actor": {
    "callerType": "USER",
    "email": "noa.friedman@globallogis.com",
    "profileId": "104729385610473829156"
  },
  "ownerDomain": "globallogis.com",
  "ipAddress": "203.0.113.91",
  "events": [
    {
      "type": "email_forwarding_change",
      "name": "email_forwarding_out_of_domain",
      "parameters": [
        { "name": "email_forwarding_destination_address", "value": "noa.friedman.archive@proton.me" }
      ]
    }
  ]
}
```

### G5 — OAuth app authorized with broad scopes (`token` / `authorize`)
```json
{
  "kind": "admin#reports#activity",
  "id": {
    "time": "2026-09-29T07:58:19.004Z",
    "uniqueQualifier": "5621907348816627093",
    "applicationName": "token",
    "customerId": "C03k8x2pq"
  },
  "etag": "\"Qm9vX3Rva2VuX2V0YWc/Rt5yU7iO9pA1sD3fG5hJ7kL9zX1\"",
  "actor": {
    "callerType": "USER",
    "email": "noa.friedman@globallogis.com",
    "profileId": "104729385610473829156"
  },
  "ownerDomain": "globallogis.com",
  "ipAddress": "203.0.113.91",
  "events": [
    {
      "type": "auth",
      "name": "authorize",
      "parameters": [
        { "name": "client_id", "value": "418273650912-7kq2d9vbn3m5x8r1t4w6y0z2a4c6e8g0.apps.googleusercontent.com" },
        { "name": "app_name", "value": "PDF Docs Sync" },
        { "name": "client_type", "value": "WEB" },
        {
          "name": "scope_data",
          "multiMessageValue": [
            { "parameter": [ { "name": "scope_name", "value": "https://mail.google.com/" }, { "name": "product_bucket", "multiValue": ["GMAIL"] } ] },
            { "parameter": [ { "name": "scope_name", "value": "https://www.googleapis.com/auth/drive" }, { "name": "product_bucket", "multiValue": ["DRIVE"] } ] },
            { "parameter": [ { "name": "scope_name", "value": "https://www.googleapis.com/auth/contacts.readonly" }, { "name": "product_bucket", "multiValue": ["OTHER"] } ] },
            { "parameter": [ { "name": "scope_name", "value": "https://www.googleapis.com/auth/userinfo.email" }, { "name": "product_bucket", "multiValue": ["IDENTITY"] } ] },
            { "parameter": [ { "name": "scope_name", "value": "openid" }, { "name": "product_bucket", "multiValue": ["IDENTITY"] } ] }
          ]
        },
        {
          "name": "scope",
          "multiValue": [
            "https://mail.google.com/",
            "https://www.googleapis.com/auth/drive",
            "https://www.googleapis.com/auth/contacts.readonly",
            "https://www.googleapis.com/auth/userinfo.email",
            "openid"
          ]
        }
      ]
    }
  ]
}
```

### G6 — Mass Drive download (`drive` / `download`; one of ~450 events in 12 minutes)
```json
{
  "kind": "admin#reports#activity",
  "id": {
    "time": "2026-09-29T08:06:52.771Z",
    "uniqueQualifier": "-6093847215560192837",
    "applicationName": "drive",
    "customerId": "C03k8x2pq"
  },
  "etag": "\"Qm9vX2RyaXZlX2V0YWc/Ab2cD4eF6gH8iJ0kL2mN4oP6qR8\"",
  "actor": {
    "callerType": "USER",
    "email": "noa.friedman@globallogis.com",
    "profileId": "104729385610473829156"
  },
  "ownerDomain": "globallogis.com",
  "ipAddress": "203.0.113.91",
  "events": [
    {
      "type": "access",
      "name": "download",
      "parameters": [
        { "name": "primary_event", "boolValue": true },
        { "name": "billable", "boolValue": true },
        { "name": "owner_is_shared_drive", "boolValue": true },
        { "name": "owner", "value": "Finance Shared" },
        { "name": "shared_drive_id", "value": "0AKx9pQ2rT4vNUk9PVA" },
        { "name": "doc_id", "value": "1Rk7nQ2wX9vB4mT6yH8jL0pZ3cF5dS1aE7gU9iO2" },
        { "name": "doc_type", "value": "spreadsheet" },
        { "name": "is_encrypted", "boolValue": false },
        { "name": "doc_title", "value": "Customer Rates 2026 - CONFIDENTIAL" },
        { "name": "visibility", "value": "shared_internally" },
        { "name": "originating_app_id", "value": "691301496089" },
        { "name": "actor_is_collaborator_account", "boolValue": false }
      ]
    }
  ]
}
```

### G7 — File made public on the web (`drive` / `change_document_visibility`)
```json
{
  "kind": "admin#reports#activity",
  "id": {
    "time": "2026-09-29T08:21:07.335Z",
    "uniqueQualifier": "3318470925561048276",
    "applicationName": "drive",
    "customerId": "C03k8x2pq"
  },
  "etag": "\"Qm9vX2RyaXZlX2V0YWc/St9uV1wX3yZ5aB7cD9eF1gH3iJ5\"",
  "actor": {
    "callerType": "USER",
    "email": "noa.friedman@globallogis.com",
    "profileId": "104729385610473829156"
  },
  "ownerDomain": "globallogis.com",
  "ipAddress": "203.0.113.91",
  "events": [
    {
      "type": "acl_change",
      "name": "change_document_visibility",
      "parameters": [
        { "name": "primary_event", "boolValue": true },
        { "name": "billable", "boolValue": true },
        { "name": "visibility_change", "value": "external" },
        { "name": "target_domain", "value": "all" },
        { "name": "old_value", "multiValue": ["private"] },
        { "name": "new_value", "multiValue": ["people_with_link"] },
        { "name": "old_visibility", "value": "private" },
        { "name": "visibility", "value": "people_with_link" },
        { "name": "owner_is_shared_drive", "boolValue": false },
        { "name": "owner", "value": "noa.friedman@globallogis.com" },
        { "name": "doc_id", "value": "1Mq4wE6rT8yU0iO2pA4sD6fG8hJ0kL2zX4cV6bN8" },
        { "name": "doc_type", "value": "pdf" },
        { "name": "is_encrypted", "boolValue": false },
        { "name": "doc_title", "value": "Payroll_Export_Sep2026.pdf" },
        { "name": "originating_app_id", "value": "691301496089" },
        { "name": "actor_is_collaborator_account", "boolValue": false }
      ]
    }
  ]
}
```

### G8 — File shared with an external personal account (`drive` / `change_user_access`)
```json
{
  "kind": "admin#reports#activity",
  "id": {
    "time": "2026-09-29T08:23:41.090Z",
    "uniqueQualifier": "-2749105836617320954",
    "applicationName": "drive",
    "customerId": "C03k8x2pq"
  },
  "etag": "\"Qm9vX2RyaXZlX2V0YWc/Kl7mN9oP1qR3sT5uV7wX9yZ1aB3\"",
  "actor": {
    "callerType": "USER",
    "email": "noa.friedman@globallogis.com",
    "profileId": "104729385610473829156"
  },
  "ownerDomain": "globallogis.com",
  "ipAddress": "203.0.113.91",
  "events": [
    {
      "type": "acl_change",
      "name": "change_user_access",
      "parameters": [
        { "name": "primary_event", "boolValue": true },
        { "name": "billable", "boolValue": true },
        { "name": "visibility_change", "value": "external" },
        { "name": "target_user", "value": "logis.backup.2026@gmail.com" },
        { "name": "old_value", "value": "none" },
        { "name": "new_value", "value": "can_view" },
        { "name": "old_visibility", "value": "shared_internally" },
        { "name": "visibility", "value": "shared_externally" },
        { "name": "owner_is_shared_drive", "boolValue": true },
        { "name": "owner", "value": "Finance Shared" },
        { "name": "shared_drive_id", "value": "0AKx9pQ2rT4vNUk9PVA" },
        { "name": "doc_id", "value": "1Rk7nQ2wX9vB4mT6yH8jL0pZ3cF5dS1aE7gU9iO2" },
        { "name": "doc_type", "value": "spreadsheet" },
        { "name": "is_encrypted", "boolValue": false },
        { "name": "doc_title", "value": "Customer Rates 2026 - CONFIDENTIAL" },
        { "name": "originating_app_id", "value": "691301496089" },
        { "name": "actor_is_collaborator_account", "boolValue": false }
      ]
    }
  ]
}
```

### G9 — Super-admin granted (`admin` / `GRANT_ADMIN_PRIVILEGE`) and role assignment (`ASSIGN_ROLE`)
```json
{
  "kind": "admin#reports#activity",
  "id": {
    "time": "2026-09-30T21:04:51.226Z",
    "uniqueQualifier": "8402716395547719012",
    "applicationName": "admin",
    "customerId": "C03k8x2pq"
  },
  "etag": "\"Qm9vX2FkbWluX2V0YWc/Cd5eF7gH9iJ1kL3mN5oP7qR9sT1\"",
  "actor": {
    "callerType": "USER",
    "email": "it.admin@globallogis.com",
    "profileId": "117204958361047289305"
  },
  "ownerDomain": "globallogis.com",
  "ipAddress": "203.0.113.91",
  "events": [
    {
      "type": "USER_SETTINGS",
      "name": "GRANT_ADMIN_PRIVILEGE",
      "parameters": [
        { "name": "USER_EMAIL", "value": "svc-sync@globallogis.com" }
      ]
    }
  ]
}
```
```json
{
  "kind": "admin#reports#activity",
  "id": {
    "time": "2026-09-30T21:05:02.871Z",
    "uniqueQualifier": "-5530918274406671193",
    "applicationName": "admin",
    "customerId": "C03k8x2pq"
  },
  "etag": "\"Qm9vX2FkbWluX2V0YWc/Uv3wX5yZ7aB9cD1eF3gH5iJ7kL9\"",
  "actor": {
    "callerType": "USER",
    "email": "it.admin@globallogis.com",
    "profileId": "117204958361047289305"
  },
  "ownerDomain": "globallogis.com",
  "ipAddress": "203.0.113.91",
  "events": [
    {
      "type": "DELEGATED_ADMIN_SETTINGS",
      "name": "ASSIGN_ROLE",
      "parameters": [
        { "name": "ROLE_NAME", "value": "_SEED_ADMIN_ROLE" },
        { "name": "USER_EMAIL", "value": "svc-sync@globallogis.com" },
        { "name": "ORG_UNIT_NAME", "value": "/" }
      ]
    }
  ]
}
```

### G10 — Gmail delivery log: phishing message received (`gmail` / `delivery`) — UNVERIFIED nesting
```json
{
  "kind": "admin#reports#activity",
  "id": {
    "time": "2026-09-29T07:12:03.554Z",
    "uniqueQualifier": "1940365812274093716",
    "applicationName": "gmail",
    "customerId": "C03k8x2pq"
  },
  "etag": "\"Qm9vX2dtYWlsX2V0YWc/Mn1oP3qR5sT7uV9wX1yZ3aB5cD7\"",
  "actor": {
    "callerType": "USER",
    "email": "noa.friedman@globallogis.com",
    "profileId": "104729385610473829156"
  },
  "ownerDomain": "globallogis.com",
  "events": [
    {
      "type": "delivery_type",
      "name": "delivery",
      "parameters": [
        {
          "name": "event_info",
          "messageValue": {
            "parameter": [
              { "name": "mail_event_type", "intValue": "2" },
              { "name": "success", "boolValue": true }
            ]
          }
        },
        {
          "name": "message_info",
          "messageValue": {
            "parameter": [
              { "name": "rfc2822_message_id", "value": "<CAJ7x0m9Q2wE4rT6yU8iO0pA2sD4fG6hJ8kL0zX2cV4bN6m@mail.gmail.com>" },
              { "name": "subject", "value": "Action required: shipment invoice #88231 on hold" },
              {
                "name": "source",
                "messageValue": {
                  "parameter": [
                    { "name": "address", "value": "billing@globa1logis-docs.com" },
                    { "name": "from_header_address", "value": "billing@globa1logis-docs.com" }
                  ]
                }
              },
              {
                "name": "connection_info",
                "messageValue": {
                  "parameter": [
                    { "name": "client_ip", "value": "198.51.100.203" }
                  ]
                }
              },
              {
                "name": "destination",
                "multiMessageValue": [
                  { "parameter": [ { "name": "address", "value": "noa.friedman@globallogis.com" } ] }
                ]
              },
              { "name": "is_spam", "boolValue": false },
              { "name": "link_domain", "multiValue": ["globa1logis-docs.com"] }
            ]
          }
        }
      ]
    }
  ]
}
```

---

## 5. Investigation notes (pivots)

- **Unique event id**: `id.time` + `id.uniqueQualifier` (+ `id.applicationName`). Drive "side-effect" events share the action with a `primary_event:true` record — count only `primary_event=true` for volumes.
- **IP pivot**: `ipAddress` across `login` → `user_accounts` → `token` → `drive` → `admin`; `networkInfo.ipAsn`/`regionCode` for impossible-travel without external geo.
- **User pivot**: `actor.email` (actor) vs parameter-level targets (`affected_email_address`, `target_user`, `USER_EMAIL`, `email_forwarding_destination_address`).
- **OAuth pivot**: `token` `client_id` → later `token` `activity` events with same `client_id` (`api_name` `gmail`/`drive`, `num_response_bytes`) show what the app actually pulled. `actor.applicationInfo.oauthClientId` on drive/gmail events shows app-initiated access.
- **Document pivot**: `doc_id` across `download` → `change_user_access` → `change_document_visibility`.
- **Message pivot**: `message_info.rfc2822_message_id` (Gmail) = RFC 5322 `Message-ID`; same value as Defender `InternetMessageId` / Proofpoint `messageID` if the mail traversed those systems.
- Sequence signature of ATO: `login_success(is_suspicious=true)` → `suspicious_login` → `2sv_disable` → `email_forwarding_out_of_domain` → `authorize` (mail/drive scopes) → burst of `download`.

## 6. Google Workspace ↔ M365 equivalence (do not fake an equivalent)

| Google event | M365 UAL equivalent | Equivalence |
|---|---|---|
| `login_success` / `login_failure` | `UserLoggedIn` / `UserLoginFailed` (RT 15) | True. |
| `suspicious_login`, `suspicious_programmatic_login` (`account_warning`) | none inside UAL (Entra Identity Protection risk detections are a separate source) | Partial / different source. |
| `gov_attack_warning` | none | **No equivalent.** |
| `2sv_disable` | per-user MFA / security-info removal in Entra audit (names UNVERIFIED in UAL) | Partial. |
| `email_forwarding_out_of_domain` | `Set-Mailbox` with `ForwardingSmtpAddress` (user/OWA-set) | Near-true. |
| Gmail filter that forwards/deletes | `New-InboxRule` / `Set-InboxRule` / `UpdateInboxRules` | **Google has no documented Reports API event for user filter creation — never generate one.** |
| `gmail` `delivery` with `mail_event_type` 7/31/33 | `MailItemsAccessed` | Partial (no SessionId, no Bind/Sync). |
| `download` / `view` | `FileDownloaded` / `FileAccessed` | True. |
| `change_document_visibility` → `people_with_link`/`public_on_the_web` | `AnonymousLinkCreated` | True. |
| `change_user_access` (external `target_user`) | `SharingSet` / `SharingInvitationCreated` / `AddedToSecureLink` | True. |
| `token` `authorize` | `Consent to application.` | True for per-user consent. |
| `GRANT_ADMIN_PRIVILEGE` / `ASSIGN_ROLE` | `Add member to role.` | True. |

## 7. Common mistakes / fields that do NOT exist

- No top-level `event_name`, `eventName`, `event_type`, `app_name`, `client_id`, `scope`, `doc_title`, `user`, `src_ip` — those live in `events[].name` / `events[].parameters[]` / `actor.email` / `ipAddress`.
- `events` is an **array**, `parameters` is an **array of `{name, <typedValue>}`** — never a dict like `"parameters":{"doc_title":"..."}`.
- No `value` + `boolValue` together; booleans use `boolValue`, int64 use `intValue` as a string.
- No `severity`, `risk_score`, `country`, `geo` fields (only `networkInfo` ASN/region codes).
- `login` events never carry `doc_*`; `drive` events never carry `login_type`. Admin parameters are UPPER_SNAKE (`USER_EMAIL`), not `user_email`.
- There is no `drive` event named `share`, `public_link_created`, `file_downloaded`; there is no `login` event named `mfa_disabled` or `login_suspicious`. Exact names: `change_document_visibility`, `download`, `2sv_disable`, `suspicious_login`.
- There is no `CHANGE_USER_PASSWORD` admin event; the documented one is `CHANGE_PASSWORD` (param `USER_EMAIL`).
- `id.customerId` is the `C0…` customer id, not the domain; `ownerDomain` is the domain.
- `uniqueQualifier` is a (possibly negative) int64 string, not a GUID.
