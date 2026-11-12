# Source control: GitHub Enterprise Cloud audit log (streamed events)

Category: Source control / CI (VCS) · Vendor: GitHub (Microsoft) · Card status: researched 2026-11-12

GitHub writes one audit event per action an account takes in an enterprise or organization: repository creation and
visibility changes, members and teams, tokens and SSH keys, webhooks, branch protection, Actions, and (when Git events
are enabled for the stream) every `git.clone` / `git.fetch` / `git.push`. A SOC receives it one of two ways:

| Path | What arrives |
|---|---|
| **Audit log streaming** (Enterprise Cloud: Azure Event Hubs, Azure Blob, Amazon S3, Splunk, Datadog, Google Cloud Storage) | Compressed JSON files `YYYY/MM/DD/HH/MM/<uuid>.json.log.gz`, one JSON object per event, at-least-once delivery (duplicates possible). Audit AND Git events. |
| **REST API** `GET /enterprises/{enterprise}/audit-log` (or `/orgs/{org}/audit-log`), scope `read:audit_log` | A JSON array of the same event objects. Default range three months, 180 days kept; Git events only with `include=git` / `include=all`, kept 7 days. |

Microsoft Sentinel's GitHub solution reads the same objects into **`GitHubAuditLogsV2_CL`** (connector "GitHub Enterprise
Audit Log (via Codeless Connector Framework)"; the older polling connector wrote `GitHubAuditLogPolling_CL` and is
deprecated). Column names are the snake_case keys in PascalCase: `Action`, `Actor`, `ActorId`, `ActorIp`, `ActorLocation`,
`ActorIsBot`, `OperationType`, `Org`, `OrgId`, `Repo`, `RepoId`, `Repository`, `RepositoryPublic`, `Business`, `BusinessId`,
`UserAgent`, `TransportProtocol`, `TransportProtocolName`, `HashedToken`, `TokenId`, `TokenScopes`, `ProgrammaticAccessType`,
`Visibility`, `PreviousVisibility`, `PullRequestId`, `PullRequestTitle`, `PullRequestUrl`, `Fingerprint`, `User`, `CreatedAt`,
`DocumentId`, `TimeGenerated`.

Platform rule: the feed shows the **streamed event object** (snake_case keys, epoch-millisecond times). The XDR console
shows the `GitHubAuditLogsV2_CL` row built from it.

---

## 1. Official / primary sources consulted

| URL | What it confirmed |
|---|---|
| https://docs.github.com/en/enterprise-cloud@latest/rest/enterprise-admin/audit-log | Event object properties: `@timestamp` (integer), `action`, `actor`, `actor_id` (integer), `actor_location` (object), `org`, `org_id`, `business`, `business_id`, `user`, `user_id`, `operation_type`, `created_at` (integer), `_document_id` (string), `repo`, `repository`, `repository_public` (boolean), `transport_protocol` (integer), `transport_protocol_name`, `visibility`, `previous_visibility`, `fingerprint`, `deploy_key_fingerprint`, `hook_id`, `name`, `events`, `config`, `team`, `read_only`, `explanation`, `data` (open object) |
| https://docs.github.com/en/enterprise-cloud@latest/admin/monitoring-activity-in-your-enterprise/reviewing-audit-logs-for-your-enterprise/audit-log-events-for-your-enterprise | Per-action descriptions and additional fields: `git.clone` / `git.fetch` / `git.push` ("A repository was cloned." ... with `external_id`, `repository_public`, `transport_protocol`, `transport_protocol_name`); `repo.create` (`actor_is_agent`, `oauth_application_id`, `public_repo`, `request_category`, `request_method`, `user_programmatic_access_name`, `visibility`); `repo.access` ("The visibility of a repository changed", `previous_visibility`, `visibility`); `repo.download_zip`; `repo.add_member` (`permission`); `pull_request.create` (`actor_is_agent`, `agent_session_id`, `pull_request_id`, `pull_request_title`, `pull_request_url`); `public_key.create` ("An SSH key was added to a user account or a deploy key was added to a repository", `fingerprint`, `key`, `read_only`, `title`); `personal_access_token.access_granted` / `.request_created` (`repositories`, `repository_selection`, `user_programmatic_access_id`, `user_programmatic_access_name`); `org.add_member` / `org.invite_member` (`invitation_id`, `invitee_email`, `permission`); `protected_branch.policy_override`; `hook.create` (`hook_id`, `events`, `name`) |
| https://docs.github.com/en/enterprise-cloud@latest/admin/monitoring-activity-in-your-enterprise/reviewing-audit-logs-for-your-enterprise/identifying-audit-log-events-performed-by-an-access-token | `hashed_token` = SHA-256 of the token, base64 (`echo -n TOKEN \| openssl dgst -sha256 -binary \| base64`); `programmatic_access_type` = type of authentication used; `token_scopes` = the token's scopes |
| https://docs.github.com/en/enterprise-cloud@latest/admin/monitoring-activity-in-your-enterprise/reviewing-audit-logs-for-your-enterprise/searching-the-audit-log-for-your-enterprise | Operation types `create`, `access`, `modify`, `remove`, `authentication`, `transfer`, `restore`; qualifiers `ip` (actor IP), `country` (two-letter code), `hashed_token`; Git events are not in UI search |
| https://docs.github.com/en/enterprise-cloud@latest/admin/monitoring-activity-in-your-enterprise/reviewing-audit-logs-for-your-enterprise/streaming-the-audit-log-for-your-enterprise | Stream file naming, compressed JSON, audit + Git events, at-least-once delivery; Event Hubs / Blob targets |
| https://docs.github.com/en/enterprise-cloud@latest/admin/monitoring-activity-in-your-enterprise/reviewing-audit-logs-for-your-enterprise/using-the-audit-log-api-for-your-enterprise | Times are UTC epoch milliseconds; 180-day window; Git events kept seven days; `include=git` |
| https://learn.microsoft.com/azure/sentinel/data-connectors/github-enterprise-audit-log and the GitHub solution's `GitHubAuditLogs_Table.json` (column list mirrored at oshezaf.github.io/sentinelninja, table githubauditlogsv2-cl) | Sentinel table `GitHubAuditLogsV2_CL` and its columns listed above, including `ActorIp`, `ActorLocation` (dynamic), `ActorIsBot`, `ActorIsAgent`, `AgentSessionId`, `HashedToken`, `TokenId`, `TokenScopes`, `ProgrammaticAccessType`, `TransportProtocolName`, `RepositoryPublic` |
| https://cloud.google.com/chronicle/docs/ingestion/default-parsers/github (Google SecOps GitHub parser field mapping) | Streamed keys as received by a SIEM: `actor_ip`, `actor_location.country_code`, `user_agent`, `hashed_token`, `programmatic_access_type`, `transport_protocol_name`, `repository`, `business`, `org_id`, `external_identity_nameid`, `token_scopes`, `operation_type`, `request_id` |

## 2. Field reference (streamed event)

| Field | Type | Notes |
|---|---|---|
| `@timestamp` | integer (epoch ms) | When GitHub recorded the event. Same value as `created_at` in practice. |
| `created_at` | integer (epoch ms) | |
| `_document_id` | string | Opaque 22-character id (base64url alphabet). Dedupe key for at-least-once delivery. |
| `action` | string | `<category>.<event>`: `git.clone`, `repo.create`, `pull_request.create` ... |
| `operation_type` | string | `create` / `access` / `modify` / `remove` / `authentication` / `transfer` / `restore` |
| `actor`, `actor_id` | string, integer | The login that acted and its numeric id. An Enterprise Managed User login carries the enterprise shortcode suffix (`m-cohen_nexacorp`). |
| `actor_ip` | string | Present only when the enterprise enabled "Display IP addresses in the audit log". |
| `actor_location` | object | `{ "country_code": "IL" }` (two-letter code). |
| `actor_is_bot` / `actor_is_agent` | boolean | A GitHub App / bot account; an AI agent acting for the user (Copilot agent sessions). |
| `user_agent` | string | Web and API events: the client's User-Agent (`git/2.47.1`, `GitHub CLI 2.63.0`, a browser string). |
| `request_id` | string | GitHub's request id (`X-GitHub-Request-Id`), web and API events. |
| `business`, `business_id` | string, integer | The enterprise slug and id. |
| `org`, `org_id` | string, integer | |
| `repo`, `repo_id` | string (`owner/name`), integer | |
| `repository`, `repository_public` | string, boolean | Git events name the repository here (and in `repo`). |
| `visibility`, `previous_visibility`, `public_repo` | string, string, boolean | `public` / `private` / `internal`. |
| `transport_protocol`, `transport_protocol_name` | integer, string | Git events: `1` / `http`, `2` / `ssh`. |
| `programmatic_access_type` | string | How the request authenticated when it was not a browser session: `Personal access token (classic)`, `Fine-grained personal access token`, `OAuth access token`, `GitHub App user-to-server token`, `GitHub App server-to-server token`. |
| `hashed_token`, `token_id`, `token_scopes` | string (base64 SHA-256), integer, string (comma list) | The token that made the call. |
| `user_programmatic_access_name` | string | The fine-grained token's name. |
| `pull_request_id`, `pull_request_title`, `pull_request_url` | integer, string, string | `pull_request.*` events. |
| `fingerprint`, `title`, `read_only` | string (`SHA256:...`), string, boolean | `public_key.create` (SSH key / deploy key). |
| `user`, `user_id`, `permission`, `invitee_email` | | The affected account (`org.add_member`, `repo.add_member`, `org.invite_member`). |
| `repositories`, `repository_selection` | array, string | `personal_access_token.*`: the repositories granted, `all` / `selected`. |
| `external_identity_nameid`, `external_identity_username` | string | SAML / SCIM identity linked to the account (the corporate email for an EMU). |

Fields that do NOT exist on audit events: `ref` / `before` / `after` on `git.push` (those are webhook `push` payload fields),
`issues.opened` / `pull_request.merged` / `create` (webhook event names, not audit actions), a city or GeoIP object beyond
`country_code`, a commit count.

## 3. Samples

Git event (a clone over HTTPS with a classic token):

```json
{
  "@timestamp": 1762941480123,
  "_document_id": "q7Lr0bW3xYk2cVnA9sPe1g",
  "action": "git.clone",
  "actor": "m-cohen_nexacorp",
  "actor_id": 128833471,
  "actor_ip": "198.51.100.44",
  "actor_location": { "country_code": "IL" },
  "business": "nexacorp",
  "business_id": 4411,
  "created_at": 1762941480123,
  "operation_type": "access",
  "org": "nexacorp-eng",
  "org_id": 90417731,
  "repo": "nexacorp-eng/payments-api",
  "repo_id": 774190361,
  "repository": "nexacorp-eng/payments-api",
  "repository_public": false,
  "transport_protocol": 1,
  "transport_protocol_name": "http",
  "user_agent": "git/2.47.1",
  "programmatic_access_type": "Personal access token (classic)",
  "hashed_token": "EH4L8o6PfCqipALbL+QT62lyqUtnI7ql0SPbkaQnjv8=",
  "token_id": 51122874,
  "token_scopes": "repo,workflow"
}
```

A public repository created through the API with an OAuth token:

```json
{
  "@timestamp": 1762941600512,
  "_document_id": "Vqvg6kZ4MYqwWRKFDzlMoQ",
  "action": "repo.create",
  "actor": "m-cohen_nexacorp",
  "actor_id": 128833471,
  "actor_ip": "198.51.100.44",
  "actor_location": { "country_code": "IL" },
  "business": "nexacorp",
  "business_id": 4411,
  "created_at": 1762941600512,
  "operation_type": "create",
  "repo": "m-cohen_nexacorp/build-cache-7f3a",
  "repo_id": 774191002,
  "visibility": "public",
  "public_repo": true,
  "request_id": "C2F1:3A9E:1B44D7:1C9F02:6913A5C0",
  "user_agent": "node",
  "programmatic_access_type": "OAuth access token",
  "hashed_token": "Rk1rCq8zG3mWfS6yV0aLh2pXo9tBnE4uJcQdKiZwY1s=",
  "token_id": 51122990,
  "token_scopes": "gist,read:org,repo,workflow"
}
```

A pull request opened by a fine-grained token:

```json
{
  "@timestamp": 1762943410870,
  "_document_id": "LwW2vpJZCDS-WUmo9Z-ifw",
  "action": "pull_request.create",
  "actor": "d-levi_nexacorp",
  "actor_id": 128833502,
  "actor_ip": "198.51.100.61",
  "actor_location": { "country_code": "IL" },
  "business": "nexacorp",
  "business_id": 4411,
  "created_at": 1762943410870,
  "operation_type": "create",
  "org": "nexacorp-oss",
  "org_id": 90417740,
  "repo": "nexacorp-oss/sdk-js",
  "repo_id": 774190999,
  "public_repo": true,
  "pull_request_id": 2281734409,
  "pull_request_title": "Docs: add author details to README",
  "pull_request_url": "https://github.com/nexacorp-oss/sdk-js/pull/212",
  "request_id": "C2F1:3A9E:1B4AA0:1CA411:6913AD32",
  "user_agent": "github-mcp-server/0.20.2",
  "programmatic_access_type": "Fine-grained personal access token",
  "hashed_token": "p2Xn7cLm4Qw8sZt0yBv6aKe1rHj3oUi9dFg5NlMxCzA=",
  "token_id": 51123311,
  "user_programmatic_access_name": "assistant-mcp"
}
```

An SSH key added to an account:

```json
{
  "@timestamp": 1762950011205,
  "_document_id": "xJJFlFOhQ6b-5vaAFy9Rjw",
  "action": "public_key.create",
  "actor": "a-novak_nexacorp",
  "actor_id": 128834120,
  "actor_ip": "203.0.113.88",
  "actor_location": { "country_code": "US" },
  "business": "nexacorp",
  "business_id": 4411,
  "created_at": 1762950011205,
  "operation_type": "create",
  "fingerprint": "SHA256:9kQ1vV7bX2mZt8yLr3cN6pWs0aHf4eJuGdKiOq5nBxE",
  "title": "work-laptop",
  "read_only": false,
  "request_id": "C2F1:3A9E:1B5C11:1CB7E0:6913C87B",
  "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36"
}
```

A member added to an organization:

```json
{
  "@timestamp": 1762864211870,
  "_document_id": "b0T4mRk9Yw2sQe7LpVz3Hg",
  "action": "org.add_member",
  "actor": "it-admin_nexacorp",
  "actor_id": 128830007,
  "actor_ip": "198.51.100.10",
  "actor_location": { "country_code": "IL" },
  "business": "nexacorp",
  "business_id": 4411,
  "created_at": 1762864211870,
  "operation_type": "create",
  "org": "nexacorp-eng",
  "org_id": 90417731,
  "user": "a-novak_nexacorp",
  "user_id": 128834120,
  "permission": "read",
  "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36"
}
```

## 4. Investigation notes

- **Who is behind a token:** `hashed_token` ties every call one token made, across days and addresses; `programmatic_access_type`
  says what kind of token it was. A browser session has no `programmatic_access_type`.
- **Mass collection:** many `git.clone` (or `repo.download_zip`) of different `repo` values by one `actor` in minutes, from an
  address or `user_agent` the account never used, is the bulk-clone pattern of a stolen token or a malicious insider.
- **Exfiltration to GitHub itself:** `repo.create` with `visibility: public` in a user namespace, followed by `git.push`, from a
  token on a developer workstation: the pattern of supply-chain malware that publishes harvested secrets (s1ngularity, Aug 2025).
- **Agents:** `user_agent` names the client (`github-mcp-server/...`, `GitHub CLI ...`); `actor_is_agent` / `agent_session_id`
  mark GitHub's own agent sessions. A personal token used by a local AI agent looks like the person.
- **Git events retention:** 7 days in the API; stream them to keep them.

## 5. Common mistakes

- Using webhook payload names (`push`, `issues.opened`, `pull_request.merged`, `ref`, `head_commit`) in an audit record.
- ISO-8601 strings in `@timestamp` / `created_at` (they are epoch milliseconds).
- A city or full GeoIP object in `actor_location` (country code only).
- `actor_ip` on an enterprise that never enabled IP disclosure.
