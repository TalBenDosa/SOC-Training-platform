# Okta — System Log (LogEvent)

Category: IDENTITY (cloud IdP). Vendor: Okta. Card version: 2026-10-01.

---

## 1. Official sources consulted

| URL | What it confirmed |
|---|---|
| https://raw.githubusercontent.com/okta/okta-management-openapi-spec/master/dist/current/management-minimal.yaml (official Okta Management OpenAPI spec; schemas `LogEvent`, `LogActor`, `LogClient`, `LogUserAgent`, `LogGeographicalContext`, `LogGeolocation`, `LogOutcome`, `LogTarget`, `LogTransaction`, `LogDebugContext`, `LogAuthenticationContext`, `LogSecurityContext`, `LogIpAddress`, `LogRequest`, `LogSeverity`, `LogDevice`, `LogRisk`, `LogUserBehavior`, `LogIssuer`) | Every top-level property of `LogEvent` (`actor, authenticationContext, client, debugContext, displayMessage, eventType, legacyEventType, outcome, published, request, securityContext, severity, target, transaction, uuid, version`). Enums: severity `DEBUG/INFO/WARN/ERROR`; outcome.result `SUCCESS, FAILURE, SKIPPED, ALLOW, DENY, CHALLENGE, UNKNOWN, RATE_LIMIT, DEFERRED, SCHEDULED, ABANDONED, UNANSWERED`; authenticationProvider / credentialProvider / credentialType enums; transaction.type `WEB`/`JOB` and `detail.requestApiTokenId`; geolocation `lat`/`lon`; `target[].changeDetails{from,to}`; securityContext `asNumber, asOrg, isp, domain, isProxy` (+ newer `ipDetails, risk, userBehaviors, botProtection`); `LogRisk` = `level, previousLevel, reasons, detectionName, issuer`; `authenticationStep` always `0`. |
| https://developer.okta.com/docs/reference/api/event-types/ (and the catalog data bundle the page loads) | All event types used here exist, with descriptions: `user.session.start` ("User login to Okta"), `user.authentication.auth_via_mfa` (Classic: second factor only; **OIE: both primary and second factor**), `user.mfa.okta_verify.deny_push` ("triggered in classic V1 API calls. In OIE we use … `user.authentication.auth_via_mfa` with reason INVALID_CREDENTIALS"), `system.push.send_factor_verify_push` ("fired whenever a Push is sent"), `user.account.lock` ("Auto-lock user account"), `user.account.lock.limit`, `policy.evaluate_sign_on` (outcomes ALLOW / CHALLENGE / DENY; in OIE one event may carry global-session + authentication-policy results), `user.mfa.factor.activate` (OIE: fires when an authenticator is enrolled), `user.mfa.factor.reset_all`, `application.user_membership.add` ("Add user to application membership"), `system.api_token.create` ("new unscoped API token"), `security.threat.detected` (ThreatInsight; outcome.result `ALLOW`/`DENY`/`RATE_LIMIT`, reason in `outcome.reason`). The catalog's debugData schemas list the keys `threatSuspected`, `threatDetections` (e.g. `{"Password Spray":"HIGH"}`, `{"Login Failures":"HIGH"}`), `behaviors`, `risk`, `logOnlySecurityData`, `deviceFingerprint`, `dtHash`, `authnRequestId`, `factor` (`PASSWORD_AS_FACTOR`, `SOFT_TOKEN`, `SECURITY_QUESTION`…), `factorIntent` (`LOGIN`, `CREDENTIAL_ENROLLMENT`, `CREDENTIAL_RECOVERY`), `pushOnlyResponseType` (`OV_RESPONSE_APPROVE`, `OV_RESPONSE_DENY`, `OV_RESPONSE_ERROR`), `pushWithNumberChallengeResponseType`, `promptingPolicyTypes`, `okta_user_agent_extended`/`origin` (the catalog writes keys in snake_case internally; the API emits camelCase — see below). |
| https://github.com/elastic/integrations/tree/main/packages/okta/data_stream/system/_dev/test/pipeline (test-okta-system-events.log) | Real raw LogEvents as returned by `/api/v1/logs`: key order, null handling (`detailEntry: null`, `client.zone: "null"`, `target: null`), `debugData` keys emitted in **camelCase** (`requestId`, `requestUri`, `url`, `threatSuspected`, `deviceFingerprint`, `dtHash`, `authnRequestId`, `behaviors`, `risk`, `factor`, `promptingPolicyTypes`, `logOnlySecurityData`), values as **strings**, `request.ipChain[].{ip,geographicalContext,version,source}`, top-level `device` object on OIE events (present but **not** in the OpenAPI `LogEvent` schema), `legacyEventType`, policy targets `PolicyEntity` (detailEntry `{"policyType":"OktaSignOn"}`) + `PolicyRule`, group targets `User` + `UserGroup`. |
| https://help.okta.com/oie/en-us/content/topics/security/threat-insight/configure-threatinsight-system-log.htm | `security.threat.detected` ("Request from suspicious actor"); `debugContext.debugData.threatSuspected eq "true"` on sign-in events; outcome DENY / RATE_LIMIT / ALLOW; `security.attack.start` / `security.attack.end`; pivot via `transaction.id`. The Admin Console renders keys capitalised (`ThreatSuspected`) — the API key is `threatSuspected`. |
| https://support.okta.com/help/s/article/does-rejecting-an-okta-verify-push-notification-counts-as-failed-mfa | A denied Okta Verify push is logged as a failed authentication with reason `INVALID_CREDENTIALS`; expanded event shows `PushOnlyResponseType = OV_RESPONSE_DENY` (Admin Console capitalisation; API key `pushOnlyResponseType` — camelCase casing inferred from the catalog + the `ThreatSuspected`/`threatSuspected` precedent, UNVERIFIED in a raw API sample). A deny does **not** count toward lockout. |
| https://support.okta.com/help/s/article/System-Log-queries-for-attempted-account-takeover | Okta's own hunting queries: `user.authentication.auth_via_mfa AND outcome.result eq "FAILURE"`, `user.mfa.okta_verify.deny_push`, `debugData.behaviors co "POSITIVE"`, `debugData.risk co "HIGH"`, `debugData.logOnlySecurityData co "HIGH"`, `system.api_token.create`, `user.mfa.factor.reset_all`, `user.mfa.factor.activate/deactivate`, `user.account.privilege.grant`, `user.session.impersonation.initiate`. |
| https://sec.okta.com/articles/2023/02/user-sign-and-recovery-events-okta-system-log/ and https://support.okta.com/help/s/article/common-okta-login-failures | `user.session.start` failure reasons `INVALID_CREDENTIALS`, `VERIFICATION_ERROR`, `LOCKED_OUT`. |
| https://research.splunk.com/application/8085b79b-9b85-4e67-ad63-351c9e9a5e9a/ (Splunk detection, secondary source) | `system.push.send_factor_verify_push` (outcome `SUCCESS`, carries `debugData.behaviors`) is joined to `user.authentication.auth_via_mfa` with `debugData.factor = "OKTA_VERIFY_PUSH"` on `authenticationContext.externalSessionId`. |

---

## 2. Native format, delivery, and the representation we standardise on

- **Native:** the JSON **LogEvent** object returned by `GET https://{org}.okta.com/api/v1/logs`, which is a JSON array of LogEvents. The same object is pushed by Okta Log Streaming (AWS EventBridge / Splunk Cloud) and by Event Hooks (inside `data.events[]`).
- **STANDARD FOR THIS PLATFORM:** one LogEvent per event, exactly as the API returns it — no array wrapper.
  - Keep `null` values for documented keys that aren't populated (`detailEntry: null`, `credentialType: null`, `target: null`, `legacyEventType: null`). Okta returns them, and analysts see them.
  - `published` is ISO-8601 UTC with milliseconds: `"2026-09-30T02:14:07.418Z"`.
  - `uuid` is a time-based UUID (`"6f1c2e8a-9e7b-11f1-a3c4-0b52d7e9f1a6"`).
  - `version` is the string `"0"`.
  - All `debugContext.debugData` values are **strings**, even booleans and structured data (`"threatSuspected": "true"`, `"behaviors": "{New IP=POSITIVE, …}"`, `"risk": "{reasons=Anomalous Location, level=HIGH}"`, `"logOnlySecurityData": "{\"risk\":{…}}"` — escaped JSON).
  - `debugData` keys are **camelCase** in the API (`threatSuspected`, `requestUri`, `pushOnlyResponseType`). The Admin Console capitalises them for display (`ThreatSuspected`) and the event-type catalog lists them in snake_case (`threat_suspected`) — neither of those is the wire format.
  - Okta object-id prefixes: users `00u…`, groups `00g…`, apps `0oa…`, app users `0ua…`, API tokens `00T…`, policies `00p…`/`rst…`, policy rules `0pr…`/`rul…`, network zones `nzo…`, Okta Verify push factors `opf…`, authenticator enrollments `pfd…`/`opf…`, devices `guo…`. IDs are 20 characters.
- Key order: Okta returns keys alphabetically (`actor`, `authenticationContext`, `client`, `debugContext`, `device`, `displayMessage`, `eventType`, `legacyEventType`, `outcome`, `published`, `request`, `securityContext`, `severity`, `target`, `transaction`, `uuid`, `version`). Our samples keep that order.
- No SIEM layer: no `okta.*` prefix, no `event.action`, no `source.ip`, no Wazuh `data.*` envelope.

---

## 3. Core field reference

### 3.1 LogEvent

| Path | Type | Meaning / allowed values |
|---|---|---|
| `uuid` | string | Unique event id. |
| `published` | date-time | Event time (UTC, ms). |
| `eventType` | string | Dot-notation type (catalog). The key filter field. |
| `legacyEventType` | string/null | Old Events-API type. Confirmed values: `core.user_auth.login_success`, `core.user_auth.logout_success`, `core.user.factor.attempt_success`, `core.user_group_member.user_add`. Values used for failures/other types in our samples (`core.user_auth.login_failed`, `core.user.factor.attempt_fail`, `core.user_auth.account_locked`, `core.user.factor.activate`, `core.user.factor.reset_all`, `api.token.create`) are UNVERIFIED. `null` for event types created after the Events API (e.g. `policy.evaluate_sign_on`, `security.threat.detected`, `system.push.send_factor_verify_push`). |
| `version` | string | `"0"`. |
| `severity` | enum | `DEBUG`, `INFO`, `WARN`, `ERROR`. Successful logins are `INFO`; failed logins, lockouts and ThreatInsight detections are typically `WARN` (UNVERIFIED per type). |
| `displayMessage` | string | Human-readable event name (see 3.4). |
| `actor.{id,type,alternateId,displayName,detailEntry}` | object | Who acted. `type`: `User`, `PublicClientApp`, `SystemPrincipal`, `Client`. `alternateId` = login/email. System-initiated actions use `alternateId: "system@okta.com"`. |
| `client.userAgent.{rawUserAgent,os,browser}` | object | `browser` uppercase (`CHROME`, `FIREFOX`, `SAFARI`, `EDGE`, `UNKNOWN`); `os` e.g. `Windows 10`, `Mac OS X`, `Linux`, `iOS`, `Android`, `Unknown`. |
| `client.zone` | string | Network-zone name the IP matched (e.g. `"LegacyIpZone"`, `"Corporate HQ"`), or the **string** `"null"`. |
| `client.device` | string | `Computer`, `Mobile`, `Unknown`. |
| `client.id` | string/null | OAuth client id when an app initiated the request. |
| `client.ipAddress` | string | Client IP (first public IP; proxies appear in `request.ipChain`). |
| `client.geographicalContext.{city,state,country,postalCode,geolocation{lat,lon}}` | object | `country` is the **full English name** ("Netherlands"), not an ISO code. |
| `device` | object/null | OIE device record (Okta Verify / FastPass): `id`, `name`, `os_platform`, `os_version`, `managed`, `registered`, `device_integrator`, `disk_encryption_type`, `screen_lock_type`, `jailbreak`, `secure_hardware_present` (snake_case, as returned). `null` when no Okta-Verify-bound device took part. |
| `authenticationContext.authenticationProvider` | enum/null | `ACTIVE_DIRECTORY`, `FACTOR_PROVIDER`, `FEDERATION`, `LDAP`, `OKTA_AUTHENTICATION_PROVIDER`, `SOCIAL`. |
| `authenticationContext.credentialProvider` | enum/null | `DUO`, `GOOGLE`, `OKTA_AUTHENTICATION_PROVIDER`, `OKTA_CREDENTIAL_PROVIDER`, `RSA`, `SYMANTEC`, `YUBIKEY`. |
| `authenticationContext.credentialType` | enum/null | `ASSERTION`, `CERTIFICATE`, `DEVICE_UDID`, `EMAIL`, `IWA`, `JWT`, `OAuth 2.0`, `OKTA_CLIENT_SESSION`, `OTP`, `PASSWORD`, `PRE_SHARED_SYMMETRIC_KEY`, `SMS`. |
| `authenticationContext.externalSessionId` | string | Okta session id (cookie `sid` related), e.g. `102Xy…`. **The main session pivot.** |
| `authenticationContext.interface` | string/null | Client interface for app access (e.g. `"Outlook"`), usually `null`. |
| `authenticationContext.issuer` | object/null | `{id, type}` of the token issuer (federation); usually `null`. |
| `authenticationContext.authenticationStep` | int | Always `0` (deprecated). |
| `outcome.result` | enum | See 3.3. |
| `outcome.reason` | string/null | Free text or a code (`INVALID_CREDENTIALS`, `LOCKED_OUT`, `VERIFICATION_ERROR`, `Password Spray`, `Sign-on policy evaluation resulted in CHALLENGE`). |
| `target[]` | array/null | Objects acted on: `{id, type, alternateId, displayName, detailEntry, changeDetails}`. Types seen: `User`, `UserGroup`, `AppInstance`, `AppUser`, `PolicyEntity`, `PolicyRule`, `AuthenticatorEnrollment`, `Token`. `alternateId` is `"unknown"` for non-user objects. `changeDetails{from,to}` only on update-style events (often omitted). |
| `transaction.{type,id,detail}` | object | `type` `WEB` (HTTP request) or `JOB` (async). `id` = request id (also in `debugData.requestId`) — **groups all events of one HTTP request**. `detail.requestApiTokenId` appears when an API token made the call. |
| `debugContext.debugData` | map<string,string> | See 3.2. |
| `securityContext.{asNumber,asOrg,isp,domain,isProxy}` | object | ASN enrichment of `client.ipAddress`. `asNumber` int; `isProxy` bool (true = anonymiser / known proxy). All `null` for private IPs. |
| `request.ipChain[]` | array | Every IP that forwarded the request: `{ip, geographicalContext{…}, version ("V4"/"V6"), source (null or proxy name)}`. Index 0 = the client. |

### 3.2 `debugContext.debugData` keys (camelCase, string values)

| Key | Seen on | Meaning / example |
|---|---|---|
| `requestId` | almost all | Same value as `transaction.id`. |
| `requestUri` | web events | Path only: `/api/v1/authn`, `/idp/idx/identify`, `/idp/idx/challenge/answer`, `/idp/idx/authenticators/poll`, `/api/v1/users/00u…/lifecycle/reset_factors`, `/api/internal/tokens`. |
| `url` | web events | Path + query: `/idp/idx/identify?`. |
| `authnRequestId` | auth flows | Ties the steps of one authentication transaction. |
| `deviceFingerprint` | session.start / verify | Hash of browser fingerprint (32 hex). |
| `dtHash` | OIE events | Device-token hash (64 hex). New `dtHash` = new browser. |
| `threatSuspected` | session.start, auth_via_mfa, threat.detected | `"true"` / `"false"` — ThreatInsight verdict on the IP. |
| `threatDetections` | session.start (UNVERIFIED on which others) | `"{\"Password Spray\":\"HIGH\"}"`, `"{\"Login Failures\":\"MEDIUM\"}"` (catalog example; camelCase key inferred — UNVERIFIED in raw sample). |
| `behaviors` | session.start, policy.evaluate_sign_on, auth_via_mfa, push send | `"{New Geo-Location=POSITIVE, New Device=POSITIVE, New IP=POSITIVE, New State=POSITIVE, New Country=POSITIVE, Velocity=POSITIVE, New City=POSITIVE}"`. Values `POSITIVE` (anomalous), `NEGATIVE` (normal), `UNKNOWN`, `BAD_REQUEST`. |
| `risk` | session.start, policy, auth_via_mfa | `"{level=LOW}"`, `"{reasons=Anomalous Location, Anomalous Device, level=HIGH}"`. |
| `logOnlySecurityData` | session.start, policy | Escaped JSON with `risk` + `behaviors` in JSON form. |
| `factor` | auth_via_mfa | `OKTA_VERIFY_PUSH`, `FIDO_WEBAUTHN`, `PASSWORD_AS_FACTOR`, `SOFT_TOKEN`, `SMS_FACTOR` (UNVERIFIED spelling), `SECURITY_QUESTION`. |
| `factorIntent` | auth_via_mfa | `LOGIN`, `CREDENTIAL_ENROLLMENT`, `CREDENTIAL_RECOVERY`. |
| `pushOnlyResponseType` | auth_via_mfa (OV push) | `OV_RESPONSE_APPROVE`, `OV_RESPONSE_DENY`, `OV_RESPONSE_ERROR`. |
| `pushWithNumberChallengeResponseType` | auth_via_mfa (number challenge) | e.g. `OV_WITH_CHALLENGE_RESPONSE_VALID` (other values UNVERIFIED). |
| `promptingPolicyTypes` | auth_via_mfa | `"[OKTA_SIGN_ON]"`, `"[ACCESS]"`. |
| `originalPrincipal` | impersonation / admin-as-user | **Exception:** observed as a nested object, not a string. |

### 3.3 `outcome.result` per event type (what we emit)

| eventType | result values | reason |
|---|---|---|
| `user.session.start` | `SUCCESS`, `FAILURE` | `null`, `INVALID_CREDENTIALS`, `VERIFICATION_ERROR`, `LOCKED_OUT` |
| `user.authentication.auth_via_mfa` | `SUCCESS`, `FAILURE` | `null`, `INVALID_CREDENTIALS` (OIE push deny / wrong code) |
| `system.push.send_factor_verify_push` | `SUCCESS` | `null` |
| `policy.evaluate_sign_on` | `ALLOW`, `CHALLENGE`, `DENY` | `"Sign-on policy evaluation resulted in <RESULT>"` |
| `security.threat.detected` | `ALLOW` (log mode), `DENY` (enforce), `RATE_LIMIT` | threat name, e.g. `Password Spray` |
| `user.account.lock` | `SUCCESS` (UNVERIFIED) | `null` (UNVERIFIED) |
| `user.mfa.factor.activate`, `user.mfa.factor.reset_all`, `application.user_membership.add`, `system.api_token.create` | `SUCCESS` | `null` |

### 3.4 displayMessage values

| eventType | displayMessage |
|---|---|
| `user.session.start` | `User login to Okta` (confirmed) |
| `user.session.end` | `User logout from Okta` (confirmed) |
| `user.authentication.auth_via_mfa` | `Authentication of user via MFA` (confirmed) |
| `policy.evaluate_sign_on` | `Evaluation of sign-on policy` (confirmed) |
| `group.user_membership.add` | `Add user to group membership` (confirmed) |
| `security.threat.detected` | `Request from suspicious actor` (confirmed, ThreatInsight help page) |
| `application.user_membership.add` | `Add user to application membership` (catalog description) |
| `system.api_token.create` | `Create API token` (catalog description) |
| `user.account.lock` | `Max sign in attempts exceeded` (Okta help/support wording; exact string UNVERIFIED) |
| `user.mfa.factor.activate` | `Activate factor or authenticator enrollment method for user` (catalog; Classic orgs show `Activate factor for user` — UNVERIFIED) |
| `user.mfa.factor.reset_all` | `Reset all factors for user` (UNVERIFIED; OIE wording may read "…authenticator enrollments…") |
| `system.push.send_factor_verify_push` | `Push notification sent for verification` (UNVERIFIED) |
| `user.mfa.okta_verify.deny_push` | `User rejected Okta push verify` (catalog; Classic only) |

---

## 4. Samples (fictitious org `nexacorp.okta.com`; IPs from RFC 5737 documentation ranges)

Shared values for the storyline (2026-09-30, UTC):
- Victim **Dana Levi** `dana.levi@nexacorp.com`, id `00u8k2m4n6p8q0r2s4t6` (Help Desk Administrator role). Normal location: Tel Aviv, Israel, `192.0.2.10`, zone `Corporate HQ`.
- Password-spray infrastructure `203.0.113.0/24` (AS 9009, hosting provider, Amsterdam).
- Attacker interactive host `198.51.100.23` (Rotterdam, Netherlands) — a country Dana never signs in from.
- Attacker browser session `externalSessionId` = `102Tq7rVh2KxW9mLp4sNc8dEw` (appears from 4.4 onward).
- Compact formatting: small nested objects are kept on one line to save space; the wire format is the same JSON.

### 4.1 `user.session.start` — FAILURE (password spray hit, INVALID_CREDENTIALS)

```json
{
  "actor": { "alternateId": "dana.levi@nexacorp.com", "detailEntry": null, "displayName": "Dana Levi", "id": "00u8k2m4n6p8q0r2s4t6", "type": "User" },
  "authenticationContext": { "authenticationProvider": null, "authenticationStep": 0, "credentialProvider": null, "credentialType": null, "externalSessionId": "unknown", "interface": null, "issuer": null },
  "client": {
    "device": "Unknown",
    "geographicalContext": { "city": "Amsterdam", "country": "Netherlands", "geolocation": { "lat": 52.3740, "lon": 4.8897 }, "postalCode": "1012", "state": "North Holland" },
    "id": null,
    "ipAddress": "203.0.113.47",
    "userAgent": { "browser": "UNKNOWN", "os": "Unknown", "rawUserAgent": "python-requests/2.32.3" },
    "zone": "null"
  },
  "debugContext": {
    "debugData": {
      "requestId": "Zvoa3x1kQm8nE0bAe7sLgAAAB4c",
      "requestUri": "/api/v1/authn",
      "threatSuspected": "true",
      "url": "/api/v1/authn?"
    }
  },
  "device": null,
  "displayMessage": "User login to Okta",
  "eventType": "user.session.start",
  "legacyEventType": "core.user_auth.login_failed",
  "outcome": { "reason": "INVALID_CREDENTIALS", "result": "FAILURE" },
  "published": "2026-09-30T02:14:07.418Z",
  "request": {
    "ipChain": [
      { "geographicalContext": { "city": "Amsterdam", "country": "Netherlands", "geolocation": { "lat": 52.3740, "lon": 4.8897 }, "postalCode": "1012", "state": "North Holland" }, "ip": "203.0.113.47", "source": null, "version": "V4" }
    ]
  },
  "securityContext": { "asNumber": 9009, "asOrg": "m247 europe srl", "domain": "m247.com", "isProxy": true, "isp": "m247 ltd" },
  "severity": "WARN",
  "target": null,
  "transaction": { "detail": {}, "id": "Zvoa3x1kQm8nE0bAe7sLgAAAB4c", "type": "WEB" },
  "uuid": "6f1c2e8a-9e7b-11f1-a3c4-0b52d7e9f1a6",
  "version": "0"
}
```
*Spray pattern: one `client.ipAddress` / `securityContext.asNumber`, dozens of different `actor.alternateId` values, `INVALID_CREDENTIALS`, a non-browser `rawUserAgent`, `threatSuspected: "true"`. `externalSessionId: "unknown"` because no session exists yet (pre-session value — UNVERIFIED but commonly observed).*

### 4.2 `security.threat.detected` — ThreatInsight flags the spray source (log-only mode)

```json
{
  "actor": { "alternateId": "unknown", "detailEntry": null, "displayName": "unknown", "id": "unknown", "type": "User" },
  "authenticationContext": { "authenticationProvider": null, "authenticationStep": 0, "credentialProvider": null, "credentialType": null, "externalSessionId": "unknown", "interface": null, "issuer": null },
  "client": {
    "device": "Unknown",
    "geographicalContext": { "city": "Amsterdam", "country": "Netherlands", "geolocation": { "lat": 52.3740, "lon": 4.8897 }, "postalCode": "1012", "state": "North Holland" },
    "id": null,
    "ipAddress": "203.0.113.47",
    "userAgent": { "browser": "UNKNOWN", "os": "Unknown", "rawUserAgent": "python-requests/2.32.3" },
    "zone": "null"
  },
  "debugContext": {
    "debugData": {
      "requestId": "Zvoa6b4nTp1qH3eDh0vOjAAACc8",
      "requestUri": "/api/v1/authn",
      "threatSuspected": "true",
      "url": "/api/v1/authn?"
    }
  },
  "device": null,
  "displayMessage": "Request from suspicious actor",
  "eventType": "security.threat.detected",
  "legacyEventType": null,
  "outcome": { "reason": "Password Spray", "result": "ALLOW" },
  "published": "2026-09-30T02:16:41.902Z",
  "request": {
    "ipChain": [
      { "geographicalContext": { "city": "Amsterdam", "country": "Netherlands", "geolocation": { "lat": 52.3740, "lon": 4.8897 }, "postalCode": "1012", "state": "North Holland" }, "ip": "203.0.113.47", "source": null, "version": "V4" }
    ]
  },
  "securityContext": { "asNumber": 9009, "asOrg": "m247 europe srl", "domain": "m247.com", "isProxy": true, "isp": "m247 ltd" },
  "severity": "WARN",
  "target": null,
  "transaction": { "detail": {}, "id": "Zvoa6b4nTp1qH3eDh0vOjAAACc8", "type": "WEB" },
  "uuid": "c41d7a02-9e7b-11f1-8f2e-3b6a0c9d4e17",
  "version": "0"
}
```
*`result: "ALLOW"` = ThreatInsight is in log-only mode, so the request continued. In "log and enforce" mode the same event carries `DENY`. The `actor` for an unauthenticated request is shown as `unknown` here (UNVERIFIED — some orgs show the attempted username).*

### 4.3 `user.account.lock` — the spray pushes another user over the lockout threshold

```json
{
  "actor": { "alternateId": "ron.shapiro@nexacorp.com", "detailEntry": null, "displayName": "Ron Shapiro", "id": "00u8k2m4n6p8q0r2s9x1", "type": "User" },
  "authenticationContext": { "authenticationProvider": null, "authenticationStep": 0, "credentialProvider": null, "credentialType": null, "externalSessionId": "unknown", "interface": null, "issuer": null },
  "client": {
    "device": "Unknown",
    "geographicalContext": { "city": "Amsterdam", "country": "Netherlands", "geolocation": { "lat": 52.3740, "lon": 4.8897 }, "postalCode": "1012", "state": "North Holland" },
    "id": null,
    "ipAddress": "203.0.113.51",
    "userAgent": { "browser": "UNKNOWN", "os": "Unknown", "rawUserAgent": "python-requests/2.32.3" },
    "zone": "null"
  },
  "debugContext": {
    "debugData": {
      "requestId": "ZvobKc9rWs2tJ5gFk3xQmAAAD1a",
      "requestUri": "/api/v1/authn",
      "threatSuspected": "true",
      "url": "/api/v1/authn?"
    }
  },
  "device": null,
  "displayMessage": "Max sign in attempts exceeded",
  "eventType": "user.account.lock",
  "legacyEventType": "core.user_auth.account_locked",
  "outcome": { "reason": null, "result": "SUCCESS" },
  "published": "2026-09-30T02:18:22.067Z",
  "request": {
    "ipChain": [
      { "geographicalContext": { "city": "Amsterdam", "country": "Netherlands", "geolocation": { "lat": 52.3740, "lon": 4.8897 }, "postalCode": "1012", "state": "North Holland" }, "ip": "203.0.113.51", "source": null, "version": "V4" }
    ]
  },
  "securityContext": { "asNumber": 9009, "asOrg": "m247 europe srl", "domain": "m247.com", "isProxy": true, "isp": "m247 ltd" },
  "severity": "WARN",
  "target": [
    { "alternateId": "ron.shapiro@nexacorp.com", "detailEntry": null, "displayName": "Ron Shapiro", "id": "00u8k2m4n6p8q0r2s9x1", "type": "User" }
  ],
  "transaction": { "detail": {}, "id": "ZvobKc9rWs2tJ5gFk3xQmAAAD1a", "type": "WEB" },
  "uuid": "0a9be3f6-9e7c-11f1-b5d1-6e2f8a3c7b90",
  "version": "0"
}
```
*Every later attempt for Ron returns `user.session.start` FAILURE with `outcome.reason: "LOCKED_OUT"` until an admin unlocks him (`user.account.unlock`) or the auto-unlock period passes. A lockout coming from the spray ASN — not from Ron's own device — means Ron did not mistype his password. The outcome values of this event type are UNVERIFIED (see 3.3).*

### 4.4 `policy.evaluate_sign_on` — CHALLENGE: correct password from an unusual country, MFA required

```json
{
  "actor": { "alternateId": "dana.levi@nexacorp.com", "detailEntry": null, "displayName": "Dana Levi", "id": "00u8k2m4n6p8q0r2s4t6", "type": "User" },
  "authenticationContext": { "authenticationProvider": null, "authenticationStep": 0, "credentialProvider": null, "credentialType": null, "externalSessionId": "102Tq7rVh2KxW9mLp4sNc8dEw", "interface": null, "issuer": null },
  "client": {
    "device": "Computer",
    "geographicalContext": { "city": "Rotterdam", "country": "Netherlands", "geolocation": { "lat": 51.9225, "lon": 4.4792 }, "postalCode": "3011", "state": "South Holland" },
    "id": null,
    "ipAddress": "198.51.100.23",
    "userAgent": { "browser": "CHROME", "os": "Windows 10", "rawUserAgent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36" },
    "zone": "null"
  },
  "debugContext": {
    "debugData": {
      "behaviors": "{New Geo-Location=POSITIVE, New Device=POSITIVE, New IP=POSITIVE, New State=POSITIVE, New Country=POSITIVE, Velocity=POSITIVE, New City=POSITIVE}",
      "deviceFingerprint": "9c4e1b7a2d6f8e03b5a7c9d1e3f50a62",
      "dtHash": "3f8a1c6e9b2d4f7a0c5e8b1d3f6a9c2e4b7d0f3a6c9e2b5d8f1a4c7e0b3d6f9a",
      "logOnlySecurityData": "{\"risk\":{\"reasons\":\"Anomalous Location, Anomalous Device\",\"level\":\"HIGH\"},\"behaviors\":{\"New Geo-Location\":\"POSITIVE\",\"New Device\":\"POSITIVE\",\"New IP\":\"POSITIVE\",\"New State\":\"POSITIVE\",\"New Country\":\"POSITIVE\",\"Velocity\":\"POSITIVE\",\"New City\":\"POSITIVE\"}}",
      "requestId": "Zvoj1d7sXt3uK6hGl4yRnAAAE2b",
      "requestUri": "/idp/idx/identify",
      "risk": "{reasons=Anomalous Location, Anomalous Device, level=HIGH}",
      "threatSuspected": "false",
      "url": "/idp/idx/identify?"
    }
  },
  "device": null,
  "displayMessage": "Evaluation of sign-on policy",
  "eventType": "policy.evaluate_sign_on",
  "legacyEventType": null,
  "outcome": { "reason": "Sign-on policy evaluation resulted in CHALLENGE", "result": "CHALLENGE" },
  "published": "2026-09-30T03:02:11.530Z",
  "request": {
    "ipChain": [
      { "geographicalContext": { "city": "Rotterdam", "country": "Netherlands", "geolocation": { "lat": 51.9225, "lon": 4.4792 }, "postalCode": "3011", "state": "South Holland" }, "ip": "198.51.100.23", "source": null, "version": "V4" }
    ]
  },
  "securityContext": { "asNumber": 9009, "asOrg": "m247 europe srl", "domain": "m247.com", "isProxy": false, "isp": "m247 ltd" },
  "severity": "INFO",
  "target": [
    { "alternateId": "unknown", "detailEntry": { "policyType": "OktaSignOn" }, "displayName": "Default Policy", "id": "00p1nexa0GlobalSe4x7", "type": "PolicyEntity" },
    { "alternateId": "00p1nexa0GlobalSe4x7", "detailEntry": null, "displayName": "Require MFA outside Corporate HQ", "id": "0pr1nexa0MfaOutHq4x7", "type": "PolicyRule" }
  ],
  "transaction": { "detail": {}, "id": "Zvoj1d7sXt3uK6hGl4yRnAAAE2b", "type": "WEB" },
  "uuid": "4b7e9c10-9e81-11f1-9a63-1d4f7b2e8c05",
  "version": "0"
}
```
*The password step already succeeded (otherwise there would be no CHALLENGE). All seven `behaviors` are `POSITIVE` and `risk` is `HIGH`, but `threatSuspected` is `"false"` — this IP is not on ThreatInsight's list, so only the behaviour engine sees the anomaly. `client.zone: "null"` = the IP matched no named network zone.*

### 4.5 `system.push.send_factor_verify_push` — Okta sends a push to Dana's phone (one of many)

```json
{
  "actor": { "alternateId": "dana.levi@nexacorp.com", "detailEntry": null, "displayName": "Dana Levi", "id": "00u8k2m4n6p8q0r2s4t6", "type": "User" },
  "authenticationContext": { "authenticationProvider": null, "authenticationStep": 0, "credentialProvider": null, "credentialType": null, "externalSessionId": "102Tq7rVh2KxW9mLp4sNc8dEw", "interface": null, "issuer": null },
  "client": {
    "device": "Computer",
    "geographicalContext": { "city": "Rotterdam", "country": "Netherlands", "geolocation": { "lat": 51.9225, "lon": 4.4792 }, "postalCode": "3011", "state": "South Holland" },
    "id": null,
    "ipAddress": "198.51.100.23",
    "userAgent": { "browser": "CHROME", "os": "Windows 10", "rawUserAgent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36" },
    "zone": "null"
  },
  "debugContext": {
    "debugData": {
      "behaviors": "{New Geo-Location=POSITIVE, New Device=POSITIVE, New IP=POSITIVE, New State=POSITIVE, New Country=POSITIVE, Velocity=POSITIVE, New City=POSITIVE}",
      "requestId": "Zvoj2e8tYu4vL7iHm5zSoAAAF3c",
      "requestUri": "/idp/idx/challenge",
      "url": "/idp/idx/challenge?"
    }
  },
  "device": null,
  "displayMessage": "Push notification sent for verification",
  "eventType": "system.push.send_factor_verify_push",
  "legacyEventType": null,
  "outcome": { "reason": null, "result": "SUCCESS" },
  "published": "2026-09-30T03:02:12.104Z",
  "request": {
    "ipChain": [
      { "geographicalContext": { "city": "Rotterdam", "country": "Netherlands", "geolocation": { "lat": 51.9225, "lon": 4.4792 }, "postalCode": "3011", "state": "South Holland" }, "ip": "198.51.100.23", "source": null, "version": "V4" }
    ]
  },
  "securityContext": { "asNumber": 9009, "asOrg": "m247 europe srl", "domain": "m247.com", "isProxy": false, "isp": "m247 ltd" },
  "severity": "INFO",
  "target": [
    { "alternateId": "unknown", "detailEntry": null, "displayName": "Okta Verify", "id": "opf3nexaPushDana04x7", "type": "AuthenticatorEnrollment" }
  ],
  "transaction": { "detail": {}, "id": "Zvoj2e8tYu4vL7iHm5zSoAAAF3c", "type": "WEB" },
  "uuid": "4c02a7d3-9e81-11f1-9a63-1d4f7b2e8c05",
  "version": "0"
}
```
*`client.*` is the browser that **requested** the push (the attacker in Rotterdam), not Dana's phone. Count these per `externalSessionId`: 6 pushes in 9 minutes is MFA fatigue. The `target` shape and `displayMessage` of this type are UNVERIFIED.*

### 4.6 `user.authentication.auth_via_mfa` — FAILURE: Dana rejects the push (OIE)

```json
{
  "actor": { "alternateId": "dana.levi@nexacorp.com", "detailEntry": null, "displayName": "Dana Levi", "id": "00u8k2m4n6p8q0r2s4t6", "type": "User" },
  "authenticationContext": { "authenticationProvider": "FACTOR_PROVIDER", "authenticationStep": 0, "credentialProvider": "OKTA_CREDENTIAL_PROVIDER", "credentialType": null, "externalSessionId": "102Tq7rVh2KxW9mLp4sNc8dEw", "interface": null, "issuer": null },
  "client": {
    "device": "Computer",
    "geographicalContext": { "city": "Rotterdam", "country": "Netherlands", "geolocation": { "lat": 51.9225, "lon": 4.4792 }, "postalCode": "3011", "state": "South Holland" },
    "id": null,
    "ipAddress": "198.51.100.23",
    "userAgent": { "browser": "CHROME", "os": "Windows 10", "rawUserAgent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36" },
    "zone": "null"
  },
  "debugContext": {
    "debugData": {
      "authnRequestId": "Zvoj1d7sXt3uK6hGl4yRnAAAE2b",
      "behaviors": "{New Geo-Location=POSITIVE, New Device=POSITIVE, New IP=POSITIVE, New State=POSITIVE, New Country=POSITIVE, Velocity=POSITIVE, New City=POSITIVE}",
      "dtHash": "3f8a1c6e9b2d4f7a0c5e8b1d3f6a9c2e4b7d0f3a6c9e2b5d8f1a4c7e0b3d6f9a",
      "factor": "OKTA_VERIFY_PUSH",
      "factorIntent": "LOGIN",
      "promptingPolicyTypes": "[OKTA_SIGN_ON]",
      "pushOnlyResponseType": "OV_RESPONSE_DENY",
      "requestId": "Zvoj4g0vAw6xN9kJo7bUqAAAH5e",
      "requestUri": "/idp/idx/authenticators/poll",
      "risk": "{reasons=Anomalous Location, Anomalous Device, level=HIGH}",
      "threatSuspected": "false",
      "url": "/idp/idx/authenticators/poll?"
    }
  },
  "device": null,
  "displayMessage": "Authentication of user via MFA",
  "eventType": "user.authentication.auth_via_mfa",
  "legacyEventType": "core.user.factor.attempt_fail",
  "outcome": { "reason": "INVALID_CREDENTIALS", "result": "FAILURE" },
  "published": "2026-09-30T03:02:31.877Z",
  "request": {
    "ipChain": [
      { "geographicalContext": { "city": "Rotterdam", "country": "Netherlands", "geolocation": { "lat": 51.9225, "lon": 4.4792 }, "postalCode": "3011", "state": "South Holland" }, "ip": "198.51.100.23", "source": null, "version": "V4" }
    ]
  },
  "securityContext": { "asNumber": 9009, "asOrg": "m247 europe srl", "domain": "m247.com", "isProxy": false, "isp": "m247 ltd" },
  "severity": "WARN",
  "target": [
    { "alternateId": "dana.levi@nexacorp.com", "detailEntry": null, "displayName": "Dana Levi", "id": "00u8k2m4n6p8q0r2s4t6", "type": "User" },
    { "alternateId": "unknown", "detailEntry": { "methodTypeUsed": "Get a push notification", "methodUsedVerifiedProperties": "[USER_PRESENCE]" }, "displayName": "Okta Verify", "id": "opf3nexaPushDana04x7", "type": "AuthenticatorEnrollment" }
  ],
  "transaction": { "detail": {}, "id": "Zvoj4g0vAw6xN9kJo7bUqAAAH5e", "type": "WEB" },
  "uuid": "57e3b9a8-9e81-11f1-a0d4-9b1c6e3f7a28",
  "version": "0"
}
```
*This is how an OIE org records "user tapped **No, it's not me**": the generic MFA event with `FAILURE` / `INVALID_CREDENTIALS` and `pushOnlyResponseType: "OV_RESPONSE_DENY"`. A Classic org would instead emit `user.mfa.okta_verify.deny_push`. Denies do not count toward lockout, so fatigue never locks the account. The `target[1].detailEntry` key names and wording are UNVERIFIED.*

**4.6b — the approval at 03:11:48.** After five more push/deny pairs, Dana approves. The approval is the **same event type** with only these values changed (all other fields identical to 4.6):

| Field | 4.6 (deny) | 4.6b (approve) |
|---|---|---|
| `outcome` | `{ "reason": "INVALID_CREDENTIALS", "result": "FAILURE" }` | `{ "reason": null, "result": "SUCCESS" }` |
| `debugData.pushOnlyResponseType` | `OV_RESPONSE_DENY` | `OV_RESPONSE_APPROVE` |
| `legacyEventType` | `core.user.factor.attempt_fail` | `core.user.factor.attempt_success` |
| `severity` | `WARN` | `INFO` |
| `published` | `2026-09-30T03:02:31.877Z` | `2026-09-30T03:11:48.215Z` |
| `uuid` / `requestId` / `transaction.id` | (as above) | new values (`ab92c4e1-9e82-11f1-a0d4-9b1c6e3f7a28` / `ZvolPq3wBx7yO0lKp8cVrAAAJ6f`) |

### 4.7 `user.session.start` — SUCCESS: session created for the attacker in the Netherlands

```json
{
  "actor": { "alternateId": "dana.levi@nexacorp.com", "detailEntry": null, "displayName": "Dana Levi", "id": "00u8k2m4n6p8q0r2s4t6", "type": "User" },
  "authenticationContext": { "authenticationProvider": null, "authenticationStep": 0, "credentialProvider": null, "credentialType": null, "externalSessionId": "102Tq7rVh2KxW9mLp4sNc8dEw", "interface": null, "issuer": null },
  "client": {
    "device": "Computer",
    "geographicalContext": { "city": "Rotterdam", "country": "Netherlands", "geolocation": { "lat": 51.9225, "lon": 4.4792 }, "postalCode": "3011", "state": "South Holland" },
    "id": null,
    "ipAddress": "198.51.100.23",
    "userAgent": { "browser": "CHROME", "os": "Windows 10", "rawUserAgent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36" },
    "zone": "null"
  },
  "debugContext": {
    "debugData": {
      "behaviors": "{New Geo-Location=POSITIVE, New Device=POSITIVE, New IP=POSITIVE, New State=POSITIVE, New Country=POSITIVE, Velocity=POSITIVE, New City=POSITIVE}",
      "deviceFingerprint": "9c4e1b7a2d6f8e03b5a7c9d1e3f50a62",
      "dtHash": "3f8a1c6e9b2d4f7a0c5e8b1d3f6a9c2e4b7d0f3a6c9e2b5d8f1a4c7e0b3d6f9a",
      "requestId": "ZvolPq3wBx7yO0lKp8cVrAAAJ6f",
      "requestUri": "/idp/idx/authenticators/poll",
      "risk": "{reasons=Anomalous Location, Anomalous Device, level=HIGH}",
      "threatSuspected": "false",
      "url": "/idp/idx/authenticators/poll?"
    }
  },
  "device": null,
  "displayMessage": "User login to Okta",
  "eventType": "user.session.start",
  "legacyEventType": "core.user_auth.login_success",
  "outcome": { "reason": null, "result": "SUCCESS" },
  "published": "2026-09-30T03:11:48.391Z",
  "request": {
    "ipChain": [
      { "geographicalContext": { "city": "Rotterdam", "country": "Netherlands", "geolocation": { "lat": 51.9225, "lon": 4.4792 }, "postalCode": "3011", "state": "South Holland" }, "ip": "198.51.100.23", "source": null, "version": "V4" }
    ]
  },
  "securityContext": { "asNumber": 9009, "asOrg": "m247 europe srl", "domain": "m247.com", "isProxy": false, "isp": "m247 ltd" },
  "severity": "INFO",
  "target": null,
  "transaction": { "detail": {}, "id": "ZvolPq3wBx7yO0lKp8cVrAAAJ6f", "type": "WEB" },
  "uuid": "ab9f01c7-9e82-11f1-a0d4-9b1c6e3f7a28",
  "version": "0"
}
```
*Same `transaction.id` as the approving `auth_via_mfa` (4.6b) — one HTTP request produced both events. Dana's sign-ins over the last 90 days are all from Israel, zone `Corporate HQ`; this one is `Netherlands`, zone `"null"`, new device, HIGH risk. That is the "sign-in from an unusual country" finding.*

### 4.8 `user.mfa.factor.activate` — attacker enrolls a second Okta Verify on their own phone

```json
{
  "actor": { "alternateId": "dana.levi@nexacorp.com", "detailEntry": null, "displayName": "Dana Levi", "id": "00u8k2m4n6p8q0r2s4t6", "type": "User" },
  "authenticationContext": { "authenticationProvider": null, "authenticationStep": 0, "credentialProvider": null, "credentialType": null, "externalSessionId": "102Tq7rVh2KxW9mLp4sNc8dEw", "interface": null, "issuer": null },
  "client": {
    "device": "Computer",
    "geographicalContext": { "city": "Rotterdam", "country": "Netherlands", "geolocation": { "lat": 51.9225, "lon": 4.4792 }, "postalCode": "3011", "state": "South Holland" },
    "id": null,
    "ipAddress": "198.51.100.23",
    "userAgent": { "browser": "CHROME", "os": "Windows 10", "rawUserAgent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36" },
    "zone": "null"
  },
  "debugContext": {
    "debugData": {
      "dtHash": "3f8a1c6e9b2d4f7a0c5e8b1d3f6a9c2e4b7d0f3a6c9e2b5d8f1a4c7e0b3d6f9a",
      "requestId": "ZvomA5xCy8zP1mLq9dWsAAAK7g",
      "requestUri": "/idp/idx/challenge/poll",
      "url": "/idp/idx/challenge/poll?"
    }
  },
  "device": { "device_integrator": null, "disk_encryption_type": "USER", "id": "guo9nexaAtkPixel04x7", "jailbreak": false, "managed": false, "name": "Pixel 8", "os_platform": "ANDROID", "os_version": "15", "registered": true, "screen_lock_type": "BIOMETRIC", "secure_hardware_present": true },
  "displayMessage": "Activate factor or authenticator enrollment method for user",
  "eventType": "user.mfa.factor.activate",
  "legacyEventType": "core.user.factor.activate",
  "outcome": { "reason": null, "result": "SUCCESS" },
  "published": "2026-09-30T03:14:30.662Z",
  "request": {
    "ipChain": [
      { "geographicalContext": { "city": "Rotterdam", "country": "Netherlands", "geolocation": { "lat": 51.9225, "lon": 4.4792 }, "postalCode": "3011", "state": "South Holland" }, "ip": "198.51.100.23", "source": null, "version": "V4" }
    ]
  },
  "securityContext": { "asNumber": 9009, "asOrg": "m247 europe srl", "domain": "m247.com", "isProxy": false, "isp": "m247 ltd" },
  "severity": "INFO",
  "target": [
    { "alternateId": "dana.levi@nexacorp.com", "detailEntry": null, "displayName": "Dana Levi", "id": "00u8k2m4n6p8q0r2s4t6", "type": "User" },
    { "alternateId": "unknown", "detailEntry": null, "displayName": "Okta Verify", "id": "opf9nexaPushAtk04x7a", "type": "AuthenticatorEnrollment" }
  ],
  "transaction": { "detail": {}, "id": "ZvomA5xCy8zP1mLq9dWsAAAK7g", "type": "WEB" },
  "uuid": "0d4a62f9-9e83-11f1-87c2-5a0e3d9b1f64",
  "version": "0"
}
```
*Persistence: the attacker no longer needs Dana to approve pushes. Red flags: enrollment within minutes of a risky session, in the same `externalSessionId`, from the same foreign IP, and a new device (`device.name` "Pixel 8") that Dana's asset record doesn't list. Dana's legitimate enrollment `opf3nexaPushDana04x7` is still active, so she won't notice anything. The `device` values are illustrative (keys confirmed; `os_platform` casing UNVERIFIED — samples show `OSX`, catalog shows `OSx`/`Android`).*

### 4.9 `user.mfa.factor.reset_all` — the hijacked Help Desk admin wipes the CFO's MFA

```json
{
  "actor": { "alternateId": "dana.levi@nexacorp.com", "detailEntry": null, "displayName": "Dana Levi", "id": "00u8k2m4n6p8q0r2s4t6", "type": "User" },
  "authenticationContext": { "authenticationProvider": null, "authenticationStep": 0, "credentialProvider": null, "credentialType": null, "externalSessionId": "102Tq7rVh2KxW9mLp4sNc8dEw", "interface": null, "issuer": null },
  "client": {
    "device": "Computer",
    "geographicalContext": { "city": "Rotterdam", "country": "Netherlands", "geolocation": { "lat": 51.9225, "lon": 4.4792 }, "postalCode": "3011", "state": "South Holland" },
    "id": null,
    "ipAddress": "198.51.100.23",
    "userAgent": { "browser": "CHROME", "os": "Windows 10", "rawUserAgent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36" },
    "zone": "null"
  },
  "debugContext": {
    "debugData": {
      "dtHash": "3f8a1c6e9b2d4f7a0c5e8b1d3f6a9c2e4b7d0f3a6c9e2b5d8f1a4c7e0b3d6f9a",
      "requestId": "ZvoqR2yDz9aQ2nMr0eXtAAAL8h",
      "requestUri": "/api/v1/users/00u8k2m4n6p8q0r3a1b2/lifecycle/reset_factors",
      "url": "/api/v1/users/00u8k2m4n6p8q0r3a1b2/lifecycle/reset_factors?"
    }
  },
  "device": null,
  "displayMessage": "Reset all factors for user",
  "eventType": "user.mfa.factor.reset_all",
  "legacyEventType": "core.user.factor.reset_all",
  "outcome": { "reason": null, "result": "SUCCESS" },
  "published": "2026-09-30T03:20:05.148Z",
  "request": {
    "ipChain": [
      { "geographicalContext": { "city": "Rotterdam", "country": "Netherlands", "geolocation": { "lat": 51.9225, "lon": 4.4792 }, "postalCode": "3011", "state": "South Holland" }, "ip": "198.51.100.23", "source": null, "version": "V4" }
    ]
  },
  "securityContext": { "asNumber": 9009, "asOrg": "m247 europe srl", "domain": "m247.com", "isProxy": false, "isp": "m247 ltd" },
  "severity": "INFO",
  "target": [
    { "alternateId": "yossi.bendavid@nexacorp.com", "detailEntry": null, "displayName": "Yossi Ben-David", "id": "00u8k2m4n6p8q0r3a1b2", "type": "User" }
  ],
  "transaction": { "detail": {}, "id": "ZvoqR2yDz9aQ2nMr0eXtAAAL8h", "type": "WEB" },
  "uuid": "e81c5b37-9e83-11f1-87c2-5a0e3d9b1f64",
  "version": "0"
}
```
*`actor` is not the `target`: an administrator removed every factor of another user. Legitimate resets come from Help Desk staff in the corporate zone after a ticket. This one comes from the session hijacked in 4.7. Yossi's next sign-in will force a fresh MFA enrollment, which the attacker can complete if they also get his password.*

### 4.10 `application.user_membership.add` — attacker assigns Dana to the AWS production app

```json
{
  "actor": { "alternateId": "dana.levi@nexacorp.com", "detailEntry": null, "displayName": "Dana Levi", "id": "00u8k2m4n6p8q0r2s4t6", "type": "User" },
  "authenticationContext": { "authenticationProvider": null, "authenticationStep": 0, "credentialProvider": null, "credentialType": null, "externalSessionId": "102Tq7rVh2KxW9mLp4sNc8dEw", "interface": null, "issuer": null },
  "client": {
    "device": "Computer",
    "geographicalContext": { "city": "Rotterdam", "country": "Netherlands", "geolocation": { "lat": 51.9225, "lon": 4.4792 }, "postalCode": "3011", "state": "South Holland" },
    "id": null,
    "ipAddress": "198.51.100.23",
    "userAgent": { "browser": "CHROME", "os": "Windows 10", "rawUserAgent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36" },
    "zone": "null"
  },
  "debugContext": {
    "debugData": {
      "requestId": "ZvorC6zEa0bR3oNs1fYuAAAM9i",
      "requestUri": "/api/v1/apps/0oa5nexaAwsProd04x7a/users",
      "url": "/api/v1/apps/0oa5nexaAwsProd04x7a/users?"
    }
  },
  "device": null,
  "displayMessage": "Add user to application membership",
  "eventType": "application.user_membership.add",
  "legacyEventType": "app.generic.provision.assign_user_to_app",
  "outcome": { "reason": null, "result": "SUCCESS" },
  "published": "2026-09-30T03:22:47.590Z",
  "request": {
    "ipChain": [
      { "geographicalContext": { "city": "Rotterdam", "country": "Netherlands", "geolocation": { "lat": 51.9225, "lon": 4.4792 }, "postalCode": "3011", "state": "South Holland" }, "ip": "198.51.100.23", "source": null, "version": "V4" }
    ]
  },
  "securityContext": { "asNumber": 9009, "asOrg": "m247 europe srl", "domain": "m247.com", "isProxy": false, "isp": "m247 ltd" },
  "severity": "INFO",
  "target": [
    { "alternateId": "dana.levi@nexacorp.com", "detailEntry": null, "displayName": "Dana Levi", "id": "0ua7nexaDanaAws04x7a", "type": "AppUser" },
    { "alternateId": "AWS IAM Identity Center - Production", "detailEntry": { "signOnModeType": "SAML_2_0" }, "displayName": "AWS IAM Identity Center", "id": "0oa5nexaAwsProd04x7a", "type": "AppInstance" },
    { "alternateId": "dana.levi@nexacorp.com", "detailEntry": null, "displayName": "Dana Levi", "id": "00u8k2m4n6p8q0r2s4t6", "type": "User" }
  ],
  "transaction": { "detail": {}, "id": "ZvorC6zEa0bR3oNs1fYuAAAM9i", "type": "WEB" },
  "uuid": "4a07d9e2-9e84-11f1-87c2-5a0e3d9b1f64",
  "version": "0"
}
```
*Self-assignment (`actor.id` equals the `User` target id) to a high-value app, from the risky session. Expect `user.authentication.sso` to that `AppInstance` minutes later. The three-target shape (`AppUser` / `AppInstance` / `User`), the `detailEntry` and the legacy type are UNVERIFIED.*

### 4.11 `system.api_token.create` — persistence via an unscoped API token

```json
{
  "actor": { "alternateId": "dana.levi@nexacorp.com", "detailEntry": null, "displayName": "Dana Levi", "id": "00u8k2m4n6p8q0r2s4t6", "type": "User" },
  "authenticationContext": { "authenticationProvider": null, "authenticationStep": 0, "credentialProvider": null, "credentialType": null, "externalSessionId": "102Tq7rVh2KxW9mLp4sNc8dEw", "interface": null, "issuer": null },
  "client": {
    "device": "Computer",
    "geographicalContext": { "city": "Rotterdam", "country": "Netherlands", "geolocation": { "lat": 51.9225, "lon": 4.4792 }, "postalCode": "3011", "state": "South Holland" },
    "id": null,
    "ipAddress": "198.51.100.23",
    "userAgent": { "browser": "CHROME", "os": "Windows 10", "rawUserAgent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36" },
    "zone": "null"
  },
  "debugContext": {
    "debugData": {
      "requestId": "ZvosN0aFb1cS4pOt2gZvAAANAj",
      "requestUri": "/api/internal/tokens",
      "url": "/api/internal/tokens?"
    }
  },
  "device": null,
  "displayMessage": "Create API token",
  "eventType": "system.api_token.create",
  "legacyEventType": "api.token.create",
  "outcome": { "reason": null, "result": "SUCCESS" },
  "published": "2026-09-30T03:25:13.004Z",
  "request": {
    "ipChain": [
      { "geographicalContext": { "city": "Rotterdam", "country": "Netherlands", "geolocation": { "lat": 51.9225, "lon": 4.4792 }, "postalCode": "3011", "state": "South Holland" }, "ip": "198.51.100.23", "source": null, "version": "V4" }
    ]
  },
  "securityContext": { "asNumber": 9009, "asOrg": "m247 europe srl", "domain": "m247.com", "isProxy": false, "isp": "m247 ltd" },
  "severity": "INFO",
  "target": [
    { "alternateId": "unknown", "detailEntry": null, "displayName": "svc-backup-sync", "id": "00T6nexaTokSync04x7a", "type": "Token" }
  ],
  "transaction": { "detail": {}, "id": "ZvosN0aFb1cS4pOt2gZvAAANAj", "type": "WEB" },
  "uuid": "a3e6f1b8-9e84-11f1-87c2-5a0e3d9b1f64",
  "version": "0"
}
```
*An API token carries the creator's admin rights and survives a password reset and session revocation for Dana. Later calls made with it show `transaction.detail.requestApiTokenId` and `actor` = Dana. Remediation must revoke `00T6nexaTokSync04x7a` (`system.api_token.revoke`). The `requestUri` and the target `type` value are UNVERIFIED.*

---

## 5. Investigation notes (pivots)

- **`authenticationContext.externalSessionId`** is the session pivot. Every event from the hijacked browser (4.4 → 4.11) carries `102Tq7rVh2KxW9mLp4sNc8dEw`. Filter on it to see everything the attacker did. Kill that session (`user.session.clear` / "Clear user sessions") during containment.
- **`transaction.id` = `debugData.requestId`** groups the events created by one HTTP request. 4.6b (`auth_via_mfa` SUCCESS) and 4.7 (`user.session.start` SUCCESS) share one. Use it to find the policy and MFA steps behind a login.
- **`debugData.authnRequestId`** ties the steps of one authentication transaction (identify → challenge → poll).
- **Spray vs. brute force:** group `user.session.start` + `outcome.reason = INVALID_CREDENTIALS` by `client.ipAddress` / `securityContext.asNumber`. Many `actor.alternateId` values from one ASN = spray. One user from many IPs = brute force / credential stuffing. Confirm with `security.threat.detected` (`outcome.reason`) and `threatSuspected: "true"`.
- **Lockouts:** `user.account.lock` (and `user.session.start` with `LOCKED_OUT`) whose `client.ipAddress` is a spray IP, not the user's own device, is collateral damage from an attack. Check `user.account.lock.limit` for accounts that will not auto-unlock.
- **Unusual country:** compare `client.geographicalContext.country`, `client.zone`, `securityContext.asOrg` and `debugData.behaviors` (`New Country=POSITIVE`, `Velocity=POSITIVE`) with the user's 30–90-day baseline. `isProxy: true` points to an anonymiser.
- **MFA fatigue (OIE):** per `externalSessionId`, count `system.push.send_factor_verify_push`, then `user.authentication.auth_via_mfa` with `debugData.factor = OKTA_VERIFY_PUSH`. Several `FAILURE`/`INVALID_CREDENTIALS` (`pushOnlyResponseType = OV_RESPONSE_DENY`) followed by one `SUCCESS` from a new IP/device = fatigue that ended in an approval. In Classic orgs look for `user.mfa.okta_verify.deny_push` instead.
- **Post-compromise persistence (admin trail):** after a risky `user.session.start`, look in the same session for `user.mfa.factor.activate` (new authenticator), `user.mfa.factor.reset_all` / `user.mfa.factor.deactivate` (on other users), `application.user_membership.add` / `group.user_membership.add` (new access), `user.account.privilege.grant` (admin role), `system.api_token.create` (token) and `app.oauth2.as.consent.grant`.
- **`actor` vs `target`:** in admin events, `actor` = who did it, `target[]` = who/what it was done to. A user acting on themselves (self-assignment, self-enrollment) from a risky session is the strongest signal.
- **Device pivots:** `debugData.dtHash` / `deviceFingerprint` identify the browser; top-level `device.id` / `device.name` identify an Okta Verify device. A new `dtHash` together with a new Okta Verify device in one session = attacker-controlled hardware.
- **API-token activity:** `transaction.detail.requestApiTokenId` marks every call made with a token. Join it with the `system.api_token.create` target to see what the token did.
- **Chain to teach:** spray (`user.session.start` FAILURE ×N + `security.threat.detected`) → collateral `user.account.lock` → `policy.evaluate_sign_on` CHALLENGE from a new country → push ×6 / deny ×5 → approve → `user.session.start` SUCCESS → `user.mfa.factor.activate` → `user.mfa.factor.reset_all` (CFO) → `application.user_membership.add` → `system.api_token.create`.

---

## 6. Common mistakes / fields that do NOT exist

**Do NOT use these (not in the native LogEvent):**
- `okta.*`, `data.okta.*`, `event.action`, `source.ip`, `user.name`, `client.ip`. These are SIEM normalisations (Elastic / Wazuh / Splunk CIM).
- `eventType` values that don't exist: `user.login.failed`, `user.session.failed`, `user.mfa.push.denied`, `user.mfa.okta_verify.deny` (the real Classic type is `user.mfa.okta_verify.deny_push`), `policy.evaluate.sign_on` (dot instead of underscore — wrong, even though one Okta support page has this typo), `user.mfa.factor.enroll` (the real type is `user.mfa.factor.activate`), `security.threat.detect`, `api_token.create` (the real type is `system.api_token.create`).
- `outcome.status`, `outcome.code`, `result` at top level. The real keys are `outcome.result` and `outcome.reason`.
- `client.geographicalContext.countryCode` / ISO country codes. `country` is the full English name.
- `client.ip` / `client.userAgent` as a string. The real keys are `client.ipAddress` and `client.userAgent.rawUserAgent`.
- `debugContext.debugData` values as JSON booleans or numbers (`"threatSuspected": true`). They are always strings.
- snake_case or PascalCase debugData keys (`threat_suspected`, `ThreatSuspected`, `PushOnlyResponseType`). Those are the catalog's and the Admin Console's spellings; the API uses camelCase.
- `actor.email`, `actor.login`, `target.name`. Use `actor.alternateId` and `target[].displayName` / `alternateId`.
- `target` as a single object. It is an array, or `null`.
- `securityContext.country`, `securityContext.asn`. The real keys are `asNumber` / `asOrg` / `isp` / `domain` / `isProxy`.
- `severity: "HIGH"` / `"CRITICAL"`. Only `DEBUG`, `INFO`, `WARN`, `ERROR` exist. Risk levels (`LOW`/`MEDIUM`/`HIGH`) live inside `debugData.risk`, not in `severity`.
- `version: 0` (number). It is the string `"0"`.

**Semantic mistakes to avoid in generated events:**
- Emitting `user.mfa.okta_verify.deny_push` in an OIE org. In OIE a deny is `user.authentication.auth_via_mfa` + `FAILURE` + `INVALID_CREDENTIALS`. Pick one engine per org and stay consistent.
- Showing `user.account.lock` after push denies. Denies don't count toward lockout; only bad passwords (and OTP failures, which suspend the factor) do.
- `security.threat.detected` with `result: "DENY"` followed by a successful login from the same request. DENY means the request was blocked.
- A `policy.evaluate_sign_on` event with an empty or `unknown` actor. The policy is evaluated for an identified user, so `actor` is that user.
- Putting the phone's IP/location in `system.push.send_factor_verify_push` `client.*`. `client` is the requesting browser.
- `published` without milliseconds or with a local offset. Use `YYYY-MM-DDTHH:MM:SS.mmmZ`.
