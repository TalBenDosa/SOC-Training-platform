# Microsoft Entra ID — sign-in logs + directory audit logs

Category: IDENTITY (cloud IdP). Vendor: Microsoft. Card version: 2026-10-01.

---

## 1. Official sources consulted

| URL | What it confirmed |
|---|---|
| https://learn.microsoft.com/en-us/graph/api/resources/signin?view=graph-rest-1.0 | v1.0 `signIn` property list + JSON shape; enums for `conditionalAccessStatus`, `riskLevel*`, `riskState`, `riskEventTypes_v2`; UPN always lowercase. |
| https://learn.microsoft.com/en-us/graph/api/resources/signin?view=graph-rest-beta | Full beta `signIn` (authenticationDetails, authenticationRequirement, signInEventTypes, sessionId, uniqueTokenIdentifier, userAgent, autonomousSystemNumber, authenticationProtocol / incomingTokenType / crossTenantAccessType / clientCredentialType / signInIdentifierType / userType enums; `mfaDetail` deprecated). |
| https://learn.microsoft.com/en-us/graph/api/signin-list?view=graph-rest-beta | Real example responses (50126 failure, nonInteractive success, appliedConditionalAccessPolicies element shape, authenticationProcessingDetails key/value, networkLocationDetails). Only interactive sign-ins are returned unless `signInEventTypes` is filtered. |
| https://learn.microsoft.com/en-us/graph/api/resources/authenticationdetail?view=graph-rest-beta | `authenticationDetails[]` element: authenticationMethod, authenticationMethodDetail, authenticationStepDateTime, authenticationStepRequirement, authenticationStepResultDetail, succeeded. |
| https://learn.microsoft.com/en-us/graph/api/resources/devicedetail?view=graph-rest-1.0 | `deviceDetail` = browser, deviceId, displayName, isCompliant, isManaged, operatingSystem, trustType. |
| https://learn.microsoft.com/en-us/graph/api/resources/directoryaudit?view=graph-rest-1.0 | `directoryAudit` shape: activityDateTime, activityDisplayName, additionalDetails, category, correlationId, id, initiatedBy, loggedByService, operationType, result, resultReason, targetResources. |
| https://learn.microsoft.com/en-us/entra/identity/monitoring-health/concept-activity-log-schemas | Graph is the primary programmatic schema; Azure Monitor / Log Analytics schemas "might differ"; `hidden` returned without P2. |
| https://learn.microsoft.com/en-us/entra/identity/monitoring-health/reference-audit-activities | Activity names + service + category: "Add member to role" (Core Directory / RoleManagement), "Consent to application", "Add service principal credentials" (Core Directory / ApplicationManagement), "Update user", "Reset password", "Disable account" (Core Directory / UserManagement), "User registered security info" (Authentication Methods / UserManagement), PIM variants ("Add member to role completed (PIM activation)" …). |
| https://github.com/elastic/integrations/tree/main/packages/azure/data_stream/signinlogs/_dev/test/pipeline (test-signinlogs-raw.log) and `auditlogs` equivalent | Real Azure Monitor diagnostic-export envelopes: `time, resourceId, operationName "Sign-in activity", operationVersion, category "SignInLogs"/"NonInteractiveUserSignInLogs", tenantId, resultType (string), resultSignature, resultDescription, durationMs, callerIpAddress, correlationId, identity, Level, location, properties{…}`; audit envelope `operationName "Update device"`, `level "Informational"`, `properties{…directoryAudit…}`. |

---

## 2. Native format, delivery, and the representation we standardise on

Entra exposes the same events through three delivery paths:

1. **Microsoft Graph** — `GET https://graph.microsoft.com/beta/auditLogs/signIns` and `/v1.0/auditLogs/directoryAudits`. Returns camelCase JSON objects inside `{"@odata.context": …, "value": [ … ]}`. The admin-center "Download → JSON" export uses the same shape.
2. **Azure Monitor diagnostic settings** (Event Hub / Storage account). Each record is an envelope (`time`, `category`, `resultType`, `callerIpAddress`, …) and the Graph-like object sits under `properties`.
3. **Log Analytics / Sentinel tables** (`SigninLogs`, `AADNonInteractiveUserSignInLogs`, `AuditLogs`). These use PascalCase columns (`UserPrincipalName`, `ResultType`, `LocationDetails`, `ConditionalAccessPolicies`). This is a SIEM table projection, **not** native.

**STANDARD FOR THIS PLATFORM: one Graph object per event, no envelope.**
- Sign-ins use the **Graph beta `signIn`** shape. v1.0 does not have `authenticationDetails`, `authenticationRequirement`, `signInEventTypes`, `sessionId`, `userAgent` or `autonomousSystemNumber`, and a SOC analyst needs all of them. The beta shape is also what the portal JSON export produces.
- Audits use the **Graph v1.0 `directoryAudit`** shape.
- Don't wrap the object in `{"value":[…]}`. Show the single object.
- Timestamps follow Graph: `createdDateTime` is ISO-8601 UTC and usually has no fraction (`"2026-09-30T02:14:07Z"`). `activityDateTime` is shown with 7-digit fractional seconds (`"2026-09-30T02:41:18.4419382Z"`).
- `userPrincipalName` is always lowercase in sign-ins.
- Never mix in the Azure Monitor envelope fields (`resultType`, `callerIpAddress`, `category: "SignInLogs"`, `properties`) or the Log Analytics PascalCase columns.

---

## 3. Core field reference — `signIn` (Graph beta)

| Path | Type | Meaning / allowed values |
|---|---|---|
| `id` | string (GUID) | Unique sign-in request id. In practice it's a GUID that often ends in hex digits, for example `…0e00`. |
| `createdDateTime` | DateTimeOffset | UTC time the sign-in started. |
| `userDisplayName`, `userPrincipalName`, `userId` | string | The user. UPN is lowercase. `userId` is the object GUID. |
| `userType` | enum | `member`, `guest`. |
| `appId`, `appDisplayName` | string | Client application. Well-known IDs: Microsoft Office `d3590ed6-52b3-4102-aeff-aad2292ab01c`, OfficeHome `4765445b-32c6-49b0-83e6-1d93765276ca`, Azure Portal `c44b4083-3bb0-49c1-b47d-974e53cbdf3c`, Microsoft Authentication Broker `29d9ed98-a469-4536-ade2-f981bc1d605e`. |
| `resourceId`, `resourceDisplayName` | string | Resource the token targets. Microsoft Graph `00000003-0000-0000-c000-000000000000`, Office 365 Exchange Online `00000002-0000-0ff1-ce00-000000000000`, Windows Azure Service Management API `797f4846-ba00-4fd7-ba43-dac1f8f63013`. |
| `resourceTenantId`, `homeTenantId`, `homeTenantName` | string | Tenant that owns the resource vs. the user's home tenant. If they differ, the sign-in is cross-tenant/guest. |
| `ipAddress` | string | Client IP as seen by Entra. |
| `autonomousSystemNumber` | int | ASN of `ipAddress`. |
| `location.city / state / countryOrRegion` | string | `countryOrRegion` is a 2-letter ISO code. |
| `location.geoCoordinates.{altitude,latitude,longitude}` | double/null | Often `{}` in exports. |
| `clientAppUsed` | string | Modern: `Browser`, `Mobile Apps and Desktop clients`. Legacy: `Exchange ActiveSync`, `IMAP4`, `POP3`, `Authenticated SMTP`, `MAPI Over HTTP`, `Exchange Web Services`, `Other clients` (Graph docs abbreviate these as IMAP/POP/SMTP/MAPI; the exact strings follow the Entra legacy-auth/CA documentation — UNVERIFIED letter-for-letter). |
| `userAgent` | string | Raw user agent string. |
| `isInteractive` | bool | `true` if the user presented a factor. |
| `signInEventTypes` | string[] | `interactiveUser`, `nonInteractiveUser`, `servicePrincipal`, `managedIdentity`. |
| `authenticationProtocol` | enum | `none`, `oAuth2`, `ropc`, `wsFederation`, `saml20`, `deviceCode`, … (`deviceCode` is the device-code phishing signal). |
| `incomingTokenType` | enum | `none`, `primaryRefreshToken`, `saml11`, `saml20`, `remoteDesktopToken`, `refreshToken`. (Graph's own example shows the display form "Primary Refresh Token". Use the enum form.) |
| `authenticationRequirement` | string | `singleFactorAuthentication` or `multiFactorAuthentication`. This is the requirement **reached**, not what was satisfied. If primary auth fails, the value is always `singleFactorAuthentication`. |
| `authenticationMethodsUsed` | string[] | e.g. `Password`, `Authenticator App`, `SMS`, `FIDO`, `PTA`, `PHS`. |
| `authenticationDetails[]` | array | One element per step: `authenticationStepDateTime`, `authenticationMethod` (`Password`, `SMS`, `Voice`, `Authenticator App`, `Software OATH token`, `Satisfied by token`, `Previously satisfied`), `authenticationMethodDetail` (e.g. `Password in the cloud`, phone, device name), `succeeded` (bool), `authenticationStepResultDetail` (free text, e.g. `Correct password`, `Invalid username or password or Invalid on-premise username or password.`, `MFA denied; user declined the authentication`, `MFA requirement satisfied by claim in the token`), `authenticationStepRequirement` (`Primary authentication`, MFA step). The push method text "Mobile app notification" and the MFA-step label are common in tenant exports but aren't listed on the Graph page — UNVERIFIED. |
| `authenticationProcessingDetails[]` | {key,value}[] | e.g. `Login Hint Present`, `Root Key Type`, `Oauth Scope Info`, `Legacy TLS (TLS 1.0, 1.1, 3DES)`. |
| `conditionalAccessStatus` | enum | `success`, `failure`, `notApplied`, `unknownFutureValue`. |
| `appliedConditionalAccessPolicies[]` | array | `id`, `displayName`, `enforcedGrantControls[]` (e.g. `Mfa`, `Block`, `RequireCompliantDevice`), `enforcedSessionControls[]`, `result` (`success`, `failure`, `notApplied`, `notEnabled`, `unknown`, `reportOnlySuccess`, `reportOnlyFailure`, `reportOnlyNotApplied`, `reportOnlyInterrupted`), `conditionsSatisfied`, `conditionsNotSatisfied`, `includeRulesSatisfied[]`, `excludeRulesSatisfied[]`. Omitted entirely if the caller lacks CA-read permission. |
| `riskDetail` | enum | `none`, `adminGeneratedTemporaryPassword`, `userPerformedSecuredPasswordChange`, `userPerformedSecuredPasswordReset`, `adminConfirmedSigninSafe`, `aiConfirmedSigninSafe`, `userPassedMFADrivenByRiskBasedPolicy`, `adminDismissedAllRiskForUser`, `adminConfirmedSigninCompromised`, `hidden`, … (`hidden` without P2). |
| `riskLevelAggregated`, `riskLevelDuringSignIn` | enum | `none`, `low`, `medium`, `high`, `hidden`. *DuringSignIn* = real-time. *Aggregated* = includes offline detections. |
| `riskState` | enum | `none`, `confirmedSafe`, `remediated`, `dismissed`, `atRisk`, `confirmedCompromised`. |
| `riskEventTypes_v2` | string[] | `unlikelyTravel`, `anonymizedIPAddress`, `maliciousIPAddress`, `unfamiliarFeatures`, `malwareInfectedIPAddress`, `suspiciousIPAddress`, `leakedCredentials`, `investigationsThreatIntelligence`, `generic`. (`riskEventTypes` without `_v2` is deprecated.) |
| `status.errorCode` | int | `0` = success. See the table below. |
| `status.failureReason` | string | Short text. Graph examples show `"Other."` on successes. |
| `status.additionalDetails` | string/null | Longer explanation. |
| `deviceDetail.{deviceId,displayName,operatingSystem,browser,isCompliant,isManaged,trustType}` | mixed | `trustType`: `Azure AD joined`, `Azure AD registered`, `Hybrid Azure AD joined`, or `""`. |
| `correlationId` | string (GUID) | Client request id. Shared by all sign-ins of one auth flow. |
| `originalRequestId` | string | First request in the auth sequence. |
| `sessionId` | string (GUID) | Entra session generated at sign-in. Every later token refresh from the same session carries it. **Primary pivot.** |
| `uniqueTokenIdentifier` | string (base64) | Token id. Joins to M365/Graph activity logs (where it is `UniqueTokenId`/`uti`). |
| `crossTenantAccessType` | enum | `none`, `b2bCollaboration`, `b2bDirectConnect`, `microsoftSupport`, `serviceProvider`, `passthrough`. |
| `tokenIssuerType` | enum | `AzureAD`, `ADFederationServices`, … |
| `networkLocationDetails[]` | array | `networkType` (`namedNetwork`, `trustedNamedLocation`, …), `networkNames[]`. |
| `servicePrincipalId`, `servicePrincipalName`, `clientCredentialType` | string/enum | Service-principal sign-ins. `clientCredentialType`: `none`, `clientSecret`, `clientAssertion`, `federatedIdentityCredential`, `managedIdentity`, `certificate`. |
| `flaggedForReview`, `isTenantRestricted`, `processingTimeInMilliseconds` | bool/int | Misc. |

### `status.errorCode` values commonly needed in SOC scenarios

| errorCode | Meaning (short) |
|---|---|
| 0 | Success |
| 50126 | Invalid username or password (`Error validating credentials due to invalid username or password.`) |
| 50053 | Account locked (Smart Lockout) **or** sign-in from a malicious-IP block |
| 50034 | User account doesn't exist in the directory |
| 50057 | User account is disabled |
| 50055 | Password expired |
| 50074 | Strong authentication (MFA) required — an interrupt, not an attack signal by itself |
| 50076 | MFA required because of a configuration change or new location (CA) |
| 500121 | Authentication failed during the strong-authentication request (MFA denied, timed out or failed) |
| 50158 | External security challenge not satisfied |
| 53003 | Blocked by Conditional Access |
| 50140 | "Keep me signed in" interrupt |
| 50097 | Device authentication required |
| 70044 / 50133 | Session expired / session invalid after password change |

---

## 3b. Core field reference — `directoryAudit` (Graph v1.0)

| Path | Type | Meaning / allowed values |
|---|---|---|
| `id` | string | Activity id. The format is service-specific (e.g. `Directory_<guid>_<suffix>`). Treat it as opaque. |
| `category` | string | `UserManagement`, `GroupManagement`, `ApplicationManagement`, `RoleManagement`, `Policy`, `Device`, `DirectoryManagement`, … |
| `correlationId` | GUID | Correlates the multi-event operations of one admin action. |
| `result` | enum | `success`, `failure`, `timeout`, `unknownFutureValue`. |
| `resultReason` | string | Free text. Often empty on success. |
| `activityDisplayName` | string | Activity name exactly as in the audit-activities reference (see the list below). |
| `activityDateTime` | DateTimeOffset | UTC. |
| `loggedByService` | string | `Core Directory`, `Authentication Methods`, `Self-service Password Management`, `PIM`, `Invited Users`, `B2C`, … |
| `operationType` | string | `Add`, `Assign`, `Update`, `Unassign`, `Delete`. |
| `initiatedBy.user.{id,displayName,userPrincipalName,ipAddress}` | object | Present when a user acted. `ipAddress` = the client IP. |
| `initiatedBy.app.{appId,displayName,servicePrincipalId,servicePrincipalName}` | object | Present when an app/SP acted. The other branch is `null`. |
| `targetResources[]` | array | `id`, `displayName`, `type` (`User`, `Group`, `Device`, `Directory`, `ServicePrincipal`, `Application`, `Role`, `Policy`, `Other`), `userPrincipalName`, `groupType`, `modifiedProperties[]`. |
| `targetResources[].modifiedProperties[]` | array | `displayName`, `oldValue`, `newValue`. Values are **JSON-encoded strings** (e.g. `"\"Global Administrator\""`). |
| `additionalDetails[]` | {key,value}[] | e.g. `User-Agent`, `AppId`, `MethodsRegistered`. |

Key activity names: `Add member to role`, `Add eligible member to role`, `Add member to role completed (PIM activation)`, `Consent to application`, `Add delegated permission grant`, `Add app role assignment to service principal`, `Add service principal credentials`, `Remove service principal credentials`, `Add owner to application`, `Update user`, `Reset password`, `Disable account`, `User registered security info`, `User deleted security info`, `Admin registered security info`, `Update policy`, `Add member to group`.

---

## 4. Samples (Graph shape; fictitious tenant `nexacorp.com`, IPs from RFC 5737 documentation ranges)

Shared values: tenant `7c1e5b9a-3f4d-4e2a-9b8c-2d6f0a1e4b37`. Victim Dana Levi `4f2b8c1d-9e3a-4b7f-8c2d-1a5e6f7b8c9d`. Attacker spray infrastructure 203.0.113.0/24. Attacker interactive host 198.51.100.23 (AS9009).

### 4.1 Password spray — one failed attempt (50126, ROPC, legacy-style client)

```json
{
  "id": "b3f6a2c1-7d4e-4f8a-9c2b-5e1d3a7f0c00",
  "createdDateTime": "2026-09-30T02:14:07Z",
  "userDisplayName": "Dana Levi",
  "userPrincipalName": "dana.levi@nexacorp.com",
  "userId": "4f2b8c1d-9e3a-4b7f-8c2d-1a5e6f7b8c9d",
  "userType": "member",
  "appId": "d3590ed6-52b3-4102-aeff-aad2292ab01c",
  "appDisplayName": "Microsoft Office",
  "ipAddress": "203.0.113.47",
  "autonomousSystemNumber": 9009,
  "clientAppUsed": "Mobile Apps and Desktop clients",
  "userAgent": "python-requests/2.32.3",
  "correlationId": "e7a19c42-5b3d-4c8e-a1f6-0d2b9e4c7a31",
  "originalRequestId": "b3f6a2c1-7d4e-4f8a-9c2b-5e1d3a7f0c00",
  "conditionalAccessStatus": "notApplied",
  "isInteractive": true,
  "signInEventTypes": ["interactiveUser"],
  "authenticationProtocol": "ropc",
  "incomingTokenType": "none",
  "authenticationRequirement": "singleFactorAuthentication",
  "authenticationMethodsUsed": [],
  "tokenIssuerName": "",
  "tokenIssuerType": "AzureAD",
  "processingTimeInMilliseconds": 97,
  "riskDetail": "none",
  "riskLevelAggregated": "none",
  "riskLevelDuringSignIn": "none",
  "riskState": "none",
  "riskEventTypes_v2": [],
  "resourceDisplayName": "Office 365 Exchange Online",
  "resourceId": "00000002-0000-0ff1-ce00-000000000000",
  "resourceTenantId": "7c1e5b9a-3f4d-4e2a-9b8c-2d6f0a1e4b37",
  "homeTenantId": "7c1e5b9a-3f4d-4e2a-9b8c-2d6f0a1e4b37",
  "homeTenantName": "",
  "signInIdentifier": "dana.levi@nexacorp.com",
  "signInIdentifierType": "userPrincipalName",
  "servicePrincipalId": "",
  "sessionId": "",
  "uniqueTokenIdentifier": "wqJvs6F9REyX0dKJ4sZ8AA",
  "crossTenantAccessType": "none",
  "flaggedForReview": false,
  "isTenantRestricted": false,
  "status": {
    "errorCode": 50126,
    "failureReason": "Error validating credentials due to invalid username or password.",
    "additionalDetails": "The user didn't enter the right credentials. It's expected to see some number of these errors in your logs due to users making mistakes."
  },
  "deviceDetail": {
    "deviceId": "",
    "displayName": "",
    "operatingSystem": "",
    "browser": "Python Requests 2.32",
    "isCompliant": false,
    "isManaged": false,
    "trustType": ""
  },
  "location": {
    "city": "Amsterdam",
    "state": "Noord-Holland",
    "countryOrRegion": "NL",
    "geoCoordinates": { "altitude": null, "latitude": 52.37403, "longitude": 4.88969 }
  },
  "appliedConditionalAccessPolicies": [],
  "authenticationProcessingDetails": [
    { "key": "Legacy TLS (TLS 1.0, 1.1, 3DES)", "value": "False" }
  ],
  "networkLocationDetails": [],
  "authenticationDetails": [
    {
      "authenticationStepDateTime": "2026-09-30T02:14:07Z",
      "authenticationMethod": "Password",
      "authenticationMethodDetail": "Password in the cloud",
      "succeeded": false,
      "authenticationStepResultDetail": "Invalid username or password or Invalid on-premise username or password.",
      "authenticationStepRequirement": "Primary authentication"
    }
  ],
  "authenticationRequirementPolicies": [],
  "sessionLifetimePolicies": []
}
```
*Spray pattern: the same `ipAddress`/ASN, many different `userPrincipalName` values, `errorCode` 50126, and a few attempts per user per hour. CA isn't evaluated, so `notApplied` is expected.*

### 4.2 Successful sign-in after the spray, foreign IP, single factor, real-time risk

```json
{
  "id": "5d8e0b7a-2c41-4f9e-8a63-91c7f2d40e00",
  "createdDateTime": "2026-09-30T02:37:51Z",
  "userDisplayName": "Dana Levi",
  "userPrincipalName": "dana.levi@nexacorp.com",
  "userId": "4f2b8c1d-9e3a-4b7f-8c2d-1a5e6f7b8c9d",
  "userType": "member",
  "appId": "4765445b-32c6-49b0-83e6-1d93765276ca",
  "appDisplayName": "OfficeHome",
  "ipAddress": "198.51.100.23",
  "autonomousSystemNumber": 9009,
  "clientAppUsed": "Browser",
  "userAgent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36",
  "correlationId": "0c4f7a2e-9d18-4b63-b5e0-7a2c1f9d3e86",
  "originalRequestId": "5d8e0b7a-2c41-4f9e-8a63-91c7f2d40e00",
  "conditionalAccessStatus": "notApplied",
  "isInteractive": true,
  "signInEventTypes": ["interactiveUser"],
  "authenticationProtocol": "oAuth2",
  "incomingTokenType": "none",
  "authenticationRequirement": "singleFactorAuthentication",
  "authenticationMethodsUsed": ["Password"],
  "tokenIssuerName": "",
  "tokenIssuerType": "AzureAD",
  "processingTimeInMilliseconds": 212,
  "riskDetail": "none",
  "riskLevelAggregated": "medium",
  "riskLevelDuringSignIn": "medium",
  "riskState": "atRisk",
  "riskEventTypes_v2": ["unfamiliarFeatures"],
  "resourceDisplayName": "OfficeHome",
  "resourceId": "4765445b-32c6-49b0-83e6-1d93765276ca",
  "resourceTenantId": "7c1e5b9a-3f4d-4e2a-9b8c-2d6f0a1e4b37",
  "homeTenantId": "7c1e5b9a-3f4d-4e2a-9b8c-2d6f0a1e4b37",
  "homeTenantName": "",
  "signInIdentifier": "dana.levi@nexacorp.com",
  "signInIdentifierType": "userPrincipalName",
  "servicePrincipalId": "",
  "sessionId": "a91f3c6d-0e2b-4d85-9f17-c3b8e5a2d740",
  "uniqueTokenIdentifier": "e7j8XdZpbkOjqY2fK1VvAA",
  "crossTenantAccessType": "none",
  "flaggedForReview": false,
  "isTenantRestricted": false,
  "status": { "errorCode": 0, "failureReason": "Other.", "additionalDetails": null },
  "deviceDetail": {
    "deviceId": "",
    "displayName": "",
    "operatingSystem": "Windows10",
    "browser": "Chrome 140.0.0",
    "isCompliant": false,
    "isManaged": false,
    "trustType": ""
  },
  "location": {
    "city": "Bucharest",
    "state": "Bucuresti",
    "countryOrRegion": "RO",
    "geoCoordinates": { "altitude": null, "latitude": 44.43225, "longitude": 26.10626 }
  },
  "appliedConditionalAccessPolicies": [
    {
      "id": "2b6d9f1e-7c3a-4e58-b0d4-6a1f8e2c9b57",
      "displayName": "Require MFA - Admin portals",
      "enforcedGrantControls": [],
      "enforcedSessionControls": [],
      "result": "notApplied",
      "conditionsSatisfied": "none",
      "conditionsNotSatisfied": "application",
      "includeRulesSatisfied": [],
      "excludeRulesSatisfied": []
    }
  ],
  "authenticationProcessingDetails": [
    { "key": "Login Hint Present", "value": "False" }
  ],
  "networkLocationDetails": [],
  "authenticationDetails": [
    {
      "authenticationStepDateTime": "2026-09-30T02:37:51Z",
      "authenticationMethod": "Password",
      "authenticationMethodDetail": "Password in the cloud",
      "succeeded": true,
      "authenticationStepResultDetail": "Correct password",
      "authenticationStepRequirement": "Primary authentication"
    }
  ],
  "authenticationRequirementPolicies": [],
  "sessionLifetimePolicies": []
}
```

### 4.3 MFA push fatigue — push denied by the user (500121)

```json
{
  "id": "c27a94e1-6f0d-4b3c-8e95-2d71a0f6b300",
  "createdDateTime": "2026-09-30T03:02:19Z",
  "userDisplayName": "Dana Levi",
  "userPrincipalName": "dana.levi@nexacorp.com",
  "userId": "4f2b8c1d-9e3a-4b7f-8c2d-1a5e6f7b8c9d",
  "userType": "member",
  "appId": "c44b4083-3bb0-49c1-b47d-974e53cbdf3c",
  "appDisplayName": "Azure Portal",
  "ipAddress": "198.51.100.23",
  "autonomousSystemNumber": 9009,
  "clientAppUsed": "Browser",
  "userAgent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36",
  "correlationId": "7f3b1d58-a2c9-4e06-9b74-e18d5c2f0a93",
  "originalRequestId": "c27a94e1-6f0d-4b3c-8e95-2d71a0f6b300",
  "conditionalAccessStatus": "failure",
  "isInteractive": true,
  "signInEventTypes": ["interactiveUser"],
  "authenticationProtocol": "oAuth2",
  "incomingTokenType": "none",
  "authenticationRequirement": "multiFactorAuthentication",
  "authenticationMethodsUsed": ["Password"],
  "tokenIssuerName": "",
  "tokenIssuerType": "AzureAD",
  "processingTimeInMilliseconds": 61408,
  "riskDetail": "none",
  "riskLevelAggregated": "medium",
  "riskLevelDuringSignIn": "medium",
  "riskState": "atRisk",
  "riskEventTypes_v2": ["unfamiliarFeatures"],
  "resourceDisplayName": "Windows Azure Service Management API",
  "resourceId": "797f4846-ba00-4fd7-ba43-dac1f8f63013",
  "resourceTenantId": "7c1e5b9a-3f4d-4e2a-9b8c-2d6f0a1e4b37",
  "homeTenantId": "7c1e5b9a-3f4d-4e2a-9b8c-2d6f0a1e4b37",
  "homeTenantName": "",
  "signInIdentifier": "dana.levi@nexacorp.com",
  "signInIdentifierType": "userPrincipalName",
  "servicePrincipalId": "",
  "sessionId": "",
  "uniqueTokenIdentifier": "4ZSnwg1vPEuOlS1xoPazAA",
  "crossTenantAccessType": "none",
  "flaggedForReview": false,
  "isTenantRestricted": false,
  "status": {
    "errorCode": 500121,
    "failureReason": "Authentication failed during strong authentication request.",
    "additionalDetails": "The user didn't complete the MFA prompt. They may have decided not to authenticate, timed out while doing other work, or has an issue with their authentication setup."
  },
  "deviceDetail": {
    "deviceId": "",
    "displayName": "",
    "operatingSystem": "Windows10",
    "browser": "Chrome 140.0.0",
    "isCompliant": false,
    "isManaged": false,
    "trustType": ""
  },
  "location": {
    "city": "Bucharest",
    "state": "Bucuresti",
    "countryOrRegion": "RO",
    "geoCoordinates": { "altitude": null, "latitude": 44.43225, "longitude": 26.10626 }
  },
  "appliedConditionalAccessPolicies": [
    {
      "id": "2b6d9f1e-7c3a-4e58-b0d4-6a1f8e2c9b57",
      "displayName": "Require MFA - Admin portals",
      "enforcedGrantControls": ["Mfa"],
      "enforcedSessionControls": [],
      "result": "failure",
      "conditionsSatisfied": "application,users",
      "conditionsNotSatisfied": "none",
      "includeRulesSatisfied": [],
      "excludeRulesSatisfied": []
    }
  ],
  "authenticationProcessingDetails": [],
  "networkLocationDetails": [],
  "authenticationDetails": [
    {
      "authenticationStepDateTime": "2026-09-30T03:01:18Z",
      "authenticationMethod": "Password",
      "authenticationMethodDetail": "Password in the cloud",
      "succeeded": true,
      "authenticationStepResultDetail": "Correct password",
      "authenticationStepRequirement": "Primary authentication"
    },
    {
      "authenticationStepDateTime": "2026-09-30T03:02:19Z",
      "authenticationMethod": "Mobile app notification",
      "authenticationMethodDetail": "iPhone 15",
      "succeeded": false,
      "authenticationStepResultDetail": "MFA denied; user declined the authentication",
      "authenticationStepRequirement": "Multifactor authentication"
    }
  ],
  "authenticationRequirementPolicies": [
    { "requirementProvider": "multiConditionalAccess", "detail": "Conditional Access" }
  ],
  "sessionLifetimePolicies": []
}
```
*Push fatigue = several 500121 events like this one (different `id`/`correlationId`, the same attacker `ipAddress`), followed by 4.4. The text `conditionalAccessStatus: "failure"` on an MFA-denied event and the `authenticationRequirementPolicies` element shape are UNVERIFIED (both plausible from tenant exports).*

### 4.4 MFA push fatigue — push finally approved (success, MFA)

```json
{
  "id": "e94d0c3b-18a7-4f52-b6e9-0a3d7c1f5800",
  "createdDateTime": "2026-09-30T03:06:44Z",
  "userDisplayName": "Dana Levi",
  "userPrincipalName": "dana.levi@nexacorp.com",
  "userId": "4f2b8c1d-9e3a-4b7f-8c2d-1a5e6f7b8c9d",
  "userType": "member",
  "appId": "c44b4083-3bb0-49c1-b47d-974e53cbdf3c",
  "appDisplayName": "Azure Portal",
  "ipAddress": "198.51.100.23",
  "autonomousSystemNumber": 9009,
  "clientAppUsed": "Browser",
  "userAgent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36",
  "correlationId": "3a6c8e1f-4b27-4d90-a5c3-f72e9b0d1c64",
  "originalRequestId": "e94d0c3b-18a7-4f52-b6e9-0a3d7c1f5800",
  "conditionalAccessStatus": "success",
  "isInteractive": true,
  "signInEventTypes": ["interactiveUser"],
  "authenticationProtocol": "oAuth2",
  "incomingTokenType": "none",
  "authenticationRequirement": "multiFactorAuthentication",
  "authenticationMethodsUsed": ["Password", "Authenticator App"],
  "tokenIssuerName": "",
  "tokenIssuerType": "AzureAD",
  "processingTimeInMilliseconds": 18342,
  "riskDetail": "none",
  "riskLevelAggregated": "medium",
  "riskLevelDuringSignIn": "medium",
  "riskState": "atRisk",
  "riskEventTypes_v2": ["unfamiliarFeatures"],
  "resourceDisplayName": "Windows Azure Service Management API",
  "resourceId": "797f4846-ba00-4fd7-ba43-dac1f8f63013",
  "resourceTenantId": "7c1e5b9a-3f4d-4e2a-9b8c-2d6f0a1e4b37",
  "homeTenantId": "7c1e5b9a-3f4d-4e2a-9b8c-2d6f0a1e4b37",
  "homeTenantName": "",
  "signInIdentifier": "dana.levi@nexacorp.com",
  "signInIdentifierType": "userPrincipalName",
  "servicePrincipalId": "",
  "sessionId": "6be2d1f9-35c8-4a07-8e4d-b19f0c7a2e53",
  "uniqueTokenIdentifier": "O9tq3zE2y0Wc1pNbXk4RAA",
  "crossTenantAccessType": "none",
  "flaggedForReview": false,
  "isTenantRestricted": false,
  "status": { "errorCode": 0, "failureReason": "Other.", "additionalDetails": "MFA completed in Azure AD" },
  "deviceDetail": {
    "deviceId": "",
    "displayName": "",
    "operatingSystem": "Windows10",
    "browser": "Chrome 140.0.0",
    "isCompliant": false,
    "isManaged": false,
    "trustType": ""
  },
  "location": {
    "city": "Bucharest",
    "state": "Bucuresti",
    "countryOrRegion": "RO",
    "geoCoordinates": { "altitude": null, "latitude": 44.43225, "longitude": 26.10626 }
  },
  "appliedConditionalAccessPolicies": [
    {
      "id": "2b6d9f1e-7c3a-4e58-b0d4-6a1f8e2c9b57",
      "displayName": "Require MFA - Admin portals",
      "enforcedGrantControls": ["Mfa"],
      "enforcedSessionControls": [],
      "result": "success",
      "conditionsSatisfied": "application,users",
      "conditionsNotSatisfied": "none",
      "includeRulesSatisfied": [],
      "excludeRulesSatisfied": []
    }
  ],
  "authenticationProcessingDetails": [],
  "networkLocationDetails": [],
  "authenticationDetails": [
    {
      "authenticationStepDateTime": "2026-09-30T03:06:26Z",
      "authenticationMethod": "Password",
      "authenticationMethodDetail": "Password in the cloud",
      "succeeded": true,
      "authenticationStepResultDetail": "Correct password",
      "authenticationStepRequirement": "Primary authentication"
    },
    {
      "authenticationStepDateTime": "2026-09-30T03:06:44Z",
      "authenticationMethod": "Mobile app notification",
      "authenticationMethodDetail": "iPhone 15",
      "succeeded": true,
      "authenticationStepResultDetail": "MFA successfully completed",
      "authenticationStepRequirement": "Multifactor authentication"
    }
  ],
  "authenticationRequirementPolicies": [
    { "requirementProvider": "multiConditionalAccess", "detail": "Conditional Access" }
  ],
  "sessionLifetimePolicies": []
}
```

### 4.5 Legacy authentication — valid password, blocked by Conditional Access (53003)

```json
{
  "id": "1f7c2a9d-4e83-4b16-9d0a-c5e2b7f83a00",
  "createdDateTime": "2026-09-30T04:11:02Z",
  "userDisplayName": "Yossi Mizrahi",
  "userPrincipalName": "yossi.mizrahi@nexacorp.com",
  "userId": "9a3e7c51-2d6b-4f08-b4e1-7c0d5a8f2e96",
  "userType": "member",
  "appId": "00000002-0000-0ff1-ce00-000000000000",
  "appDisplayName": "Office 365 Exchange Online",
  "ipAddress": "203.0.113.112",
  "autonomousSystemNumber": 14061,
  "clientAppUsed": "Exchange ActiveSync",
  "userAgent": "Android-Mail/2025.08.10.123456789.release",
  "correlationId": "d05b8f3a-6c71-4e29-a8d4-1b9e7c3f0d52",
  "originalRequestId": "1f7c2a9d-4e83-4b16-9d0a-c5e2b7f83a00",
  "conditionalAccessStatus": "failure",
  "isInteractive": true,
  "signInEventTypes": ["interactiveUser"],
  "authenticationProtocol": "ropc",
  "incomingTokenType": "none",
  "authenticationRequirement": "singleFactorAuthentication",
  "authenticationMethodsUsed": ["Password"],
  "tokenIssuerName": "",
  "tokenIssuerType": "AzureAD",
  "processingTimeInMilliseconds": 143,
  "riskDetail": "none",
  "riskLevelAggregated": "low",
  "riskLevelDuringSignIn": "low",
  "riskState": "atRisk",
  "riskEventTypes_v2": ["suspiciousIPAddress"],
  "resourceDisplayName": "Office 365 Exchange Online",
  "resourceId": "00000002-0000-0ff1-ce00-000000000000",
  "resourceTenantId": "7c1e5b9a-3f4d-4e2a-9b8c-2d6f0a1e4b37",
  "homeTenantId": "7c1e5b9a-3f4d-4e2a-9b8c-2d6f0a1e4b37",
  "homeTenantName": "",
  "signInIdentifier": "yossi.mizrahi@nexacorp.com",
  "signInIdentifierType": "userPrincipalName",
  "servicePrincipalId": "",
  "sessionId": "",
  "uniqueTokenIdentifier": "ApxL9cWq9EKzR2gT3fYmAA",
  "crossTenantAccessType": "none",
  "flaggedForReview": false,
  "isTenantRestricted": false,
  "status": {
    "errorCode": 53003,
    "failureReason": "Access has been blocked by Conditional Access policies. The access policy does not allow token issuance.",
    "additionalDetails": null
  },
  "deviceDetail": {
    "deviceId": "",
    "displayName": "",
    "operatingSystem": "Android",
    "browser": "",
    "isCompliant": false,
    "isManaged": false,
    "trustType": ""
  },
  "location": {
    "city": "Frankfurt am Main",
    "state": "Hessen",
    "countryOrRegion": "DE",
    "geoCoordinates": { "altitude": null, "latitude": 50.11552, "longitude": 8.68417 }
  },
  "appliedConditionalAccessPolicies": [
    {
      "id": "8e4a1c7f-0b9d-4d36-a2e5-5f3c9b1d7e40",
      "displayName": "Block legacy authentication",
      "enforcedGrantControls": ["Block"],
      "enforcedSessionControls": [],
      "result": "failure",
      "conditionsSatisfied": "application,users,clientType",
      "conditionsNotSatisfied": "none",
      "includeRulesSatisfied": [],
      "excludeRulesSatisfied": []
    }
  ],
  "authenticationProcessingDetails": [],
  "networkLocationDetails": [],
  "authenticationDetails": [
    {
      "authenticationStepDateTime": "2026-09-30T04:11:02Z",
      "authenticationMethod": "Password",
      "authenticationMethodDetail": "Password in the cloud",
      "succeeded": true,
      "authenticationStepResultDetail": "Correct password",
      "authenticationStepRequirement": "Primary authentication"
    }
  ],
  "authenticationRequirementPolicies": [],
  "sessionLifetimePolicies": []
}
```
*The teaching point: CA blocked the session, but `authenticationDetails[0].succeeded: true` proves the attacker has a **valid password**. Reset it.*

### 4.6 "Impossible travel" — offline detection raises aggregated risk only

```json
{
  "id": "8b2e6f04-c9d3-4a71-9e58-3f0b7d2a6c00",
  "createdDateTime": "2026-09-30T06:48:15Z",
  "userDisplayName": "Noa Ben-David",
  "userPrincipalName": "noa.bendavid@nexacorp.com",
  "userId": "c6d0f2a8-7b4e-4c19-93a5-e8f1b2d7c064",
  "userType": "member",
  "appId": "4765445b-32c6-49b0-83e6-1d93765276ca",
  "appDisplayName": "OfficeHome",
  "ipAddress": "192.0.2.77",
  "autonomousSystemNumber": 37148,
  "clientAppUsed": "Browser",
  "userAgent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.4 Safari/605.1.15",
  "correlationId": "f2c9a5e7-1d84-4b30-b6f2-9e7a3c0d5b18",
  "originalRequestId": "8b2e6f04-c9d3-4a71-9e58-3f0b7d2a6c00",
  "conditionalAccessStatus": "success",
  "isInteractive": true,
  "signInEventTypes": ["interactiveUser"],
  "authenticationProtocol": "oAuth2",
  "incomingTokenType": "none",
  "authenticationRequirement": "multiFactorAuthentication",
  "authenticationMethodsUsed": ["Password"],
  "tokenIssuerName": "",
  "tokenIssuerType": "AzureAD",
  "processingTimeInMilliseconds": 188,
  "riskDetail": "none",
  "riskLevelAggregated": "high",
  "riskLevelDuringSignIn": "none",
  "riskState": "atRisk",
  "riskEventTypes_v2": ["unlikelyTravel"],
  "resourceDisplayName": "OfficeHome",
  "resourceId": "4765445b-32c6-49b0-83e6-1d93765276ca",
  "resourceTenantId": "7c1e5b9a-3f4d-4e2a-9b8c-2d6f0a1e4b37",
  "homeTenantId": "7c1e5b9a-3f4d-4e2a-9b8c-2d6f0a1e4b37",
  "homeTenantName": "",
  "signInIdentifier": "noa.bendavid@nexacorp.com",
  "signInIdentifierType": "userPrincipalName",
  "servicePrincipalId": "",
  "sessionId": "0d7f4b2c-e8a1-4c63-9f05-a6b3d8e1c270",
  "uniqueTokenIdentifier": "zXo4T2rS9U6m0yP1Lw8fAA",
  "crossTenantAccessType": "none",
  "flaggedForReview": false,
  "isTenantRestricted": false,
  "status": { "errorCode": 0, "failureReason": "Other.", "additionalDetails": "MFA requirement satisfied by claim in the token" },
  "deviceDetail": {
    "deviceId": "",
    "displayName": "",
    "operatingSystem": "MacOs",
    "browser": "Safari 18.4",
    "isCompliant": false,
    "isManaged": false,
    "trustType": ""
  },
  "location": {
    "city": "Lagos",
    "state": "Lagos",
    "countryOrRegion": "NG",
    "geoCoordinates": { "altitude": null, "latitude": 6.45407, "longitude": 3.39467 }
  },
  "appliedConditionalAccessPolicies": [
    {
      "id": "5c1e8a3d-9f42-4b07-8d6e-2a7f0c4b9e15",
      "displayName": "Require MFA - All users",
      "enforcedGrantControls": ["Mfa"],
      "enforcedSessionControls": [],
      "result": "success",
      "conditionsSatisfied": "application,users",
      "conditionsNotSatisfied": "none",
      "includeRulesSatisfied": [],
      "excludeRulesSatisfied": []
    }
  ],
  "authenticationProcessingDetails": [],
  "networkLocationDetails": [],
  "authenticationDetails": [
    {
      "authenticationStepDateTime": "2026-09-30T06:48:15Z",
      "authenticationMethod": "Password",
      "authenticationMethodDetail": "Password in the cloud",
      "succeeded": true,
      "authenticationStepResultDetail": "Correct password",
      "authenticationStepRequirement": "Primary authentication"
    },
    {
      "authenticationStepDateTime": "2026-09-30T06:48:15Z",
      "authenticationMethod": "Previously satisfied",
      "authenticationMethodDetail": null,
      "succeeded": true,
      "authenticationStepResultDetail": "MFA requirement satisfied by claim in the token",
      "authenticationStepRequirement": "Multifactor authentication"
    }
  ],
  "authenticationRequirementPolicies": [],
  "sessionLifetimePolicies": []
}
```
*`unlikelyTravel` is computed offline. Note `riskLevelDuringSignIn: "none"` vs `riskLevelAggregated: "high"`. The previous sign-in for this user (not shown) came from Tel Aviv, IL, 40 minutes earlier.*

### 4.7 Audit — new MFA method registered by the attacker (User registered security info)

```json
{
  "id": "AuthMethods_7d1c4e9a-2b6f-4a83-9c05-e8f3b1a7d264_K7Q2P",
  "category": "UserManagement",
  "correlationId": "6be2d1f9-35c8-4a07-8e4d-b19f0c7a2e53",
  "result": "success",
  "resultReason": "User registered Authenticator App with Notification and Code",
  "activityDisplayName": "User registered security info",
  "activityDateTime": "2026-09-30T03:09:12.5512374Z",
  "loggedByService": "Authentication Methods",
  "operationType": "Add",
  "initiatedBy": {
    "app": null,
    "user": {
      "id": "4f2b8c1d-9e3a-4b7f-8c2d-1a5e6f7b8c9d",
      "displayName": null,
      "userPrincipalName": "dana.levi@nexacorp.com",
      "ipAddress": "198.51.100.23"
    }
  },
  "targetResources": [
    {
      "id": "4f2b8c1d-9e3a-4b7f-8c2d-1a5e6f7b8c9d",
      "displayName": "Dana Levi",
      "type": "User",
      "userPrincipalName": "dana.levi@nexacorp.com",
      "groupType": null,
      "modifiedProperties": []
    }
  ],
  "additionalDetails": []
}
```
*Usually accompanied by a Core Directory `Update user` whose `modifiedProperties` include `StrongAuthenticationMethod` / `StrongAuthenticationPhoneAppDetail` with old/new JSON-encoded values (UNVERIFIED exact property names). The `id` prefix format and the `resultReason` wording are UNVERIFIED.*

### 4.8 Audit — admin role assignment (Add member to role → Global Administrator)

```json
{
  "id": "Directory_3f8b2d61-a7c4-4e09-b5d1-c6e0f9a2b738_PX4LT_172993105",
  "category": "RoleManagement",
  "correlationId": "c4e17a2b-9d3f-4806-a5b2-7e1f0c8d3a69",
  "result": "success",
  "resultReason": "",
  "activityDisplayName": "Add member to role",
  "activityDateTime": "2026-09-30T03:21:47.0835210Z",
  "loggedByService": "Core Directory",
  "operationType": "Assign",
  "initiatedBy": {
    "app": null,
    "user": {
      "id": "4f2b8c1d-9e3a-4b7f-8c2d-1a5e6f7b8c9d",
      "displayName": null,
      "userPrincipalName": "dana.levi@nexacorp.com",
      "ipAddress": "198.51.100.23"
    }
  },
  "targetResources": [
    {
      "id": "e2b9c4f7-1a6d-4038-9e5b-d7a3f0c812e4",
      "displayName": null,
      "type": "User",
      "userPrincipalName": "svc-o365sync@nexacorp.com",
      "groupType": null,
      "modifiedProperties": [
        { "displayName": "Role.ObjectID", "oldValue": null, "newValue": "\"a4d7c2e9-5b81-4f36-8c0a-3e9b1d6f7a25\"" },
        { "displayName": "Role.DisplayName", "oldValue": null, "newValue": "\"Global Administrator\"" },
        { "displayName": "Role.TemplateId", "oldValue": null, "newValue": "\"62e90394-69f5-4237-9190-012177145e10\"" },
        { "displayName": "Role.WellKnownObjectName", "oldValue": null, "newValue": "\"TenantAdmins\"" }
      ]
    }
  ],
  "additionalDetails": []
}
```
*`62e90394-69f5-4237-9190-012177145e10` is the real built-in Global Administrator template id. With PIM, the activity is `Add member to role completed (PIM activation)` / `Add member to role in PIM completed (permanent)`, logged by service `PIM`.*

### 4.9 Audit — illicit OAuth consent grant (Consent to application)

```json
{
  "id": "Directory_0a5d9e3c-6f12-4b87-a4c9-2e7b1f8d0c53_9WMRA_172993482",
  "category": "ApplicationManagement",
  "correlationId": "1b7e3f9a-c2d5-4a60-8e14-f9a0b6c3d278",
  "result": "success",
  "resultReason": "",
  "activityDisplayName": "Consent to application",
  "activityDateTime": "2026-09-30T08:02:33.6610482Z",
  "loggedByService": "Core Directory",
  "operationType": "Assign",
  "initiatedBy": {
    "app": null,
    "user": {
      "id": "c6d0f2a8-7b4e-4c19-93a5-e8f1b2d7c064",
      "displayName": null,
      "userPrincipalName": "noa.bendavid@nexacorp.com",
      "ipAddress": "192.0.2.77"
    }
  },
  "targetResources": [
    {
      "id": "7f3a1e8c-4d29-4b65-b0c7-9e2d5a8f1b36",
      "displayName": "MailSafe Archiver",
      "type": "ServicePrincipal",
      "userPrincipalName": null,
      "groupType": null,
      "modifiedProperties": [
        { "displayName": "ConsentContext.IsAdminConsent", "oldValue": null, "newValue": "\"False\"" },
        { "displayName": "ConsentContext.IsAppOnly", "oldValue": null, "newValue": "\"False\"" },
        { "displayName": "ConsentContext.OnBehalfOfAll", "oldValue": null, "newValue": "\"False\"" },
        { "displayName": "ConsentContext.Tags", "oldValue": null, "newValue": "\"WindowsAzureActiveDirectoryIntegratedApp\"" },
        { "displayName": "ConsentAction.Permissions", "oldValue": null, "newValue": "\"[] => [[Id: 6O8vGqNJ2kuaYnQ8sR5Xr4ZPqC7nRLRNlQfKkl3bT5k, ClientId: 7f3a1e8c-4d29-4b65-b0c7-9e2d5a8f1b36, PrincipalId: c6d0f2a8-7b4e-4c19-93a5-e8f1b2d7c064, ResourceId: 2d4c8b1e-9f73-4a06-b5e2-c1a7d9f3e840, ConsentType: Principal, Scope: Mail.Read Mail.Send offline_access User.Read, CreatedDateTime: , LastModifiedDateTime ]]; \"" },
        { "displayName": "TargetId.ServicePrincipalNames", "oldValue": null, "newValue": "\"b8e5d2a9-3c71-4f04-9a6e-0d4f7c2b1e93\"" }
      ]
    }
  ],
  "additionalDetails": [
    { "key": "User-Agent", "value": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.4 Safari/605.1.15" },
    { "key": "AppId", "value": "b8e5d2a9-3c71-4f04-9a6e-0d4f7c2b1e93" }
  ]
}
```
*The `ConsentAction.Permissions` string format is UNVERIFIED letter-for-letter, but the property names are the ones Microsoft's illicit-consent guidance tells analysts to read. `offline_access` + `Mail.Read` granted by a non-admin to an unverified multi-tenant app is the classic illicit-consent pattern.*

### 4.10 Audit — backdoor secret on a service principal (Add service principal credentials)

```json
{
  "id": "Directory_8c2f6a1d-e4b9-4c73-a058-1d7e3b9f2c46_TZ8NB_172994010",
  "category": "ApplicationManagement",
  "correlationId": "9e4b0d7c-2a3f-4815-b6c9-e1f8a5d2c037",
  "result": "success",
  "resultReason": "",
  "activityDisplayName": "Add service principal credentials",
  "activityDateTime": "2026-09-30T03:34:05.2290117Z",
  "loggedByService": "Core Directory",
  "operationType": "Update",
  "initiatedBy": {
    "app": null,
    "user": {
      "id": "e2b9c4f7-1a6d-4038-9e5b-d7a3f0c812e4",
      "displayName": null,
      "userPrincipalName": "svc-o365sync@nexacorp.com",
      "ipAddress": "198.51.100.23"
    }
  },
  "targetResources": [
    {
      "id": "3d9a7e2f-5c14-4b80-a6d3-8f0e1c7b4a59",
      "displayName": "Nexa-Payroll-Connector",
      "type": "ServicePrincipal",
      "userPrincipalName": null,
      "groupType": null,
      "modifiedProperties": [
        { "displayName": "KeyDescription", "oldValue": "[]", "newValue": "[\"[KeyIdentifier=5b8e2c1f-7a4d-4e96-b03c-d1f9a6e8c274,KeyType=Password,KeyUsage=Verify,DisplayName=sync-2026]\"]" },
        { "displayName": "Included Updated Properties", "oldValue": null, "newValue": "\"KeyDescription\"" },
        { "displayName": "TargetId.ServicePrincipalNames", "oldValue": null, "newValue": "\"f1c7a3e9-2d58-4b06-9e4a-7c0b5d8f3e12\"" }
      ]
    }
  ],
  "additionalDetails": [
    { "key": "User-Agent", "value": "python-requests/2.32.3" }
  ]
}
```
*Follow-up: service-principal sign-ins (`signInEventTypes: ["servicePrincipal"]`, `clientCredentialType: "clientSecret"`, `servicePrincipalCredentialKeyId: "5b8e2c1f-…"`) from new IPs. `KeyDescription` string formatting is UNVERIFIED letter-for-letter.*

---

## 5. Investigation notes (pivots)

- **`sessionId`** is the strongest sign-in pivot. Every interactive and non-interactive token refresh from a stolen session carries the same value, so the same `sessionId` appearing from two countries means token theft/replay (AiTM).
- **`correlationId`** groups the sign-in records of one authentication flow (password step, MFA interrupt, final success). In audits it groups the sub-operations of one admin action. Microsoft explicitly warns that seeing the same `correlationId` in different logs does not guarantee a join.
- **`uniqueTokenIdentifier`** joins a sign-in to the M365 Unified Audit Log / Graph activity events that used the issued token.
- **IP pivot:** `ipAddress` + `autonomousSystemNumber` (sign-in) ↔ `initiatedBy.user.ipAddress` (audit). Many failing UPNs from one IP = spray. One UPN from many IPs = brute force/stuffing.
- **Attack chain to teach:** 50126 spray → 0 success (single factor) → 500121 ×N → 0 success MFA → audit `User registered security info` → `Add member to role` → `Add service principal credentials` / `Consent to application`.
- **Risk fields:** compare `riskLevelDuringSignIn` (real time) with `riskLevelAggregated` (offline). `riskState` changes over time when an admin remediates.
- **Legacy auth:** `clientAppUsed` outside {`Browser`, `Mobile Apps and Desktop clients`} combined with `authenticationProtocol: "ropc"`. A valid password + CA block still needs a password reset.
- **MFA interrupt vs. attack:** 50074/50076 are normal interrupts that precede success. 500121 repeated 3+ times within minutes from a new IP = fatigue.
- **Device-code phishing:** `authenticationProtocol: "deviceCode"` for a user who never uses device code.

---

## 6. Common mistakes / non-existent fields / Graph vs Azure Monitor

**Do NOT use these (they are not in the native Graph object):**
- `resultType`, `resultDescription`, `resultSignature`, `callerIpAddress`, `durationMs`, `identity`, `Level`, `category: "SignInLogs"`, `operationName: "Sign-in activity"`, `properties{}`. These belong to the Azure Monitor envelope.
- `UserPrincipalName`, `ResultType`, `LocationDetails`, `ConditionalAccessPolicies`, `AuthenticationDetails` (PascalCase). These are Log Analytics columns.
- `data.office365.*`, `azure.signinlogs.*`, `source.ip`, `user.name`. These are SIEM normalisations.
- `mfaDetail` (deprecated, returns `null`) and `riskEventTypes` without `_v2` (deprecated).
- `location.country` or `location.countryCode`. The real key is `location.countryOrRegion`.
- `status.code` / `status.reason`. The real keys are `status.errorCode` / `status.failureReason`.
- `deviceDetail.os`. The real key is `deviceDetail.operatingSystem`.
- On audits: `actor`, `target`, `operation`, `ipAddress` at top level. Use `initiatedBy.user.ipAddress`, `targetResources[]`, `activityDisplayName`.
- Don't emit `errorCode` as a string in Graph. It is an int. (In the Azure Monitor envelope `resultType` *is* a string.)

**Graph vs Azure Monitor diagnostic form (for reference only — the platform uses Graph):**

| Aspect | Graph (`/beta/auditLogs/signIns`) | Azure Monitor export record |
|---|---|---|
| Top level | The signIn object itself | Envelope + `properties` = signIn-like object |
| Time | `createdDateTime` `"2026-09-30T02:14:07Z"` | `time` `"2026-09-30T02:14:07.1234567Z"` plus `properties.createdDateTime` (may carry a local offset) |
| Result | `status.errorCode` (int) | `resultType` (string, `"50126"`) + `resultDescription` + `properties.status` |
| IP | `ipAddress` | `callerIpAddress` + `properties.ipAddress` |
| Category | `signInEventTypes[]` | `category`: `SignInLogs`, `NonInteractiveUserSignInLogs`, `ServicePrincipalSignInLogs`, `ManagedIdentitySignInLogs` |
| Other | — | `resourceId: "/tenants/<tid>/providers/Microsoft.aadiam"`, `operationVersion: "1.0"`, `identity: <display name>`, `Level: "4"`, `location: "<CC>"` |
| Audit | directoryAudit object | Envelope with `operationName` = activity, `level: "Informational"`, `properties` = directoryAudit |

Minimal Azure Monitor shape, so the generator can recognise and avoid it:
```json
{ "time": "2026-09-30T02:14:07.1834410Z", "resourceId": "/tenants/7c1e5b9a-3f4d-4e2a-9b8c-2d6f0a1e4b37/providers/Microsoft.aadiam", "operationName": "Sign-in activity", "operationVersion": "1.0", "category": "SignInLogs", "tenantId": "7c1e5b9a-3f4d-4e2a-9b8c-2d6f0a1e4b37", "resultType": "50126", "resultSignature": "None", "resultDescription": "Error validating credentials due to invalid username or password.", "durationMs": 0, "callerIpAddress": "203.0.113.47", "correlationId": "e7a19c42-5b3d-4c8e-a1f6-0d2b9e4c7a31", "identity": "Dana Levi", "Level": "4", "location": "NL", "properties": { "id": "b3f6a2c1-7d4e-4f8a-9c2b-5e1d3a7f0c00", "userPrincipalName": "dana.levi@nexacorp.com", "status": { "errorCode": 50126 } } }
```
