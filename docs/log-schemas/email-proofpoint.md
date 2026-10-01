# Proofpoint TAP — SIEM API v2 (native schema card)

Category: Email security · Vendor: Proofpoint · Endpoints: `/v2/siem/messages/delivered`, `/messages/blocked`, `/clicks/permitted`, `/clicks/blocked`, `/issues`, `/all`
Rule reminder: each log is ONE message event or ONE click event exactly as it appears inside the SIEM API JSON
response arrays. No Elastic `proofpoint_tap.*` flattening, no Sentinel `ProofPointTAPMessagesDelivered_CL` `_s`/`_d`/`_t`
columns (where arrays become escaped strings), no Wazuh `data.*`.

---

## 1. Official sources

| URL | What it confirmed |
|---|---|
| https://help.proofpoint.com/Threat_Insight_Dashboard/API_Documentation/SIEM_API | Endpoints; query params (`interval` ISO 8601 range, `sinceSeconds`, `sinceTime` — mutually exclusive; `format=json|syslog`; `threatType=url|attachment|messageText`; `threatStatus=active|cleared|falsePositive`); response keys `queryEndTime`, `messagesDelivered`, `messagesBlocked`, `clicksPermitted`, `clicksBlocked`; message fields (GUID, QID, ccAddresses, cluster, completelyRewritten, fromAddress, headerFrom, headerReplyTo, impostorScore, malwareScore, messageID, messageParts[], messageSize, messageTime, modulesRun, phishScore, policyRoutes, quarantineFolder, quarantineRule, recipient, replyToAddress, sender, senderIP, spamScore, subject, threatsInfoMap[], toAddresses, xmailer); messageParts (contentType, oContentType, disposition `inline|attached`, filename, md5, sha256, sandboxStatus `unsupported|threat|clean|prefilter|uploaded|inprogress|uploaddisabled`); threatsInfoMap (campaignId, classification, threat, threatID, threatStatus, threatTime, threatType, threatUrl, actors); click fields (campaignId, classification, clickIP, clickTime, GUID, id, messageID, recipient, sender, senderIP, threatID, threatTime, threatURL, threatStatus, url, userAgent); classification set includes Malware, Phish, Spam, Impostor, TOAD; syslog variant (RFC 5424, event types MSGDLV/MSGBLK/CLKPER/CLKBLK, SD-ID `tapmsg@21139`/`tapclk@21139`). |
| https://github.com/elastic/integrations/tree/main/packages/proofpoint_tap/data_stream (`_dev/test/pipeline/*.log`) | Real wire values (2022): `cluster` key (not `clusterId`), `fromAddress` as **array**, `completelyRewritten` as **boolean**, `classification` and `threatType` **lower-case** (`malware`, `phish`, `url`), `campaignID` (capital ID) inside `threatsInfoMap`, `id` (UUID) present on message events, `impostorScore` may be float `0.0`, `quarantineFolder`/`quarantineRule`/`headerReplyTo` `null` when unused, click `campaignId` + `threatURL`. |
| https://github.com/Azure/Azure-Sentinel/tree/master/Sample%20Data/Custom (`ProofPointTAP*_CL_sample_data.json`) | Same lower-case values from 2020 data (`"classification": "phish"`, `"threatType": "url"`), `threatUrl` format `https://threatinsight.proofpoint.com/<org-uuid>/threat/email/<threatID>`, 64-hex `threatID`, QID like `03I5YVvs004766`, GUID 32-char token, `modulesRun` values (`access`, `dkim`, `smtpsrv`, `av`, `zerohour`, `spf`, `dkimv`, `sandbox`, `spam`, `dmarc`, `pdr`, `urldefense`), `policyRoutes` (`default_inbound`, `pp_spoofsafe`). |

Doc-vs-wire differences are resolved in favour of **what the API actually returns** (observed in two independent vendor-integration fixtures) and flagged below.

---

## 2. Native format & delivery

- **Transport**: `GET https://tap-api-v2.proofpoint.com/v2/siem/all?format=json&sinceSeconds=3600` with HTTP Basic (service principal + secret). Max window 1 hour per call, data retained 7 days.
- **Response envelope** (always all four arrays, possibly empty):
  ```json
  { "queryEndTime": "2026-09-29T08:00:00Z", "messagesDelivered": [], "messagesBlocked": [], "clicksPermitted": [], "clicksBlocked": [] }
  ```
- **We standardise on**: one element of one of the four arrays = one log. The array it came from is the event kind
  (show it as the log's source label, e.g. "TAP · messagesDelivered"); do **not** inject an `eventType` field into the object.
- Timestamps: ISO 8601 UTC, observed with milliseconds `2026-09-29T07:12:03.000Z` (docs also show second precision `...Z`).
- Message events: `recipient`, `toAddresses`, `ccAddresses`, `fromAddress`, `replyToAddress`, `modulesRun`, `policyRoutes`, `messageParts`, `threatsInfoMap` are **arrays**. Click events: `recipient` is a **string**.

---

## 3. Core field reference

### 3.1 Message event (`messagesDelivered`, `messagesBlocked`)

| Field | Type | Notes |
|---|---|---|
| `GUID` | string | Unique message id inside Proofpoint (PPS). **Primary key; links to clicks.** |
| `QID` | string | Sendmail queue id on the PPS node — not unique across time/cluster. |
| `id` | string (UUID) | Event id (observed; not in the doc table). |
| `cluster` | string | PPS cluster name, e.g. `nexacorp_hosted`. Doc table calls it `clusterId` — wire key observed is `cluster`. |
| `messageID` | string | RFC 5322 `Message-ID` header incl. `<>`. |
| `messageTime` | string ISO 8601 | when PPS processed it |
| `sender` | string | SMTP envelope sender (doc: user-part may be hashed; fixtures show clear-text) |
| `senderIP` | string | connecting IP |
| `fromAddress` | string[] | address(es) in From header (doc table says string; wire = array) |
| `headerFrom` | string | full From header incl. display name: `"\"DocuSign\" <dse@docusign-esign.net>"` |
| `headerReplyTo` | string \| null | full Reply-To |
| `replyToAddress` | string[] | |
| `recipient` | string[] | envelope recipients |
| `toAddresses`, `ccAddresses` | string[] | header recipients |
| `subject` | string | |
| `messageSize` | int | bytes |
| `xmailer` | string \| null | X-Mailer header |
| `spamScore`, `phishScore`, `malwareScore`, `impostorScore` | int (0–100) | impostor may appear as float `0.0` |
| `completelyRewritten` | boolean | URL Defense rewrote all URLs (doc says string `"true"/"false"/"na"`; wire = boolean) |
| `modulesRun` | string[] | `access`, `av`, `spam`, `spf`, `dkimv`, `dmarc`, `pdr`, `urldefense`, `zerohour`, `sandbox`, `smtpsrv`, `dkim` ... |
| `policyRoutes` | string[] | `default_inbound`, `pp_spoofsafe`, `allow_relay`, `internalnet` ... |
| `quarantineFolder`, `quarantineRule` | string \| null | populated on `messagesBlocked` (e.g. folder `Attachment Defense`, rule `module.sandbox.threat` — value strings UNVERIFIED) |
| `messageParts[]` | object[] | `disposition` (`inline`/`attached`), `filename`, `contentType`, `oContentType`, `md5`, `sha256`, `sandboxStatus` (`threat`, `clean`, `unsupported`, `prefilter`, `uploaded`, `inprogress`, `uploaddisabled`, or `null`) |
| `threatsInfoMap[]` | object[] | see 3.2 |

### 3.2 `threatsInfoMap[]` element

| Field | Type | Values |
|---|---|---|
| `threatID` | string | 64-hex id (capital `ID`) |
| `threat` | string | the indicator: URL, attachment SHA256, or sender/message identifier |
| `threatType` | string | wire: `url`, `attachment`, `message` (doc capitalises: URL/Attachment/Message) |
| `classification` | string | wire: `malware`, `phish`, `spam`, `impostor`, `toad` (doc capitalises) |
| `threatStatus` | string | `active`, `cleared`, `falsePositive` |
| `threatTime` | string ISO 8601 | when Proofpoint convicted the threat (can be AFTER messageTime → retroactive) |
| `threatUrl` | string | TAP dashboard link `https://threatinsight.proofpoint.com/<org-uuid>/threat/email/<threatID>` (lower-case `Url` here) |
| `campaignID` | string \| null | wire key `campaignID` (doc: `campaignId`) |
| `actors` | object[] | optional `{id, name, type}` (doc) — UNVERIFIED on wire |
| `detectionType` | string | optional (doc) — UNVERIFIED on wire |

### 3.3 Click event (`clicksPermitted`, `clicksBlocked`)

| Field | Type | Notes |
|---|---|---|
| `id` | string (UUID) | click id |
| `GUID` | string | GUID of the message that carried the URL → join to message event |
| `messageID` | string | Message-ID header |
| `url` | string | URL the user clicked (original, un-rewritten) |
| `classification` | string | `phish`, `malware`, `spam` (lower-case on wire) |
| `clickTime` | string ISO 8601 | |
| `clickIP` | string | user's external IP |
| `userAgent` | string | |
| `recipient` | string | the clicker's address (single string) |
| `sender`, `senderIP` | string | of the original message |
| `threatID`, `threatStatus`, `threatTime` | string | |
| `threatURL` | string | dashboard link (capital `URL` in click events) |
| `campaignId` | string \| null | (lower-case `Id` in click events) |

---

## 4. Realistic samples (fictitious org `nexacorp.com`, cluster `nexacorp_hosted`)

Story A: credential-phish URL delivered (URL convicted 20 min after delivery), one user's click permitted, another's blocked.
Story B: malicious HTML attachment blocked by Attachment Defense sandbox.
Story C: BEC impostor message delivered.

### P1 — messagesDelivered: phish URL, retroactively convicted (Story A)
```json
{
  "GUID": "hT3kQ9vX2mB7wL4pZ8nR1cF6yJ0sD5aE",
  "QID": "48TA7cKq014233",
  "id": "b4e1c7a9-3d2f-4b86-9e05-1a7c3f9d2e64",
  "cluster": "nexacorp_hosted",
  "messageID": "<20260929071158.9F2C41A07B@mta3.docusign-esign.net>",
  "messageTime": "2026-09-29T07:12:03.000Z",
  "sender": "bounce-7731@docusign-esign.net",
  "senderIP": "203.0.113.45",
  "fromAddress": ["dse@docusign-esign.net"],
  "headerFrom": "\"DocuSign via Finance\" <dse@docusign-esign.net>",
  "headerReplyTo": null,
  "replyToAddress": [],
  "recipient": ["dana.levi@nexacorp.com", "itai.bar@nexacorp.com"],
  "toAddresses": ["dana.levi@nexacorp.com", "itai.bar@nexacorp.com"],
  "ccAddresses": [],
  "subject": "Please review and sign: Q3 Vendor Payment Authorization",
  "messageSize": 38214,
  "xmailer": null,
  "spamScore": 12,
  "phishScore": 46,
  "malwareScore": 0,
  "impostorScore": 0.0,
  "completelyRewritten": true,
  "modulesRun": ["access", "av", "zerohour", "spf", "dkimv", "spam", "dmarc", "pdr", "urldefense"],
  "policyRoutes": ["default_inbound"],
  "quarantineFolder": null,
  "quarantineRule": null,
  "messageParts": [
    {
      "disposition": "inline",
      "filename": "text.txt",
      "contentType": "text/plain",
      "oContentType": "text/plain",
      "md5": "5d41c3a9e7b1f2d4c6a8e0b2d4f6a8c0",
      "sha256": "9a3c5e7b1d2f4a6c8e0b2d4f6a8c1e3b5d7f9a2c4e6b8d0f1a3c5e7b9d2f4a61",
      "sandboxStatus": null
    },
    {
      "disposition": "inline",
      "filename": "text.html",
      "contentType": "text/html",
      "oContentType": "text/html",
      "md5": "e8b2d4f6a1c3e5b7d9f0a2c4e6b8d1f3",
      "sha256": "2f4a6c8e0b1d3f5a7c9e2b4d6f8a1c3e5b7d9f0a2c4e6b8d1f3a5c7e9b2d4f68",
      "sandboxStatus": null
    }
  ],
  "threatsInfoMap": [
    {
      "threatID": "7c2e9a4f1b3d5c8e0a2f4b6d8c1e3a5f7b9d2c4e6a8f0b1d3c5e7a9f2b4d6c81",
      "threat": "https://docusign-esign.net/envelope/review?id=Q3-VPA-88231",
      "threatType": "url",
      "classification": "phish",
      "threatStatus": "active",
      "threatTime": "2026-09-29T07:31:40.000Z",
      "threatUrl": "https://threatinsight.proofpoint.com/5a8e2c1f-7d3b-4e96-a0c4-9f1b3d7e5a28/threat/email/7c2e9a4f1b3d5c8e0a2f4b6d8c1e3a5f7b9d2c4e6a8f0b1d3c5e7a9f2b4d6c81",
      "campaignID": null
    }
  ]
}
```

### P2 — clicksPermitted: Dana clicks before conviction propagated (Story A)
```json
{
  "id": "3f8a1c6e-2b9d-4e57-a0c3-7d1f5b9e2a46",
  "GUID": "hT3kQ9vX2mB7wL4pZ8nR1cF6yJ0sD5aE",
  "messageID": "<20260929071158.9F2C41A07B@mta3.docusign-esign.net>",
  "url": "https://docusign-esign.net/envelope/review?id=Q3-VPA-88231",
  "classification": "phish",
  "clickTime": "2026-09-29T07:29:12.000Z",
  "clickIP": "198.51.100.24",
  "userAgent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36 Edg/128.0.0.0",
  "recipient": "dana.levi@nexacorp.com",
  "sender": "bounce-7731@docusign-esign.net",
  "senderIP": "203.0.113.45",
  "threatID": "7c2e9a4f1b3d5c8e0a2f4b6d8c1e3a5f7b9d2c4e6a8f0b1d3c5e7a9f2b4d6c81",
  "threatStatus": "active",
  "threatTime": "2026-09-29T07:31:40.000Z",
  "threatURL": "https://threatinsight.proofpoint.com/5a8e2c1f-7d3b-4e96-a0c4-9f1b3d7e5a28/threat/email/7c2e9a4f1b3d5c8e0a2f4b6d8c1e3a5f7b9d2c4e6a8f0b1d3c5e7a9f2b4d6c81",
  "campaignId": null
}
```
(`clickTime` < `threatTime`: the click was allowed because the URL was not yet convicted; it is reported as a *permitted* click once convicted. This is the TAP "clicked before we knew" case analysts must chase.)

### P3 — clicksBlocked: Itai clicks after conviction (Story A)
```json
{
  "id": "9b2d7f4a-1e6c-4a83-b5d0-2c8e4a1f7b39",
  "GUID": "hT3kQ9vX2mB7wL4pZ8nR1cF6yJ0sD5aE",
  "messageID": "<20260929071158.9F2C41A07B@mta3.docusign-esign.net>",
  "url": "https://docusign-esign.net/envelope/review?id=Q3-VPA-88231",
  "classification": "phish",
  "clickTime": "2026-09-29T07:48:05.000Z",
  "clickIP": "198.51.100.24",
  "userAgent": "Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Mobile/15E148 Safari/604.1",
  "recipient": "itai.bar@nexacorp.com",
  "sender": "bounce-7731@docusign-esign.net",
  "senderIP": "203.0.113.45",
  "threatID": "7c2e9a4f1b3d5c8e0a2f4b6d8c1e3a5f7b9d2c4e6a8f0b1d3c5e7a9f2b4d6c81",
  "threatStatus": "active",
  "threatTime": "2026-09-29T07:31:40.000Z",
  "threatURL": "https://threatinsight.proofpoint.com/5a8e2c1f-7d3b-4e96-a0c4-9f1b3d7e5a28/threat/email/7c2e9a4f1b3d5c8e0a2f4b6d8c1e3a5f7b9d2c4e6a8f0b1d3c5e7a9f2b4d6c81",
  "campaignId": null
}
```

### P4 — messagesBlocked: HTML-smuggling attachment caught by sandbox (Story B)
```json
{
  "GUID": "Wq6nE2rT8yU4iO0pA7sD3fG9hJ1kL5zX",
  "QID": "48UAb3Rz027811",
  "id": "c7e3a9f1-5b2d-4c68-8e04-3a9d1f7c5b20",
  "cluster": "nexacorp_hosted",
  "messageID": "<CAOq7v2Wk9xR3mT5pL1aZ8nB4dH6jF2sY0uE7cQ9iG3o@mail.gmail.com>",
  "messageTime": "2026-09-30T10:02:14.000Z",
  "sender": "accounts.payable.vendor44@gmail.com",
  "senderIP": "209.85.218.47",
  "fromAddress": ["accounts.payable.vendor44@gmail.com"],
  "headerFrom": "\"Accounts Payable\" <accounts.payable.vendor44@gmail.com>",
  "headerReplyTo": null,
  "replyToAddress": [],
  "recipient": ["yael.cohen@nexacorp.com"],
  "toAddresses": ["yael.cohen@nexacorp.com"],
  "ccAddresses": [],
  "subject": "Remittance advice 30-09-2026",
  "messageSize": 412887,
  "xmailer": null,
  "spamScore": 0,
  "phishScore": 0,
  "malwareScore": 100,
  "impostorScore": 0.0,
  "completelyRewritten": false,
  "modulesRun": ["access", "av", "zerohour", "spf", "dkimv", "spam", "dmarc", "pdr", "sandbox", "urldefense"],
  "policyRoutes": ["default_inbound"],
  "quarantineFolder": "Attachment Defense",
  "quarantineRule": "module.sandbox.threat",
  "messageParts": [
    {
      "disposition": "inline",
      "filename": "text.html",
      "contentType": "text/html",
      "oContentType": "text/html",
      "md5": "1b3d5f7a9c2e4b6d8f0a1c3e5b7d9f2a",
      "sha256": "6d8f0a2c4e1b3d5f7a9c2e4b6d8f1a3c5e7b9d0f2a4c6e8b1d3f5a7c9e2b4d60",
      "sandboxStatus": null
    },
    {
      "disposition": "attached",
      "filename": "Remittance_30092026.html",
      "contentType": "text/html",
      "oContentType": "text/html",
      "md5": "a2c4e6b8d0f1a3c5e7b9d2f4a6c8e0b1",
      "sha256": "4f9a2c7e1b3d5f8a0c2e4b6d8f1a3c5e7b9d2f4a6c8e0b1d3f5a7c9e2b4d6f80",
      "sandboxStatus": "threat"
    }
  ],
  "threatsInfoMap": [
    {
      "threatID": "4f9a2c7e1b3d5f8a0c2e4b6d8f1a3c5e7b9d2f4a6c8e0b1d3f5a7c9e2b4d6f80",
      "threat": "4f9a2c7e1b3d5f8a0c2e4b6d8f1a3c5e7b9d2f4a6c8e0b1d3f5a7c9e2b4d6f80",
      "threatType": "attachment",
      "classification": "malware",
      "threatStatus": "active",
      "threatTime": "2026-09-30T10:03:02.000Z",
      "threatUrl": "https://threatinsight.proofpoint.com/5a8e2c1f-7d3b-4e96-a0c4-9f1b3d7e5a28/threat/email/4f9a2c7e1b3d5f8a0c2e4b6d8f1a3c5e7b9d2f4a6c8e0b1d3f5a7c9e2b4d6f80",
      "campaignID": "e1b7d3f9-6a2c-4e58-b4d0-9c3a7f1e5b62"
    }
  ]
}
```
(For attachment threats `threat` and `threatID` are commonly the attachment SHA256 — UNVERIFIED that they are always equal.)

### P5 — messagesDelivered: BEC impostor (Story C)
```json
{
  "GUID": "Zr4tY8uI2oP6aS0dF4gH8jK2lZ6xC0vB",
  "QID": "48UDf7Wm031904",
  "id": "e2a8c4f1-9d3b-4e75-b6a0-1c7e3f9b5d48",
  "cluster": "nexacorp_hosted",
  "messageID": "<0102019243b7e1a4-8c2f-4d1e-9a7b-3f5e1c9d2b84-000000@eu-west-1.amazonses.com>",
  "messageTime": "2026-09-30T13:47:49.000Z",
  "sender": "0102019243b7e1a4@eu-west-1.amazonses.com",
  "senderIP": "54.240.4.17",
  "fromAddress": ["ronen.shapira.ceo@nexacorp-exec.com"],
  "headerFrom": "\"Ronen Shapira\" <ronen.shapira.ceo@nexacorp-exec.com>",
  "headerReplyTo": "\"Ronen Shapira\" <r.shapira.office@proton.me>",
  "replyToAddress": ["r.shapira.office@proton.me"],
  "recipient": ["yael.cohen@nexacorp.com"],
  "toAddresses": ["yael.cohen@nexacorp.com"],
  "ccAddresses": [],
  "subject": "Urgent - confidential wire today",
  "messageSize": 6120,
  "xmailer": null,
  "spamScore": 0,
  "phishScore": 0,
  "malwareScore": 0,
  "impostorScore": 94.0,
  "completelyRewritten": false,
  "modulesRun": ["access", "av", "zerohour", "spf", "dkimv", "spam", "dmarc", "pdr", "urldefense"],
  "policyRoutes": ["default_inbound"],
  "quarantineFolder": null,
  "quarantineRule": null,
  "messageParts": [
    {
      "disposition": "inline",
      "filename": "text.txt",
      "contentType": "text/plain",
      "oContentType": "text/plain",
      "md5": "c3e5b7d9f1a2c4e6b8d0f2a4c6e8b1d3",
      "sha256": "8b1d3f5a7c9e2b4d6f8a0c2e4b6d9f1a3c5e7b8d0f2a4c6e9b1d3f5a7c8e0b2d",
      "sandboxStatus": null
    }
  ],
  "threatsInfoMap": [
    {
      "threatID": "d5f7a9c2e4b6d8f1a3c5e7b9d0f2a4c6e8b1d3f5a7c9e2b4d6f8a0c2e4b7d9f1",
      "threat": "ronen.shapira.ceo@nexacorp-exec.com",
      "threatType": "message",
      "classification": "impostor",
      "threatStatus": "active",
      "threatTime": "2026-09-30T13:47:50.000Z",
      "threatUrl": "https://threatinsight.proofpoint.com/5a8e2c1f-7d3b-4e96-a0c4-9f1b3d7e5a28/threat/email/d5f7a9c2e4b6d8f1a3c5e7b9d0f2a4c6e8b1d3f5a7c9e2b4d6f8a0c2e4b7d9f1",
      "campaignID": null
    }
  ]
}
```
(Value of `threat` for impostor/message threats is UNVERIFIED — doc only says "SHA256, URL, or email address".)

### P6 — Full `/v2/siem/all` response envelope (abridged to one click to show nesting)
```json
{
  "queryEndTime": "2026-09-29T08:00:00Z",
  "messagesDelivered": [],
  "messagesBlocked": [],
  "clicksPermitted": [
    {
      "id": "3f8a1c6e-2b9d-4e57-a0c3-7d1f5b9e2a46",
      "GUID": "hT3kQ9vX2mB7wL4pZ8nR1cF6yJ0sD5aE",
      "messageID": "<20260929071158.9F2C41A07B@mta3.docusign-esign.net>",
      "url": "https://docusign-esign.net/envelope/review?id=Q3-VPA-88231",
      "classification": "phish",
      "clickTime": "2026-09-29T07:29:12.000Z",
      "clickIP": "198.51.100.24",
      "userAgent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36 Edg/128.0.0.0",
      "recipient": "dana.levi@nexacorp.com",
      "sender": "bounce-7731@docusign-esign.net",
      "senderIP": "203.0.113.45",
      "threatID": "7c2e9a4f1b3d5c8e0a2f4b6d8c1e3a5f7b9d2c4e6a8f0b1d3c5e7a9f2b4d6c81",
      "threatStatus": "active",
      "threatTime": "2026-09-29T07:31:40.000Z",
      "threatURL": "https://threatinsight.proofpoint.com/5a8e2c1f-7d3b-4e96-a0c4-9f1b3d7e5a28/threat/email/7c2e9a4f1b3d5c8e0a2f4b6d8c1e3a5f7b9d2c4e6a8f0b1d3c5e7a9f2b4d6c81",
      "campaignId": null
    }
  ],
  "clicksBlocked": []
}
```

---

## 5. Investigation notes (pivots)

- **GUID** links click events to their message event (`clicksPermitted[].GUID` = `messagesDelivered[].GUID`). `QID` is per-node and recycles — never join on QID alone.
- **threatID** groups every message and click involving the same indicator across users/time; `campaignID`/`campaignId` groups related threats.
- **messageID** (RFC 5322) leaves Proofpoint: join to Defender `InternetMessageId`, M365 UAL `InternetMessageId` (MailItemsAccessed / Item), Gmail `rfc2822_message_id`, mail-server logs.
- **Retroactive conviction**: `threatTime` > `messageTime` means the message was delivered clean and later convicted → pull it (TRAP/CLEAR) and hunt for `clicksPermitted` where `clickTime` < `threatTime`.
- **Clicker identity**: `recipient` + `clickIP` + `userAgent` → identity-provider sign-ins from new IPs right after `clickTime` (credential harvest success).
- **BEC**: `impostorScore` high + `replyToAddress` ≠ `fromAddress` domain + look-alike `headerFrom` display name.
- Scores are per-engine 0–100; a delivered message with `phishScore` 46 is "suspicious, below block threshold" (thresholds are customer policy).

## 6. Common mistakes / fields that do NOT exist

- No `eventType`, `action`, `disposition` (at message level), `verdict`, `severity`, `user`, `src_ip`, `dst` fields. Message vs click vs blocked vs delivered is conveyed by **which array** the object is in.
- No `threatsInfoMap` on click events; no `clickTime`/`url` on message events.
- Case-sensitive keys: `GUID`, `QID`, `messageID`, `senderIP`, `clickIP`, `threatID`, `threatUrl` (inside threatsInfoMap) vs `threatURL` (click events), `campaignID` (threatsInfoMap) vs `campaignId` (click events).
- Message `recipient` is an **array**; click `recipient` is a **string**.
- `classification` values are `phish`/`malware`/`spam`/`impostor`/`toad` — not `phishing`, `credential_phish`, `bec`.
- `threatType` values are `url`/`attachment`/`message` — not `link`, `file`, `body`.
- Do not invent `riskScore`, `deliveryStatus`, `quarantined: true`; quarantine is expressed by the `messagesBlocked` array + `quarantineFolder`/`quarantineRule`.
- Do not render Sentinel's escaped-string arrays (`"recipient_s":"[\r\n \"...\"]"`) as the native shape.
