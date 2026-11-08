# SIEM ingestion: Microsoft Graph Security alerts (alerts_v2 through the Wazuh Microsoft Graph module)

Category: product detections in the SIEM · Vendor: Microsoft, Wazuh · Card status: researched 2026-11-07

A SOC that runs on Microsoft ingests the alerts of Defender, Entra ID Protection, Purview and Sentinel into its SIEM through the
**Microsoft Graph Security API** (`GET /security/alerts_v2`). This card is the one record on the platform that is shown **as the
SIEM indexes it**, with the `data.ms-graph.*` shape, because the integration is the source: the analyst reads the SIEM's copy of the
alert, not a product log. Every other card stays native (README rule). Only the Wazuh `data` block, `decoder` and `timestamp` are
kept. `rule`, `agent` and `manager` are left out: the feed row already shows the platform's own rule level and id, and a second set
would contradict it.

---

## 1. Official / primary sources consulted

| URL | What it confirmed |
|---|---|
| https://learn.microsoft.com/en-us/graph/api/resources/security-alert?view=graph-rest-1.0 | Every `alert` property and type, the enums `alertClassification`, `alertDetermination`, `alertSeverity`, `investigationState`. `title` is the alert name (there is no `displayName`). `category` is deprecated in favour of `categories` |
| https://learn.microsoft.com/en-us/graph/api/security-list-alerts_v2?view=graph-rest-1.0 | Example responses: id shape `da<18 digits>_<signed int>`, `providerAlertId` equal to `id`, URL shape with `?tid=`, `serviceSource` / `detectionSource` pairs `microsoftDefenderForEndpoint` / `antivirus` and `microsoftSentinel` / `scheduledAlerts`, `$filter` on severity, status, serviceSource, classification, determination, assignedTo and dates |
| https://learn.microsoft.com/en-us/graph/api/resources/enums-security?view=graph-rest-1.0 | `alertStatus`: unknown, new, inProgress, resolved, unknownFutureValue. `serviceSource` members, including `microsoftSentinel` and `microsoftDefenderForCloud` |
| https://learn.microsoft.com/en-us/graph/api/resources/security-detectionsource?view=graph-rest-1.0 | `detectionSource` members, including `cloudAppSecurity`, `azureAdIdentityProtection`, `microsoftDataLossPrevention`, `scheduledAlerts`, `nrtAlerts`, `builtInMl`, `microsoftInsiderRiskManagement` |
| https://learn.microsoft.com/en-us/graph/api/resources/security-alertevidence?view=graph-rest-1.0 | Base evidence properties, `evidenceVerdict` (unknown, suspicious, malicious, noThreatsFound), `evidenceRole`, `evidenceRemediationStatus`, the list of derived types |
| security-deviceevidence, -userevidence, -processevidence, -fileevidence, -ipevidence, -urlevidence, -mailboxevidence, -analyzedmessageevidence, -useraccount, -filedetails, -loggedonuser, -emailsender (same path) | The evidence fields used here |
| https://documentation.wazuh.com/current/cloud-security/azure/ms-graph-api-setup.html | The indexed alert: `data.integration: "ms-graph"`, the record under `data.ms-graph`, `resource: "security"`, `relationship: "alerts_v2"`, `decoder.name: "json-msgraph"`. The MDO pair `microsoftDefenderForOffice365` / `microsoftDefenderForOffice365` |
| https://documentation.wazuh.com/current/user-manual/reference/ossec-conf/ms-graph-module.html | `resource` / `relationship` configuration, `alerts_v2` under `security` |
| github.com/wazuh/wazuh, tag v4.14.0: `ruleset/rules/0995-microsoft-graph_rules.xml`, `src/wazuh_modules/wm_ms_graph.c` | The module adds `resource` and `relationship` to the record and `integration` next to it. Rule ids 99500-99658. Rules match on `ms-graph.status`, `severity`, `category`, `classification`, `determination` |

---

## 2. Native format and delivery path

1. A Microsoft product raises an alert. Microsoft 365 Defender stores it and Graph serves it at `/security/alerts_v2`.
2. The Wazuh `<ms-graph>` module polls `resource` `security`, `relationship` `alerts_v2`, and sends one JSON message per alert:
   `{"integration":"ms-graph","ms-graph":{ <alert>, "resource":"security", "relationship":"alerts_v2" }}`.
3. The `json-msgraph` decoder indexes it. Fields are `data.integration` and `data.ms-graph.*`.

---

## 3. Fields

`status`, `classification`, `determination`: on a fresh alert `new`, `unknown`, `unknown`. Later values come from analysts. The API has no critical severity: `high` is the top.

`incidentId`: a real alert shares this with the other alerts of its incident. **On this platform it is per alert**, because a shared
value would group an attack's alerts in a way benign alerts never are.

`evidence[].verdict`: `unknown` (no verdict determined). `roles` is empty, or `source` / `destination` on an IP: both state direction, never a conclusion.

### serviceSource and detectionSource by product

| Product | serviceSource | detectionSource | Source |
|---|---|---|---|
| Defender for Endpoint, behaviour | `microsoftDefenderForEndpoint` | `microsoftDefenderForEndpoint` | serviceSource enum, detectionSource enum |
| Defender for Endpoint, antivirus | `microsoftDefenderForEndpoint` | `antivirus` | Graph list example |
| Entra ID Protection | `azureAdIdentityProtection` | `azureAdIdentityProtection` | both enums |
| Defender for Office 365 | `microsoftDefenderForOffice365` | `microsoftDefenderForOffice365` | Wazuh sample |
| Defender for Cloud Apps | `microsoftDefenderForCloudApps` | `cloudAppSecurity` | both enums |
| Defender for Identity | `microsoftDefenderForIdentity` | `microsoftDefenderForIdentity` | both enums |
| Purview DLP | `dataLossPrevention` | `microsoftDataLossPrevention` | both enums |
| XDR (the platform's own console), analytics rule | `unknown` | `scheduledAlerts` | detectionSource enum; XDR is not a Microsoft service, so serviceSource has no member for it (2026-11-08: the console is XDR, not Sentinel) |
| XDR, threat intelligence match | `unknown` | `microsoftDefenderThreatIntelligenceAnalytics` | detectionSource enum |
| XDR, UEBA / anomaly | `unknown` | `builtInMl` | detectionSource enum |
| Defender for Cloud | `microsoftDefenderForCloud` | `microsoftDefenderForCloud` | both enums |
| Microsoft 365 Defender correlation | `microsoft365Defender` | `microsoft365Defender` | both enums |
| Insider Risk Management | `unknown` | `microsoftInsiderRiskManagement` | detectionSource enum; **serviceSource has no member for it** |

**UNVERIFIED:** the pairing of the two enums for a product is confirmed only where the Source column names a sample. `productName` is documented as a string with no value list; the module uses each product's display name. `id` uses the `da` form of the Graph examples for every product (the Wazuh sample masks its ids).

---

## 4. Samples

### 4.1 Defender for Endpoint, behaviour: process and file evidence

```json
{
  "timestamp": "2026-05-06T04:45:09.469+0000",
  "decoder": {
    "name": "json-msgraph"
  },
  "data": {
    "integration": "ms-graph",
    "ms-graph": {
      "@odata.type": "#microsoft.graph.security.alert",
      "id": "da947717355964494974_-1266211055",
      "providerAlertId": "da947717355964494974_-1266211055",
      "incidentId": "56022508",
      "status": "new",
      "severity": "high",
      "classification": "unknown",
      "determination": "unknown",
      "serviceSource": "microsoftDefenderForEndpoint",
      "detectionSource": "microsoftDefenderForEndpoint",
      "productName": "Microsoft Defender for Endpoint",
      "detectorId": "c654855d-b846-4265-bddb-fd1d706ac9d6",
      "tenantId": "74155343-f751-4c49-b96d-3af1878a608c",
      "title": "Suspicious credential access activity",
      "description": "Microsoft Defender for Endpoint raised this alert on activity recorded on the device.",
      "recommendedActions": "Review the device timeline around the alert time and the process tree of the activity. Decide from those records whether the activity was expected.",
      "category": "CredentialAccess",
      "categories": [
        "CredentialAccess"
      ],
      "assignedTo": null,
      "alertWebUrl": "https://security.microsoft.com/alerts/da947717355964494974_-1266211055?tid=74155343-f751-4c49-b96d-3af1878a608c",
      "incidentWebUrl": "https://security.microsoft.com/incidents/56022508?tid=74155343-f751-4c49-b96d-3af1878a608c",
      "actorDisplayName": null,
      "threatDisplayName": null,
      "threatFamilyName": null,
      "resource": "security",
      "relationship": "alerts_v2",
      "mitreTechniques": [
        "T1003.001"
      ],
      "createdDateTime": "2026-05-06T04:45:06.1938997Z",
      "lastUpdateDateTime": "2026-05-06T04:45:06.5282994Z",
      "resolvedDateTime": null,
      "firstActivityDateTime": "2026-05-06T04:45:05.000Z",
      "lastActivityDateTime": "2026-05-06T04:45:05.000Z",
      "alertPolicyId": null,
      "investigationState": "unknown",
      "additionalData": {},
      "customDetails": {},
      "comments": [],
      "evidence": [
        {
          "@odata.type": "#microsoft.graph.security.deviceEvidence",
          "createdDateTime": "2026-05-06T04:45:06.1938997Z",
          "verdict": "unknown",
          "remediationStatus": "none",
          "remediationStatusDetails": null,
          "roles": [],
          "detailedRoles": [],
          "tags": [],
          "mdeDeviceId": "af1100fc7a340576677a5e45d069d10f86928356",
          "azureAdDeviceId": "7197f06e-c3be-49ec-95d9-a61214e3f594",
          "deviceDnsName": "WS-FIN-1193.nexacorp.com",
          "hostName": "WS-FIN-1193",
          "ntDomain": "NEXACORP",
          "dnsDomain": "nexacorp.com",
          "osPlatform": "Windows11",
          "healthStatus": "active",
          "riskScore": "high",
          "onboardingStatus": "onboarded",
          "defenderAvStatus": "updated",
          "ipInterfaces": [
            "10.10.20.33"
          ],
          "loggedOnUsers": [
            {
              "accountName": "c.martin",
              "domainName": "NEXACORP"
            }
          ]
        },
        {
          "@odata.type": "#microsoft.graph.security.userEvidence",
          "createdDateTime": "2026-05-06T04:45:06.1938997Z",
          "verdict": "unknown",
          "remediationStatus": "none",
          "remediationStatusDetails": null,
          "roles": [],
          "detailedRoles": [],
          "tags": [],
          "userAccount": {
            "accountName": "c.martin",
            "domainName": "NEXACORP",
            "userSid": "S-1-5-21-3421479547-3897544621-1789562108-9538",
            "azureAdUserId": "6556e60a-a6a8-4e64-946b-5b8fc6e75f38",
            "userPrincipalName": "c.martin@nexacorp.com",
            "displayName": "C Martin"
          }
        },
        {
          "@odata.type": "#microsoft.graph.security.processEvidence",
          "createdDateTime": "2026-05-06T04:45:06.1938997Z",
          "verdict": "unknown",
          "remediationStatus": "none",
          "remediationStatusDetails": null,
          "roles": [],
          "detailedRoles": [],
          "tags": [],
          "detectionStatus": "detected",
          "mdeDeviceId": "af1100fc7a340576677a5e45d069d10f86928356",
          "processId": 19856,
          "parentProcessId": 13888,
          "processCommandLine": "rundll32.exe C:\\Windows\\System32\\comsvcs.dll MiniDump 704 C:\\Windows\\Temp\\mem.dmp full",
          "processCreationDateTime": "2026-05-06T04:45:04.9996590Z",
          "parentProcessCreationDateTime": null,
          "imageFile": {
            "sha1": "6d7c14f5f8ab3a7725c9f952802610dfc20a9b77",
            "sha256": "14d02f0841bb5ddefff4503c9b9fcfbcb7c38b70aab103d985c7de87ceaa279b",
            "md5": "2e48eece533525cd5c8eb6e821d51c6a",
            "fileName": "rundll32.exe",
            "filePath": "C:\\Windows\\System32",
            "fileSize": null,
            "filePublisher": null,
            "signer": null,
            "issuer": null
          },
          "parentProcessImageFile": {
            "sha1": "b031c344549ce55b7ce195bdd749b464c58bf0e0",
            "sha256": "098a080ccdf2b1cf779482b81d2d678f68db1e9aa7efaad286038c1ac1e2c8d4",
            "md5": "d6887bf7f2d93f1c187bb39457abad6d",
            "fileName": "powershell.exe",
            "filePath": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0",
            "fileSize": null,
            "filePublisher": null,
            "signer": null,
            "issuer": null
          },
          "userAccount": {
            "accountName": "c.martin",
            "domainName": "NEXACORP",
            "userSid": "S-1-5-21-3421479547-3897544621-1789562108-9538",
            "azureAdUserId": "6556e60a-a6a8-4e64-946b-5b8fc6e75f38",
            "userPrincipalName": "c.martin@nexacorp.com",
            "displayName": "C Martin"
          }
        },
        {
          "@odata.type": "#microsoft.graph.security.fileEvidence",
          "createdDateTime": "2026-05-06T04:45:06.1938997Z",
          "verdict": "unknown",
          "remediationStatus": "none",
          "remediationStatusDetails": null,
          "roles": [],
          "detailedRoles": [],
          "tags": [],
          "detectionStatus": "detected",
          "mdeDeviceId": "af1100fc7a340576677a5e45d069d10f86928356",
          "fileDetails": {
            "sha1": "16e30e80313a24114385f764d4af96159b3ed42c",
            "sha256": null,
            "md5": null,
            "fileName": "mem.dmp",
            "filePath": "C:\\Windows\\Temp",
            "fileSize": null,
            "filePublisher": null,
            "signer": null,
            "issuer": null
          }
        },
        {
          "@odata.type": "#microsoft.graph.security.ipEvidence",
          "createdDateTime": "2026-05-06T04:45:06.1938997Z",
          "verdict": "unknown",
          "remediationStatus": "none",
          "remediationStatusDetails": null,
          "roles": [
            "source"
          ],
          "detailedRoles": [],
          "tags": [],
          "ipAddress": "10.10.20.33",
          "countryLetterCode": null
        }
      ],
      "systemTags": []
    }
  }
}
```

### 4.2 Defender for Endpoint, antivirus

```json
{
  "timestamp": "2026-03-11T14:27:29.636+0000",
  "decoder": {
    "name": "json-msgraph"
  },
  "data": {
    "integration": "ms-graph",
    "ms-graph": {
      "@odata.type": "#microsoft.graph.security.alert",
      "id": "da425299395442077014_-888629015",
      "providerAlertId": "da425299395442077014_-888629015",
      "incidentId": "307417",
      "status": "new",
      "severity": "high",
      "classification": "unknown",
      "determination": "unknown",
      "serviceSource": "microsoftDefenderForEndpoint",
      "detectionSource": "antivirus",
      "productName": "Microsoft Defender for Endpoint",
      "detectorId": "f1d8cf30-05cc-41eb-a15f-f8487be35206",
      "tenantId": "74155343-f751-4c49-b96d-3af1878a608c",
      "title": "'Rhadesta' malware was prevented",
      "description": "Microsoft Defender for Endpoint raised this alert on activity recorded on the device.",
      "recommendedActions": "Review the device timeline around the alert time and the process tree of the activity. Decide from those records whether the activity was expected.",
      "category": "CredentialAccess",
      "categories": [
        "CredentialAccess"
      ],
      "assignedTo": null,
      "alertWebUrl": "https://security.microsoft.com/alerts/da425299395442077014_-888629015?tid=74155343-f751-4c49-b96d-3af1878a608c",
      "incidentWebUrl": "https://security.microsoft.com/incidents/307417?tid=74155343-f751-4c49-b96d-3af1878a608c",
      "actorDisplayName": null,
      "threatDisplayName": "Trojan:Win32/Rhadesta.SP!MTB",
      "threatFamilyName": "Rhadesta",
      "resource": "security",
      "relationship": "alerts_v2",
      "mitreTechniques": [
        "T1555.003"
      ],
      "createdDateTime": "2026-03-11T14:27:24.5774989Z",
      "lastUpdateDateTime": "2026-03-11T14:27:24.9739946Z",
      "resolvedDateTime": null,
      "firstActivityDateTime": "2026-03-11T14:27:19.000Z",
      "lastActivityDateTime": "2026-03-11T14:27:19.000Z",
      "alertPolicyId": null,
      "investigationState": "unknown",
      "additionalData": {},
      "customDetails": {},
      "comments": [],
      "evidence": [
        {
          "@odata.type": "#microsoft.graph.security.deviceEvidence",
          "createdDateTime": "2026-03-11T14:27:24.5774989Z",
          "verdict": "unknown",
          "remediationStatus": "none",
          "remediationStatusDetails": null,
          "roles": [],
          "detailedRoles": [],
          "tags": [],
          "mdeDeviceId": "f63b27e22c3b835e8af8b271fd3fb025d7e33517",
          "azureAdDeviceId": "2c43ea4a-360d-471c-b9d9-23f9d5534988",
          "deviceDnsName": "LAP-3312.nexacorp.com",
          "hostName": "LAP-3312",
          "ntDomain": "NEXACORP",
          "dnsDomain": "nexacorp.com",
          "osPlatform": "Windows11",
          "healthStatus": "active",
          "riskScore": "high",
          "onboardingStatus": "onboarded",
          "defenderAvStatus": "updated",
          "ipInterfaces": [
            "10.14.19.63"
          ],
          "loggedOnUsers": [
            {
              "accountName": "d.avraham",
              "domainName": "NEXACORP"
            }
          ]
        },
        {
          "@odata.type": "#microsoft.graph.security.userEvidence",
          "createdDateTime": "2026-03-11T14:27:24.5774989Z",
          "verdict": "unknown",
          "remediationStatus": "none",
          "remediationStatusDetails": null,
          "roles": [],
          "detailedRoles": [],
          "tags": [],
          "userAccount": {
            "accountName": "d.avraham",
            "domainName": "NEXACORP",
            "userSid": "S-1-5-21-3421479547-3897544621-1789562108-1751",
            "azureAdUserId": "964577e3-1599-4ac4-8661-b4ecabd5fd50",
            "userPrincipalName": "d.avraham@nexacorp.com",
            "displayName": "D Avraham"
          }
        },
        {
          "@odata.type": "#microsoft.graph.security.processEvidence",
          "createdDateTime": "2026-03-11T14:27:24.5774989Z",
          "verdict": "unknown",
          "remediationStatus": "none",
          "remediationStatusDetails": null,
          "roles": [],
          "detailedRoles": [],
          "tags": [],
          "detectionStatus": "blocked",
          "mdeDeviceId": "f63b27e22c3b835e8af8b271fd3fb025d7e33517",
          "processId": 5160,
          "parentProcessId": 5948,
          "processCommandLine": "upd_helper.exe",
          "processCreationDateTime": "2026-03-11T14:27:18.9992006Z",
          "parentProcessCreationDateTime": null,
          "imageFile": {
            "sha1": "6c3292cbb8930034f7e22fd79935465936de8720",
            "sha256": "ef7d081857063d90d0e8ce72d0181d62b8936deebd21d458d79c8224b5594ea8",
            "md5": "2b7592a1fc1cba97805591790d6ccfe0",
            "fileName": "upd_helper.exe",
            "filePath": "C:\\Users\\d.avraham\\AppData\\Local\\Temp\\sysdata",
            "fileSize": null,
            "filePublisher": null,
            "signer": null,
            "issuer": null
          },
          "parentProcessImageFile": {
            "sha1": "f0366dddecd94afb6e4777f30332999c78ce638f",
            "sha256": null,
            "md5": null,
            "fileName": "PuTTY-0.83-installer.exe",
            "filePath": null,
            "fileSize": null,
            "filePublisher": null,
            "signer": null,
            "issuer": null
          },
          "userAccount": {
            "accountName": "d.avraham",
            "domainName": "NEXACORP",
            "userSid": "S-1-5-21-3421479547-3897544621-1789562108-1751",
            "azureAdUserId": "964577e3-1599-4ac4-8661-b4ecabd5fd50",
            "userPrincipalName": "d.avraham@nexacorp.com",
            "displayName": "D Avraham"
          }
        },
        {
          "@odata.type": "#microsoft.graph.security.ipEvidence",
          "createdDateTime": "2026-03-11T14:27:24.5774989Z",
          "verdict": "unknown",
          "remediationStatus": "none",
          "remediationStatusDetails": null,
          "roles": [
            "source"
          ],
          "detailedRoles": [],
          "tags": [],
          "ipAddress": "10.14.19.63",
          "countryLetterCode": null
        }
      ],
      "systemTags": []
    }
  }
}
```

### 4.3 Entra ID Protection

```json
{
  "timestamp": "2026-05-12T07:06:10.419+0000",
  "decoder": {
    "name": "json-msgraph"
  },
  "data": {
    "integration": "ms-graph",
    "ms-graph": {
      "@odata.type": "#microsoft.graph.security.alert",
      "id": "da109738616160071473_-1204189794",
      "providerAlertId": "da109738616160071473_-1204189794",
      "incidentId": "72642691",
      "status": "new",
      "severity": "high",
      "classification": "unknown",
      "determination": "unknown",
      "serviceSource": "azureAdIdentityProtection",
      "detectionSource": "azureAdIdentityProtection",
      "productName": "Microsoft Entra ID Protection",
      "detectorId": "8356cdcb-21ef-42f2-91e4-fb24da256a9d",
      "tenantId": "74155343-f751-4c49-b96d-3af1878a608c",
      "title": "Valid Accounts",
      "description": "Microsoft Entra ID Protection raised this alert on sign-in or account activity.",
      "recommendedActions": "Review the user's sign-ins and directory changes around the alert time. Confirm with the user whether the activity was theirs.",
      "category": "InitialAccess",
      "categories": [
        "InitialAccess"
      ],
      "assignedTo": null,
      "alertWebUrl": "https://security.microsoft.com/alerts/da109738616160071473_-1204189794?tid=74155343-f751-4c49-b96d-3af1878a608c",
      "incidentWebUrl": "https://security.microsoft.com/incidents/72642691?tid=74155343-f751-4c49-b96d-3af1878a608c",
      "actorDisplayName": null,
      "threatDisplayName": null,
      "threatFamilyName": null,
      "resource": "security",
      "relationship": "alerts_v2",
      "mitreTechniques": [
        "T1078"
      ],
      "createdDateTime": "2026-05-12T07:06:01.7932688Z",
      "lastUpdateDateTime": "2026-05-12T07:06:02.6814623Z",
      "resolvedDateTime": null,
      "firstActivityDateTime": "2026-05-12T07:06:00.000Z",
      "lastActivityDateTime": "2026-05-12T07:06:00.000Z",
      "alertPolicyId": null,
      "investigationState": "unknown",
      "additionalData": {},
      "customDetails": {},
      "comments": [],
      "evidence": [
        {
          "@odata.type": "#microsoft.graph.security.userEvidence",
          "createdDateTime": "2026-05-12T07:06:01.7932688Z",
          "verdict": "unknown",
          "remediationStatus": "none",
          "remediationStatusDetails": null,
          "roles": [],
          "detailedRoles": [],
          "tags": [],
          "userAccount": {
            "accountName": "k.taylor",
            "domainName": "NEXACORP",
            "userSid": "S-1-5-21-3421479547-3897544621-1789562108-6382",
            "azureAdUserId": "2c57e44b-9c42-48da-bd56-54f546382565",
            "userPrincipalName": "k.taylor@nexacorp.com",
            "displayName": "K Taylor"
          }
        },
        {
          "@odata.type": "#microsoft.graph.security.ipEvidence",
          "createdDateTime": "2026-05-12T07:06:01.7932688Z",
          "verdict": "unknown",
          "remediationStatus": "none",
          "remediationStatusDetails": null,
          "roles": [
            "source"
          ],
          "detailedRoles": [],
          "tags": [],
          "ipAddress": "203.0.113.9",
          "countryLetterCode": null
        }
      ],
      "systemTags": []
    }
  }
}
```

### 4.4 Defender for Office 365: mailbox and message evidence

```json
{
  "timestamp": "2026-05-10T08:38:09.825+0000",
  "decoder": {
    "name": "json-msgraph"
  },
  "data": {
    "integration": "ms-graph",
    "ms-graph": {
      "@odata.type": "#microsoft.graph.security.alert",
      "id": "da137956488188289345_-2075971922",
      "providerAlertId": "da137956488188289345_-2075971922",
      "incidentId": "93690956",
      "status": "new",
      "severity": "high",
      "classification": "unknown",
      "determination": "unknown",
      "serviceSource": "microsoftDefenderForOffice365",
      "detectionSource": "microsoftDefenderForOffice365",
      "productName": "Microsoft Defender for Office 365",
      "detectorId": "ce0666b9-808b-4f9d-854b-201f681f3f4c",
      "tenantId": "45ffe58f-f287-400c-a151-2a096f15c38c",
      "title": "Phishing: Spearphishing Attachment",
      "description": "Microsoft Defender for Office 365 raised this alert on a message or a click.",
      "recommendedActions": "Review the message, its sender and its URLs, and who else received it.",
      "category": "InitialAccess",
      "categories": [
        "InitialAccess"
      ],
      "assignedTo": null,
      "alertWebUrl": "https://security.microsoft.com/alerts/da137956488188289345_-2075971922?tid=45ffe58f-f287-400c-a151-2a096f15c38c",
      "incidentWebUrl": "https://security.microsoft.com/incidents/93690956?tid=45ffe58f-f287-400c-a151-2a096f15c38c",
      "actorDisplayName": null,
      "threatDisplayName": null,
      "threatFamilyName": null,
      "resource": "security",
      "relationship": "alerts_v2",
      "mitreTechniques": [
        "T1566.001"
      ],
      "createdDateTime": "2026-05-10T08:38:03.0814272Z",
      "lastUpdateDateTime": "2026-05-10T08:38:03.4604399Z",
      "resolvedDateTime": null,
      "firstActivityDateTime": "2026-05-10T08:38:00.000Z",
      "lastActivityDateTime": "2026-05-10T08:38:00.000Z",
      "alertPolicyId": null,
      "investigationState": "unknown",
      "additionalData": {},
      "customDetails": {},
      "comments": [],
      "evidence": [
        {
          "@odata.type": "#microsoft.graph.security.userEvidence",
          "createdDateTime": "2026-05-10T08:38:03.0814272Z",
          "verdict": "unknown",
          "remediationStatus": "none",
          "remediationStatusDetails": null,
          "roles": [],
          "detailedRoles": [],
          "tags": [],
          "userAccount": {
            "accountName": "dr.vandijk",
            "domainName": "MEDCORE",
            "userSid": "S-1-5-21-2669053813-3193093880-2203159228-4030",
            "azureAdUserId": "39aca3bc-32d7-4e89-b140-5e639f909ad3",
            "userPrincipalName": "dr.vandijk@medcorehealth.org",
            "displayName": "Dr Vandijk"
          }
        },
        {
          "@odata.type": "#microsoft.graph.security.mailboxEvidence",
          "createdDateTime": "2026-05-10T08:38:03.0814272Z",
          "verdict": "unknown",
          "remediationStatus": "none",
          "remediationStatusDetails": null,
          "roles": [],
          "detailedRoles": [],
          "tags": [],
          "displayName": "Dr Vandijk",
          "primaryAddress": "dr.vandijk@medcorehealth.org",
          "upn": "dr.vandijk@medcorehealth.org",
          "userAccount": {
            "accountName": "dr.vandijk",
            "domainName": "MEDCORE",
            "userSid": "S-1-5-21-2669053813-3193093880-2203159228-4030",
            "azureAdUserId": "39aca3bc-32d7-4e89-b140-5e639f909ad3",
            "userPrincipalName": "dr.vandijk@medcorehealth.org",
            "displayName": "Dr Vandijk"
          }
        },
        {
          "@odata.type": "#microsoft.graph.security.urlEvidence",
          "createdDateTime": "2026-05-10T08:38:03.0814272Z",
          "verdict": "unknown",
          "remediationStatus": "none",
          "remediationStatusDetails": null,
          "roles": [],
          "detailedRoles": [],
          "tags": [],
          "url": "medconference2026.example"
        },
        {
          "@odata.type": "#microsoft.graph.security.analyzedMessageEvidence",
          "createdDateTime": "2026-05-10T08:38:03.0814272Z",
          "verdict": "unknown",
          "remediationStatus": "none",
          "remediationStatusDetails": null,
          "roles": [],
          "detailedRoles": [],
          "tags": [],
          "networkMessageId": "ddc0ddea-3508-440e-a0ad-08dce5f1c953",
          "internetMessageId": "<20260510083800.B92035852E@medconference2026.example>",
          "subject": "MedConf2026 Programme Schedule",
          "language": "en",
          "senderIp": "198.51.100.55",
          "recipientEmailAddress": "dr.vandijk@medcorehealth.org",
          "antiSpamDirection": "inbound",
          "deliveryAction": "delivered",
          "deliveryLocation": "inbox",
          "urn": null,
          "threats": [],
          "threatDetectionMethods": [],
          "urls": [],
          "urlCount": 0,
          "attachmentsCount": 0,
          "receivedDateTime": "2026-05-10T08:38:00.0002258Z",
          "p1Sender": {
            "emailAddress": "agenda@medconference2026.example",
            "displayName": null,
            "domainName": "medconference2026.example"
          },
          "p2Sender": {
            "emailAddress": "agenda@medconference2026.example",
            "displayName": null,
            "domainName": "medconference2026.example"
          }
        }
      ],
      "systemTags": []
    }
  }
}
```

### 4.5 Purview DLP

```json
{
  "timestamp": "2026-05-06T13:25:06.619+0000",
  "decoder": {
    "name": "json-msgraph"
  },
  "data": {
    "integration": "ms-graph",
    "ms-graph": {
      "@odata.type": "#microsoft.graph.security.alert",
      "id": "da528996149478663292_47957263",
      "providerAlertId": "da528996149478663292_47957263",
      "incidentId": "50294304",
      "status": "new",
      "severity": "high",
      "classification": "unknown",
      "determination": "unknown",
      "serviceSource": "dataLossPrevention",
      "detectionSource": "microsoftDataLossPrevention",
      "productName": "Microsoft Purview Data Loss Prevention",
      "detectorId": "d00fcf56-4943-47c6-9193-40a7060d63ad",
      "tenantId": "74155343-f751-4c49-b96d-3af1878a608c",
      "title": "DLP policy (Finance-PII-Bulk-Download) matched",
      "description": "A Microsoft Purview Data Loss Prevention policy matched this activity.",
      "recommendedActions": "Review the policy match, the content and the destination. Confirm whether the transfer had a business reason.",
      "category": "Collection",
      "categories": [
        "Collection"
      ],
      "assignedTo": null,
      "alertWebUrl": "https://security.microsoft.com/alerts/da528996149478663292_47957263?tid=74155343-f751-4c49-b96d-3af1878a608c",
      "incidentWebUrl": "https://security.microsoft.com/incidents/50294304?tid=74155343-f751-4c49-b96d-3af1878a608c",
      "actorDisplayName": null,
      "threatDisplayName": null,
      "threatFamilyName": null,
      "resource": "security",
      "relationship": "alerts_v2",
      "mitreTechniques": [
        "T1213.002"
      ],
      "createdDateTime": "2026-05-06T13:25:04.5632799Z",
      "lastUpdateDateTime": "2026-05-06T13:25:05.1991436Z",
      "resolvedDateTime": null,
      "firstActivityDateTime": "2026-05-06T13:25:00.000Z",
      "lastActivityDateTime": "2026-05-06T13:25:00.000Z",
      "alertPolicyId": null,
      "investigationState": "unknown",
      "additionalData": {},
      "customDetails": {},
      "comments": [],
      "evidence": [
        {
          "@odata.type": "#microsoft.graph.security.userEvidence",
          "createdDateTime": "2026-05-06T13:25:04.5632799Z",
          "verdict": "unknown",
          "remediationStatus": "none",
          "remediationStatusDetails": null,
          "roles": [],
          "detailedRoles": [],
          "tags": [],
          "userAccount": {
            "accountName": "m.torres",
            "domainName": "NEXACORP",
            "userSid": "S-1-5-21-3421479547-3897544621-1789562108-7775",
            "azureAdUserId": "57cda247-3c4a-46f7-afdd-eef308454184",
            "userPrincipalName": "m.torres@nexacorp.com",
            "displayName": "M Torres"
          }
        },
        {
          "@odata.type": "#microsoft.graph.security.ipEvidence",
          "createdDateTime": "2026-05-06T13:25:04.5632799Z",
          "verdict": "unknown",
          "remediationStatus": "none",
          "remediationStatusDetails": null,
          "roles": [
            "source"
          ],
          "detailedRoles": [],
          "tags": [],
          "ipAddress": "10.10.20.91",
          "countryLetterCode": null
        }
      ],
      "systemTags": []
    }
  }
}
```

### 4.6 Sentinel analytics rule

```json
{
  "timestamp": "2026-06-03T22:29:37.282+0000",
  "decoder": {
    "name": "json-msgraph"
  },
  "data": {
    "integration": "ms-graph",
    "ms-graph": {
      "@odata.type": "#microsoft.graph.security.alert",
      "id": "da926058578909280959_1345019692",
      "providerAlertId": "da926058578909280959_1345019692",
      "incidentId": "8901076",
      "status": "new",
      "severity": "high",
      "classification": "unknown",
      "determination": "unknown",
      "serviceSource": "microsoftSentinel",
      "detectionSource": "scheduledAlerts",
      "productName": "Microsoft Sentinel",
      "detectorId": "70a2565f-6660-4ade-ab70-994b71647afb",
      "tenantId": "74155343-f751-4c49-b96d-3af1878a608c",
      "title": "Kerberos service ticket requested without a prior TGT",
      "description": "A Microsoft Sentinel analytics rule raised this alert.",
      "recommendedActions": "Review the events the rule matched and the entities they name.",
      "category": "CredentialAccess",
      "categories": [
        "CredentialAccess"
      ],
      "assignedTo": null,
      "alertWebUrl": "https://security.microsoft.com/alerts/da926058578909280959_1345019692?tid=74155343-f751-4c49-b96d-3af1878a608c",
      "incidentWebUrl": "https://security.microsoft.com/incidents/8901076?tid=74155343-f751-4c49-b96d-3af1878a608c",
      "actorDisplayName": null,
      "threatDisplayName": null,
      "threatFamilyName": null,
      "resource": "security",
      "relationship": "alerts_v2",
      "mitreTechniques": [
        "T1558.001"
      ],
      "createdDateTime": "2026-06-03T22:29:35.1399562Z",
      "lastUpdateDateTime": "2026-06-03T22:29:35.4211673Z",
      "resolvedDateTime": null,
      "firstActivityDateTime": "2026-06-03T22:29:30.000Z",
      "lastActivityDateTime": "2026-06-03T22:29:30.000Z",
      "alertPolicyId": null,
      "investigationState": "unknown",
      "additionalData": {},
      "customDetails": {},
      "comments": [],
      "evidence": [
        {
          "@odata.type": "#microsoft.graph.security.deviceEvidence",
          "createdDateTime": "2026-06-03T22:29:35.1399562Z",
          "verdict": "unknown",
          "remediationStatus": "none",
          "remediationStatusDetails": null,
          "roles": [],
          "detailedRoles": [],
          "tags": [],
          "mdeDeviceId": "b1ca28f39a172ca20df26c1bcbdc70bc6d0d00c3",
          "azureAdDeviceId": "aafe1c10-cad3-4e64-98cc-a2c65ec4f5ab",
          "deviceDnsName": "SRV-NEXACORP-DC01.nexacorp.com",
          "hostName": "SRV-NEXACORP-DC01",
          "ntDomain": "NEXACORP",
          "dnsDomain": "nexacorp.com",
          "osPlatform": "WindowsServer2022",
          "healthStatus": "active",
          "riskScore": "high",
          "onboardingStatus": "onboarded",
          "defenderAvStatus": "updated",
          "ipInterfaces": [],
          "loggedOnUsers": [
            {
              "accountName": "it.admin",
              "domainName": "NEXACORP"
            }
          ]
        },
        {
          "@odata.type": "#microsoft.graph.security.userEvidence",
          "createdDateTime": "2026-06-03T22:29:35.1399562Z",
          "verdict": "unknown",
          "remediationStatus": "none",
          "remediationStatusDetails": null,
          "roles": [],
          "detailedRoles": [],
          "tags": [],
          "userAccount": {
            "accountName": "it.admin",
            "domainName": "NEXACORP",
            "userSid": "S-1-5-21-3421479547-3897544621-1789562108-1287",
            "azureAdUserId": "f23edb9d-3a57-4432-bdbc-2866aa2b00c5",
            "userPrincipalName": "it.admin@nexacorp.com",
            "displayName": "It Admin"
          }
        }
      ],
      "systemTags": []
    }
  }
}
```

---

## 5. Investigation notes

- The alert is the start of triage. Open the raw logs of its evidence: the Graph record says what a product saw, the logs say what happened.
- Pivot from `evidence[]`: `hostName` to the device's logs, `userAccount.userPrincipalName` to its sign-ins, `ipAddress` and `url` to threat intelligence, `sha256` to the file.
- `detectionSource` tells the technology: `antivirus` is a signature or file verdict, `microsoftDefenderForEndpoint` is behaviour.
- `detectionStatus` on process and file evidence says what the product did: `detected` means it may still have run.

---

## 6. Common mistakes

- `data.ms-graph.displayName` does not exist on `alerts_v2`: the name is `title`. `displayName` belongs to the `incident` resource.
- `lastModifiedBy`, `customTags` and `resource: "user:..."` are not alert properties. `resource` is the module's own field and holds the API resource: `security`. `relationship` holds `alerts_v2`, not a link between alerts.
- `severity` has no `critical`. `status` has no `redirected` on `alerts_v2`.
- `classification` has no `benignPositive` here: the member is `informationalExpectedActivity`.
- `determination` members are `compromisedAccount`, `confirmedActivity` and `securityPersonnel`, not `compromisedUser` or `confirmedUserActivity`.
- `comments` is a collection of `alertComment` objects, not strings. `systemTags` is a string collection, not a semicolon list.
- The decoder is `json-msgraph`, not `json`. Rule ids are in 99500-99658.
