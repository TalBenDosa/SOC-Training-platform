# Zscaler Private Access (ZPA) — LSS User Activity & User Status logs

Category: ZTNA / remote access. Vendor: Zscaler. Native format: JSON lines streamed by the Log Streaming Service (LSS) (JSON-native).
Platform representation: **the LSS JSON object exactly as emitted** (PascalCase keys, flat).

---

## 1. Official sources

| Source | What it confirmed |
|---|---|
| https://help.zscaler.com/zpa/user-activity-log-fields | Official field list for the User Activity log type (page is JS-rendered; field names cross-checked against the real samples below). |
| https://help.zscaler.com/zpa/user-status-log-fields | Official field list for the User Status log type. |
| https://help.zscaler.com/zpa/understanding-zpa-session-status-codes | Status / internal-reason codes; `BRK_MT_SETUP_FAIL_REJECTED_BY_POLICY` = request blocked by access policy. |
| https://registry.terraform.io/providers/zscaler/zpa/latest/docs/resources/zpa_lss_config_user_activity | LSS config objects: `source_log_type` (`zpn_trans_log` = User Activity, `zpn_auth_log` = User Status, ...), log format template is configurable (JSON/CSV/TSV). |
| https://github.com/elastic/integrations/tree/main/packages/zscaler_zpa/data_stream (`user_activity/_dev/test/pipeline/test-user-activity.log`, `user_status/.../test-user-status.log`) | Real default-JSON-template lines with every key: `LogTimestamp` (`"Fri May 31 17:35:42 2019"`), `Customer`, `SessionID`, `ConnectionID`, `InternalReason`, `ConnectionStatus` (`active`), `IPProtocol`, `DoubleEncryption`, `Username`, `ServicePort`, `ClientPublicIP`, `ClientPrivateIP`, `ClientLatitude/Longitude`, `ClientCountryCode`, `ClientZEN`, `Policy`, `Connector`, `ConnectorZEN`, `ConnectorIP`, `ConnectorPort`, `Host`, `Application`, `AppGroup`, `Server`, `ServerIP`, `ServerPort`, timing and byte counters, `Idp`, `ClientToClient`; User Status: `SessionStatus` (`ZPN_STATUS_AUTHENTICATED`), `Version`, `ZEN`, `CertificateCN`, `PrivateIP`, `PublicIP`, `CountryCode`, `TimestampAuthentication/UnAuthentication`, `TotalBytesRx/Tx`, `Hostname`, `Platform`, `ClientType` (`zpn_client_type_zapp`), `TrustedNetworks`, `SAMLAttributes`, `PosturesHit/Miss`, `FQDNRegistered`. |
| https://github.com/dvmrry/zscaler-skill/blob/main/references/zpa/troubleshooting.md and Google SecOps ZPA parser doc (https://cloud.google.com/chronicle/docs/ingestion/default-parsers/zscaler-zpa) | `ConnectionStatus` values open / active / close; full `InternalReason` catalogue is not public. |

## 2. Native format and delivery

- LSS runs on a customer App Connector and pushes logs over TCP (optionally TLS) to a receiver (SIEM/syslog). Each log type is its own LSS config: **User Activity** (`zpn_trans_log`, one record per application connection), **User Status** (`zpn_auth_log`, one record per Client Connector session), plus App Connector Status, Audit, Browser Access, etc.
- The default JSON template emits one flat JSON object per line. Timestamps: `LogTimestamp` = ctime-style `"Thu Oct  1 05:02:11 2026"` (UTC); `Timestamp*` fields = ISO-8601 UTC with ms and `Z`; empty string when not reached.
- Admins can edit the template (rename/drop keys); we use the **default template key names**.
- User Activity is emitted repeatedly for long connections (`ConnectionStatus` `open` -> `active` (periodic) -> `close`); `ZENBytes*` are deltas since the previous record, `ZENTotalBytes*` are running totals.

## 3. Core field reference

### User Activity (zpn_trans_log)
| Field | Meaning | Values / notes |
|---|---|---|
| `LogTimestamp` | Record time (UTC, ctime format) | `"Thu Oct  1 05:02:15 2026"` |
| `Customer` | Tenant name | |
| `SessionID` | Client Connector session (joins to User Status) | 20-char base64-ish |
| `ConnectionID` | Connection ID(s) | `"<id>,<id>"` |
| `InternalReason` | Internal status/close reason | empty when OK; e.g. `BRK_MT_SETUP_FAIL_REJECTED_BY_POLICY`; other codes (`BRK_MT_CLOSED_FROM_CLIENT`, `BRK_MT_TERMINATED_IDLE_TIMEOUT`, `BRK_MT_SETUP_FAIL_NO_POLICY_FOUND`) UNVERIFIED |
| `ConnectionStatus` | Connection state | `open`, `active`, `close` |
| `IPProtocol` | IANA protocol number | `6`, `17` |
| `DoubleEncryption` | Double encryption on | `0` / `1` |
| `Username` | User (IdP name ID) | `dana.levi@nexacorp.co.il` |
| `ServicePort` | Port the client requested | |
| `ClientPublicIP` / `ClientPrivateIP` | Client's public egress IP / local LAN IP | |
| `ClientLatitude` / `ClientLongitude` / `ClientCountryCode` | Geo of public IP | `IL` |
| `ClientZEN` | Zscaler broker (Public Service Edge) the client used | `broker1b.tlv1` style |
| `Policy` | Access policy rule matched | |
| `Connector` / `ConnectorZEN` / `ConnectorIP` / `ConnectorPort` | App Connector that served the app | |
| `Host` | Requested FQDN/IP | |
| `Application` / `AppGroup` | Application segment / segment group | |
| `Server` / `ServerIP` / `ServerPort` | Resolved server | `Server` = `"0"` for dynamically discovered |
| `PolicyProcessingTime`, `CAProcessingTime`, `ConnectorZENSetupTime`, `ConnectionSetupTime`, `ServerSetupTime`, `AppLearnTime` | Timings (µs) | |
| `TimestampConnectionStart` / `TimestampConnectionEnd` | ISO-8601 | end empty until close |
| `TimestampCATx`, `TimestampCARx`, `TimestampAppLearnStart`, `TimestampZEN*`, `TimestampConnectorZENSetupComplete` | Phase timestamps | |
| `ZENTotalBytesRxClient` / `ZENBytesRxClient` | Bytes broker received from client (upload) total / delta | |
| `ZENTotalBytesTxClient` / `ZENBytesTxClient` | Bytes broker sent to client (download) | |
| `ZENTotalBytesRxConnector` / `...TxConnector` (+ delta variants) | Bytes on the connector side | |
| `Idp` | IdP config name | |
| `ClientToClient` | Client-to-client connection flag | `"0"` |

### User Status (zpn_auth_log)
| Field | Meaning | Values / notes |
|---|---|---|
| `LogTimestamp`, `Customer`, `Username`, `SessionID` | as above | |
| `SessionStatus` | Session state | `ZPN_STATUS_AUTHENTICATED`, `ZPN_STATUS_DISCONNECTED` (latter UNVERIFIED) |
| `Version` | Client Connector version | |
| `ZEN` | Broker | |
| `CertificateCN` | Client certificate CN | |
| `PrivateIP` / `PublicIP` | Client LAN IP / public egress IP | |
| `Latitude` / `Longitude` / `CountryCode` | Geo of `PublicIP` | |
| `TimestampAuthentication` / `TimestampUnAuthentication` | Session start / end (ISO) | |
| `TotalBytesRx` / `TotalBytesTx` | Session byte totals | |
| `Idp` | IdP config | |
| `Hostname` / `Platform` | Device name / `windows`, `mac`, `linux`, `ios`, `android` | |
| `ClientType` | Client type | `zpn_client_type_zapp` (Client Connector), others e.g. `zpn_client_type_browser_isolation` UNVERIFIED |
| `TrustedNetworks` / `TrustedNetworksNames` | Trusted-network detection | |
| `SAMLAttributes` | SAML attributes received | `"key:value,key:value"` |
| `PosturesHit` / `PosturesMiss` | Device-posture profiles passed / failed | comma string (older) or array |
| `ZENLatitude` / `ZENLongitude` / `ZENCountryCode` | Broker geo | |
| `FQDNRegistered` / `FQDNRegisteredError` | Client FQDN registration | |

## 4. Realistic samples

### 4.1 User Status — normal authenticated session from Israel, managed laptop
```json
{"LogTimestamp":"Thu Oct  1 05:02:11 2026","Customer":"NexaCorp Ltd","Username":"dana.levi@nexacorp.co.il","SessionID":"Qm9rZ1hQd2VYcDNaTDFv","SessionStatus":"ZPN_STATUS_AUTHENTICATED","Version":"4.4.0.379","ZEN":"broker2a.tlv1","CertificateCN":"C-7f3e1c2a9b.dana.levi@nexacorp.co.il","PrivateIP":"192.168.1.23","PublicIP":"203.0.113.24","Latitude":32.08,"Longitude":34.78,"CountryCode":"IL","TimestampAuthentication":"2026-10-01T05:02:09.000Z","TimestampUnAuthentication":"","TotalBytesRx":0,"TotalBytesTx":0,"Idp":"NexaCorp-EntraID","Hostname":"NXC-LT-0412","Platform":"windows","ClientType":"zpn_client_type_zapp","TrustedNetworks":"","TrustedNetworksNames":"","SAMLAttributes":"department:Finance,email:dana.levi@nexacorp.co.il","PosturesHit":"CrowdStrike-ZTA,Domain-Joined,Disk-Encrypted","PosturesMiss":"","ZENLatitude":32,"ZENLongitude":34,"ZENCountryCode":"IL","FQDNRegistered":"0","FQDNRegisteredError":"CUSTOMER_NOT_ENABLED"}
```

### 4.2 User Activity — allowed RDP connection to an internal server (close record)
```json
{"LogTimestamp":"Thu Oct  1 06:40:02 2026","Customer":"NexaCorp Ltd","SessionID":"Qm9rZ1hQd2VYcDNaTDFv","ConnectionID":"Uk9rM2xQaUZ0ZzRhQkMx,bXhQcUw4ZDJ0WkFhUjNr","InternalReason":"","ConnectionStatus":"close","IPProtocol":6,"DoubleEncryption":0,"Username":"dana.levi@nexacorp.co.il","ServicePort":3389,"ClientPublicIP":"203.0.113.24","ClientPrivateIP":"192.168.1.23","ClientLatitude":32.080000,"ClientLongitude":34.780000,"ClientCountryCode":"IL","ClientZEN":"broker2a.tlv1","Policy":"Allow-Finance-RDP","Connector":"AC-HQ-DC1-01","ConnectorZEN":"broker2a.tlv1","ConnectorIP":"10.20.0.15","ConnectorPort":51234,"Host":"fin-app01.corp.nexacorp.local","Application":"Finance-Servers","AppGroup":"Finance","Server":"0","ServerIP":"10.20.30.41","ServerPort":3389,"PolicyProcessingTime":31,"CAProcessingTime":1180,"ConnectorZENSetupTime":40211,"ConnectionSetupTime":41522,"ServerSetupTime":612,"AppLearnTime":0,"TimestampConnectionStart":"2026-10-01T05:10:44.120Z","TimestampConnectionEnd":"2026-10-01T06:40:01.884Z","TimestampCATx":"2026-10-01T05:10:44.120Z","TimestampCARx":"2026-10-01T05:10:44.121Z","TimestampAppLearnStart":"","TimestampZENFirstRxClient":"2026-10-01T05:10:44.162Z","TimestampZENFirstTxClient":"2026-10-01T05:10:44.170Z","TimestampZENLastRxClient":"2026-10-01T06:40:01.880Z","TimestampZENLastTxClient":"2026-10-01T06:40:01.882Z","TimestampConnectorZENSetupComplete":"2026-10-01T05:10:44.160Z","TimestampZENFirstRxConnector":"2026-10-01T05:10:44.169Z","TimestampZENFirstTxConnector":"2026-10-01T05:10:44.163Z","TimestampZENLastRxConnector":"2026-10-01T06:40:01.881Z","TimestampZENLastTxConnector":"2026-10-01T06:40:01.880Z","ZENTotalBytesRxClient":18422391,"ZENBytesRxClient":20412,"ZENTotalBytesTxClient":96310944,"ZENBytesTxClient":118204,"ZENTotalBytesRxConnector":96310944,"ZENBytesRxConnector":118204,"ZENTotalBytesTxConnector":18422391,"ZENBytesTxConnector":20412,"Idp":"NexaCorp-EntraID","ClientToClient":"0"}
```

### 4.3 User Activity — access blocked by policy (user probing an app outside their role)
```json
{"LogTimestamp":"Thu Oct  1 06:12:37 2026","Customer":"NexaCorp Ltd","SessionID":"Qm9rZ1hQd2VYcDNaTDFv","ConnectionID":"Wk5hcTJ0Uk1wTDdmQ3Bx","InternalReason":"BRK_MT_SETUP_FAIL_REJECTED_BY_POLICY","ConnectionStatus":"close","IPProtocol":6,"DoubleEncryption":0,"Username":"dana.levi@nexacorp.co.il","ServicePort":445,"ClientPublicIP":"203.0.113.24","ClientPrivateIP":"192.168.1.23","ClientLatitude":32.080000,"ClientLongitude":34.780000,"ClientCountryCode":"IL","ClientZEN":"broker2a.tlv1","Policy":"Block-NonIT-Admin-Shares","Connector":"","ConnectorZEN":"","ConnectorIP":"","ConnectorPort":0,"Host":"dc01.corp.nexacorp.local","Application":"Domain-Controllers","AppGroup":"Infrastructure","Server":"","ServerIP":"","ServerPort":0,"PolicyProcessingTime":27,"CAProcessingTime":0,"ConnectorZENSetupTime":0,"ConnectionSetupTime":0,"ServerSetupTime":0,"AppLearnTime":0,"TimestampConnectionStart":"2026-10-01T06:12:37.402Z","TimestampConnectionEnd":"2026-10-01T06:12:37.430Z","TimestampCATx":"","TimestampCARx":"","TimestampAppLearnStart":"","TimestampZENFirstRxClient":"","TimestampZENFirstTxClient":"","TimestampZENLastRxClient":"","TimestampZENLastTxClient":"","TimestampConnectorZENSetupComplete":"","TimestampZENFirstRxConnector":"","TimestampZENFirstTxConnector":"","TimestampZENLastRxConnector":"","TimestampZENLastTxConnector":"","ZENTotalBytesRxClient":0,"ZENBytesRxClient":0,"ZENTotalBytesTxClient":0,"ZENBytesTxClient":0,"ZENTotalBytesRxConnector":0,"ZENBytesRxConnector":0,"ZENTotalBytesTxConnector":0,"ZENBytesTxConnector":0,"Idp":"NexaCorp-EntraID","ClientToClient":"0"}
```

### 4.4 User Status — session from a foreign hosting-provider IP, unmanaged device failing posture
```json
{"LogTimestamp":"Thu Oct  1 00:41:53 2026","Customer":"NexaCorp Ltd","Username":"r.mizrahi@nexacorp.co.il","SessionID":"dlpRcTN4TjJhS2ZtUTl3","SessionStatus":"ZPN_STATUS_AUTHENTICATED","Version":"4.2.1.212","ZEN":"broker1b.ams2","CertificateCN":"C-0a9d44e1f2.r.mizrahi@nexacorp.co.il","PrivateIP":"10.0.2.15","PublicIP":"192.0.2.140","Latitude":52.37,"Longitude":4.89,"CountryCode":"NL","TimestampAuthentication":"2026-10-01T00:41:51.000Z","TimestampUnAuthentication":"","TotalBytesRx":0,"TotalBytesTx":0,"Idp":"NexaCorp-EntraID","Hostname":"DESKTOP-8QF2L1M","Platform":"windows","ClientType":"zpn_client_type_zapp","TrustedNetworks":"","TrustedNetworksNames":"","SAMLAttributes":"department:Sales,email:r.mizrahi@nexacorp.co.il","PosturesHit":"","PosturesMiss":"CrowdStrike-ZTA,Domain-Joined,Disk-Encrypted","ZENLatitude":52,"ZENLongitude":4,"ZENCountryCode":"NL","FQDNRegistered":"0","FQDNRegisteredError":"CUSTOMER_NOT_ENABLED"}
```

### 4.5 User Status — concurrent session for the same user from Germany (different SessionID/device)
```json
{"LogTimestamp":"Thu Oct  1 06:17:33 2026","Customer":"NexaCorp Ltd","Username":"dana.levi@nexacorp.co.il","SessionID":"TmhXcjRzVDlwQzJ2WmE4","SessionStatus":"ZPN_STATUS_AUTHENTICATED","Version":"4.4.0.379","ZEN":"broker2b.fra4","CertificateCN":"C-b31f0e7d55.dana.levi@nexacorp.co.il","PrivateIP":"172.31.18.204","PublicIP":"198.51.100.203","Latitude":50.11,"Longitude":8.68,"CountryCode":"DE","TimestampAuthentication":"2026-10-01T06:17:31.000Z","TimestampUnAuthentication":"","TotalBytesRx":0,"TotalBytesTx":0,"Idp":"NexaCorp-EntraID","Hostname":"WIN-K7T2M0QX","Platform":"windows","ClientType":"zpn_client_type_zapp","TrustedNetworks":"","TrustedNetworksNames":"","SAMLAttributes":"department:Finance,email:dana.levi@nexacorp.co.il","PosturesHit":"","PosturesMiss":"CrowdStrike-ZTA,Domain-Joined","ZENLatitude":50,"ZENLongitude":8,"ZENCountryCode":"DE","FQDNRegistered":"0","FQDNRegisteredError":"CUSTOMER_NOT_ENABLED"}
```

### 4.6 User Activity — bulk download from an internal file server by the foreign session (active record)
```json
{"LogTimestamp":"Thu Oct  1 01:20:44 2026","Customer":"NexaCorp Ltd","SessionID":"dlpRcTN4TjJhS2ZtUTl3","ConnectionID":"Q2RmN1pLcTN4YlR3TW4y,cFoyTGs5dlFhUjRuWHQx","InternalReason":"","ConnectionStatus":"active","IPProtocol":6,"DoubleEncryption":0,"Username":"r.mizrahi@nexacorp.co.il","ServicePort":445,"ClientPublicIP":"192.0.2.140","ClientPrivateIP":"10.0.2.15","ClientLatitude":52.370000,"ClientLongitude":4.890000,"ClientCountryCode":"NL","ClientZEN":"broker1b.ams2","Policy":"Allow-Sales-FileShares","Connector":"AC-HQ-DC1-02","ConnectorZEN":"broker1b.ams2","ConnectorIP":"10.20.0.16","ConnectorPort":49811,"Host":"fs02.corp.nexacorp.local","Application":"File-Servers","AppGroup":"Sales","Server":"0","ServerIP":"10.20.40.12","ServerPort":445,"PolicyProcessingTime":29,"CAProcessingTime":1204,"ConnectorZENSetupTime":88412,"ConnectionSetupTime":89710,"ServerSetupTime":540,"AppLearnTime":0,"TimestampConnectionStart":"2026-10-01T00:44:02.551Z","TimestampConnectionEnd":"","TimestampCATx":"2026-10-01T00:44:02.551Z","TimestampCARx":"2026-10-01T00:44:02.552Z","TimestampAppLearnStart":"","TimestampZENFirstRxClient":"2026-10-01T00:44:02.643Z","TimestampZENFirstTxClient":"2026-10-01T00:44:02.650Z","TimestampZENLastRxClient":"2026-10-01T01:20:43.997Z","TimestampZENLastTxClient":"2026-10-01T01:20:44.001Z","TimestampConnectorZENSetupComplete":"2026-10-01T00:44:02.640Z","TimestampZENFirstRxConnector":"2026-10-01T00:44:02.648Z","TimestampZENFirstTxConnector":"2026-10-01T00:44:02.644Z","TimestampZENLastRxConnector":"2026-10-01T01:20:44.000Z","TimestampZENLastTxConnector":"2026-10-01T01:20:43.998Z","ZENTotalBytesRxClient":41877302,"ZENBytesRxClient":1022811,"ZENTotalBytesTxClient":7841203394,"ZENBytesTxClient":184220981,"ZENTotalBytesRxConnector":7841203394,"ZENBytesRxConnector":184220981,"ZENTotalBytesTxConnector":41877302,"ZENBytesTxConnector":1022811,"Idp":"NexaCorp-EntraID","ClientToClient":"0"}
```

Note: ZPA authenticates via SAML, so **password brute force is not visible in ZPA logs** — it appears in the IdP (Entra ID / Okta) sign-in logs. ZPA only shows sessions that already passed SSO.

## 5. Investigation notes

- **Join keys:** `SessionID` joins User Activity <-> User Status. `Username` joins to IdP sign-ins (Entra `userPrincipalName`, Okta `actor.alternateId`).
- **Foreign / hosting IP:** `PublicIP` + `CountryCode` (User Status) / `ClientPublicIP` + `ClientCountryCode` (Activity). The broker (`ZEN`, `ClientZEN`) location also shifts (e.g. `.ams2`, `.fra4`).
- **Device trust:** `Hostname`, `Platform`, `Version`, `PosturesHit` / `PosturesMiss`, `CertificateCN`. Missing EDR/domain posture + non-corporate hostname = unmanaged device.
- **Concurrent sessions:** same `Username`, two open sessions (`TimestampUnAuthentication` empty) with different `SessionID`/`PublicIP`/`Hostname`.
- **Data theft through ZTNA:** watch `ZENTotalBytesTxClient` (bytes delivered to the client) on file-server / DB applications; deltas in `ZENBytesTxClient` per `active` record show rate.
- **Policy probing / lateral discovery:** many `ConnectionStatus=close` with `InternalReason=BRK_MT_SETUP_FAIL_REJECTED_BY_POLICY` across different `Host`/`ServicePort`.
- **Pivot inside the network:** the server sees the **App Connector IP** (`ConnectorIP`) as source, not the user. Correlate server-side logs (Windows 4624 `IpAddress`, firewall `src`) on `ConnectorIP` + time + `ServerIP`/`ServerPort`, then attribute back to `Username` through ZPA.

## 6. Common mistakes / fields that do NOT exist

- No `user`, `src_ip`, `action`, `allowed`, `country`, `app` keys — use `Username`, `ClientPublicIP`, `ConnectionStatus`+`InternalReason`, `ClientCountryCode`, `Application`.
- There is no `Action: "Block"` field; a block shows as `close` with an `InternalReason` and the matched block rule in `Policy`.
- `LogTimestamp` is ctime-style text, not ISO; the ISO timestamps are the `Timestamp*` fields.
- Server-side logs never show the user's public IP — they show the App Connector.
- ZPA logs are not ZIA logs: no `url`, `urlcategory`, `threatname` here (those are ZIA NSS web fields).
- Don't use Elastic (`zscaler_zpa.user_activity.*`) or Wazuh (`data.*`) shapes.
