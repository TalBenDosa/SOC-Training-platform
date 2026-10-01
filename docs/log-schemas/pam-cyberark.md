# CyberArk Privileged Access Manager (Self-Hosted) — Vault audit via syslog (CEF)

Category: PAM (privileged access management). Vendor: CyberArk (now part of Palo Alto Networks, docs branded "Idira"). Card version: 2026-10-01.

---

## 1. Official sources consulted

| URL | What it confirmed |
|---|---|
| CyberArk docs — "Security Information and Event Management (SIEM) Applications" (PAM Self-Hosted 15.x, docs.cyberark.com) | The Vault sends audit records over syslog using an XSL translator. `DBParm.ini` parameters `SyslogServerIP`, `SyslogServerPort`, `SyslogServerProtocol`, `SyslogMessageCodeFilter` (e.g. `1,2,3,5-10,30`), `SyslogTranslatorFile=Syslog\Arcsight.sample.xsl` (the shipped sample, copied into `PrivateArk\Server\Syslog`). Several translators / servers can be listed comma-separated. |
| CyberArk docs — "Create a Custom XSL Translator File" | The Vault's internal XML record (`<syslog><audit_record>`) and its fields: `Rfc5424, Timestamp, IsoTimestamp, Hostname, Vendor, Product, Version, MessageID, Desc, Severity, Issuer, Action, SourceUser, TargetUser, Safe, File, Station, Location, Category, RequestId, Reason, ExtraDetails, Message, GatewayStation, PvwaDetails, CAProperties`. CEF header = `CEF:0|Vendor|Product|Version|MessageID|Desc|<severity>`; severity mapping `Critical → 10`, `Error → 7`, `Info → 5`, otherwise `0`. `Station` = client IP (for PVWA sessions, the real client IP); `GatewayStation` = PVWA server IP; `Issuer` = Vault user who performed the operation. |
| CyberArk docs — "Vault Audit Action Codes" | Action codes and descriptions, e.g. `4` User Authentication Failure, `7` Logon, `8` Logoff, `22` CPM Verify Password, `24` CPM Change Password, `31` CPM Reconcile Password, `38` CPM Verify Password Failure, `57` CPM Change Password Failure, `180` Add User, `265` Add Group Member, `294` Store password, `295` Retrieve password, `300` PSM Connect, `301` PSM Connect Failed, `302` PSM Disconnect, `308` Use Password, `309` Undefined User Logon, `319` Retrieve password (From Provider), `359` SQL command, `361` SSH command / PSM Keystrokes, `411` PSM Window Title, `427`/`428` Store/Retrieve SSH Key. The "recommended for monitoring" list includes 4, 22, 24, 31, 38, 57, 60, 130, 295, 300, 302, 308, 359–362, 411, 412. Note: the page's two tables disagree on the labels of 361 and 412 (Keystrokes vs SSH command; Keystroke logging vs Window Title Failure). |
| https://docs.sekoia.com/integration/categories/iam/cyberark_vault/ (secondary) | Real Arcsight.sample.xsl output lines from Vault 14.x, e.g. `CEF:0\|Cyber-Ark\|Vault\|14.2.0002\|300\|PSM Connect\|5\|act="PSM Connect" suser=… fname=Root\… shost=… dhost=… duser=… externalId=<session GUID> app=RDP reason= cs1Label="Affected User Name" cs2Label="Safe Name" cs2="…" cs3Label="Device Type" cs3="Operating System" cs4Label="Database" cs5Label="Other info" cn1Label="Request Id" cn2Label="Ticket Id" msg=`. Vendor string is `Cyber-Ark`. Multi-word values are double-quoted. Empty `cs1`/`cs4`/`cs5`/`cn1`/`cn2` values are left out, while their `…Label` keys stay. |
| https://github.com/Azure/Azure-Sentinel/tree/master/Parsers/CyberArk (secondary) | Extension key order of the shipped XSL: `act, suser, fname, dvc, shost, dhost, duser, externalId, app, reason, cs1Label, cs1, cs2Label, cs2, cs3Label, cs3, cs4Label, cs4, cs5Label, cs5, cn1Label, cn1, cn2Label, cn2, msg`. Older Vault versions also emit `dvc=`; the 14.x samples above don't. PSM code set used for session parsing: 300–304, 359–362, 372–381, 411–413. |
| https://github.com/elastic/integrations/tree/main/packages/cyberarkpas (test data) | Real Vault XML records for codes 4, 7, 22, 24, 38, 180, 265, 295, 300, 302, 308, 309, 359, 361, 411. Confirmed: `Vendor` = `Cyber-Ark`, `Version` like `11.6.0000`, `Issuer` values (`PasswordManager` for CPM, `Prov_PVWA`/application ids for AAM), `File` = `Root\<PlatformType>-<PolicyID>-<Address>-<UserName>`, `Reason` examples (`AIM password request`, `(Action: Connect)`, `ImmediateTask`), PSM `ExtraDetails` as `key=value;` pairs (`ApplicationType`, `DstHost`, `Protocol`, `PSMID`, `SessionID`, `SessionDuration`, `SrcHost`, `User`, `Command`, `ProcessName`), `CAProperties` (`PolicyID`, `UserName`, `Address`, `DeviceType`, `LogonDomain`, `CPMStatus`, `LastTask`). Legacy header `Mar 08 03:41:01 VAULT …`; RFC 5424 header `<5>1 2021-03-04T17:27:14Z VAULT …`. |

---

## 2. Native format, delivery, and the representation we standardise on

- **Native:** the Vault turns each audit record (XML, see §1) into a text line with the XSL named in `SyslogTranslatorFile`. With the shipped `Arcsight.sample.xsl`, each line is **CEF** after a syslog header:
  ```
  Sep 30 03:47:12 VAULT01 CEF:0|Cyber-Ark|Vault|14.2.0002|295|Retrieve password|5|act="Retrieve password" suser=noa.katz fname=Root\Operating System-WinDomain-nexacorp.local-adm.yoav shost=10.20.14.88 dhost=nexacorp.local duser=adm.yoav app= reason="Urgent fix INC-4471" cs1Label="Affected User Name" cs2Label="Safe Name" cs2="T0-DomainAdmins" cs3Label="Device Type" cs3="Operating System" cs4Label="Database" cs5Label="Other info" cs5="10.20.0.40" cn1Label="Request Id" cn2Label="Ticket Id" msg=
  ```
  Transport: UDP/TCP 514 or TLS (`SyslogServerProtocol`). With `Rfc5424=yes` the header is RFC 5424 (`<5>1 2026-09-30T03:47:12Z VAULT01 …`); otherwise the BSD form above.
- **STANDARD FOR THIS PLATFORM — flat JSON + raw** (same convention as the other CEF cards in this folder):
  - Syslog header → `timestamp` (as printed, `"Sep 30 03:47:12"`), `hostname` (Vault host, upper case).
  - CEF header → `CEFVersion`, `DeviceVendor`, `DeviceProduct`, `DeviceVersion`, `SignatureID` (= the **action code**), `Name` (= `Desc`), `Severity` (`"5"`/`"7"`/`"10"`).
  - Extension keys **verbatim and in XSL order**: `act, suser, fname, shost, dhost, duser, externalId, app, reason, cs1Label, cs1, cs2Label, cs2, cs3Label, cs3, cs4Label, cs4, cs5Label, cs5, cn1Label, cn1, cn2Label, cn2, msg`. All values are strings. A key the line doesn't carry is left out; a key printed with an empty value (`app=`) becomes `""`.
  - `raw` = the complete original line.
- Times in the syslog header are the Vault server's local time (UTC in our samples). The Vault itself does not put a time inside the CEF extension (no `rt`/`end`).
- No SIEM layer: no `cyberarkpas.audit.*`, no `event.code`, no `deviceCustomString1`, no Sentinel `CommonSecurityLog` column names.

---

## 3. Core field reference

### 3.1 CEF header

| Key | Source (XML) | Values |
|---|---|---|
| `CEFVersion` | constant | `0` |
| `DeviceVendor` | `Vendor` | `Cyber-Ark` (with hyphen) |
| `DeviceProduct` | `Product` | `Vault` |
| `DeviceVersion` | `Version` | Vault build, e.g. `14.2.0002`, `14.6.0002`, `11.6.0000` |
| `SignatureID` | `MessageID` | Action code (§3.3) |
| `Name` | `Desc` | Action description, e.g. `Retrieve password`, `PSM Connect` |
| `Severity` | `Severity` | `5` (Info), `7` (Error), `10` (Critical), `0` (other) |

### 3.2 Extension keys (Arcsight.sample.xsl)

| Key | Meaning | Typical content |
|---|---|---|
| `act` | Action (XML `Action`) | Same text as `Name` in most records |
| `suser` | Vault user who did it (XML `Issuer`) | Human Vault user (`noa.katz`), component user (`PasswordManager` = CPM, `PSMApp_…`/`PSMGw_…`, `Prov_<app>` / app id for AAM/CP), `Administrator` |
| `fname` | Target object (XML `File`) | Account object `Root\<Platform>-<PolicyID>-<Address>-<UserName>`, or a file path in a safe |
| `shost` | Source station (XML `Station`) | Client IP; for PVWA logons the real end-user IP. For PSM records it is the PSM server address (UNVERIFIED for every code — the Elastic samples show `Station` = PSM host and `SrcHost` = end user) |
| `dhost` | Target machine | Account `Address` / PSM `DstHost` (e.g. `SQL01.nexacorp.local`, a domain name for domain accounts) |
| `duser` | Target account | Privileged account name (XML `TargetUser` or account `UserName`) |
| `externalId` | PSM session ID | GUID; joins 300 → 359/361/411 → 302 |
| `app` | Protocol / connection component | `RDP`, `SSH`, `PSM-RDP`, `PSMP-SSH`, `SQLPlus`… |
| `reason` | Reason the user typed, or system reason | Free text (ticket), `(Action: Connect)`, `AIM password request`, `ImmediateTask` |
| `cs1Label` / `cs1` | `Affected User Name` | Vault user affected (user-management codes) |
| `cs2Label` / `cs2` | `Safe Name` | Safe that holds the account |
| `cs3Label` / `cs3` | `Device Type` | `Operating System`, `Database`, `Application`, `Network Device` |
| `cs4Label` / `cs4` | `Database` | Database name (DB platforms) |
| `cs5Label` / `cs5` | `Other info` | Location / category / `GatewayStation` (PVWA IP), command text for some PSM codes (exact mapping per code UNVERIFIED) |
| `cn1Label` / `cn1` | `Request Id` | Dual-control (access-request) id |
| `cn2Label` / `cn2` | `Ticket Id` | Ticketing-system id (ServiceNow/Jira integration) |
| `msg` | `Message` / extra details | Often empty, or a short detail (`ExpirationPeriod`, a command) |

### 3.3 Action codes used in SOC scenarios

| Code | Name (`Name`/`act`) | Severity | Why it matters |
|---|---|---|---|
| 4 | User Authentication Failure | 7 | Failed Vault logon (bad password / MFA / disabled user). Repeated = guessing against the Vault. |
| 7 | Logon | 5 | Successful Vault logon (PVWA, PrivateArk client, API). |
| 8 | Logoff | 5 | |
| 22 / 38 | CPM Verify Password / … Failure | 5 / 7 | 38 = the password in the Vault no longer works on the target — someone changed it outside CyberArk. |
| 24 / 57 | CPM Change Password / … Failure | 5 / 7 | Scheduled or forced rotation. |
| 31 / 60 | CPM Reconcile Password / … Failure | 5 / 7 | Reconcile after drift. |
| 180 | Add User | 5 | New Vault user. |
| 265 | Add Group Member | 5 | Vault group change (e.g. into `Vault Admins`). |
| 295 | Retrieve password | 5 | A user (or application) **revealed/copied** the password. Key privileged-access event. |
| 300 / 301 | PSM Connect / PSM Connect Failed | 5 / 7 | Start of a brokered session (password not shown to the user). |
| 302 / 303 | PSM Disconnect / … Failed | 5 / 7 | End of session; duration in extra details. |
| 308 | Use Password | 5 | Password used by a connection (PSM / PVWA "Connect") without being shown. |
| 309 | Undefined User Logon | 7 (UNVERIFIED) | Logon attempt with a user that doesn't exist in the Vault. |
| 319 | Retrieve password (From Provider) | 5 | Application retrieval via Credential Provider (AAM). |
| 359 | SQL command | 5 | SQL text recorded in a PSM DB session. |
| 361 | SSH command / PSM Keystrokes | 5 | Command typed in a PSM SSH session (label differs between doc tables). |
| 411 | PSM Window Title | 5 | Window title / process seen in a PSM RDP session. |
| 427 / 428 | Store / Retrieve SSH Key | 5 | Private-key retrieval — like 295 for keys. |

Severity values per code are the record's `Severity` element mapped by the XSL. Failure / unauthorised codes are `Error` (7) in the Vault's own examples; exact severity of every code listed above is not documented per code (UNVERIFIED beyond 4 = Error and the Info examples).

---

## 4. Samples (fictitious org `nexacorp.local`; Vault `VAULT01`, PVWA `10.20.0.40`, PSM `10.20.0.45`; times UTC)

Storyline (2026-09-30): business hours are 04:00–16:00 UTC. IT admin `noa.katz` normally works from `10.20.12.31`. At night her Vault account is used from the compromised workstation `10.20.14.88` to reveal the Tier-0 domain-admin password and open a session to the DC.

### 4.1 Code 4 — repeated Vault authentication failures (PVWA)

```json
{
  "timestamp": "Sep 30 03:44:58",
  "hostname": "VAULT01",
  "CEFVersion": "0",
  "DeviceVendor": "Cyber-Ark",
  "DeviceProduct": "Vault",
  "DeviceVersion": "14.2.0002",
  "SignatureID": "4",
  "Name": "User Authentication Failure",
  "Severity": "7",
  "act": "User Authentication Failure",
  "suser": "noa.katz",
  "fname": "",
  "shost": "10.20.14.88",
  "dhost": "",
  "duser": "",
  "app": "",
  "reason": "",
  "cs1Label": "Affected User Name",
  "cs2Label": "Safe Name",
  "cs2": "",
  "cs3Label": "Device Type",
  "cs3": "",
  "cs4Label": "Database",
  "cs5Label": "Other info",
  "cs5": "10.20.0.40",
  "cn1Label": "Request Id",
  "cn2Label": "Ticket Id",
  "msg": "",
  "raw": "Sep 30 03:44:58 VAULT01 CEF:0|Cyber-Ark|Vault|14.2.0002|4|User Authentication Failure|7|act=\"User Authentication Failure\" suser=noa.katz fname= shost=10.20.14.88 dhost= duser= app= reason= cs1Label=\"Affected User Name\" cs2Label=\"Safe Name\" cs2= cs3Label=\"Device Type\" cs3= cs4Label=\"Database\" cs5Label=\"Other info\" cs5=10.20.0.40 cn1Label=\"Request Id\" cn2Label=\"Ticket Id\" msg="
}
```
*Third failure in 90 seconds for `noa.katz`, from `10.20.14.88` — not her usual workstation (`10.20.12.31`) and outside her working hours. `cs5` carries the PVWA gateway address (mapping of `GatewayStation` into `cs5` is UNVERIFIED). The Vault locks the user after the configured number of failures (`MaxLogonFailures`, UNVERIFIED parameter name here).*

### 4.2 Code 7 — successful Vault logon from the same unusual station

```json
{
  "timestamp": "Sep 30 03:46:21",
  "hostname": "VAULT01",
  "CEFVersion": "0",
  "DeviceVendor": "Cyber-Ark",
  "DeviceProduct": "Vault",
  "DeviceVersion": "14.2.0002",
  "SignatureID": "7",
  "Name": "Logon",
  "Severity": "5",
  "act": "Logon",
  "suser": "noa.katz",
  "fname": "",
  "shost": "10.20.14.88",
  "dhost": "",
  "duser": "",
  "app": "",
  "reason": "",
  "cs1Label": "Affected User Name",
  "cs2Label": "Safe Name",
  "cs2": "",
  "cs3Label": "Device Type",
  "cs3": "",
  "cs4Label": "Database",
  "cs5Label": "Other info",
  "cs5": "10.20.0.40",
  "cn1Label": "Request Id",
  "cn2Label": "Ticket Id",
  "msg": "",
  "raw": "Sep 30 03:46:21 VAULT01 CEF:0|Cyber-Ark|Vault|14.2.0002|7|Logon|5|act=\"Logon\" suser=noa.katz fname= shost=10.20.14.88 dhost= duser= app= reason= cs1Label=\"Affected User Name\" cs2Label=\"Safe Name\" cs2= cs3Label=\"Device Type\" cs3= cs4Label=\"Database\" cs5Label=\"Other info\" cs5=10.20.0.40 cn1Label=\"Request Id\" cn2Label=\"Ticket Id\" msg="
}
```
*Failures followed by success from the same `shost` = the password was eventually guessed or reused. Check the IdP/MFA logs for the same minute: if Vault logon is federated (SAML/RADIUS), the MFA approval will be there, not here.*

### 4.3 Code 295 — Tier-0 password revealed outside business hours

```json
{
  "timestamp": "Sep 30 03:47:12",
  "hostname": "VAULT01",
  "CEFVersion": "0",
  "DeviceVendor": "Cyber-Ark",
  "DeviceProduct": "Vault",
  "DeviceVersion": "14.2.0002",
  "SignatureID": "295",
  "Name": "Retrieve password",
  "Severity": "5",
  "act": "Retrieve password",
  "suser": "noa.katz",
  "fname": "Root\\Operating System-WinDomain-nexacorp.local-adm.yoav",
  "shost": "10.20.14.88",
  "dhost": "nexacorp.local",
  "duser": "adm.yoav",
  "app": "",
  "reason": "Urgent fix INC-4471",
  "cs1Label": "Affected User Name",
  "cs2Label": "Safe Name",
  "cs2": "T0-DomainAdmins",
  "cs3Label": "Device Type",
  "cs3": "Operating System",
  "cs4Label": "Database",
  "cs5Label": "Other info",
  "cs5": "10.20.0.40",
  "cn1Label": "Request Id",
  "cn2Label": "Ticket Id",
  "msg": "",
  "raw": "Sep 30 03:47:12 VAULT01 CEF:0|Cyber-Ark|Vault|14.2.0002|295|Retrieve password|5|act=\"Retrieve password\" suser=noa.katz fname=Root\\Operating System-WinDomain-nexacorp.local-adm.yoav shost=10.20.14.88 dhost=nexacorp.local duser=adm.yoav app= reason=\"Urgent fix INC-4471\" cs1Label=\"Affected User Name\" cs2Label=\"Safe Name\" cs2=\"T0-DomainAdmins\" cs3Label=\"Device Type\" cs3=\"Operating System\" cs4Label=\"Database\" cs5Label=\"Other info\" cs5=10.20.0.40 cn1Label=\"Request Id\" cn2Label=\"Ticket Id\" msg="
}
```
*The highest-value event in this card: a human revealed a domain-admin password (295 = "Show/Copy"; a brokered connection would log 308/300 instead). Red flags: 06:47 local time, a station that isn't the user's, a Tier-0 safe, no `cn1` (no dual-control approval) and no `cn2` (no ticket id), and a `reason` that names an incident number which must be checked against the ticketing system. Severity is only `5` — CyberArk does not rate it; the SOC must.*

### 4.4 Code 300 — PSM session opened to the domain controller

```json
{
  "timestamp": "Sep 30 03:49:40",
  "hostname": "VAULT01",
  "CEFVersion": "0",
  "DeviceVendor": "Cyber-Ark",
  "DeviceProduct": "Vault",
  "DeviceVersion": "14.2.0002",
  "SignatureID": "300",
  "Name": "PSM Connect",
  "Severity": "5",
  "act": "PSM Connect",
  "suser": "noa.katz",
  "fname": "Root\\Operating System-WinDomain-nexacorp.local-adm.yoav",
  "shost": "10.20.0.45",
  "dhost": "DC01.nexacorp.local",
  "duser": "adm.yoav",
  "externalId": "7d2c9e41-5b8a-4f3e-a1c6-0e9b4d2f7a58",
  "app": "RDP",
  "reason": "",
  "cs1Label": "Affected User Name",
  "cs2Label": "Safe Name",
  "cs2": "T0-DomainAdmins",
  "cs3Label": "Device Type",
  "cs3": "Operating System",
  "cs4Label": "Database",
  "cs5Label": "Other info",
  "cn1Label": "Request Id",
  "cn2Label": "Ticket Id",
  "msg": "",
  "raw": "Sep 30 03:49:40 VAULT01 CEF:0|Cyber-Ark|Vault|14.2.0002|300|PSM Connect|5|act=\"PSM Connect\" suser=noa.katz fname=Root\\Operating System-WinDomain-nexacorp.local-adm.yoav shost=10.20.0.45 dhost=DC01.nexacorp.local duser=adm.yoav externalId=7d2c9e41-5b8a-4f3e-a1c6-0e9b4d2f7a58 app=RDP reason= cs1Label=\"Affected User Name\" cs2Label=\"Safe Name\" cs2=\"T0-DomainAdmins\" cs3Label=\"Device Type\" cs3=\"Operating System\" cs4Label=\"Database\" cs5Label=\"Other info\" cn1Label=\"Request Id\" cn2Label=\"Ticket Id\" msg="
}
```
*`externalId` is the PSM session GUID: every 359/361/411 record and the final 302 for this session carry it, and it names the session recording. `shost` here is the PSM server (`10.20.0.45`) — the RDP to DC01 comes from PSM, so DC01's 4624 shows `IpAddress 10.20.0.45`, not the user's workstation (end-user IP sits in the Vault's XML `ExtraDetails` `SrcHost`; whether the shipped XSL exposes it is UNVERIFIED).*

### 4.5 Code 411 — window titles recorded inside the PSM session

```json
{
  "timestamp": "Sep 30 03:53:05",
  "hostname": "VAULT01",
  "CEFVersion": "0",
  "DeviceVendor": "Cyber-Ark",
  "DeviceProduct": "Vault",
  "DeviceVersion": "14.2.0002",
  "SignatureID": "411",
  "Name": "Window Title",
  "Severity": "5",
  "act": "Window Title",
  "suser": "noa.katz",
  "fname": "Root\\Operating System-WinDomain-nexacorp.local-adm.yoav",
  "shost": "10.20.0.45",
  "dhost": "DC01.nexacorp.local",
  "duser": "adm.yoav",
  "externalId": "7d2c9e41-5b8a-4f3e-a1c6-0e9b4d2f7a58",
  "app": "RDP",
  "reason": "",
  "cs1Label": "Affected User Name",
  "cs2Label": "Safe Name",
  "cs2": "T0-DomainAdmins",
  "cs3Label": "Device Type",
  "cs3": "Operating System",
  "cs4Label": "Database",
  "cs5Label": "Other info",
  "cs5": "dsa.exe, Active Directory Users and Computers",
  "cn1Label": "Request Id",
  "cn2Label": "Ticket Id",
  "msg": "",
  "raw": "Sep 30 03:53:05 VAULT01 CEF:0|Cyber-Ark|Vault|14.2.0002|411|Window Title|5|act=\"Window Title\" suser=noa.katz fname=Root\\Operating System-WinDomain-nexacorp.local-adm.yoav shost=10.20.0.45 dhost=DC01.nexacorp.local duser=adm.yoav externalId=7d2c9e41-5b8a-4f3e-a1c6-0e9b4d2f7a58 app=RDP reason= cs1Label=\"Affected User Name\" cs2Label=\"Safe Name\" cs2=\"T0-DomainAdmins\" cs3Label=\"Device Type\" cs3=\"Operating System\" cs4Label=\"Database\" cs5Label=\"Other info\" cs5=\"dsa.exe, Active Directory Users and Computers\" cn1Label=\"Request Id\" cn2Label=\"Ticket Id\" msg="
}
```
*Window-title records give the analyst a text timeline of the session without opening the video. The value format `<process>, <title>` follows the Vault XML `Command=` value in Elastic's sample; which CEF key the shipped XSL puts it in (`cs5` here) is UNVERIFIED. Correlate: ADUC opened on DC01 at 03:53, matching the account/group changes in the Windows Security log (4720/4728) a few minutes later.*

### 4.6 Code 302 — PSM session closed

```json
{
  "timestamp": "Sep 30 04:02:17",
  "hostname": "VAULT01",
  "CEFVersion": "0",
  "DeviceVendor": "Cyber-Ark",
  "DeviceProduct": "Vault",
  "DeviceVersion": "14.2.0002",
  "SignatureID": "302",
  "Name": "PSM Disconnect",
  "Severity": "5",
  "act": "PSM Disconnect",
  "suser": "noa.katz",
  "fname": "Root\\Operating System-WinDomain-nexacorp.local-adm.yoav",
  "shost": "10.20.0.45",
  "dhost": "DC01.nexacorp.local",
  "duser": "adm.yoav",
  "externalId": "7d2c9e41-5b8a-4f3e-a1c6-0e9b4d2f7a58",
  "app": "RDP",
  "reason": "",
  "cs1Label": "Affected User Name",
  "cs2Label": "Safe Name",
  "cs2": "T0-DomainAdmins",
  "cs3Label": "Device Type",
  "cs3": "Operating System",
  "cs4Label": "Database",
  "cs5Label": "Other info",
  "cn1Label": "Request Id",
  "cn2Label": "Ticket Id",
  "msg": "",
  "raw": "Sep 30 04:02:17 VAULT01 CEF:0|Cyber-Ark|Vault|14.2.0002|302|PSM Disconnect|5|act=\"PSM Disconnect\" suser=noa.katz fname=Root\\Operating System-WinDomain-nexacorp.local-adm.yoav shost=10.20.0.45 dhost=DC01.nexacorp.local duser=adm.yoav externalId=7d2c9e41-5b8a-4f3e-a1c6-0e9b4d2f7a58 app=RDP reason= cs1Label=\"Affected User Name\" cs2Label=\"Safe Name\" cs2=\"T0-DomainAdmins\" cs3Label=\"Device Type\" cs3=\"Operating System\" cs4Label=\"Database\" cs5Label=\"Other info\" cn1Label=\"Request Id\" cn2Label=\"Ticket Id\" msg="
}
```
*Session length = 302 time − 300 time (12 min 37 s). The Vault XML holds `SessionDuration=00:12:37` in `ExtraDetails`; the shipped XSL does not print it as its own key (UNVERIFIED), so compute it from the pair.*

### 4.7 Code 38 — CPM verify failure: the password was changed outside CyberArk

```json
{
  "timestamp": "Sep 30 05:10:44",
  "hostname": "VAULT01",
  "CEFVersion": "0",
  "DeviceVendor": "Cyber-Ark",
  "DeviceProduct": "Vault",
  "DeviceVersion": "14.2.0002",
  "SignatureID": "38",
  "Name": "CPM Verify Password Failure",
  "Severity": "7",
  "act": "CPM Verify Password Failure",
  "suser": "PasswordManager",
  "fname": "Root\\Operating System-WinDomain-nexacorp.local-svc_mssql",
  "shost": "10.20.0.42",
  "dhost": "nexacorp.local",
  "duser": "svc_mssql",
  "app": "",
  "reason": "VerifyTask",
  "cs1Label": "Affected User Name",
  "cs2Label": "Safe Name",
  "cs2": "T1-ServiceAccounts",
  "cs3Label": "Device Type",
  "cs3": "Operating System",
  "cs4Label": "Database",
  "cs5Label": "Other info",
  "cn1Label": "Request Id",
  "cn2Label": "Ticket Id",
  "msg": "Invalid username or bad password",
  "raw": "Sep 30 05:10:44 VAULT01 CEF:0|Cyber-Ark|Vault|14.2.0002|38|CPM Verify Password Failure|7|act=\"CPM Verify Password Failure\" suser=PasswordManager fname=Root\\Operating System-WinDomain-nexacorp.local-svc_mssql shost=10.20.0.42 dhost=nexacorp.local duser=svc_mssql app= reason=VerifyTask cs1Label=\"Affected User Name\" cs2Label=\"Safe Name\" cs2=\"T1-ServiceAccounts\" cs3Label=\"Device Type\" cs3=\"Operating System\" cs4Label=\"Database\" cs5Label=\"Other info\" cn1Label=\"Request Id\" cn2Label=\"Ticket Id\" msg=\"Invalid username or bad password\""
}
```
*`suser PasswordManager` = the CPM component (`shost` = CPM server). A verify failure on a managed account means the real password no longer matches the Vault — either an admin changed it by hand or someone else did. Check the DC for 4724/4723 on `svc_mssql` in the preceding hours. The `reason` / `msg` texts are illustrative (UNVERIFIED wording).*

---

## 5. Investigation notes (pivots)

- **Who / from where:** `suser` (Vault identity) + `shost` (station). Build a baseline of stations and hours per `suser`; a known user from a new `shost` at night is the main PAM anomaly.
- **What was touched:** `fname` (account object), `duser` + `dhost` (the real privileged account and target), `cs2` (safe). Safe names usually encode the tier (`T0-…`), so filter on them.
- **Reveal vs. use:** `295` (password shown/copied to the human) is riskier than `308`/`300` (password used by PSM without being shown). After a 295, the password is outside CyberArk's control until the CPM rotates it — check for an immediate `24` (rotation after use, if "one-time password" is configured).
- **Approvals and tickets:** empty `cn1` (Request Id) and `cn2` (Ticket Id) on a Tier-0 retrieval means no dual control and no ticket. Validate any ticket number written in `reason`.
- **Session reconstruction:** filter on `externalId`. Order 300 → 411/361/359 → 302. The PSM recording has the same id.
- **Cross-source join:** a PSM session to `dhost` creates a logon on the target from the **PSM server** IP (Windows 4624 type 10 with `IpAddress` = PSM). Logons by the same privileged account on that target from any other IP bypassed CyberArk. A 295 followed by a logon from the user's own workstation means the revealed password was used directly.
- **Brute force against the Vault:** count `4` per `suser` and per `shost`; a run of 4s then a 7 from one `shost` = successful guess/reuse.
- **Out-of-band changes:** `38`/`57`/`60` (CPM failures) on privileged accounts → check the directory for password resets of that `duser`.
- **Vault-side persistence:** `180` Add User, `265` Add Group Member (e.g. into a Vault admin group), safe-permission changes — by whom (`suser`) and from where (`shost`).
- **Component users are normal:** `PasswordManager` (CPM), `PSMApp_*` / `PSMGw_*` (PSM), application ids (Credential Provider, code 319). Alert on human `suser` values doing what only components should do, and vice versa.
- **Chain to teach:** 4 ×3 → 7 (unusual station, 03:46) → 295 Tier-0 reveal without approval → 300 PSM to DC01 → 411 window titles (ADUC) → 302 → (Windows: 4720/4728 on DC01) → 38 on `svc_mssql`.

---

## 6. Common mistakes / fields that do NOT exist

**Do NOT use these (not in the Arcsight.sample.xsl output):**
- `DeviceVendor` `CyberArk` (no hyphen). The Vault writes `Cyber-Ark`. `DeviceProduct` is `Vault`, not `PAS`, `PVWA` or `Privileged Access Security`.
- SIEM-renamed fields: `deviceCustomString1`, `cs1Label` turned into columns (`AffectedUserName`), `sourceUserName`, `destinationHostName`, `cyberarkpas.audit.*`, `event.code`, `DeviceEventClassID`. Keep the CEF keys `suser`, `dhost`, `cs1` … as emitted.
- `src`, `dst`, `spt`, `dpt`, `rt`, `end`, `outcome`, `cat`, `deviceExternalId`. The shipped XSL emits none of them (older XSL versions also emit `dvc=`).
- `cs6` or `cn3`. The template stops at `cs5` and `cn2`.
- Vault XML element names inside CEF (`Issuer=`, `Station=`, `Safe=`, `SessionID=`). In CEF they become `suser`, `shost`, `cs2`, `externalId`.
- `severity` words (`Info`, `High`) in the header. The CEF `Severity` is the number from the XSL mapping (`5`, `7`, `10`, `0`).

**Value mistakes:**
- Missing `…Label` keys. The XSL always prints `cs1Label` … `cn2Label` even when the paired value is absent.
- `cs1` filled with the target account. `cs1` = "Affected User Name" (a **Vault** user in user-management events); the target privileged account is `duser`.
- `shost` = the user's workstation on PSM records. For PSM codes it is normally the PSM server.
- `SignatureID` that doesn't match `Name` (e.g. `295` with `PSM Connect`). Use the action-code table.
- A different `externalId` on the 302 than on the 300 of the same session.
- Reporting 295 as `Severity 10`. The Vault marks it Info (`5`); risk comes from the context, not the CEF severity.
- `fname` without the `Root\` prefix, or in a format other than `Root\<Platform>-<PolicyID>-<Address>-<UserName>` for account objects.
