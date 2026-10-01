# Microsoft Windows — Security event log (+ System 7045)

Category: ENDPOINT / IDENTITY (Windows hosts and Active Directory domain controllers). Vendor: Microsoft. Card version: 2026-10-01.

---

## 1. Official sources consulted

| URL | What it confirmed |
|---|---|
| https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4624 (and the sibling pages `event-4625`, `event-4634`, `event-4648`, `event-4672`, `event-4688`, `event-4697`, `event-4720`, `event-4722`, `event-4724`, `event-4728`, `event-4732`, `event-4738`, `event-4740`, `event-4756`, `event-4768`, `event-4769`, `event-4771`, `event-4776`, `event-4662`, `event-5136`) | Each event's XML sample, the exact `<Data Name="…">` list and field order, the `System` block (`Provider Name="Microsoft-Windows-Security-Auditing" Guid="{54849625-5478-4994-a5ba-3e3b0328c30d}"`, `Task`, `Keywords 0x8020000000000000` success / `0x8010000000000000` failure, `Channel Security`), LogonType table, 4625 Status/SubStatus table, Kerberos result codes, TicketEncryptionType and PreAuthType tables, TicketOptions bits, `%%NNNN` message-table placeholders (`%%2313`, `%%1833`, `%%1842/%%1843`, `%%1936–%%1938`, `%%7688`, `%%14674/%%14675`). |
| https://learn.microsoft.com/en-us/windows-server/security/kerberos/detect-remediate-rc4-kerberos | **2025 additions to 4768/4769** on DCs (Server 2019+; Server 2016 from the January 2025 CU): per-account / per-service / per-DC `msDS-SupportedEncryptionTypes` and **Available Keys**, client **Advertized Etypes**, **Session Encryption Type**. Ticket etype table `0x1, 0x3, 0x11, 0x12, 0x17, 0x18`. Sample failure 4769 with `Ticket Encryption Type 0xFFFFFFFF`, `Failure Code 0xE` (`KDC_ERR_ETYPE_NOTSUPP`). Server 2025 DCs don't issue RC4 TGTs. Microsoft is disabling RC4 as the default assumed etype by end of Q2 2026 (CVE-2026-20833 / KB5073381). The article's 4768 Event Viewer screenshot (`media/detect-remediate-rc4-kerberos/event-viewer-id-4768.png`) shows the value formats: `0x27 (DES, RC4, AES-Sk)`, `0x1F (DES, RC4, AES128-SHA96, AES256-SHA96)`, keys `AES-SHA1, RC4`, Advertized Etypes `AES256-CTS-HMAC-SHA1-96` / `RC4-HMAC-NT`, Session Encryption Type `0x12`, Pre-Authentication Type `138`, "Pre-Authentication EncryptionType" `0x12`, Ticket Options `0x40810010`. |
| https://system32.eventsentry.com/security/event/4769 (secondary) | The `Data Name` of every 4769 insertion string, including the new ones, in order: `TargetUserName, TargetDomainName, ServiceName, ServiceSid, TicketOptions, TicketEncryptionType, IpAddress, IpPort, Status, LogonGuid, TransmittedServices, RequestTicketHash, ResponseTicketHash, AccountSupportedEncryptionTypes, AccountAvailableKeys, ServiceSupportedEncryptionTypes, ServiceAvailableKeys, DCSupportedEncryptionTypes, DCAvailableKeys, ClientAdvertizedEncryptionTypes, SessionKeyEncryptionType`. |
| https://github.com/microsoft/Kerberos-Crypto (`scripts/Get-KerbEncryptionUsage.ps1`, `scripts/List-AccountKeys.ps1`) | Microsoft's own parsers read 4769 `Properties[5]` = ticket etype, `[6]` = IP, `[16]` = service keys, `[20]` = session-key etype; 4768 `[7]` = ticket etype, `[9]` = IP, `[16]` = account keys, `[22]` = session-key etype. This is consistent with the 4769 list above and with a 4768 order of 14 classic fields + `ResponseTicket, AccountSupportedEncryptionTypes, AccountAvailableKeys, ServiceSupportedEncryptionTypes, ServiceAvailableKeys, DCSupportedEncryptionTypes, DCAvailableKeys, ClientAdvertizedEncryptionTypes, SessionKeyEncryptionType, PreAuthEncryptionType`. The 4768 names `ResponseTicket` and `PreAuthEncryptionType` are UNVERIFIED by name (index-consistent only). Etype names used by Microsoft: `RC4` 0x17, `AES128-SHA96` 0x11, `AES256-SHA96` 0x12, `AES128-SHA256` 0x13, `AES256-SHA384` 0x14. |
| https://learn.microsoft.com/en-us/windows/win32/adschema/r-ds-replication-get-changes , `…/r-ds-replication-get-changes-all`, `…/r-ds-replication-get-changes-in-filtered-set` | Control-access-right GUIDs: `1131f6aa-9c07-11d1-f79f-00c04fc2dcd2` (DS-Replication-Get-Changes), `1131f6ad-9c07-11d1-f79f-00c04fc2dcd2` (DS-Replication-Get-Changes-All), `89e95b76-444d-4c62-991a-0facbeda640c` (DS-Replication-Get-Changes-In-Filtered-Set). `domainDNS` class GUID `19195a5b-6da0-11d0-afd3-00c04fd930c9`. |
| https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/appendix-l--events-to-monitor | Which IDs Microsoft recommends monitoring (4624/4625/4648/4672/4688/4720/4728/4732/4740/4756/4768/4769/4771/4776/5136/4697 …). |
| https://research.splunk.com/sources/614dedc8-8a14-4393-ba9b-6f093cbcd293/ and https://www.evtxparser.com/en/blog/service-creation-event-id-7045 (secondary) | System-log 7045 (`Provider Name="Service Control Manager"`, `EventSourceName="Service Control Manager"`), EventData `ServiceName, ImagePath, ServiceType, StartType, AccountName`, values rendered as text (`user mode service`, `demand start`, `LocalSystem`). |

---

## 2. Native format, delivery, and the representation we standardise on

**Native:** each record is an EVTX event, exposed as XML (`wevtutil qe Security /f:xml`, `Get-WinEvent … | .ToXml()`, Windows Event Forwarding):

```xml
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-Security-Auditing" Guid="{54849625-5478-4994-a5ba-3e3b0328c30d}" />
    <EventID>4624</EventID>
    <Version>2</Version>
    <Level>0</Level>
    <Task>12544</Task>
    <Opcode>0</Opcode>
    <Keywords>0x8020000000000000</Keywords>
    <TimeCreated SystemTime="2026-09-30T03:12:44.5174291Z" />
    <EventRecordID>8841207</EventRecordID>
    <Correlation ActivityID="{6a1e3b9c-2f4d-4e1a-9b7c-0d5e8f2a4c61}" />
    <Execution ProcessID="788" ThreadID="5212" />
    <Channel>Security</Channel>
    <Computer>SRV-APP02.nexacorp.local</Computer>
    <Security />
  </System>
  <EventData>
    <Data Name="SubjectUserSid">S-1-5-18</Data>
    <Data Name="TargetUserName">dana.levi</Data>
    <Data Name="LogonType">10</Data>
    <!-- … every Data element in the documented order … -->
  </EventData>
</Event>
```

Delivery paths: local `.evtx`; Windows Event Forwarding (WEC, `ForwardedEvents` channel — `Channel` stays `Security`); agents (Winlogbeat, NXLog, Splunk UF, Wazuh, AMA) that re-shape the record. Those agent shapes are **not** native.

**STANDARD FOR THIS PLATFORM — flat JSON, Windows names unchanged:**
- System keys we keep: `EventID` (int), `Computer` (FQDN), `TimeCreated` (the `SystemTime` attribute, ISO-8601 UTC, 7 fractional digits), `Channel`, `Provider` (the `Provider Name` attribute), `EventRecordID` (int), `Keywords` (hex string). Other System elements (`Version`, `Task`, `Level`, `Opcode`, `Execution`, `Correlation`) are omitted from samples.
- Then every `EventData/Data` element as `"<Name>": "<text>"`, in the documented order, **all values as strings** exactly as the XML holds them (`"LogonType": "3"`, `"Status": "0xc000006d"`, `"IpPort": "0"`).
- Empty values stay as Windows writes them: `"-"` for "not applicable", `"0x0"`, `"NULL SID"` (only in rendered text — XML holds `S-1-0-0`), `"{00000000-0000-0000-0000-000000000000}"`.
- `%%NNNN` placeholders stay as-is (`"FailureReason": "%%2313"`, `"ImpersonationLevel": "%%1833"`). They are expanded only in the rendered message; section 3.6 maps them.
- Hex casing follows the XML: NTSTATUS lowercase (`0xc000006d`), Kerberos codes `0x18`, `0x17`.
- No `winlog.*`, `event.code`, `data.win.eventdata.*`, `EventData.` prefix, and no camelCased names (`targetUserName`).
- 7045 comes from the **System** channel (`Provider`: `Service Control Manager`, `Keywords` `0x8080000000000000` — classic-event keyword, UNVERIFIED exact value).

---

## 3. Core field reference

### 3.1 Common Subject / Target fields

| Field | Meaning |
|---|---|
| `SubjectUserSid`, `SubjectUserName`, `SubjectDomainName`, `SubjectLogonId` | Account that **requested** the action (logged-on caller). For logon events this is usually the computer (`S-1-5-18`, `SRV-APP02$`). |
| `TargetUserSid`, `TargetUserName`, `TargetDomainName`, `TargetLogonId` | Account the action is **about** (the user who logged on, the account created/changed). |
| `TargetSid` | SID of a created/changed account or group (4720, 4722, 4724, 4728, 4738, 4740). |
| `LogonId` values | Hex (`0x3e7` = SYSTEM, `0x3e4` = NETWORK SERVICE, `0x3e5` = LOCAL SERVICE). Join `TargetLogonId` (4624) ↔ `SubjectLogonId` (4672, 4688, 4648, 4634) to follow one session. |
| `IpAddress`, `IpPort` | Source of the request. IPv4 on a DC is often `::ffff:10.20.30.40`. `-` / `0` = local. |
| `WorkstationName` / `Workstation` | NetBIOS name the client claims (4624/4625/4776). Client-supplied — can be spoofed or empty. |

### 3.2 EventData names per event (exact, in XML order)

| EventID (Task) | Logged on | Message | `Data Name` list |
|---|---|---|---|
| **4624** v2 (12544 Logon) | target host | An account was successfully logged on | `SubjectUserSid, SubjectUserName, SubjectDomainName, SubjectLogonId, TargetUserSid, TargetUserName, TargetDomainName, TargetLogonId, LogonType, LogonProcessName, AuthenticationPackageName, WorkstationName, LogonGuid, TransmittedServices, LmPackageName, KeyLength, ProcessId, ProcessName, IpAddress, IpPort, ImpersonationLevel, RestrictedAdminMode, TargetOutboundUserName, TargetOutboundDomainName, VirtualAccount, TargetLinkedLogonId, ElevatedToken` |
| **4625** v0 (12544) | target host | An account failed to log on | `SubjectUserSid, SubjectUserName, SubjectDomainName, SubjectLogonId, TargetUserSid, TargetUserName, TargetDomainName, Status, FailureReason, SubStatus, LogonType, LogonProcessName, AuthenticationPackageName, WorkstationName, TransmittedServices, LmPackageName, KeyLength, ProcessId, ProcessName, IpAddress, IpPort` |
| **4634** (12545 Logoff) | target host | An account was logged off | `TargetUserSid, TargetUserName, TargetDomainName, TargetLogonId, LogonType` |
| **4648** (12544) | source host | A logon was attempted using explicit credentials | `SubjectUserSid, SubjectUserName, SubjectDomainName, SubjectLogonId, LogonGuid, TargetUserName, TargetDomainName, TargetLogonGuid, TargetServerName, TargetInfo, ProcessId, ProcessName, IpAddress, IpPort` |
| **4672** (12548 Special Logon) | target host | Special privileges assigned to new logon | `SubjectUserSid, SubjectUserName, SubjectDomainName, SubjectLogonId, PrivilegeList` (here "Subject" = the user who just logged on) |
| **4688** v2 (13312 Process Creation) | host | A new process has been created | `SubjectUserSid, SubjectUserName, SubjectDomainName, SubjectLogonId, NewProcessId, NewProcessName, TokenElevationType, ProcessId, CommandLine, TargetUserSid, TargetUserName, TargetDomainName, TargetLogonId, ParentProcessName, MandatoryLabel` (`CommandLine` is empty unless "Include command line in process creation events" is enabled) |
| **4697** (12289 Security System Extension) | host | A service was installed in the system | `SubjectUserSid, SubjectUserName, SubjectDomainName, SubjectLogonId, ServiceName, ServiceFileName, ServiceType, ServiceStartType, ServiceAccount` (newer builds append `ClientProcessStartKey, ClientProcessId, ParentProcessId` — UNVERIFIED) |
| **4720** (13824 User Account Mgmt) | DC / host | A user account was created | `TargetUserName, TargetDomainName, TargetSid, SubjectUserSid, SubjectUserName, SubjectDomainName, SubjectLogonId, PrivilegeList, SamAccountName, DisplayName, UserPrincipalName, HomeDirectory, HomePath, ScriptPath, ProfilePath, UserWorkstations, PasswordLastSet, AccountExpires, PrimaryGroupId, AllowedToDelegateTo, OldUacValue, NewUacValue, UserAccountControl, UserParameters, SidHistory, LogonHours` |
| **4722** (13824) | DC / host | A user account was enabled | `TargetUserName, TargetDomainName, TargetSid, SubjectUserSid, SubjectUserName, SubjectDomainName, SubjectLogonId` |
| **4724** (13824) | DC / host | An attempt was made to reset an account's password | same 7 fields as 4722 (4723 = user changed own password) |
| **4738** (13824) | DC / host | A user account was changed | `Dummy, TargetUserName, TargetDomainName, TargetSid, SubjectUserSid, SubjectUserName, SubjectDomainName, SubjectLogonId, PrivilegeList, SamAccountName, DisplayName, UserPrincipalName, HomeDirectory, HomePath, ScriptPath, ProfilePath, UserWorkstations, PasswordLastSet, AccountExpires, PrimaryGroupId, AllowedToDelegateTo, OldUacValue, NewUacValue, UserAccountControl, UserParameters, SidHistory, LogonHours` — unchanged attributes are `-` |
| **4728 / 4732 / 4756** (13826 Security Group Mgmt) | DC (4732 also local SAM) | A member was added to a security-enabled **global** / **local** / **universal** group | `MemberName, MemberSid, TargetUserName, TargetDomainName, TargetSid, SubjectUserSid, SubjectUserName, SubjectDomainName, SubjectLogonId, PrivilegeList` (here `Target*` = the **group**; `MemberName` = DN of the added account, `-` for local SAM adds) |
| **4740** (13824) | DC (PDC emulator) | A user account was locked out | `TargetUserName, TargetDomainName, TargetSid, SubjectUserSid, SubjectUserName, SubjectDomainName, SubjectLogonId` — **`TargetDomainName` holds the "Caller Computer Name"** (the host that sent the bad passwords) |
| **4768** (14339 Kerberos Authentication Service) | DC | A Kerberos authentication ticket (TGT) was requested | Classic: `TargetUserName, TargetDomainName, TargetSid, ServiceName, ServiceSid, TicketOptions, Status, TicketEncryptionType, PreAuthType, IpAddress, IpPort, CertIssuerName, CertSerialNumber, CertThumbprint`. 2025+: `ResponseTicket, AccountSupportedEncryptionTypes, AccountAvailableKeys, ServiceSupportedEncryptionTypes, ServiceAvailableKeys, DCSupportedEncryptionTypes, DCAvailableKeys, ClientAdvertizedEncryptionTypes, SessionKeyEncryptionType, PreAuthEncryptionType` (names of the first and last UNVERIFIED — see §1) |
| **4769** (14337 Kerberos Service Ticket Operations) | DC | A Kerberos service ticket was requested | Classic: `TargetUserName, TargetDomainName, ServiceName, ServiceSid, TicketOptions, TicketEncryptionType, IpAddress, IpPort, Status, LogonGuid, TransmittedServices`. 2025+: `RequestTicketHash, ResponseTicketHash, AccountSupportedEncryptionTypes, AccountAvailableKeys, ServiceSupportedEncryptionTypes, ServiceAvailableKeys, DCSupportedEncryptionTypes, DCAvailableKeys, ClientAdvertizedEncryptionTypes, SessionKeyEncryptionType` (here `TargetUserName` = the **requesting** user as `user@REALM`) |
| **4771** (14339) | DC | Kerberos pre-authentication failed | `TargetUserName, TargetSid, ServiceName, TicketOptions, Status, PreAuthType, IpAddress, IpPort, CertIssuerName, CertSerialNumber, CertThumbprint` |
| **4776** (14336 Credential Validation) | DC (domain accts) or host (local accts) | The computer attempted to validate the credentials for an account | `PackageName, TargetUserName, Workstation, Status` (`PackageName` = `MICROSOFT_AUTHENTICATION_PACKAGE_V1_0`) |
| **4662** (14080 Directory Service Access) | DC | An operation was performed on an object | `SubjectUserSid, SubjectUserName, SubjectDomainName, SubjectLogonId, ObjectServer, ObjectType, ObjectName, OperationType, HandleId, AccessList, AccessMask, Properties, AdditionalInfo, AdditionalInfo2` (requires a SACL on the object and "Audit Directory Service Access") |
| **5136** (14081 Directory Service Changes) | DC | A directory service object was modified | `OpCorrelationID, AppCorrelationID, SubjectUserSid, SubjectUserName, SubjectDomainName, SubjectLogonId, DSName, DSType, ObjectDN, ObjectGUID, ObjectClass, AttributeLDAPDisplayName, AttributeSyntaxOID, AttributeValue, OperationType` |
| **7045** (System log) | host | A service was installed in the system | `ServiceName, ImagePath, ServiceType, StartType, AccountName` |

### 3.3 LogonType (4624 / 4625 / 4634)

| Value | Name | Typical source |
|---|---|---|
| 2 | Interactive | Console keyboard logon |
| 3 | Network | SMB share, `net use`, PsExec auth, WMI, most lateral movement |
| 4 | Batch | Scheduled task |
| 5 | Service | Service start under an account |
| 7 | Unlock | Workstation unlock |
| 8 | NetworkCleartext | Password sent in clear text to the server (IIS Basic authentication, some LDAP simple binds) |
| 9 | NewCredentials | `runas /netonly` (`LogonProcessName` `seclogo`) — classic pass-the-hash signal with `LogonType 9` + `seclogo` |
| 10 | RemoteInteractive | RDP / Terminal Services |
| 11 | CachedInteractive | Laptop logon with cached domain creds |
| 12 | CachedRemoteInteractive | RDP with cached creds (Microsoft-account scenarios) |
| 13 | CachedUnlock | Unlock with cached creds |
| 0 | System | Only for the SYSTEM account at boot |

### 3.4 Status / SubStatus codes

**4625 / 4776 (NTSTATUS):**

| Code | Meaning |
|---|---|
| `0xc000006d` | Generic logon failure (bad user name or auth info) — usual 4625 `Status`; detail is in `SubStatus` |
| `0xc000006a` | Correct user name, **wrong password** |
| `0xc0000064` | **User name does not exist** |
| `0xc0000234` | Account is **locked out** |
| `0xc0000072` | Account is disabled |
| `0xc000006f` | Logon outside allowed hours |
| `0xc0000070` | Logon from an unauthorised workstation |
| `0xc0000071` | Password expired |
| `0xc0000193` | Account expired |
| `0xc0000224` | User must change password at next logon |
| `0xc000015b` | Logon type not granted on this machine |
| `0xc0000133` | Clock skew between client and DC |
| `0xc0000413` | Authentication firewall — machine not allowed |
| `0x0` | Success (4776 success) |

**Kerberos result codes (4768 `Status`, 4769 `Status`, 4771 `Status`):**

| Code | Name | Meaning |
|---|---|---|
| `0x0` | — | Success |
| `0x6` | KDC_ERR_C_PRINCIPAL_UNKNOWN | User name not found (4768) — user enumeration |
| `0x7` | KDC_ERR_S_PRINCIPAL_UNKNOWN | SPN not found (4769) |
| `0xc` | KDC_ERR_POLICY | Logon restriction (workstation/hours) |
| `0xe` | KDC_ERR_ETYPE_NOTSUPP | No common encryption type (RC4 disabled scenarios) |
| `0x12` | KDC_ERR_CLIENT_REVOKED | Account disabled, expired or **locked out** |
| `0x17` | KDC_ERR_KEY_EXPIRED | Password expired |
| `0x18` | KDC_ERR_PREAUTH_FAILED | **Wrong password** (4771) |
| `0x19` | KDC_ERR_PREAUTH_REQUIRED | Pre-auth required (normal first round-trip; often not logged) |
| `0x1b` | KDC_ERR_MUST_USE_USER2USER | Server requires user-to-user |
| `0x1f` | KRB_AP_ERR_BAD_INTEGRITY | Integrity check failed (4769) |
| `0x20` | KRB_AP_ERR_TKT_EXPIRED | Ticket expired (4769, renewal) |
| `0x25` | KRB_AP_ERR_SKEW | Clock skew |

### 3.5 Kerberos encryption and pre-authentication

**`TicketEncryptionType` / `SessionKeyEncryptionType` (single etype):**

| Value | Etype | SOC meaning |
|---|---|---|
| `0x1` | DES-CBC-CRC | Disabled by default since Win7/2008 R2 — should never appear |
| `0x3` | DES-CBC-MD5 | Same |
| `0x11` | AES128-CTS-HMAC-SHA1-96 | Normal |
| `0x12` | AES256-CTS-HMAC-SHA1-96 | Normal (the modern default) |
| `0x13` / `0x14` | AES128-SHA256 / AES256-SHA384 | Newer etypes listed by Microsoft's Kerberos-Crypto scripts (Server 2025 era) |
| `0x17` | RC4-HMAC | **Kerberoasting / AS-REP roasting signal** when the account has AES keys and the client is modern |
| `0x18` | RC4-HMAC-EXP | Legacy export RC4 — should never appear |
| `0xffffffff` | — | Failure event, no ticket issued |
| `0x2d` | — | Appears as `SessionKeyEncryptionType` on the failure example in Microsoft's RC4 article (meaning UNVERIFIED) |

**`*SupportedEncryptionTypes` (bit mask, 2025 fields):** `0x4` RC4 only, `0x8` AES128, `0x10` AES256, `0x18` AES128+AES256, `0x1C` RC4+AES, `0x1F` DES+RC4+AES128+AES256, `0x27` DES+RC4+AES session-key bit (on Server 2022 and earlier the "processed" value always includes DES and RC4). Value format, from the Event Viewer screenshot in Microsoft's RC4 article (Server 2025-era DC, Jan 2025): `"0x27 (DES, RC4, AES-Sk)"`, `"0x1F (DES, RC4, AES128-SHA96, AES256-SHA96)"`; `*AvailableKeys` = `"AES-SHA1, RC4"`; `ClientAdvertizedEncryptionTypes` = a multi-line list (`AES256-CTS-HMAC-SHA1-96`, `RC4-HMAC-NT`, one per line — the exact whitespace in the XML is UNVERIFIED; we render `"\n\t\tAES256-CTS-HMAC-SHA1-96\n\t\tRC4-HMAC-NT"`); `SessionKeyEncryptionType` / `PreAuthEncryptionType` = `"0x12"`. A field is `"-"` when not populated (the `Account*` pair on most 4769s, everything on failures). `0x0` = not defined, so the KDC falls back to `DefaultDomainSupportedEncTypes`. The format of `RequestTicketHash` / `ResponseTicketHash` / `ResponseTicket` values is UNVERIFIED (we render a base64-looking hash string).

**`PreAuthType` (4768 / 4771):**

| Value | Name | Meaning |
|---|---|---|
| `0` | — | **Logon without pre-authentication** (account has "Do not require Kerberos preauthentication" = AS-REP roastable) |
| `2` | PA-ENC-TIMESTAMP | Standard password logon |
| `11` | PA-ETYPE-INFO | Sent by the KDC in KRB-ERROR only |
| `15` | PA-PK-AS-REP_OLD | Smart-card logon (old) |
| `16` | PA-PK-AS-REQ | Smart-card / certificate logon (PKINIT) — check `CertIssuerName`/`CertThumbprint` (ADCS abuse) |
| `17` | PA-PK-AS-REP | Smart-card logon |
| `19` | PA-ETYPE-INFO2 | Sent by the KDC in KRB-ERROR only |
| `20` | PA-SVR-REFERRAL-INFO | Referral |
| `138` | PA-ENCRYPTED-CHALLENGE | Kerberos armoring (FAST), Win 8 / 2012+ |
| `-` | — | Failure events where no pre-auth was processed |

**`TicketOptions` (hex flags):** `0x40810000` (Forwardable, Renewable, Canonicalize — the most common 4769 value), `0x40810010` (+ Renewable-ok), `0x60810010` (+ Forwarded). Rubeus/Impacket defaults often show `0x40800010` / `0x40810010` (do not use alone as a detection).

### 3.6 `%%NNNN` placeholders that appear in EventData

| Field | Raw value | Rendered |
|---|---|---|
| 4625 `FailureReason` | `%%2313` | Unknown user name or bad password |
| 4625 `FailureReason` | `%%2307` | Account locked out |
| 4625 `FailureReason` | `%%2310` | Account currently disabled |
| 4624 `ImpersonationLevel` | `%%1833` / `%%1832` / `%%1840` | Impersonation / Identification / Delegation |
| 4624 `ElevatedToken`, `VirtualAccount`, `RestrictedAdminMode` | `%%1842` / `%%1843` | Yes / No (`RestrictedAdminMode` is `-` unless logon type 10) |
| 4688 `TokenElevationType` | `%%1936` / `%%1937` / `%%1938` | Type 1 full token (UAC off or built-in admin) / Type 2 elevated ("Run as administrator") / Type 3 limited |
| 4662 `AccessList` | `%%7688` | Control Access (`AccessMask` `0x100`) |
| 4662 `OperationType` | `Object Access` | (plain text, not a placeholder) |
| 5136 `OperationType` | `%%14674` / `%%14675` | Value Added / Value Deleted |
| 4720/4738 `UserAccountControl` | `%%2080`… `%%2096` | One line per changed UAC flag (Microsoft's 4720 sample: `%%2080` Account Disabled, `%%2082` 'Password Not Required' – Enabled, `%%2084` 'Normal Account' – Enabled; codes for other flags, e.g. "Don't Require Preauth", UNVERIFIED) |
| 4720/4738 `PasswordLastSet`, `AccountExpires` | `%%1794` | `<never>` |
| 4720/4738 `UserParameters` | `%%1793` | `<value not set>` |
| 4720/4738 `LogonHours` | `%%1797` | All |
| 5136 `DSType` | `%%14676` | Active Directory Domain Services |

### 3.7 4662 GUIDs and System `Keywords`

| GUID in 4662 `Properties` | Meaning |
|---|---|
| `{1131f6aa-9c07-11d1-f79f-00c04fc2dcd2}` | DS-Replication-Get-Changes |
| `{1131f6ad-9c07-11d1-f79f-00c04fc2dcd2}` | DS-Replication-Get-Changes-All (needed to pull password hashes — **DCSync**) |
| `{89e95b76-444d-4c62-991a-0facbeda640c}` | DS-Replication-Get-Changes-In-Filtered-Set |
| `{19195a5b-6da0-11d0-afd3-00c04fd930c9}` | `domainDNS` object class (the domain head — appears in `ObjectType` and `Properties`) |

| `Keywords` | Meaning |
|---|---|
| `0x8020000000000000` | Audit Success |
| `0x8010000000000000` | Audit Failure (4625, 4771, failed 4768/4769, failed 4776) |
| `0x8080000000000000` | Classic System-log keyword used on 7045 (UNVERIFIED exact value) |

---

## 4. Samples (fictitious domain `NEXACORP` / `nexacorp.local`; private 10.20.0.0/16 addressing)

Shared values (2026-09-30, UTC). Domain SID `S-1-5-21-3623811015-3361044348-30300820`. DC `DC01.nexacorp.local` (10.20.0.10, PDC emulator). Compromised workstation `WKS-MKT-12` (10.20.14.88, user `amit.peretz`, RID 1544). File server `FS01`. SQL server `SQL01` (10.20.3.15). Domain admin `adm.yoav` (RID 1102). Kerberoastable service account `svc_mssql` (RID 1607). AS-REP-roastable account `svc_scanner` (RID 1712, "Do not require Kerberos preauthentication" set). Normal business hours 07:00–19:00 Israel time (04:00–16:00 UTC).

### 4.1 4625 — repeated NTLM network logon failures against the file server (wrong password)

```json
{
  "EventID": 4625,
  "Computer": "FS01.nexacorp.local",
  "TimeCreated": "2026-09-30T01:47:12.3816620Z",
  "Channel": "Security",
  "Provider": "Microsoft-Windows-Security-Auditing",
  "EventRecordID": 2210457,
  "Keywords": "0x8010000000000000",
  "SubjectUserSid": "S-1-0-0",
  "SubjectUserName": "-",
  "SubjectDomainName": "-",
  "SubjectLogonId": "0x0",
  "TargetUserSid": "S-1-0-0",
  "TargetUserName": "adm.yoav",
  "TargetDomainName": "NEXACORP",
  "Status": "0xc000006d",
  "FailureReason": "%%2313",
  "SubStatus": "0xc000006a",
  "LogonType": "3",
  "LogonProcessName": "NtLmSsp ",
  "AuthenticationPackageName": "NTLM",
  "WorkstationName": "WKS-MKT-12",
  "TransmittedServices": "-",
  "LmPackageName": "-",
  "KeyLength": "0",
  "ProcessId": "0x0",
  "ProcessName": "-",
  "IpAddress": "10.20.14.88",
  "IpPort": "51544"
}
```
*One of 38 failures for `adm.yoav` from `10.20.14.88` between 01:46 and 01:49. `SubStatus 0xc000006a` = the account exists and the password is wrong (`0xc0000064` would mean the user name doesn't exist). `LogonProcessName` really has a trailing space (`"NtLmSsp "`). `TargetUserSid` is `S-1-0-0` (NULL SID) on failures. A marketing workstation guessing a domain admin's password at 04:47 local time is not a typo.*

### 4.2 4776 — the DC validates the same NTLM attempt

```json
{
  "EventID": 4776,
  "Computer": "DC01.nexacorp.local",
  "TimeCreated": "2026-09-30T01:47:12.3794018Z",
  "Channel": "Security",
  "Provider": "Microsoft-Windows-Security-Auditing",
  "EventRecordID": 15738802,
  "Keywords": "0x8010000000000000",
  "PackageName": "MICROSOFT_AUTHENTICATION_PACKAGE_V1_0",
  "TargetUserName": "adm.yoav",
  "Workstation": "WKS-MKT-12",
  "Status": "0xc000006a"
}
```
*4776 has no IP field — the `Workstation` name is all you get, and the client supplies it. Pair it with 4625 on the member server (same second, same user) to recover the source IP.*

### 4.3 4740 — the account locks out on the PDC emulator

```json
{
  "EventID": 4740,
  "Computer": "DC01.nexacorp.local",
  "TimeCreated": "2026-09-30T01:49:03.0127745Z",
  "Channel": "Security",
  "Provider": "Microsoft-Windows-Security-Auditing",
  "EventRecordID": 15738961,
  "Keywords": "0x8020000000000000",
  "TargetUserName": "adm.yoav",
  "TargetDomainName": "WKS-MKT-12",
  "TargetSid": "S-1-5-21-3623811015-3361044348-30300820-1102",
  "SubjectUserSid": "S-1-5-18",
  "SubjectUserName": "DC01$",
  "SubjectDomainName": "NEXACORP",
  "SubjectLogonId": "0x3e7"
}
```
*`TargetDomainName` here is the **Caller Computer Name** — the machine that sent the bad passwords — not a domain. 4740 is an Audit **Success** event (the lockout action succeeded). After this, 4625s for the same user switch to `SubStatus 0xc0000234` and 4771/4768 to `0x12`.*

### 4.4 4771 — Kerberos pre-authentication failure (password spray over Kerberos)

```json
{
  "EventID": 4771,
  "Computer": "DC01.nexacorp.local",
  "TimeCreated": "2026-09-30T01:58:40.7731904Z",
  "Channel": "Security",
  "Provider": "Microsoft-Windows-Security-Auditing",
  "EventRecordID": 15739540,
  "Keywords": "0x8010000000000000",
  "TargetUserName": "ron.shapiro",
  "TargetSid": "S-1-5-21-3623811015-3361044348-30300820-1388",
  "ServiceName": "krbtgt/NEXACORP.LOCAL",
  "TicketOptions": "0x40810010",
  "Status": "0x18",
  "PreAuthType": "2",
  "IpAddress": "::ffff:10.20.14.88",
  "IpPort": "52871",
  "CertIssuerName": "",
  "CertSerialNumber": "",
  "CertThumbprint": ""
}
```
*Spray signature: the same `IpAddress` produces `0x18` for 60+ different `TargetUserName` values, one attempt each, in a few minutes. `0x18` = wrong password; `0x6` (in 4768) would be a non-existent user. Kerberos sprays leave **no** 4625 on member servers — only 4771 on the DC.*

### 4.5 4688 — unknown binary launched from a public folder just before the ticket burst (command-line auditing enabled)

```json
{
  "EventID": 4688,
  "Computer": "WKS-MKT-12.nexacorp.local",
  "TimeCreated": "2026-09-30T02:05:17.9930412Z",
  "Channel": "Security",
  "Provider": "Microsoft-Windows-Security-Auditing",
  "EventRecordID": 774120,
  "Keywords": "0x8020000000000000",
  "SubjectUserSid": "S-1-5-21-3623811015-3361044348-30300820-1544",
  "SubjectUserName": "amit.peretz",
  "SubjectDomainName": "NEXACORP",
  "SubjectLogonId": "0x5d2e1a",
  "NewProcessId": "0x2f6c",
  "NewProcessName": "C:\\Users\\Public\\Music\\wmsync.exe",
  "TokenElevationType": "%%1938",
  "ProcessId": "0x1b48",
  "CommandLine": "\"C:\\Users\\Public\\Music\\wmsync.exe\" /s /o C:\\Users\\Public\\Music\\h.txt",
  "TargetUserSid": "S-1-0-0",
  "TargetUserName": "-",
  "TargetDomainName": "-",
  "TargetLogonId": "0x0",
  "ParentProcessName": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
  "MandatoryLabel": "S-1-16-8192"
}
```
*An unsigned binary in `C:\Users\Public\Music` writing an output file next to itself, started from PowerShell, at medium integrity (`S-1-16-8192`, `%%1938` = limited token). No admin rights are needed for Kerberoasting. `ProcessId` is the **parent's** PID; `NewProcessId` is the child's. The `Target*` fields are only filled when the process runs as a different user.*

### 4.6 4769 — service ticket requested with RC4 for a SQL service account (Kerberoasting)

```json
{
  "EventID": 4769,
  "Computer": "DC01.nexacorp.local",
  "TimeCreated": "2026-09-30T02:05:19.2084471Z",
  "Channel": "Security",
  "Provider": "Microsoft-Windows-Security-Auditing",
  "EventRecordID": 15739912,
  "Keywords": "0x8020000000000000",
  "TargetUserName": "amit.peretz@NEXACORP.LOCAL",
  "TargetDomainName": "NEXACORP.LOCAL",
  "ServiceName": "svc_mssql",
  "ServiceSid": "S-1-5-21-3623811015-3361044348-30300820-1607",
  "TicketOptions": "0x40810000",
  "TicketEncryptionType": "0x17",
  "IpAddress": "::ffff:10.20.14.88",
  "IpPort": "52990",
  "Status": "0x0",
  "LogonGuid": "{8c5e2f1a-7b3d-4e9a-b0c4-1d6f3a8e2b75}",
  "TransmittedServices": "-",
  "RequestTicketHash": "q3V0dW1fZXhhbXBsZV9yZXF1ZXN0X3RpY2tldA==",
  "ResponseTicketHash": "c3ZjX21zc3FsX3Jlc3BvbnNlX3RpY2tldF8wMQ==",
  "AccountSupportedEncryptionTypes": "-",
  "AccountAvailableKeys": "-",
  "ServiceSupportedEncryptionTypes": "0x4 (RC4)",
  "ServiceAvailableKeys": "RC4",
  "DCSupportedEncryptionTypes": "0x1F (DES, RC4, AES128-SHA96, AES256-SHA96)",
  "DCAvailableKeys": "AES-SHA1, RC4",
  "ClientAdvertizedEncryptionTypes": "\n\t\tRC4-HMAC-NT",
  "SessionKeyEncryptionType": "0x17"
}
```
*Three things make this Kerberoasting: (1) `TicketEncryptionType 0x17` (RC4) from a modern Windows 11 client, (2) `ClientAdvertizedEncryptionTypes` lists **only** `RC4-HMAC-NT` — a normal Windows client advertises AES first (`/rc4opsec` forces RC4), (3) `ServiceName` is a **user** account with an SPN (no `$`), and the same client requests tickets for 14 different SPN accounts within 3 seconds. `ServiceSupportedEncryptionTypes 0x4 (RC4)` / `ServiceAvailableKeys RC4` explain why the DC agreed: the account's password predates AES keys. Remediation is a long random password reset (which also creates AES keys). The hash-field values are illustrative (format UNVERIFIED); the 2025 fields only exist on patched DCs — on older DCs the event ends at `TransmittedServices`.*

### 4.7 4768 — TGT issued without pre-authentication (AS-REP roasting)

```json
{
  "EventID": 4768,
  "Computer": "DC01.nexacorp.local",
  "TimeCreated": "2026-09-30T02:06:02.6650139Z",
  "Channel": "Security",
  "Provider": "Microsoft-Windows-Security-Auditing",
  "EventRecordID": 15739977,
  "Keywords": "0x8020000000000000",
  "TargetUserName": "svc_scanner",
  "TargetDomainName": "NEXACORP.LOCAL",
  "TargetSid": "S-1-5-21-3623811015-3361044348-30300820-1712",
  "ServiceName": "krbtgt",
  "ServiceSid": "S-1-5-21-3623811015-3361044348-30300820-502",
  "TicketOptions": "0x40800010",
  "Status": "0x0",
  "TicketEncryptionType": "0x17",
  "PreAuthType": "0",
  "IpAddress": "::ffff:10.20.14.88",
  "IpPort": "53022",
  "CertIssuerName": "",
  "CertSerialNumber": "",
  "CertThumbprint": "",
  "ResponseTicket": "c3ZjX3NjYW5uZXJfYXNyZXBfdGlja2V0X2hhc2g=",
  "AccountSupportedEncryptionTypes": "0x27 (DES, RC4, AES-Sk)",
  "AccountAvailableKeys": "AES-SHA1, RC4",
  "ServiceSupportedEncryptionTypes": "0x1F (DES, RC4, AES128-SHA96, AES256-SHA96)",
  "ServiceAvailableKeys": "AES-SHA1, RC4",
  "DCSupportedEncryptionTypes": "0x1F (DES, RC4, AES128-SHA96, AES256-SHA96)",
  "DCAvailableKeys": "AES-SHA1, RC4",
  "ClientAdvertizedEncryptionTypes": "\n\t\tRC4-HMAC-NT",
  "SessionKeyEncryptionType": "0x17",
  "PreAuthEncryptionType": "-"
}
```
*`PreAuthType "0"` + `Status "0x0"` = the KDC handed out a TGT encrypted with the user's key without proof of the password. The attacker cracks the AS-REP offline. RC4 is chosen because the client advertised only RC4. Normal logons show `PreAuthType 2` (password) or `138` (armoring) and `0x12`. Fix: clear "Do not require Kerberos preauthentication" on `svc_scanner` (UAC flag `DONT_REQ_PREAUTH`, 0x400000) and reset its password. Note Server 2025 DCs refuse to issue RC4 TGTs; this DC is Server 2022 with the January 2025+ CU. The `ResponseTicket` / `PreAuthEncryptionType` names and value formats are UNVERIFIED (index-consistent, see §1).*

### 4.8 4624 — the cracked service account logs on over RDP at night (LogonType 10)

```json
{
  "EventID": 4624,
  "Computer": "SQL01.nexacorp.local",
  "TimeCreated": "2026-09-30T03:12:44.5174291Z",
  "Channel": "Security",
  "Provider": "Microsoft-Windows-Security-Auditing",
  "EventRecordID": 3381906,
  "Keywords": "0x8020000000000000",
  "SubjectUserSid": "S-1-5-18",
  "SubjectUserName": "SQL01$",
  "SubjectDomainName": "NEXACORP",
  "SubjectLogonId": "0x3e7",
  "TargetUserSid": "S-1-5-21-3623811015-3361044348-30300820-1607",
  "TargetUserName": "svc_mssql",
  "TargetDomainName": "NEXACORP",
  "TargetLogonId": "0x8a3f21c",
  "LogonType": "10",
  "LogonProcessName": "User32 ",
  "AuthenticationPackageName": "Negotiate",
  "WorkstationName": "WKS-MKT-12",
  "LogonGuid": "{3e9b1c7d-5a2f-4d8e-91b6-0c4a7f2e5d18}",
  "TransmittedServices": "-",
  "LmPackageName": "-",
  "KeyLength": "0",
  "ProcessId": "0x2c8",
  "ProcessName": "C:\\Windows\\System32\\winlogon.exe",
  "IpAddress": "10.20.14.88",
  "IpPort": "0",
  "ImpersonationLevel": "%%1833",
  "RestrictedAdminMode": "%%1843",
  "TargetOutboundUserName": "-",
  "TargetOutboundDomainName": "-",
  "VirtualAccount": "%%1843",
  "TargetLinkedLogonId": "0x8a3f1f0",
  "ElevatedToken": "%%1842"
}
```
*A service account should log on as `LogonType 5` (service) on its own server — never interactively over RDP (`10`) from a marketing workstation at 06:12 local time. `ElevatedToken %%1842` (Yes) means the account is a local administrator on SQL01; the pair `TargetLogonId` / `TargetLinkedLogonId` is the elevated/filtered split token. Follow `TargetLogonId 0x8a3f21c` into 4672, 4688 and 4634 on SQL01.*

### 4.9 4672 — special privileges assigned to that logon

```json
{
  "EventID": 4672,
  "Computer": "SQL01.nexacorp.local",
  "TimeCreated": "2026-09-30T03:12:44.5175102Z",
  "Channel": "Security",
  "Provider": "Microsoft-Windows-Security-Auditing",
  "EventRecordID": 3381907,
  "Keywords": "0x8020000000000000",
  "SubjectUserSid": "S-1-5-21-3623811015-3361044348-30300820-1607",
  "SubjectUserName": "svc_mssql",
  "SubjectDomainName": "NEXACORP",
  "SubjectLogonId": "0x8a3f21c",
  "PrivilegeList": "SeSecurityPrivilege\n\t\t\tSeBackupPrivilege\n\t\t\tSeRestorePrivilege\n\t\t\tSeTakeOwnershipPrivilege\n\t\t\tSeDebugPrivilege\n\t\t\tSeSystemEnvironmentPrivilege\n\t\t\tSeLoadDriverPrivilege\n\t\t\tSeImpersonatePrivilege\n\t\t\tSeDelegateSessionUserImpersonatePrivilege"
}
```
*4672 follows 4624 within the same millisecond and has the **same LogonId** (`SubjectLogonId` here = `TargetLogonId` in 4624). `SeDebugPrivilege` is what LSASS-dumping tools need. 4672 for a non-admin-tier account on a server is worth a look on its own. `PrivilegeList` entries are separated by newline + tabs in the XML.*

### 4.10 7045 (System log) — a new service is installed on SQL01

```json
{
  "EventID": 7045,
  "Computer": "SQL01.nexacorp.local",
  "TimeCreated": "2026-09-30T03:18:09.1046633Z",
  "Channel": "System",
  "Provider": "Service Control Manager",
  "EventRecordID": 412377,
  "Keywords": "0x8080000000000000",
  "ServiceName": "WinSysMonSvc",
  "ImagePath": "C:\\Windows\\Temp\\wsysmon.exe -k netsvc",
  "ServiceType": "user mode service",
  "StartType": "auto start",
  "AccountName": "LocalSystem"
}
```
*Persistence / execution as SYSTEM: a service whose binary lives in `C:\Windows\Temp`, set to auto start, running as `LocalSystem`, created 6 minutes after a suspicious RDP logon. 7045 has no "who" field; the installer is found through the Security-log twin **4697** (if "Audit Security System Extension" is enabled) or through 4688 (`sc.exe create …`) in the same `SubjectLogonId`. A random 8-character `ServiceName` with `ImagePath` `%COMSPEC% /c …` or `\\127.0.0.1\ADMIN$\…` is the PsExec/Impacket/Cobalt Strike pattern.*

**The same installation as 4697 (Security log)** — only the fields that differ from the 7045 shape:

| Field | Value |
|---|---|
| `EventID` / `Channel` / `Provider` / `Keywords` | `4697` / `Security` / `Microsoft-Windows-Security-Auditing` / `0x8020000000000000` |
| `SubjectUserSid` / `SubjectUserName` / `SubjectDomainName` / `SubjectLogonId` | `S-1-5-21-3623811015-3361044348-30300820-1607` / `svc_mssql` / `NEXACORP` / `0x8a3f21c` |
| `ServiceName` | `WinSysMonSvc` |
| `ServiceFileName` | `C:\Windows\Temp\wsysmon.exe -k netsvc` |
| `ServiceType` | `0x10` (own process) — numeric here, text in 7045 |
| `ServiceStartType` | `2` (auto start; `3` = demand, `4` = disabled) |
| `ServiceAccount` | `LocalSystem` |

### 4.11 4720 — backdoor account created with the stolen domain-admin credentials

```json
{
  "EventID": 4720,
  "Computer": "DC01.nexacorp.local",
  "TimeCreated": "2026-09-30T03:31:26.4410937Z",
  "Channel": "Security",
  "Provider": "Microsoft-Windows-Security-Auditing",
  "EventRecordID": 15744318,
  "Keywords": "0x8020000000000000",
  "TargetUserName": "svc_backup2",
  "TargetDomainName": "NEXACORP",
  "TargetSid": "S-1-5-21-3623811015-3361044348-30300820-1823",
  "SubjectUserSid": "S-1-5-21-3623811015-3361044348-30300820-1102",
  "SubjectUserName": "adm.yoav",
  "SubjectDomainName": "NEXACORP",
  "SubjectLogonId": "0x1c44a90",
  "PrivilegeList": "-",
  "SamAccountName": "svc_backup2",
  "DisplayName": "svc_backup2",
  "UserPrincipalName": "svc_backup2@nexacorp.local",
  "HomeDirectory": "-",
  "HomePath": "-",
  "ScriptPath": "-",
  "ProfilePath": "-",
  "UserWorkstations": "-",
  "PasswordLastSet": "%%1794",
  "AccountExpires": "%%1794",
  "PrimaryGroupId": "513",
  "AllowedToDelegateTo": "-",
  "OldUacValue": "0x0",
  "NewUacValue": "0x15",
  "UserAccountControl": "\n\t\t%%2080\n\t\t%%2082\n\t\t%%2084",
  "UserParameters": "%%1793",
  "SidHistory": "-",
  "LogonHours": "%%1797"
}
```
*Account creation by `adm.yoav` at 06:31 local, through a logon session (`SubjectLogonId 0x1c44a90`) that started from SQL01 — where `adm.yoav`'s credentials were in LSASS memory. A new account is born **disabled** (`%%2080`, NewUacValue `0x15`), so the full creation sequence is 4720 → **4722** (enabled) → **4724** (password set) → **4738** (changed: `UserAccountControl` shows `%%2080` removed, `PasswordLastSet` updated) within seconds. `%%1794` = `<never>`, `%%1793` = `<value not set>`, `%%1797` = `All` (logon hours). Name chosen to blend in with real `svc_backup`.*

### 4.12 4728 — the new account is added to Domain Admins (global group)

```json
{
  "EventID": 4728,
  "Computer": "DC01.nexacorp.local",
  "TimeCreated": "2026-09-30T03:32:02.9073318Z",
  "Channel": "Security",
  "Provider": "Microsoft-Windows-Security-Auditing",
  "EventRecordID": 15744371,
  "Keywords": "0x8020000000000000",
  "MemberName": "CN=svc_backup2,OU=Service Accounts,DC=nexacorp,DC=local",
  "MemberSid": "S-1-5-21-3623811015-3361044348-30300820-1823",
  "TargetUserName": "Domain Admins",
  "TargetDomainName": "NEXACORP",
  "TargetSid": "S-1-5-21-3623811015-3361044348-30300820-512",
  "SubjectUserSid": "S-1-5-21-3623811015-3361044348-30300820-1102",
  "SubjectUserName": "adm.yoav",
  "SubjectDomainName": "NEXACORP",
  "SubjectLogonId": "0x1c44a90",
  "PrivilegeList": "-"
}
```
*Here `Target*` is the **group** and `Member*` is the account added. The privileged-group RIDs to alert on: `-512` Domain Admins, `-519` Enterprise Admins (universal → **4756**), `-518` Schema Admins (universal → 4756), `S-1-5-32-544` Administrators (domain-local/builtin → **4732**), `-520` Group Policy Creator Owners, `S-1-5-32-548` Account Operators. Removal events are 4729 / 4733 / 4757.*

### 4.13 5136 — a GPO is linked to the domain root (staging for domain-wide execution)

```json
{
  "EventID": 5136,
  "Computer": "DC01.nexacorp.local",
  "TimeCreated": "2026-09-30T03:36:47.1180254Z",
  "Channel": "Security",
  "Provider": "Microsoft-Windows-Security-Auditing",
  "EventRecordID": 15744690,
  "Keywords": "0x8020000000000000",
  "OpCorrelationID": "{a7c3e915-2b6d-4f08-9e1a-5d4c8b0f3e27}",
  "AppCorrelationID": "-",
  "SubjectUserSid": "S-1-5-21-3623811015-3361044348-30300820-1823",
  "SubjectUserName": "svc_backup2",
  "SubjectDomainName": "NEXACORP",
  "SubjectLogonId": "0x1d0f6b2",
  "DSName": "nexacorp.local",
  "DSType": "%%14676",
  "ObjectDN": "DC=nexacorp,DC=local",
  "ObjectGUID": "{5e1f0a3b-8c2d-4b7e-a619-3f0d2c8e4a71}",
  "ObjectClass": "domainDNS",
  "AttributeLDAPDisplayName": "gPLink",
  "AttributeSyntaxOID": "2.5.5.12",
  "AttributeValue": "[LDAP://cn={31B2F340-016D-11D2-945F-00C04FB984F9},cn=policies,cn=system,DC=nexacorp,DC=local;0][LDAP://cn={9D4F2A61-3C7E-4B18-A05D-6E2B8F1C7D94},cn=policies,cn=system,DC=nexacorp,DC=local;0]",
  "OperationType": "%%14674"
}
```
*A change to one attribute produces **two** 5136 events with the same `OpCorrelationID`: `%%14675` (Value Deleted, the old `gPLink`) and `%%14674` (Value Added, the new one shown here). The new value adds a second GPO `{9D4F2A61-…}` to the whole domain, created minutes earlier (5137 on its `groupPolicyContainer`). Ransomware crews use exactly this to push a scheduled task or startup script to every machine. `DSType %%14676` = Active Directory Domain Services. 5136 needs "Audit Directory Service Changes" plus a SACL on the object.*

### 4.14 4662 — directory replication rights used by a non-DC account (DCSync)

```json
{
  "EventID": 4662,
  "Computer": "DC01.nexacorp.local",
  "TimeCreated": "2026-09-30T03:40:15.6627019Z",
  "Channel": "Security",
  "Provider": "Microsoft-Windows-Security-Auditing",
  "EventRecordID": 15744955,
  "Keywords": "0x8020000000000000",
  "SubjectUserSid": "S-1-5-21-3623811015-3361044348-30300820-1823",
  "SubjectUserName": "svc_backup2",
  "SubjectDomainName": "NEXACORP",
  "SubjectLogonId": "0x1d0f6b2",
  "ObjectServer": "DS",
  "ObjectType": "%{19195a5b-6da0-11d0-afd3-00c04fd930c9}",
  "ObjectName": "%{5e1f0a3b-8c2d-4b7e-a619-3f0d2c8e4a71}",
  "OperationType": "Object Access",
  "HandleId": "0x0",
  "AccessList": "%%7688\r\n\t\t\t\t",
  "AccessMask": "0x100",
  "Properties": "%%7688\r\n\t\t{1131f6ad-9c07-11d1-f79f-00c04fc2dcd2}\r\n\t{19195a5b-6da0-11d0-afd3-00c04fd930c9}\r\n",
  "AdditionalInfo": "-",
  "AdditionalInfo2": ""
}
```
*`1131f6ad-…` = DS-Replication-Get-Changes-**All**: the right to pull password hashes (including `krbtgt`). A DCSync usually logs a pair of 4662s within a second (`1131f6aa-…` and `1131f6ad-…`, sometimes `89e95b76-…`). Domain controllers (`DC01$`, `DC02$`) and Entra Connect's `MSOL_…` sync account do this legitimately; **any other `SubjectUserName`** is DCSync (Mimikatz `lsadump::dcsync`, Impacket `secretsdump`). `ObjectName` is the GUID of the domain head object (same as `ObjectGUID` in 4.13). Pivot `SubjectLogonId` to the 4624 on DC01 to find the source IP. The exact tab/CRLF padding inside `AccessList` / `Properties` follows Microsoft's documented sample and may vary.*

---

## 5. Investigation notes (pivots)

- **LogonId is the session key.** `TargetLogonId` in 4624 = `SubjectLogonId` in 4672, 4688, 4648, 4697, 4720/4728/5136 (when the action ran on that host) and `TargetLogonId` in 4634. Note LogonIds are unique **per computer** only — never join them across hosts.
- **Where each event lives:** logons (4624/4625/4634/4648/4672) and process/service events (4688/4697/7045) are on the **host** the user reached. Kerberos (4768/4769/4771), NTLM validation for domain accounts (4776), lockouts (4740, on the PDC emulator), account/group changes (4720…4756), 4662 and 5136 are on **domain controllers**. A complete picture needs both.
- **Failure triage:** 4625 `SubStatus` (`0xc000006a` wrong password vs `0xc0000064` no such user vs `0xc0000234` locked) and 4771/4768 `Status` (`0x18` vs `0x6` vs `0x12`). Many users × one source = spray. One user × many attempts = brute force. Lockout source = 4740 `TargetDomainName` (caller computer).
- **NTLM vs Kerberos path:** NTLM failures show 4625 on the server + 4776 on the DC; Kerberos failures show only 4771 on the DC. Attackers spraying via Kerberos to avoid 4625 still hit 4771.
- **Kerberoasting:** 4769 with `TicketEncryptionType 0x17`, `ServiceName` not ending in `$` and not `krbtgt`, `Status 0x0`, many distinct `ServiceName` values from one `IpAddress` in seconds. On patched DCs, `ClientAdvertizedEncryptionTypes` containing only RC4 and `ServiceAvailableKeys` lacking AES confirm it. Join the source IP to 4688 on that host (tool command line).
- **AS-REP roasting:** 4768 with `PreAuthType 0` and `Status 0x0` — list every account with `DONT_REQ_PREAUTH` and treat each such event as suspicious.
- **Logon type tells the story:** a service account with `LogonType 10` or `2`, an admin account with `LogonType 3` from a workstation tier it never uses, `LogonType 9` + `LogonProcessName seclogo` (pass-the-hash via `runas /netonly`-style token), `AuthenticationPackageName NTLM` for an account that normally uses Kerberos.
- **Explicit credentials (4648):** on the **source** host, `TargetUserName` + `TargetServerName` show which credentials were typed or injected to reach which server (runas, PsExec with `-u`, scheduled-task creation). Pair with 4624 type 3 on `TargetServerName`.
- **Privilege use:** 4672 right after 4624 = admin-equivalent logon. Unexpected `SeDebugPrivilege` / `SeTcbPrivilege` holders deserve review.
- **Persistence:** 7045/4697 with `ImagePath` outside `System32`/`Program Files`, `%COMSPEC%`, `powershell -enc`, `\\127.0.0.1\ADMIN$`, or random names. Correlate with 4624 type 3 from the same source (remote service creation).
- **Account manipulation chain:** 4720 → 4722 → 4724 → 4738 → 4728/4732/4756. Alert on any add to a privileged group (RIDs in 4.12) and verify against a change ticket.
- **DCSync:** 4662 with `AccessMask 0x100` and `Properties` containing `1131f6ad-…` / `1131f6aa-…` / `89e95b76-…` from a `SubjectUserName` that is not a DC computer account or the documented sync account.
- **AD object tampering:** 5136 — group the `%%14675`/`%%14674` pair by `OpCorrelationID` to get the before/after values (`gPLink`, `servicePrincipalName`, `msDS-AllowedToActOnBehalfOfOtherIdentity`, `userAccountControl`, `member`).
- **Time:** `TimeCreated` is UTC. Convert to the site's local time before judging "outside business hours" (03:12Z = 06:12 Israel summer time).
- **Chain to teach (this card):** 4625 ×38 + 4776 → 4740 → 4771 spray → 4688 unknown binary → 4769 RC4 ×14 → 4768 PreAuthType 0 → 4624 type 10 (svc_mssql) + 4672 → 7045/4697 → (LSASS dump) → 4720 → 4728 Domain Admins → 5136 gPLink → 4662 DCSync.

---

## 6. Common mistakes / fields that do NOT exist

**Do NOT use these (not in the native event):**
- SIEM/agent shapes: `winlog.event_data.*`, `winlog.event_id`, `event.code`, `data.win.eventdata.*`, `data.win.system.*`, `EventData.TargetUserName`, `win.eventdata.*`, `user.name`, `source.ip`. These come from Winlogbeat / Wazuh / ECS.
- camelCase or snake_case names: `targetUserName`, `logon_type`, `ipAddress`. Windows names are PascalCase exactly as listed in 3.2 (`IpAddress`, not `IPAddress`; `TargetUserName`, not `TargetUsername`; `LogonType`, not `Logon_Type`).
- Invented fields: `SourceIp`, `SourceAddress`, `ClientIP` (the field is `IpAddress`), `UserName` (use `SubjectUserName` / `TargetUserName`), `Domain`, `FailureCode` (4769/4768 use `Status` in the XML; "Failure Code" / "Result Code" are only the rendered labels), `LogonTypeName`, `ProcessCommandLine` (the field is `CommandLine`), `ParentProcessId` in 4688 (4688 has `ProcessId` = the parent PID and `ParentProcessName`; there is no `ParentProcessId`), `Hashes` / `Image` / `ParentImage` (those are **Sysmon** fields, not Security-log fields), `ServiceFileName` in 7045 (that's 4697; 7045 uses `ImagePath`), `ImagePath` in 4697.
- `SourceWorkstation` on 4776: the field is `Workstation`. 4776 has no IP field at all.
- 4771 has **no** `TargetDomainName`, `TicketEncryptionType` or `LogonGuid` — don't copy 4768's list.
- 4740 has no `CallerComputerName` key — the caller name sits in `TargetDomainName`.
- 2025 Kerberos fields on events from unpatched or pre-2019 DCs, or on 4771 / 4776 (they exist only on 4768 and 4769).

**Value mistakes:**
- Numeric JSON values for EventData (`"LogonType": 3`). XML holds text; keep strings (`"3"`). Only our System keys `EventID` and `EventRecordID` are numbers.
- Expanded text where the XML has a placeholder (`"FailureReason": "Unknown user name or bad password"` — the raw value is `%%2313`), and vice versa.
- Uppercase NTSTATUS hex (`0xC000006A`). The XML uses lowercase (`0xc000006a`); upper case is only seen in docs and rendered text.
- `TicketEncryptionType "RC4"` or `"23"`. It is hex text: `"0x17"`.
- `IpAddress "10.20.14.88"` on a DC Kerberos event — DCs usually log the IPv4-mapped form `"::ffff:10.20.14.88"`. Member-server 4624/4625 use plain IPv4.
- 4625 with a real `TargetUserSid` — on failures it is `S-1-0-0`.
- 4624 `LogonProcessName "NtLmSsp"` / `"User32"` without the trailing space that Windows writes (`"NtLmSsp "`, `"User32 "`, `"Kerberos"` has none).
- `Channel "Security"` on 7045 — it is the **System** log, provider `Service Control Manager`.
- 4728 for Enterprise/Schema Admins (those are universal groups → 4756) or for the builtin `Administrators` group (domain-local → 4732).
- `PreAuthType "0"` with `Status "0x18"`. A pre-auth failure (`0x18`) needs pre-auth data (`PreAuthType 2`), and `0` means "no pre-authentication was required".
