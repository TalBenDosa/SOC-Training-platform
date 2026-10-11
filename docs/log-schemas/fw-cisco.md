# Cisco Secure Firewall — FTD security events (430001–430005) and ASA core messages

Category: Network firewall · Vendor: Cisco · Products: Secure Firewall Threat Defense (FTD, formerly Firepower) 7.x, managed by FMC/cdFMC/FDM; Cisco ASA (and FTD's LINA engine, which emits the same ASA-style messages with an `%FTD-` prefix)
Scope: FTD connection events (430002 start / 430003 end), intrusion events (430001), file/malware (430004/430005, brief); ASA 106023 (ACL deny), 302013 (built TCP), 302014 (teardown TCP).

## 1. Official sources

| Source | What it confirmed |
|---|---|
| Cisco Secure Firewall Threat Defense Syslog Messages → *Security Event Syslog Messages* — https://www.cisco.com/c/en/us/td/docs/security/firepower/Syslogs/fptd_syslog_guide/security-event-syslog-messages.html | IDs 430001 intrusion, 430002 connection start, 430003 connection end, 430004 file, 430005 file malware; connection/SI field names (`AccessControlRuleAction`, `AccessControlRuleName`, `AccessControlRuleReason`, `ACPolicy`, `SrcIP`, `DstIP`, `SrcPort`, `DstPort`, `Protocol`, `IngressInterface`/`EgressInterface`, `IngressZone`/`EgressZone`, `ApplicationProtocol`, `Client`, `WebApplication`, `URL`, `URLCategory`, `URLReputation`, `URLSICategory`, `IPReputationSICategory`, `DNSSICategory`, `SecIntMatchingIP`, `InitiatorBytes`, `ResponderBytes`, `InitiatorPackets`, `ResponderPackets`, `ConnectionDuration`, `FirstPacketSecond`, `NAT_InitiatorIP`…, `Prefilter Policy`, `NAPPolicy`, `DNSQuery`, `SSL*`); `AccessControlRuleAction` values; intrusion fields (`Priority`, `GID`, `SID`, `Revision`, `Message`, `Classification`, `IntrusionPolicy`, `InlineResult` = `Dropped`/`Would have dropped`) |
| FMC Device Configuration Guide 7.3 → *URL Filtering* — https://www.cisco.com/c/en/us/td/docs/security/secure-firewall/management-center/device-config/730/management-center-device-config-73/access-url-filtering.html | Reputation levels (6.5+): `Untrusted`, `Questionable`, `Neutral`, `Favorable`, `Trusted`, `Unknown` |
| Talos content categories — https://support.talosintelligence.com/docs/content-categories/ | Category names such as `Malware Sites`, `Phishing`, `Newly Seen Domains`, `Online Storage and Backup` |
| Cisco ASA Series Syslog Messages 302003–342008 — https://www.cisco.com/c/en/us/td/docs/security/asa/syslog/asa-syslog/syslog-messages-302003-to-342008.html | 302013/302014 message text, variables (`connection_id`, `interface`, `real_address`/`real_port`, `mapped_address`/`mapped_port`, `duration`, `bytes`, `reason`, `teardown_initiator`) and teardown reasons (`TCP FINs`, `TCP Reset-I`, `TCP Reset-O`, `Conn-timeout`, `SYN Timeout`, `Deny Terminate`, `Flow closed by inspection`…) |
| Cisco ASA Series Syslog Messages 101001–199021 — https://www.cisco.com/c/en/us/td/docs/security/asa/syslog/asa-syslog/syslog-messages-101001-to-199021.html | 106023 = level 4, "packet denied by ACL", shows real (pre-NAT) addresses |
| Snort rule doc 1:58722 — https://www.snort.org/rule_docs/1-58722 ; Talos advisory — https://www.snort.org/advisories/talos-rules-2021-12-10 | `SERVER-OTHER Apache Log4j logging remote code execution attempt`; Snort 2 SIDs 58722–58733 for CVE-2021-44228 |
| elastic/integrations `packages/cisco_ftd/data_stream/log/_dev/test/pipeline/*.log` and `packages/cisco_asa/…` — https://github.com/elastic/integrations/tree/main/packages/cisco_ftd/data_stream/log/_dev/test/pipeline | Real RAW lines: `%FTD-1-430002/3` and `%FTD-6-430002/3` (severity is configurable), 7.x leading fields `EventPriority`, `DeviceUUID`, `InstanceID`, `FirstPacketSecond`, `ConnectionID`; `ClientAppDetector: AppID`; `%NGIPS-0-430003` from NGIPS devices; ASA 106023/302013/302014 exact text |

## 2. Native format & delivery

**FTD security events (430001–430005)** — syslog from the device (Platform Settings → Syslog, or the access-control policy's syslog alert) or from FMC:
`2026-09-30T06:14:07Z FTD-HQ-01 : %FTD-1-430003: EventPriority: Low, DeviceUUID: …, SrcIP: 10.20.14.37, …`
- Body = `Key: Value` pairs separated by `, `. Keys are CamelCase and a few contain spaces (`Prefilter Policy`, `Endpoint Profile`, `Tunnel or Prefilter Rule`). Values are unquoted and **may themselves contain commas** (`UserAgent`, `Message`, URLs) — parse by known key tokens, not by splitting on commas.
- Prefix `%FTD-<severity>-<id>`; NGIPS/legacy sensors emit `%NGIPS-…`. Severity of 430002/430003 appears as both `1` and `6` in real data (configurable).
- Fields are only present when they have a value (no empty keys). Doc names `Connection Counter` / `Connection Instance ID` appear on the wire as `ConnectionID` / `InstanceID` in 7.x.

**ASA / LINA messages** — `<timestamp> <device-id> : %ASA-<Level>-<Message_number>: <Message_text>` (FTD LINA uses `%FTD-` with the same numbers and text). The body is **free text**; Cisco defines variable *positions*, not key names.

**Our JSON rendering rule (platform):**
1. FTD 43000x: flat object; keys = the Cisco key names exactly as emitted (including the space in `"Prefilter Policy"`); **all values strings**. Header parts are added as `timestamp`, `device_id` (Cisco's "logging device-id"), `Level` and `Message_number` (Cisco's syslog-format terms).
2. ASA / LINA (106023, 302013, 302014 …): `timestamp`, `device_id`, `Level`, `Message_number`, `Message_text` — the text is kept **verbatim**. Do not invent `src_ip`/`dst_port` keys for ASA; the analyst reads the text, exactly as on a real ASA.

## 3. Core field reference

### 3.1 FTD connection events (430002 start / 430003 end)

| Field | Meaning | Values |
|---|---|---|
| `EventPriority` | Connection priority | `High` (linked to intrusion/SI/file/malware), `Low` |
| `DeviceUUID`, `InstanceID`, `ConnectionID`, `FirstPacketSecond` | Together uniquely identify a connection (InstanceID = Snort instance, ConnectionID = counter) | `FirstPacketSecond` ISO-8601 UTC |
| `AccessControlRuleAction` | Rule action | `Allow`, `Trust`, `Fastpath`, `Monitor`, `Block`, `Block with reset`, `Interactive Block`, `Interactive Block with reset`, `Default Action` |
| `AccessControlRuleReason` | Why logged (when applicable) | `IP Block`, `URL Block`, `DNS Block` (doc), `IP Monitor`, `File Block` (real samples); `URL Monitor`, `DNS Monitor`, `File Monitor`, `Intrusion Block`, `Intrusion Monitor` UNVERIFIED wording |
| `ACPolicy`, `AccessControlRuleName`, `Prefilter Policy`, `NAPPolicy`, `SSLPolicy` | Policies involved | |
| `SrcIP`, `DstIP`, `SrcPort`, `DstPort`, `Protocol` | 5-tuple (`Protocol` usually a name, sometimes a number) | `tcp`, `udp`, `icmp`, `6` |
| `ICMPType`, `ICMPCode` | ICMP only | `Echo Request`, `No Code` |
| `IngressInterface`, `EgressInterface`, `IngressZone`, `EgressZone`, `IngressVRF`, `EgressVRF` | Path | |
| `User` | Identity (`<realm>\user` 6.5+) | `ACME\dlevi`, `No Authentication Required`, `Not Found` |
| `ApplicationProtocol`, `Client`, `ClientVersion`, `WebApplication`, `UserAgent`, `ClientAppDetector` | OpenAppID detection | `HTTPS`, `SSL client`, `Chrome`, `MEGA`, `AppID` |
| `InitiatorBytes`, `ResponderBytes`, `InitiatorPackets`, `ResponderPackets` | Counters by **role** (initiator = side that opened the connection) | |
| `ConnectionDuration` | Seconds (430003 only) | |
| `URL`, `URLCategory`, `URLReputation`, `ReferencedHost`, `HTTPReferer`, `HTTPResponse` | Web context | `URLReputation` ∈ `Untrusted`, `Questionable`, `Neutral`, `Favorable`, `Trusted`, `Unknown` |
| `URLSICategory`, `IPReputationSICategory`, `DNSSICategory`, `SecIntMatchingIP` | Security Intelligence match | `SecIntMatchingIP` ∈ `None`, `Source`, `Destination` |
| `DNSQuery`, `DNSRecordType`, `DNSResponseType`, `DNS_TTL`, `DNS_Sinkhole` | DNS context | |
| `NAT_InitiatorIP`, `NAT_InitiatorPort`, `NAT_ResponderIP`, `NAT_ResponderPort` | NAT (7.1+) | |
| `SSLServerName`, `SSLVersion`, `SSLCipherSuite`, `SSLActualAction`, `SSLFlowStatus`… | TLS decryption context | |

430002 is logged at connection start (no duration/final counters); 430003 at the end. **Blocked connections only produce 430002.**

### 3.2 FTD intrusion events (430001)

`Priority` (Talos priority; numeric `1`/`2`/`3` on the wire in samples, docs say high/medium/low), `GID`, `SID`, `Revision`, `Message` (rule message), `Classification`, `IntrusionPolicy`, `InlineResult` (`Dropped`, `Would have dropped`; `Pass` also seen in samples), plus 5-tuple, interfaces/zones, `User`, `Client`, `ApplicationProtocol`, `WebApplication`, `ACPolicy`, `AccessControlRuleName`, `NAPPolicy`, `DeviceUUID`, `InstanceID`, `ConnectionID`, `FirstPacketSecond`.

### 3.3 FTD file events (430004 / 430005) — brief

`FileDirection` (`Download`/`Upload`), `FileAction` (`Detect`, `Block`, `Malware Cloud Lookup`…), `FileName`, `FileType`, `FileSHA256`, `SHA_Disposition` (`Malware`, `Clean`, `Unknown`), `ThreatName`, `FilePolicy`, `FileSandboxStatus`, `URI`. (Disposition/ThreatName names: UNVERIFIED wording for 7.x.)

### 3.4 ASA messages used here

| ID | Level | Native text pattern |
|---|---|---|
| 106023 | 4 | `Deny <protocol> src <interface>:<source_address>/<source_port> dst <interface>:<dest_address>/<dest_port> by access-group "<acl_ID>" [<hash1>, <hash2>]` |
| 302013 | 6 | `Built {inbound\|outbound} TCP connection <connection_id> for <interface>:<real_address>/<real_port> (<mapped_address>/<mapped_port>) to <interface>:<real_address>/<real_port> (<mapped_address>/<mapped_port>)` |
| 302014 | 6 | `Teardown TCP connection <connection_id> for <interface>:<real_address>/<real_port> to <interface>:<real_address>/<real_port> duration <h:mm:ss> bytes <bytes> <reason> [from <teardown_initiator>]` |

## 4. Realistic samples

Scenario thread (fictitious): workstation `10.20.14.37` (user `ACME\dlevi`) behind PAT `203.0.113.10`; DMZ server `10.30.1.15` published as `203.0.113.25`. External IPs RFC 5737; domains invented. FTD 7.4-style field order (as in real 7.x samples).

### CISCO-1 - FTD connection end: allowed HTTPS to a Newly Seen Domain (C2-like beacon)

430003 = connection event logged at end of connection. Small symmetric byte counts, 1 s duration, Talos category `Newly Seen Domains`. Repeats every ~60 s with new `ConnectionID`s -> beacon. Without decryption the `URL` is built from the TLS SNI.

**Raw (native):**

```text
2026-09-30T06:14:07Z FTD-HQ-01 : %FTD-1-430003: EventPriority: Low, DeviceUUID: 8c1f5a3e-2b7d-11ef-9a4c-6e0b3d2f1a57, InstanceID: 3, FirstPacketSecond: 2026-09-30T06:14:06Z, ConnectionID: 41877, AccessControlRuleAction: Allow, SrcIP: 10.20.14.37, DstIP: 198.51.100.77, SrcPort: 52144, DstPort: 443, Protocol: tcp, IngressInterface: inside, EgressInterface: outside, IngressZone: INSIDE, EgressZone: OUTSIDE, IngressVRF: Global, EgressVRF: Global, ACPolicy: HQ-Access-Policy, AccessControlRuleName: Allow-Web-Outbound, Prefilter Policy: Default Prefilter Policy, User: ACME\dlevi, Client: SSL client, ApplicationProtocol: HTTPS, ConnectionDuration: 1, InitiatorPackets: 11, ResponderPackets: 11, InitiatorBytes: 1322, ResponderBytes: 4870, NAPPolicy: Balanced Security and Connectivity, URLCategory: Newly Seen Domains, URLReputation: Questionable, URL: https://cdn-telemetry-sync.top, NAT_InitiatorIP: 203.0.113.10, NAT_InitiatorPort: 31877, NAT_ResponderIP: 198.51.100.77, NAT_ResponderPort: 443, ClientAppDetector: AppID
```

**Flat JSON rendering:**

```json
{
  "timestamp": "2026-09-30T06:14:07Z",
  "device_id": "FTD-HQ-01",
  "Level": "1",
  "Message_number": "430003",
  "EventPriority": "Low",
  "DeviceUUID": "8c1f5a3e-2b7d-11ef-9a4c-6e0b3d2f1a57",
  "InstanceID": "3",
  "FirstPacketSecond": "2026-09-30T06:14:06Z",
  "ConnectionID": "41877",
  "AccessControlRuleAction": "Allow",
  "SrcIP": "10.20.14.37",
  "DstIP": "198.51.100.77",
  "SrcPort": "52144",
  "DstPort": "443",
  "Protocol": "tcp",
  "IngressInterface": "inside",
  "EgressInterface": "outside",
  "IngressZone": "INSIDE",
  "EgressZone": "OUTSIDE",
  "IngressVRF": "Global",
  "EgressVRF": "Global",
  "ACPolicy": "HQ-Access-Policy",
  "AccessControlRuleName": "Allow-Web-Outbound",
  "Prefilter Policy": "Default Prefilter Policy",
  "User": "ACME\\dlevi",
  "Client": "SSL client",
  "ApplicationProtocol": "HTTPS",
  "ConnectionDuration": "1",
  "InitiatorPackets": "11",
  "ResponderPackets": "11",
  "InitiatorBytes": "1322",
  "ResponderBytes": "4870",
  "NAPPolicy": "Balanced Security and Connectivity",
  "URLCategory": "Newly Seen Domains",
  "URLReputation": "Questionable",
  "URL": "https://cdn-telemetry-sync.top",
  "NAT_InitiatorIP": "203.0.113.10",
  "NAT_InitiatorPort": "31877",
  "NAT_ResponderIP": "198.51.100.77",
  "NAT_ResponderPort": "443",
  "ClientAppDetector": "AppID"
}
```

### CISCO-2 - FTD connection blocked by access-control rule (inbound RDP probe)

Blocked connections can only be logged at the *beginning* (430002) - there is no end event because no session is built. `AccessControlRuleAction` = `Block` (or `Block with reset`).

**Raw (native):**

```text
2026-09-30T06:32:51Z FTD-HQ-01 : %FTD-1-430002: EventPriority: Low, DeviceUUID: 8c1f5a3e-2b7d-11ef-9a4c-6e0b3d2f1a57, InstanceID: 5, FirstPacketSecond: 2026-09-30T06:32:51Z, ConnectionID: 42109, AccessControlRuleAction: Block, SrcIP: 192.0.2.45, DstIP: 203.0.113.25, SrcPort: 61022, DstPort: 3389, Protocol: tcp, IngressInterface: outside, EgressInterface: dmz, IngressZone: OUTSIDE, EgressZone: DMZ, IngressVRF: Global, EgressVRF: Global, ACPolicy: HQ-Access-Policy, AccessControlRuleName: Block-Inbound-Default, Prefilter Policy: Default Prefilter Policy, User: No Authentication Required, InitiatorPackets: 1, ResponderPackets: 0, InitiatorBytes: 66, ResponderBytes: 0, NAPPolicy: Balanced Security and Connectivity
```

**Flat JSON rendering:**

```json
{
  "timestamp": "2026-09-30T06:32:51Z",
  "device_id": "FTD-HQ-01",
  "Level": "1",
  "Message_number": "430002",
  "EventPriority": "Low",
  "DeviceUUID": "8c1f5a3e-2b7d-11ef-9a4c-6e0b3d2f1a57",
  "InstanceID": "5",
  "FirstPacketSecond": "2026-09-30T06:32:51Z",
  "ConnectionID": "42109",
  "AccessControlRuleAction": "Block",
  "SrcIP": "192.0.2.45",
  "DstIP": "203.0.113.25",
  "SrcPort": "61022",
  "DstPort": "3389",
  "Protocol": "tcp",
  "IngressInterface": "outside",
  "EgressInterface": "dmz",
  "IngressZone": "OUTSIDE",
  "EgressZone": "DMZ",
  "IngressVRF": "Global",
  "EgressVRF": "Global",
  "ACPolicy": "HQ-Access-Policy",
  "AccessControlRuleName": "Block-Inbound-Default",
  "Prefilter Policy": "Default Prefilter Policy",
  "User": "No Authentication Required",
  "InitiatorPackets": "1",
  "ResponderPackets": "0",
  "InitiatorBytes": "66",
  "ResponderBytes": "0",
  "NAPPolicy": "Balanced Security and Connectivity"
}
```

### CISCO-3 - FTD intrusion event: Log4Shell exploit attempt (dropped)

430001 = intrusion event. GID 1 / SID 58722 is the real Talos Snort 2 rule for CVE-2021-44228 (Talos released SIDs 58722-58733). `InlineResult` = `Dropped` (vs `Would have dropped` in detect-only). FTD shows the post-NAT server IP. The `Revision` number and `Classification` text are UNVERIFIED for this SID.

**Raw (native):**

```text
2026-09-30T07:02:18Z FTD-HQ-01 : %FTD-1-430001: DeviceUUID: 8c1f5a3e-2b7d-11ef-9a4c-6e0b3d2f1a57, InstanceID: 2, FirstPacketSecond: 2026-09-30T07:02:18Z, ConnectionID: 43350, SrcIP: 192.0.2.88, DstIP: 10.30.1.15, SrcPort: 44810, DstPort: 8080, Protocol: tcp, IngressInterface: outside, EgressInterface: dmz, IngressZone: OUTSIDE, EgressZone: DMZ, Priority: 1, GID: 1, SID: 58722, Revision: 10, Message: SERVER-OTHER Apache Log4j logging remote code execution attempt, Classification: Attempted User Privilege Gain, User: No Authentication Required, ApplicationProtocol: HTTP, IntrusionPolicy: HQ-Inline-IPS, ACPolicy: HQ-Access-Policy, AccessControlRuleName: Allow-DMZ-AppServer, NAPPolicy: Balanced Security and Connectivity, InlineResult: Dropped, IngressVRF: Global, EgressVRF: Global
```

**Flat JSON rendering:**

```json
{
  "timestamp": "2026-09-30T07:02:18Z",
  "device_id": "FTD-HQ-01",
  "Level": "1",
  "Message_number": "430001",
  "DeviceUUID": "8c1f5a3e-2b7d-11ef-9a4c-6e0b3d2f1a57",
  "InstanceID": "2",
  "FirstPacketSecond": "2026-09-30T07:02:18Z",
  "ConnectionID": "43350",
  "SrcIP": "192.0.2.88",
  "DstIP": "10.30.1.15",
  "SrcPort": "44810",
  "DstPort": "8080",
  "Protocol": "tcp",
  "IngressInterface": "outside",
  "EgressInterface": "dmz",
  "IngressZone": "OUTSIDE",
  "EgressZone": "DMZ",
  "Priority": "1",
  "GID": "1",
  "SID": "58722",
  "Revision": "10",
  "Message": "SERVER-OTHER Apache Log4j logging remote code execution attempt",
  "Classification": "Attempted User Privilege Gain",
  "User": "No Authentication Required",
  "ApplicationProtocol": "HTTP",
  "IntrusionPolicy": "HQ-Inline-IPS",
  "ACPolicy": "HQ-Access-Policy",
  "AccessControlRuleName": "Allow-DMZ-AppServer",
  "NAPPolicy": "Balanced Security and Connectivity",
  "InlineResult": "Dropped",
  "IngressVRF": "Global",
  "EgressVRF": "Global"
}
```

### CISCO-4 - FTD URL filtering block (Malware Sites / Untrusted)

An access-control rule with a URL-category condition blocks the request; logged at connection start (430002). Values of `UserAgent` contain commas, so a naive split on `, ` breaks - parse on the known `Key: ` tokens. Variant: if the block came from **Security Intelligence** instead, you get `AccessControlRuleReason: URL Block` plus `URLSICategory: <feed/list name>` and `AccessControlRuleName` is empty.

**Raw (native):**

```text
2026-09-30T07:47:33Z FTD-HQ-01 : %FTD-1-430002: EventPriority: Low, DeviceUUID: 8c1f5a3e-2b7d-11ef-9a4c-6e0b3d2f1a57, InstanceID: 4, FirstPacketSecond: 2026-09-30T07:47:33Z, ConnectionID: 44012, AccessControlRuleAction: Block, SrcIP: 10.20.14.37, DstIP: 198.51.100.140, SrcPort: 53017, DstPort: 80, Protocol: tcp, IngressInterface: inside, EgressInterface: outside, IngressZone: INSIDE, EgressZone: OUTSIDE, IngressVRF: Global, EgressVRF: Global, ACPolicy: HQ-Access-Policy, AccessControlRuleName: Block-Malicious-URL-Categories, Prefilter Policy: Default Prefilter Policy, User: ACME\dlevi, UserAgent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.0.0 Safari/537.36, Client: Chrome, ClientVersion: 129.0.0.0, ApplicationProtocol: HTTP, InitiatorPackets: 4, ResponderPackets: 2, InitiatorBytes: 702, ResponderBytes: 132, NAPPolicy: Balanced Security and Connectivity, HTTPReferer: http://mail-attach-preview.example/view?id=88413, ReferencedHost: invoice-docs-share.xyz, URL: http://invoice-docs-share.xyz/dl/Invoice_8841.zip, URLCategory: Malware Sites, URLReputation: Untrusted
```

**Flat JSON rendering:**

```json
{
  "timestamp": "2026-09-30T07:47:33Z",
  "device_id": "FTD-HQ-01",
  "Level": "1",
  "Message_number": "430002",
  "EventPriority": "Low",
  "DeviceUUID": "8c1f5a3e-2b7d-11ef-9a4c-6e0b3d2f1a57",
  "InstanceID": "4",
  "FirstPacketSecond": "2026-09-30T07:47:33Z",
  "ConnectionID": "44012",
  "AccessControlRuleAction": "Block",
  "SrcIP": "10.20.14.37",
  "DstIP": "198.51.100.140",
  "SrcPort": "53017",
  "DstPort": "80",
  "Protocol": "tcp",
  "IngressInterface": "inside",
  "EgressInterface": "outside",
  "IngressZone": "INSIDE",
  "EgressZone": "OUTSIDE",
  "IngressVRF": "Global",
  "EgressVRF": "Global",
  "ACPolicy": "HQ-Access-Policy",
  "AccessControlRuleName": "Block-Malicious-URL-Categories",
  "Prefilter Policy": "Default Prefilter Policy",
  "User": "ACME\\dlevi",
  "UserAgent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.0.0 Safari/537.36",
  "Client": "Chrome",
  "ClientVersion": "129.0.0.0",
  "ApplicationProtocol": "HTTP",
  "InitiatorPackets": "4",
  "ResponderPackets": "2",
  "InitiatorBytes": "702",
  "ResponderBytes": "132",
  "NAPPolicy": "Balanced Security and Connectivity",
  "HTTPReferer": "http://mail-attach-preview.example/view?id=88413",
  "ReferencedHost": "invoice-docs-share.xyz",
  "URL": "http://invoice-docs-share.xyz/dl/Invoice_8841.zip",
  "URLCategory": "Malware Sites",
  "URLReputation": "Untrusted"
}
```

### CISCO-5 - FTD connection end: large outbound transfer (exfil-like)

`InitiatorBytes` = bytes sent by the host that opened the connection (here the internal workstation) -> 4.83 GB upload vs 51 MB download. `FirstPacketSecond` + `ConnectionDuration` give the upload window.

**Raw (native):**

```text
2026-09-30T08:39:02Z FTD-HQ-01 : %FTD-1-430003: EventPriority: Low, DeviceUUID: 8c1f5a3e-2b7d-11ef-9a4c-6e0b3d2f1a57, InstanceID: 3, FirstPacketSecond: 2026-09-30T07:53:50Z, ConnectionID: 44388, AccessControlRuleAction: Allow, SrcIP: 10.20.14.37, DstIP: 198.51.100.201, SrcPort: 53466, DstPort: 443, Protocol: tcp, IngressInterface: inside, EgressInterface: outside, IngressZone: INSIDE, EgressZone: OUTSIDE, IngressVRF: Global, EgressVRF: Global, ACPolicy: HQ-Access-Policy, AccessControlRuleName: Allow-Web-Outbound, Prefilter Policy: Default Prefilter Policy, User: ACME\dlevi, Client: SSL client, ApplicationProtocol: HTTPS, WebApplication: MEGA, ConnectionDuration: 2712, InitiatorPackets: 3302114, ResponderPackets: 609161, InitiatorBytes: 4831203118, ResponderBytes: 51388220, NAPPolicy: Balanced Security and Connectivity, URLCategory: Online Storage and Backup, URLReputation: Neutral, URL: https://g.api.mega.co.nz, NAT_InitiatorIP: 203.0.113.10, NAT_InitiatorPort: 18233, NAT_ResponderIP: 198.51.100.201, NAT_ResponderPort: 443, ClientAppDetector: AppID
```

**Flat JSON rendering:**

```json
{
  "timestamp": "2026-09-30T08:39:02Z",
  "device_id": "FTD-HQ-01",
  "Level": "1",
  "Message_number": "430003",
  "EventPriority": "Low",
  "DeviceUUID": "8c1f5a3e-2b7d-11ef-9a4c-6e0b3d2f1a57",
  "InstanceID": "3",
  "FirstPacketSecond": "2026-09-30T07:53:50Z",
  "ConnectionID": "44388",
  "AccessControlRuleAction": "Allow",
  "SrcIP": "10.20.14.37",
  "DstIP": "198.51.100.201",
  "SrcPort": "53466",
  "DstPort": "443",
  "Protocol": "tcp",
  "IngressInterface": "inside",
  "EgressInterface": "outside",
  "IngressZone": "INSIDE",
  "EgressZone": "OUTSIDE",
  "IngressVRF": "Global",
  "EgressVRF": "Global",
  "ACPolicy": "HQ-Access-Policy",
  "AccessControlRuleName": "Allow-Web-Outbound",
  "Prefilter Policy": "Default Prefilter Policy",
  "User": "ACME\\dlevi",
  "Client": "SSL client",
  "ApplicationProtocol": "HTTPS",
  "WebApplication": "MEGA",
  "ConnectionDuration": "2712",
  "InitiatorPackets": "3302114",
  "ResponderPackets": "609161",
  "InitiatorBytes": "4831203118",
  "ResponderBytes": "51388220",
  "NAPPolicy": "Balanced Security and Connectivity",
  "URLCategory": "Online Storage and Backup",
  "URLReputation": "Neutral",
  "URL": "https://g.api.mega.co.nz",
  "NAT_InitiatorIP": "203.0.113.10",
  "NAT_InitiatorPort": "18233",
  "NAT_ResponderIP": "198.51.100.201",
  "NAT_ResponderPort": "443",
  "ClientAppDetector": "AppID"
}
```

### CISCO-6 - Cisco ASA core messages (106023 deny, 302013 build, 302014 teardown)

ASA (and FTD's LINA engine) messages are free text - Cisco defines **no key names** for the message body, only the header parts `Level`, `Message_number` and `Message_text`. We therefore keep the body verbatim in `Message_text` and never invent keys like `src_ip`. The 302013/302014 pair shares connection id 917733104; 302014 `bytes` is the **total of both directions** (no up/down split - that is why FTD 430003 or NetFlow is needed for an upload ratio).

**Raw (native):**

```text
Sep 30 2026 09:32:51 ASA-EDGE-01 : %ASA-4-106023: Deny tcp src outside:192.0.2.45/61022 dst dmz:203.0.113.25/3389 by access-group "outside_access_in" [0x5f2c81d4, 0x0]
Sep 30 2026 10:53:50 ASA-EDGE-01 : %ASA-6-302013: Built outbound TCP connection 917733104 for outside:198.51.100.201/443 (198.51.100.201/443) to inside:10.20.14.37/53466 (203.0.113.10/18233)
Sep 30 2026 11:39:02 ASA-EDGE-01 : %ASA-6-302014: Teardown TCP connection 917733104 for outside:198.51.100.201/443 to inside:10.20.14.37/53466 duration 0:45:12 bytes 4882591338 TCP FINs from inside
```

**Flat JSON rendering (one object per line):**

```json
{
  "timestamp": "Sep 30 2026 09:32:51",
  "device_id": "ASA-EDGE-01",
  "Level": "4",
  "Message_number": "106023",
  "Message_text": "Deny tcp src outside:192.0.2.45/61022 dst dmz:203.0.113.25/3389 by access-group \"outside_access_in\" [0x5f2c81d4, 0x0]"
}
```

```json
{
  "timestamp": "Sep 30 2026 10:53:50",
  "device_id": "ASA-EDGE-01",
  "Level": "6",
  "Message_number": "302013",
  "Message_text": "Built outbound TCP connection 917733104 for outside:198.51.100.201/443 (198.51.100.201/443) to inside:10.20.14.37/53466 (203.0.113.10/18233)"
}
```

```json
{
  "timestamp": "Sep 30 2026 11:39:02",
  "device_id": "ASA-EDGE-01",
  "Level": "6",
  "Message_number": "302014",
  "Message_text": "Teardown TCP connection 917733104 for outside:198.51.100.201/443 to inside:10.20.14.37/53466 duration 0:45:12 bytes 4882591338 TCP FINs from inside"
}
```

Positional meaning (for teaching only - from the Cisco message guide variable names, NOT emitted keys): 302013 = `Built {inbound|outbound} TCP connection <connection_id> for <interface>:<real_address>/<real_port> (<mapped_address>/<mapped_port>) to <interface>:<real_address>/<real_port> (<mapped_address>/<mapped_port>)`. For an *outbound* build the first socket is the outside (responder) side. 302014 = `... duration <hh:mm:ss> bytes <bytes> <reason> [from <teardown_initiator>]`.


## 5. Investigation notes

- **Connection identity (FTD):** `DeviceUUID` + `InstanceID` + `ConnectionID` + `FirstPacketSecond` — this joins 430001 intrusion events and 430004/5 file events to their 430002/430003 connection records. `ConnectionID` alone repeats.
- **Connection identity (ASA):** the numeric connection id in 302013/302014 (and 302015/302016 for UDP) pairs build ↔ teardown on the same device.
- **Pivot fields:** `SrcIP`/`User` → `DstIP`/`URL`/`ReferencedHost`/`URLCategory` → `AccessControlRuleName` + `AccessControlRuleAction` → `NAT_InitiatorIP` (public egress).
- **Direction of bytes:** FTD splits by *role* (`InitiatorBytes` vs `ResponderBytes`), not by inside/outside. ASA 302014 `bytes` is the **sum** of both directions.
- **Beaconing:** 430003 for the same `SrcIP`/`DstIP`/`URL` at fixed intervals, tiny symmetric byte counts, `URLCategory` `Newly Seen Domains` / reputation `Questionable`/`Untrusted`.
- **Exfil:** `InitiatorBytes` ≫ `ResponderBytes` on an internal initiator; `WebApplication` = storage/file-sharing app.
- **Console view:** FMC → Analysis → Connections → Events / Intrusions → Events (column names: Initiator IP, Responder IP, Access Control Rule, Action, URL Category, URL Reputation, Initiator Bytes…). On ASA: `show logging`, ASDM Real-Time Log Viewer, `show conn address <ip>`.

## 6. Common mistakes / fields that do NOT exist in Cisco logs

- No `srcip` / `dstip` / `policyid` / `sentbyte` / `logid` (FortiGate), no `src` / `dst` / `rule` / `natsrc` / `threatid` (Palo Alto), no `s_port` / `service_id` / `rule_uid` / `loguid` / `product` (Check Point).
- No snake_case or lower-case variants: it is `SrcIP` not `src_ip`/`srcIp`, `AccessControlRuleAction` not `action`.
- No `BytesSent` / `BytesReceived` / `SentBytes` in FTD — counters are `InitiatorBytes` / `ResponderBytes`.
- No `Severity` field in 430001 — priority is `Priority`; the number after `%FTD-` is the *syslog* level, not threat severity.
- ASA messages have **no key=value body**: never emit `%ASA-6-302013: src_ip=…`. And ASA 302014 has no upload/download split.
- 430003 for a blocked connection does not exist (blocked = 430002 only); `ConnectionDuration` never appears on 430002.
- Do not mix ASA free text and FTD key/value in one message (e.g. `%FTD-1-430003: Built outbound TCP …`).
- Don't wrap in `cisco.ftd.*`, `event.*`, `data.*` — SIEM normalisation.
