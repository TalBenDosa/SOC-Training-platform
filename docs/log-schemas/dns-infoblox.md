# Infoblox NIOS DNS — query / response logs and RPZ hit logs

Category: DNS. Vendor: Infoblox (NIOS, BIND-based `named`). Native format: syslog text — BIND query/response lines and RPZ hits in **CEF** (text-native).
Platform representation: **flat JSON** — query/response lines use the BIND positional parts (key names below), RPZ hits use the CEF header names + Infoblox's own CEF extension keys (`app`, `dst`, `src`, `spt`, `view`, `qtype`, `msg`, `CAT`) unchanged; plus `raw`.

---

## 1. Official sources

| Source | What it confirmed |
|---|---|
| https://infoblox-docs.atlassian.net/wiki/spaces/nios90/pages/280275770 (NIOS 9.0 "Monitoring through Syslog") and https://infoblox-docs.atlassian.net/wiki/spaces/nios86/pages/1105037695 | Query logging and response logging are separate logging categories (`queries`, `responses`, `rpz`) sent via syslog from `named`. |
| https://docs.infoblox.com/space/NAG8/22253114/Testing+RPZ+Feed+Rules and https://infoblox-docs.atlassian.net/wiki/spaces/nios85/pages/35751177/Monitoring+Subscriber+Policy+Violations | RPZ hit CEF layout: `CEF:0|Infoblox|NIOS|<version>|RPZ-QNAME|<action>|<severity>|app=DNS dst=<server> src=<client> spt=<port> view=<view> qtype=<type> msg="rpz QNAME <action> rewrite <name> [<type>] via <rule>" CAT=RPZ`; the 5th header field is the hard-coded rule-type constant, the 6th is the mitigation action, severity = rule severity (`4` Informational, `6` Warning, `7` Major, `8` Critical); `CAT` is `RPZ`. |
| https://docs.infoblox.com/space/BloxOneCloud/35366601/DNS+Security+Policy+Hit+and+RPZ+Hit+Log+Message+Mapping | RPZ hit message mapping (QNAME / IP / CLIENT-IP / NSDNAME / NSIP triggers). |
| https://github.com/elastic/integrations/blob/main/packages/infoblox_nios/data_stream/log/_dev/test/pipeline/test-dns.log | Real lines: `named[17742]: client @0x7f1dd4114af0 192.168.0.1#59735 (config.nos-avg.cz): query: config.nos-avg.cz IN TXT + (192.168.0.1)`; response logging `... client 192.168.0.1#57398 UDP: query: a1.foo.com IN A response: NOERROR +ED a1.foo.com 28800 IN A 192.168.0.2;`; `... response: NXDOMAIN +ED`; RPZ `CEF:0|Infoblox|NIOS|8.6.2-49634-e88e9df276a8|RPZ-QNAME|NXDOMAIN|7|app=DNS dst=192.168.0.1 src=192.168.0.1 spt=51424 view=_default qtype=A msg="rpz QNAME NXDOMAIN rewrite nxd1.com [A] via nxd1.com.rpz1.com" CAT=RPZ`. |
| BIND 9 ARM, logging category `queries` (https://bind9.readthedocs.io/en/latest/reference.html#logging-categories) | Query-log flag meanings: `+` recursion desired / `-` not, `E` EDNS (with version), `S` signed, `T` TCP, `D` DO bit, `C` CD bit, `V` valid server cookie, `K` cookie present. |

## 2. Native format and delivery

- NIOS members send syslog (UDP/TCP/TLS) from program `named`. NIOS may prefix the BIND timestamp `DD-Mon-YYYY HH:MM:SS.mmm` inside the message (seen in response logs); the syslog header carries the device timestamp and hostname.
- **Query log** (category `queries`): `client @<ctx> <client-ip>#<port> (<qname>): query: <qname> <class> <type> <flags> (<server-ip>)` — one line per incoming query.
- **Response log** (category `responses`, NIOS feature): `client <client-ip>#<port>: <UDP|TCP>: query: <qname> <class> <type> response: <RCODE> <flags> [<answer RRs ;-separated>]`.
- **RPZ hit** (category `rpz`, CEF): see sources. One line per rewrite.
- **We standardise on:**
  - Query/response lines -> keys `timestamp`, `hostname`, `program`, `pid`, `client_ctx`, `client_ip`, `client_port`, `qname`, `qclass`, `qtype`, `flags`, `server_ip` (query) / `protocol`, `rcode`, `answers` (response). These names are ours for BIND's unlabeled positions — keep them exactly so.
  - RPZ CEF -> keys `CEFVersion`, `DeviceVendor`, `DeviceProduct`, `DeviceVersion`, `SignatureID`, `Name`, `Severity` + extension keys verbatim (`app`, `dst`, `src`, `spt`, `view`, `qtype`, `msg`, `CAT`).

## 3. Core field reference

| Key | Meaning | Values / notes |
|---|---|---|
| `client_ctx` | BIND client object address | `@0x7f3a1c0b2e40` |
| `client_ip` / `client_port` | Querying client | `10.20.31.77` / `58312` |
| `qname` | Query name (no trailing dot) | |
| `qclass` | Class | `IN` |
| `qtype` | Type mnemonic | `A`, `AAAA`, `TXT`, `MX`, `PTR`, `SRV`, `CNAME`, `NULL`, `ANY`, `HTTPS` |
| `flags` | Query flags | `+` RD set, `-` RD clear, `E(0)` EDNS v0, `T` TCP, `D` DO, `C` CD, `K` cookie, `S` signed |
| `server_ip` | Local address that received the query | |
| `protocol` | (response log) transport | `UDP`, `TCP` |
| `rcode` | (response log) response code | `NOERROR`, `NXDOMAIN`, `SERVFAIL`, `REFUSED` |
| `answers` | (response log) answer RRs | `name TTL IN TYPE data;` repeated; response flags `A` authoritative, `E` EDNS, `D` DO, `V`... precede them |
| `SignatureID` (CEF) | RPZ trigger type | `RPZ-QNAME`, `RPZ-IP`, `RPZ-CLIENT-IP`, `RPZ-NSDNAME`, `RPZ-NSIP` |
| `Name` (CEF) | Mitigation action | `NXDOMAIN`, `NODATA`, `PASSTHRU`, `Local-Data` / substitute (last UNVERIFIED as exact string) |
| `Severity` (CEF) | Rule severity | `4`, `6`, `7`, `8` |
| `app` | Application | `DNS` |
| `dst` / `src` / `spt` | DNS server IP / client IP / client port | |
| `view` | DNS view | `_default` |
| `qtype` (CEF) | Query type | |
| `msg` | Rewrite description | `rpz QNAME NXDOMAIN rewrite <qname> [<qtype>] via <qname>.<rpz-zone>` |
| `CAT` | Category | `RPZ` |

## 4. Realistic samples

### 4.1 Normal query (query log)
```json
{"timestamp": "Oct  1 08:02:31", "hostname": "ns1.corp.nexacorp.local", "program": "named", "pid": "2871", "client_ctx": "@0x7f3a1c0b2e40", "client_ip": "10.20.31.77", "client_port": "51022", "qname": "outlook.office365.com", "qclass": "IN", "qtype": "A", "flags": "+E(0)K", "server_ip": "10.20.0.53",
 "raw": "<30>Oct  1 08:02:31 ns1.corp.nexacorp.local named[2871]: client @0x7f3a1c0b2e40 10.20.31.77#51022 (outlook.office365.com): query: outlook.office365.com IN A +E(0)K (10.20.0.53)"}
```

### 4.2 DGA-like burst — queries and NXDOMAIN responses from one host
```json
[
  {"timestamp": "Oct  1 08:14:03", "hostname": "ns1.corp.nexacorp.local", "program": "named", "pid": "2871", "client_ctx": "@0x7f3a1c0d8a10", "client_ip": "10.20.31.77", "client_port": "58312", "qname": "qxkzjvbtrwpmhd.com", "qclass": "IN", "qtype": "A", "flags": "+E(0)K", "server_ip": "10.20.0.53",
   "raw": "<30>Oct  1 08:14:03 ns1.corp.nexacorp.local named[2871]: client @0x7f3a1c0d8a10 10.20.31.77#58312 (qxkzjvbtrwpmhd.com): query: qxkzjvbtrwpmhd.com IN A +E(0)K (10.20.0.53)"},
  {"timestamp": "Oct  1 08:14:03", "hostname": "ns1.corp.nexacorp.local", "program": "named", "pid": "2871", "client_ip": "10.20.31.77", "client_port": "58312", "protocol": "UDP", "qname": "qxkzjvbtrwpmhd.com", "qclass": "IN", "qtype": "A", "rcode": "NXDOMAIN", "flags": "+ED", "answers": "",
   "raw": "<30>Oct  1 08:14:03 ns1.corp.nexacorp.local named[2871]: 01-Oct-2026 08:14:03.541 client 10.20.31.77#58312: UDP: query: qxkzjvbtrwpmhd.com IN A response: NXDOMAIN +ED"},
  {"timestamp": "Oct  1 08:14:04", "hostname": "ns1.corp.nexacorp.local", "program": "named", "pid": "2871", "client_ip": "10.20.31.77", "client_port": "58313", "protocol": "UDP", "qname": "vbnrtqlzmwxkpe.net", "qclass": "IN", "qtype": "A", "rcode": "NXDOMAIN", "flags": "+ED", "answers": "",
   "raw": "<30>Oct  1 08:14:04 ns1.corp.nexacorp.local named[2871]: 01-Oct-2026 08:14:04.117 client 10.20.31.77#58313: UDP: query: vbnrtqlzmwxkpe.net IN A response: NXDOMAIN +ED"},
  {"timestamp": "Oct  1 08:14:04", "hostname": "ns1.corp.nexacorp.local", "program": "named", "pid": "2871", "client_ip": "10.20.31.77", "client_port": "58314", "protocol": "UDP", "qname": "hjwqzpxkrtlmvb.org", "qclass": "IN", "qtype": "A", "rcode": "NOERROR", "flags": "+ED", "answers": "hjwqzpxkrtlmvb.org 300 IN A 192.0.2.66;",
   "raw": "<30>Oct  1 08:14:04 ns1.corp.nexacorp.local named[2871]: 01-Oct-2026 08:14:04.690 client 10.20.31.77#58314: UDP: query: hjwqzpxkrtlmvb.org IN A response: NOERROR +ED hjwqzpxkrtlmvb.org 300 IN A 192.0.2.66;"}
]
```
(The one domain that resolves — `192.0.2.66` — is the live C2 for this DGA seed.)

### 4.3 DNS tunneling — long TXT queries with incrementing sequence label
```json
[
  {"timestamp": "Oct  1 22:42:17", "hostname": "ns1.corp.nexacorp.local", "program": "named", "pid": "2871", "client_ctx": "@0x7f3a1c11f020", "client_ip": "10.20.33.105", "client_port": "61877", "qname": "nbswy3dpeb3w64tmmqqgc5tbnfxgiidunbsxgzjamjqxk2lmmrsxezlsmvxgizl.a7f3.t.cdn-telemetry-sync.net", "qclass": "IN", "qtype": "TXT", "flags": "+", "server_ip": "10.20.0.53",
   "raw": "<30>Oct  1 22:42:17 ns1.corp.nexacorp.local named[2871]: client @0x7f3a1c11f020 10.20.33.105#61877 (nbswy3dpeb3w64tmmqqgc5tbnfxgiidunbsxgzjamjqxk2lmmrsxezlsmvxgizl.a7f3.t.cdn-telemetry-sync.net): query: nbswy3dpeb3w64tmmqqgc5tbnfxgiidunbsxgzjamjqxk2lmmrsxezlsmvxgizl.a7f3.t.cdn-telemetry-sync.net IN TXT + (10.20.0.53)"},
  {"timestamp": "Oct  1 22:42:17", "hostname": "ns1.corp.nexacorp.local", "program": "named", "pid": "2871", "client_ip": "10.20.33.105", "client_port": "61877", "protocol": "UDP", "qname": "nbswy3dpeb3w64tmmqqgc5tbnfxgiidunbsxgzjamjqxk2lmmrsxezlsmvxgizl.a7f3.t.cdn-telemetry-sync.net", "qclass": "IN", "qtype": "TXT", "rcode": "NOERROR", "flags": "+", "answers": "nbswy3dpeb3w64tmmqqgc5tbnfxgiidunbsxgzjamjqxk2lmmrsxezlsmvxgizl.a7f3.t.cdn-telemetry-sync.net 0 IN TXT \"MZXW6YTBOI======\";",
   "raw": "<30>Oct  1 22:42:17 ns1.corp.nexacorp.local named[2871]: 01-Oct-2026 22:42:17.322 client 10.20.33.105#61877: UDP: query: nbswy3dpeb3w64tmmqqgc5tbnfxgiidunbsxgzjamjqxk2lmmrsxezlsmvxgizl.a7f3.t.cdn-telemetry-sync.net IN TXT response: NOERROR + nbswy3dpeb3w64tmmqqgc5tbnfxgiidunbsxgzjamjqxk2lmmrsxezlsmvxgizl.a7f3.t.cdn-telemetry-sync.net 0 IN TXT \"MZXW6YTBOI======\";"},
  {"timestamp": "Oct  1 22:42:18", "hostname": "ns1.corp.nexacorp.local", "program": "named", "pid": "2871", "client_ctx": "@0x7f3a1c11f6b0", "client_ip": "10.20.33.105", "client_port": "61879", "qname": "mfrggzdfmztwq2lknnwg23tpobyxe43uov3ho6dzpiys2mbqgezdgnbvgy3t.a7f4.t.cdn-telemetry-sync.net", "qclass": "IN", "qtype": "TXT", "flags": "+", "server_ip": "10.20.0.53",
   "raw": "<30>Oct  1 22:42:18 ns1.corp.nexacorp.local named[2871]: client @0x7f3a1c11f6b0 10.20.33.105#61879 (mfrggzdfmztwq2lknnwg23tpobyxe43uov3ho6dzpiys2mbqgezdgnbvgy3t.a7f4.t.cdn-telemetry-sync.net): query: mfrggzdfmztwq2lknnwg23tpobyxe43uov3ho6dzpiys2mbqgezdgnbvgy3t.a7f4.t.cdn-telemetry-sync.net IN TXT + (10.20.0.53)"}
]
```

### 4.4 RPZ block — known-malware domain rewritten to NXDOMAIN (threat feed)
```json
{"timestamp": "Oct  1 09:05:44", "hostname": "ns1.corp.nexacorp.local", "program": "named", "pid": "2871", "CEFVersion": "0", "DeviceVendor": "Infoblox", "DeviceProduct": "NIOS", "DeviceVersion": "9.0.4-50212-a1c3e8f02b77", "SignatureID": "RPZ-QNAME", "Name": "NXDOMAIN", "Severity": "7", "app": "DNS", "dst": "10.20.0.53", "src": "10.20.31.77", "spt": "60411", "view": "_default", "qtype": "A", "msg": "rpz QNAME NXDOMAIN rewrite docs-invoice-share.top [A] via docs-invoice-share.top.antimalware.rpz.infoblox.local", "CAT": "RPZ",
 "raw": "<29>Oct  1 09:05:44 ns1.corp.nexacorp.local named[2871]: CEF:0|Infoblox|NIOS|9.0.4-50212-a1c3e8f02b77|RPZ-QNAME|NXDOMAIN|7|app=DNS dst=10.20.0.53 src=10.20.31.77 spt=60411 view=_default qtype=A msg=\"rpz QNAME NXDOMAIN rewrite docs-invoice-share.top [A] via docs-invoice-share.top.antimalware.rpz.infoblox.local\" CAT=RPZ"}
```
(The feed zone name `antimalware.rpz.infoblox.local` is UNVERIFIED as an exact Infoblox feed name; local RPZ zones are customer-named.)

### 4.5 RPZ block of a tunneling parent domain by a local policy zone (wildcard rule), severity Critical
```json
{"timestamp": "Oct  1 22:51:02", "hostname": "ns1.corp.nexacorp.local", "program": "named", "pid": "2871", "CEFVersion": "0", "DeviceVendor": "Infoblox", "DeviceProduct": "NIOS", "DeviceVersion": "9.0.4-50212-a1c3e8f02b77", "SignatureID": "RPZ-QNAME", "Name": "NXDOMAIN", "Severity": "8", "app": "DNS", "dst": "10.20.0.53", "src": "10.20.33.105", "spt": "62044", "view": "_default", "qtype": "TXT", "msg": "rpz QNAME NXDOMAIN rewrite ojsxg5dfoqqgc3tefzzxi5lgmy.a812.t.cdn-telemetry-sync.net [TXT] via *.cdn-telemetry-sync.net.soc-block.rpz", "CAT": "RPZ",
 "raw": "<29>Oct  1 22:51:02 ns1.corp.nexacorp.local named[2871]: CEF:0|Infoblox|NIOS|9.0.4-50212-a1c3e8f02b77|RPZ-QNAME|NXDOMAIN|8|app=DNS dst=10.20.0.53 src=10.20.33.105 spt=62044 view=_default qtype=TXT msg=\"rpz QNAME NXDOMAIN rewrite ojsxg5dfoqqgc3tefzzxi5lgmy.a812.t.cdn-telemetry-sync.net [TXT] via *.cdn-telemetry-sync.net.soc-block.rpz\" CAT=RPZ"}
```
(How the `via` clause renders for wildcard rules is UNVERIFIED.)

### 4.6 RPZ PASSTHRU — allow-listed domain (Informational)
```json
{"timestamp": "Oct  1 10:20:13", "hostname": "ns1.corp.nexacorp.local", "program": "named", "pid": "2871", "CEFVersion": "0", "DeviceVendor": "Infoblox", "DeviceProduct": "NIOS", "DeviceVersion": "9.0.4-50212-a1c3e8f02b77", "SignatureID": "RPZ-QNAME", "Name": "PASSTHRU", "Severity": "4", "app": "DNS", "dst": "10.20.0.53", "src": "10.20.31.52", "spt": "53390", "view": "_default", "qtype": "A", "msg": "rpz QNAME PASSTHRU rewrite updates.vendor-tools.example [A] via updates.vendor-tools.example.allowlist.rpz", "CAT": "RPZ",
 "raw": "<30>Oct  1 10:20:13 ns1.corp.nexacorp.local named[2871]: CEF:0|Infoblox|NIOS|9.0.4-50212-a1c3e8f02b77|RPZ-QNAME|PASSTHRU|4|app=DNS dst=10.20.0.53 src=10.20.31.52 spt=53390 view=_default qtype=A msg=\"rpz QNAME PASSTHRU rewrite updates.vendor-tools.example [A] via updates.vendor-tools.example.allowlist.rpz\" CAT=RPZ"}
```

## 5. Investigation notes

- **Client attribution:** `client_ip` (query log) / `src` (RPZ) is the internal host — map to hostname via DHCP lease logs (NIOS DHCP `DHCPACK on <ip> to <mac> (<hostname>)`) and EDR.
- **Process attribution** is on the endpoint: Sysmon Event 22 (`QueryName`, `Image`) or EDR DNS events with the same name and time.
- **RPZ hit = attempted contact, not compromise proof** — but the requesting host is executing something that knows the domain. Check whether the same host resolved other domains from the same feed or got a NOERROR for an earlier variant.
- **DGA:** response-log `rcode=NXDOMAIN` ratio per `client_ip`; high-entropy names across many TLDs; the occasional NOERROR answer gives the live C2 IP -> pivot to firewall/proxy logs for connections to it.
- **Tunneling:** `qtype=TXT`/`NULL`, label length near 63, base32/hex alphabet, sequence label, thousands of unique subdomains under one parent; long TXT answers. Firewall logs only show DNS server -> internet resolvers, so this is the only place with the internal source.
- `msg` "via ..." tells which RPZ zone/feed matched — use it to prove which intel source caught it.

## 6. Common mistakes / fields that do NOT exist

- BIND query logs do **not** include the answer or RCODE — that requires response logging (separate line).
- No `action=block` / `blocked=true` field — RPZ action is the CEF `Name` (`NXDOMAIN`, `PASSTHRU`, ...).
- CEF extension uses `src`/`dst`/`spt` (no `dpt`, no `suser`, no `request`); `CAT=RPZ` is literal.
- No process, user, or URL in DNS logs.
- Don't output Elastic `infoblox_nios.log.*` / `dns.question.name` or a Wazuh `data.*` envelope.
- Don't mix Windows DNS fields (`QNAME`, `XID`, `RCODE` numbers) into Infoblox lines.
