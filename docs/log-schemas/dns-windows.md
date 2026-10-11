# Microsoft Windows DNS Server — Analytical / Audit events and DNS debug log

Category: DNS. Vendor: Microsoft. Native formats:
(a) ETW/Event Log channel `Microsoft-Windows-DNSServer/Analytical` (events 256–280) and `Microsoft-Windows-DNSServer/Audit` (513–582) — Windows Event XML (text-native);
(b) the legacy **DNS debug log** text file (`dns.log`) — fixed-column text (text-native).
Platform representation: **flat JSON** — Event XML `System` element/attribute names + `EventData` `Data Name` keys unchanged; debug log = the column names from the file's own header + `raw`.

---

## 1. Official sources

| Source | What it confirmed |
|---|---|
| https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/dn800669(v=ws.11) (DNS Logging and Diagnostics) | Provider GUID `{EB79061A-A566-4698-9119-3ED2807060E7}`; analytic log path `%SystemRoot%\System32\Winevt\Logs\Microsoft-Windows-DNSServer%4Analytical.etl`; audit log enabled by default, analytic not; full event-text templates: 257 `RESPONSE_SUCCESS: TCP; InterfaceIP; Destination; AA; AD; QNAME; QTYPE; XID; DNSSEC; RCODE; Port; Flags; Scope; Zone; PolicyName; PacketData`, 258 `RESPONSE_FAILURE ... Reason ...`, 259 `IGNORED_QUERY`, 260 `RECURSE_QUERY_OUT: TCP; Destination; InterfaceIP; RD; QNAME; QTYPE; XID; Port; Flags; ServerScope; CacheScope; PolicyName; PacketData`, 261 `RECURSE_RESPONSE_IN`, 262 timeout, 263/264 dynamic update, 265–276 zone transfer, 279/280 internal lookup; audit table 513–582 (e.g. 515 record create, 516 record delete, 519/520 dynamic-update create/delete "from IP Address %8", 536 cache purge, 541 server setting). |
| https://learn.microsoft.com/en-us/windows-server/networking/dns/dns-logging-and-diagnostics | Current version of the same page (Windows Server 2016+ ship it by default). Event 256 `QUERY_RECEIVED: TCP=%1; InterfaceIP=%2; Source=%3; RD=%4; QNAME=%5; QTYPE=%6; XID=%7; Port=%8; Flags=%9; ServerScope=%10; CacheScope=%11; PacketData=%13` (the 2012 R2 archived table omits row 256). |
| https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/cc776361(v=ws.10) ("Using server debugging logging options") | DNS debug logging options (packet direction, transport, query/response, details); file header "Message logging key" defines the column layout used below. |

## 2. Native format and delivery

**Analytical/Audit (preferred):**
- Real-time ETW channel; collected with WEF/WEC, an agent reading the ETL, or an ETW consumer. One event per DNS transaction step.
- Event XML: `<System>` (Provider `Microsoft-Windows-DNSServer`, `EventID`, `Version`, `Level`, `Task`, `Opcode`, `Keywords`, `TimeCreated SystemTime`, `EventRecordID`, `Execution ProcessID/ThreadID`, `Channel`, `Computer`, `Security UserID`) + `<EventData>` with `<Data Name="QNAME">...`.
- Value conventions: `QNAME` is the FQDN with trailing dot; `QTYPE`, `XID`, `Port`, `Flags`, `RCODE` are **decimal integers**; `TCP` = `0`/`1`; `PacketData` = hex dump of the DNS message prefixed `0x`; `TimeCreated` = UTC ISO-8601 with 7-digit fraction.
- **We standardise on:** flat JSON — `ProviderName`, `EventID`, `Version`, `Level`, `Task`, `Opcode`, `Keywords`, `TimeCreated`, `EventRecordID`, `ProcessID`, `ThreadID`, `Channel`, `Computer`, `UserID`, then every `EventData` name as-is.

**Debug log (legacy, still common):**
- Plain text file (default `%SystemRoot%\System32\dns\dns.log`), rolled by size; collected by file agents. Local time, locale-formatted date (`10/1/2026 8:14:03 AM`).
- Columns (from the file's own header): `Date`, `Time`, `Thread ID`, `Context`, `Internal packet identifier`, `UDP/TCP indicator`, `Send/Receive indicator`, `Remote IP`, `Xid (hex)`, `Query/Response` (`R` or blank), `Opcode` (`Q`/`N`/`U`/`?`), `Flags (hex)`, `Flags (char codes)` (`A` `T` `D` `R`), `ResponseCode`, `Question Type`, `Question Name` (wire form `(len)label...(0)`).
- **We standardise on:** flat JSON whose keys are exactly those header column names, plus `raw`.

## 3. Core field reference

### Analytical events 256 / 257 / 260 (EventData)
| Field | Meaning | Values / notes |
|---|---|---|
| `TCP` | Transport | `0` UDP, `1` TCP |
| `InterfaceIP` | DNS server interface that received/sent | |
| `Source` (256, 261) / `Destination` (257, 260) | Client IP (256/257) or upstream server (260/261) | |
| `RD` | Recursion desired flag | `0`/`1` |
| `AA` / `AD` | Authoritative answer / authenticated data | `0`/`1` |
| `QNAME` | Queried name | `example.com.` |
| `QTYPE` | Query type (decimal) | `1` A, `2` NS, `5` CNAME, `6` SOA, `12` PTR, `15` MX, `16` TXT, `28` AAAA, `33` SRV, `65` HTTPS, `252` AXFR, `255` ANY |
| `XID` | Transaction ID (decimal) | ties 256 <-> 257 |
| `Port` | Client (or upstream) UDP/TCP port | |
| `Flags` | DNS header flags word (decimal) | `256` = 0x0100 (RD query); `33152` = 0x8180 (NOERROR response); `33155` = 0x8183 (NXDOMAIN response) |
| `RCODE` (257) | Response code (decimal) | `0` NOERROR, `2` SERVFAIL, `3` NXDOMAIN, `5` REFUSED |
| `DNSSEC` (257) | DNSSEC used | `0`/`1` |
| `ServerScope` / `CacheScope` / `Scope` / `Zone` / `PolicyName` | DNS policy context | `Default`, `..`, `NULL` |
| `BufferSize` | Length of `PacketData` in bytes | (`%12`/`%16` in the template) |
| `PacketData` | Raw DNS message, hex | `0x6C1A0100...` |

### Audit events (examples)
| ID | EventData | Meaning |
|---|---|---|
| 515 | `Type`, `NAME`, `TTL`, `BufferSize`, `RDATA`, `Zone`, `ZoneScope`, `VirtualizationID` | Record created (admin) |
| 519 | same + `Source` | Record created via dynamic update from an IP |
| 541 | `Setting`, `Scope`, `NewValue` | Server setting changed |
(Exact `Data Name` spellings for audit events are UNVERIFIED — templates are positional `%1..%n` in the doc.)

## 4. Realistic samples

### 4.1 DGA-like lookup — 256 QUERY_RECEIVED + 257 response NXDOMAIN
```json
[
  {"ProviderName": "Microsoft-Windows-DNSServer", "EventID": 256, "Version": 0, "Level": 4, "Task": 1, "Opcode": 0, "Keywords": "0x8000000000000001", "TimeCreated": "2026-10-01T05:14:03.4823117Z", "EventRecordID": 88412037, "ProcessID": 2736, "ThreadID": 4108, "Channel": "Microsoft-Windows-DNSServer/Analytical", "Computer": "DC01.corp.nexacorp.local", "UserID": "S-1-5-18",
   "TCP": "0", "InterfaceIP": "10.20.0.10", "Source": "10.20.31.77", "RD": "1", "QNAME": "qxkzjvbtrwpmhd.com.", "QTYPE": "1", "XID": "27674", "Port": "58312", "Flags": "256", "ServerScope": "Default", "CacheScope": "Default", "BufferSize": "36", "PacketData": "0x6C1A010000010000000000000E71786B7A6A7662747277706D686403636F6D0000010001"},
  {"ProviderName": "Microsoft-Windows-DNSServer", "EventID": 257, "Version": 0, "Level": 4, "Task": 1, "Opcode": 0, "Keywords": "0x8000000000000001", "TimeCreated": "2026-10-01T05:14:03.5390442Z", "EventRecordID": 88412041, "ProcessID": 2736, "ThreadID": 4108, "Channel": "Microsoft-Windows-DNSServer/Analytical", "Computer": "DC01.corp.nexacorp.local", "UserID": "S-1-5-18",
   "TCP": "0", "InterfaceIP": "10.20.0.10", "Destination": "10.20.31.77", "AA": "0", "AD": "0", "QNAME": "qxkzjvbtrwpmhd.com.", "QTYPE": "1", "XID": "27674", "DNSSEC": "0", "RCODE": "3", "Port": "58312", "Flags": "33155", "Scope": "Default", "Zone": "..Cache", "PolicyName": "NULL", "BufferSize": "36", "PacketData": "0x6C1A818300010000000000000E71786B7A6A7662747277706D686403636F6D0000010001"}
]
```
(`Task`/`Keywords` numbers, `Zone="..Cache"` and logging NXDOMAIN under 257 with `RCODE=3` are UNVERIFIED details; `PacketData` of the response is shown without the SOA authority record for brevity.)

Raw XML of the 256 event (abbreviated System block):
```xml
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System><Provider Name="Microsoft-Windows-DNSServer" Guid="{EB79061A-A566-4698-9119-3ED2807060E7}"/><EventID>256</EventID><Version>0</Version><Level>4</Level><Task>1</Task><Opcode>0</Opcode><Keywords>0x8000000000000001</Keywords><TimeCreated SystemTime="2026-10-01T05:14:03.4823117Z"/><EventRecordID>88412037</EventRecordID><Execution ProcessID="2736" ThreadID="4108"/><Channel>Microsoft-Windows-DNSServer/Analytical</Channel><Computer>DC01.corp.nexacorp.local</Computer><Security UserID="S-1-5-18"/></System><EventData><Data Name="TCP">0</Data><Data Name="InterfaceIP">10.20.0.10</Data><Data Name="Source">10.20.31.77</Data><Data Name="RD">1</Data><Data Name="QNAME">qxkzjvbtrwpmhd.com.</Data><Data Name="QTYPE">1</Data><Data Name="XID">27674</Data><Data Name="Port">58312</Data><Data Name="Flags">256</Data><Data Name="ServerScope">Default</Data><Data Name="CacheScope">Default</Data><Data Name="BufferSize">36</Data><Data Name="PacketData">0x6C1A010000010000000000000E71786B7A6A7662747277706D686403636F6D0000010001</Data></EventData></Event>
```

### 4.2 DNS tunneling — long base32 TXT query (256) and the recursive query out to the attacker's NS (260)
```json
[
  {"ProviderName": "Microsoft-Windows-DNSServer", "EventID": 256, "Version": 0, "Level": 4, "Task": 1, "Opcode": 0, "Keywords": "0x8000000000000001", "TimeCreated": "2026-10-01T19:42:17.0912236Z", "EventRecordID": 88977104, "ProcessID": 2736, "ThreadID": 3920, "Channel": "Microsoft-Windows-DNSServer/Analytical", "Computer": "DC01.corp.nexacorp.local", "UserID": "S-1-5-18",
   "TCP": "0", "InterfaceIP": "10.20.0.10", "Source": "10.20.33.105", "RD": "1", "QNAME": "nbswy3dpeb3w64tmmqqgc5tbnfxgiidunbsxgzjamjqxk2lmmrsxezlsmvxgizl.a7f3.t.cdn-telemetry-sync.net.", "QTYPE": "16", "XID": "16017", "Port": "61877", "Flags": "256", "ServerScope": "Default", "CacheScope": "Default", "BufferSize": "111", "PacketData": "0x3E91010000010000000000003F6E62737779336470656233773634746D6D717167633574626E667867696964756E627378677A6A616D6A71786B326C6D6D727378657A6C736D767867697A6C046137663301741263646E2D74656C656D657472792D73796E63036E65740000100001"},
  {"ProviderName": "Microsoft-Windows-DNSServer", "EventID": 260, "Version": 0, "Level": 4, "Task": 2, "Opcode": 0, "Keywords": "0x8000000000000002", "TimeCreated": "2026-10-01T19:42:17.0931870Z", "EventRecordID": 88977105, "ProcessID": 2736, "ThreadID": 3920, "Channel": "Microsoft-Windows-DNSServer/Analytical", "Computer": "DC01.corp.nexacorp.local", "UserID": "S-1-5-18",
   "TCP": "0", "Destination": "192.0.2.53", "InterfaceIP": "10.20.0.10", "RD": "0", "QNAME": "nbswy3dpeb3w64tmmqqgc5tbnfxgiidunbsxgzjamjqxk2lmmrsxezlsmvxgizl.a7f3.t.cdn-telemetry-sync.net.", "QTYPE": "16", "XID": "50218", "Port": "53", "Flags": "0", "ServerScope": "Default", "CacheScope": "Default", "PolicyName": "NULL", "BufferSize": "111", "PacketData": "0xC42A000000010000000000003F6E62737779336470656233773634746D6D717167633574626E667867696964756E627378677A6A616D6A71786B326C6D6D727378657A6C736D767867697A6C046137663301741263646E2D74656C656D657472792D73796E63036E65740000100001"}
]
```

### 4.3 Audit — record created through dynamic update (e.g. attacker-added `wpad` record, ADIDNS abuse)
```json
{"ProviderName": "Microsoft-Windows-DNSServer", "EventID": 519, "Version": 0, "Level": 4, "Task": 5, "Opcode": 0, "Keywords": "0x4000000000020000", "TimeCreated": "2026-10-01T20:03:55.7712004Z", "EventRecordID": 104221, "ProcessID": 2736, "ThreadID": 5012, "Channel": "Microsoft-Windows-DNSServer/Audit", "Computer": "DC01.corp.nexacorp.local", "UserID": "S-1-5-21-3841920571-2209614458-1736201947-1188",
 "Type": "1", "NAME": "wpad.corp.nexacorp.local", "TTL": "1200", "BufferSize": "4", "RDATA": "0x0A142169", "Zone": "corp.nexacorp.local", "ZoneScope": "Default", "VirtualizationID": ".", "Source": "10.20.33.105"}
```
Rendered message: `A resource record of type 1, name wpad.corp.nexacorp.local, TTL 1200 and RDATA 0x0A142169 was created in scope Default of zone corp.nexacorp.local via dynamic update from IP Address 10.20.33.105.` (`RDATA` 0x0A142169 = 10.20.33.105. Data Name keys UNVERIFIED; message template is from the Microsoft table.)

### 4.4 DNS debug log — same DGA query and NXDOMAIN response
```json
[
  {"Date": "10/1/2026", "Time": "8:14:03 AM", "Thread ID": "0A4C", "Context": "PACKET", "Internal packet identifier": "000002B1C4E8A170", "UDP/TCP indicator": "UDP", "Send/Receive indicator": "Rcv", "Remote IP": "10.20.31.77", "Xid (hex)": "6c1a", "Query/Response": "", "Opcode": "Q", "Flags (hex)": "0001", "Flags (char codes)": "D", "ResponseCode": "NOERROR", "Question Type": "A", "Question Name": "(14)qxkzjvbtrwpmhd(3)com(0)",
   "raw": "10/1/2026 8:14:03 AM 0A4C PACKET  000002B1C4E8A170 UDP Rcv 10.20.31.77     6c1a   Q [0001   D   NOERROR] A      (14)qxkzjvbtrwpmhd(3)com(0)"},
  {"Date": "10/1/2026", "Time": "8:14:03 AM", "Thread ID": "0A4C", "Context": "PACKET", "Internal packet identifier": "000002B1C4E8A170", "UDP/TCP indicator": "UDP", "Send/Receive indicator": "Snd", "Remote IP": "10.20.31.77", "Xid (hex)": "6c1a", "Query/Response": "R", "Opcode": "Q", "Flags (hex)": "8183", "Flags (char codes)": "DR", "ResponseCode": "NXDOMAIN", "Question Type": "A", "Question Name": "(14)qxkzjvbtrwpmhd(3)com(0)",
   "raw": "10/1/2026 8:14:03 AM 0A4C PACKET  000002B1C4E8A170 UDP Snd 10.20.31.77     6c1a R Q [8183   DR NXDOMAIN] A      (14)qxkzjvbtrwpmhd(3)com(0)"}
]
```

### 4.5 DNS debug log — tunneling TXT query burst (sequence counter in the 2nd label)
```json
{"Date": "10/1/2026", "Time": "10:42:17 PM", "Thread ID": "0F50", "Context": "PACKET", "Internal packet identifier": "000002B1C51D33E0", "UDP/TCP indicator": "UDP", "Send/Receive indicator": "Rcv", "Remote IP": "10.20.33.105", "Xid (hex)": "3e92", "Query/Response": "", "Opcode": "Q", "Flags (hex)": "0001", "Flags (char codes)": "D", "ResponseCode": "NOERROR", "Question Type": "TXT", "Question Name": "(60)mfrggzdfmztwq2lknnwg23tpobyxe43uov3ho6dzpiys2mbqgezdgnbvgy3t(4)a7f4(1)t(18)cdn-telemetry-sync(3)net(0)",
 "raw": "10/1/2026 10:42:17 PM 0F50 PACKET  000002B1C51D33E0 UDP Rcv 10.20.33.105    3e92   Q [0001   D   NOERROR] TXT    (60)mfrggzdfmztwq2lknnwg23tpobyxe43uov3ho6dzpiys2mbqgezdgnbvgy3t(4)a7f4(1)t(18)cdn-telemetry-sync(3)net(0)"}
```

## 5. Investigation notes

- **The DNS server hides the endpoint:** upstream/firewall logs show the DC/DNS server as the source of every external query. Only these logs (`Source` in 256, `Remote IP` in debug) tie a query to the internal client IP — then map IP -> host via DHCP / EDR.
- **Endpoint process attribution** is not here: pivot client IP + `QNAME` + time to Sysmon Event 22 (`QueryName`, `Image`) or EDR DNS telemetry (CrowdStrike `DnsRequest`, MDE `DnsQueryResponse` in `DeviceNetworkEvents`).
- **DGA:** many `RCODE=3` (NXDOMAIN) from one `Source`, high-entropy second-level labels, same TLD set, regular timing.
- **Tunneling:** `QTYPE=16` (TXT) or `10`/`NULL`/`CNAME`, labels close to 63 chars, base32/hex alphabet, a counter label that increments (`a7f3`, `a7f4`), one parent domain with huge unique-subdomain count; high `BufferSize`. Event 260 reveals the authoritative server the DC reached (`Destination`) — block that NS/IP at the firewall.
- **Pairing:** 256 and 257 share `XID` + `Source`/`Destination` + `Port`; a 256 with no 257 = dropped/ignored (see 259/258).
- **Tampering:** audit 515/516/519/520 for unexpected records (`wpad`, `*` wildcard, look-alike hosts) and 541 for forwarder/setting changes.

## 6. Common mistakes / fields that do NOT exist

- No `query`, `answers`, `client_ip`, `response_code` text, `record_type` names in the analytic events — `QTYPE`/`RCODE`/`Flags` are numbers, `Source`/`Destination` are the IPs.
- Analytic events contain **no answer IP list** as a field; answers are only inside `PacketData` (hex).
- `QNAME` ends with a dot; the debug log uses `(len)label(0)` wire notation, not dotted names.
- No process name / PID of the requesting application — the server never knows it (that is Sysmon 22 / EDR).
- Debug log time is server-local and locale-formatted; analytic `TimeCreated` is UTC.
- Event 256 is not "query blocked"; Windows DNS has no RPZ-style block event — blocks via DNS policies show up as `PolicyName` / 258/259 with a `Reason`.
- Don't output Wazuh `data.win.eventdata.*` or Elastic `dns.question.name` shapes.
