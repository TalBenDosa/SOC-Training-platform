# Cisco Secure Client (AnyConnect) on Cisco ASA — VPN syslog messages

Category: Remote access / VPN. Vendor: Cisco. Native format: ASA syslog, one free-text message per numbered message ID (text-native).
Platform representation: **flat JSON** = syslog header keys + the message's own printed labels as keys (exactly as Cisco prints them, e.g. `Session Type`, `Bytes xmt`, `user IP`) + `raw`.

---

## 1. Official sources

| Source | What it confirmed |
|---|---|
| https://www.cisco.com/c/en/us/td/docs/security/asa/syslog/asa-syslog/syslog-messages-715001-to-721019.html | Templates of 716001 (`Group group User user IP ip WebVPN session started.`), 716002 (`... WebVPN session terminated: reason.`) with reason list (`User Requested`, `Idle timeout`, `Max time exceeded`, `Administrator reset`, `Lost carrier`, `Port preempted`, `VPN simultaneous logins limit`, ...), 716039 (`Authentication: rejected`), 716058/716059 (session lost / resumed). |
| https://www.cisco.com/c/en/us/td/docs/security/asa/syslog/asa-syslog/syslog-messages-722001-to-776020.html | Templates of 722022/722023 (`(TCP\|UDP) SVC connection established/terminated (with\|without) compression`), 722028, 722037 (`SVC closing connection: reason`), 722051 (`IPv4 Address <a> IPv6 address <b> assigned to session`), 722055 (`Client Type: <user-agent>`), 734001 (DAP record selection). |
| https://www.cisco.com/c/en/us/td/docs/security/asa/syslog/b_syslog.html (messages 101001-199021 chapter) | 113004 / 113005 / 113015 / 113019 / 113039 family (AAA result, session disconnect, AnyConnect parent session). |
| https://github.com/elastic/integrations/tree/main/packages/cisco_asa/data_stream/log/_dev/test/pipeline (`test-anyconnect-messages.log`, `test-additional-messages.log`) | Real lines: `%ASA-6-113039: Group <GroupPolicy_Remote-VPN> User <user-1> IP <81.2.69.144> AnyConnect parent session started.`; 113005 `reason = Invalid password / Account has been locked out / Password has expired / Unspecified`, `user = *****` masking; 113015 `: local database :`; 113019 `Session disconnected. Session Type: ..., Duration: 0h:32m:16s, Bytes xmt: ..., Bytes rcv: ..., Reason: User Requested`; 722051/722055/722028 with and without `<>` brackets. |
| https://community.cisco.com/t5/vpn/what-is-the-meaning-of-syslog-message-113019-in-reason/td-p/4055844 and https://medium.com/network-girl/cisco-asa-client-vpn-disconnect-reasons-78cc45438e50 | 113019 Reason values: `User Requested`, `Idle Timeout`, `Lost Service`, `Administrator Reset`, `Peer Reconnected`, `Port Preempted` (simultaneous-login limit). |

## 2. Native format and delivery

- ASA sends RFC 3164-style syslog over UDP/514, TCP/1470 or TLS (or EMBLEM). Optional `logging timestamp` adds `Mon DD YYYY HH:MM:SS` (or RFC 5424 format with `logging timestamp rfc5424`); optional `logging device-id hostname` adds the hostname.
- Message tag: `%ASA-<severity>-<message_id>:` then free text. On FTD (Firepower Threat Defense) the same messages carry `%FTD-...`.
- Newer ASA code wraps variables in angle brackets (`Group <X> User <Y> IP <Z>`); older code prints them bare (`Group X User Y IP Z`). Both are real; keep one style per device.
- Failed-auth messages mask the username as `*****` by default (shown only when `no logging hide username` is configured).
- **We standardise on:** flat JSON with header keys `timestamp`, `hostname`, `severity`, `message_id` and then the message's own printed labels as keys, values verbatim; plus `raw`. Brackets are stripped from values but the `raw` keeps them.

## 3. Core message / field reference

| ID (sev) | Template (variables in `<>`) | Keys we emit |
|---|---|---|
| 113004 (6) | `AAA user authentication Successful : server = <ip> : user = <user>` | `server`, `user` |
| 113005 (6) | `AAA user authentication Rejected : reason = <reason> : server = <ip> : user = <user> : user IP = <ip>` | `reason`, `server`, `user`, `user IP` |
| 113015 (6) | `AAA user authentication Rejected : reason = <reason> : local database : user = <user> : user IP = <ip>` | `reason`, `user`, `user IP` |
| 113039 (6) | `Group <group-policy> User <user> IP <public-ip> AnyConnect parent session started.` | `Group`, `User`, `IP` |
| 113019 (4) | `Group = <group>, Username = <user>, IP = <ip>, Session disconnected. Session Type: <type>, Duration: <Xh:Ym:Zs>, Bytes xmt: <n>, Bytes rcv: <n>, Reason: <reason>` | `Group`, `Username`, `IP`, `Session Type`, `Duration`, `Bytes xmt`, `Bytes rcv`, `Reason` |
| 734001 (6) | `DAP: User <user>, Addr <ip>, Connection <type>: The following DAP records were selected for this connection: <records>` | `User`, `Addr`, `Connection`, `DAP records` |
| 722051 (6) | `Group <gp> User <user> IP <public-ip> IPv4 Address <pool-ip> IPv6 address <v6> assigned to session` | `Group`, `User`, `IP`, `IPv4 Address`, `IPv6 address` |
| 722055 (6) | `Group <gp> User <user> IP <public-ip> Client Type: <user-agent>` | `Group`, `User`, `IP`, `Client Type` |
| 722022 (6) | `Group <gp> User <user> IP <public-ip> (TCP\|UDP) SVC connection established (with\|without) compression` | `Group`, `User`, `IP`, `Protocol`*, `Compression`* |
| 722023 (6) | `Group <gp> User <user> IP <public-ip> (TCP\|UDP) SVC connection terminated (with\|without) compression` | as 722022 |
| 722037 (5) | `Group <gp> User <user> IP <ip> SVC closing connection: <reason>.` | `Group`, `User`, `IP`, `Reason`* |
| 716001 (6) | `Group <gp> User <user> IP <ip> WebVPN session started.` | `Group`, `User`, `IP` |
| 716002 (6) | `Group <gp> User <user> IP <ip> WebVPN session terminated: <reason>.` | `Group`, `User`, `IP`, `Reason`* |

`*` = unlabeled positional value in the message; key name is ours (Cisco template variable name). Everything else is a label Cisco literally prints.

Enumerations:
- 113005/113015 `reason`: `AAA failure`, `Invalid password`, `User was not found`, `Account has been locked out`, `Password has expired`, `Password is expiring`, `Password malformed`, `Unspecified`.
- 113019 `Session Type`: `AnyConnect-Parent`, `SSL`, `DTLS`, `IKEv2`, `IPsec`, `WebVPN`, `LAN-to-LAN` (`AnyConnect-Parent` and `LAN-to-LAN` seen in real samples; others UNVERIFIED as exact strings).
- 113019 `Reason`: `User Requested`, `Idle Timeout`, `Max time exceeded`, `Lost Service`, `Administrator Reset`, `Peer Reconnected`, `Port Preempted`.
- 716002 reason list per Cisco doc (see sources).
- Concepts: **Group** in 113039/722xxx is the *group-policy*; in 113019 it is the *tunnel-group* (connection profile). The parent session (113039) is the authenticated session; SSL (TCP/443) and DTLS (UDP/443) are child tunnels (722022 TCP/UDP).

## 4. Realistic samples

### 4.1 Normal login from usual country — full message chain
```json
[
  {"timestamp": "Oct 01 2026 08:02:10", "hostname": "asa-vpn-01", "severity": 6, "message_id": "113004", "server": "10.10.1.20", "user": "dana.levi",
   "raw": "<166>Oct 01 2026 08:02:10 asa-vpn-01 : %ASA-6-113004: AAA user authentication Successful : server = 10.10.1.20 : user = dana.levi"},
  {"timestamp": "Oct 01 2026 08:02:10", "hostname": "asa-vpn-01", "severity": 6, "message_id": "734001", "User": "dana.levi", "Addr": "203.0.113.24", "Connection": "AnyConnect", "DAP records": "DAP-Corp-Managed",
   "raw": "<166>Oct 01 2026 08:02:10 asa-vpn-01 : %ASA-6-734001: DAP: User dana.levi, Addr 203.0.113.24, Connection AnyConnect: The following DAP records were selected for this connection: DAP-Corp-Managed"},
  {"timestamp": "Oct 01 2026 08:02:10", "hostname": "asa-vpn-01", "severity": 6, "message_id": "113039", "Group": "GP-Corp-Users", "User": "dana.levi", "IP": "203.0.113.24",
   "raw": "<166>Oct 01 2026 08:02:10 asa-vpn-01 : %ASA-6-113039: Group <GP-Corp-Users> User <dana.levi> IP <203.0.113.24> AnyConnect parent session started."},
  {"timestamp": "Oct 01 2026 08:02:11", "hostname": "asa-vpn-01", "severity": 6, "message_id": "722055", "Group": "GP-Corp-Users", "User": "dana.levi", "IP": "203.0.113.24", "Client Type": "Cisco AnyConnect VPN Agent for Windows 5.1.4.74",
   "raw": "<166>Oct 01 2026 08:02:11 asa-vpn-01 : %ASA-6-722055: Group <GP-Corp-Users> User <dana.levi> IP <203.0.113.24> Client Type: Cisco AnyConnect VPN Agent for Windows 5.1.4.74"},
  {"timestamp": "Oct 01 2026 08:02:11", "hostname": "asa-vpn-01", "severity": 6, "message_id": "722051", "Group": "GP-Corp-Users", "User": "dana.levi", "IP": "203.0.113.24", "IPv4 Address": "10.250.8.37", "IPv6 address": "::",
   "raw": "<166>Oct 01 2026 08:02:11 asa-vpn-01 : %ASA-6-722051: Group <GP-Corp-Users> User <dana.levi> IP <203.0.113.24> IPv4 Address <10.250.8.37> IPv6 address <::> assigned to session"},
  {"timestamp": "Oct 01 2026 08:02:11", "hostname": "asa-vpn-01", "severity": 6, "message_id": "722022", "Group": "GP-Corp-Users", "User": "dana.levi", "IP": "203.0.113.24", "Protocol": "TCP", "Compression": "without",
   "raw": "<166>Oct 01 2026 08:02:11 asa-vpn-01 : %ASA-6-722022: Group <GP-Corp-Users> User <dana.levi> IP <203.0.113.24> TCP SVC connection established without compression"},
  {"timestamp": "Oct 01 2026 08:02:12", "hostname": "asa-vpn-01", "severity": 6, "message_id": "722022", "Group": "GP-Corp-Users", "User": "dana.levi", "IP": "203.0.113.24", "Protocol": "UDP", "Compression": "without",
   "raw": "<166>Oct 01 2026 08:02:12 asa-vpn-01 : %ASA-6-722022: Group <GP-Corp-Users> User <dana.levi> IP <203.0.113.24> UDP SVC connection established without compression"}
]
```

### 4.2 Brute force / spray — AAA (RADIUS/LDAP) and local-database rejections from one IP
```json
[
  {"timestamp": "Oct 01 2026 02:14:07", "hostname": "asa-vpn-01", "severity": 6, "message_id": "113005", "reason": "AAA failure", "server": "10.10.1.20", "user": "*****", "user IP": "198.51.100.77",
   "raw": "<166>Oct 01 2026 02:14:07 asa-vpn-01 : %ASA-6-113005: AAA user authentication Rejected : reason = AAA failure : server = 10.10.1.20 : user = ***** : user IP = 198.51.100.77"},
  {"timestamp": "Oct 01 2026 02:14:09", "hostname": "asa-vpn-01", "severity": 6, "message_id": "113005", "reason": "Invalid password", "server": "10.10.1.20", "user": "*****", "user IP": "198.51.100.77",
   "raw": "<166>Oct 01 2026 02:14:09 asa-vpn-01 : %ASA-6-113005: AAA user authentication Rejected : reason = Invalid password : server = 10.10.1.20 : user = ***** : user IP = 198.51.100.77"},
  {"timestamp": "Oct 01 2026 02:14:12", "hostname": "asa-vpn-01", "severity": 6, "message_id": "113005", "reason": "Account has been locked out", "server": "10.10.1.20", "user": "*****", "user IP": "198.51.100.77",
   "raw": "<166>Oct 01 2026 02:14:12 asa-vpn-01 : %ASA-6-113005: AAA user authentication Rejected : reason = Account has been locked out : server = 10.10.1.20 : user = ***** : user IP = 198.51.100.77"},
  {"timestamp": "Oct 01 2026 02:14:15", "hostname": "asa-vpn-01", "severity": 6, "message_id": "113015", "reason": "User was not found", "user": "admin", "user IP": "198.51.100.77",
   "raw": "<166>Oct 01 2026 02:14:15 asa-vpn-01 : %ASA-6-113015: AAA user authentication Rejected : reason = User was not found : local database : user = admin : user IP = 198.51.100.77"}
]
```
(The last line shows a device with `no logging hide username`; on default config it would read `user = *****`.)

### 4.3 Successful login from a foreign hosting-provider IP at night
```json
[
  {"timestamp": "Oct 01 2026 03:41:51", "hostname": "asa-vpn-01", "severity": 6, "message_id": "113039", "Group": "GP-Corp-Users", "User": "r.mizrahi", "IP": "192.0.2.140",
   "raw": "<166>Oct 01 2026 03:41:51 asa-vpn-01 : %ASA-6-113039: Group <GP-Corp-Users> User <r.mizrahi> IP <192.0.2.140> AnyConnect parent session started."},
  {"timestamp": "Oct 01 2026 03:41:52", "hostname": "asa-vpn-01", "severity": 6, "message_id": "722055", "Group": "GP-Corp-Users", "User": "r.mizrahi", "IP": "192.0.2.140", "Client Type": "Cisco AnyConnect VPN Agent for Linux 4.10.07073",
   "raw": "<166>Oct 01 2026 03:41:52 asa-vpn-01 : %ASA-6-722055: Group <GP-Corp-Users> User <r.mizrahi> IP <192.0.2.140> Client Type: Cisco AnyConnect VPN Agent for Linux 4.10.07073"},
  {"timestamp": "Oct 01 2026 03:41:52", "hostname": "asa-vpn-01", "severity": 6, "message_id": "722051", "Group": "GP-Corp-Users", "User": "r.mizrahi", "IP": "192.0.2.140", "IPv4 Address": "10.250.8.112", "IPv6 address": "::",
   "raw": "<166>Oct 01 2026 03:41:52 asa-vpn-01 : %ASA-6-722051: Group <GP-Corp-Users> User <r.mizrahi> IP <192.0.2.140> IPv4 Address <10.250.8.112> IPv6 address <::> assigned to session"}
]
```

### 4.4 Concurrent session — second login preempts the first (vpn-simultaneous-logins 1)
```json
[
  {"timestamp": "Oct 01 2026 09:17:31", "hostname": "asa-vpn-01", "severity": 6, "message_id": "113039", "Group": "GP-Corp-Users", "User": "dana.levi", "IP": "198.51.100.203",
   "raw": "<166>Oct 01 2026 09:17:31 asa-vpn-01 : %ASA-6-113039: Group <GP-Corp-Users> User <dana.levi> IP <198.51.100.203> AnyConnect parent session started."},
  {"timestamp": "Oct 01 2026 09:17:31", "hostname": "asa-vpn-01", "severity": 4, "message_id": "113019", "Group": "TG-AnyConnect", "Username": "dana.levi", "IP": "203.0.113.24", "Session Type": "AnyConnect-Parent", "Duration": "1h:15m:21s", "Bytes xmt": "48211904", "Bytes rcv": "9120443", "Reason": "Port Preempted",
   "raw": "<164>Oct 01 2026 09:17:31 asa-vpn-01 : %ASA-4-113019: Group = TG-AnyConnect, Username = dana.levi, IP = 203.0.113.24, Session disconnected. Session Type: AnyConnect-Parent, Duration: 1h:15m:21s, Bytes xmt: 48211904, Bytes rcv: 9120443, Reason: Port Preempted"},
  {"timestamp": "Oct 01 2026 09:17:32", "hostname": "asa-vpn-01", "severity": 6, "message_id": "722051", "Group": "GP-Corp-Users", "User": "dana.levi", "IP": "198.51.100.203", "IPv4 Address": "10.250.8.91", "IPv6 address": "::",
   "raw": "<166>Oct 01 2026 09:17:32 asa-vpn-01 : %ASA-6-722051: Group <GP-Corp-Users> User <dana.levi> IP <198.51.100.203> IPv4 Address <10.250.8.91> IPv6 address <::> assigned to session"}
]
```

### 4.5 Normal end of day — tunnel teardown and parent-session summary
```json
[
  {"timestamp": "Oct 01 2026 17:45:01", "hostname": "asa-vpn-01", "severity": 6, "message_id": "722023", "Group": "GP-Corp-Users", "User": "r.mizrahi", "IP": "203.0.113.61", "Protocol": "UDP", "Compression": "without",
   "raw": "<166>Oct 01 2026 17:45:01 asa-vpn-01 : %ASA-6-722023: Group <GP-Corp-Users> User <r.mizrahi> IP <203.0.113.61> UDP SVC connection terminated without compression"},
  {"timestamp": "Oct 01 2026 17:45:01", "hostname": "asa-vpn-01", "severity": 6, "message_id": "722023", "Group": "GP-Corp-Users", "User": "r.mizrahi", "IP": "203.0.113.61", "Protocol": "TCP", "Compression": "without",
   "raw": "<166>Oct 01 2026 17:45:01 asa-vpn-01 : %ASA-6-722023: Group <GP-Corp-Users> User <r.mizrahi> IP <203.0.113.61> TCP SVC connection terminated without compression"},
  {"timestamp": "Oct 01 2026 17:45:01", "hostname": "asa-vpn-01", "severity": 4, "message_id": "113019", "Group": "TG-AnyConnect", "Username": "r.mizrahi", "IP": "203.0.113.61", "Session Type": "AnyConnect-Parent", "Duration": "9h:02m:44s", "Bytes xmt": "1873301542", "Bytes rcv": "211874390", "Reason": "User Requested",
   "raw": "<164>Oct 01 2026 17:45:01 asa-vpn-01 : %ASA-4-113019: Group = TG-AnyConnect, Username = r.mizrahi, IP = 203.0.113.61, Session disconnected. Session Type: AnyConnect-Parent, Duration: 9h:02m:44s, Bytes xmt: 1873301542, Bytes rcv: 211874390, Reason: User Requested"}
]
```

### 4.6 Clientless (WebVPN) portal session
```json
[
  {"timestamp": "Oct 01 2026 11:20:05", "hostname": "asa-vpn-01", "severity": 6, "message_id": "716001", "Group": "GP-Contractors", "User": "ext.avi.b", "IP": "203.0.113.88",
   "raw": "<166>Oct 01 2026 11:20:05 asa-vpn-01 : %ASA-6-716001: Group <GP-Contractors> User <ext.avi.b> IP <203.0.113.88> WebVPN session started."},
  {"timestamp": "Oct 01 2026 11:50:07", "hostname": "asa-vpn-01", "severity": 6, "message_id": "716002", "Group": "GP-Contractors", "User": "ext.avi.b", "IP": "203.0.113.88", "Reason": "Idle timeout",
   "raw": "<166>Oct 01 2026 11:50:07 asa-vpn-01 : %ASA-6-716002: Group <GP-Contractors> User <ext.avi.b> IP <203.0.113.88> WebVPN session terminated: Idle timeout."}
]
```

## 5. Investigation notes

- **Correlating a session:** the key tuple is `User` + `IP` (public). 113039 opens the parent session, 722051 gives the pool address, 113019 closes it with duration and byte counts. Bytes in 113019 are from the ASA's perspective: `Bytes xmt` = sent to the client (downloads), `Bytes rcv` = received from the client (uploads). A large `Bytes rcv` = possible exfil through the VPN. (Direction semantics follow `show vpn-sessiondb` Tx/Rx from the ASA's point of view; not spelled out in the 113019 message doc — treat as UNVERIFIED.)
- **Brute force:** count 113005/113015/716039 by `user IP`. Usernames are often masked (`*****`), so pivot on the source IP and on the AAA server (RADIUS/NPS or IdP) logs to recover usernames. `Account has been locked out` after a burst = successful lockout of a targeted account.
- **Impossible travel / concurrent sessions:** two 113039 for the same `User` from different `IP` with no 113019 in between, or a 113019 with `Reason: Port Preempted` (a new login kicked the old one).
- **Device fingerprint:** 722055 `Client Type` (OS + client version). A Linux client or an old 4.x client for a Windows-only fleet stands out. DAP selection (734001) shows whether posture checks passed (e.g. `DAP-Corp-Managed` vs a quarantine record).
- **Pivot:** the 722051 `IPv4 Address` is the user's source IP inside the network — use it to search firewall connection logs (ASA 302013/302015 built connection), EDR network events and Windows 4624/4625 `IpAddress` during the session window.
- Geo / ASN is never in the message; it comes from enrichment.

## 6. Common mistakes / fields that do NOT exist

- There is no `src_ip`, `country`, `user_agent`, `mfa_result`, `session_id` field in these messages. Session IDs exist only in `show vpn-sessiondb` output, not in these syslogs.
- 113039 is the AnyConnect parent session start — it is *not* an authentication message. Auth results are 113004 (success) / 113005 / 113015 (rejected).
- 113019 is severity 4 (`%ASA-4-113019`); 113039/722051/113004/113005/113015 are severity 6.
- Don't invent a "login failed" message ID — AnyConnect failures are 113005/113015/716039 (and 113029-113040 for session-limit/ACL problems).
- `Duration` format is `Xh:YYm:ZZs`, not seconds.
- Don't combine bracketed and non-bracketed variants within the same device stream; don't add `%FTD-` and `%ASA-` in the same session.
- Do not output Elastic shapes (`cisco.asa.*`, `source.ip`) or a Wazuh `data.*` envelope.
