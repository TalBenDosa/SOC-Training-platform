# Fortinet FortiGate SSL-VPN (FortiOS event log, subtype `vpn`)

Category: Remote access / VPN. Vendor: Fortinet. Native format: FortiOS syslog `key=value` (text-native).
Platform representation: **flat JSON with the FortiOS keys unchanged** (`logid`, `type`, `subtype`, `action`, `tunneltype`, `remip`, ...) + `raw`.

---

## 1. Official sources

| Source | What it confirmed |
|---|---|
| https://docs.fortinet.com/document/fortigate/7.0.1/fortios-log-message-reference/39426/39426-log-id-event-ssl-vpn-user-ssl-login-fail | Log ID 39426 `LOG_ID_EVENT_SSL_VPN_USER_SSL_LOGIN_FAIL`, message meaning "SSL VPN login fail", type event, subtype vpn, severity Alert; fields `action, date, devid, dst_host, eventtime, group, level, logdesc, logid, msg, reason, remip, subtype, time, tunnelid, tunneltype, type, tz, user, vd`. |
| https://docs.fortinet.com/document/fortigate/7.6.1/fortios-log-message-reference/39424/39424-log-id-event-ssl-vpn-user-tunnel-up | Log ID 39424 `LOG_ID_EVENT_SSL_VPN_USER_TUNNEL_UP` "SSL VPN tunnel up", Information; same field set plus `srccountry`. |
| https://docs.fortinet.com/document/fortigate/7.6.0/fortios-log-message-reference/39947/39947-log-id-event-ssl-vpn-session-tunnel-up | Log ID 39947 `LOG_ID_EVENT_SSL_VPN_SESSION_TUNNEL_UP` (the tunnel-mode "tunnel established" log). |
| https://community.fortinet.com/t5/FortiGate/Technical-Tip-SSL-VPN-event-logs-when-successfully-connected/ta-p/331206 | A FortiClient connect produces `ssl-new-con`, then `tunnel-up` with `tunneltype="ssl-web"` `reason="login successfully"` (no tunnel IP), then `tunnel-up` with `tunneltype="ssl-tunnel"` `reason="tunnel established"` + `tunnelip` + `fctuid`. |
| https://blog.boll.ch/fortigate-lots-of-ssl-user-failed-to-logged-in-events/ | Real 39426 line: `logdesc="SSL VPN login fail" action="ssl-login-fail" tunneltype="ssl-web" tunnelid=0 ... reason="sslvpn_login_permission_denied" msg="SSL user failed to logged in"` (note Fortinet's own grammar). |
| https://github.com/elastic/integrations/blob/main/packages/fortinet_fortigate/data_stream/log/_dev/test/pipeline/test-fortinet.log | Real 39943 (`action="ssl-new-con"`, `tunneltype="ssl"`, `msg="SSL new connection"`) and 39947 (`action="tunnel-up"`, `tunneltype="ssl-tunnel"`, `tunnelip=`, `msg="SSL tunnel established"`) with 19-digit `eventtime` and `tz="-0500"`. |
| Fortinet KB "Host check errors while connecting SSL-VPN" (community.fortinet.com/t5/FortiGate/Technical-Tip-Host-check-errors-while-connecting-SSL-VPN/ta-p/190372) | 39948 `SSL VPN tunnel down`, `action="tunnel-down"`, `sentbyte`/`rcvdbyte`, `msg="SSL tunnel shutdown"`. |
| https://community.fortinet.com/t5/FortiGate/Troubleshooting-Tip-SSL-VPN-Debugs-Error-sslvpn-login-unknown/ta-p/232020 | Failure reason tokens `sslvpn_login_unknown_user`, `sslvpn_login_permission_denied`, `sslvpn_login_cert_checked_error`. |

## 2. Native format and delivery

- FortiGate sends syslog (UDP/514 by default, or TCP/reliable, or to FortiAnalyzer/FortiGate Cloud). Body is space-separated `key=value`; string values are double-quoted, numbers and IPs are bare.
- Header fields always first: `date=YYYY-MM-DD time=HH:MM:SS devname devid eventtime tz logid type subtype level vd`.
- `eventtime`: FortiOS 6.2+ = 19-digit epoch **nanoseconds** (older builds: 10-digit seconds). `tz` = `"+0300"` style offset.
- `logid` is a 10-character string: 2-digit type + 2-digit subtype + 6-digit message ID (`0101039426` = event/vpn/39426).
- Context: FortiOS 7.6.x removes SSL-VPN tunnel mode in favour of IPsec dial-up (UNVERIFIED for exact build/model matrix); scenarios should present FortiOS 7.0–7.4 era devices when using SSL-VPN.
- **We standardise on:** flat JSON, keys exactly as in the line, quoted values as strings, bare numbers as numbers — except `eventtime`, kept as a string because 19-digit integers exceed JavaScript's safe-integer range. Plus `raw`.

## 3. Core field reference

| Field | Meaning | Values / notes |
|---|---|---|
| `date`, `time` | Device-local date/time | `2026-10-01`, `08:02:11` |
| `devname`, `devid` | Hostname / serial | `FGT-HQ-01`, `FG200FT921900123` |
| `eventtime`, `tz` | Epoch ns, UTC offset | `"1790830931114000000"`, `"+0300"` |
| `logid` | Message ID | `0101039943` new connection, `0101039424` tunnel-up (web/login), `0101039947` tunnel-up (tunnel mode), `0101039425` / `0101039948` tunnel-down, `0101039426` login fail, `0101039949` tunnel stats (39949 UNVERIFIED) |
| `type` / `subtype` | Log type | `event` / `vpn` |
| `level` | Severity | `information`, `notice`, `warning`, `alert` (39426 = `alert`) |
| `vd` | VDOM | `root` |
| `logdesc` | Fixed description | `SSL VPN new connection`, `SSL VPN tunnel up`, `SSL VPN tunnel down`, `SSL VPN login fail` |
| `action` | Event action | `ssl-new-con`, `tunnel-up`, `tunnel-down`, `ssl-login-fail`, `tunnel-stats` |
| `tunneltype` | SSL-VPN mode | `ssl` (new-con), `ssl-web` (portal/login step, also on failures even via FortiClient), `ssl-tunnel` (full tunnel) |
| `tunnelid` | Tunnel index | `0` on failures |
| `remip` | Client public IP | |
| `tunnelip` | IP assigned from the SSL-VPN pool | only on `ssl-tunnel` events; FortiGate default pool `10.212.134.200-210` |
| `user`, `group` | Username / matched user group | `"N/A"` when unknown |
| `dst_host` | Destination host (web-mode bookmarks) | usually `"N/A"` |
| `reason` | Reason token or text | `login successfully`, `tunnel established`, `sslvpn_login_permission_denied`, `sslvpn_login_unknown_user`, `sslvpn_login_cert_checked_error`, `N/A` |
| `msg` | Message text | `SSL new connection`, `SSL tunnel established`, `SSL tunnel shutdown`, `SSL user failed to logged in` |
| `srccountry` | GeoIP country of `remip` (39424 per 7.6 doc) | `"Israel"`, `"Netherlands"`, `"Reserved"` |
| `fctuid` | FortiClient UID (tunnel-mode log) | 32 hex |
| `duration`, `sentbyte`, `rcvdbyte` | Session seconds / bytes (tunnel-down) | integers |

## 4. Realistic samples

### 4.1 Normal FortiClient connect from Israel (three logs)
```json
[
  {"date": "2026-10-01", "time": "08:02:10", "devname": "FGT-HQ-01", "devid": "FG200FT921900123", "eventtime": "1790830930412000000", "tz": "+0300", "logid": "0101039943", "type": "event", "subtype": "vpn", "level": "information", "vd": "root", "logdesc": "SSL VPN new connection", "action": "ssl-new-con", "tunneltype": "ssl", "tunnelid": 0, "remip": "203.0.113.24", "user": "N/A", "group": "N/A", "dst_host": "N/A", "reason": "N/A", "msg": "SSL new connection",
   "raw": "date=2026-10-01 time=08:02:10 devname=\"FGT-HQ-01\" devid=\"FG200FT921900123\" eventtime=1790830930412000000 tz=\"+0300\" logid=\"0101039943\" type=\"event\" subtype=\"vpn\" level=\"information\" vd=\"root\" logdesc=\"SSL VPN new connection\" action=\"ssl-new-con\" tunneltype=\"ssl\" tunnelid=0 remip=203.0.113.24 user=\"N/A\" group=\"N/A\" dst_host=\"N/A\" reason=\"N/A\" msg=\"SSL new connection\""},
  {"date": "2026-10-01", "time": "08:02:11", "devname": "FGT-HQ-01", "devid": "FG200FT921900123", "eventtime": "1790830931114000000", "tz": "+0300", "logid": "0101039424", "type": "event", "subtype": "vpn", "level": "information", "vd": "root", "logdesc": "SSL VPN tunnel up", "action": "tunnel-up", "tunneltype": "ssl-web", "tunnelid": 1938241, "remip": "203.0.113.24", "srccountry": "Israel", "user": "dana.levi", "group": "VPN-Employees", "dst_host": "N/A", "reason": "login successfully", "msg": "SSL tunnel established",
   "raw": "date=2026-10-01 time=08:02:11 devname=\"FGT-HQ-01\" devid=\"FG200FT921900123\" eventtime=1790830931114000000 tz=\"+0300\" logid=\"0101039424\" type=\"event\" subtype=\"vpn\" level=\"information\" vd=\"root\" logdesc=\"SSL VPN tunnel up\" action=\"tunnel-up\" tunneltype=\"ssl-web\" tunnelid=1938241 remip=203.0.113.24 srccountry=\"Israel\" user=\"dana.levi\" group=\"VPN-Employees\" dst_host=\"N/A\" reason=\"login successfully\" msg=\"SSL tunnel established\""},
  {"date": "2026-10-01", "time": "08:02:12", "devname": "FGT-HQ-01", "devid": "FG200FT921900123", "eventtime": "1790830932006000000", "tz": "+0300", "logid": "0101039947", "type": "event", "subtype": "vpn", "level": "information", "vd": "root", "logdesc": "SSL VPN tunnel up", "action": "tunnel-up", "tunneltype": "ssl-tunnel", "tunnelid": 1938242, "remip": "203.0.113.24", "tunnelip": "10.212.134.201", "user": "dana.levi", "group": "VPN-Employees", "dst_host": "N/A", "reason": "tunnel established", "msg": "SSL tunnel established", "fctuid": "8F3A2C1D9B7E4F60A1C2D3E4F5A6B7C8",
   "raw": "date=2026-10-01 time=08:02:12 devname=\"FGT-HQ-01\" devid=\"FG200FT921900123\" eventtime=1790830932006000000 tz=\"+0300\" logid=\"0101039947\" type=\"event\" subtype=\"vpn\" level=\"information\" vd=\"root\" logdesc=\"SSL VPN tunnel up\" action=\"tunnel-up\" tunneltype=\"ssl-tunnel\" tunnelid=1938242 remip=203.0.113.24 tunnelip=10.212.134.201 user=\"dana.levi\" group=\"VPN-Employees\" dst_host=\"N/A\" reason=\"tunnel established\" msg=\"SSL tunnel established\" fctuid=\"8F3A2C1D9B7E4F60A1C2D3E4F5A6B7C8\""}
]
```
(`msg` text on 39424 and placement of `fctuid` in the line are UNVERIFIED; the KB confirms `fctuid` appears only on the ssl-tunnel log.)

### 4.2 Brute force / spray — repeated `ssl-login-fail` from one IP
```json
[
  {"date": "2026-10-01", "time": "02:14:07", "devname": "FGT-HQ-01", "devid": "FG200FT921900123", "eventtime": "1790810047100000000", "tz": "+0300", "logid": "0101039426", "type": "event", "subtype": "vpn", "level": "alert", "vd": "root", "logdesc": "SSL VPN login fail", "action": "ssl-login-fail", "tunneltype": "ssl-web", "tunnelid": 0, "remip": "198.51.100.77", "user": "administrator", "group": "N/A", "dst_host": "N/A", "reason": "sslvpn_login_unknown_user", "msg": "SSL user failed to logged in",
   "raw": "date=2026-10-01 time=02:14:07 devname=\"FGT-HQ-01\" devid=\"FG200FT921900123\" eventtime=1790810047100000000 tz=\"+0300\" logid=\"0101039426\" type=\"event\" subtype=\"vpn\" level=\"alert\" vd=\"root\" logdesc=\"SSL VPN login fail\" action=\"ssl-login-fail\" tunneltype=\"ssl-web\" tunnelid=0 remip=198.51.100.77 user=\"administrator\" group=\"N/A\" dst_host=\"N/A\" reason=\"sslvpn_login_unknown_user\" msg=\"SSL user failed to logged in\""},
  {"date": "2026-10-01", "time": "02:14:09", "devname": "FGT-HQ-01", "devid": "FG200FT921900123", "eventtime": "1790810049320000000", "tz": "+0300", "logid": "0101039426", "type": "event", "subtype": "vpn", "level": "alert", "vd": "root", "logdesc": "SSL VPN login fail", "action": "ssl-login-fail", "tunneltype": "ssl-web", "tunnelid": 0, "remip": "198.51.100.77", "user": "j.cohen", "group": "N/A", "dst_host": "N/A", "reason": "sslvpn_login_permission_denied", "msg": "SSL user failed to logged in",
   "raw": "date=2026-10-01 time=02:14:09 devname=\"FGT-HQ-01\" devid=\"FG200FT921900123\" eventtime=1790810049320000000 tz=\"+0300\" logid=\"0101039426\" type=\"event\" subtype=\"vpn\" level=\"alert\" vd=\"root\" logdesc=\"SSL VPN login fail\" action=\"ssl-login-fail\" tunneltype=\"ssl-web\" tunnelid=0 remip=198.51.100.77 user=\"j.cohen\" group=\"N/A\" dst_host=\"N/A\" reason=\"sslvpn_login_permission_denied\" msg=\"SSL user failed to logged in\""},
  {"date": "2026-10-01", "time": "02:14:12", "devname": "FGT-HQ-01", "devid": "FG200FT921900123", "eventtime": "1790810052870000000", "tz": "+0300", "logid": "0101039426", "type": "event", "subtype": "vpn", "level": "alert", "vd": "root", "logdesc": "SSL VPN login fail", "action": "ssl-login-fail", "tunneltype": "ssl-web", "tunnelid": 0, "remip": "198.51.100.77", "user": "vpn", "group": "N/A", "dst_host": "N/A", "reason": "sslvpn_login_unknown_user", "msg": "SSL user failed to logged in",
   "raw": "date=2026-10-01 time=02:14:12 devname=\"FGT-HQ-01\" devid=\"FG200FT921900123\" eventtime=1790810052870000000 tz=\"+0300\" logid=\"0101039426\" type=\"event\" subtype=\"vpn\" level=\"alert\" vd=\"root\" logdesc=\"SSL VPN login fail\" action=\"ssl-login-fail\" tunneltype=\"ssl-web\" tunnelid=0 remip=198.51.100.77 user=\"vpn\" group=\"N/A\" dst_host=\"N/A\" reason=\"sslvpn_login_unknown_user\" msg=\"SSL user failed to logged in\""}
]
```
(Exact mapping of "wrong password" vs "unknown user" to each reason token is UNVERIFIED; both tokens exist.)

### 4.3 Successful login from a foreign hosting-provider IP at 03:41
```json
{"date": "2026-10-01", "time": "03:41:52", "devname": "FGT-HQ-01", "devid": "FG200FT921900123", "eventtime": "1790815312873000000", "tz": "+0300", "logid": "0101039947", "type": "event", "subtype": "vpn", "level": "information", "vd": "root", "logdesc": "SSL VPN tunnel up", "action": "tunnel-up", "tunneltype": "ssl-tunnel", "tunnelid": 1938377, "remip": "192.0.2.140", "tunnelip": "10.212.134.207", "user": "r.mizrahi", "group": "VPN-Employees", "dst_host": "N/A", "reason": "tunnel established", "msg": "SSL tunnel established",
 "raw": "date=2026-10-01 time=03:41:52 devname=\"FGT-HQ-01\" devid=\"FG200FT921900123\" eventtime=1790815312873000000 tz=\"+0300\" logid=\"0101039947\" type=\"event\" subtype=\"vpn\" level=\"information\" vd=\"root\" logdesc=\"SSL VPN tunnel up\" action=\"tunnel-up\" tunneltype=\"ssl-tunnel\" tunnelid=1938377 remip=192.0.2.140 tunnelip=10.212.134.207 user=\"r.mizrahi\" group=\"VPN-Employees\" dst_host=\"N/A\" reason=\"tunnel established\" msg=\"SSL tunnel established\""}
```
Pair it with the preceding 39424 log carrying `srccountry="Netherlands"` for the same `remip`.

### 4.4 Concurrent sessions — same user, two tunnels from two countries
```json
{"date": "2026-10-01", "time": "09:17:32", "devname": "FGT-HQ-01", "devid": "FG200FT921900123", "eventtime": "1790835452006000000", "tz": "+0300", "logid": "0101039947", "type": "event", "subtype": "vpn", "level": "information", "vd": "root", "logdesc": "SSL VPN tunnel up", "action": "tunnel-up", "tunneltype": "ssl-tunnel", "tunnelid": 1938519, "remip": "198.51.100.203", "tunnelip": "10.212.134.209", "user": "dana.levi", "group": "VPN-Employees", "dst_host": "N/A", "reason": "tunnel established", "msg": "SSL tunnel established",
 "raw": "date=2026-10-01 time=09:17:32 devname=\"FGT-HQ-01\" devid=\"FG200FT921900123\" eventtime=1790835452006000000 tz=\"+0300\" logid=\"0101039947\" type=\"event\" subtype=\"vpn\" level=\"information\" vd=\"root\" logdesc=\"SSL VPN tunnel up\" action=\"tunnel-up\" tunneltype=\"ssl-tunnel\" tunnelid=1938519 remip=198.51.100.203 tunnelip=10.212.134.209 user=\"dana.levi\" group=\"VPN-Employees\" dst_host=\"N/A\" reason=\"tunnel established\" msg=\"SSL tunnel established\""}
```
The 08:02 tunnel of 4.1 (`tunnelip=10.212.134.201`, `remip=203.0.113.24`) has no tunnel-down yet.

### 4.5 Tunnel down with duration and bytes (large upload through VPN)
```json
{"date": "2026-10-01", "time": "11:58:40", "devname": "FGT-HQ-01", "devid": "FG200FT921900123", "eventtime": "1790845120551000000", "tz": "+0300", "logid": "0101039948", "type": "event", "subtype": "vpn", "level": "information", "vd": "root", "logdesc": "SSL VPN tunnel down", "action": "tunnel-down", "tunneltype": "ssl-tunnel", "tunnelid": 1938519, "remip": "198.51.100.203", "tunnelip": "10.212.134.209", "user": "dana.levi", "group": "VPN-Employees", "dst_host": "N/A", "reason": "N/A", "duration": 9668, "sentbyte": 21877340, "rcvdbyte": 3841992017, "msg": "SSL tunnel shutdown",
 "raw": "date=2026-10-01 time=11:58:40 devname=\"FGT-HQ-01\" devid=\"FG200FT921900123\" eventtime=1790845120551000000 tz=\"+0300\" logid=\"0101039948\" type=\"event\" subtype=\"vpn\" level=\"information\" vd=\"root\" logdesc=\"SSL VPN tunnel down\" action=\"tunnel-down\" tunneltype=\"ssl-tunnel\" tunnelid=1938519 remip=198.51.100.203 tunnelip=10.212.134.209 user=\"dana.levi\" group=\"VPN-Employees\" dst_host=\"N/A\" reason=\"N/A\" duration=9668 sentbyte=21877340 rcvdbyte=3841992017 msg=\"SSL tunnel shutdown\""}
```
(Field order and whether `rcvdbyte` counts client->FortiGate bytes in this log are UNVERIFIED.)

## 5. Investigation notes

- **Brute force / spray:** `action="ssl-login-fail"` grouped by `remip` (many distinct `user` = spray; `administrator`, `admin`, `vpn`, `test` are classic) or by `user`. Then search for `action="tunnel-up"` from the same `remip`.
- **Login flow:** `ssl-new-con` (TLS session, no user) -> `tunnel-up` `ssl-web` (`reason="login successfully"`) -> `tunnel-up` `ssl-tunnel` (`tunnelip`). Failures carry `tunneltype="ssl-web"` even when FortiClient was used.
- **Impossible travel / concurrent:** same `user`, overlapping `ssl-tunnel` sessions (no `tunnel-down` with that `tunnelid`) from different `remip`/`srccountry`.
- **Pivot:** `tunnelip` is the user's source IP in FortiGate traffic logs (`srcip`, with `srcintf="ssl.root"`) and in EDR/AD logs; FortiGate traffic logs also carry `user` / `group` for SSL-VPN sessions. `tunnelid` links up/down/stats logs of the same session.
- Hosting-provider/ASN classification is enrichment, not a log field.

## 6. Common mistakes / fields that do NOT exist

- No `srcip`/`dstip` in SSL-VPN event logs — the client is `remip`, the pool address is `tunnelip`. (`srcip` belongs to traffic logs.)
- No `status`, `result`, `outcome`, `country_code`, `mfa`, `login_result` keys. Outcome is encoded in `action` (`ssl-login-fail` vs `tunnel-up`).
- `type` is `event` and `subtype` is `vpn` — not `type="vpn"`, not `subtype="sslvpn"`.
- `logid` is a quoted 10-digit string with leading zero (`"0101039426"`), not `39426`.
- `msg="SSL user failed to logged in"` is Fortinet's actual (ungrammatical) wording — don't "fix" it.
- Don't output Wazuh `data.*` / `rule.*` envelopes or Elastic `fortinet.firewall.*` fields.
