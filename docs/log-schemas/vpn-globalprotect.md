# Palo Alto Networks GlobalProtect (PAN-OS GLOBALPROTECT log type)

Category: Remote access / VPN. Vendor: Palo Alto Networks. Native format: PAN-OS syslog CSV (text-native).
Platform representation: **flat JSON whose keys are the PAN-OS syslog variable names** + `raw` (the CSV line).

---

## 1. Official sources

| Source | What it confirmed |
|---|---|
| https://docs.paloaltonetworks.com/pan-os/11-1/pan-os-admin/monitoring/use-syslog-for-monitoring/syslog-field-descriptions/globalprotect-log-fields | Full ordered CSV format string; every field's display name + syslog variable name (`eventid`, `stage`, `auth_method`, `tunnel_type`, `srcuser`, `srcregion`, `machinename`, `public_ip`, `private_ip`, `hostid`, `serialnumber`, `client_ver`, `client_os`, `client_os_ver`, `repeatcnt`, `reason`, `error`, `opaque`, `status`, `location`, `login_duration`, `connect_method`, `error_code`, `portal`, `seqno`, `actionflags`, `selection_type`, `response_time`, `priority`, `attempted_gateways`, `gateway`, `dg_hier_level_1..4`, `vsys_name`, `device_name`, `vsys_id`, `cluster_name`). Documented enums: stage, auth_method, tunnel_type, status, connect_method, selection_type, priority. |
| https://docs.paloaltonetworks.com/ngfw/administration/monitoring/use-syslog-for-monitoring/syslog-field-descriptions/globalprotect-log-fields | Same list (current NGFW doc tree). |
| https://github.com/elastic/integrations/blob/main/packages/panw/data_stream/panos/_dev/test/pipeline/test-panw-panos-globalprotect-sample.log | Real raw GLOBALPROTECT lines: `subtype` is `0`, 6th column is a FUTURE_USE number, event IDs `portal-prelogin`, `portal-getconfig`, `gateway-auth`, `gateway-getconfig`, `gateway-hip-check`, `gateway-setup-ipsec`, `gateway-tunnel-latency`, `gateway-config-release`; stages `before-login`, `login`, `configuration`, `host-info`, `tunnel`; quoted `client_os_ver` like `"OS 10 Enterprise, 64-bit"`. |
| https://live.paloaltonetworks.com/t5/globalprotect-discussions/what-does-it-mean-stage-and-event-globalprotect-fields/td-p/411623 and https://docs.logrhythm.com/devices/docs/v-2-0-general-globalprotect-messages | Event-ID meanings: `gateway-register`, `gateway-connected`, `gateway-logout`, `gateway-switch-to-ssl`, `gateway-config-release`; stage list incl. `configuration`/`host-info`. |

## 2. Native format and delivery

- Since PAN-OS 9.1 GlobalProtect activity is its own log type (`type=GLOBALPROTECT`), visible in Monitor > Logs > GlobalProtect and forwarded via a Log Forwarding profile (syslog BSD/IETF, or to Panorama / Strata Logging Service). Before 9.1 these were SYSTEM logs with subtype `globalprotect` — do not mix the two.
- Wire format: syslog header + comma-separated values in the fixed order below. Values containing commas are double-quoted.
- Timestamps: `receive_time` / `time_generated` = `YYYY/MM/DD HH:MM:SS` (firewall local time, no zone); `high_res_timestamp` = ISO-8601 with ms and offset.
- **We standardise on:** a flat JSON object, keys = syslog variable names exactly as in the PAN doc, values as strings (as on the wire), plus `raw`. The two FUTURE_USE columns are not emitted as keys.

Column order (1-based, as on the wire):
`FUTURE_USE, receive_time, serial, type, subtype, FUTURE_USE, time_generated, vsys, eventid, stage, auth_method, tunnel_type, srcuser, srcregion, machinename, public_ip, public_ipv6, private_ip, private_ipv6, hostid, serialnumber, client_ver, client_os, client_os_ver, repeatcnt, reason, error, opaque, status, location, login_duration, connect_method, error_code, portal, seqno, actionflags, high_res_timestamp, selection_type, response_time, priority, attempted_gateways, gateway, dg_hier_level_1, dg_hier_level_2, dg_hier_level_3, dg_hier_level_4, vsys_name, device_name, vsys_id, cluster_name`

## 3. Core field reference

| Field | Meaning | Values / notes |
|---|---|---|
| `receive_time` | Time the management plane received the log | `2026/10/01 08:02:11` |
| `serial` | Firewall serial number | 12 digits |
| `type` | Log type | always `GLOBALPROTECT` |
| `subtype` | Subtype column | observed `0` in real logs |
| `time_generated` | Time the dataplane generated the event | same format as receive_time |
| `vsys` | Virtual system | `vsys1` |
| `eventid` | Event name (string, not a number) | `portal-prelogin`, `portal-auth`, `portal-getconfig`, `gateway-prelogin`, `gateway-auth`, `gateway-getconfig`, `gateway-register`, `gateway-hip-check`, `gateway-hip-report`, `gateway-setup-ipsec`, `gateway-setup-ssl`, `gateway-switch-to-ssl`, `gateway-tunnel-latency`, `gateway-connected`, `gateway-config-release`, `gateway-logout` (list not exhaustive; `gateway-prelogin`, `gateway-hip-report`, `gateway-setup-ssl` UNVERIFIED in official doc) |
| `stage` | Connection stage | doc: `before-login`, `login`, `tunnel`; real logs also `configuration`, `host-info`, `logout` (`logout` UNVERIFIED in doc) |
| `auth_method` | Auth type | `LDAP`, `RADIUS`, `SAML`, `Kerberos`, `Local DB`, `Other` (empty on non-auth events) |
| `tunnel_type` | Tunnel type | `IPSec`, `SSLVPN` (empty before tunnel) |
| `srcuser` | Username as entered / from IdP | `user`, `domain\user`, or UPN; `pre-logon` for pre-logon tunnels |
| `srcregion` | Region (country code or address-range name) of the client public IP | `IL`, `NL`, or `10.0.0.0-10.255.255.255` for private |
| `machinename` | Endpoint hostname | `NXC-LT-0412` |
| `public_ip` / `public_ipv6` | Client's public IP | unused family = `0.0.0.0` |
| `private_ip` / `private_ipv6` | IP assigned inside the tunnel (pool) | `0.0.0.0` until tunnel is up |
| `hostid` | GP-assigned host ID (GUID-like) | stable per device install |
| `serialnumber` | Endpoint hardware serial | |
| `client_ver` | GP app version | `6.2.4-28` |
| `client_os` / `client_os_ver` | Endpoint OS / version string | `Microsoft Windows` / `"Microsoft Windows 11 Enterprise , 64-bit"` |
| `repeatcnt` | Identical events within 5 s | integer |
| `reason` | Quarantine reason | mostly empty |
| `error` | Error string | e.g. `Authentication failed: Invalid username or password` |
| `opaque` | "Description" free text | e.g. `Client region: IL, Client version: ..., Login from: ...` (wording UNVERIFIED, varies by event) |
| `status` | Outcome | `success`, `failure` |
| `location` | Admin-defined location of portal/gateway | |
| `login_duration` | Seconds the user stayed connected (on logout) | integer |
| `connect_method` | Connect method | `user-logon`, `pre-logon`, `on-demand` |
| `error_code` | Integer error code | `0` = none; specific codes UNVERIFIED |
| `portal` | Portal or gateway name | `GP-Portal-HQ`, `GP-GW-HQ` |
| `seqno` | 64-bit log sequence number | unique per firewall |
| `actionflags` | Panorama forwarding bitfield | `0x0`, `0x8000000000000000` |
| `high_res_timestamp` | ms-resolution time | `2026-10-01T08:02:11.114+03:00` |
| `selection_type` | Gateway selection | `manual`, `preferred`, `auto` |
| `response_time` | Gateway SSL response time (ms) | |
| `priority` | Gateway priority | `1` (highest) .. `5`; real logs also show strings like `manual only` |
| `attempted_gateways` | Gateways tried (comma-separated, quoted) | |
| `gateway` | Selected gateway | |
| `dg_hier_level_1..4`, `vsys_name`, `device_name`, `vsys_id`, `cluster_name` | Panorama hierarchy / device identity | `device_name` = firewall hostname |

## 4. Realistic samples

### 4.1 Successful SAML portal login from the user's usual country (IL)
```json
{
  "receive_time": "2026/10/01 08:02:11",
  "serial": "016201004321",
  "type": "GLOBALPROTECT",
  "subtype": "0",
  "time_generated": "2026/10/01 08:02:10",
  "vsys": "vsys1",
  "eventid": "portal-auth",
  "stage": "login",
  "auth_method": "SAML",
  "tunnel_type": "",
  "srcuser": "dana.levi@nexacorp.co.il",
  "srcregion": "IL",
  "machinename": "NXC-LT-0412",
  "public_ip": "203.0.113.24",
  "public_ipv6": "0.0.0.0",
  "private_ip": "0.0.0.0",
  "private_ipv6": "0.0.0.0",
  "hostid": "6c1f3e2a-8b7d-4c19-9e55-0a2f7d1c4b90",
  "serialnumber": "PF3K9Z2A",
  "client_ver": "6.2.4-28",
  "client_os": "Microsoft Windows",
  "client_os_ver": "Microsoft Windows 11 Enterprise , 64-bit",
  "repeatcnt": "1",
  "reason": "",
  "error": "",
  "opaque": "Client region: IL, Client version: 6.2.4-28, Device name: NXC-LT-0412, Login from: 203.0.113.24.",
  "status": "success",
  "location": "",
  "login_duration": "0",
  "connect_method": "",
  "error_code": "0",
  "portal": "GP-Portal-HQ",
  "seqno": "7412983300185523201",
  "actionflags": "0x0",
  "high_res_timestamp": "2026-10-01T08:02:11.114+03:00",
  "selection_type": "",
  "response_time": "0",
  "priority": "",
  "attempted_gateways": "",
  "gateway": "",
  "dg_hier_level_1": "12",
  "dg_hier_level_2": "0",
  "dg_hier_level_3": "0",
  "dg_hier_level_4": "0",
  "vsys_name": "",
  "device_name": "PA-3220-HQ",
  "vsys_id": "1",
  "cluster_name": "",
  "raw": "<14>Oct  1 08:02:11 PA-3220-HQ 1,2026/10/01 08:02:11,016201004321,GLOBALPROTECT,0,2817,2026/10/01 08:02:10,vsys1,portal-auth,login,SAML,,dana.levi@nexacorp.co.il,IL,NXC-LT-0412,203.0.113.24,0.0.0.0,0.0.0.0,0.0.0.0,6c1f3e2a-8b7d-4c19-9e55-0a2f7d1c4b90,PF3K9Z2A,6.2.4-28,Microsoft Windows,\"Microsoft Windows 11 Enterprise , 64-bit\",1,,,\"Client region: IL, Client version: 6.2.4-28, Device name: NXC-LT-0412, Login from: 203.0.113.24.\",success,,0,,0,GP-Portal-HQ,7412983300185523201,0x0,2026-10-01T08:02:11.114+03:00,,0,,,,12,0,0,0,,PA-3220-HQ,1,"
}
```

### 4.2 Tunnel up (gateway-connected) — same user, pool IP assigned
```json
{"receive_time": "2026/10/01 08:02:19", "serial": "016201004321", "type": "GLOBALPROTECT", "subtype": "0", "time_generated": "2026/10/01 08:02:18", "vsys": "vsys1", "eventid": "gateway-connected", "stage": "tunnel", "auth_method": "", "tunnel_type": "IPSec", "srcuser": "dana.levi@nexacorp.co.il", "srcregion": "IL", "machinename": "NXC-LT-0412", "public_ip": "203.0.113.24", "public_ipv6": "0.0.0.0", "private_ip": "10.212.4.37", "private_ipv6": "0.0.0.0", "hostid": "6c1f3e2a-8b7d-4c19-9e55-0a2f7d1c4b90", "serialnumber": "PF3K9Z2A", "client_ver": "6.2.4-28", "client_os": "Microsoft Windows", "client_os_ver": "Microsoft Windows 11 Enterprise , 64-bit", "repeatcnt": "1", "reason": "", "error": "", "opaque": "", "status": "success", "location": "", "login_duration": "0", "connect_method": "user-logon", "error_code": "0", "portal": "GP-GW-HQ", "seqno": "7412983300185523207", "actionflags": "0x0", "high_res_timestamp": "2026-10-01T08:02:19.402+03:00", "selection_type": "auto", "response_time": "38", "priority": "1", "attempted_gateways": "GP-GW-HQ,GP-GW-DR", "gateway": "GP-GW-HQ", "dg_hier_level_1": "12", "dg_hier_level_2": "0", "dg_hier_level_3": "0", "dg_hier_level_4": "0", "vsys_name": "", "device_name": "PA-3220-HQ", "vsys_id": "1", "cluster_name": "", "raw": "<14>Oct  1 08:02:19 PA-3220-HQ 1,2026/10/01 08:02:19,016201004321,GLOBALPROTECT,0,2817,2026/10/01 08:02:18,vsys1,gateway-connected,tunnel,,IPSec,dana.levi@nexacorp.co.il,IL,NXC-LT-0412,203.0.113.24,0.0.0.0,10.212.4.37,0.0.0.0,6c1f3e2a-8b7d-4c19-9e55-0a2f7d1c4b90,PF3K9Z2A,6.2.4-28,Microsoft Windows,\"Microsoft Windows 11 Enterprise , 64-bit\",1,,,,success,,0,user-logon,0,GP-GW-HQ,7412983300185523207,0x0,2026-10-01T08:02:19.402+03:00,auto,38,1,\"GP-GW-HQ,GP-GW-DR\",GP-GW-HQ,12,0,0,0,,PA-3220-HQ,1,"}
```

### 4.3 Brute force / password spray against the portal (3 users, one source IP, seconds apart)
```json
{"receive_time": "2026/10/01 02:14:07", "serial": "016201004321", "type": "GLOBALPROTECT", "subtype": "0", "time_generated": "2026/10/01 02:14:07", "vsys": "vsys1", "eventid": "portal-auth", "stage": "login", "auth_method": "LDAP", "tunnel_type": "", "srcuser": "admin", "srcregion": "RU", "machinename": "", "public_ip": "198.51.100.77", "public_ipv6": "0.0.0.0", "private_ip": "0.0.0.0", "private_ipv6": "0.0.0.0", "hostid": "", "serialnumber": "", "client_ver": "", "client_os": "", "client_os_ver": "", "repeatcnt": "1", "reason": "", "error": "Authentication failed: Invalid username or password", "opaque": "Client region: RU, Login from: 198.51.100.77, Source region: RU.", "status": "failure", "location": "", "login_duration": "0", "connect_method": "", "error_code": "0", "portal": "GP-Portal-HQ", "seqno": "7412983300185544010", "actionflags": "0x0", "high_res_timestamp": "2026-10-01T02:14:07.100+03:00", "selection_type": "", "response_time": "0", "priority": "", "attempted_gateways": "", "gateway": "", "dg_hier_level_1": "12", "dg_hier_level_2": "0", "dg_hier_level_3": "0", "dg_hier_level_4": "0", "vsys_name": "", "device_name": "PA-3220-HQ", "vsys_id": "1", "cluster_name": "", "raw": "<14>Oct  1 02:14:07 PA-3220-HQ 1,2026/10/01 02:14:07,016201004321,GLOBALPROTECT,0,2817,2026/10/01 02:14:07,vsys1,portal-auth,login,LDAP,,admin,RU,,198.51.100.77,0.0.0.0,0.0.0.0,0.0.0.0,,,,,,1,,Authentication failed: Invalid username or password,\"Client region: RU, Login from: 198.51.100.77, Source region: RU.\",failure,,0,,0,GP-Portal-HQ,7412983300185544010,0x0,2026-10-01T02:14:07.100+03:00,,0,,,,12,0,0,0,,PA-3220-HQ,1,"}
```
Follow-on lines (same JSON shape; only `srcuser`, times and `seqno` differ):
```
<14>Oct  1 02:14:09 PA-3220-HQ 1,2026/10/01 02:14:09,016201004321,GLOBALPROTECT,0,2817,2026/10/01 02:14:09,vsys1,portal-auth,login,LDAP,,j.cohen,RU,,198.51.100.77,0.0.0.0,0.0.0.0,0.0.0.0,,,,,,1,,Authentication failed: Invalid username or password,"Client region: RU, Login from: 198.51.100.77, Source region: RU.",failure,,0,,0,GP-Portal-HQ,7412983300185544013,0x0,2026-10-01T02:14:09.107+03:00,,0,,,,12,0,0,0,,PA-3220-HQ,1,
<14>Oct  1 02:14:12 PA-3220-HQ 1,2026/10/01 02:14:12,016201004321,GLOBALPROTECT,0,2817,2026/10/01 02:14:12,vsys1,portal-auth,login,LDAP,,helpdesk,RU,,198.51.100.77,0.0.0.0,0.0.0.0,0.0.0.0,,,,,,1,,Authentication failed: Invalid username or password,"Client region: RU, Login from: 198.51.100.77, Source region: RU.",failure,,0,,0,GP-Portal-HQ,7412983300185544019,0x0,2026-10-01T02:14:12.114+03:00,,0,,,,12,0,0,0,,PA-3220-HQ,1,
```

### 4.4 Successful login from a foreign hosting-provider IP at 03:41 (unknown device, old client)
```json
{"receive_time": "2026/10/01 03:41:52", "serial": "016201004321", "type": "GLOBALPROTECT", "subtype": "0", "time_generated": "2026/10/01 03:41:51", "vsys": "vsys1", "eventid": "gateway-auth", "stage": "login", "auth_method": "LDAP", "tunnel_type": "", "srcuser": "nexacorp\\r.mizrahi", "srcregion": "NL", "machinename": "DESKTOP-8QF2L1M", "public_ip": "192.0.2.140", "public_ipv6": "0.0.0.0", "private_ip": "0.0.0.0", "private_ipv6": "0.0.0.0", "hostid": "0d4e91aa-77c2-4f0b-b3e1-5f8a2c6d9e13", "serialnumber": "", "client_ver": "6.0.7-11", "client_os": "Microsoft Windows", "client_os_ver": "Microsoft Windows 10 Pro , 64-bit", "repeatcnt": "1", "reason": "", "error": "", "opaque": "Client region: NL, Client version: 6.0.7-11, Device name: DESKTOP-8QF2L1M, Login from: 192.0.2.140.", "status": "success", "location": "", "login_duration": "0", "connect_method": "on-demand", "error_code": "0", "portal": "GP-GW-HQ", "seqno": "7412983300185547702", "actionflags": "0x0", "high_res_timestamp": "2026-10-01T03:41:52.873+03:00", "selection_type": "auto", "response_time": "91", "priority": "1", "attempted_gateways": "", "gateway": "GP-GW-HQ", "dg_hier_level_1": "12", "dg_hier_level_2": "0", "dg_hier_level_3": "0", "dg_hier_level_4": "0", "vsys_name": "", "device_name": "PA-3220-HQ", "vsys_id": "1", "cluster_name": "", "raw": "<14>Oct  1 03:41:52 PA-3220-HQ 1,2026/10/01 03:41:52,016201004321,GLOBALPROTECT,0,2817,2026/10/01 03:41:51,vsys1,gateway-auth,login,LDAP,,nexacorp\\r.mizrahi,NL,DESKTOP-8QF2L1M,192.0.2.140,0.0.0.0,0.0.0.0,0.0.0.0,0d4e91aa-77c2-4f0b-b3e1-5f8a2c6d9e13,,6.0.7-11,Microsoft Windows,\"Microsoft Windows 10 Pro , 64-bit\",1,,,\"Client region: NL, Client version: 6.0.7-11, Device name: DESKTOP-8QF2L1M, Login from: 192.0.2.140.\",success,,0,on-demand,0,GP-GW-HQ,7412983300185547702,0x0,2026-10-01T03:41:52.873+03:00,auto,91,1,,GP-GW-HQ,12,0,0,0,,PA-3220-HQ,1,"}
```

### 4.5 Concurrent session — same user connects from DE on a VM while the IL tunnel (4.2) is still up
```json
{"receive_time": "2026/10/01 09:17:33", "serial": "016201004321", "type": "GLOBALPROTECT", "subtype": "0", "time_generated": "2026/10/01 09:17:32", "vsys": "vsys1", "eventid": "gateway-connected", "stage": "tunnel", "auth_method": "", "tunnel_type": "SSLVPN", "srcuser": "dana.levi@nexacorp.co.il", "srcregion": "DE", "machinename": "WIN-K7T2M0QX", "public_ip": "198.51.100.203", "public_ipv6": "0.0.0.0", "private_ip": "10.212.4.91", "private_ipv6": "0.0.0.0", "hostid": "a93be0d4-1c55-4e7a-8f20-6b7d3e2c1f08", "serialnumber": "VMware-56 4d 1a 9e", "client_ver": "6.2.4-28", "client_os": "Microsoft Windows", "client_os_ver": "Microsoft Windows Server 2022 , 64-bit", "repeatcnt": "1", "reason": "", "error": "", "opaque": "", "status": "success", "location": "", "login_duration": "0", "connect_method": "on-demand", "error_code": "0", "portal": "GP-GW-HQ", "seqno": "7412983300185561130", "actionflags": "0x0", "high_res_timestamp": "2026-10-01T09:17:33.006+03:00", "selection_type": "auto", "response_time": "64", "priority": "1", "attempted_gateways": "GP-GW-HQ", "gateway": "GP-GW-HQ", "dg_hier_level_1": "12", "dg_hier_level_2": "0", "dg_hier_level_3": "0", "dg_hier_level_4": "0", "vsys_name": "", "device_name": "PA-3220-HQ", "vsys_id": "1", "cluster_name": "", "raw": "<14>Oct  1 09:17:33 PA-3220-HQ 1,2026/10/01 09:17:33,016201004321,GLOBALPROTECT,0,2817,2026/10/01 09:17:32,vsys1,gateway-connected,tunnel,,SSLVPN,dana.levi@nexacorp.co.il,DE,WIN-K7T2M0QX,198.51.100.203,0.0.0.0,10.212.4.91,0.0.0.0,a93be0d4-1c55-4e7a-8f20-6b7d3e2c1f08,VMware-56 4d 1a 9e,6.2.4-28,Microsoft Windows,\"Microsoft Windows Server 2022 , 64-bit\",1,,,,success,,0,on-demand,0,GP-GW-HQ,7412983300185561130,0x0,2026-10-01T09:17:33.006+03:00,auto,64,1,GP-GW-HQ,GP-GW-HQ,12,0,0,0,,PA-3220-HQ,1,"}
```

### 4.6 Logout with session duration (closes 4.2; 34963 s = 9 h 42 m)
```json
{"receive_time": "2026/10/01 17:45:02", "serial": "016201004321", "type": "GLOBALPROTECT", "subtype": "0", "time_generated": "2026/10/01 17:45:01", "vsys": "vsys1", "eventid": "gateway-logout", "stage": "logout", "auth_method": "", "tunnel_type": "IPSec", "srcuser": "dana.levi@nexacorp.co.il", "srcregion": "IL", "machinename": "NXC-LT-0412", "public_ip": "203.0.113.24", "public_ipv6": "0.0.0.0", "private_ip": "10.212.4.37", "private_ipv6": "0.0.0.0", "hostid": "6c1f3e2a-8b7d-4c19-9e55-0a2f7d1c4b90", "serialnumber": "PF3K9Z2A", "client_ver": "6.2.4-28", "client_os": "Microsoft Windows", "client_os_ver": "Microsoft Windows 11 Enterprise , 64-bit", "repeatcnt": "1", "reason": "", "error": "", "opaque": "Logout reason: client logout.", "status": "success", "location": "", "login_duration": "34963", "connect_method": "user-logon", "error_code": "0", "portal": "GP-GW-HQ", "seqno": "7412983300185599921", "actionflags": "0x0", "high_res_timestamp": "2026-10-01T17:45:02.551+03:00", "selection_type": "", "response_time": "0", "priority": "", "attempted_gateways": "", "gateway": "GP-GW-HQ", "dg_hier_level_1": "12", "dg_hier_level_2": "0", "dg_hier_level_3": "0", "dg_hier_level_4": "0", "vsys_name": "", "device_name": "PA-3220-HQ", "vsys_id": "1", "cluster_name": "", "raw": "<14>Oct  1 17:45:02 PA-3220-HQ 1,2026/10/01 17:45:02,016201004321,GLOBALPROTECT,0,2817,2026/10/01 17:45:01,vsys1,gateway-logout,logout,,IPSec,dana.levi@nexacorp.co.il,IL,NXC-LT-0412,203.0.113.24,0.0.0.0,10.212.4.37,0.0.0.0,6c1f3e2a-8b7d-4c19-9e55-0a2f7d1c4b90,PF3K9Z2A,6.2.4-28,Microsoft Windows,\"Microsoft Windows 11 Enterprise , 64-bit\",1,,,\"Logout reason: client logout.\",success,,34963,user-logon,0,GP-GW-HQ,7412983300185599921,0x0,2026-10-01T17:45:02.551+03:00,,0,,,GP-GW-HQ,12,0,0,0,,PA-3220-HQ,1,"}
```
(The exact `opaque` wording for logout is UNVERIFIED.)

## 5. Investigation notes

- **Session lifecycle:** `portal-prelogin` -> `portal-auth` -> `portal-getconfig` -> `gateway-auth` -> `gateway-getconfig` -> `gateway-register` -> `gateway-hip-check` -> `gateway-setup-ipsec` (or `-ssl`) -> `gateway-connected` -> ... -> `gateway-logout`. Failures stop at the auth step with `status=failure` and `error` populated.
- **Brute force / spray:** group `status=failure` + `eventid in (portal-auth, gateway-auth)` by `public_ip` (many `srcuser` = spray) or by `srcuser` (many failures = brute force). Watch for the first `success` from the same `public_ip` afterwards.
- **Impossible travel / concurrent sessions:** same `srcuser`, two `gateway-connected` with different `public_ip`/`srcregion` and no `gateway-logout` in between. Different `hostid`/`machinename`/`serialnumber` (here a VM serial `VMware-...`) means a different device = likely credential theft.
- **Device fingerprint:** `hostid`, `machinename`, `serialnumber`, `client_ver`, `client_os_ver`. An unmanaged hostname (`DESKTOP-XXXXXXX`), empty serial, or an outdated `client_ver` on a user who normally runs the corporate build is a strong signal.
- **Pivot to the rest of the network:** the tunnel IP `private_ip` becomes the user's source IP in PAN-OS TRAFFIC/THREAT logs (`src`) and in EDR/AD logs (e.g. Windows 4624 `IpAddress`). PAN-OS User-ID maps `private_ip` -> `srcuser`, so TRAFFIC logs carry the same user in `srcuser`. Bound the window with `gateway-connected` .. `gateway-logout`.
- ASN / hosting-provider classification is **not** in the log — it comes from enrichment of `public_ip`.

## 6. Common mistakes / fields that do NOT exist

- No `src_ip`, `source.ip`, `user.name`, `client_ip`, `country`, `geo`, `asn`, `event_type`, `result`, `mfa` fields. Country is `srcregion`; IPs are `public_ip` / `private_ip`.
- `eventid` is a string like `gateway-auth`, never a numeric ID; `type` is `GLOBALPROTECT` (not `SYSTEM`, not `TRAFFIC`).
- `status` is lowercase `success`/`failure` (not `allowed`/`denied`, not `Success`).
- `tunnel_type` values are `IPSec` and `SSLVPN` exactly (not `ssl`, `ipsec`, `SSL-VPN`).
- GP logs carry no bytes/packets counters and no destination — traffic volume lives in TRAFFIC logs.
- Do not use the Wazuh/Elastic shapes (`data.srcuser`, `panw.panos.*`, `observer.serial_number`).
- MFA detail is not in GP logs; for SAML it lives in the IdP (Entra/Okta) sign-in log.
