# Virtualization: VMware vSphere (vCenter Server events, ESXi host syslog)

Category: Virtualization / hypervisor · Vendor: VMware by Broadcom · Card status: researched 2026-11-11

vSphere produces two different native log families. They must never be mixed in one record:

| Output | What it is | Shape on the wire |
|---|---|---|
| **vCenter Server event stream** (`vpxd`) | Every `vim.event.*` data object vCenter stores in its event database (logins, permission and role changes, VM power and inventory changes, alarms, host events, and `EventEx` / `ExtendedEvent` items such as `com.vmware.sso.*` and `esx.audit.*`) | (a) **Syslog**: RFC 5424 line from program `vpxd`, body `Event [eventId] [partInfo] [createdTime] [eventType] [severity] [user] [target] [chainId] [desc]`. (b) **API JSON**: the event data object as returned by `EventManager.QueryEvents` (VI/JSON API), camelCase keys plus `_typeName` |
| **ESXi host syslog** (`vmsyslogd`) | Per-daemon log streams of the host: `auth.log` (sshd, login), `shell.log` (every ESXi Shell command), `hostd.log` (host agent: API/Host Client sessions, tasks, host events), `vobd.log` (VMkernel observations, `vob.*` and `esx.audit.*` ids), `syslog.log`, `vmkernel.log` | RFC 3164 (default) or RFC 5424 syslog line, one line per message; program names `sshd` (or `sshd-session`), `shell`, `Hostd`, `vobd`, `vmkernel`, `vpxa`; hostd lines carry `[Originator@6876 sub=... opID=... sid=... user=...]` |

Platform rule: a vCenter record is rendered either as the **flat vpxd syslog record** (default for SOC feeds, this is what most SIEMs receive) or as the **API event object** (for "pulled via API" stories). An ESXi record is always a **flat syslog record** keyed by syslog header names plus the vendor tokens parsed from the message (`Originator`, `sub`, `opID`, `sid`, `user`, `vob_id`). Never put `esx.audit.*` text on a vpxd line unless it arrived through vCenter as an event, and never put vCenter `Event [..]` brackets on an ESXi line.

---

## 1. Official / primary sources consulted

| URL | What it confirmed |
|---|---|
| https://developer.broadcom.com/xapis/virtual-infrastructure-json-api/latest/data-structures/Event/ | Base `Event` properties: `key` (int32, required, "The event ID"), `chainId` (int32, required, "The parent or group ID"), `createdTime` (date-time, required), `userName` (string, required, "The user who caused the event"), optional `datacenter`, `computeResource`, `host`, `vm`, `ds`, `net`, `dvs`, `tgw` (9.1+) entity arguments (each `{_typeName, name, <moref>{_typeName,type,value}}`), `fullFormattedMessage` (may be localized), `changeTag`, `auditId` (9.1+). Subtype families: `SessionEvent`, `AuthorizationEvent`, `AlarmEvent`, `HostEvent`, `VmEvent`, `TaskEvent`, `EventEx`, `GeneralEvent` ... |
| https://developer.broadcom.com/xapis/virtual-infrastructure-json-api/latest/data-structures/UserLoginSessionEvent/ | Own fields `ipAddress` (required, "IP address of the peer that initiated the connection", may be a proxy), `userAgent` (optional), `locale` (required), `sessionId` (required) |
| https://developer.broadcom.com/xapis/virtual-infrastructure-json-api/latest/data-structures/UserLogoutSessionEvent/ | Own fields `ipAddress`, `userAgent`, `callCount` (int64), `sessionId`, `loginTime` (date-time) |
| https://developer.broadcom.com/xapis/virtual-infrastructure-json-api/latest/data-structures/BadUsernameSessionEvent/ | Own field `ipAddress` (required); extends `SessionEvent` |
| https://developer.broadcom.com/xapis/virtual-infrastructure-json-api/latest/data-structures/PermissionAddedEvent/ | Fields `entity{_typeName,name,entity{type,value}}`, `principal` (string), `group` (boolean), `role{_typeName,roleId,name}` (required), `propagate` (boolean, required, "applies to sub-entities") |
| https://developer.broadcom.com/xapis/virtual-infrastructure-json-api/latest/data-structures/RoleUpdatedEvent/ | `role{roleId,name}`, `privilegeList[]`, `prevRoleName`, `privilegesAdded[]`, `privilegesRemoved[]` |
| https://developer.broadcom.com/xapis/virtual-infrastructure-json-api/latest/data-structures/AlarmStatusChangedEvent/ | Own fields `source`, `entity` (both `{_typeName,name,entity{type,value}}`), `from`, `to` (strings); inherits `alarm` from `AlarmEvent` |
| https://developer.broadcom.com/xapis/virtual-infrastructure-json-api/latest/data-structures/EventEx/ | `eventTypeId` (required, the dynamic type such as `com.vmware.sso.LoginFailure`), `severity` (null = info), `message`, `arguments[]` (KeyAnyValue), `objectId`, `objectType`, `objectName`, `fault` |
| https://developer.broadcom.com/xapis/virtual-infrastructure-json-api/latest/sdk/vim25/release/EventManager/moId/QueryEvents/post/ | API pull path `POST https://{vcenter}/sdk/vim25/{release}/EventManager/{moId}/QueryEvents` with `filter{time, userName, entity, eventTypeId[], type[], category[], maxCount ...}`; response = JSON array of event objects |
| https://github.com/lamw/vcenter-event-mapping (`vsphere-8.0u3.md`) | vCenter 8.0 U3 event catalog (2194 ids): confirms `UserLoginSessionEvent`, `UserLogoutSessionEvent`, `BadUsernameSessionEvent`, `PermissionAddedEvent` / `PermissionUpdatedEvent` / `PermissionRemovedEvent`, `RoleAddedEvent` / `RoleUpdatedEvent` / `RoleRemovedEvent`, `AccountCreatedEvent` / `AccountUpdatedEvent` / `AccountRemovedEvent`, `VmPoweredOffEvent`, `VmRemovedEvent`, `VmReconfiguredEvent`, `HostConnectedEvent`, `AlarmStatusChangedEvent`, EventEx ids `com.vmware.cis.CreatePermission`, `com.vmware.cis.CreateGlobalPermission`, `com.vmware.sso.LoginSuccess` / `LoginFailure` / `PrincipalManagement` / `LockoutPolicy`, ESXi ids `esx.audit.ssh.enabled` / `esx.audit.ssh.session.opened` / `esx.audit.ssh.session.failed`, `esx.audit.shell.enabled`, `esx.audit.lockdownmode.enabled` / `disabled` ("Administrator access to the host has been enabled."), `esx.audit.lockdownmode.exceptions.changed`, `esx.audit.account.locked`, `esx.audit.account.loginfailures`, `esx.audit.net.firewall.disabled` ("Firewall has been disabled."), `esx.audit.net.firewall.config.changed`, `esx.audit.uw.security.execInstalledOnly.violation`, `esx.audit.uw.security.User.ExecInstalledOnly.disabled`, `esx.audit.esximage.install.nosigcheck`, `esx.problem.vmsyslogd.remote.failure`. (Community repo by a VMware engineer, generated from `EventManager.description`; treated as primary-equivalent for ids only) |
| https://techdocs.broadcom.com/ (vSphere 8.0 Monitoring and Performance, "Streaming Events to a Remote Syslog Server"; legacy URL docs.vmware.com/en/VMware-vSphere/8.0/vsphere-monitoring-performance/GUID-F92A08A1-646A-4DCD-8DB0-47E6D2B49C5D.html) | vpxd event line layout `Event [eventId] [partInfo] [createdTime] [eventType] [severity] [user] [target] [chainId] [desc]`; prefix set by syslog config; events longer than 1024 characters are split into several syslog messages with `partInfo` `1-X`, `2-X` ...; streaming configured from the VAMI |
| https://knowledge.broadcom.com/external/article/410301/remote-event-streaming-for-vcenter-serve.html | Advanced setting `vpxd.event.syslog.enabled = TRUE` is what makes vCenter stream events to the remote syslog target |
| https://knowledge.broadcom.com/external/article/431046 | vCenter cannot forward syslog in RFC 3164 (BSD) format: vCenter output is RFC 5424 only |
| https://knowledge.broadcom.com/external/article/449467/the-vpxd-vmreconfiguredevent-messages-ar.html | Real vpxd line `vpxd[7165] Event [5680655] [1-1] [...] [vim.event.VmReconfiguredEvent] [info] [VSPHERE.LOCAL\Administrator] [<DATACENTER>] [5680652] [Reconfigured <VM> on <ESX> in <DATACENTER>.` (chainId differs from key: chained to the task event); multi-line `Modified:` / `Added:` / `Deleted:` continuation lines arrive as separate syslog messages |
| https://knowledge.broadcom.com/external/article/418568 | Real vpxd line `vpxd[19009]: Event [153325] [1-1] [2025-11-16T07:47:01.801868Z] [vim.event.VmRemovedEvent] ... [VSPHERE.LOCAL\Administrator] [Datacenter] [153324] [Removed <VM> on <ESXi FQDN> from Datacenter]` |
| https://knowledge.broadcom.com/external/article/376043/user-ad-account-getting-locked-out-and-a.html | Real vpxd line `vpxd[#####] : Event [#####] [1-1] [...] [vim.event.BadUsernameSessionEvent] ... [Cannot login UserName@Domain@ClientIP]` |
| https://williamlam.com/2021/11/monitoring-vsphere-account-password-permission-changes.html | Real permission event: `fullFormattedMessage` `Permission created for VSPHERE.LOCAL\readonly-svc on Datacenters, role is Administrator, propagation is Enabled`, `principal`, `role.name`, `propagate:true`; removal text `Permission rule removed for <principal> on <entity>`; `com.vmware.sso.PrincipalManagement` message `Principal Management event by <user> at <date> GMT : Resetting local person user '<name>' password` (shown in PowerCLI PascalCase; native API keys are camelCase) |
| https://raw.githubusercontent.com/elastic/integrations/main/packages/vsphere/data_stream/log/_dev/test/pipeline/test-format-common.log | Real SIEM-received lines: vCenter `<14>1 2021-09-06T14:40:13.263383+00:00 vcenter vpxd 58650 - -  Event [575792] [1-1] [2021-09-06T14:40:13.26309Z] [vim.event.UserLoginSessionEvent] [info] [VSPHERE.LOCAL\Administrator] [] [575792] [User VSPHERE.LOCAL\Administrator@10.100.10.190 logged in as Go-http-client/1.1]`; logout text `logged out (login time: Monday, 06 September, 2021 02:40:13 PM, number of API invocations: 3, user agent: Go-http-client/1.1)`; SSO failure via `[vim.event.EventEx] [info] [philipp] [] [...] [Failed login philipp from 192.168.11.1 at 12/29/2022 01:33:33 GMT in SSO]`; ESXi 7 style `<166>1 ... esxihost Hostd: info hostd[12345612] [Originator@1244 sub=Solo.VmwareCLI opID=... user=vpxuser:...] Dispatch get`; hostd event `[Originator@1234 sub=Vimsvc.ha-eventmgr opID=b323ab3] Event 12345678 : User demo@192.168.0.1 logged in as VMware-client/6.5.0`; RFC 5424 SD form `<166>1 ... Hostd 100001 - [Originator@6876 sub="Vimsvc.ha-eventmgr" opID="..." user="..." sid="..."] Event 1 : Account acct-x1y2z3 was created on host host-a1b2c3.example.local`; NFC text `NFC operation 'Upload' for path '/var/log/vlf-ts' was initiated from '192.168.0.1' and completed with status 'Success'`; sshd `<38>1 ... esxihost sshd 12345 - -  Received disconnect from ...`; multi-line `-->` continuation lines |
| https://raw.githubusercontent.com/elastic/integrations/main/packages/vsphere/data_stream/log/elasticsearch/ingest_pipeline/default.yml | Elastic grok: RFC 5424 header, optional SD, `%{DATA:process.name}(\[pid\])?:` 3164 form, `Event \[%{POSINT:event.id}\] ...` vpxd form, `Event\s+%{POSINT}\s*:` hostd form, `user=` extracted from SD |
| https://github.com/elastic/detection-rules/tree/main/rules/integrations/vsphere | Elastic ESXi rules confirm real message strings: hostd `pam_do_authenticate: error` with `rhost=<ip>` and `login:<user>`; `Account <name> was created on host <host>`; `Permission created ... role is Administrator`; `Password was changed for account root`; `SSH access has been enabled`; `SSH session was opened for 'vpxuser@<addr>'`; `esx.audit.lockdownmode.disabled`; shell commands `esxcli system account add`, `esxcli system permission set --role Admin`, `esxcli system account set -i root`, `vim-cmd hostsvc/enable_ssh`, `vim-cmd ... lockdown_mode_exit`, `esxcli network firewall set --default-action true` / `--enabled false`, `esxcli system syslog config set --reset=loghost`, `esxcli system auditrecords ... disable`, `vim-cmd vmsvc/power.off`, `esxcli vm process kill`, `vim-cmd vmsvc/snapshot.removeall`, payloads run against `/vmfs/volumes`; DCUI changes show `user=dcui` |
| https://knowledge.broadcom.com/external/article/306962 | ESXi log files: `auth.log` (ESXi Shell authentication success and failure), `shell.log` (ESXi Shell usage, enable/disable and every command entered), `hostd.log` (host management service, VM and host tasks and events, Host Client / vpxa / SDK connections), `vobd.log` (VMkernel observation events), `syslog.log`, `vmkernel.log`, `vpxa.log`; path `/var/run/log/<file>` (symlinked as `/var/log/<file>`) |
| https://knowledge.broadcom.com/external/article/421596 | ESXi 8.0 log line format change: local files gain severity code plus syslog PRI and program[pid], e.g. `...Z In(14) vobd[2097521]: [UserLevelCorrelator] ...us: [vob.user.ssh.session.closed] SSH session was closed for 'root@<ip>'.`, `...Z Er(163) Hostd[2098450]: [Originator@6876 sub=Default] ...`, `...Z In(182) vmkernel: cpu0:...)`; severity codes `Em Al Cr Er Wa No In Db`; `hostd` became `Hostd`; outbound RFC 3164 example `<38>... sshd-session[6588162]: Failed password...`; ESXi 7.0 equivalent lines without the severity code |
| https://knowledge.broadcom.com/external/article/318939/configuring-syslog-on-esxi.html | `Syslog.global.logHost` (`udp://host:514`, `tcp://host:514`, `ssl://host:1514`), `esxcli system syslog config set --loghost=... / --reset=loghost`, `esxcli system syslog reload`, firewall ruleset `syslog`, `esxcli system syslog mark` |
| https://docs.vmware.com/en/VMware-vSphere/8.0/vsphere-esxi-installation/GUID-7FD74787-29CC-416A-9642-7CF0617E1CC1.html (moved to techdocs.broadcom.com, "ESXi Syslog Options") | Remote-host URI options `?formatter=RFC_3164` or `RFC_5424` (RFC 3164 default), `framing=octet_counting` required for RFC 5424 over TCP/SSL, default max message length 1 KiB, configurable up to 16 KiB |
| https://knowledge.broadcom.com/external/article/321910/auditing-esxi-shell-logins-and-commands.html | Real `auth.log` lines: `sshd[12345]: Connection from 10.11.12.13 port 2605`, `sshd[12345]: Accepted keyboard-interactive/pam for root from 10.11.12.13 port 2605 ssh2`, `Accepted publickey for root ...`, `sshd[64386]: Session opened for 'root' on /dev/char/pty/t0`, `Session closed for 'root' ...`, `login[64386]: root login on 'char/tty/1'`; `shell.log`: `shell[64386]: Interactive shell session started`, `shell[64386]: <command>`; correlate auth and shell by the shared PID / world id |
| https://knowledge.broadcom.com/external/article/312772/esxi-root-account-locked-with-error-acce.html | Real failure lines `sshd[335148]: pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ...`, `sshd[335145]: error: PAM: Authentication failure for root from <ip>`; vobd `[UserLevelCorrelator] ...us: [vob.user.account.locked] Remote access for ESXi local user account 'root' has been locked for ...` and `[esx.audit.account.locked]`; settings `Security.AccountLockFailures`, `Security.AccountUnlockTime`; `pam_tally2 --user root --reset` |
| https://knowledge.broadcom.com/external/article/340038/error-remote-access-for-esxi-local-user.html | hostd `Rejected password for user root from <IP> - session=<uuid>`; `Security.AccountLockFailures` default 5, `0` disables lockout |
| https://knowledge.broadcom.com/external/article/438478/rejected-password-events-in-vcenter-serv.html | hostd `[Originator@6876 sub=Default rhost=] [module:pam_lsass]pam_do_authenticate: error ...`, `[Originator@6876 sub=Vimsvc.HaSessionManager] Rejected password for user '<acct>' ...`, `[Originator@6876 sub=Vimsvc.ha-eventmgr] Event 53081 : Cannot login <acct>@<ip>` |
| https://knowledge.broadcom.com/external/article/393192/identify-who-accessed-the-vm-console-fro.html | hostd `Accepted password for user root from <IP>` tied to a `sid`, followed by `Event NNNN : User root@<ip> logged in as Mozilla/5.0 ...`; Host Client opIDs start `esxui-` |
| https://knowledge.broadcom.com/external/article/414911/many-instances-of-user-root127001-logged.html | hostd `info hostd[...] [Originator@#### sub=Vimsvc.ha-eventmgr opID=esxcli-##-####] Event ###### : User root@127.0.0.1 logged in as pyvmomi Python/3.8.18 (VMkernel; 7.0.3; x86_64)`: local `esxcli` calls appear as root@127.0.0.1 sessions; opID prefix `esxcli-` |
| https://knowledge.broadcom.com/external/article/448889/esxi-sysloggloballoghost-settings-contin.html | hostd `Hostd[...]: [Originator@6876 sub=Vimsvc.TaskManager opID=... sid=... user=vpxuser:VSPHERE.LOCAL\Administrator] Task Created : haTask-ha-host-vim.option.OptionManager.updateValues-...` and `sub=Hostsvc.SyslogConfigProvider ... Set called with key 'Syslog.global.logHost', value '...'`: advanced-setting changes are `OptionManager.updateValues` tasks |
| https://knowledge.broadcom.com/external/article/397721/vm-is-randomly-in-a-powered-off-state-v.html | hostd `info hostd[2100025] [Originator@6876 sub=Vimsvc.TaskManager opID=...] Task Created : haTask-7-vim.VirtualMachine.powerOff-#######` and `verbose hostd[...] [Originator@6876 sub=Vmsvc.vm:/vmfs/volumes/<uuid>/<vm>/<vm>.vmx opID=...] Power off request received` |
| https://williamlam.com/2023/01/applying-additional-security-hardening-enhancements-in-esxi-8-0.html | ESXi 8 account commands `esxcli system account add -i <id> -p -c -s true`, `esxcli system permission set -i <id> -r Admin`; passwords typed on the command line are captured in `shell.log` |
| https://research.splunk.com/sources/f91c5ad1-2a44-4be3-93df-43150fa243e5/ | Real ESXi 8 shell line as received by Splunk (`sourcetype=vmw-syslog`): `2025-07-01T14:29:11.508Z localhost.localdomain shell[1627100]: [root]: esxcli system auditrecords local set`: ESXi 8 shell lines carry a `[<user>]:` prefix before the command |
| https://raw.githubusercontent.com/Azure/Azure-Sentinel/master/Solutions/VMWareESXi/Parsers/VMwareESXi.yaml | Sentinel ESXi parser: splits `SyslogMessage` into process / bracket / body, extracts `sub=`, `opID=`, `suser=`; host detection via `vpxd-main`, `vmkwarning`, `hostd-probe` process names |
| https://raw.githubusercontent.com/Azure/Azure-Sentinel/master/Parsers/ASimAuthentication/Parsers/ASimAuthenticationVMwareESXi.yaml | Sentinel ASIM ESXi auth: `Hostd` messages `Accepted password`, `Rejected password`, `Cannot login`, user regex `for user (\S+) from`, `session=`, `opID=`, `sid=`; `DCUI` messages `logged in` / `logged out` / `Authentication of user ... failed` |
| https://raw.githubusercontent.com/Azure/Azure-Sentinel/master/Solutions/VMware%20vCenter/Parsers/vCenter.yaml | Sentinel vCenter parser on the vpxd line: `"Event [" EventId "] [1-1] [" EventTime "] [" EventType "] [" EventSeverity "]"`, login `[User <DOMAIN\user>@<ip> logged in as <agent>]`, role added `... role <name> <operation>]`, role removed `[Role <name> <operation>]`, role modified `Previous name: X, new name: Y.` plus added / removed privileges |

---

## 2. Native format & delivery path

### 2.1 vCenter Server events

- **Syslog streaming** (push): VAMI (`https://<vcsa>:5480` -> Syslog) sets up to three remote targets (UDP / TCP / TLS);
  `vpxd.event.syslog.enabled = TRUE` puts every stored event onto that stream. Output is **RFC 5424 only** (no 3164).
  Program (APP-NAME) is `vpxd`, PROCID is the vpxd PID, MSGID and SD are `-`. On the appliance itself the same line is
  visible with `journalctl` as `vpxd[<pid>]: Event [...]`.
- **Line body** (official field names):
  `Event [eventId] [partInfo] [createdTime] [eventType] [severity] [user] [target] [chainId] [desc]`
  - `eventId` = API `key`; `partInfo` = `1-1` unless the event is longer than 1024 chars (then `1-3`, `2-3`, `3-3`,
    each a separate syslog message with the same `eventId`); `createdTime` = API `createdTime` (UTC, microseconds,
    `Z`); `eventType` = full class name `vim.event.<Class>`; `severity` = `info` / `warning` / `error` / `user`;
    `user` = API `userName` (empty `[]` for system events); `target` = inventory context, observed as the datacenter
    name (empty for session events); `chainId` = API `chainId` (equals `eventId` for standalone events, points at the
    parent task event for task-driven events); `desc` = API `fullFormattedMessage`.
- **What the line does NOT carry**: the typed fields (`ipAddress`, `userAgent`, `sessionId`, `principal`,
  `role`, `propagate`, `vm`, `host`, `eventTypeId` of `EventEx`). They exist only inside `desc` text, or only in the API
  object. For `vim.event.EventEx` the `eventType` bracket shows `vim.event.EventEx`, not the `eventTypeId`
  (Elastic fixture: SSO failure arrives as `[vim.event.EventEx] ... [Failed login philipp from ... in SSO]`).
- **API pull** (JSON): `POST /sdk/vim25/{release}/EventManager/EventManager/QueryEvents` (VI/JSON, vSphere 8.0 U1+), or
  SOAP `QueryEvents` / `CreateCollectorForEvents` (Splunk Add-on for VMware, pyVmomi, govc, PowerCLI `Get-VIEvent`).
  We render one array element exactly as returned: camelCase keys, `_typeName` discriminator, entity arguments as
  `{_typeName, name, <kind>{_typeName, type, value}}`. PowerCLI prints the same object PascalCase: that is a client
  view, not native.

### 2.2 ESXi host syslog

- `vmsyslogd` forwards every log stream to `Syslog.global.logHost` (`udp://host:514`, `tcp://host:514`,
  `ssl://host:1514`, optional `?formatter=RFC_5424&framing=octet_counting`). **Default formatter is RFC 3164.**
- **RFC 3164 wire form (default, ESXi 8.x):**
  `<PRI>YYYY-MM-DDThh:mm:ss.mmmZ <hostname> <Program>[<pid>]: <message>`
- **RFC 5424 wire form:** `<PRI>1 YYYY-MM-DDThh:mm:ss.mmmZ <hostname> <Program> <pid> - <SD or -> <message>`. For hostd,
  the `[Originator@6876 ...]` element can arrive as RFC 5424 STRUCTURED-DATA with quoted values (Elastic fixture);
  with 3164 it stays at the start of the message, unquoted.
- **ESXi 7.0 legacy wire form** (still common in SIEM history): `<166>1 <ts> <host> Hostd: info hostd[<pid>] [Originator@6876 sub=...] <message>`
  (lower-case `hostd`, severity word inside the message).
- **Local file form (ESXi 8)**: `<ts> In(166) Hostd[<pid>]: ...` where `In` is the severity code and `166` the syslog
  PRI. The SIEM never sees the `In(166)` token on the wire: it sees `<166>` as PRI.
- PRI values observed: `Hostd` `<166>` (local4.info) / `<163>` (local4.err) / `<164>` (local4.warning); `vobd` `<14>`
  (user.info); `vmkernel` `<182>` (local6.info); `sshd` `<38>` (auth.info) and `<86>` (authpriv.info). PRI for `shell`
  is **UNVERIFIED** (samples below use `<13>`, user.notice).
- Program-to-file map (the file name is NOT on the wire; the SIEM infers it from the program):

| Program on the wire | Local file | Content |
|---|---|---|
| `sshd` (ESXi 8.0 U3+ builds with newer OpenSSH also `sshd-session`, exact build **UNVERIFIED**), `login` | `auth.log` | SSH / console authentication |
| `shell` | `shell.log` | Every ESXi Shell command, shell enable/disable |
| `Hostd` (7.0: `Hostd: info hostd[pid]`) | `hostd.log` | Host Client / API sessions, tasks, host events (`Event N : ...`) |
| `vobd` | `vobd.log` | `vob.*` and `esx.audit.*` observations |
| `vpxa` | `vpxa.log` | vCenter agent on the host |
| `vmkernel` | `vmkernel.log` | Kernel, storage, network |
| `DCUI` | `syslog.log` | Direct Console UI logins |

---

## 3. Core field reference

### 3a. vCenter base event (all `vim.event.*`)

| API field | Syslog bracket | Type | Meaning |
|---|---|---|---|
| `_typeName` | `eventType` (`vim.event.` + `_typeName`) | string | Event class, e.g. `UserLoginSessionEvent` |
| `key` | `eventId` | int32 | Event ID, increasing per vCenter |
| `chainId` | `chainId` | int32 | Group / parent ID (task chain) |
| `createdTime` | `createdTime` | date-time | When vCenter created the event (UTC) |
| `userName` | `user` | string | Who caused it: `VSPHERE.LOCAL\Administrator`, `CORP\j.doe`, `root`, `vpxuser`, or empty |
| `datacenter`, `computeResource`, `host`, `vm`, `ds`, `net`, `dvs` | (only `target` = datacenter name) | entity argument | `{_typeName:"DatacenterEventArgument", name, datacenter:{_typeName:"ManagedObjectReference", type:"Datacenter", value:"datacenter-3"}}` |
| `fullFormattedMessage` | `desc` | string | Rendered text |
| `changeTag` | none | string | User-entered tag (rarely set) |
| `auditId` | none | string | vSphere 9.1+ audit event name; unset for non-auditable events |
| none | `partInfo` | string | `1-1`, or `n-X` when split |
| none | `severity` | string | `info`, `warning`, `error`, `user` (from the event description; for `EventEx` the `severity` field) |

### 3b. vCenter typed fields per kind

| Kind | Classes | Extra fields (API) | `desc` text pattern (syslog) |
|---|---|---|---|
| Login success | `UserLoginSessionEvent` | `ipAddress`, `userAgent`, `locale`, `sessionId` | `User <userName>@<ipAddress> logged in as <userAgent>` |
| Login failure | `BadUsernameSessionEvent`; SSO side `EventEx` `com.vmware.sso.LoginFailure` | `ipAddress`; EventEx `eventTypeId`, `arguments[]` | `Cannot login <userName>@<ipAddress>`; SSO: `Failed login <user> from <ip> at <MM/DD/YYYY hh:mm:ss> GMT in SSO` |
| Logout | `UserLogoutSessionEvent` | `ipAddress`, `userAgent`, `callCount`, `sessionId`, `loginTime` | `User <u>@<ip> logged out (login time: <Weekday, DD Month, YYYY hh:mm:ss AM/PM>, number of API invocations: <n>, user agent: <ua>)` |
| Permission (role assignment) | `PermissionAddedEvent`, `PermissionUpdatedEvent`, `PermissionRemovedEvent`; vSphere Client path also `EventEx` `com.vmware.cis.CreatePermission` / `CreateGlobalPermission` | `entity`, `principal`, `group`, `role{roleId,name}`, `propagate`; updated adds `prevRole`, `prevPropagate` (**UNVERIFIED** names) | `Permission created for <principal> on <entity.name>, role is <role.name>, propagation is Enabled|Disabled`; removed `Permission rule removed for <principal> on <entity.name>` |
| Role change | `RoleAddedEvent`, `RoleUpdatedEvent`, `RoleRemovedEvent` | `role{roleId,name}`, `privilegeList[]`; updated `prevRoleName`, `privilegesAdded[]`, `privilegesRemoved[]` | Added: `New role <name> created` (**UNVERIFIED** exact, Sentinel pattern `... role <name> <operation>]`); removed `Role <name> removed`; updated `... Previous name: X, new name: Y. ...` |
| SSO principal change | `EventEx` `com.vmware.sso.PrincipalManagement` | `arguments[]` (`description`, `timestamp`) | `Principal Management event by <user> at <date> GMT : <description>` |
| Local host account | `AccountCreatedEvent`, `AccountUpdatedEvent`, `AccountRemovedEvent` | `spec{id,description,...}`, `group` (**UNVERIFIED** shape) | `Account <id> was created on host <host>` (same sentence hostd logs) |
| VM power / inventory | `VmPoweredOffEvent`, `VmRemovedEvent`, `VmReconfiguredEvent` | `vm`, `host`, `datacenter`, `computeResource`, `template`; reconfigured `configSpec` | Removed: `Removed <vm> on <host> from <datacenter>`; reconfigured `Reconfigured <vm> on <host> in <datacenter>.`; powered off `<vm> on <host> in <datacenter> is powered off` (**UNVERIFIED** exact) |
| Host | `HostConnectedEvent` and other `HostEvent` | `host`, `datacenter` | `Connected to <host> in <datacenter>` (**UNVERIFIED** exact) |
| Alarm | `AlarmStatusChangedEvent` | `alarm{name, alarm moref}`, `source`, `entity`, `from`, `to` (`gray`/`green`/`yellow`/`red`) | `Alarm '<alarm>' on <entity> changed from Green to Red` (**UNVERIFIED** exact) |
| ESXi audit via vCenter | `esx.audit.ssh.enabled`, `esx.audit.shell.enabled`, `esx.audit.lockdownmode.disabled`, `esx.audit.account.locked`, `esx.audit.net.firewall.disabled` (catalog type `ExtendedEvent` / `EventEx`) | `eventTypeId`, `arguments[]`, `host` | Rendered text per catalog (`Firewall has been disabled.`, `Administrator access to the host has been enabled.`); vpxd `eventType` bracket for these is **UNVERIFIED** (`vim.event.EventEx` or `vim.event.ExtendedEvent`) |

### 3c. ESXi syslog record (flat keys used by this platform)

| Key | Source | Meaning / values |
|---|---|---|
| `pri` | syslog PRI | `166`, `14`, `38` ... (facility*8 + severity) |
| `timestamp` | syslog header | ISO-8601 UTC with ms, `2026-11-03T02:21:44.512Z` |
| `hostname` | syslog header | ESXi FQDN as configured (`esxi-01.corp.example`); a fresh host may send `localhost.localdomain` |
| `program` | syslog TAG / APP-NAME | `sshd`, `shell`, `Hostd`, `vobd`, `vmkernel`, `vpxa`, `DCUI`, `login` |
| `pid` | `[pid]` / PROCID | Process (world) id; same value links `sshd` session and `shell` commands |
| `message` | rest of line | Verbatim text |
| `Originator` | hostd bracket | Always `6876` on hostd (`Originator@6876`) |
| `sub` | hostd bracket | Sub-component: `Vimsvc.ha-eventmgr` (host events), `Vimsvc.HaSessionManager` (password accept/reject), `Vimsvc.TaskManager` (task created/completed), `Vmsvc.vm:/vmfs/volumes/<ds-uuid>/<vm>/<vm>.vmx` (per-VM), `Solo.VmwareCLI` (vim-cmd / esxcli dispatch), `Hostsvc.SyslogConfigProvider`, `Default` |
| `opID` | hostd bracket | Operation id; prefix shows the client: `esxui-` (Host Client), `esxcli-` (local esxcli), vCenter-generated hex ids for `vpxuser` calls |
| `sid` | hostd bracket | Short session id (first 8 hex of the session UUID) |
| `user` | hostd bracket / shell prefix | `root`, `dcui`, `vpxuser`, `vpxuser:VSPHERE.LOCAL\Administrator` (vCenter acting for a vCenter user); shell: the `[root]:` prefix |
| `vob_id` | vobd bracket | `vob.user.ssh.session.opened`, `esx.audit.account.locked` ... |
| `correlator` | vobd bracket | `UserLevelCorrelator` / `GenericCorrelator` |
| `uptime_us` | vobd | Microsecond uptime counter, `1478941347002us` |

### 3d. ESXi security settings referenced in stories

| Setting / command | Meaning | Default |
|---|---|---|
| `Security.AccountLockFailures` | Failed remote logins before lockout; `0` disables lockout | `5` |
| `Security.AccountUnlockTime` | Lockout duration (seconds) | `900` (KB examples show 120 and 900; default per build **UNVERIFIED**) |
| `UserVars.ESXiShellTimeOut` | Seconds until ESXi Shell / SSH service auto-disables; `0` = never | `0` (hardening guides require a non-zero value) |
| `UserVars.ESXiShellInteractiveTimeOut` | Idle shell session timeout | `0` |
| `Syslog.global.logHost` | Remote syslog targets; `--reset=loghost` blanks it (log blinding) | empty |
| `VMkernel.Boot.execInstalledOnly` | Only VIB-installed binaries may run | `TRUE` on ESXi 8 |
| Lockdown mode | `normal` / `strict` / `disabled`; exit from shell `vim-cmd -U dcui vimsvc/auth/lockdown_mode_exit` | disabled |

---

## 4. Realistic samples (fictitious)

Story (shared across both products): a phished admin's workstation `10.20.30.45` is used to brute force and then log in
to vCenter `vcsa-01.corp.example` as `CORP\svc-backup`, grant a new principal Administrator on the root folder, enable
SSH on `esxi-01.corp.example`, create a backdoor host account, loosen lockout and shell timeout, disable the firewall
and lockdown mode, upload an encryptor to `datastore1`, power off VMs and encrypt `.vmdk` files.

### 4.1 vCenter, syslog (vpxd)

#### V1. `BadUsernameSessionEvent` (login failure)

```text
<14>1 2026-11-03T02:09:58.221804+00:00 vcsa-01.corp.example vpxd 6225 - -  Event [8841207] [1-1] [2026-11-03T02:09:58.221517Z] [vim.event.BadUsernameSessionEvent] [error] [CORP\svc-backup] [] [8841207] [Cannot login CORP\svc-backup@10.20.30.45]
```

```json
{
  "pri": 14,
  "timestamp": "2026-11-03T02:09:58.221804+00:00",
  "hostname": "vcsa-01.corp.example",
  "program": "vpxd",
  "pid": 6225,
  "eventId": 8841207,
  "partInfo": "1-1",
  "createdTime": "2026-11-03T02:09:58.221517Z",
  "eventType": "vim.event.BadUsernameSessionEvent",
  "severity": "error",
  "user": "CORP\\svc-backup",
  "target": "",
  "chainId": 8841207,
  "desc": "Cannot login CORP\\svc-backup@10.20.30.45",
  "message": "Event [8841207] [1-1] [2026-11-03T02:09:58.221517Z] [vim.event.BadUsernameSessionEvent] [error] [CORP\\svc-backup] [] [8841207] [Cannot login CORP\\svc-backup@10.20.30.45]"
}
```

(`severity` value `error` for this class is **UNVERIFIED**; the header and `desc` text follow KB 376043.)

#### V2. `UserLoginSessionEvent` (login success, API client)

```text
<14>1 2026-11-03T02:12:41.087312+00:00 vcsa-01.corp.example vpxd 6225 - -  Event [8841263] [1-1] [2026-11-03T02:12:41.086990Z] [vim.event.UserLoginSessionEvent] [info] [CORP\svc-backup] [] [8841263] [User CORP\svc-backup@10.20.30.45 logged in as pyvmomi Python/3.11.9 (Windows; 10; AMD64)]
```

```json
{
  "pri": 14,
  "timestamp": "2026-11-03T02:12:41.087312+00:00",
  "hostname": "vcsa-01.corp.example",
  "program": "vpxd",
  "pid": 6225,
  "eventId": 8841263,
  "partInfo": "1-1",
  "createdTime": "2026-11-03T02:12:41.086990Z",
  "eventType": "vim.event.UserLoginSessionEvent",
  "severity": "info",
  "user": "CORP\\svc-backup",
  "target": "",
  "chainId": 8841263,
  "desc": "User CORP\\svc-backup@10.20.30.45 logged in as pyvmomi Python/3.11.9 (Windows; 10; AMD64)",
  "message": "Event [8841263] [1-1] [2026-11-03T02:12:41.086990Z] [vim.event.UserLoginSessionEvent] [info] [CORP\\svc-backup] [] [8841263] [User CORP\\svc-backup@10.20.30.45 logged in as pyvmomi Python/3.11.9 (Windows; 10; AMD64)]"
}
```

#### V3. `PermissionAddedEvent` (role assignment on the root folder)

```text
<14>1 2026-11-03T02:14:07.912345+00:00 vcsa-01.corp.example vpxd 6225 - -  Event [8841290] [1-1] [2026-11-03T02:14:07.911876Z] [vim.event.PermissionAddedEvent] [info] [CORP\svc-backup] [] [8841290] [Permission created for CORP\esx-maint on Datacenters, role is Administrator, propagation is Enabled]
```

```json
{
  "pri": 14,
  "timestamp": "2026-11-03T02:14:07.912345+00:00",
  "hostname": "vcsa-01.corp.example",
  "program": "vpxd",
  "pid": 6225,
  "eventId": 8841290,
  "partInfo": "1-1",
  "createdTime": "2026-11-03T02:14:07.911876Z",
  "eventType": "vim.event.PermissionAddedEvent",
  "severity": "info",
  "user": "CORP\\svc-backup",
  "target": "",
  "chainId": 8841290,
  "desc": "Permission created for CORP\\esx-maint on Datacenters, role is Administrator, propagation is Enabled",
  "message": "Event [8841290] [1-1] [2026-11-03T02:14:07.911876Z] [vim.event.PermissionAddedEvent] [info] [CORP\\svc-backup] [] [8841290] [Permission created for CORP\\esx-maint on Datacenters, role is Administrator, propagation is Enabled]"
}
```

(`desc` text confirmed by William Lam's captured event and the Elastic rule. Empty `target` for a root-folder permission
is **UNVERIFIED**.)

#### V4. `RoleAddedEvent` (custom role created)

```text
<14>1 2026-11-03T02:13:30.402118+00:00 vcsa-01.corp.example vpxd 6225 - -  Event [8841281] [1-1] [2026-11-03T02:13:30.401733Z] [vim.event.RoleAddedEvent] [info] [CORP\svc-backup] [] [8841281] [New role Host-Maintenance created]
```

```json
{
  "pri": 14,
  "timestamp": "2026-11-03T02:13:30.402118+00:00",
  "hostname": "vcsa-01.corp.example",
  "program": "vpxd",
  "pid": 6225,
  "eventId": 8841281,
  "partInfo": "1-1",
  "createdTime": "2026-11-03T02:13:30.401733Z",
  "eventType": "vim.event.RoleAddedEvent",
  "severity": "info",
  "user": "CORP\\svc-backup",
  "target": "",
  "chainId": 8841281,
  "desc": "New role Host-Maintenance created",
  "message": "Event [8841281] [1-1] [2026-11-03T02:13:30.401733Z] [vim.event.RoleAddedEvent] [info] [CORP\\svc-backup] [] [8841281] [New role Host-Maintenance created]"
}
```

(`desc` wording **UNVERIFIED**: only the Sentinel parser pattern `... role <name> <operation>]` is confirmed.)

#### V5. `VmPoweredOffEvent` (chained to a power-off task)

```text
<14>1 2026-11-03T02:41:12.660204+00:00 vcsa-01.corp.example vpxd 6225 - -  Event [8841622] [1-1] [2026-11-03T02:41:12.659871Z] [vim.event.VmPoweredOffEvent] [info] [root] [DC-TLV] [8841619] [FIN-SQL-01 on esxi-01.corp.example in DC-TLV is powered off]
```

```json
{
  "pri": 14,
  "timestamp": "2026-11-03T02:41:12.660204+00:00",
  "hostname": "vcsa-01.corp.example",
  "program": "vpxd",
  "pid": 6225,
  "eventId": 8841622,
  "partInfo": "1-1",
  "createdTime": "2026-11-03T02:41:12.659871Z",
  "eventType": "vim.event.VmPoweredOffEvent",
  "severity": "info",
  "user": "root",
  "target": "DC-TLV",
  "chainId": 8841619,
  "desc": "FIN-SQL-01 on esxi-01.corp.example in DC-TLV is powered off",
  "message": "Event [8841622] [1-1] [2026-11-03T02:41:12.659871Z] [vim.event.VmPoweredOffEvent] [info] [root] [DC-TLV] [8841619] [FIN-SQL-01 on esxi-01.corp.example in DC-TLV is powered off]"
}
```

(A power-off done directly on the host with `vim-cmd` is seen by vCenter through vpxa; whether `user` then shows
`root` or is empty is **UNVERIFIED**. `desc` wording **UNVERIFIED**.)

#### V6. `VmRemovedEvent` (VM unregistered before encryption)

```text
<14>1 2026-11-03T02:43:05.118733+00:00 vcsa-01.corp.example vpxd 6225 - -  Event [8841655] [1-1] [2026-11-03T02:43:05.118402Z] [vim.event.VmRemovedEvent] [info] [CORP\esx-maint] [DC-TLV] [8841654] [Removed FIN-APP-02 on esxi-01.corp.example from DC-TLV]
```

```json
{
  "pri": 14,
  "timestamp": "2026-11-03T02:43:05.118733+00:00",
  "hostname": "vcsa-01.corp.example",
  "program": "vpxd",
  "pid": 6225,
  "eventId": 8841655,
  "partInfo": "1-1",
  "createdTime": "2026-11-03T02:43:05.118402Z",
  "eventType": "vim.event.VmRemovedEvent",
  "severity": "info",
  "user": "CORP\\esx-maint",
  "target": "DC-TLV",
  "chainId": 8841654,
  "desc": "Removed FIN-APP-02 on esxi-01.corp.example from DC-TLV",
  "message": "Event [8841655] [1-1] [2026-11-03T02:43:05.118402Z] [vim.event.VmRemovedEvent] [info] [CORP\\esx-maint] [DC-TLV] [8841654] [Removed FIN-APP-02 on esxi-01.corp.example from DC-TLV]"
}
```

#### V7. SSO login failure (`EventEx` `com.vmware.sso.LoginFailure`, type not shown on the line)

```text
<14>1 2026-11-03T02:08:44.530917+00:00 vcsa-01.corp.example vpxd 6225 - -  Event [8841199] [1-1] [2026-11-03T02:08:44.530622Z] [vim.event.EventEx] [info] [j.doe@corp.example] [] [8841199] [Failed login j.doe@corp.example from 10.20.30.45 at 11/03/2026 02:08:44 GMT in SSO]
```

```json
{
  "pri": 14,
  "timestamp": "2026-11-03T02:08:44.530917+00:00",
  "hostname": "vcsa-01.corp.example",
  "program": "vpxd",
  "pid": 6225,
  "eventId": 8841199,
  "partInfo": "1-1",
  "createdTime": "2026-11-03T02:08:44.530622Z",
  "eventType": "vim.event.EventEx",
  "severity": "info",
  "user": "j.doe@corp.example",
  "target": "",
  "chainId": 8841199,
  "desc": "Failed login j.doe@corp.example from 10.20.30.45 at 11/03/2026 02:08:44 GMT in SSO",
  "message": "Event [8841199] [1-1] [2026-11-03T02:08:44.530622Z] [vim.event.EventEx] [info] [j.doe@corp.example] [] [8841199] [Failed login j.doe@corp.example from 10.20.30.45 at 11/03/2026 02:08:44 GMT in SSO]"
}
```

### 4.2 vCenter, API event objects (`QueryEvents` result elements)

#### V8. `UserLoginSessionEvent`

```json
{
  "_typeName": "UserLoginSessionEvent",
  "key": 8841263,
  "chainId": 8841263,
  "createdTime": "2026-11-03T02:12:41.08699Z",
  "userName": "CORP\\svc-backup",
  "fullFormattedMessage": "User CORP\\svc-backup@10.20.30.45 logged in as pyvmomi Python/3.11.9 (Windows; 10; AMD64)",
  "ipAddress": "10.20.30.45",
  "userAgent": "pyvmomi Python/3.11.9 (Windows; 10; AMD64)",
  "locale": "en",
  "sessionId": "52d8a3f1-6c0e-9b47-2a15-e4f07c3b9d81"
}
```

#### V9. `PermissionAddedEvent`

```json
{
  "_typeName": "PermissionAddedEvent",
  "key": 8841290,
  "chainId": 8841290,
  "createdTime": "2026-11-03T02:14:07.911876Z",
  "userName": "CORP\\svc-backup",
  "fullFormattedMessage": "Permission created for CORP\\esx-maint on Datacenters, role is Administrator, propagation is Enabled",
  "entity": {
    "_typeName": "ManagedEntityEventArgument",
    "name": "Datacenters",
    "entity": {"_typeName": "ManagedObjectReference", "type": "Folder", "value": "group-d1"}
  },
  "principal": "CORP\\esx-maint",
  "group": false,
  "role": {"_typeName": "RoleEventArgument", "roleId": -1, "name": "Administrator"},
  "propagate": true
}
```

(`roleId: -1` is the built-in Administrator role id; `group-d1` is the root folder moref. Both are long-standing vSphere
values but not re-confirmed in a current doc page: **UNVERIFIED**.)

#### V10. `AlarmStatusChangedEvent` (host alarm goes red after the firewall is disabled)

```json
{
  "_typeName": "AlarmStatusChangedEvent",
  "key": 8841402,
  "chainId": 8841402,
  "createdTime": "2026-11-03T02:27:19.30418Z",
  "userName": "",
  "datacenter": {
    "_typeName": "DatacenterEventArgument",
    "name": "DC-TLV",
    "datacenter": {"_typeName": "ManagedObjectReference", "type": "Datacenter", "value": "datacenter-3"}
  },
  "computeResource": {
    "_typeName": "ComputeResourceEventArgument",
    "name": "CL-PROD",
    "computeResource": {"_typeName": "ManagedObjectReference", "type": "ClusterComputeResource", "value": "domain-c8"}
  },
  "host": {
    "_typeName": "HostEventArgument",
    "name": "esxi-01.corp.example",
    "host": {"_typeName": "ManagedObjectReference", "type": "HostSystem", "value": "host-1012"}
  },
  "fullFormattedMessage": "Alarm 'Host error' on esxi-01.corp.example changed from Green to Red",
  "alarm": {
    "_typeName": "AlarmEventArgument",
    "name": "Host error",
    "alarm": {"_typeName": "ManagedObjectReference", "type": "Alarm", "value": "alarm-11"}
  },
  "source": {
    "_typeName": "ManagedEntityEventArgument",
    "name": "Datacenters",
    "entity": {"_typeName": "ManagedObjectReference", "type": "Folder", "value": "group-d1"}
  },
  "entity": {
    "_typeName": "ManagedEntityEventArgument",
    "name": "esxi-01.corp.example",
    "entity": {"_typeName": "ManagedObjectReference", "type": "HostSystem", "value": "host-1012"}
  },
  "from": "green",
  "to": "red"
}
```

(Field set from the official data structure; `fullFormattedMessage` wording **UNVERIFIED**.)

### 4.3 ESXi host syslog

All ESXi samples use the **default RFC 3164 wire form** from an ESXi 8.0 U3 host.

#### E1. sshd, password guessing (auth failure)

```text
<38>2026-11-03T02:16:52.118Z esxi-01.corp.example sshd[2134871]: error: PAM: Authentication failure for root from 10.20.30.45
```

```json
{
  "pri": 38,
  "timestamp": "2026-11-03T02:16:52.118Z",
  "hostname": "esxi-01.corp.example",
  "program": "sshd",
  "pid": 2134871,
  "message": "error: PAM: Authentication failure for root from 10.20.30.45"
}
```

(The paired line `sshd[<pid>]: pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=10.20.30.45  user=root`
also appears; the trailing `ruser=` / `rhost=` / `user=` part is standard pam_unix and only partly visible in the KB:
partly **UNVERIFIED**. The PRI of `error:` lines is **UNVERIFIED**.)

#### E2. sshd, SSH login success

```text
<38>2026-11-03T02:17:04.630Z esxi-01.corp.example sshd[2134902]: Connection from 10.20.30.45 port 51544
<38>2026-11-03T02:17:06.981Z esxi-01.corp.example sshd[2134902]: Accepted keyboard-interactive/pam for root from 10.20.30.45 port 51544 ssh2
```

```json
{
  "pri": 38,
  "timestamp": "2026-11-03T02:17:06.981Z",
  "hostname": "esxi-01.corp.example",
  "program": "sshd",
  "pid": 2134902,
  "message": "Accepted keyboard-interactive/pam for root from 10.20.30.45 port 51544 ssh2"
}
```

#### E3. vobd, SSH session opened (same login, VMkernel observation)

```text
<14>2026-11-03T02:17:07.004Z esxi-01.corp.example vobd[2097521]: [UserLevelCorrelator] 1812448097311us: [vob.user.ssh.session.opened] SSH session was opened for 'root@10.20.30.45'.
```

```json
{
  "pri": 14,
  "timestamp": "2026-11-03T02:17:07.004Z",
  "hostname": "esxi-01.corp.example",
  "program": "vobd",
  "pid": 2097521,
  "correlator": "UserLevelCorrelator",
  "uptime_us": "1812448097311us",
  "vob_id": "vob.user.ssh.session.opened",
  "message": "[UserLevelCorrelator] 1812448097311us: [vob.user.ssh.session.opened] SSH session was opened for 'root@10.20.30.45'."
}
```

#### E4. hostd, Host Client / API login with root password (`Vimsvc.HaSessionManager`)

```text
<166>2026-11-03T02:15:11.402Z esxi-01.corp.example Hostd[2099478]: [Originator@6876 sub=Vimsvc.HaSessionManager opID=esxui-5c1e-81a2 sid=52e7b0c4 user=root] Accepted password for user root from 10.20.30.45
<166>2026-11-03T02:15:11.405Z esxi-01.corp.example Hostd[2099478]: [Originator@6876 sub=Vimsvc.ha-eventmgr opID=esxui-5c1e-81a2 sid=52e7b0c4 user=root] Event 1184 : User root@10.20.30.45 logged in as Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36
```

```json
{
  "pri": 166,
  "timestamp": "2026-11-03T02:15:11.402Z",
  "hostname": "esxi-01.corp.example",
  "program": "Hostd",
  "pid": 2099478,
  "Originator": "6876",
  "sub": "Vimsvc.HaSessionManager",
  "opID": "esxui-5c1e-81a2",
  "sid": "52e7b0c4",
  "user": "root",
  "message": "Accepted password for user root from 10.20.30.45"
}
```

(Presence of `sid=` / `user=` on the `Accepted password` line itself is **UNVERIFIED**: KB 393192 ties the line to a
`sid`, and the ESXi 8 bracket is known to carry `sid` and `user` on later lines of the session.)

#### E5. hostd, failed Host Client / API logon (brute force through hostd)

```text
<163>2026-11-03T02:15:02.771Z esxi-01.corp.example Hostd[2099478]: [Originator@6876 sub=Default rhost=10.20.30.45] [module:pam_lsass]pam_do_authenticate: error [login:root][error code:2]
<166>2026-11-03T02:15:02.774Z esxi-01.corp.example Hostd[2099478]: [Originator@6876 sub=Vimsvc.HaSessionManager] Rejected password for user root from 10.20.30.45 - session=52a19f6e-3d0b-7c84-91e2-b6c5d8a0f437
<166>2026-11-03T02:15:02.776Z esxi-01.corp.example Hostd[2099478]: [Originator@6876 sub=Vimsvc.ha-eventmgr] Event 1181 : Cannot login root@10.20.30.45
```

```json
{
  "pri": 166,
  "timestamp": "2026-11-03T02:15:02.776Z",
  "hostname": "esxi-01.corp.example",
  "program": "Hostd",
  "pid": 2099478,
  "Originator": "6876",
  "sub": "Vimsvc.ha-eventmgr",
  "message": "Event 1181 : Cannot login root@10.20.30.45"
}
```

#### E6. shell, backdoor account creation and Admin role assignment (ESXi 8 shell prefix `[user]:`)

```text
<13>2026-11-03T02:18:33.215Z esxi-01.corp.example shell[2135011]: [root]: esxcli system account add -i svc-patch -d "Patch service" -p Winter2026! -c Winter2026! -s true
<13>2026-11-03T02:18:47.902Z esxi-01.corp.example shell[2135011]: [root]: esxcli system permission set -i svc-patch -r Admin
```

```json
{
  "pri": 13,
  "timestamp": "2026-11-03T02:18:33.215Z",
  "hostname": "esxi-01.corp.example",
  "program": "shell",
  "pid": 2135011,
  "user": "root",
  "command": "esxcli system account add -i svc-patch -d \"Patch service\" -p Winter2026! -c Winter2026! -s true",
  "message": "[root]: esxcli system account add -i svc-patch -d \"Patch service\" -p Winter2026! -c Winter2026! -s true"
}
```

```json
{
  "pri": 13,
  "timestamp": "2026-11-03T02:18:47.902Z",
  "hostname": "esxi-01.corp.example",
  "program": "shell",
  "pid": 2135011,
  "user": "root",
  "command": "esxcli system permission set -i svc-patch -r Admin",
  "message": "[root]: esxcli system permission set -i svc-patch -r Admin"
}
```

(`user` and `command` are split from the message by the platform for convenience; the vendor only emits the message.
Password in clear text on the command line is real behaviour per William Lam. `<13>` PRI **UNVERIFIED**.)

#### E7. hostd, the same account creation as a host event

```text
<166>2026-11-03T02:18:33.611Z esxi-01.corp.example Hostd[2099478]: [Originator@6876 sub=Vimsvc.ha-eventmgr opID=esxcli-7d-a41c sid=52f0d6a2 user=root] Event 1192 : Account svc-patch was created on host esxi-01.corp.example
```

```json
{
  "pri": 166,
  "timestamp": "2026-11-03T02:18:33.611Z",
  "hostname": "esxi-01.corp.example",
  "program": "Hostd",
  "pid": 2099478,
  "Originator": "6876",
  "sub": "Vimsvc.ha-eventmgr",
  "opID": "esxcli-7d-a41c",
  "sid": "52f0d6a2",
  "user": "root",
  "message": "Event 1192 : Account svc-patch was created on host esxi-01.corp.example"
}
```

(The matching hostd sentence for the role step, `Permission created for svc-patch on ha-folder-root, role is Admin, propagation is Enabled`,
is implied by the Elastic rule (`Permission created` + role) but its exact host-side wording is **UNVERIFIED**.)

#### E8. shell and hostd, advanced settings weakened (policy modification)

```text
<13>2026-11-03T02:19:20.044Z esxi-01.corp.example shell[2135011]: [root]: esxcli system settings advanced set -o /UserVars/ESXiShellTimeOut -i 0
<13>2026-11-03T02:19:31.517Z esxi-01.corp.example shell[2135011]: [root]: esxcli system settings advanced set -o /Security/AccountLockFailures -i 0
<166>2026-11-03T02:19:31.633Z esxi-01.corp.example Hostd[2099478]: [Originator@6876 sub=Vimsvc.TaskManager opID=esxcli-7d-a45f sid=52f0d6a2 user=root] Task Created : haTask-ha-host-vim.option.OptionManager.updateValues-2104127
```

```json
{
  "pri": 13,
  "timestamp": "2026-11-03T02:19:31.517Z",
  "hostname": "esxi-01.corp.example",
  "program": "shell",
  "pid": 2135011,
  "user": "root",
  "command": "esxcli system settings advanced set -o /Security/AccountLockFailures -i 0",
  "message": "[root]: esxcli system settings advanced set -o /Security/AccountLockFailures -i 0"
}
```

```json
{
  "pri": 166,
  "timestamp": "2026-11-03T02:19:31.633Z",
  "hostname": "esxi-01.corp.example",
  "program": "Hostd",
  "pid": 2099478,
  "Originator": "6876",
  "sub": "Vimsvc.TaskManager",
  "opID": "esxcli-7d-a45f",
  "sid": "52f0d6a2",
  "user": "root",
  "message": "Task Created : haTask-ha-host-vim.option.OptionManager.updateValues-2104127"
}
```

(Task line format from KB 448889. Whether a local `esxcli system settings advanced set` goes through hostd as an
`OptionManager.updateValues` task, rather than straight to the config store, is **UNVERIFIED**; the shell line is the
reliable evidence.)

#### E9. shell and vobd, firewall disabled and lockdown mode exited

```text
<13>2026-11-03T02:20:02.380Z esxi-01.corp.example shell[2135011]: [root]: esxcli network firewall set --enabled false
<14>2026-11-03T02:20:02.912Z esxi-01.corp.example vobd[2097521]: [UserLevelCorrelator] 1812623005920us: [esx.audit.net.firewall.disabled] Firewall has been disabled.
<13>2026-11-03T02:20:19.006Z esxi-01.corp.example shell[2135011]: [root]: vim-cmd -U dcui vimsvc/auth/lockdown_mode_exit
<14>2026-11-03T02:20:19.288Z esxi-01.corp.example vobd[2097521]: [UserLevelCorrelator] 1812639382114us: [esx.audit.lockdownmode.disabled] Administrator access to the host has been enabled.
```

```json
{
  "pri": 14,
  "timestamp": "2026-11-03T02:20:02.912Z",
  "hostname": "esxi-01.corp.example",
  "program": "vobd",
  "pid": 2097521,
  "correlator": "UserLevelCorrelator",
  "uptime_us": "1812623005920us",
  "vob_id": "esx.audit.net.firewall.disabled",
  "message": "[UserLevelCorrelator] 1812623005920us: [esx.audit.net.firewall.disabled] Firewall has been disabled."
}
```

```json
{
  "pri": 13,
  "timestamp": "2026-11-03T02:20:19.006Z",
  "hostname": "esxi-01.corp.example",
  "program": "shell",
  "pid": 2135011,
  "user": "root",
  "command": "vim-cmd -U dcui vimsvc/auth/lockdown_mode_exit",
  "message": "[root]: vim-cmd -U dcui vimsvc/auth/lockdown_mode_exit"
}
```

(The ids and sentences are from the vCenter 8.0 U3 event catalog and the Elastic rules. That vobd, rather than only
hostd, prints these two `esx.audit.*` ids is **UNVERIFIED**; `esx.audit.account.locked` in vobd is confirmed.)

#### E10. vobd, account lockout from the earlier guessing

```text
<14>2026-11-03T02:16:58.440Z esxi-01.corp.example vobd[2097521]: [UserLevelCorrelator] 1812439528907us: [esx.audit.account.locked] Remote access for ESXi local user account 'root' has been locked for 900 seconds after 5 failed login attempts.
```

```json
{
  "pri": 14,
  "timestamp": "2026-11-03T02:16:58.440Z",
  "hostname": "esxi-01.corp.example",
  "program": "vobd",
  "pid": 2097521,
  "correlator": "UserLevelCorrelator",
  "uptime_us": "1812439528907us",
  "vob_id": "esx.audit.account.locked",
  "message": "[UserLevelCorrelator] 1812439528907us: [esx.audit.account.locked] Remote access for ESXi local user account 'root' has been locked for 900 seconds after 5 failed login attempts."
}
```

#### E11. hostd, encryptor uploaded to the datastore (file create via NFC / datastore browser)

```text
<166>2026-11-03T02:22:40.118Z esxi-01.corp.example Hostd[2099478]: [Originator@6876 sub=Vimsvc.ha-eventmgr opID=esxui-5c1e-8c07 sid=52e7b0c4 user=root] Event 1207 : NFC operation 'Upload' for path '/vmfs/volumes/datastore1/.tools/vmsyncd' was initiated from '10.20.30.45' and completed with status 'Success'
```

```json
{
  "pri": 166,
  "timestamp": "2026-11-03T02:22:40.118Z",
  "hostname": "esxi-01.corp.example",
  "program": "Hostd",
  "pid": 2099478,
  "Originator": "6876",
  "sub": "Vimsvc.ha-eventmgr",
  "opID": "esxui-5c1e-8c07",
  "sid": "52e7b0c4",
  "user": "root",
  "message": "Event 1207 : NFC operation 'Upload' for path '/vmfs/volumes/datastore1/.tools/vmsyncd' was initiated from '10.20.30.45' and completed with status 'Success'"
}
```

#### E12. shell, VMs stopped and `.vmdk` files encrypted / renamed

```text
<13>2026-11-03T02:40:51.330Z esxi-01.corp.example shell[2135011]: [root]: vim-cmd vmsvc/getallvms
<13>2026-11-03T02:41:09.774Z esxi-01.corp.example shell[2135011]: [root]: vim-cmd vmsvc/power.off 12
<166>2026-11-03T02:41:09.901Z esxi-01.corp.example Hostd[2099478]: [Originator@6876 sub=Vimsvc.TaskManager opID=1f3a9c20 sid=52f0d6a2 user=root] Task Created : haTask-12-vim.VirtualMachine.powerOff-2104388
<166>2026-11-03T02:41:09.903Z esxi-01.corp.example Hostd[2099478]: [Originator@6876 sub=Vmsvc.vm:/vmfs/volumes/6543f2a1-9be0c3d4-7e12-0050569a1b2c/FIN-SQL-01/FIN-SQL-01.vmx opID=1f3a9c20 sid=52f0d6a2 user=root] Power off request received
<13>2026-11-03T02:44:30.012Z esxi-01.corp.example shell[2135011]: [root]: chmod +x /vmfs/volumes/datastore1/.tools/vmsyncd
<13>2026-11-03T02:44:36.587Z esxi-01.corp.example shell[2135011]: [root]: /vmfs/volumes/datastore1/.tools/vmsyncd --path /vmfs/volumes/datastore1 --ext .lck9 --threads 8
<13>2026-11-03T02:58:12.443Z esxi-01.corp.example shell[2135011]: [root]: ls /vmfs/volumes/datastore1/FIN-SQL-01/
```

```json
{
  "pri": 13,
  "timestamp": "2026-11-03T02:41:09.774Z",
  "hostname": "esxi-01.corp.example",
  "program": "shell",
  "pid": 2135011,
  "user": "root",
  "command": "vim-cmd vmsvc/power.off 12",
  "message": "[root]: vim-cmd vmsvc/power.off 12"
}
```

```json
{
  "pri": 166,
  "timestamp": "2026-11-03T02:41:09.903Z",
  "hostname": "esxi-01.corp.example",
  "program": "Hostd",
  "pid": 2099478,
  "Originator": "6876",
  "sub": "Vmsvc.vm:/vmfs/volumes/6543f2a1-9be0c3d4-7e12-0050569a1b2c/FIN-SQL-01/FIN-SQL-01.vmx",
  "opID": "1f3a9c20",
  "sid": "52f0d6a2",
  "user": "root",
  "message": "Power off request received"
}
```

```json
{
  "pri": 13,
  "timestamp": "2026-11-03T02:44:36.587Z",
  "hostname": "esxi-01.corp.example",
  "program": "shell",
  "pid": 2135011,
  "user": "root",
  "command": "/vmfs/volumes/datastore1/.tools/vmsyncd --path /vmfs/volumes/datastore1 --ext .lck9 --threads 8",
  "message": "[root]: /vmfs/volumes/datastore1/.tools/vmsyncd --path /vmfs/volumes/datastore1 --ext .lck9 --threads 8"
}
```

(ESXi has **no native per-file create / rename / write log**. The encryption of `FIN-SQL-01-flat.vmdk` into
`FIN-SQL-01-flat.vmdk.lck9` is never logged as a file event: evidence is the shell command that launched the encryptor,
the NFC upload (E11), the power-off tasks, and later `vmkernel` / `hostd` errors when a VM can no longer open its disk
(exact text **UNVERIFIED**). If `execInstalledOnly` is enforced, the launch is blocked and logged as
`esx.audit.uw.security.execInstalledOnly.violation` ("Execution of non-installed file prevented."; full line text
**UNVERIFIED**). The `opID` format for `vim-cmd` initiated tasks is **UNVERIFIED**.)

#### E13. RFC 5424 variant of a hostd line (for collectors configured with `formatter=RFC_5424`)

```text
<166>1 2026-11-03T02:18:33.611Z esxi-01.corp.example Hostd 2099478 - [Originator@6876 sub="Vimsvc.ha-eventmgr" opID="esxcli-7d-a41c" sid="52f0d6a2" user="root"] Event 1192 : Account svc-patch was created on host esxi-01.corp.example
```

```json
{
  "pri": 166,
  "version": 1,
  "timestamp": "2026-11-03T02:18:33.611Z",
  "hostname": "esxi-01.corp.example",
  "program": "Hostd",
  "pid": 2099478,
  "msgid": "-",
  "Originator": "6876",
  "sub": "Vimsvc.ha-eventmgr",
  "opID": "esxcli-7d-a41c",
  "sid": "52f0d6a2",
  "user": "root",
  "message": "Event 1192 : Account svc-patch was created on host esxi-01.corp.example"
}
```

(SD form taken from the Elastic fixture; whether every ESXi 8 build moves the Originator bracket into SD under
RFC 5424 is **UNVERIFIED**.)

---

## 5. Investigation notes

- **Who and from where (vCenter)**: in syslog, `ipAddress` and `userAgent` exist only inside `desc`
  (`User <u>@<ip> logged in as <ua>`, `Cannot login <u>@<ip>`). Parse them; do not invent `src_ip` keys on the line.
  In the API object they are typed fields.
- **Chain pivot**: `chainId` links a `VmPoweredOffEvent` / `VmReconfiguredEvent` / `VmRemovedEvent` to the task event
  that caused it (`chainId < eventId`). Standalone events have `chainId == eventId`.
- **vCenter acting on a host**: hostd shows `user=vpxuser:VSPHERE.LOCAL\<vcenter user>` when vCenter performs an
  action for a vCenter user; `user=vpxuser` alone means vCenter itself. `root` / a local account means the host was
  driven directly (Host Client, SSH, or API to the host), bypassing vCenter RBAC and the vCenter event stream.
- **SSH session to commands**: auth.log `sshd[<pid>]` and shell.log `shell[<pid>]` share the session's world id per
  KB 321910 (in practice the shell PID is a child; match by time and PID tree when they differ). The ESXi 8 shell
  prefix `[root]:` gives the user directly.
- **Client from opID**: `esxui-` = Host Client in a browser; `esxcli-` = local `esxcli` (also creates
  `root@127.0.0.1` login events in hostd, which are noise, not remote logins); hex ids under `vpxuser` = vCenter.
- **Log blinding**: watch for `esxcli system syslog config set --reset=loghost`, `esxcli system auditrecords ... disable`,
  `rm /var/log/*.log` in shell.log, and `esx.problem.vmsyslogd.remote.failure` (remote logging host unreachable). After
  a reset the SIEM simply goes quiet: absence of a host's stream is itself the signal.
- **Ransomware sequence on ESXi**: SSH enabled (`SSH access has been enabled`, `vim-cmd hostsvc/enable_ssh`) ->
  account / permission changes -> `AccountLockFailures` / `ESXiShellTimeOut` / firewall / lockdown / execInstalledOnly
  changes -> `vim-cmd vmsvc/getallvms` -> `power.off` or `esxcli vm process kill` -> `snapshot.removeall` -> binary run
  from `/tmp` or `/vmfs/volumes/...`.

---

## 6. Common mistakes / fields that do NOT exist

- vCenter syslog is **RFC 5424 only**. Do not render vpxd lines in BSD `Mon DD hh:mm:ss host vpxd[pid]:` form on the
  wire (that form is only what `journalctl` shows on the appliance).
- No `src_ip`, `client_ip`, `user_agent`, `event_type_id`, `principal`, `role`, `vm_name`, `host_name` keys on a vpxd
  syslog record: only the nine bracket fields (`eventId`, `partInfo`, `createdTime`, `eventType`, `severity`, `user`,
  `target`, `chainId`, `desc`) plus the syslog header.
- `eventType` is the full class name with the `vim.event.` prefix (`vim.event.UserLoginSessionEvent`); in the API object
  the discriminator is `_typeName` without the prefix (`UserLoginSessionEvent`). `EventEx` subtypes (`com.vmware.sso.*`,
  `com.vmware.cis.*`) appear as `vim.event.EventEx` on the syslog line; the dotted id is only in API `eventTypeId`.
- API keys are camelCase (`fullFormattedMessage`, `createdTime`, `ipAddress`). PascalCase (`FullFormattedMessage`,
  `CreatedTime`) is PowerCLI output, not native.
- `UserLoginSessionEvent` has no `success` / `result` field; failure is a different class (`BadUsernameSessionEvent`)
  or an SSO `EventEx`. There is no `UserLoginFailedEvent`.
- ESXi lines never carry `Event [..] [1-1]` brackets; hostd host events are `Event <n> : <text>` (no brackets around
  the number). ESXi `Event <n>` numbers are host-local and unrelated to vCenter `eventId`.
- ESXi has no `cmdline`, `process.args`, `file.path`, `file.action` fields and no file-creation event; datastore file
  changes are visible only through shell commands, NFC upload events and later errors.
- `In(166)` / `Er(163)` severity tokens belong to the **local ESXi 8 file**, not the wire line. Do not put them after
  the hostname in a forwarded record. ESXi 7.0 wire lines instead show `Hostd: info hostd[pid]`.
- Program name is `Hostd` (capital H) on ESXi 8, `hostd` inside ESXi 7 lines. `shell` and `sshd` are lower-case.
- `Originator@6876` is a fixed SD-ID style token (VMware private enterprise number), not a variable host id.
- Do not mix vCenter and ESXi names: `vpxuser` is the vCenter-created account on hosts; `VSPHERE.LOCAL\...` users never
  log in to ESXi directly (they appear on hosts only inside `user=vpxuser:VSPHERE.LOCAL\...`).

---

## 7. Recommendation for a native module

### 7.1 Record kinds to support

| Kind id | Product | Rendered as | Minimal required fields |
|---|---|---|---|
| `vcenter.syslog.event` | vCenter | Flat vpxd syslog record + raw line | `pri` (14), `timestamp`, `hostname`, `program` (`vpxd`), `pid`, `eventId`, `partInfo` (`1-1`), `createdTime`, `eventType`, `severity`, `user`, `target`, `chainId`, `desc` |
| `vcenter.api.event` | vCenter | API object (nested JSON) | `_typeName`, `key`, `chainId`, `createdTime`, `userName`, `fullFormattedMessage`, plus per-class fields from 3b (`ipAddress`/`userAgent`/`sessionId`/`locale`; `entity`/`principal`/`group`/`role`/`propagate`; `vm`/`host`/`datacenter`; `alarm`/`source`/`entity`/`from`/`to`; `eventTypeId`/`arguments` for EventEx) |
| `esxi.syslog.sshd` | ESXi | Flat syslog + raw | `pri` (38), `timestamp`, `hostname`, `program` (`sshd`), `pid`, `message` |
| `esxi.syslog.shell` | ESXi | Flat syslog + raw | `pri`, `timestamp`, `hostname`, `program` (`shell`), `pid`, `user`, `command`, `message` (`[<user>]: <command>`) |
| `esxi.syslog.hostd` | ESXi | Flat syslog + raw | `pri` (166/163/164), `timestamp`, `hostname`, `program` (`Hostd`), `pid`, `Originator` (`6876`), `sub`, `message`; optional `opID`, `sid`, `user` |
| `esxi.syslog.vobd` | ESXi | Flat syslog + raw | `pri` (14), `timestamp`, `hostname`, `program` (`vobd`), `pid`, `correlator`, `uptime_us`, `vob_id`, `message` |

The module should always also store the raw wire line (the `text` blocks above) and build it from the flat fields, so
the two can never disagree.

### 7.2 Mapping a platform event onto the native kinds

Platform event fields: `hostname`, `user` / `user_email`, `src_ip`, `event_type`, `description`, `raw` (map).

| Platform `event_type` | vCenter target (kind / `eventType`) | ESXi target (kind / message template) |
|---|---|---|
| `auth_failure` | `vcenter.syslog.event` `vim.event.BadUsernameSessionEvent`, `desc` = `Cannot login {user}@{src_ip}`; SSO user (UPN form): `vim.event.EventEx`, `desc` = `Failed login {user} from {src_ip} at {MM/DD/YYYY hh:mm:ss} GMT in SSO` | Host Client/API: `esxi.syslog.hostd` `sub=Vimsvc.HaSessionManager`, `Rejected password for user {user} from {src_ip} - session={uuid}` plus `sub=Vimsvc.ha-eventmgr` `Event {n} : Cannot login {user}@{src_ip}`; SSH: `esxi.syslog.sshd` `error: PAM: Authentication failure for {user} from {src_ip}` |
| `auth_success` | `vim.event.UserLoginSessionEvent`, `desc` = `User {user}@{src_ip} logged in as {raw.user_agent}` | `esxi.syslog.hostd` `Accepted password for user {user} from {src_ip}` then `Event {n} : User {user}@{src_ip} logged in as {raw.user_agent}` |
| `ssh_login` | (only if relayed: EventEx `esx.audit.ssh.session.opened`, **UNVERIFIED** line form; prefer ESXi kinds) | `esxi.syslog.sshd` `Connection from {src_ip} port {raw.src_port}` + `Accepted keyboard-interactive/pam for {user} from {src_ip} port {raw.src_port} ssh2`; plus `esxi.syslog.vobd` `[vob.user.ssh.session.opened] SSH session was opened for '{user}@{src_ip}'.` |
| `privileged_operation` | `vim.event.VmPoweredOffEvent` / `VmRemovedEvent` / `VmReconfiguredEvent` with `target` = datacenter and `chainId` = task id | `esxi.syslog.shell` `[{user}]: {raw.command}` (for example `vim-cmd vmsvc/power.off {vmid}`, `esxcli vm process kill --type=force --world-id={wid}`, `vim-cmd hostsvc/enable_ssh`) plus `esxi.syslog.hostd` `Task Created : haTask-{vmid}-vim.VirtualMachine.powerOff-{n}` |
| `role_assignment` | `vim.event.PermissionAddedEvent`, `desc` = `Permission created for {raw.principal} on {raw.entity}, role is {raw.role}, propagation is Enabled`; role definition: `vim.event.RoleAddedEvent` / `RoleUpdatedEvent` | `esxi.syslog.shell` `[{user}]: esxcli system permission set -i {raw.principal} -r {raw.role}` |
| `account_modify` | `vim.event.AccountCreatedEvent` (host account via vCenter) or `EventEx` `com.vmware.sso.PrincipalManagement` (SSO user / password reset) | `esxi.syslog.shell` `[{user}]: esxcli system account add -i {raw.account} ...` / `esxcli system account set -i {raw.account} ...` plus `esxi.syslog.hostd` `Event {n} : Account {raw.account} was created on host {hostname}` or `Password was changed for account {raw.account}` |
| `policy_modification` | Host-level changes via vCenter appear as EventEx `esx.audit.*` ids (`esx.audit.lockdownmode.disabled`, `esx.audit.net.firewall.disabled`, `esx.audit.ssh.enabled`); line `eventType` **UNVERIFIED** | `esxi.syslog.shell` `[{user}]: esxcli system settings advanced set -o /{raw.setting_path} -i {raw.value}` (`/UserVars/ESXiShellTimeOut`, `/Security/AccountLockFailures`), `esxcli network firewall set --enabled false`, `vim-cmd -U dcui vimsvc/auth/lockdown_mode_exit`, `esxcli system syslog config set --reset=loghost`; plus `esxi.syslog.vobd` `[esx.audit.net.firewall.disabled] Firewall has been disabled.` / `[esx.audit.lockdownmode.disabled] Administrator access to the host has been enabled.` and `esxi.syslog.hostd` `Task Created : haTask-ha-host-vim.option.OptionManager.updateValues-{n}` |
| `file_create` | none (vCenter has no datastore file event for uploads in the catalog subset checked) | `esxi.syslog.hostd` `Event {n} : NFC operation 'Upload' for path '{raw.file_path}' was initiated from '{src_ip}' and completed with status 'Success'`; encryption / rename itself only as `esxi.syslog.shell` command lines (no file event exists) |

Field rules for the mapper:

- `hostname`: vCenter kinds use the vCenter FQDN in the syslog header; the affected ESXi host goes only into `desc`
  (or `host.name` in the API object). ESXi kinds use the ESXi FQDN in the header.
- `user` / `user_email`: vCenter `user` = `DOMAIN\name` (AD / vsphere.local via SSO) or UPN for SSO EventEx; ESXi `user`
  = local account (`root`, `svc-patch`, `dcui`) or `vpxuser:VSPHERE.LOCAL\name` when the action came through vCenter.
  Never put an email address into an ESXi local account field.
- `src_ip`: written only into message text (`@{src_ip}`, `from {src_ip}`, `initiated from '{src_ip}'`, `rhost=`), and
  into `ipAddress` for `vcenter.api.event` session classes.
- `description`: becomes `desc` (vCenter) or the message body after the vendor prefix (ESXi); it must follow the
  templates above, not free text.
- `raw`: holds the per-kind extras (`eventId`, `chainId`, `pid`, `opID`, `sid`, `sub`, `vob_id`, `command`, `principal`,
  `role`, `user_agent`, `src_port`, `file_path`, `setting_path`, `value`) and the assembled wire line.
