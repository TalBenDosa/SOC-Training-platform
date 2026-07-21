/**
 * Scenario: Hypervisor Ransomware — ESXi Datastore Encryption  (EXPERT)
 *
 * The platform's other ransomware scenario is a Windows endpoint LockBit chain.
 * This one deliberately lives one layer below the operating systems the SOC is
 * used to watching: the attacker never runs a PE, never touches a Windows
 * process tree, and never trips a Sysmon rule. Every action after the vCenter
 * login happens on an appliance that has no EDR agent and cannot have one.
 *
 * ESXi is not Windows. There are no integrity levels, no DLL loads, no
 * Authenticode signatures and no Sysmon. The evidence here is vCenter event
 * types, ESXi `esx.audit.*` VOB events, and plain syslog from hostd / sshd /
 * shell.log. The encryptor is an ELF binary.
 */

import type {
  ScenarioBundle,
  TelemetryEvent,
  IOC,
  ScenarioQuestion,
} from "@/lib/sim/types";
import { makeSha256 } from "@/lib/sim/iocs";

export function buildEsxiRansomwareScenario(
  scenarioId = "esxi-ransomware-2026",
): ScenarioBundle {
  // Saturday 13 June 2026, 21:40 UTC — deliberately a weekend evening.
  const B = new Date("2026-06-13T21:40:00Z").getTime();
  const T = (ms: number) => new Date(B + ms).toISOString();
  const MIN = 60_000;

  const attackerIp = "45.132.192.77";
  const tunnelIp = "10.99.8.44";
  const vcenter = { host: "vcsa-01.cryotech.local", ip: "10.20.5.20" };
  const esxi = { host: "esx-prod-03.cryotech.local", ip: "10.20.5.33" };
  const datastore = "DS-PROD-01";
  const elfHash = makeSha256("akira_esxi_elf_encryptor_v3");

  const events: TelemetryEvent[] = [
    // ── 1. Initial access — SSL-VPN, valid credential, no second factor ────────
    {
      id: "evt_01_vpn_login",
      ts: T(0),
      source: "vpn",
      vendor: "FortiGate",
      event_type: "vpn_login",
      hostname: "FG-EDGE-01",
      user_email: "r.okonkwo@cryotech.com",
      src_ip: attackerIp,
      dst_ip: "198.51.100.10",
      dst_port: 443,
      protocol: "tcp",
      geo: { country: "Bulgaria", city: "Sofia" },
      severity: "medium",
      mitre_technique: "T1133",
      mitre_tactic: "Initial Access",
      description:
        "Contractor account r.okonkwo established an SSL-VPN tunnel from a Bulgarian address and was assigned tunnel IP 10.99.8.44; group VPN-Contractors, authenticated against LDAP.",
      raw: {
        "data.type": "event",
        "data.subtype": "vpn",
        "data.logid": "0101039947",
        "data.level": "notice",
        "data.vd": "root",
        "data.eventtime": "1781386800000000000",
        "data.action": "tunnel-up",
        "data.tunneltype": "ssl-tunnel",
        "data.tunnelid": "1876543210",
        "data.user": "r.okonkwo",
        "data.group": "VPN-Contractors",
        "data.authproto": "LDAP(CRYOTECH-DC)",
        "data.remip": attackerIp,
        "data.tunnelip": tunnelIp,
        "data.dst_host": "N/A",
        "data.reason": "N/A",
        "data.srccountry": "Bulgaria",
        "data.duration": "0",
        "data.sentbyte": "0",
        "data.rcvdbyte": "0",
        "data.msg": "SSL tunnel established",
        "data.logdesc": "SSL VPN tunnel up",
        "rule.id": "81613",
        "rule.level": "5",
        "rule.description": "FortiGate: SSL VPN tunnel established.",
        "rule.groups": "fortigate,vpn,authentication",
      },
    },

    // ── 2. Discovery — management VLAN, vCenter web UI ────────────────────────
    {
      id: "evt_02_mgmt_recon",
      ts: T(6 * MIN),
      source: "firewall",
      vendor: "FortiGate",
      event_type: "net_connection",
      hostname: "FG-EDGE-01",
      user_email: "r.okonkwo@cryotech.com",
      src_ip: tunnelIp,
      dst_ip: vcenter.ip,
      dst_port: 443,
      protocol: "tcp",
      severity: "medium",
      mitre_technique: "T1046",
      mitre_tactic: "Discovery",
      description:
        "Between 21:44 and 21:52 tunnel IP 10.99.8.44 opened sessions to 118 addresses in the 10.20.5.0/24 management VLAN on ports 22, 443 and 902; 9 answered. The vCenter HTTPS session is shown.",
      raw: {
        "data.type": "traffic",
        "data.subtype": "forward",
        "data.logid": "0000000013",
        "data.level": "notice",
        "data.vd": "root",
        "data.eventtime": "1781387160000000000",
        "data.action": "accept",
        "data.srcip": tunnelIp,
        "data.srcport": "50318",
        "data.srcintf": "ssl.root",
        "data.srcintfrole": "undefined",
        "data.dstip": vcenter.ip,
        "data.dstport": "443",
        "data.dstintf": "port3",
        "data.dstintfrole": "lan",
        "data.sessionid": "884213771",
        "data.proto": "6",
        "data.policyid": "42",
        "data.policyname": "VPN-Contractors-to-Internal",
        "data.service": "HTTPS",
        "data.trandisp": "noop",
        "data.duration": "31",
        "data.sentbyte": "8412",
        "data.rcvdbyte": "44190",
        "data.appcat": "unscanned",
        "rule.id": "81603",
        "rule.level": "3",
        "rule.description": "FortiGate: Traffic session accepted by policy.",
        "rule.groups": "fortigate,firewall",
      },
    },

    // ── 3. Credential access — SSO password spray against vCenter ─────────────
    {
      id: "evt_03_sso_spray",
      ts: T(14 * MIN),
      source: "iam",
      vendor: "VMware vCenter Server",
      event_type: "auth_failure",
      hostname: vcenter.host,
      src_ip: tunnelIp,
      severity: "high",
      mitre_technique: "T1110.003",
      mitre_tactic: "Credential Access",
      description:
        "vCenter SSO rejected 61 logins from 10.99.8.44 in nine minutes across 14 principals, four or five attempts each. One representative BadUsernameSessionEvent is shown.",
      raw: {
        "vsphere.event.key": "4418902",
        "vsphere.event.chainId": "4418902",
        "vsphere.event.createdTime": "2026-06-13T21:54:00.412Z",
        "vsphere.event.eventTypeId": "BadUsernameSessionEvent",
        "vsphere.event.severity": "error",
        "vsphere.event.userName": "",
        "vsphere.event.ipAddress": tunnelIp,
        "vsphere.event.userAgent": "VMware vim-java 1.0",
        "vsphere.event.fullFormattedMessage":
          "Cannot login vcadmin@10.99.8.44",
        "log.file.path": "/var/log/vmware/vpxd/vpxd.log",
        "syslog.hostname": vcenter.host,
        "syslog.program": "vpxd",
        "syslog.pid": "10442",
        "event.original":
          "2026-06-13T21:54:00.412Z info vpxd[10442] [Originator@6876 sub=[SSO][SsoAdminServiceImpl]] Cannot login vcadmin@10.99.8.44",
      },
    },

    // ── 4. Valid accounts — built-in SSO administrator succeeds ───────────────
    {
      id: "evt_04_sso_success",
      ts: T(21 * MIN),
      source: "iam",
      vendor: "VMware vCenter Server",
      event_type: "auth_success",
      hostname: vcenter.host,
      user_email: "administrator@vsphere.local",
      src_ip: tunnelIp,
      severity: "critical",
      mitre_technique: "T1078.001",
      mitre_tactic: "Defense Evasion",
      description:
        "vCenter recorded a UserLoginSessionEvent for VSPHERE.LOCAL\\Administrator from 10.99.8.44 via the vim-java client, session 52e1a3f9-7c40-4b18-9d02-6a1f88c3b410.",
      raw: {
        "vsphere.event.key": "4418967",
        "vsphere.event.chainId": "4418967",
        "vsphere.event.createdTime": "2026-06-13T22:01:00.907Z",
        "vsphere.event.eventTypeId": "UserLoginSessionEvent",
        "vsphere.event.severity": "info",
        "vsphere.event.userName": "VSPHERE.LOCAL\\Administrator",
        "vsphere.event.ipAddress": tunnelIp,
        "vsphere.event.userAgent": "VMware vim-java 1.0",
        "vsphere.event.locale": "en",
        "vsphere.event.sessionId": "52e1a3f9-7c40-4b18-9d02-6a1f88c3b410",
        "vsphere.event.fullFormattedMessage":
          "User VSPHERE.LOCAL\\Administrator@10.99.8.44 logged in as VMware vim-java 1.0",
        "log.file.path": "/var/log/vmware/vpxd/vpxd.log",
        "syslog.hostname": vcenter.host,
        "syslog.program": "vpxd",
        "syslog.pid": "10442",
      },
    },

    // ── 5. Persistence + explicit privilege proof ─────────────────────────────
    //  Everything after this point (SSH enable, VM power-off) requires a role
    //  carrying Host.Config.Settings and VirtualMachine.Interact.PowerOff.
    //  This event is where the attacker's working account acquires them.
    {
      id: "evt_05_perm_grant",
      ts: T(24 * MIN),
      source: "iam",
      vendor: "VMware vCenter Server",
      event_type: "role_assignment",
      hostname: vcenter.host,
      user_email: "administrator@vsphere.local",
      src_ip: tunnelIp,
      severity: "critical",
      mitre_technique: "T1098",
      mitre_tactic: "Persistence",
      description:
        "A PermissionAddedEvent granted role -1 (Administrator) to VSPHERE.LOCAL\\svc-monitor on the root Datacenters folder with propagation enabled, issued by VSPHERE.LOCAL\\Administrator.",
      raw: {
        "vsphere.event.key": "4418988",
        "vsphere.event.chainId": "4418988",
        "vsphere.event.createdTime": "2026-06-13T22:04:12.155Z",
        "vsphere.event.eventTypeId": "PermissionAddedEvent",
        "vsphere.event.severity": "info",
        "vsphere.event.userName": "VSPHERE.LOCAL\\Administrator",
        "vsphere.event.ipAddress": tunnelIp,
        "vsphere.event.entity.name": "Datacenters",
        "vsphere.event.entity.type": "Folder",
        "vsphere.event.entity.moref": "group-d1",
        "vsphere.event.permission.principal": "VSPHERE.LOCAL\\svc-monitor",
        "vsphere.event.permission.group": "false",
        "vsphere.event.permission.propagate": "true",
        "vsphere.event.permission.roleId": "-1",
        "vsphere.event.permission.roleName": "Administrator",
        "vsphere.event.fullFormattedMessage":
          "Permission created for VSPHERE.LOCAL\\svc-monitor on Datacenters, role Administrator, propagating",
        "log.file.path": "/var/log/vmware/vpxd/vpxd.log",
        "syslog.hostname": vcenter.host,
        "syslog.program": "vpxd",
        "syslog.pid": "10442",
      },
    },

    // ── 6. THE SIGNATURE MOVE — SSH turned on across the cluster ──────────────
    {
      id: "evt_06_ssh_enabled",
      ts: T(29 * MIN),
      source: "linux_audit",
      vendor: "VMware ESXi",
      event_type: "policy_modification",
      hostname: esxi.host,
      user_email: "svc-monitor@vsphere.local",
      src_ip: tunnelIp,
      severity: "critical",
      mitre_technique: "T1021.004",
      mitre_tactic: "Lateral Movement",
      description:
        "TSM-SSH was started on esx-prod-03 through vCenter by svc-monitor and its startup policy set to 'on'; the same change followed on esx-prod-04 and esx-prod-05 within 80 seconds.",
      raw: {
        "vsphere.event.eventTypeId": "esx.audit.ssh.enabled",
        "vsphere.event.severity": "info",
        "vsphere.event.createdTime": "2026-06-13T22:09:03.771Z",
        "vsphere.event.host.name": esxi.host,
        "vsphere.event.host.moref": "host-1043",
        "vsphere.event.computeResource.name": "PROD-CLUSTER-A",
        "vsphere.event.datacenter.name": "CRYOTECH-DC",
        "vsphere.event.userName": "VSPHERE.LOCAL\\svc-monitor",
        "vsphere.event.fullFormattedMessage": "SSH access has been enabled.",
        "esxi.service.key": "TSM-SSH",
        "esxi.service.label": "SSH",
        "esxi.service.running": "true",
        "esxi.service.policy": "on",
        "log.file.path": "/var/log/vobd.log",
        "syslog.hostname": esxi.host,
        "syslog.program": "vobd",
        "syslog.pid": "2098431",
        "event.original":
          "2026-06-13T22:09:03.771Z esx-prod-03.cryotech.local vobd[2098431]: [GenericCorrelator] [esx.audit.ssh.enabled] SSH access has been enabled.",
      },
    },

    // ── 7. Impair defenses — host firewall opened for sshServer ───────────────
    {
      id: "evt_07_fw_changed",
      ts: T(31 * MIN),
      source: "linux_audit",
      vendor: "VMware ESXi",
      event_type: "policy_modification",
      hostname: esxi.host,
      user_email: "svc-monitor@vsphere.local",
      severity: "critical",
      mitre_technique: "T1562.004",
      mitre_tactic: "Defense Evasion",
      description:
        "The ESXi host firewall ruleset sshServer on esx-prod-03 was set with allowedAll true and an empty allowed-IP list, by svc-monitor.",
      raw: {
        "vsphere.event.eventTypeId": "esx.audit.net.firewall.config.changed",
        "vsphere.event.severity": "info",
        "vsphere.event.createdTime": "2026-06-13T22:11:38.204Z",
        "vsphere.event.host.name": esxi.host,
        "vsphere.event.host.moref": "host-1043",
        "vsphere.event.computeResource.name": "PROD-CLUSTER-A",
        "vsphere.event.userName": "VSPHERE.LOCAL\\svc-monitor",
        "vsphere.event.fullFormattedMessage":
          "Firewall configuration has changed. Operation 'set' for rule set sshServer succeeded.",
        "esxi.firewall.ruleset": "sshServer",
        "esxi.firewall.operation": "set",
        "esxi.firewall.enabled": "true",
        "esxi.firewall.allowedAll": "true",
        "esxi.firewall.allowedIp": "",
        "log.file.path": "/var/log/vobd.log",
        "syslog.hostname": esxi.host,
        "syslog.program": "vobd",
        "syslog.pid": "2098431",
        "event.original":
          "2026-06-13T22:11:38.204Z esx-prod-03.cryotech.local vobd[2098431]: [GenericCorrelator] [esx.audit.net.firewall.config.changed] Firewall configuration has changed. Operation 'set' for rule set sshServer succeeded.",
      },
    },

    // ── 8. The root password is reset so the shell can actually be entered ────
    {
      id: "evt_08_root_pw",
      ts: T(34 * MIN),
      source: "linux_audit",
      vendor: "VMware ESXi",
      event_type: "account_modify",
      hostname: esxi.host,
      user_email: "svc-monitor@vsphere.local",
      severity: "critical",
      mitre_technique: "T1098",
      mitre_tactic: "Persistence",
      description:
        "The local root password on esx-prod-03 was changed through vCenter host account management, initiator vpxuser, acting as svc-monitor. The same change followed on esx-prod-04 and esx-prod-05.",
      raw: {
        "vsphere.event.eventTypeId": "esx.audit.account.password.updated",
        "vsphere.event.severity": "info",
        "vsphere.event.createdTime": "2026-06-13T22:14:07.660Z",
        "vsphere.event.host.name": esxi.host,
        "vsphere.event.host.moref": "host-1043",
        "vsphere.event.userName": "VSPHERE.LOCAL\\svc-monitor",
        "vsphere.event.fullFormattedMessage":
          "Password was changed for account root on host esx-prod-03.cryotech.local.",
        "esxi.account.name": "root",
        "esxi.account.id": "0",
        "esxi.account.initiator": "vpxuser",
        "log.file.path": "/var/log/vobd.log",
        "syslog.hostname": esxi.host,
        "syslog.program": "vobd",
        "syslog.pid": "2098431",
        "event.original":
          "2026-06-13T22:14:07.660Z esx-prod-03.cryotech.local vobd[2098431]: [GenericCorrelator] [esx.audit.account.password.updated] Password was changed for account root on host esx-prod-03.cryotech.local.",
      },
    },

    // ── 9. Interactive shell on the hypervisor ────────────────────────────────
    {
      id: "evt_09_ssh_session",
      ts: T(37 * MIN),
      source: "linux_audit",
      vendor: "VMware ESXi",
      event_type: "ssh_login",
      hostname: esxi.host,
      user_email: "root@esx-prod-03.cryotech.local",
      src_ip: tunnelIp,
      dst_ip: esxi.ip,
      dst_port: 22,
      protocol: "tcp",
      severity: "critical",
      mitre_technique: "T1021.004",
      mitre_tactic: "Lateral Movement",
      description:
        "root logged in over SSH to esx-prod-03 from 10.99.8.44 — the VPN tunnel address assigned to r.okonkwo thirty-seven minutes earlier.",
      raw: {
        "syslog.hostname": esxi.host,
        "syslog.program": "sshd",
        "syslog.pid": "2098700",
        "syslog.priority": "authpriv.info",
        "log.file.path": "/var/log/auth.log",
        "syslog.message":
          "Accepted keyboard-interactive/pam for root from 10.99.8.44 port 51022 ssh2",
        "event.original":
          "2026-06-13T22:17:04Z esx-prod-03.cryotech.local sshd[2098700]: Accepted keyboard-interactive/pam for root from 10.99.8.44 port 51022 ssh2",
        "vsphere.event.eventTypeId": "esx.audit.ssh.session.opened",
        "vsphere.event.fullFormattedMessage":
          "SSH session was opened for 'root@10.99.8.44'.",
        "source.ip": tunnelIp,
        "source.port": "51022",
        "destination.ip": esxi.ip,
        "destination.port": "22",
        "user.name": "root",
      },
    },

    // ── 10. Service Stop — VMs forced off so the disk files unlock ────────────
    {
      id: "evt_10_vim_cmd_poweroff",
      ts: T(41 * MIN),
      source: "linux_audit",
      vendor: "VMware ESXi",
      event_type: "privileged_operation",
      hostname: esxi.host,
      user_email: "root@esx-prod-03.cryotech.local",
      src_ip: tunnelIp,
      severity: "critical",
      mitre_technique: "T1489",
      mitre_tactic: "Impact",
      description:
        "The root shell ran a loop over `vim-cmd vmsvc/getallvms` calling power.off on each entry; all 96 VMs on PROD-CLUSTER-A were stopped between 22:21 and 22:26.",
      raw: {
        "syslog.hostname": esxi.host,
        "syslog.program": "shell",
        "syslog.pid": "2098754",
        "log.file.path": "/var/log/shell.log",
        "syslog.message":
          "[root]: for v in $(vim-cmd vmsvc/getallvms | awk 'NR>1{print $1}'); do vim-cmd vmsvc/power.off $v; done",
        "event.original":
          "2026-06-13T22:21:11Z esx-prod-03.cryotech.local shell[2098754]: [root]: for v in $(vim-cmd vmsvc/getallvms | awk 'NR>1{print $1}'); do vim-cmd vmsvc/power.off $v; done",
        "user.name": "root",
        "process.working_directory": "/tmp",
      },
    },

    // ── 11. The same power-offs as vCenter records them ───────────────────────
    {
      id: "evt_11_vm_poweroff",
      ts: T(42 * MIN),
      source: "linux_audit",
      vendor: "VMware vCenter Server",
      event_type: "privileged_operation",
      hostname: vcenter.host,
      severity: "critical",
      mitre_technique: "T1489",
      mitre_tactic: "Impact",
      description:
        "vCenter recorded a VmPoweredOffEvent for each of the 96 guests; the record for SQL-PROD-02 on esx-prod-03 is shown, with an empty userName field.",
      raw: {
        "vsphere.event.key": "4419331",
        "vsphere.event.chainId": "4419331",
        "vsphere.event.createdTime": "2026-06-13T22:22:19.883Z",
        "vsphere.event.eventTypeId": "VmPoweredOffEvent",
        "vsphere.event.severity": "info",
        "vsphere.event.userName": "",
        "vsphere.event.vm.name": "SQL-PROD-02",
        "vsphere.event.vm.moref": "vm-2041",
        "vsphere.event.host.name": esxi.host,
        "vsphere.event.computeResource.name": "PROD-CLUSTER-A",
        "vsphere.event.datacenter.name": "CRYOTECH-DC",
        "vsphere.event.fullFormattedMessage":
          "SQL-PROD-02 on esx-prod-03.cryotech.local in CRYOTECH-DC is powered off",
        "log.file.path": "/var/log/vmware/vpxd/vpxd.log",
        "syslog.hostname": vcenter.host,
        "syslog.program": "vpxd",
        "syslog.pid": "10442",
      },
    },

    // ── 12. THE BLIND SPOT — the only thing endpoint tooling ever noticed ─────
    {
      id: "evt_12_edr_silence",
      ts: T(47 * MIN),
      source: "edr",
      vendor: "CrowdStrike Falcon",
      event_type: "edr_alert",
      hostname: "SQL-PROD-02",
      severity: "high",
      description:
        "Falcon stopped receiving check-ins from 71 server sensors between 22:22 and 22:27, all of them guests on PROD-CLUSTER-A; the record for SQL-PROD-02 is shown, host status offline.",
      raw: {
        "crowdstrike.event_simplename": "SensorHeartbeatMissing",
        "crowdstrike.host.hostname": "SQL-PROD-02",
        "crowdstrike.host.aid": "b41d9c77e2a54f0e8c1a6d3f9b207e55",
        "crowdstrike.host.platform_name": "Windows",
        "crowdstrike.host.os_version": "Windows Server 2022",
        "crowdstrike.host.product_type_desc": "Server",
        "crowdstrike.host.local_ip": "10.30.12.61",
        "crowdstrike.host.last_seen": "2026-06-13T22:22:41Z",
        "crowdstrike.host.status": "offline",
        "crowdstrike.host.reduced_functionality_mode": "no",
        "crowdstrike.sensor.version": "7.18.18604.0",
        "crowdstrike.network_containment_state": "Not Contained",
        "event.action": "sensor_heartbeat_missing",
        "host.name": "SQL-PROD-02",
      },
    },

    // ── 13. Impact — the ELF encryptor against the datastore ──────────────────
    {
      id: "evt_13_encryptor",
      ts: T(52 * MIN),
      source: "linux_audit",
      vendor: "VMware ESXi",
      event_type: "privileged_operation",
      hostname: esxi.host,
      user_email: "root@esx-prod-03.cryotech.local",
      src_ip: tunnelIp,
      severity: "critical",
      mitre_technique: "T1486",
      mitre_tactic: "Impact",
      file: {
        name: "encryptor",
        path: "/tmp/.x/encryptor",
        sha256: elfHash,
        size: 1476592,
      },
      description:
        "A 1.4 MB ELF binary staged in /tmp/.x was made executable and run against /vmfs/volumes/DS-PROD-01 with the flags -n 20 -t 32, from the root shell session.",
      raw: {
        "syslog.hostname": esxi.host,
        "syslog.program": "shell",
        "syslog.pid": "2098754",
        "log.file.path": "/var/log/shell.log",
        "syslog.message":
          "[root]: chmod +x /tmp/.x/encryptor; /tmp/.x/encryptor -p /vmfs/volumes/DS-PROD-01 -n 20 -t 32",
        "event.original":
          "2026-06-13T22:32:26Z esx-prod-03.cryotech.local shell[2098754]: [root]: chmod +x /tmp/.x/encryptor; /tmp/.x/encryptor -p /vmfs/volumes/DS-PROD-01 -n 20 -t 32",
        "user.name": "root",
        "process.working_directory": "/tmp/.x",
      },
    },

    // ── 14. Ransom note ───────────────────────────────────────────────────────
    {
      id: "evt_14_ransom_note",
      ts: T(56 * MIN),
      source: "linux_audit",
      vendor: "VMware ESXi",
      event_type: "file_create",
      hostname: esxi.host,
      user_email: "root@esx-prod-03.cryotech.local",
      src_ip: tunnelIp,
      severity: "critical",
      mitre_technique: "T1486",
      mitre_tactic: "Impact",
      file: {
        name: "akira_readme.txt",
        path: "/vmfs/volumes/DS-PROD-01/SQL-PROD-02/akira_readme.txt",
        size: 2914,
      },
      description:
        "A shell loop copied akira_readme.txt into every VM folder on DS-PROD-01; responders browsing the datastore found SQL-PROD-02-flat.vmdk renamed with a .akira suffix.",
      raw: {
        "syslog.hostname": esxi.host,
        "syslog.program": "shell",
        "syslog.pid": "2098754",
        "log.file.path": "/var/log/shell.log",
        "syslog.message":
          "[root]: for d in /vmfs/volumes/DS-PROD-01/*/; do cp /tmp/.x/akira_readme.txt \"$d\"; done",
        "event.original":
          "2026-06-13T22:36:48Z esx-prod-03.cryotech.local shell[2098754]: [root]: for d in /vmfs/volumes/DS-PROD-01/*/; do cp /tmp/.x/akira_readme.txt \"$d\"; done",
        "user.name": "root",
        "process.working_directory": "/tmp/.x",
      },
    },
  ];

  const iocs: IOC[] = [
    {
      type: "ip",
      value: attackerIp,
      first_seen: T(0),
      last_seen: T(56 * MIN),
      reputation: "malicious",
      tags: ["external", "vpn-source"],
    },
    {
      type: "ip",
      value: tunnelIp,
      first_seen: T(0),
      last_seen: T(56 * MIN),
      reputation: "suspicious",
      tags: ["internal", "vpn-tunnel-address"],
    },
    {
      type: "sha256",
      value: elfHash,
      reputation: "malicious",
      tags: ["elf", "encryptor"],
    },
    {
      type: "user",
      value: "r.okonkwo@cryotech.com",
      reputation: "suspicious",
      tags: ["contractor", "vpn"],
    },
    {
      type: "user",
      value: "administrator@vsphere.local",
      reputation: "suspicious",
      tags: ["sso", "built-in-account"],
    },
    {
      type: "user",
      value: "svc-monitor@vsphere.local",
      reputation: "malicious",
      tags: ["sso", "role-granted-during-window"],
    },
    {
      type: "host",
      value: vcenter.host,
      reputation: "unknown",
      tags: ["management-plane"],
    },
    {
      type: "host",
      value: esxi.host,
      reputation: "unknown",
      tags: ["hypervisor", "shell-access"],
    },
  ];

  const killchain = [
    {
      ts: T(0),
      phase: "Initial Access",
      action:
        "SSL-VPN tunnel established with contractor credentials — VPN-Contractors group has no second factor",
    },
    {
      ts: T(6 * MIN),
      phase: "Discovery",
      action:
        "Tunnel IP sweeps the 10.20.5.0/24 management VLAN and reaches the vCenter HTTPS interface",
    },
    {
      ts: T(14 * MIN),
      phase: "Credential Access",
      action:
        "Low-and-slow password spray against 14 vCenter SSO principals — no lockouts triggered",
    },
    {
      ts: T(21 * MIN),
      phase: "Privilege Escalation",
      action:
        "administrator@vsphere.local authenticates — built-in SSO account holds Administrator on root",
    },
    {
      ts: T(24 * MIN),
      phase: "Persistence",
      action:
        "Administrator role granted to svc-monitor on the Datacenters folder, propagating",
    },
    {
      ts: T(29 * MIN),
      phase: "Lateral Movement",
      action:
        "TSM-SSH enabled on three production ESXi hosts via vCenter (esx.audit.ssh.enabled)",
    },
    {
      ts: T(31 * MIN),
      phase: "Defense Evasion",
      action:
        "ESXi host firewall sshServer ruleset opened to all source addresses",
    },
    {
      ts: T(37 * MIN),
      phase: "Lateral Movement",
      action:
        "Interactive root SSH session opened on esx-prod-03 from the VPN tunnel address",
    },
    {
      ts: T(41 * MIN),
      phase: "Impact — Service Stop",
      action:
        "vim-cmd vmsvc/power.off loop stops all 96 VMs, releasing the locks on their -flat.vmdk files",
    },
    {
      ts: T(52 * MIN),
      phase: "Impact — Encryption",
      action:
        "ELF encryptor runs against /vmfs/volumes/DS-PROD-01 with 20% partial encryption across 32 threads",
    },
    {
      ts: T(56 * MIN),
      phase: "Impact — Extortion",
      action:
        "akira_readme.txt copied into every VM folder; virtual disks renamed with a .akira suffix",
    },
  ];

  const questions: ScenarioQuestion[] = [
    {
      id: "q1",
      prompt:
        "Which pair of events, taken together, ties the vCenter compromise back to the VPN account rather than to an insider on the management VLAN?",
      hint: "Look for a value that one event assigns and another event reports.",
      kind: "single",
      options: [
        {
          value: "tunnel_and_login",
          label:
            "The FortiGate tunnel-up assigning 10.99.8.44 to r.okonkwo, and the vCenter login from 10.99.8.44",
        },
        {
          value: "spray_and_grant",
          label:
            "The SSO password spray at 21:54, and the Administrator role granted to svc-monitor at 22:04",
        },
        {
          value: "ssh_and_shell",
          label:
            "The esx.audit.ssh.enabled event at 22:09, and the root SSH session on esx-prod-03 at 22:17",
        },
        {
          value: "poweroff_and_edr",
          label:
            "The VmPoweredOffEvent for SQL-PROD-02, and the Falcon sensor heartbeat loss on the same host",
        },
      ],
      answer: "tunnel_and_login",
      xp: 75,
      explanation:
        "10.99.8.44 is the pivot value. The FortiGate is the only device that knows which human that address belongs to; vCenter only ever sees the address. Joining them attributes the whole vSphere intrusion to r.okonkwo's credential. The other pairs are all real and all useful, but each one links two attacker actions to each other — none of them crosses the boundary from an IP address back to an identity, which is the specific question being asked.",
    },
    {
      id: "q2",
      prompt:
        "Ninety-six VMs were encrypted and the EDR platform raised no ransomware detection at all. Why?",
      kind: "single",
      options: [
        {
          value: "no_agent",
          label:
            "The encryptor ran on the hypervisor, below the guests — and no EDR sensor exists on ESXi",
        },
        {
          value: "detect_only",
          label:
            "The sensors were running in detection-only mode, so the payload was logged but never blocked",
        },
        {
          value: "signed_elf",
          label:
            "The ELF binary carried a valid signature, so the sensors treated it as trusted vendor tooling",
        },
        {
          value: "uninstalled",
          label:
            "The attacker uninstalled the sensors from each guest before launching the encryption routine",
        },
      ],
      answer: "no_agent",
      xp: 100,
      explanation:
        "The sensors were not bypassed, disabled or fooled — they were never in the room. A Falcon sensor watches processes and file writes inside a guest OS. The encryptor never entered a guest: it opened the -flat.vmdk files from the VMFS layer, which the guest cannot see and the sensor cannot instrument. Detection-only is wrong because a detection-only sensor still writes a detection, and none exists. The signed-binary answer imports a Windows concept — ESXi has no Authenticode and no signature-based execution trust for arbitrary ELF files. Uninstalling agents would itself have generated sensor-removal events on 71 hosts; instead the hosts simply stopped answering, which is what a hard power-off looks like.",
    },
    {
      id: "q3",
      prompt:
        "Reviewing the timeline for a detection rule, what was the earliest high-fidelity opportunity to catch this before impact?",
      kind: "single",
      options: [
        {
          value: "ssh_enabled",
          label:
            "esx.audit.ssh.enabled on esx-prod-03 at 22:09, with no change record for the maintenance window",
        },
        {
          value: "vpn_login",
          label:
            "The SSL-VPN tunnel for r.okonkwo at 21:40, from a Bulgarian address on a Saturday evening",
        },
        {
          value: "sso_spray",
          label:
            "The burst of vCenter BadUsernameSessionEvent rejections from a single source at 21:54",
        },
        {
          value: "heartbeat_loss",
          label:
            "The loss of 71 Falcon sensor heartbeats inside a five-minute window starting at 22:22",
        },
      ],
      answer: "ssh_enabled",
      xp: 100,
      explanation:
        "Fidelity and earliness are different things, and the best rule maximises both. The VPN login is the earliest event but a contractor logging in from abroad at the weekend is ordinary — on its own it is close to noise. The SSO rejections are stronger and worth alerting on, but expired service accounts and stale scripts generate the same pattern in every vSphere estate, so it is a triage lead rather than a decision. esx.audit.ssh.enabled is different in kind: ESXi ships with SSH off, it is enabled only deliberately, the event names the host and the vSphere principal, and it can be joined against the change calendar automatically — an enable with no change record is very close to a certainty. It also sits 32 minutes ahead of the first power-off, which is enough time to act. The heartbeat loss is the highest-confidence signal of all, but it arrives after the VMs are already down; it reports the incident rather than preventing it.",
    },
    {
      id: "q4",
      prompt:
        "Enabling SSH on an ESXi host and powering off its VMs are both privileged vSphere operations. What in this timeline gave the attacker the right to perform them?",
      kind: "single",
      options: [
        {
          value: "admin_role",
          label:
            "The Administrator role granted on the Datacenters folder, carrying Host.Config.Settings and VM.Interact.PowerOff",
        },
        {
          value: "root_ssh",
          label:
            "The interactive root SSH session on esx-prod-03, which gives unrestricted control of the host and its guests",
        },
        {
          value: "firewall_rule",
          label:
            "The sshServer firewall change, which removed the source restriction protecting the management interfaces",
        },
        {
          value: "vpn_group",
          label:
            "Membership of the VPN-Contractors group, whose policy permits routed access into the management VLAN",
        },
      ],
      answer: "admin_role",
      xp: 100,
      explanation:
        "vSphere authorises by role, and the PermissionAddedEvent at 22:04 is where the required privileges appear: Administrator on the root folder with propagation enabled, which inherits down to every host and VM. Host.Config.Settings is what permits starting TSM-SSH; VirtualMachine.Interact.PowerOff is what permits stopping a guest. The root SSH session is a consequence of that role, not its cause — it happens at 22:17, eight minutes after SSH was already enabled, so it cannot explain the enable. The firewall change is reachability, not authorisation: it decides whether packets arrive, not whether the caller is permitted to act. VPN group membership only gets the attacker onto the network; the FortiGate has no view of vSphere privileges at all.",
    },
    {
      id: "q5",
      prompt:
        "The attacker powered off all 96 VMs before launching the encryptor. What was the purpose, and which technique does it map to?",
      kind: "single",
      options: [
        {
          value: "t1489",
          label:
            "T1489 Service Stop — a running VM holds an exclusive lock on its -flat.vmdk, so it must be stopped first",
        },
        {
          value: "t1490",
          label:
            "T1490 Inhibit System Recovery — powering a VM off discards its snapshots and its restore points",
        },
        {
          value: "t1486",
          label:
            "T1486 Data Encrypted for Impact — the power-off is simply the opening stage of the encryption routine",
        },
        {
          value: "t1529",
          label:
            "T1529 System Shutdown/Reboot — the outage was the objective and encryption was added opportunistically",
        },
      ],
      answer: "t1489",
      xp: 100,
      explanation:
        "This is a mechanical requirement, not a psychological one. ESXi holds an exclusive lock on the -flat.vmdk of every running VM; an encryptor cannot rewrite a locked file, so the disks have to be released first. Stopping the workload to enable the impact is T1489. T1490 is wrong on the facts — VMFS snapshot deltas survive a power-off untouched, and the recovery damage here comes from the encryption of the base disks, not the shutdown. T1486 does apply to the encryptor itself but not to the power-off, which writes nothing; collapsing the two loses the detection opportunity, because the power-off is visible in vCenter minutes before any file changes. T1529 describes shutting down a system as the end goal, whereas here the outage is a side effect of clearing the way.",
    },
  ];

  return {
    scenario_id: scenarioId,
    title: "Hypervisor Ransomware — ESXi Datastore Encryption",
    threat_actor: "Akira ransomware affiliate (ESXi-focused)",
    attack_kind: "ransomware_hypervisor",
    briefing: "The NOC escalated at 22:30: every guest on PROD-CLUSTER-A is unreachable and monitoring shows 71 server sensors offline. The vCenter appliance for that cluster is still responding. Saturday night, with no change window open.",
    narrative:
      "At 21:40 on a Saturday, a contractor's SSL-VPN credential was used from Sofia. The VPN-Contractors group had never been moved onto FortiToken, so a password was all it took. Within six minutes the tunnel address was sweeping the management VLAN; within fifteen it was spraying vCenter SSO. The account that answered was administrator@vsphere.local — the built-in SSO account that owns the entire inventory. From there the attacker granted a second principal the Administrator role, enabled SSH on three production hosts, opened the ESXi firewall, reset root's password and dropped into a shell on the hypervisor. All 96 VMs on PROD-CLUSTER-A were forced off to release the locks on their virtual disks, and an ELF encryptor was pointed at /vmfs/volumes/DS-PROD-01. Not one of these steps produced an EDR detection, because ESXi cannot run an EDR sensor: the only endpoint-side signal the SOC ever received was 71 Falcon agents going quiet at once. Your job is to reconstruct the chain from vCenter and syslog evidence alone, prove which privileges made each step possible, and identify the point where a single detection rule would have stopped it.",
    learning_objectives: [
      "Trace a hypervisor ransomware chain from VPN initial access through vCenter to an ESXi root shell using only vCenter events and syslog",
      "Explain why endpoint EDR produces no ransomware detection when the encryptor executes on the hypervisor, and reason from missing telemetry",
      "Identify the earliest high-fidelity detection opportunity in a vSphere intrusion and justify it against earlier but noisier signals",
      "Prove the vSphere privilege chain — which role privileges are required to enable SSH on a host and to power off its VMs",
      "Recognise mass VM power-off as T1489 Service Stop and distinguish it from T1490 and T1486",
    ],
    alerts: [], // alerts are attached by the catalogue wiring
    events,
    iocs,
    killchain,
    questions,
  };
}
