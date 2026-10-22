/**
 * Events-only half of the ./esxiRansomware.ts scenario pack.
 *
 * The dashboard's live feed runs in the browser (attackStories.ts), so what it
 * imports ships in a public /_next/static chunk. The answer key (questions,
 * answers, explanations, IOCs, killchain, narrative) stays in the builder in
 * ./esxiRansomware.ts, which composes this module on the server. Keep anything
 * answer-bearing out of this file: every visitor can read it.
 */
import type { TelemetryEvent } from "@/lib/sim/types";
import { makeSha256 } from "@/lib/sim/iocs";
import { winLogon } from "@/lib/sim/emitters/windowsSecurity";

/** Telemetry half of `buildEsxiRansomwareScenario`: the events and the story title, no answer key. */
export function esxiRansomwareScenarioEvents() {
  // Saturday 13 June 2026, 21:40 UTC — deliberately a weekend evening.
  const B = new Date("2026-06-13T21:40:00Z").getTime();
  const T = (ms: number) => new Date(B + ms).toISOString();
  const MIN = 60_000;

  const attackerIp = "45.135.232.44";
  const tunnelIp = "10.99.8.44";
  const vcenter = { host: "vcsa-01.nexacorp.local", ip: "10.20.5.20" };
  const esxi = { host: "esx-prod-03.nexacorp.local", ip: "10.20.5.33" };
  const elfHash = makeSha256("akira_esxi_elf_encryptor_v3");

  // EDR↔scenario integration (Phase 4): ONE incident that spans two planes — the
  // identity side (SSO password spray → vCenter admin → role grant) AND the host
  // side (ESXi shell sessions and the ELF encryptor on the hypervisor, plus the
  // Falcon guest-sensor blackout). edr_scope "hybrid": the analyst pivots to EDR
  // for the endpoint blind-spot (71 guests going offline) while the SSO/permission
  // abuse is investigated on the identity plane, correlated by incident_id.
  // is_detection is EDR-source only — here the single Falcon AgentOffline alert;
  // the ESXi impact events are host telemetry (linux_audit), not EDR detections.
  const INCIDENT = "inc:esxi:1";

  const esxHost4 = { host: "esx-prod-04.nexacorp.local", ip: "10.20.5.34", moref: "host-1044" };
  const esxHost5 = { host: "esx-prod-05.nexacorp.local", ip: "10.20.5.35", moref: "host-1045" };
  type EsxHost = { host: string; ip: string; moref?: string };

  // FortiGate SSL-VPN tunnel-up record for r.okonkwo (same shape as the 21:40 login).
  const vpnTunnelUp = (id: string, ts: string, o: { remip: string; tunnelip: string; country: string; city: string; lat: number; lon: number; tunnelid: string; description: string }): TelemetryEvent => ({
    id, ts, source: "vpn", vendor: "FortiGate SSL-VPN", event_type: "vpn_login", hostname: "FG-EDGE-01",
    user_email: "r.okonkwo@nexacorp.com", src_ip: o.remip, dst_ip: "45.86.207.10", dst_port: 443, protocol: "tcp",
    geo: { country: o.country, city: o.city, latitude: o.lat, longitude: o.lon }, severity: "informational", description: o.description,
    raw: {
      "data.type": "event",
      "data.subtype": "vpn",
      "data.logid": "0101039947",
      "data.level": "notice",
      "data.vd": "root",
      "data.eventtime": `${Date.parse(ts)}000000`,
      "data.action": "tunnel-up",
      "data.tunneltype": "ssl-tunnel",
      "data.tunnelid": o.tunnelid,
      "data.user": "r.okonkwo",
      "data.group": "VPN-Contractors",
      "data.authproto": "LDAP(NEXACORP-DC)",
      "data.remip": o.remip,
      "data.tunnelip": o.tunnelip,
      "data.dst_host": "N/A",
      "data.reason": "N/A",
      "data.srccountry": o.country,
      "data.duration": "0",
      "data.sentbyte": "0",
      "data.rcvdbyte": "0",
      "data.msg": "SSL tunnel established",
      "data.logdesc": "SSL VPN tunnel up",
      "rule.id": "81613",
      "rule.level": "5",
      "rule.description": "FortiGate: SSL VPN tunnel established.",
      "rule.groups": ["fortigate", "vpn", "authentication"],
    },
  });

  // The firewall's record of the tunnel address opening an SSH session to a host in the management VLAN.
  const fgSshHop = (id: string, ts: string, hostShort: string, dstip: string, srcport: string, sessionid: string, offsetMs: number): TelemetryEvent => ({
    id, ts, source: "firewall", vendor: "FortiGate", event_type: "net_connection", hostname: "FG-EDGE-01",
    user_email: "r.okonkwo@nexacorp.com", src_ip: tunnelIp, dst_ip: dstip, dst_port: 22, protocol: "tcp", severity: "medium",
    mitre_technique: "T1021.004", mitre_tactic: "Lateral Movement",
    description: `An SSH session from the tunnel address 10.99.8.44 to ${hostShort} (${dstip}:22) was accepted under the VPN-Contractors-to-Internal policy.`,
    raw: {
      "data.type": "traffic",
      "data.subtype": "forward",
      "data.logid": "0000000013",
      "data.level": "notice",
      "data.vd": "root",
      "data.eventtime": `${B + offsetMs}000000`,
      "data.action": "accept",
      "data.srcip": tunnelIp,
      "data.srcport": srcport,
      "data.srcintf": "ssl.root",
      "data.srcintfrole": "undefined",
      "data.dstip": dstip,
      "data.dstport": "22",
      "data.dstintf": "port3",
      "data.dstintfrole": "lan",
      "data.sessionid": sessionid,
      "data.proto": "6",
      "data.policyid": "42",
      "data.policyname": "VPN-Contractors-to-Internal",
      "data.service": "SSH",
      "data.trandisp": "noop",
      "data.appcat": "unscanned",
      "rule.id": "81601",
      "rule.level": "3",
      "rule.description": "FortiGate: Traffic session accepted by policy.",
      "rule.groups": ["fortigate", "firewall"],
    },
  });

  // sshd accepting the root login on a host, with the matching ESXi VOB event.
  const esxSshSession = (id: string, ts: string, h: EsxHost, pid: string, sport: string, utc: string): TelemetryEvent => ({
    id, ts, source: "virtualization", vendor: "VMware ESXi", event_type: "ssh_login", hostname: h.host,
    user_email: `root@${h.host}`, src_ip: tunnelIp, dst_ip: h.ip, dst_port: 22, protocol: "tcp", severity: "critical",
    mitre_technique: "T1021.004", mitre_tactic: "Lateral Movement",
    description: `root logged in over SSH to ${h.host.split(".")[0]} from 10.99.8.44.`,
    raw: {
      "syslog.hostname": h.host,
      "syslog.program": "sshd",
      "syslog.pid": pid,
      "syslog.priority": "authpriv.info",
      "log.file.path": "/var/log/auth.log",
      "syslog.message": `Accepted keyboard-interactive/pam for root from 10.99.8.44 port ${sport} ssh2`,
      "event.original": `${utc} ${h.host} sshd[${pid}]: Accepted keyboard-interactive/pam for root from 10.99.8.44 port ${sport} ssh2`,
      "vsphere.event.eventTypeId": "esx.audit.ssh.session.opened",
      "vsphere.event.fullFormattedMessage": "SSH session was opened for 'root@10.99.8.44'.",
      "source.ip": tunnelIp,
      "source.port": sport,
      "destination.ip": h.ip,
      "destination.port": "22",
      "user.name": "root",
    },
  });

  // The root shell's power-off loop on one host (shell.log).
  const shellPoweroff = (id: string, ts: string, h: EsxHost, pid: string, utc: string): TelemetryEvent => ({
    id, ts, source: "virtualization", vendor: "VMware ESXi", event_type: "privileged_operation", hostname: h.host,
    user_email: `root@${h.host}`, src_ip: tunnelIp, severity: "critical", mitre_technique: "T1489", mitre_tactic: "Impact",
    description: `The root shell on ${h.host.split(".")[0]} ran the same vim-cmd power.off loop over every VM registered on that host.`,
    raw: {
      "syslog.hostname": h.host,
      "syslog.program": "shell",
      "syslog.pid": pid,
      "log.file.path": "/var/log/shell.log",
      "syslog.message": "[root]: for v in $(vim-cmd vmsvc/getallvms | awk 'NR>1{print $1}'); do vim-cmd vmsvc/power.off $v; done",
      "event.original": `${utc} ${h.host} shell[${pid}]: [root]: for v in $(vim-cmd vmsvc/getallvms | awk 'NR>1{print $1}'); do vim-cmd vmsvc/power.off $v; done`,
      "user.name": "root",
      "process.working_directory": "/tmp",
    },
  });

  // vCenter's VmPoweredOffEvent for one guest (no vSphere user: the power-off came from the host shell).
  const vmPoweredOff = (id: string, ts: string, key: string, created: string, vm: string, moref: string, h: EsxHost): TelemetryEvent => ({
    id, ts, source: "virtualization", vendor: "VMware vCenter Server", event_type: "privileged_operation", hostname: vcenter.host,
    severity: "critical", mitre_technique: "T1489", mitre_tactic: "Impact",
    description: `vCenter recorded a VmPoweredOffEvent for ${vm} on ${h.host.split(".")[0]}, with an empty userName field.`,
    raw: {
      "vsphere.event.key": key,
      "vsphere.event.chainId": key,
      "vsphere.event.createdTime": created,
      "vsphere.event.eventTypeId": "VmPoweredOffEvent",
      "vsphere.event.severity": "info",
      "vsphere.event.userName": "",
      "vsphere.event.vm.name": vm,
      "vsphere.event.vm.moref": moref,
      "vsphere.event.host.name": h.host,
      "vsphere.event.computeResource.name": "PROD-CLUSTER-A",
      "vsphere.event.datacenter.name": "NEXACORP-DC",
      "vsphere.event.fullFormattedMessage": `${vm} on ${h.host} in NEXACORP-DC is powered off`,
      "log.file.path": "/var/log/vmware/vpxd/vpxd.log",
      "syslog.hostname": vcenter.host,
      "syslog.program": "vpxd",
      "syslog.pid": "10442",
    },
  });

  const events: TelemetryEvent[] = [
    // ── 0. Baseline — an earlier tunnel for the same contractor, from a different place ──
    {
      ...vpnTunnelUp("evt_00_vpn_prior", T(-(2 * 24 * 60 + 13 * 60 + 35) * MIN), {
        remip: "83.8.145.77", tunnelip: "10.99.8.21", country: "Poland", city: "Warsaw", lat: 52.2297, lon: 21.0122, tunnelid: "1874120934",
        description: "Contractor account r.okonkwo established an SSL-VPN tunnel from a Polish address and was assigned tunnel IP 10.99.8.21; group VPN-Contractors, authenticated against LDAP.",
      }),
      is_baseline: true,
    },

    // ── 0a. The directory side of the same VPN login ─────────────────────────────
    winLogon({
      companyId: "nexacorp", id: "evt_00a_dc_ldap_bind", ts: T(-2_000), host: "NEXACORP-DC", fqdn: "NEXACORP-DC.nexacorp.local", userEmail: "r.okonkwo@nexacorp.com",
      targetUser: "r.okonkwo", srcIp: "10.20.1.1", logonType: 3, authPackage: "Negotiate", logonProcess: "Advapi  ", workstation: "-",
      srcPort: "49822", recordId: "90311442", severity: "informational",
      description: "NEXACORP-DC recorded a 4624 network logon for r.okonkwo from 10.20.1.1 (FG-EDGE-01), the LDAP bind behind the SSL-VPN login.",
    }),

    // ── 1. Initial access — SSL-VPN, valid credential, no second factor ────────
    {
      id: "evt_01_vpn_login",
      ts: T(0),
      source: "vpn",
      vendor: "FortiGate SSL-VPN",
      event_type: "vpn_login",
      hostname: "FG-EDGE-01",
      user_email: "r.okonkwo@nexacorp.com",
      src_ip: attackerIp,
      dst_ip: "45.86.207.10",
      dst_port: 443,
      protocol: "tcp",
      geo: { country: "Bulgaria", city: "Sofia", latitude: 42.6977, longitude: 23.3219 },
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
        "data.authproto": "LDAP(NEXACORP-DC)",
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
        "rule.groups": ["fortigate", "vpn", "authentication"],
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
      user_email: "r.okonkwo@nexacorp.com",
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
        "rule.id": "81601",
        "rule.level": "3",
        "rule.description": "FortiGate: Traffic session accepted by policy.",
        "rule.groups": ["fortigate", "firewall"],
      },
    },

    // ── 3. Credential access — SSO password spray against vCenter ─────────────
    {
      id: "evt_03_sso_spray",
      ts: T(14 * MIN),
      source: "virtualization",
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
      source: "virtualization",
      vendor: "VMware vCenter Server",
      event_type: "auth_success",
      hostname: vcenter.host,
      user_email: "administrator@vsphere.local",
      src_ip: tunnelIp,
      severity: "critical",
      mitre_technique: "T1078.001",
      mitre_tactic: "Privilege Escalation", // aligned with the killchain phase for this step; T1078.001 is valid under Privilege Escalation
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
      source: "virtualization",
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

    // ── 5b. The account that was just granted the role signs in ─────────────────
    {
      id: "evt_05b_svc_monitor_login",
      ts: T(25 * MIN),
      source: "virtualization",
      vendor: "VMware vCenter Server",
      event_type: "auth_success",
      hostname: vcenter.host,
      user_email: "svc-monitor@vsphere.local",
      src_ip: tunnelIp,
      severity: "high",
      description:
        "vCenter recorded a UserLoginSessionEvent for VSPHERE.LOCAL\\svc-monitor from 10.99.8.44 via the vim-java client, session 8d03b7a2-1f46-4e59-b3a8-c52e19f7d640.",
      raw: {
        "vsphere.event.key": "4418995",
        "vsphere.event.chainId": "4418995",
        "vsphere.event.createdTime": "2026-06-13T22:05:00.518Z",
        "vsphere.event.eventTypeId": "UserLoginSessionEvent",
        "vsphere.event.severity": "info",
        "vsphere.event.userName": "VSPHERE.LOCAL\\svc-monitor",
        "vsphere.event.ipAddress": tunnelIp,
        "vsphere.event.userAgent": "VMware vim-java 1.0",
        "vsphere.event.locale": "en",
        "vsphere.event.sessionId": "8d03b7a2-1f46-4e59-b3a8-c52e19f7d640",
        "vsphere.event.fullFormattedMessage":
          "User VSPHERE.LOCAL\\svc-monitor@10.99.8.44 logged in as VMware vim-java 1.0",
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
      source: "virtualization",
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
        "vsphere.event.datacenter.name": "NEXACORP-DC",
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
          "2026-06-13T22:09:03.771Z esx-prod-03.nexacorp.local vobd[2098431]: [GenericCorrelator] [esx.audit.ssh.enabled] SSH access has been enabled.",
      },
    },

    // ── 7. Impair defenses — host firewall opened for sshServer ───────────────
    {
      id: "evt_07_fw_changed",
      ts: T(31 * MIN),
      source: "virtualization",
      vendor: "VMware ESXi",
      event_type: "policy_modification",
      hostname: esxi.host,
      user_email: "svc-monitor@vsphere.local",
      severity: "critical",
      mitre_technique: "T1686",
      mitre_tactic: "Defense Impairment",
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
          "2026-06-13T22:11:38.204Z esx-prod-03.nexacorp.local vobd[2098431]: [GenericCorrelator] [esx.audit.net.firewall.config.changed] Firewall configuration has changed. Operation 'set' for rule set sshServer succeeded.",
      },
    },

    // ── 8. The root password is reset so the shell can actually be entered ────
    {
      id: "evt_08_root_pw",
      ts: T(34 * MIN),
      source: "virtualization",
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
          "Password was changed for account root on host esx-prod-03.nexacorp.local.",
        "esxi.account.name": "root",
        "esxi.account.id": "0",
        "esxi.account.initiator": "vpxuser",
        "log.file.path": "/var/log/vobd.log",
        "syslog.hostname": esxi.host,
        "syslog.program": "vobd",
        "syslog.pid": "2098431",
        "event.original":
          "2026-06-13T22:14:07.660Z esx-prod-03.nexacorp.local vobd[2098431]: [GenericCorrelator] [esx.audit.account.password.updated] Password was changed for account root on host esx-prod-03.nexacorp.local.",
      },
    },

    fgSshHop("evt_08a_fw_ssh_03", T(37 * MIN + 2_000), "esx-prod-03", esxi.ip, "51022", "884301966", 37 * MIN + 2_000),

    // ── 9. Interactive shell on the hypervisor ────────────────────────────────
    {
      id: "evt_09_ssh_session",
      ts: T(37 * MIN + 4_000),
      source: "virtualization",
      vendor: "VMware ESXi",
      event_type: "ssh_login",
      hostname: esxi.host,
      user_email: "root@esx-prod-03.nexacorp.local",
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
          "2026-06-13T22:17:04Z esx-prod-03.nexacorp.local sshd[2098700]: Accepted keyboard-interactive/pam for root from 10.99.8.44 port 51022 ssh2",
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

    fgSshHop("evt_09a_fw_ssh_04", T(38 * MIN + 10_000), "esx-prod-04", "10.20.5.34", "51047", "884302418", 38 * MIN + 10_000),
    esxSshSession("evt_09b_ssh_session_04", T(38 * MIN + 12_000), esxHost4, "2098812", "51047", "2026-06-13T22:18:12Z"),
    fgSshHop("evt_09c_fw_ssh_05", T(39 * MIN + 28_000), "esx-prod-05", "10.20.5.35", "51063", "884302905", 39 * MIN + 28_000),
    esxSshSession("evt_09d_ssh_session_05", T(39 * MIN + 30_000), esxHost5, "2098844", "51063", "2026-06-13T22:19:30Z"),

    // ── 10. Service Stop — VMs forced off so the disk files unlock ────────────
    {
      id: "evt_10_vim_cmd_poweroff",
      ts: T(41 * MIN),
      source: "virtualization",
      vendor: "VMware ESXi",
      event_type: "privileged_operation",
      hostname: esxi.host,
      user_email: "root@esx-prod-03.nexacorp.local",
      src_ip: tunnelIp,
      severity: "critical",
      mitre_technique: "T1489",
      mitre_tactic: "Impact",
      description:
        "The root shell on esx-prod-03 ran a loop over `vim-cmd vmsvc/getallvms` calling power.off on each entry, stopping the 32 VMs registered on that host. The same loop ran on esx-prod-04 (31 VMs) and esx-prod-05 (33 VMs): 96 VMs on PROD-CLUSTER-A in all, between 22:21 and 22:26.",
      raw: {
        "syslog.hostname": esxi.host,
        "syslog.program": "shell",
        "syslog.pid": "2098754",
        "log.file.path": "/var/log/shell.log",
        "syslog.message":
          "[root]: for v in $(vim-cmd vmsvc/getallvms | awk 'NR>1{print $1}'); do vim-cmd vmsvc/power.off $v; done",
        "event.original":
          "2026-06-13T22:21:11Z esx-prod-03.nexacorp.local shell[2098754]: [root]: for v in $(vim-cmd vmsvc/getallvms | awk 'NR>1{print $1}'); do vim-cmd vmsvc/power.off $v; done",
        "user.name": "root",
        "process.working_directory": "/tmp",
      },
    },

    shellPoweroff("evt_10a_vim_cmd_poweroff_04", T(41 * MIN + 34_000), esxHost4, "2098871", "2026-06-13T22:21:34Z"),
    shellPoweroff("evt_10b_vim_cmd_poweroff_05", T(41 * MIN + 58_000), esxHost5, "2098903", "2026-06-13T22:21:58Z"),

    // ── 11. The same power-offs as vCenter records them ───────────────────────
    {
      id: "evt_11_vm_poweroff",
      ts: T(42 * MIN),
      source: "virtualization",
      vendor: "VMware vCenter Server",
      event_type: "privileged_operation",
      hostname: vcenter.host,
      severity: "critical",
      mitre_technique: "T1489",
      mitre_tactic: "Impact",
      description:
        "vCenter recorded a VmPoweredOffEvent for each of the 96 guests; the record for SQL-PROD-02 on esx-prod-03 is shown, with an empty userName field; one record for each of the other two hosts follows it.",
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
        "vsphere.event.datacenter.name": "NEXACORP-DC",
        "vsphere.event.fullFormattedMessage":
          "SQL-PROD-02 on esx-prod-03.nexacorp.local in NEXACORP-DC is powered off",
        "log.file.path": "/var/log/vmware/vpxd/vpxd.log",
        "syslog.hostname": vcenter.host,
        "syslog.program": "vpxd",
        "syslog.pid": "10442",
      },
    },

    vmPoweredOff("evt_11a_vm_poweroff_04", T(42 * MIN + 41_000), "4419348", "2026-06-13T22:22:41.206Z", "APP-PROD-05", "vm-2077", esxHost4),
    vmPoweredOff("evt_11b_vm_poweroff_05", T(43 * MIN + 20_000), "4419377", "2026-06-13T22:23:20.771Z", "FS-PROD-03", "vm-2112", esxHost5),

    // ── 12. THE BLIND SPOT — the only thing endpoint tooling ever noticed ─────
    {
      id: "evt_12_edr_silence",
      ts: T(47 * MIN),
      source: "edr",
      vendor: "CrowdStrike Falcon",
      event_type: "edr_alert",
      hostname: "SQL-PROD-02",
      severity: "high",
      is_detection: true,    // the ONE endpoint-side signal the SOC ever received — must surface under the "Detections only" filter
      edr_scope: "non_edr",  // ESXi ransomware — the host impact is on the hypervisor (vCenter/ESXi shell), not a Windows/Linux EDR process tree, so there's no walkable EDR case on this platform; investigated in vCenter/SIEM
      description:
        "Falcon stopped receiving check-ins from 71 server sensors between 22:22 and 22:27, all of them guests on PROD-CLUSTER-A; the record for SQL-PROD-02 is shown, host status offline.",
      raw: {
        "crowdstrike.event_simpleName": "AgentOffline",
        "crowdstrike.host.hostname": "SQL-PROD-02",
        "crowdstrike.host.id": "b41d9c77e2a54f0e8c1a6d3f9b207e55",
        "crowdstrike.host.platform.name": "Windows",
        "crowdstrike.host.os.version": "Windows Server 2022",
        "crowdstrike.host.product_type_desc": "Server",
        "crowdstrike.host.local_ip": "10.30.12.61",
        "crowdstrike.host.last_seen": "2026-06-13T22:22:12Z",
        "crowdstrike.host.status": "offline",
        "crowdstrike.host.reduced_functionality_mode": "no",
        "crowdstrike.host.agent.version": "7.18.18604.0",
        "crowdstrike.NetworkContainmentState": "Not Contained",
        "event.action": "agent_offline",
        "host.name": "SQL-PROD-02",
      },
    },

    // ── 12b. The encryptor and the note are brought onto the host ───────────────
    {
      id: "evt_12b_mkdir",
      ts: T(47 * MIN + 48_000),
      source: "virtualization",
      vendor: "VMware ESXi",
      event_type: "privileged_operation",
      hostname: esxi.host,
      user_email: "root@esx-prod-03.nexacorp.local",
      src_ip: tunnelIp,
      severity: "high",
      description: "The root shell on esx-prod-03 created the directory /tmp/.x.",
      raw: {
        "syslog.hostname": esxi.host,
        "syslog.program": "shell",
        "syslog.pid": "2098754",
        "log.file.path": "/var/log/shell.log",
        "syslog.message": "[root]: mkdir -p /tmp/.x",
        "event.original":
          "2026-06-13T22:27:48Z esx-prod-03.nexacorp.local shell[2098754]: [root]: mkdir -p /tmp/.x",
        "user.name": "root",
        "process.working_directory": "/tmp",
      },
    },
    esxSshSession("evt_12c_ssh_session_scp", T(48 * MIN + 9_000), esxi, "2098921", "51240", "2026-06-13T22:28:09Z"),
    {
      id: "evt_12d_scp_receive",
      ts: T(48 * MIN + 10_000),
      source: "virtualization",
      vendor: "VMware ESXi",
      event_type: "file_create",
      hostname: esxi.host,
      user_email: "root@esx-prod-03.nexacorp.local",
      src_ip: tunnelIp,
      severity: "high",
      description: "A second SSH session from 10.99.8.44 ran scp -t /tmp/.x/ on esx-prod-03, the receiving end of an scp upload into /tmp/.x.",
      raw: {
        "syslog.hostname": esxi.host,
        "syslog.program": "shell",
        "syslog.pid": "2098925",
        "log.file.path": "/var/log/shell.log",
        "syslog.message": "[root]: scp -t /tmp/.x/",
        "event.original":
          "2026-06-13T22:28:10Z esx-prod-03.nexacorp.local shell[2098925]: [root]: scp -t /tmp/.x/",
        "user.name": "root",
        "source.ip": tunnelIp,
        "process.working_directory": "/tmp",
      },
    },

    // ── 13. Impact — the ELF encryptor against the datastore ──────────────────
    {
      id: "evt_13_encryptor",
      ts: T(52 * MIN),
      source: "virtualization",
      vendor: "VMware ESXi",
      event_type: "privileged_operation",
      hostname: esxi.host,
      user_email: "root@esx-prod-03.nexacorp.local",
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
          "2026-06-13T22:32:26Z esx-prod-03.nexacorp.local shell[2098754]: [root]: chmod +x /tmp/.x/encryptor; /tmp/.x/encryptor -p /vmfs/volumes/DS-PROD-01 -n 20 -t 32",
        "user.name": "root",
        "process.working_directory": "/tmp/.x",
      },
    },

    // ── 14. Ransom note ───────────────────────────────────────────────────────
    {
      id: "evt_14_ransom_note",
      ts: T(56 * MIN),
      source: "virtualization",
      vendor: "VMware ESXi",
      event_type: "file_create",
      hostname: esxi.host,
      user_email: "root@esx-prod-03.nexacorp.local",
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
          "2026-06-13T22:36:48Z esx-prod-03.nexacorp.local shell[2098754]: [root]: for d in /vmfs/volumes/DS-PROD-01/*/; do cp /tmp/.x/akira_readme.txt \"$d\"; done",
        "user.name": "root",
        "process.working_directory": "/tmp/.x",
      },
    },
  ];

  // Every event — identity-plane SSO abuse and host-plane ESXi impact alike —
  // belongs to the one ESXi-ransomware incident (the SIEM↔EDR correlation key).
  for (const e of events) e.incident_id = INCIDENT;

  return { title: "Every guest on PROD-CLUSTER-A unreachable on Saturday night", events, T, MIN, attackerIp, tunnelIp, vcenter, esxi, elfHash };
}
