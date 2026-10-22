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

import type { ScenarioBundle, IOC, ScenarioQuestion } from "@/lib/sim/types";
import { esxiRansomwareScenarioEvents } from "./esxiRansomware.events";

export function buildEsxiRansomwareScenario(
  scenarioId = "esxi-ransomware-2026",
): ScenarioBundle {
  const { title, events, T, MIN, attackerIp, tunnelIp, vcenter, esxi, elfHash } = esxiRansomwareScenarioEvents();

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
      first_seen: T(48 * MIN + 10_000),
      last_seen: T(52 * MIN),
      reputation: "malicious",
      tags: ["elf", "encryptor"],
    },
    {
      type: "user",
      value: "r.okonkwo@nexacorp.com",
      first_seen: T(0),
      last_seen: T(0),
      reputation: "suspicious",
      tags: ["contractor", "vpn"],
    },
    {
      type: "user",
      value: "administrator@vsphere.local",
      first_seen: T(21 * MIN),
      last_seen: T(24 * MIN),
      reputation: "suspicious",
      tags: ["sso", "built-in-account"],
    },
    {
      type: "user",
      value: "svc-monitor@vsphere.local",
      first_seen: T(24 * MIN),
      last_seen: T(34 * MIN),
      reputation: "malicious",
      tags: ["sso", "role-granted-during-window"],
    },
    {
      type: "host",
      value: vcenter.host,
      first_seen: T(14 * MIN),
      last_seen: T(43 * MIN + 20_000),
      reputation: "unknown",
      tags: ["management-plane"],
    },
    {
      type: "host",
      value: esxi.host,
      first_seen: T(29 * MIN),
      last_seen: T(56 * MIN),
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
        "Password spray against 14 vCenter SSO principals: 61 rejections in nine minutes, no lockouts triggered",
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
      ts: T(25 * MIN),
      phase: "Persistence",
      action:
        "svc-monitor signs in to vCenter from the tunnel address with the role it was just granted",
    },
    {
      ts: T(29 * MIN),
      phase: "Lateral Movement",
      action:
        "TSM-SSH enabled on three production ESXi hosts via vCenter (esx.audit.ssh.enabled)",
    },
    {
      ts: T(31 * MIN),
      phase: "Defense Impairment",
      action:
        "ESXi host firewall sshServer ruleset opened to all source addresses",
    },
    {
      ts: T(37 * MIN),
      phase: "Lateral Movement",
      action:
        "Interactive root SSH session opened on esx-prod-03 from the VPN tunnel address; the firewall logs the session first, and root sessions follow on esx-prod-04 and esx-prod-05",
    },
    {
      ts: T(41 * MIN),
      phase: "Impact — Service Stop",
      action:
        "vim-cmd vmsvc/power.off loop, run in the root shell of each host, stops all 96 VMs (32 + 31 + 33), releasing the locks on their -flat.vmdk files",
    },
    {
      ts: T(48 * MIN + 10_000),
      phase: "Command and Control",
      action:
        "A second SSH session runs scp -t /tmp/.x/ on esx-prod-03: the encryptor and the note are uploaded from the tunnel address",
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
            "The SSO password spray at 21:54, and the Administrator role granted to svc-monitor ten minutes later at 22:04",
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
            "The burst of vCenter SSO BadUsernameSessionEvent rejections, all from one source address, at 21:54",
        },
        {
          value: "heartbeat_loss",
          label:
            "The loss of 71 Falcon sensor heartbeats inside a five-minute window starting at 22:22, across the guest estate",
        },
      ],
      answer: "ssh_enabled",
      xp: 100,
      explanation:
        "Fidelity and earliness are different things, and the best rule maximises both. The VPN login is the earliest event but a contractor logging in from abroad at the weekend is ordinary, on its own it is close to noise. The SSO rejections are stronger and worth alerting on, but expired service accounts and stale scripts generate the same pattern in every vSphere estate, so it is a triage lead rather than a decision. esx.audit.ssh.enabled is different in kind: ESXi ships with SSH off, it is enabled only deliberately, the event names the host and the vSphere principal, and it can be joined against the change calendar automatically, an enable with no change record is very close to a certainty. It also sits twelve minutes ahead of the first power-off (22:09 against 22:21), which is enough time to act. The 22:01 Administrator login from a VPN-pool address and the 22:04 role grant are strong signals too, but each needs an expected-administrator source list to judge, whereas the SSH enable can be tested against the change calendar alone. The heartbeat loss is the highest-confidence signal of all, but it arrives after the VMs are already down; it reports the incident rather than preventing it.",
    },
    {
      id: "q4",
      prompt:
        "Enabling SSH and resetting root's password were done through vCenter as svc-monitor; the VM power-offs ran in a root shell on each host. What in this timeline permitted each of them?",
      kind: "single",
      options: [
        {
          value: "role_then_root",
          label:
            "The Administrator role granted at 22:04 permitted the vCenter-side changes; the power-offs needed only the root shell opened after the root password was reset",
        },
        {
          value: "role_all",
          label:
            "The Administrator role granted at 22:04 permitted all of them, because vim-cmd run in a root shell is checked against the vCenter role of the SSH source",
        },
        {
          value: "firewall_rule",
          label:
            "The sshServer firewall change permitted all of them, because opening the SSH ruleset to every address also grants the right to act on the hosts",
        },
        {
          value: "vpn_group",
          label:
            "Membership of the VPN-Contractors group permitted all of them, because the FortiGate policy for that group also carries vSphere privileges",
        },
      ],
      answer: "role_then_root",
      xp: 100,
      explanation:
        "vSphere authorises vCenter operations by role, and the PermissionAddedEvent at 22:04 is where svc-monitor acquires Administrator on the root folder with propagation, which is what authorises the SSH enable (22:09), the firewall change (22:11) and the root password reset (22:14), all recorded with the VSPHERE.LOCAL\\svc-monitor user name. The power-offs are a different matter: they run as vim-cmd inside a root shell on each host (shell.log, user root), and the vCenter VmPoweredOffEvent records carry an empty userName, so no vSphere role was consulted. What permitted them is the local root account, which the attacker could use only because vCenter had already enabled SSH, opened the firewall and reset root's password. The firewall change decides whether packets arrive, not who may act. And the FortiGate has no view of vSphere privileges at all; the VPN group only gets the attacker onto the network.",
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
            "T1529 System Shutdown/Reboot — the outage itself was the objective and encryption was added opportunistically",
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
    title,
    threat_actor: "Akira ransomware affiliate (ESXi-focused)",
    attack_kind: "ransomware_hypervisor",
    briefing: "The NOC escalated at 22:30: every guest on PROD-CLUSTER-A is unreachable and monitoring shows 71 server sensors offline. The vCenter appliance for that cluster is still responding. Saturday night, with no change window open.",
    narrative:
      "At 21:40 on a Saturday, a contractor's SSL-VPN credential was used from Sofia. The VPN-Contractors group had never been moved onto FortiToken, so a password was all it took. Within six minutes the tunnel address was sweeping the management VLAN; within fifteen it was spraying vCenter SSO. The account that answered was administrator@vsphere.local — the built-in SSO account that owns the entire inventory. From there the attacker granted a second principal the Administrator role, enabled SSH on three production hosts, opened the ESXi firewall, reset root's password and dropped into a shell on the hypervisor. All 96 VMs on PROD-CLUSTER-A were forced off to release the locks on their virtual disks, and an ELF encryptor was pointed at /vmfs/volumes/DS-PROD-01. Not one of these steps produced an EDR detection, because ESXi cannot run an EDR sensor: the only endpoint-side signal the SOC ever received was 71 Falcon agents going quiet at once. Your job is to reconstruct the chain from vCenter and syslog evidence alone, prove which privileges made each step possible, and identify the point where a single detection rule would have stopped it.",
    learning_objectives: [
      "Trace a hypervisor ransomware chain from VPN initial access through vCenter to an ESXi root shell using only vCenter events and syslog",
      "Explain why endpoint EDR produces no ransomware detection when the encryptor executes on the hypervisor, and reason from missing telemetry",
      "Identify the earliest high-fidelity detection opportunity in a vSphere intrusion and justify it against earlier but noisier signals",
      "Separate what a vSphere role authorised (the SSH enable, the firewall change and the root password reset, all recorded with a vSphere user) from what the local root account on each host did without a vSphere user (the power-offs and the encryption)",
      "Recognise mass VM power-off as T1489 Service Stop and distinguish it from T1490 and T1486",
    ],
    alerts: [], // alerts are attached by the catalogue wiring
    events,
    iocs,
    killchain,
    questions,
  };
}
