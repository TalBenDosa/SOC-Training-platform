/**
 * Learning Rooms — Batch 39
 *
 * Closes an F-09 external-audit gap: the platform's expert-tier
 * esxi-ransomware scenario requires vSphere/ESXi-specific knowledge (the
 * permission model, vpxd.log/vobd.log, esx.audit.* events, datastore
 * encryption mechanics, and why no EDR runs on the hypervisor) that no
 * dedicated room taught. rooms-batch-23.ts (security-products-behaviour)
 * carries a short bridging reading on the same topic; this room is the full
 * theory room that bridging reading pointed toward, going deeper into the
 * permission model, the two distinct host/management log sources, and the
 * mechanical reason a ransomware operator must power off VMs before
 * encrypting a datastore.
 *
 * Rooms in this batch:
 *  1. esxi-virtualization-security
 */

import type { TelemetryEvent } from "@/lib/sim/types";

// ===========================================================================
// ROOM — ESXi & Virtualization Security
// ===========================================================================

const permissionGrantEvent: TelemetryEvent = {
  id: "evt-esxf-la1-001",
  ts: "2026-07-19T23:41:08.000Z",
  source: "iam",
  vendor: "VMware vCenter Server",
  event_type: "role_assignment",
  severity: "critical",
  mitre_technique: "T1098",
  mitre_tactic: "Persistence",
  hostname: "vcsa-04.medcorehealth.org",
  user_email: "administrator@vsphere.local",
  src_ip: "10.60.9.14",
  description:
    "A PermissionAddedEvent granted a role to a second principal on the root Datacenters folder with propagation enabled, issued by the built-in SSO Administrator account.",
  raw: {
    "vsphere.event.key": "5502117",
    "vsphere.event.chainId": "5502117",
    "vsphere.event.createdTime": "2026-07-19T23:41:08.302Z",
    "vsphere.event.eventTypeId": "PermissionAddedEvent",
    "vsphere.event.severity": "info",
    "vsphere.event.userName": "VSPHERE.LOCAL\\Administrator",
    "vsphere.event.ipAddress": "10.60.9.14",
    "vsphere.event.entity.name": "Datacenters",
    "vsphere.event.entity.type": "Folder",
    "vsphere.event.entity.moref": "group-d1",
    "vsphere.event.permission.principal": "VSPHERE.LOCAL\\svc-backup",
    "vsphere.event.permission.group": "false",
    "vsphere.event.permission.propagate": "true",
    "vsphere.event.permission.roleId": "-1",
    "vsphere.event.permission.roleName": "Administrator",
    "vsphere.event.fullFormattedMessage":
      "Permission created for VSPHERE.LOCAL\\svc-backup on Datacenters, role Administrator, propagating",
    "log.file.path": "/var/log/vmware/vpxd/vpxd.log",
    "syslog.hostname": "vcsa-04.medcorehealth.org",
    "syslog.program": "vpxd",
    "syslog.pid": "8871",
  },
};

const sshEnabledEvent: TelemetryEvent = {
  id: "evt-esxf-la2-001",
  ts: "2026-07-19T23:44:52.000Z",
  source: "linux_audit",
  vendor: "VMware ESXi",
  event_type: "policy_modification",
  severity: "critical",
  mitre_technique: "T1021.004",
  mitre_tactic: "Lateral Movement",
  hostname: "esx-prod-07.medcorehealth.org",
  user_email: "svc-backup@vsphere.local",
  src_ip: "10.60.9.14",
  description:
    "TSM-SSH was started on esx-prod-07 and its startup policy was set to 'on'; the SIEM attributes the change to svc-backup, and no change record exists for a maintenance window at this time.",
  raw: {
    "vsphere.event.eventTypeId": "esx.audit.ssh.enabled",
    "vsphere.event.severity": "info",
    "vsphere.event.createdTime": "2026-07-19T23:44:52.611Z",
    "vsphere.event.host.name": "esx-prod-07.medcorehealth.org",
    "vsphere.event.host.moref": "host-2091",
    "vsphere.event.computeResource.name": "PROD-CLUSTER-B",
    "vsphere.event.datacenter.name": "MEDCORE-DC",
    "vsphere.event.fullFormattedMessage": "SSH access has been enabled.",
    "esxi.service.key": "TSM-SSH",
    "esxi.service.label": "SSH",
    "esxi.service.running": "true",
    "esxi.service.policy": "on",
    "log.file.path": "/var/log/vobd.log",
    "syslog.hostname": "esx-prod-07.medcorehealth.org",
    "syslog.program": "vobd",
    "syslog.pid": "3310217",
    "event.original":
      "2026-07-19T23:44:52.611Z esx-prod-07.medcorehealth.org vobd[3310217]: [GenericCorrelator] [esx.audit.ssh.enabled] SSH access has been enabled.",
  },
};

const benignMaintenanceSshEvent: TelemetryEvent = {
  id: "evt-esxf-ac1-001",
  ts: "2026-07-11T02:10:00.000Z",
  source: "linux_audit",
  vendor: "VMware ESXi",
  event_type: "policy_modification",
  severity: "informational",
  hostname: "esx-prod-02.medcorehealth.org",
  user_email: "j.marchetti@medcorehealth.org",
  it_verify_result: "confirmed",
  it_verify_message:
    "Change ticket CHG-77410 authorises the virtualization team's quarterly firmware-update maintenance window on PROD-CLUSTER-A this weekend, including temporary SSH enablement on each host for the update script.",
  description:
    "TSM-SSH was started on esx-prod-02 by j.marchetti during the scheduled maintenance window, and disabled again forty minutes later at the end of the update run.",
  raw: {
    "vsphere.event.eventTypeId": "esx.audit.ssh.enabled",
    "vsphere.event.severity": "info",
    "vsphere.event.createdTime": "2026-07-11T02:10:00.000Z",
    "vsphere.event.host.name": "esx-prod-02.medcorehealth.org",
    "vsphere.event.host.moref": "host-2033",
    "vsphere.event.computeResource.name": "PROD-CLUSTER-A",
    "vsphere.event.datacenter.name": "MEDCORE-DC",
    "vsphere.event.fullFormattedMessage": "SSH access has been enabled.",
    "esxi.service.key": "TSM-SSH",
    "esxi.service.label": "SSH",
    "esxi.service.running": "true",
    "esxi.service.policy": "on",
    "log.file.path": "/var/log/vobd.log",
    "syslog.hostname": "esx-prod-02.medcorehealth.org",
    "syslog.program": "vobd",
    "syslog.pid": "2207741",
  },
};

const esxiVirtualizationSecurityRoom = {
  id: "esxi-virtualization-security",
  title: "ESXi & Virtualization Security",
  description:
    "What no other room covers: the vSphere permission model (roles, propagation, and the PermissionAddedEvent that proves when a grant actually happened), the two distinct hypervisor log sources (vCenter's vpxd.log and each ESXi host's own vobd.log and shell.log), the mechanical reason a running VM must be powered off before its datastore can be encrypted, and the single fact that shapes every hypervisor investigation: no supported EDR agent runs on ESXi itself, so detection has to come from these native audit trails instead.",
  difficulty: "advanced" as const,
  category: "Cloud Security",
  estimatedMinutes: 65,
  xp: 385,
  icon: "🖥️",
  prerequisites: ["security-products-behaviour", "linux-fundamentals"],
  tasks: [
    // ── Reading 1: hypervisor stack ────────────────────────────────────────
    {
      type: "reading" as const,
      id: "esxf-r1",
      heading: "Why the Hypervisor Is a Different Universe: Hosts, VMs, and the vSphere Stack",
      content:
        "Every room this platform has taught so far assumes an investigation happens on an operating system running directly on hardware, or inside a single virtual machine that behaves, from the inside, just like any other endpoint. This room is about the layer underneath all of that: the layer most analysts never investigate until the day they have no choice.\n\n" +
        "**What a hypervisor is.** A hypervisor is software that lets one physical server run several independent operating systems (virtual machines, or VMs) at once, each believing it has its own dedicated hardware. A Type 1 (bare-metal) hypervisor runs directly on the physical hardware with no general-purpose host operating system underneath it at all. This is the category VMware's ESXi belongs to. A Type 2 hypervisor, by contrast, runs as an application on top of an existing OS (the kind of virtualization a developer runs on their own laptop): a fundamentally different, much lower-stakes deployment than what this room covers.\n\n" +
        "**ESXi: the host.** ESXi is VMware's Type 1 hypervisor: a minimal, purpose-built operating system whose entire job is running and isolating VMs efficiently and securely, with no general-purpose desktop environment, package manager, or third-party software ecosystem the way Windows or a general Linux distribution has. Each physical server running ESXi is called a host.\n\n" +
        "**vCenter Server: the management plane.** A real organisation running dozens or hundreds of ESXi hosts does not manage them one at a time. vCenter Server is VMware's centralised management application (typically itself running as a virtual appliance (the vCenter Server Appliance, or VCSA)) providing one console, one authentication layer, and one place to define policy across an entire fleet of hosts organised into datacenters and clusters. Nearly every meaningful administrative action in a real vSphere environment happens through vCenter, not by logging into an individual host directly.\n\n" +
        "**VMFS and the datastore.** The Virtual Machine File System (VMFS) is VMware's clustered filesystem for the storage that holds VM disk files. A datastore is a storage volume formatted with VMFS, shared across every host in a cluster so that a VM can be moved between hosts without moving its underlying disk files. Each VM's actual disk contents live in files with a -flat.vmdk extension sitting on that shared datastore: a detail this room returns to directly when covering why an attacker must power off a VM before encrypting its disk.\n\n" +
        "**Guest vs host: the separation that defines this whole room.** A guest VM is a complete, independent operating system (Windows Server, a Linux distribution, whatever the organisation runs) with its own users, its own processes, and its own security agents, entirely unaware of the physical host underneath it except through the narrow, virtualized hardware interfaces the hypervisor presents to it. The host (ESXi itself) is a separate, distinct operating system with its own separate set of users, processes, and logs, invisible to anything running inside any of its guests. This separation is not a minor technical detail. It is the entire reason the next reading exists.",
      diagram:
        "flowchart TB\n" +
        "  VC[vCenter Server -- the management plane\\none console, one auth layer, fleet-wide policy] --> H1[ESXi Host 1]\n" +
        "  VC --> H2[ESXi Host 2]\n" +
        "  VC --> H3[ESXi Host 3]\n" +
        "  H1 --> G1[Guest VM: Windows Server]\n" +
        "  H1 --> G2[Guest VM: Linux]\n" +
        "  H1 --> DS[(Shared VMFS Datastore\\n-flat.vmdk files)]\n" +
        "  H2 --> DS\n" +
        "  H3 --> DS\n",
      diagramCaption: "vCenter manages the fleet; every host in a cluster shares the same underlying datastore",
      checkpoint: {
        question: "An administrator changes the same setting on 40 ESXi hosts from one console, in one action. Which component did they most likely use, and how does it relate to those hosts?",
        options: [
          "The DCUI console of one host, which pushes the setting to the other cluster members through their shared VMFS datastore",
          "vCenter Server, the management plane -- usually its own virtual appliance -- that administers the whole fleet of separate hosts",
          "vCenter Server, which is the name of the hypervisor itself as installed on each of those 40 physical hosts",
          "A Type 2 hypervisor console on the admin's workstation, which manages the bare-metal hosts as if they were local VMs",
        ],
        answer: 1,
        explanation:
          "vCenter is the fleet-wide management layer sitting above individual ESXi hosts -- one console, one auth layer, centralised policy -- which is exactly why almost every real administrative action in a vSphere environment is recorded at the vCenter level, not host by host. The DCUI is a single host's local console, and a VMFS datastore holds VM disk files, not a channel for pushing host configuration. vCenter is not another name for the hypervisor: ESXi is the hypervisor on each host, and vCenter is a separate application managing them. A Type 2 hypervisor runs as an app on top of a desktop OS and has nothing to do with managing bare-metal ESXi hosts.",
      },
    },
    // ── Reading 2: no EDR on the hypervisor ──────────────────────────────────
    {
      type: "reading" as const,
      id: "esxf-r2",
      heading: "The Central Fact: No Supported EDR Runs on the Hypervisor",
      content:
        "This is the single most important fact in this entire room, and everything else here exists to compensate for it.\n\n" +
        "**Why, mechanically, no EDR agent exists for ESXi.** Endpoint detection and response products work by installing a sensor deep inside a general-purpose operating system, hooking process creation, file writes, and network activity through documented (or semi-documented) kernel and user-space interfaces that Windows, macOS, and general Linux distributions all expose for exactly this purpose. ESXi is not a general-purpose operating system. It is a minimal, purpose-built, closed platform with no supported mechanism for a third-party vendor to install a deep, kernel-level monitoring agent the way they can on a guest's operating system. VMware does not offer that surface, by design: the entire point of a hypervisor's minimalism is a smaller attack surface and a more predictable, supportable platform, and that same minimalism is exactly what leaves no room for a general-purpose security agent to attach to.\n\n" +
        "**Where EDR sensors DO run in a virtualized environment.** Every guest VM is, from its own perspective, a complete, ordinary operating system: an EDR sensor installed inside a Windows or Linux guest works exactly the way it would on physical hardware, because from that sensor's point of view, nothing about being virtualized is even visible. The sensor sees the guest's own processes, the guest's own files, the guest's own network stack. It has no visibility whatsoever into the hypervisor layer underneath it, the other guests sharing the same host, or the shared datastore they all sit on.\n\n" +
        "**The consequence.** An attacker who gains administrative access to vCenter or an ESXi host directly, and acts entirely at that layer (enabling a service, opening a shell, running a binary against the datastore) produces zero telemetry in any guest's EDR sensor, because none of that activity ever touches any guest's operating system at all. Every guest can be functioning completely normally, with its EDR sensor reporting a clean bill of health, while the datastore underneath every one of those guests is actively being encrypted.\n\n" +
        "**What actually surfaces the attack, and when.** The one signal that eventually reaches guest-level tooling is indirect and late: when a VM is forcibly powered off (a step covered later in this room as a mechanical requirement of the attack itself), that guest's EDR sensor simply stops checking in, an agent-offline event, not a ransomware detection of any kind. By the time that signal appears, the attack has already reached its final stage.\n\n" +
        "**Why this is not a gap to wait out.** There is no supported in-hypervisor EDR for ESXi today: a consequence of VMware's closed-platform policy rather than a technical impossibility, and log-based, agentless ESXi monitoring products do exist, so this room's job is not to wait for EDR vendors to solve it. The compensating strategy, covered in the readings that follow, is to treat vCenter's and ESXi's own native audit logs as the primary detection surface for this layer, the same way Sysmon or EDR telemetry is the primary detection surface for a Windows endpoint.",
    },
    // ── Question 1 ───────────────────────────────────────────────────────────
    {
      type: "question" as const,
      id: "esxf-q1",
      question:
        "Ninety-six guest VMs on an ESXi cluster were encrypted by ransomware that ran entirely on the hypervisor. Every guest's EDR sensor reported normally right up until the moment of impact, with no detection raised. What correctly explains this?",
      options: [
        "The attacker stopped each guest's EDR sensor service with stolen administrator credentials shortly before encryption, so no detection could fire during the impact itself",
        "No supported EDR runs on ESXi itself, and host-layer actions -- enabling a service, opening a shell, running a binary on the datastore -- never touch a guest OS",
        "The sensors were running in a passive detection-only mode that suppressed all alerting, so the activity was recorded in the console but never raised as a detection",
        "Guest EDR sensors normally extend visibility to the hypervisor through the VMware Tools channel, and that visibility failed in this case because of a driver bug",
      ],
      answer: 1,
      explanation:
        "Reading 2 was explicit: this is a visibility gap, not a bypass or a misconfiguration -- there is no supported EDR inside ESXi, and guest sensors see only their own guest. The sensors were never stopped: stopping them with stolen credentials would itself generate distinct sensor-offline or tamper events across 96 guests, which did not happen. Nor was it a detection-only mode hiding alerts: such a mode still records telemetry in the console, yet here there was no guest-side activity to record at all. And guest EDR sensors do not extend into the hypervisor layer through VMware Tools or any other channel, so there was no such visibility for a driver bug to break.",
      xp: 25,
    },
    // ── Reading 3: vSphere permission model ──────────────────────────────────
    {
      type: "reading" as const,
      id: "esxf-r3",
      heading: "vSphere's Authorization Model: Roles, Privileges, and Propagation",
      content:
        "Because vCenter is where nearly all meaningful administrative action happens, understanding exactly how it decides who is allowed to do what is essential before any vCenter log event can be read correctly.\n\n" +
        "**Privileges.** A privilege is the smallest unit of permission in vSphere: a specific, narrow capability like Host.Config.Settings (change a host's configuration) or VirtualMachine.Interact.PowerOff (stop a running VM). There are hundreds of individual privileges covering every meaningful action across the platform.\n\n" +
        "**Roles.** A role is a named bundle of privileges. vCenter ships several built-in roles: most importantly Administrator (roleId -1), which bundles essentially every privilege in the system, and administrators can define their own custom roles bundling a narrower, purpose-specific set of privileges (for example, a role for a backup operator that can browse VMs and take snapshots but cannot delete anything or reconfigure a host).\n\n" +
        "**Permissions: attaching a role to an identity, at an entity, with a scope.** A role by itself grants nothing. It has to be attached as a permission, which is the combination of a role, a principal (a user or group), and an entity (a specific object in the vCenter inventory: a single VM, a host, a cluster, a datacenter, or a folder). The permission also carries a propagate flag: when true, the permission cascades downward to every child object in the inventory hierarchy beneath the entity it was attached to. A permission granted at the very top of the inventory, the root Datacenters folder, with propagation enabled effectively hands that role's privileges over every single object in the entire vSphere environment, current and future.\n\n" +
        "**PermissionAddedEvent: the moment authorization actually happened.** Every time a permission is created, vCenter logs a PermissionAddedEvent naming the affected entity, the principal being granted access, the roleId and roleName, and the propagate flag. This is not a side detail. It is the single event in a vCenter-based investigation that pinpoints exactly when a given account first became capable of the privileged actions that followed. An account that later enables SSH on a host, or powers off a VM, was only ABLE to do either of those things because some earlier PermissionAddedEvent granted it a role carrying the corresponding privilege, and that earlier event is precisely what an investigation needs to find to establish how the actor got there.\n\n" +
        "**Why this matters more than the more visible steps that follow.** An analyst who focuses only on the visible, dramatic actions (SSH being turned on, a VM being stopped) without tracing back to the specific permission grant that authorised them, is investigating symptoms without finding the actual root cause: which account was empowered, over what scope, and by whom.",
      checkpoint: {
        question: "The Administrator role (roleId -1) is attached to a principal on the cluster PROD-CLUSTER-B -- not on the root folder -- with propagate set to true. What can that principal now administer?",
        options: [
          "Every object in the whole inventory, because the Administrator role carries its privileges globally wherever it is attached",
          "The cluster and every object beneath it, such as its hosts and their VMs, but nothing in other clusters or datacenters",
          "Only objects added to the cluster after the grant; hosts and VMs that were already there keep their earlier permissions",
          "Only the cluster object itself, since child objects inherit a permission only when it is granted on a folder",
        ],
        answer: 1,
        explanation:
          "A permission is a role attached at an entity, and propagate=true cascades it to every child beneath that entity -- current and future. Attached to a cluster, it therefore covers that cluster's hosts and VMs but nothing above or beside it. The role does not apply globally wherever it is attached: the entity sets the scope, which is why the same role at the root Datacenters folder is so much more dangerous. Propagation covers existing children as well as future ones, not only objects added later. And propagation works from any entity in the hierarchy, not only from folders.",
      },
    },
    // ── Reading 4: vpxd.log ──────────────────────────────────────────────────
    {
      type: "reading" as const,
      id: "esxf-r4",
      heading: "Reading vpxd.log and the vCenter Event Feed",
      content:
        "Every action taken through vCenter, by a human or by vCenter's own automated processes, is recorded as a structured event, and vpxd.log is where that record lives.\n\n" +
        "**What vpxd is.** vpxd is the core vCenter Server daemon: the process that actually implements the management logic administrators interact with through the web client or the API. Its own log file, conventionally at /var/log/vmware/vpxd/vpxd.log on the vCenter Server Appliance, is the vCenter-level equivalent of a Windows Security event log: the authoritative record of what vCenter itself did and observed.\n\n" +
        "**eventTypeId: vCenter's own taxonomy.** Every vCenter event carries an eventTypeId naming exactly what happened. UserLoginSessionEvent for a successful sign-in, BadUsernameSessionEvent for a failed one, PermissionAddedEvent for the authorization grants covered in the previous reading, VmPoweredOffEvent for a VM being stopped, and many more. As with the other event-taxonomy systems this platform teaches (Okta's eventType, for example), recognising the pattern (a specific, well-defined name per distinct action) lets an analyst reason about an unfamiliar eventTypeId value from context, without needing to have memorised every one in advance.\n\n" +
        "**fullFormattedMessage: the human-readable summary.** Alongside the structured eventTypeId, every event carries a plain-English fullFormattedMessage, for example, 'User VSPHERE.LOCAL\\Administrator@10.60.9.14 logged in as VMware vim-java 1.0'. Useful for a quick read, though the structured fields are what a real detection rule should key on.\n\n" +
        "**chainId: linking related events.** Some events share a chainId, tying together records that stem from the same underlying operation or session, useful for reconstructing a sequence rather than reading isolated, disconnected log lines.\n\n" +
        "**What userName actually represents, and its occasional gap.** Most events carry the acting principal's full name (for example, VSPHERE.LOCAL\\Administrator), but some system-generated events: a VM power-off triggered by an automated process rather than a specific interactive session, for instance. Can show an empty userName field. An empty userName is not an error to dismiss; it means the immediate vCenter event itself doesn't attribute the action to an interactive user, which is exactly why tracing back to an earlier, correlated event (like the session or permission grant that authorised the underlying access in the first place) is often necessary to establish full attribution.",
    },
    // ── Reading 5: vobd.log / esx.audit ──────────────────────────────────────
    {
      type: "reading" as const,
      id: "esxf-r5",
      heading: "Reading vobd.log and esx.audit.* Events on the ESXi Host Itself",
      content:
        "vpxd.log records what vCenter, the management plane, observed. Each individual ESXi host also keeps its own separate, host-local record, and this is the log source that catches activity vCenter itself might never see directly.\n\n" +
        "**vobd: the VMkernel Observation Daemon.** vobd is a process running on each ESXi host that watches for and logs significant host-level events into its own log file, conventionally at /var/log/vobd.log on that specific host. This is a genuinely separate log source from vpxd.log. It lives on the host, not on the vCenter appliance, and it captures host-local activity regardless of whether that activity was ever reflected up into vCenter's own event feed.\n\n" +
        "**The esx.audit.* naming convention.** A large and important category of vobd-logged events uses a consistent esx.audit. prefix, naming a specific host-level security-relevant change: esx.audit.ssh.enabled records the SSH service being turned on, esx.audit.net.firewall.config.changed records a host firewall ruleset being modified, esx.audit.account.password.updated records a local account's password being changed. As with every other event-taxonomy system in this room, the naming pattern itself carries information: the esx.audit prefix specifically flags 'this is a security-relevant host configuration change,' distinct from vobd's other, more routine housekeeping entries.\n\n" +
        "**Why esx.audit.ssh.enabled specifically is such a high-confidence signal.** ESXi ships with SSH disabled by default, and VMware's own hardening guidance recommends leaving it disabled except during specific, deliberate maintenance activity. Because of that default-off posture, any occurrence of this event at all is a deviation from the host's normal running state: it is not a routine, frequently-occurring event the way a login attempt is. An esx.audit.ssh.enabled event with no corresponding, pre-approved change record is about as close to a certain finding as a single log line gets in this entire room.\n\n" +
        "**Why an analyst needs both vpxd.log and vobd.log, not just one.** vCenter's own event feed shows the administrative action that ultimately CAUSED SSH to be enabled (the permission grant, the login session that used it) but the actual esx.audit.ssh.enabled confirmation that the change genuinely took effect on that specific host lives in that host's own vobd.log. An investigation that only reads one of the two logs is missing either the authorization chain (vpxd.log) or the on-host confirmation and exact timing (vobd.log): both matter, and they are genuinely different files, often on genuinely different machines. Note what vobd.log does NOT give you: a change pushed through vCenter executes on the host as vCenter's own agent account, vpxuser, so the vobd entry names no vCenter SSO user. Attribution comes from matching the host and timestamp to the vCenter task that made the change (for SSH, the start of the TSM-SSH service) recorded in vpxd.log.",
    },
    // ── Log Analysis 1: PermissionAddedEvent ─────────────────────────────────
    {
      type: "log_analysis" as const,
      id: "esxf-la1",
      heading: "A Permission Grant at 23:41",
      context:
        "MedCore Health's SIEM raised an after-hours alert on vcsa-04.medcorehealth.org, the vCenter appliance managing PROD-CLUSTER-B. The event below is the first vCenter-side finding in the timeline.",
      event: permissionGrantEvent,
      questions: [
        {
          question:
            "vsphere.event.permission.roleId is -1 and vsphere.event.permission.propagate is 'true', attached to the entity 'Datacenters' (a Folder). What does this combination actually grant to VSPHERE.LOCAL\\svc-backup?",
          options: [
            "Full Administrator privileges over the Datacenters folder and every datacenter, cluster, host and VM beneath it -- effectively the whole environment",
            "Administrator privileges over the Datacenters folder and its direct child datacenters only, since propagation extends one level down the tree",
            "Administrator privileges only over objects created after the grant; hosts and VMs that already exist keep their earlier permissions",
            "Administrator privileges over the folder object only, because permission.group is false and propagation applies only to group principals",
          ],
          answer: 0,
          explanation:
            "Reading 3 covered this combination: roleId -1 is the built-in Administrator role bundling essentially every privilege, and propagate=true at the very top of the inventory (the Datacenters folder) cascades that full privilege set to everything beneath it -- effectively the entire environment, current and future. Propagation is not limited to one level: it reaches every descendant, down to individual hosts and VMs. It is not limited to newly created objects either; existing children inherit it too. And permission.group=false only says the principal is a single user rather than a group -- it has no bearing on whether the grant propagates.",
          xp: 25,
        },
        {
          question:
            "This event names two accounts: vsphere.event.userName is VSPHERE.LOCAL\\Administrator and vsphere.event.permission.principal is VSPHERE.LOCAL\\svc-backup. Which reading of these fields is correct?",
          options: [
            "Administrator issued the grant from a session at 10.60.9.14, and svc-backup is the account that received the new role",
            "svc-backup issued the grant to itself, and the Administrator value in userName is the role it requested for its own account",
            "Administrator received the new role, and svc-backup is the service account vCenter used to execute the change for it",
            "Both name one session: svc-backup signed in through the built-in Administrator SSO identity, so the actor is the same",
          ],
          answer: 0,
          explanation:
            "In a vCenter event, userName (with ipAddress) identifies the session that performed the action, while permission.principal names who the permission was granted to -- so Administrator, from 10.60.9.14, granted the role to svc-backup. The role appears separately in permission.roleName, so the Administrator in userName is the acting account, not a requested role, and svc-backup did not grant itself anything. The direction is not reversed either: the principal field is the recipient, not a service account executing on someone's behalf. And the two fields name two distinct identities; nothing in the event indicates svc-backup authenticated as Administrator -- which is exactly why the granting session needs its own investigation.",
          xp: 25,
        },
        {
          question:
            "Given that this permission grant is dated 23:41 with no visible business justification in this event, what is the correct immediate next investigative step?",
          options: [
            "Trace back to how the Administrator session at 10.60.9.14 was established, and forward to what svc-backup did next with its new rights",
            "Wait for a burst of VmPoweredOffEvent records before escalating, since a permission grant on its own is routine administrative activity",
            "Pull guest EDR telemetry from PROD-CLUSTER-B's VMs, since anything svc-backup does with the new role will surface there first",
            "Delete the new permission and close the alert, since reverting the grant removes the access and its origin no longer matters",
          ],
          answer: 0,
          explanation:
            "This is the root-cause tracing this room emphasises: establishing how the granting session came to exist, and what the newly-privileged account did next, is what reconstructs the incident. Waiting for a power-off burst is the right signal at the wrong time -- by then the VMs are already stopped, and a root-level Administrator grant at 23:41 is anything but routine. Guest EDR telemetry will not show what svc-backup does at the vCenter or host layer, as Reading 2 established. And deleting the permission without finding how the Administrator session was obtained leaves that access path open and loses sight of whatever svc-backup has already done.",
          xp: 30,
        },
      ],
    },
    // ── Question 2 ───────────────────────────────────────────────────────────
    {
      type: "question" as const,
      id: "esxf-q2",
      question:
        "An account with no prior special access is later observed enabling SSH on a production ESXi host and, minutes after that, powering off a VM. Both actions require specific vSphere privileges the account did not previously hold. What single earlier event should an investigation look for to explain how this became possible?",
      options: [
        "A PermissionAddedEvent granting the account a role with the needed privileges (such as Host.Config.Settings and VirtualMachine.Interact.PowerOff) earlier in the timeline",
        "A RoleAddedEvent creating a role with those privileges -- creating the role is what makes its privileges available to the account that later uses them",
        "An esx.audit.ssh.enabled event -- it is the first privileged action recorded and so marks the moment the account acquired host-configuration rights",
        "A UserLoginSessionEvent for the account -- vSphere establishes an account's effective privileges at first authentication, so the login source explains the access",
      ],
      answer: 0,
      explanation:
        "Reading 3 was explicit that a role has to be attached as a permission before it grants anything -- a PermissionAddedEvent is the specific, findable event that marks exactly when and how an account became capable of these actions. A RoleAddedEvent is not enough: creating a role grants nothing until it is attached to a principal through a permission. Privileges are not established at login either, so the UserLoginSessionEvent cannot explain the access. And esx.audit.ssh.enabled is a CONSEQUENCE of already having the needed privilege, not the event that granted it -- confusing an action with its authorisation is exactly the root-cause-vs-symptom trap Reading 3 warned about.",
      xp: 25,
    },
    // ── Log Analysis 2: esx.audit.ssh.enabled ────────────────────────────────
    {
      type: "log_analysis" as const,
      id: "esxf-la2",
      heading: "SSH, Off by Default, Suddenly On",
      context:
        "Three minutes after the permission grant investigated above, the following event appeared in esx-prod-07's own host log.",
      event: sshEnabledEvent,
      questions: [
        {
          question:
            "This event's log.file.path is /var/log/vobd.log, on the host esx-prod-07 itself -- a different file, on a different machine, from the vpxd.log event investigated earlier. Why does an analyst need to check this log SEPARATELY from vCenter's own event feed?",
          options: [
            "It is the host's own record that the change actually took effect there, with the on-host time -- a separate source from vCenter's management-plane record",
            "It is the host's local replica of vpxd.log, kept so events survive while vCenter is unreachable, so it mainly matters when vCenter is down",
            "It names the vCenter user who requested the change, which vpxd.log does not record for host service starts, so attribution depends on it",
            "It holds a copy of the PermissionAddedEvent pushed to each host, so the authorization chain and the change can be read in one file",
          ],
          answer: 0,
          explanation:
            "Reading 5 made this distinction directly: vpxd.log shows the vCenter-side authorization chain, while vobd.log on the specific host confirms that the change took effect there, with its own exact timestamp. It is not a replica of vpxd.log -- the two are different files written by different daemons on different machines. Attribution runs the other way round: the vobd entry names no vCenter user (the change ran on the host as vpxuser), and the requesting SSO user comes from the vCenter task in vpxd.log. And permission grants are vCenter objects recorded in vpxd.log only; they are not copied into each host's vobd.log.",
          xp: 25,
        },
        {
          question:
            "Given that ESXi ships with SSH disabled by default, why does esx.audit.ssh.enabled carry such high confidence as a detection signal on its own, even before checking who triggered it?",
          options: [
            "SSH is off by default and hardening keeps it off outside planned work, so any enablement is a departure from the host's normal state",
            "Administrators manage hosts through vCenter rather than SSH, so an enablement is itself evidence that an unauthorised party is involved",
            "It is logged when someone completes an SSH login, so it shows that an interactive shell is already open on the host",
            "ESXi raises it at critical severity, unlike routine vobd entries, so the host itself has already judged the change malicious",
          ],
          answer: 0,
          explanation:
            "Reading 5 covered this precisely: the default-off posture is what makes any occurrence a genuine deviation worth flagging, independent of attribution -- unlike a login attempt, which happens constantly and legitimately. It is not proof of an unauthorised party: virtualization teams do enable SSH during planned maintenance, which is exactly why the next task covers a benign case. The event records the service being enabled, not a login -- Reading 6 separates the two, and a shell session only starts when someone actually connects. And the raw vsphere.event.severity is 'info'; the 'critical' rating is the SIEM's own triage severity, not a verdict from ESXi.",
          xp: 25,
        },
        {
          question:
            "This vobd record names the host and the time but no vCenter user, yet the SIEM attributes it to svc-backup -- the account granted Administrator minutes earlier. Given that the change was pushed through vCenter, how is that attribution properly established?",
          options: [
            "Match esx-prod-07 and 23:44:52 to the vCenter task that started TSM-SSH, which records the SSO user behind the request",
            "Take the host-side account the change executed as, vpxuser, and treat that account as the actor to investigate",
            "Pull esx-prod-07's shell.log, which records each SSH service change together with the local account that issued it",
            "Map syslog.pid 3310217 to the login session that owns it, since vobd writes under the requesting user's process",
          ],
          answer: 0,
          explanation:
            "As Reading 5 noted, a vCenter-pushed change runs on the host as vpxuser, so attribution comes from correlating the host and timestamp with the vCenter task that started TSM-SSH -- that record names the SSO user (here svc-backup), which ties the grant to the action it enabled. vpxuser is vCenter's own agent account on every managed host, so naming it as the actor attributes nothing. shell.log records commands typed in an interactive shell session; a service start requested through vCenter never passes through a shell. And syslog.pid is the process ID of the vobd daemon itself, not of any user session.",
          xp: 30,
        },
      ],
    },
    // ── Analyst Choice: benign maintenance SSH ────────────────────────────────
    {
      type: "analyst_choice" as const,
      id: "esxf-ac1",
      heading: "Verdict: SSH Enabled at 02:10 on a Saturday",
      scenario:
        "An automated rule flags every esx.audit.ssh.enabled event for review, exactly the pattern this room has taught you to treat as high-confidence. The event below fired on Saturday 11 July, eight days before the incident investigated above, on a different host in a different cluster. Matching the host and timestamp to vCenter's task list attributes the TSM-SSH start to j.marchetti, whom the identity directory lists as a named member of the virtualization team. Review it before deciding how to handle it.",
      event: benignMaintenanceSshEvent,
      correct_verdict: "false_positive",
      explanation:
        "The event type is identical to the one in the confirmed incident -- SSH being enabled on a host that ships with it off by default -- but the surrounding context is completely different. it_verify_result is 'confirmed', tied to change ticket CHG-77410 authorising exactly this maintenance activity for this weekend, the acting account (j.marchetti) is a named individual on the virtualization team rather than a generic service account, and the description states the service was disabled again forty minutes later at the end of the scripted update run -- a bounded, accounted-for window rather than an open-ended enablement.",
      fp_trap:
        "esx.audit.ssh.enabled is precisely the event this room has taught you to treat as near-certain evidence of compromise, given ESXi's default-off posture. But real virtualization teams do legitimately enable SSH during planned maintenance windows to run update scripts, exactly as the change ticket here documents. Escalating every SSH-enabled event without checking for a change record and a named individual account, and without noting whether the service was subsequently disabled again, trains a team to drown in noise on the one pattern that most needs real scrutiny when it occurs without that supporting evidence -- exactly as it did in the earlier finding.",
      xp: 30,
    },
    // ── Reading 6: shell.log / vim-cmd ────────────────────────────────────────
    {
      type: "reading" as const,
      id: "esxf-r6",
      heading: "Shell Access and shell.log: When an Attacker Gets an Interactive Session",
      content:
        "Enabling SSH, as the previous readings covered, opens the door. This reading covers what happens once someone actually walks through it: an interactive shell session on the hypervisor itself.\n\n" +
        "**ESXi Shell and SSH access.** Beyond the SSH service being merely enabled, an actual interactive login (whether over SSH remotely, or at the host's local console (DCUI) directly) starts a real shell session on the host, running as whichever local account authenticated (commonly root, ESXi's built-in administrative account). This is functionally similar to gaining an interactive shell on a Linux server, and everything this platform already teaches about investigating a suspicious Linux shell session transfers directly here.\n\n" +
        "**shell.log: the command record.** Every command executed inside an interactive ESXi shell session is recorded in /var/log/shell.log, the direct hypervisor equivalent of a Linux shell history file or auditd command-execution record. This is frequently the single richest piece of evidence in a hypervisor investigation, because it shows literally, verbatim, every command the actor typed.\n\n" +
        "**vim-cmd: VMware's own command-line VM management tool.** vim-cmd is a utility built into ESXi specifically for managing VMs from the command line, listing every VM registered on the host (vmsvc/getallvms), and controlling a specific VM's power state (vmsvc/power.off, among others), all without needing to go through vCenter's graphical interface at all. A shell-history entry showing a loop over vim-cmd vmsvc/getallvms feeding into repeated vmsvc/power.off calls is a specific, recognisable pattern: someone is programmatically discovering every VM on this host and shutting each one down in sequence, not performing routine, one-off host administration.\n\n" +
        "**Why this specific artefact matters so much for scoping impact.** shell.log doesn't just prove that a shell session happened, its verbatim command record is frequently the only place that shows the FULL SCOPE of what was actually done: exactly which VMs were targeted, in what order, and, as the next reading covers, exactly what was run against the datastore afterward. An investigation missing shell.log is often missing the single most complete account of the actor's actual actions on the host.",
    },
    // ── Reading 7: datastore encryption mechanics ────────────────────────────
    {
      type: "reading" as const,
      id: "esxf-r7",
      heading: "Datastore Encryption and Why VMs Must Be Powered Off First",
      content:
        "Ransomware operators who reach the hypervisor layer follow a strikingly consistent pattern: stop every VM, then encrypt the datastore. This reading explains why that specific order isn't a stylistic choice: it's a mechanical requirement.\n\n" +
        "**The lock.** A VM's disk contents live in a -flat.vmdk file on a shared VMFS datastore, as Reading 1 introduced. While a VM is powered on, ESXi holds an exclusive lock on that file specifically to prevent data corruption: the whole point of the lock is ensuring no two processes can write to the same virtual disk at once, which would corrupt it. This is a deliberate, necessary safety mechanism, not a security control, and it applies just as much to a legitimate backup tool as it does to an attacker's encryptor.\n\n" +
        "**Why an encryptor can't simply run against a locked file.** A ransomware encryptor targeting the datastore needs to open and rewrite each -flat.vmdk file. It cannot do so while that file is locked by a running VM: the operating system itself will not allow a second process to write to a file another process holds an exclusive lock on. This is precisely why the mass power-off step that precedes datastore encryption in a real hypervisor ransomware incident is not about disruption for its own sake, or an attempt to prevent recovery through some other mechanism: it is a direct, unavoidable technical precondition for the encryption step that follows it.\n\n" +
        "**Mapping this to MITRE ATT&CK.** Forcing VMs offline to enable a later encryption step is T1489, Service Stop: the VMs are being stopped as a means to an end, not as the objective itself. The encryption that follows is T1486, Data Encrypted for Impact. Collapsing the two into a single step loses something important for detection: the power-off events are visible in vCenter and on the host, often minutes before any file on the datastore has actually been touched, a real, if narrow, detection and response window that only exists because the two steps are mechanically separate and sequential.\n\n" +
        "**Not to be confused with legitimate VM/vSAN encryption features.** VMware offers its own legitimate encryption capabilities (VM Encryption, vSAN encryption) for protecting data at rest as a defensive feature, configured and managed deliberately by an organisation's own administrators well in advance. An attacker's encryptor is a completely separate, unauthorised binary run against the datastore from an interactive shell session, nothing about VMware's own legitimate encryption features is what's being described in a ransomware incident at this layer, and an analyst should not confuse a reference to 'VM encryption' in documentation with what an attacker's own tooling does.\n\n" +
        "**What this means for a detection rule.** A rule that fires on a burst of VmPoweredOffEvent records across many VMs in a short window, on a cluster with no scheduled maintenance recorded, is watching for the mechanical precondition rather than the encryption itself, which, per the timing point above, means it can fire before the actual damage is done, not merely report it afterward.",
      diagram:
        "flowchart LR\n" +
        "  A[VM running] --> B[ESXi holds exclusive lock on its -flat.vmdk\\nprevents corruption from concurrent writes]\n" +
        "  B --> C{Attacker wants to encrypt the datastore}\n" +
        "  C --> D[Must power off the VM first\\nT1489 Service Stop]\n" +
        "  D --> E[Lock released]\n" +
        "  E --> F[Encryptor can now rewrite the -flat.vmdk\\nT1486 Data Encrypted for Impact]\n",
      diagramCaption: "The power-off is a mechanical precondition for encryption, not a separate act of disruption",
      checkpoint: {
        question: "Why, mechanically, must a VM be powered off before its -flat.vmdk file on a shared datastore can be encrypted by an attacker's tooling?",
        options: [
          "While a VM runs, ESXi holds an exclusive lock on its -flat.vmdk to prevent concurrent writes, and that lock also blocks the encryptor",
          "The guest's EDR sensor would see its own disk being encrypted and alert, so the VM must be off to keep that sensor from reporting it",
          "Powering off stops the VM's scheduled snapshots and backups, so the encryptor can finish before a clean recovery point is taken",
          "VMFS lets only one host write to a datastore at a time, so every VM must stop to free the volume for the host running the encryptor",
        ],
        answer: 0,
        explanation:
          "This is the mechanical requirement Reading 7 built the whole section around: the exclusive lock exists to prevent corruption, and it applies to any process, malicious or not -- which is exactly why power-off precedes encryption, as a technical precondition. Silencing the guest's EDR is not the reason: Reading 2 established that a guest sensor has no view of the datastore underneath it. Reading 7 also rules out recovery-prevention as the purpose of the power-off -- it is about releasing the lock, not about backups. And VMFS is a clustered filesystem shared by every host in the cluster at once, so there is no single-writer volume to free.",
      },
    },
    // ── Question 3 ───────────────────────────────────────────────────────────
    {
      type: "question" as const,
      id: "esxf-q3",
      question:
        "A detection engineer proposes a single rule that fires only once a mass rename/rewrite of a datastore's -flat.vmdk files is observed (e.g., many disk files suddenly gaining a new extension), using the storage array's or NAS's own file-audit telemetry. Based on Reading 7, what is the main weakness of relying on ONLY that rule?",
      options: [
        "It fires only once encryption is under way, missing the earlier mass power-off (T1489) that must come first and is visible in vCenter and host logs",
        "Its weakness is scope: it would catch only the first datastore to be encrypted and miss VMs on other datastores, which the encryptor processes later in the run",
        "It would see only encryption launched from inside a guest VM, since an encryptor running on the ESXi host writes through the hypervisor and bypasses file-modification telemetry",
        "It would generate constant false positives, since every VM continually modifies its own -flat.vmdk during normal operation, making the signal indistinguishable from ordinary use",
      ],
      answer: 0,
      explanation:
        "Reading 7 made this point directly: because the power-off step is a separate, earlier, mechanically-required precondition, it is visible before the encryption itself -- a rule watching only for the encryption step throws away that earlier warning window. Nothing can run ON the ESXi host to watch this, but the storage layer underneath it (the array or NAS serving the datastore) sees every file operation regardless of whether the encryptor runs in a guest or on the host -- so host-side encryption is not invisible to it. The weakness is not a datastore-by-datastore coverage gap either. And while VMs do write to their own disk files during normal operation, the rule targets a mass rename/rewrite of many -flat.vmdk files at once, which is a distinguishable shape, not indistinguishable noise; the weakness is timing, not false-positive volume.",
      xp: 25,
    },
    // ── Reading 8: earliest high-fidelity signal ─────────────────────────────
    {
      type: "reading" as const,
      id: "esxf-r8",
      heading: "Detecting Fast, Not Just Detecting True: Ranking Signals in a vSphere Intrusion",
      content:
        "This room has now covered several genuinely different signals across a hypervisor intrusion: a VPN or initial access event, an authentication attempt, a permission grant, an SSH-enable event, a shell session, and a mass power-off. A skill worth teaching explicitly, on top of recognising each one individually, is how to rank them by which combination of earliness and confidence actually makes the best detection rule.\n\n" +
        "**Earliness and fidelity are different qualities, and the best rule needs both.** The very first event in a real intrusion timeline is often the lowest-confidence one. Initial network access alone (a VPN login, a reachable management interface) is usually far too common and far too weakly correlated with an actual attack to alert on by itself; nearly every legitimate remote worker or contractor produces the same shape of event constantly. Waiting for the highest-confidence signal available, on the other hand, often means waiting until the attack has already caused its impact.\n\n" +
        "**Where esx.audit.ssh.enabled sits on that spectrum.** This event is not the earliest possible signal in a real intrusion: a permission grant or an authentication event typically precedes it. But it combines unusually high confidence (Reading 5's default-off posture argument) with still being well ahead of any actual damage: it names the specific host and the specific vSphere principal responsible, it can be automatically checked against a change-management calendar, and, critically, it still occurs before the mass power-off and before any encryption. A detection rule built around this event captures most of the achievable earliness without sacrificing much confidence at all. A root-level Administrator grant with propagation, like the one in this room's first log, deserves a complementary rule of its own alongside it.\n\n" +
        "**Why the loudest, most certain signal is often also the latest.** A burst of guest EDR sensors going offline simultaneously (the consequence of the mass power-off covered in Reading 7) is about as close to certain as a signal gets, but by the time it fires, every VM on that host has already been forcibly stopped, and the encryptor may already be running. It is an excellent signal for confirming and scoping an incident already underway; it is a poor signal for preventing one.\n\n" +
        "**The general skill, beyond this one attack chain.** Any hypervisor investigation (not just the ransomware pattern this room has walked through) benefits from asking the same question about whatever candidate signals are available: which one combines the earliest position in the chain with the least legitimate-activity noise. That is a genuinely transferable reasoning skill, not something specific to memorising this one scenario's exact timeline.",
      checkpoint: {
        question: "This reading suggests running a rule on root-level Administrator grants with propagation alongside the SSH-enable rule. Applying its earliness-vs-fidelity reasoning, where does such a grant sit?",
        options: [
          "Early but noisy, like a VPN login, since permission changes happen constantly in a busy vCenter and mean little without context",
          "Earlier than the SSH-enable event and still high-confidence, since full Administrator grants at the inventory root are rare",
          "Late but certain, like the EDR-offline burst, since a grant is logged only once the new rights have actually been exercised",
          "Outside the spectrum, since a grant changes nothing until it is used and so belongs to post-incident scoping, not alerting",
        ],
        answer: 1,
        explanation:
          "Reading 3 showed that the grant is what made the later SSH-enable possible, so in this chain it comes earlier -- and a propagating Administrator grant at the very top of the inventory hands over the entire environment, which is a rare, narrow shape rather than everyday activity. That combination of earliness and confidence is what earns it a rule of its own. Routine permission changes do happen in vCenter, but they are not root-level Administrator grants with propagation, so the VPN-login comparison does not hold. The event is not late: PermissionAddedEvent is logged when the permission is created, before the rights are ever used. And precisely because the grant is the moment the account became capable of what followed, alerting on it gives the earliest high-confidence window rather than belonging only to after-the-fact scoping.",
      },
    },
    // ── Question 4 ───────────────────────────────────────────────────────────
    {
      type: "question" as const,
      id: "esxf-q4",
      question:
        "Reviewing a full vSphere intrusion timeline for the single best place to build an alerting rule, an analyst is choosing between: (1) the initial VPN login used to reach the management network, (2) the esx.audit.ssh.enabled event, and (3) the burst of guest EDR sensors going offline. Which ranking best reflects this room's earliness-vs-fidelity reasoning?",
      options: [
        "Rule primarily on (2) for its balance of confidence and earliness; treat (1) as weak context given legitimate remote-access noise, and use (3) to confirm and scope",
        "Rule primarily on (1) -- the VPN login is the earliest point in the chain, so alerting there gives the most response time, and tuning on geography and device can cut its noise to an acceptable level",
        "Rule primarily on (3) -- simultaneous EDR sensor loss is the highest-confidence signal in the chain and yields almost no false positives, which matters more than earliness for a Tier-1 queue",
        "Rule on (1) and (3) together -- pairing the earliest signal with the most certain one covers both ends of the chain and makes a dedicated SSH-enable rule redundant",
      ],
      answer: 0,
      explanation:
        "This is the direct synthesis of Reading 8's core lesson: neither pure earliness nor pure certainty alone makes the best rule -- the SSH-enable event's combination of both qualities is what earns it the primary role, with the VPN login serving only as weak corroborating context (given how common and low-confidence it is alone) and the EDR-offline burst serving only to confirm and scope an incident that has already progressed past the point where alerting on it could have changed the outcome. Ruling primarily on the VPN login overestimates how far tuning can cut the noise of legitimate remote access; ruling primarily on the EDR-offline burst trades away the response window for certainty; and pairing those two does not make the SSH-enable rule redundant, because neither of them offers its combination of high confidence before any damage.",
      xp: 30,
    },
    // ── Matching: term to log source ─────────────────────────────────────────
    {
      type: "matching" as const,
      id: "esxf-m1",
      heading: "Match the Term to What It Actually Records",
      instructions: "Match each vSphere/ESXi artefact to what it records and where it lives.",
      pairs: [
        { id: "vpxd", left: "vpxd.log", right: "The vCenter Server daemon's own log, recording management-plane events like logins and PermissionAddedEvent" },
        { id: "vobd", left: "vobd.log", right: "A host-local log on a specific ESXi host, recording esx.audit.* events such as SSH being enabled" },
        { id: "shelllog", left: "shell.log", right: "The verbatim record of every command run in an interactive ESXi shell session, including vim-cmd calls" },
        { id: "permadd", left: "PermissionAddedEvent", right: "The vCenter event marking exactly when a role was attached to a principal at a specific entity, with or without propagation" },
        { id: "sshenabled", left: "esx.audit.ssh.enabled", right: "A host-level event flagging that SSH, off by default on ESXi, has just been turned on" },
        { id: "vimcmd", left: "vim-cmd", right: "ESXi's built-in command-line tool for listing and controlling VMs directly, without going through vCenter's graphical interface" },
      ],
      explanation:
        "Notice how these six artefacts split cleanly across the two log sources this room teaches: vpxd.log (management plane, vCenter-side) versus vobd.log and shell.log (host-local, ESXi-side) -- a real investigation needs both halves to reconstruct the full chain from authorization to action.",
      xp: 35,
    },
    // ── Ordering: hypervisor intrusion triage ────────────────────────────────
    {
      type: "ordering" as const,
      id: "esxf-o1",
      heading: "Order the Post-Incident Reconstruction of a vSphere Intrusion",
      instructions: "The intrusion has been contained and you are writing the post-incident report. Arrange these reconstruction steps so the report follows the attack chain itself -- each step covering the stage that the previous one made possible -- and closes with the check that confirms none of the privileged actions was sanctioned.",
      items: [
        { id: "initial", text: "Identify the initial access vector into the management network (VPN, exposed interface) and the identity it used" },
        { id: "permcheck", text: "Search vpxd.log for the PermissionAddedEvent that explains how the acting account became capable of what followed" },
        { id: "hostcheck", text: "Search the affected ESXi host's own vobd.log for esx.audit.* events confirming what configuration changes actually took effect, and when" },
        { id: "shellcheck", text: "Pull shell.log from any host where an interactive session occurred, to get the verbatim command record" },
        { id: "impactscope", text: "Scope impact through vCenter's VmPoweredOffEvent records and any datastore-level file changes" },
        { id: "changecheck", text: "Cross-check every privileged action found against the change-management calendar before finalising the report's verdict" },
      ],
      correct_order: ["initial", "permcheck", "hostcheck", "shellcheck", "impactscope", "changecheck"],
      explanation:
        "The report follows causality: the actor first needed a way into the management network, then a PermissionAddedEvent gave the acting account the rights it used, then those rights enabled SSH on the host (confirmed in vobd.log), the enabled SSH made the interactive session possible (recorded verbatim in shell.log), and that session drove the power-off loop and datastore changes that make up the impact. The change-calendar cross-check closes the report because it is the confirmation applied to the full list of privileged actions just reconstructed. This is a reconstruction order, not a live-response order: during an active intrusion, containment and scoping come first, and the change calendar is often checked early -- in the analyst-choice task, the change ticket is what settles the verdict.",
      xp: 35,
    },
    // ── Flag ──────────────────────────────────────────────────────────────────
    {
      type: "flag" as const,
      id: "esxf-f1",
      event: permissionGrantEvent, // show the vcsa-04 permission-grant log this flag reads
      prompt:
        "The danger in the vcsa-04 permission grant is its scope. To search vCenter for every other permission ever attached to that same inventory object, you would pivot on the object's managed-object reference (moref), vCenter's internal ID for it. Enter that moref.",
      answer: "group-d1",
      hint: "A permission is attached to an entity; the principal is who receives it.",
      xp: 20,
    },
  ],
};

export const roomsBatch39 = [esxiVirtualizationSecurityRoom];
