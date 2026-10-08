/**
 * Learning Rooms — Batch 23
 *
 * security-products-behaviour — a beginner-level breadth room that closes a
 * gap none of the deep-dive product rooms cover: given an alert, which
 * product produced it, what could it structurally see, and what was it
 * structurally blind to? av-vs-edr-masterclass already goes deep on endpoint
 * internals (intermediate); this room does not repeat that depth. Instead it
 * walks every product class a SOC touches — AV, EDR/XDR, NGFW, IDS/IPS, WAF,
 * SWG, email gateway, NDR, DLP, Identity Protection/CASB, vulnerability
 * scanner, SIEM, SOAR — through one repeated five-point lens: where it sits,
 * what it sees vs. cannot see, a representative log line, what it does when
 * it detects (and whether that's inline/prevent or out-of-band/detect-only),
 * and its characteristic false positive.
 */

import type { Room } from "@/data/rooms";
import type { TelemetryEvent } from "@/lib/sim/types";

// =============================================================================
// TelemetryEvents
// =============================================================================

const wafOversizeBypassEvent: TelemetryEvent = {
  id: "evt-secprod-la1-001",
  ts: "2026-05-02T09:14:07.000Z",
  source: "waf",
  vendor: "AWS WAF",
  event_type: "waf_allow",
  severity: "medium",
  description:
    "An Application Load Balancer forwarded a POST to /api/v1/search on the Meridian customer portal. The AWS Managed SQL Injection Rule Group evaluated the request and recorded no matching rule; the web ACL's default action was applied to the request.",
  network: {
    url: "https://portal.meridian-corp.com/api/v1/search",
    method: "POST",
  },
  src_ip: "154.16.88.203",
  raw: {
    timestamp: 1777713247123,
    formatVersion: 1,
    webaclId:
      "arn:aws:wafv2:us-east-1:104729551200:regional/webacl/meridian-portal-acl/8e2f1a3b-6c4d-4e7a-9b1f-2d5e8c3a7f1b",
    terminatingRuleId: "Default_Action",
    terminatingRuleType: "REGULAR",
    action: "ALLOW",
    httpSourceName: "ALB",
    httpSourceId: "104729551200-app/meridian-alb/6b1f2e9c4a7d3e8f",
    ruleGroupList: [
      {
        ruleGroupId: "AWS#AWSManagedRulesSQLiRuleSet",
        terminatingRule: null,
        nonTerminatingMatchingRules: [],
        excludedRules: null,
      },
      {
        ruleGroupId: "AWS#AWSManagedRulesCommonRuleSet",
        terminatingRule: null,
        nonTerminatingMatchingRules: [
          { ruleId: "SizeRestrictions_BODY", action: "COUNT", ruleMatchDetails: [] },
        ],
        excludedRules: null,
      },
    ],
    httpRequest: {
      clientIp: "154.16.88.203",
      country: "RO",
      uri: "/api/v1/search",
      httpMethod: "POST",
      httpVersion: "HTTP/1.1",
      requestId: "3f6b2a91-8e4c-4d2f-9a7b-1c5d8e2f6a3b",
      headers: [
        { name: "Host", value: "portal.meridian-corp.com" },
        { name: "Content-Type", value: "application/json" },
        { name: "Content-Length", value: "48213" },
        { name: "User-Agent", value: "python-requests/2.31.0" },
      ],
    },
  },
};

const nessusScanIdsEvent: TelemetryEvent = {
  id: "evt-secprod-ac1-001",
  ts: "2026-05-12T02:03:11.421Z",
  source: "ids",
  vendor: "Suricata",
  event_type: "ids_signature",
  severity: "low",
  hostname: "SENSOR-CORE-02",
  description:
    "Suricata's internal sensor recorded an HTTP GET to an internal portal's admin path from a host inside the vulnerability-management subnet, matching a signature that flags a default scanner User-Agent string. alert.action reflects the sensor's deployment mode, not whether the request succeeded or failed.",
  src_ip: "10.44.8.15",
  dst_ip: "10.44.20.30",
  dst_port: 80,
  protocol: "TCP",
  network: {
    url: "/admin/config.php",
    method: "GET",
    status: 404,
    user_agent: "Mozilla/4.75 [en] (X11, U; Nessus)",
  },
  it_verify_result: "confirmed",
  it_verify_message:
    "Change ticket CHG-91004 confirms a scheduled, credentialed Nessus scan of the internal portal subnet (10.44.20.0/24) runs every Tuesday 02:00-03:00 from the vulnerability-management host 10.44.8.15.",
  raw: {
    timestamp: "2026-05-12T02:03:11.421+0000",
    flow_id: 1834792028551342,
    event_type: "alert",
    src_ip: "10.44.8.15",
    src_port: 51422,
    dest_ip: "10.44.20.30",
    dest_port: 80,
    proto: "TCP",
    http: {
      hostname: "portal-internal.meridian.local",
      url: "/admin/config.php",
      http_user_agent: "Mozilla/4.75 [en] (X11, U; Nessus)",
      http_method: "GET",
      protocol: "HTTP/1.1",
      status: 404,
      length: 287,
    },
    alert: {
      action: "allowed",
      gid: 1,
      signature_id: 2101201,
      rev: 9,
      signature: "ET SCAN Nessus Vulnerability Scanner User-Agent Detected",
      category: "Detection of a Network Scan",
      severity: 2,
    },
    host: "SENSOR-CORE-02",
  },
};

// =============================================================================
// ROOM: security-products-behaviour
// =============================================================================

const securityProductsRoom: Room = {
  id: "security-products-behaviour",
  title: "Security Products: What Each One Sees and What It Does",
  description:
    "Every alert you triage was produced by a specific product sitting in a specific place, and that placement decides what it could possibly have seen. This room walks antivirus, EDR/XDR, NGFW, IDS, IPS, WAF, secure web gateway, email security gateway, NDR, DLP, identity protection/CASB, vulnerability scanners, SIEM and SOAR through one repeated lens: where it sits, what it sees and cannot see, a real log line, what it does when it detects something, and its characteristic false positive. You will finish able to say, for any alert, which product made it and what it structurally could never have caught.",
  difficulty: "beginner",
  category: "Foundations",
  estimatedMinutes: 65,
  xp: 280,
  icon: "🧭",
  prerequisites: ["soc-structure", "networking-protocols"],
  tasks: [
    // ------------------------------------------------------------------
    // Reading 1 — framing: detection surface
    // ------------------------------------------------------------------
    {
      type: "reading",
      id: "secprod-r1",
      heading: "The Detection Surface: Every Product Sits Somewhere",
      content: `The SOC Structure room introduced the SOC toolbox (SIEM, EDR, SOAR and a handful of others) as instruments in an orchestra. This room slows that down and asks the question the toolbox overview never had room for: why does each product see what it sees, and why does it miss what it misses?

The answer is almost always physical. A security product's visibility is a direct consequence of where someone installed it: on the device itself, inline in the network path, off to the side reading a copy of traffic, inside a cloud tenant's control plane, or in front of one specific application. That placement is called its detection surface, and it is not a bug or a vendor shortcoming. It is a structural fact. An agent installed on a laptop cannot see traffic between two servers it isn't running on. A tool reading a copy of network traffic cannot reach out and stop a connection, because by the time it reads the copy, the original packet has already been delivered. A tool that only receives what other systems forward to it cannot report on a source nobody connected.

This matters to you as an analyst in three concrete ways. First, when an alert fires, knowing which product raised it tells you immediately what kind of thing it could be about: a WAF alert is always about an HTTP request, never about a file on disk. Second, when you're asked to investigate something and no product raised an alert about it, the first question is not "did nothing happen" but "was anything positioned to see it." Third, and this is the idea the platform's own scenarios keep testing: a gap in coverage is not the same as a gap in the attack. The ESXi ransomware scenario you may already have investigated is built entirely around this. Ninety-six virtual machines were encrypted and the endpoint EDR platform raised no ransomware detection at all, not because the attack was subtle, but because the encryptor ran on the hypervisor itself, a layer below every guest operating system, where no EDR sensor has ever been able to run. The attack was loud. The product was simply never positioned to hear it.

Two distinctions will repeat throughout every reading in this room, so it's worth stating them once, clearly, before you see the first product.

Detection surface: every product's visibility is bounded by its position, on the host, inline on the wire, out-of-band on a tap, inside a cloud tenant, or in front of one application. A blind spot tied to position is not a flaw to be patched; it's a property to be compensated for with a different product.

Prevent vs. detect: a product sitting inline in the path of the traffic or the process (an IPS, a WAF, an NGFW, an EDR agent) can act before the bad thing completes: block the connection, drop the request, kill the process. A product sitting out-of-band, reading a copy (an IDS, most SIEMs, most NDR sensors) can only tell you afterward that something happened. And critically, even an inline, block-capable product can be deliberately configured to only observe: the platform's LockBit scenario is built on exactly this. CrowdStrike's sensor on the file server correctly identified wu_update.exe as LockBit 3.0 and scored it 91 out of 100, well above the block threshold, and did nothing, because the server's prevention policy was set to Detection Only. The product could have stopped it. The policy chose not to let it.`,
      diagram:
        "flowchart LR\n" +
        "  INTERNET([Internet]) --> NGFW[NGFW / IPS\\ninline -- can block]\n" +
        "  NGFW --> SWG[SWG / Proxy\\ninline -- user web traffic]\n" +
        "  SWG --> WAF[WAF\\ninline -- in front of the app]\n" +
        "  WAF --> APP[(Web Application)]\n" +
        "  NGFW --> SRV[Server / Endpoint\\nAV + EDR agents]\n" +
        "  IDS([IDS\\nout-of-band tap]) -. reads a copy of .-> NGFW\n" +
        "  NDR([NDR\\nout-of-band tap]) -. reads a copy of .-> SRV\n" +
        "  SIEM[[SIEM]] -. receives forwarded logs .-> NGFW\n" +
        "  SIEM -. receives forwarded logs .-> WAF\n" +
        "  SIEM -. receives forwarded logs .-> SRV\n" +
        "  SIEM -. receives forwarded logs .-> IDS\n" +
        "  SIEM -. receives forwarded logs .-> NDR\n" +
        "  SOAR[[SOAR]] -. acts on alerts from .-> SIEM",
      diagramCaption: "The placement map: detection surface is a consequence of where a product sits",
      checkpoint: {
        question:
          "In the LockBit example from Reading 1, CrowdStrike's EDR sensor scored wu_update.exe 91/100 -- well above its block threshold -- yet took no action. Why?",
        options: [
          "The sensor sits out-of-band on that server, so it could observe the threat but not block it",
          "The server's policy was set to Detection Only, so the sensor identified the threat but did not act",
          "Servers use a higher block threshold than workstations, and 91 fell short of it on this host",
          "The vendor's analysts later judged the detection a false positive, so no action was warranted",
        ],
        answer: 1,
        explanation:
          "The sensor was inline and the score was well above the block threshold, so it could have blocked. The policy on that server was Detection Only, so it logged the threat and did nothing. Placement decides what a product COULD do; policy decides what it actually does. “The sensor sits out-of-band” is wrong: an EDR sensor runs on the host itself and is inline. “Servers use a higher block threshold” contradicts the example, where 91 was well above the threshold. “Later judged a false positive” is wrong: this was real LockBit that went on to encrypt the server.",
      },
    },

    // ------------------------------------------------------------------
    // Reading 2 — AV + EDR/XDR
    // ------------------------------------------------------------------
    {
      type: "reading",
      id: "secprod-r2",
      heading: "Antivirus and EDR/XDR: On the Host, But Not on Every Host",
      content: `Antivirus and EDR both run as agents installed directly on an endpoint, but they were built to answer different questions, and the difference explains most of what each one misses. (This reading stays deliberately brief on internals: the AV vs EDR Masterclass room covers kernel hooking, ML models and vendor-specific behaviour in depth; this room only needs the five-point shape.)

Antivirus sits on the host and watches files. Its core method is scanning: comparing a file's contents against a database of known-malicious signatures, plus some heuristic analysis of file structure. Because it works on files, it sees exactly that (files written to disk, files opened, files downloaded) and nothing else. It is structurally blind to fileless attacks (malicious code that runs entirely in memory and never becomes a file), to Living-Off-the-Land Binaries or LOLBins (an attacker abusing powershell.exe, wmic.exe or certutil.exe. Programs already trusted and present on every Windows machine, so there's no new file to flag), and to anything an attacker never writes to disk at all. When AV detects, it quarantines or deletes the file: an inline, preventive action, because the scan happens before or as the file is written. Its characteristic false positive is the generic heuristic flag: a legitimate but unusual program (an internal build tool, an uncommon packer, a newly signed installer) that trips a "looks like malware" heuristic without being malware at all.

EDR (Endpoint Detection and Response) and XDR (Extended Detection and Response, which adds correlation across endpoint, identity and cloud telemetry) sit on the host too, but instead of scanning files they hook into the operating system kernel to watch behaviour continuously: every process created, its full command line, its parent process, every file and registry change, every network connection that process makes. This is why EDR catches what AV cannot. It doesn't need a known-bad file, it can flag a known-bad pattern of behaviour (Word spawning PowerShell with an encoded command, for instance) regardless of whether any individual file involved has ever been seen before.

But EDR's blind spot is not about behaviour: it's about coverage. An EDR agent can only see what happens on a machine it is installed on. Network appliances, hypervisors, IoT devices, most operational-technology equipment, and any BYOD device an employee brought without company software all run with zero EDR visibility, by policy or by physical impossibility. This is precisely the ESXi ransomware scenario from Reading 1: the hypervisor host running dozens of virtual machines has no EDR agent running on it at all, so the ransomware that encrypted the datastore directly produced no endpoint detection whatsoever, not a missed detection, a structurally absent one. When EDR detects, it can log-only, alert, kill the offending process, or fully isolate the host from the network. All genuinely inline actions, but only if the policy governing that specific host is set to allow them; a sensor set to Detection Only, as in the LockBit example, will identify the threat and take no action at all. EDR's characteristic false positive is admin tooling: a legitimate sysadmin script using PsExec, WMI or PowerShell for routine remote administration looks, on the process tree alone, almost identical to lateral movement.`,
      codeExample:
        "MICROSOFT DEFENDER ANTIVIRUS -- DETECTION EVENT (Event ID 1116/1117)\n" +
        "===========================================================\n" +
        "Threat Name:        Trojan:Win32/Wacatac.B!ml\n" +
        "Severity Name:       Severe\n" +
        "Category Name:       Trojan\n" +
        "Path:                file:_C:\\Users\\r.chukwu\\Downloads\\invoice_2026.exe\n" +
        "Detection Source:    Real-Time Protection\n" +
        "Action Name:         Quarantine\n" +
        "Action Status:       Success\n" +
        "===========================================================\n\n" +
        "MICROSOFT DEFENDER FOR ENDPOINT -- DeviceProcessEvents\n" +
        "===========================================================\n" +
        "Timestamp:                 2026-04-08 14:22:37\n" +
        "DeviceName:                WKS-OPS14\n" +
        "ActionType:                ProcessCreated\n" +
        "FileName:                  powershell.exe\n" +
        "ProcessCommandLine:        powershell.exe -nop -w hidden -enc SQBFAFgA...\n" +
        "InitiatingProcessFileName: WINWORD.EXE\n" +
        "AccountName:               d.oyelaran\n" +
        "===========================================================",
      diagram:
        "flowchart TB\n" +
        "  H[ESXi Hypervisor\\nNo EDR agent can run at this layer] --> ENC[Ransomware encryptor\\nruns directly on the hypervisor\\nencrypts the shared VM datastore]\n" +
        "  ENC --> V1[Guest VM: FS-CORP-01\\nEDR agent WAS reporting normally]\n" +
        "  ENC --> V2[Guest VM: APP-SRV-04\\nEDR agent WAS reporting normally]\n" +
        "  ENC --> V3[Guest VM: DB-SRV-02\\nEDR agent WAS reporting normally]\n" +
        "  V1 --> SIG[First signal: all agent heartbeats\\ngo silent at the same moment --\\nnever a ransomware detection]\n" +
        "  V2 --> SIG\n" +
        "  V3 --> SIG",
      diagramCaption: "The ESXi blind spot: nothing runs where the attack ran",
    },

    // ------------------------------------------------------------------
    // Question 1 — AV/EDR blind spot, which product would/wouldn't catch it
    // ------------------------------------------------------------------
    {
      type: "question",
      id: "secprod-q1",
      question:
        "Ninety-six VMs on an ESXi host were encrypted by ransomware that ran directly on the hypervisor. Which statement correctly identifies what each host-based product could and could not have caught?",
      options: [
        "Neither product could have caught it: both install only on guest or endpoint operating systems, so the hypervisor layer was outside their coverage",
        "AV could have caught it: file-scanning engines read any mounted storage volume, so the shared VMFS datastore would have been scanned even without a local agent",
        "EDR could have caught it: the sensors on the guest VMs hook the shared host kernel, so encryption executed by the hypervisor is visible to each sensor",
        "Only EDR could have caught it, by flagging the encryptor's behavior; AV would have missed it because the binary had no known file signature",
      ],
      answer: 0,
      explanation:
        "This is the coverage-vs-detection distinction from Reading 2: AV and EDR are both host-based agents, and 'host-based' means the hypervisor layer itself, which has no operating system these agents can install into in the way a Windows or Linux guest does. Is structurally outside their reach. It is not that the encryption was too subtle for either product's method; it's that neither product was ever positioned to observe the hypervisor at all. EDR's kernel hooks apply only to the OS it is installed on, not to a physical server's other workloads, and no agent installed anywhere makes signature availability relevant here.",
      xp: 20,
    },

    // ------------------------------------------------------------------
    // Reading 2b — vCenter/ESXi as its own log source, and T1489
    // ------------------------------------------------------------------
    {
      type: "reading",
      id: "secprod-r2b",
      heading: "If EDR Can't See the Hypervisor, What Can? vCenter and ESXi Logs",
      content: `The Antivirus and EDR/XDR reading and the question that followed it established the gap: no EDR agent has ever run on an ESXi hypervisor, so a ransomware encryptor executing there produces zero endpoint detections. That gap is real and permanent, but it does not mean the SOC is blind. It means the SOC has to look somewhere else: at the hypervisor's own management and audit logs, which are a completely different log source from anything discussed so far.

ESXi is VMware's hypervisor: the thin layer of software that runs directly on physical server hardware and hosts multiple virtual machines (VMs) on top of it, each unaware the others exist. Think of an apartment building: EDR watches what happens inside each individual apartment (each VM's guest operating system), but it has no view of the building's shared utility room, elevator machinery or front door, that shared infrastructure is the hypervisor layer, and vCenter is the building's management office. vCenter is VMware's centralized management server: a separate system that administrators log into to manage many ESXi hosts and their VMs at once (create/delete VMs, assign permissions, start/stop hosts) rather than logging into each hypervisor individually.

Because neither one is a Windows or Linux endpoint, neither produces Sysmon or EDR telemetry. Instead, each has its own native audit trail, and a SOC that ingests these into the SIEM gets visibility no endpoint agent could ever provide:

- **vpxd / vCenter events** (ingested as fields like vsphere.event.* in many SIEMs), a centralized log of every action taken through vCenter: VM power operations, permission changes, host connections. A key event type here is PermissionAddedEvent, logged whenever someone grants a role to a user or group on an object (a VM, a folder, a whole datacenter). vCenter's permission model is RBAC. Role-Based Access Control, the same idea as in Windows or a cloud console: a small, defined set of roles (like "Virtual Machine Power User" or "Administrator") each bundling a fixed set of privileges, assigned to specific users on specific objects. A PermissionAddedEvent granting the Administrator role at the datacenter level, issued by an account that has never touched vCenter before, is exactly the kind of privilege-escalation signal that has no endpoint equivalent. There is no "process" and no "host" for an EDR agent to watch.
- **ESXi host audit logs** (fields like esx.audit.* in many SIEMs, backed on the host itself by files such as /var/log/hostd.log, /var/log/vobd.log and /var/log/auth.log), the hypervisor's own record of what happened on that specific host: authentication attempts, configuration changes, and, critically, SSH access. ESXi ships with SSH disabled by default specifically because interactive shell access to a hypervisor is powerful and rarely needed for routine operations; VMware's own hardening guidance treats an enabled SSH daemon as a condition to actively monitor, not a normal running state. When SSH is turned on, ESXi logs it as an auditable event (represented as esx.audit.ssh.enabled in SIEM-normalized data), and because it defaults off, any occurrence of this event is worth an analyst's attention on its own, before anything else in the log even looks suspicious.

This is also where the room's second running theme lands precisely: the "prevent vs. detect" framing from Reading 1 applies here too, but with a twist. vCenter and ESXi logs are almost always detect-only from the SOC's perspective (the SIEM receives them after the fact, the same as an IDS reading a copy of traffic) even though the actions they describe (powering off a VM, granting a permission) happened inline, directly, on infrastructure with no intermediary to block them. There is usually no equivalent of a WAF or an IPS sitting in front of vCenter's management plane. That absence is exactly why unusual vCenter/ESXi activity. Permission grants, SSH being enabled, VMs being individually powered off outside a maintenance window. Deserves faster escalation than a comparable finding on an endpoint that has EDR standing guard.

One more MITRE ATT&CK distinction belongs here, because ESXi ransomware operators consistently perform it as a separate step before the encryption itself. The technique commonly discussed for this room's ransomware scenario, T1486: Data Encrypted for Impact, covers the encryptor actually scrambling the datastore's files. But before an operator runs that encryptor, a running VM normally holds its virtual disk files open, which can prevent them from being encrypted cleanly. So the standard playbook is to first force every VM off (a separate technique, T1489) Service Stop, which covers an attacker deliberately stopping a service or process to disable a defense or enable a further impact. On ESXi this is usually done with the host's own built-in command-line tool, vim-cmd, run over the SSH access enabled in the step above: an attacker lists every running VM and powers each one off in sequence, then runs the encryptor against the now-unlocked datastore. Recognizing T1489 as its own, earlier step matters operationally: a wave of vim-cmd vmsvc/power.off calls or a burst of VM power-off events in vCenter is a detectable warning several minutes before T1486's encryption impact lands, and it is the kind of signal that only vCenter/ESXi logs, not EDR, will ever surface.

**Compensating control, not a fix.** None of this makes the hypervisor blind spot from Reading 2 go away. It means the SOC compensates for a coverage gap at one layer (endpoint agents) by adding visibility from a completely different layer (hypervisor and management-plane audit logs). The lesson generalizes: whenever you learn that a product cannot see a particular layer, the next question is always "what native logging does that layer produce on its own, and is the SOC ingesting it?"`,
      codeExample:
        "ESXi HOST -- SSH ENABLED (esx.audit.ssh.enabled)\n" +
        "===========================================================\n" +
        "Timestamp:      2026-05-02T01:47:12Z\n" +
        "Host:           esxi-host-07.meridian.local\n" +
        "Event:          esx.audit.ssh.enabled\n" +
        "TriggeredBy:    root (local ESXi account, not a named admin)\n" +
        "Message:        SSH access has been enabled for the host\n" +
        "===========================================================\n\n" +
        "ESXi HOST -- ATTACKER SHELL SESSION (vim-cmd, over the SSH above)\n" +
        "===========================================================\n" +
        "$ vim-cmd vmsvc/getallvms\n" +
        "Vmid  Name              File                          Guest OS\n" +
        "12    FS-CORP-01        [datastore1] FS-CORP-01/...   windows2019srv_64\n" +
        "18    APP-SRV-04        [datastore1] APP-SRV-04/...   windows2019srv_64\n" +
        "23    DB-SRV-02         [datastore1] DB-SRV-02/...    windows2019srv_64\n" +
        "$ vim-cmd vmsvc/power.off 12        <- MITRE T1489: Service Stop\n" +
        "$ vim-cmd vmsvc/power.off 18        <- MITRE T1489: Service Stop\n" +
        "$ vim-cmd vmsvc/power.off 23        <- MITRE T1489: Service Stop\n" +
        "===========================================================\n\n" +
        "VCENTER -- PermissionAddedEvent (vsphere.event.*)\n" +
        "===========================================================\n" +
        "Timestamp:       2026-05-02T01:12:04Z\n" +
        "EventType:       PermissionAddedEvent\n" +
        "Target Object:   Datacenter: Meridian-Primary\n" +
        "Role Assigned:   Administrator\n" +
        "Assigned To:     sysmgr_svc\n" +
        "Assigned By:     sysmgr_svc\n" +
        "===========================================================",
      checkpoint: {
        question:
          "Why does an analyst treat an esx.audit.ssh.enabled event as worth investigating, even before checking who triggered it or what happened next?",
        options: [
          "Because SSH traffic is encrypted, so the SOC cannot see the commands run over it",
          "Because SSH is off by default on ESXi, so turning it on is a change from the normal state",
          "Because ESXi has no EDR agent, so every hypervisor log event is treated as an alert",
          "Because SSH is the protocol ransomware uses to encrypt the virtual machines' disks",
        ],
        answer: 1,
        explanation:
          "ESXi ships with SSH disabled, because routine management goes through vCenter. Any logged switch to “on” is therefore a deviation from the baseline, which is worth a look on its own. “SSH traffic is encrypted, so the SOC cannot see the commands” is true, but it does not explain why the enablement event itself matters. “Every hypervisor log event is treated as an alert” is wrong: most vCenter/ESXi events are routine, and the missing EDR agent is why these logs matter, not a reason to alert on all of them. “SSH is the protocol ransomware uses to encrypt” confuses access with the encryption itself: SSH can give an attacker a shell, but the encryptor is a separate program.",
      },
    },

    // ------------------------------------------------------------------
    // Reading 3 — NGFW
    // ------------------------------------------------------------------
    {
      type: "reading",
      id: "secprod-r3",
      heading: "NGFW: Inline, App-Aware, and Blind Once TLS Is On",
      content: `A Next-Generation Firewall (NGFW) sits inline. Every packet in and out of the network segment it guards physically passes through it, which is what gives it the power a traditional Layer 3/4 firewall never had: the ability to block, not just log.

A traditional firewall decides based on source and destination IP address and port number alone. Allow or deny TCP 443 from this subnet to that one. An NGFW adds two capabilities on top of that: App-ID, which inspects traffic patterns to identify the actual application generating it regardless of the port it uses (distinguishing a real HTTPS web session from a tool tunneling C2 traffic over port 443 to look like one), and User-ID, which maps a network connection back to the specific authenticated user who initiated it, not just a source IP that could be any device on a shared subnet or behind NAT.

What an NGFW sees is connection metadata and, for unencrypted traffic, the actual content passing through. What it does not see (and this is the limitation to internalize) is the content of any connection protected by TLS unless the NGFW is specifically configured to perform TLS inspection (decrypting the session in the middle, inspecting it, then re-encrypting it onward, which most organizations only enable selectively due to privacy, performance and certificate-pinning complications). Without TLS inspection, an NGFW watching an HTTPS session sees that a connection happened, to which destination, using how much bandwidth, and (via App-ID pattern matching) roughly what kind of traffic it resembles, but not the actual bytes inside it. This is why an NGFW can flag an anomalous-looking encrypted session as worth investigating far more easily than it can prove what's inside it.

Because it sits inline, an NGFW's detection is always potentially preventive: it can allow, deny, or drop a connection outright, and it does this in real time as each new session is evaluated against its rule base. Its characteristic false positive is an App-ID misclassification: a legitimate but unusual application, an internally built tool, a SaaS product using a nonstandard protocol pattern, a vendor appliance with idiosyncratic traffic. Gets fingerprinted as a different, riskier application than it actually is, and traffic that should be routine gets blocked or flagged.`,
      codeExample:
        "PALO ALTO NGFW -- TRAFFIC LOG (allowed session)\n" +
        "===========================================================\n" +
        "src:              10.20.4.18            dst: 203.0.113.44\n" +
        "sport:            51288                 dport: 443\n" +
        "proto:            tcp\n" +
        "app:              ssl                    (App-ID classification)\n" +
        "srcuser:          MERIDIAN\\t.nkemdirim   (User-ID mapping)\n" +
        "rule:             Outbound-Web-Standard\n" +
        "action:           allow\n" +
        "bytes_sent:       4218    bytes_received: 118442\n" +
        "session_end_reason: tcp-fin\n" +
        "===========================================================\n" +
        "Note: this is everything the log shows for a TLS session with\n" +
        "no decryption policy applied -- ports, byte counts, App-ID's\n" +
        "best-effort classification, and the authenticated user. Not\n" +
        "one byte of the encrypted payload itself.",
      diagram:
        "flowchart TD\n" +
        "  D[Sensor detects malicious activity\\ne.g. a threat score of 91/100] --> P{Is prevention enabled\\nfor this asset or policy?}\n" +
        "  P -->|Yes -- NGFW block rule,\\nEDR Full Prevention policy| B[BLOCK / DROP / KILL\\nAttack stopped before completion]\n" +
        "  P -->|No -- Detection Only policy,\\nor an out-of-band IDS| L[LOG ONLY\\nAlert fires, attack proceeds unimpeded]",
      diagramCaption: "Same detection, two different outcomes: policy decides, not confidence",
      checkpoint: {
        question: "Without TLS inspection enabled, what can an NGFW see about an HTTPS session?",
        options: [
          "Nothing: an encrypted session produces no log entry at all without inspection",
          "Metadata such as destination, byte counts and App-ID's best guess, but not content",
          "The full URL path of each request, though not the request or response body",
          "Only the destination IP, since App-ID classification itself needs TLS inspection",
        ],
        answer: 1,
        explanation:
          "Without TLS inspection an NGFW still logs that the connection happened, where it went, how many bytes moved, and App-ID's pattern-based guess at the application, but not what was inside. “Nothing: an encrypted session produces no log entry” is wrong: the session metadata is logged. “The full URL path of each request” is a common misconception: the path travels inside the encrypted session, so only the hostname (from SNI) is visible. “Only the destination IP” is wrong too: App-ID still makes a best-effort classification, such as “ssl”, from the handshake.",
      },
    },

    // ------------------------------------------------------------------
    // Reading 4 — IDS vs IPS
    // ------------------------------------------------------------------
    {
      type: "reading",
      id: "secprod-r4",
      heading: "IDS vs IPS: The Pair Everyone Confuses",
      video: {
        src: "https://wrxhxtdllbctsawvewue.supabase.co/storage/v1/object/public/lesson-videos/ids-vs-ips/ids-vs-ips.mp4",
        caption: "Explainer, IDS vs IPS · subtitles: English · עברית · Español (CC menu)",
        tracks: [
          { srclang: "en", label: "English", src: "https://wrxhxtdllbctsawvewue.supabase.co/storage/v1/object/public/lesson-videos/ids-vs-ips/en.vtt", default: true },
          { srclang: "he", label: "עברית", src: "https://wrxhxtdllbctsawvewue.supabase.co/storage/v1/object/public/lesson-videos/ids-vs-ips/he.vtt" },
          { srclang: "es", label: "Español", src: "https://wrxhxtdllbctsawvewue.supabase.co/storage/v1/object/public/lesson-videos/ids-vs-ips/es.vtt" },
        ],
      },
      content: `IDS and IPS are so often used interchangeably that many analysts never learn the one fact that actually separates them: it is entirely a question of physical placement, not of what signatures they know or how smart their detection logic is.

An IDS (Intrusion Detection System) sits out-of-band. It does not sit in the path of the traffic; instead, a network TAP or a switch's SPAN/mirror port sends it a copy of the traffic while the original packets continue on their way, uninterrupted. This means an IDS always sees a session slightly after the fact, from a duplicate, and by the time it has evaluated that copy against its signatures and raised an alert, the original packets have already been delivered to their destination. Structurally, an IDS can only ever detect and alert. It cannot drop a packet it never had. It was only ever given a copy.

An IPS (Intrusion Prevention System) sits inline, in the direct path of the traffic, exactly like the NGFW from the NGFW reading (in fact, on a modern NGFW, IPS functionality is usually built in as a "Threat Prevention" or "vulnerability protection" profile rather than shipped as a separate box). Because the IPS is the thing the packet must physically pass through, it can evaluate the packet against its signature and behavioral rules and decide, in real time, whether to let it continue, drop it, or reset the connection. Before the payload ever reaches its target.

Both use the same underlying detection technique (signature matching against known attack patterns, plus protocol anomaly detection) so a "smarter" IDS is not the fix for its structural limitation, and a "dumber" IPS still gets to block. The only variable that matters for prevent-vs-detect is where the box sits in the wire. This is also why the same detection engine can run in either mode: Suricata, one of the most widely deployed open-source engines, produces identical alerts whether deployed as an out-of-band IDS or an inline IPS, the field that changes is alert.action, reporting "allowed" in IDS mode (nothing was ever capable of being blocked) versus "blocked" or "dropped" in IPS mode.

The characteristic false positive for both is identical, because it comes from the shared detection method, not the placement: a signature written broadly enough to catch a real attack pattern also matches some class of legitimate traffic that happens to share the same byte pattern or protocol anomaly, a vulnerability scanner's default banners, a load balancer's health-check probes, or a legacy application using a deprecated but harmless protocol feature.`,
      codeExample:
        "THE ONE QUESTION THAT SEPARATES THEM\n" +
        "===========================================================\n" +
        "                    IDS                      IPS\n" +
        "-----------------------------------------------------------\n" +
        "Placement            Out-of-band (a copy       Inline (the actual\n" +
        "                      via TAP/SPAN port)         path of the packet)\n" +
        "Sees traffic          Slightly after the fact,   In real time, before\n" +
        "                       already delivered           delivery\n" +
        "Can it block?          NO -- can only alert       YES -- can drop, reset,\n" +
        "                                                     or block\n" +
        "Suricata field         alert.action: allowed      alert.action: blocked\n" +
        "===========================================================\n" +
        "The detection LOGIC (signatures, anomaly rules) can be\n" +
        "identical in both modes. Only the placement changes what\n" +
        "the product is physically capable of doing about a match.",
      diagram:
        "flowchart TB\n" +
        "  subgraph INLINE[Inline -- IPS]\n" +
        "    P1[Packet arrives] --> IPS{IPS evaluates\\nin the direct path}\n" +
        "    IPS -->|malicious: DROP| X1[Packet never delivered]\n" +
        "    IPS -->|benign: forward| D1[Delivered to target]\n" +
        "  end\n" +
        "  subgraph OOB[Out-of-band -- IDS]\n" +
        "    P2[Packet arrives] --> D2[Delivered to target\\nimmediately, unconditionally]\n" +
        "    P2 -. copy via TAP/SPAN port .-> IDS{IDS evaluates\\na copy, after the fact}\n" +
        "    IDS -->|malicious: ALERT ONLY| A2[Alert fired --\\noriginal already delivered]\n" +
        "  end",
      diagramCaption: "Inline can drop the packet; out-of-band can only watch it go by",
    },

    // ------------------------------------------------------------------
    // Question 2 — turn on the IDS vs IPS distinction
    // ------------------------------------------------------------------
    {
      type: "question",
      id: "secprod-q2",
      question:
        "A Suricata sensor fires an identical signature for the same exploit attempt on two different network segments. On Segment A the alert shows alert.action: 'blocked' and the connection never reached its target. On Segment B the alert shows alert.action: 'allowed' and the exploit succeeded. What is the most likely explanation?",
      options: [
        "Sensor A has a newer revision of the signature, and newer revisions are written as blocked",
        "Sensor A sits inline as an IPS and can drop packets; sensor B is an out-of-band IDS",
        "Sensor B's copy of the rule has a lower priority, and only priority-1 matches are blocked",
        "The exploit on Segment B was encrypted, so sensor B saw it only after it was delivered",
      ],
      answer: 1,
      explanation:
        "The engine and the signature were the same, so the different outcome comes from placement. An inline IPS sits in the traffic path and can drop the packet before delivery. An out-of-band IDS reads a copy after the original has already gone through, so it can only alert. alert.action reports that difference. “A newer revision of the signature” is wrong: a rule revision changes what matches, not whether the sensor can stop traffic. “A lower priority” confuses severity with action: priority ranks alerts, it does not give a copy-reading sensor the power to block. “The exploit on Segment B was encrypted” does not fit: an encrypted payload would not have matched the signature at all, yet sensor B alerted.",
      xp: 20,
    },

    // ------------------------------------------------------------------
    // Reading 5 — WAF
    // ------------------------------------------------------------------
    {
      type: "reading",
      id: "secprod-r5",
      heading: "WAF: In Front of the App, Blocking by Rule",
      content: `A Web Application Firewall (WAF) sits in front of a specific web application (as a reverse proxy, a load-balancer add-on, or a cloud edge service) and inline in the path of every HTTP request that application receives. Unlike an NGFW, which mostly reasons about connections, a WAF is built to read HTTP itself: the method, the URI, headers, cookies, and critically, the request body, the actual form data, JSON payload or query parameters a client submitted.

Because it terminates and re-issues the connection as a reverse proxy, a WAF doesn't need separate TLS-inspection configuration the way a network-layer NGFW does. It already sits at the point where TLS is decrypted for the application to process the request. This is what lets a WAF do something no network-layer product can: evaluate a request body against rules designed to catch SQL injection, cross-site scripting, and path traversal patterns, and block the request outright before it ever reaches the application code.

But "the WAF didn't block it" is not the same as "the request was safe," and this is the single most important nuance in this reading. Managed rule groups (bundled rulesets for common attack classes like SQL injection) only inspect a request body up to a configured size limit (commonly a default of around 8KB for many cloud WAF services) because fully parsing an unbounded body against every rule on every request would be prohibitively expensive at scale. What happens to the rest of a larger body is governed by an oversize-handling setting: it can be configured to treat anything past the limit as an automatic match (safe but can cause false blocks on legitimate large payloads), a guaranteed non-match, or simply continue without evaluating the excess at all. When oversize handling is left on the permissive "continue" behavior, a request body padded past the inspection limit, with a real, valid-looking payload up front and the malicious injection placed later in the body. Can sail through as an ALLOW with the SQL injection rule group reporting no match whatsoever, not because the payload wasn't malicious, but because the rule group never got to look at it. This is exactly the platform's own SQL injection scenario callout: a WAF BLOCK verdict is reassuring, but an ALLOW is not proof of a clean request, and an oversized body is one of the most common, least obvious ways a ruleset gets bypassed.

When a WAF does detect a match, its action is genuinely inline and preventive. It can block the request, respond with a CAPTCHA challenge, or simply log and continue (a "count" mode commonly used while tuning a new rule before enforcing it). Its characteristic false positive is a legitimate request that happens to contain a substring resembling an attack pattern: a customer support form where a user pastes a snippet of SQL-like text describing their own problem, or a search field containing punctuation that coincidentally matches part of an XSS signature.`,
      codeExample:
        "AWS WAF LOG -- BLOCKED REQUEST (normal-size body, rule matched)\n" +
        "===========================================================\n" +
        "action:              BLOCK\n" +
        "terminatingRuleId:   AWSManagedRulesSQLiRuleSet_SQLiBody_Body\n" +
        "terminatingRuleType: MANAGED_RULE_GROUP\n" +
        "httpRequest.uri:     /api/v1/login\n" +
        "httpRequest.clientIp: 91.203.145.12\n" +
        "httpRequest.httpMethod: POST\n" +
        "===========================================================\n" +
        "This is what a caught injection attempt looks like: a specific\n" +
        "terminatingRuleId naming the rule that matched, and action:\n" +
        "BLOCK. Compare this to the log analysis task below, where the\n" +
        "same rule group is present but the body was too large for it\n" +
        "to fully evaluate.",
    },

    // ------------------------------------------------------------------
    // Log Analysis — WAF oversize bypass
    // ------------------------------------------------------------------
    {
      type: "log_analysis",
      id: "secprod-la1",
      heading: "Reading a WAF ALLOW That Isn't a Clean Bill of Health",
      context:
        "A daily review of the Meridian customer portal's WAF logs turns up the entry below. It didn't fire any alert on its own (it's an ALLOW, the most common verdict in the log) but a threat-hunting sweep pulled it out specifically because of the request's size.",
      event: wafOversizeBypassEvent,
      questions: [
        {
          question:
            "ruleGroupList shows the AWS Managed SQL Injection Rule Group with terminatingRule: null and nonTerminatingMatchingRules: [], no match at all, and the final action is ALLOW. The Content-Length header reads 48213 bytes. What does this combination most likely indicate?",
          options: [
            "The body is far past the rule group's ~8 KB inspection limit, so most of it was never checked",
            "A null terminatingRule means the whole body was parsed and found clean, whatever its size",
            "The SQLi rule group was skipped, because an earlier rule had already allowed the request",
            "SizeRestrictions_BODY blocked the large body, so the request never reached the application",
          ],
          answer: 0,
          explanation:
            "Managed rule groups inspect a body only up to a size limit, commonly around 8 KB. A 48,213-byte body means most of it, wherever an injection might sit, was never evaluated, so “no match” does not mean “no attack”. “A null terminatingRule means the whole body was parsed and found clean” confuses “nothing matched in what was checked” with “everything was checked”. “The SQLi rule group was skipped” misreads the log: the group appears in ruleGroupList with an empty match list, so it did evaluate the request. “SizeRestrictions_BODY blocked the large body” misreads its action: the rule matched but is set to COUNT, and the final action is ALLOW. That override is a common tuning for APIs that accept large JSON, and it is exactly why the oversized body went through.",
          xp: 20,
        },
        {
          question:
            "clientIp is 154.16.88.203 (a Romanian IP with no prior history against this endpoint) and the User-Agent is 'python-requests/2.31.0': a generic HTTP scripting library, not a browser. Combined with the oversized body, what should an analyst do next?",
          options: [
            "Close it: the managed SQLi rule group evaluated the request and allowed it",
            "Pull the full body from origin logs and review the oversize-handling setting",
            "Add a geo-block for Romania, since the source country explains the risk",
            "Block the python-requests User-Agent at the WAF to stop scripted clients",
          ],
          answer: 1,
          explanation:
            "None of the signals (a new foreign IP, a scripting-library User-Agent, an oversized body) proves malice alone, but together they justify looking at what the WAF never inspected: pull the full body from origin or access logging, and review whether oversize handling should be tightened. “Close it: the rule group evaluated the request and allowed it” ignores that it evaluated only the first part of the body. “Add a geo-block for Romania” is disproportionate after one request and does nothing about the inspection gap for other sources. “Block the python-requests User-Agent” is trivially bypassed, because the client sets that header itself, and it would also break legitimate API scripts.",
          xp: 25,
        },
        {
          question:
            "What is the broader lesson this event teaches about reading WAF verdicts?",
          options: [
            "An ALLOW from a managed rule group means the request was inspected in full",
            "An ALLOW only means as much as the part of the request that was inspected",
            "A COUNT match works like a block, so the oversized excess was stopped there",
            "WAFs cannot stop SQL injection, so input validation should replace the WAF",
          ],
          answer: 1,
          explanation:
            "A verdict is only as trustworthy as what the rule group could actually inspect. With an inspection size limit and permissive oversize handling, “no match” can come from a request that was only partly examined, a low-visibility way managed rule sets get bypassed. “An ALLOW means the request was inspected in full” is the assumption this event disproves. “A COUNT match works like a block” is wrong: COUNT records the match and lets the request continue, as the final ALLOW shows. “WAFs cannot stop SQL injection” overreacts: a correctly tuned WAF is valuable, and the fix here is configuration, not removal.",
          xp: 25,
        },
      ],
    },

    // ------------------------------------------------------------------
    // Reading 6 — SWG + Email Security Gateway
    // ------------------------------------------------------------------
    {
      type: "reading",
      id: "secprod-r6",
      heading: "Secure Web Gateway and Email Security Gateway: Watching What Users Touch",
      content: `These two products are grouped together because they share a shape: both sit in the path of something a human user does, browsing and email, rather than in the path of raw network traffic or a single application's inbound requests.

A Secure Web Gateway (SWG), sometimes just called a web proxy, sits between an organization's users and the internet, and every outbound web request a managed device makes is expected to route through it. Because it's a mandatory chokepoint for web traffic, an SWG can enforce URL category policy (blocking known-malicious, gambling, or otherwise disallowed categories of site), and (like a WAF, but from the client side) can perform TLS inspection to decrypt, inspect, and re-encrypt HTTPS sessions, giving it visibility into the actual content of a page a user is loading, not just the destination domain. Its blind spot is defined entirely by what does and doesn't route through it: any traffic that bypasses the proxy configuration (a personal device, a misconfigured application, traffic tunneled out over a non-standard port the SWG doesn't intercept) is invisible to it by definition, and even for traffic that does route through it, applications using certificate pinning (hardcoding the exact certificate they expect, so a proxy's substituted certificate is rejected) cannot be TLS-inspected without breaking the application outright. When it detects a policy violation, an SWG's action is inline and preventive, block the page load, and its characteristic false positive is category misclassification: a legitimate business site (a vendor portal, a niche SaaS tool, a newly registered domain for a real partner) gets bucketed into a risky category by an automated classifier and blocked along with genuinely malicious sites in that bucket.

An Email Security Gateway sits in the path of inbound (and often outbound) mail, inspecting attachments, embedded links, and message authentication signals: SPF (does the sending server have permission to send for this domain), DKIM (is the message cryptographically signed and unaltered), and DMARC (the policy telling receivers what to do when SPF/DKIM fail). Modern gateways also sandbox attachments (detonating them in an isolated environment to observe behavior before delivery) and rewrite links to route clicks through the gateway for inspection at click-time, not just at delivery-time.

Its blind spots are specific and worth knowing by name. Many organizations route internal-to-internal mail directly through their mail platform without passing it back through the gateway at all, meaning a compromised mailbox sending phishing to colleagues internally can bypass inspection entirely. And because sandboxing and reputation checks happen at delivery time, a link that is genuinely benign when the message is sent (an empty page, a not-yet-weaponized domain) but is swapped for malicious content afterward defeats delivery-time analysis completely; link-rewriting mitigates this by re-checking at click-time, but only if the gateway rewrote that specific link in the first place. When it detects a threat, an email gateway acts inline and preventively on mail flow: quarantine, block outright, or strip the attachment before delivery. Its characteristic false positive is an aggressive spam/phish score on a legitimate but unusual sender: a new vendor whose domain has no sending history yet, or a legitimate bulk-mail platform sharing IP space with less reputable senders.`,
      codeExample:
        "PROOFPOINT TAP -- MESSAGE SUMMARY (representative fields)\n" +
        "===========================================================\n" +
        "sender:            billing@newvendor-partners.com\n" +
        "recipient:         ap@meridian-corp.com\n" +
        "subject:           Invoice #48213 - Payment Due\n" +
        "spf:               pass\n" +
        "dkim:              none\n" +
        "dmarc:             none\n" +
        "phishScore:        62\n" +
        "malwareScore:      4\n" +
        "quarantineFolder:  none\n" +
        "urlsCount:         1\n" +
        "===========================================================\n" +
        "SPF passing but DKIM/DMARC entirely absent is common for a\n" +
        "genuinely new, small vendor that hasn't finished configuring\n" +
        "outbound mail authentication -- not proof of spoofing by\n" +
        "itself, but exactly the combination worth a closer look.",
      checkpoint: {
        question:
          "Per the Secure Web Gateway and Email Security Gateway reading, why can a compromised mailbox sending phishing to colleagues internally sometimes bypass the email security gateway entirely?",
        options: [
          "Internal mail is signed with DKIM, so the gateway skips its checks on it",
          "Internal-to-internal mail often never routes back through the gateway",
          "The gateway inspects only attachments, so a link-only message passes",
          "Internal mail is TLS-encrypted, which the gateway is unable to read",
        ],
        answer: 1,
        explanation:
          "The blind spot is routing, not detection: many organisations deliver internal-to-internal mail directly on the mail platform, so it never passes the gateway at all. “Signed with DKIM, so the gateway skips its checks” is wrong: a valid signature does not switch off content inspection. “Inspects only attachments” is wrong: gateways also analyse links (and rewrite them for click-time checks). “TLS-encrypted, which the gateway is unable to read” is wrong: TLS protects mail between servers, and a gateway in the path receives the decrypted message.",
      },
    },

    // ------------------------------------------------------------------
    // Reading 6b — Vulnerability Scanner (the one active product)
    // ------------------------------------------------------------------
    {
      type: "reading",
      id: "secprod-r6b",
      heading: "Vulnerability Scanners: The One Product That Reaches Out Instead of Watching",
      content: `Every product so far in this room is a watcher. It sits somewhere, on a host, inline on the wire, on an out-of-band tap, in front of one application, in the cloud identity plane, and waits for files, packets, or events to arrive so it can judge them. A vulnerability scanner is the exact opposite, and that inversion is the whole reason it earns its own reading: it is the one product in the entire lineup that actively reaches out and initiates traffic to the machines it assesses, rather than passively observing traffic someone else generated. It is a prober, not a sensor. The ones you'll meet by name are Tenable Nessus, Qualys, Rapid7 InsightVM (formerly Nexpose), and the open-source OpenVAS.

Where it sits: not inline, and not on a tap. A scanner is simply a host on the network (or a cloud-hosted service, or a lightweight agent installed on the target itself) that, usually on a fixed schedule, connects out to a list of target systems and interrogates each one: knocking on ports to see which are open, asking each service that answers what it is and what version it's running, and comparing every answer against a constantly-updated database of known vulnerabilities (Tenable calls each individual check a "plugin"; other vendors call them signatures or detections). Because it is the thing initiating the connections, it has no position in anyone else's traffic path from which it could block anything, and it isn't trying to. Assessment, not enforcement, is the entire job.

What it sees, and the credentialed-versus-uncredentialed split that decides how much: an uncredentialed (network-only) scan sees exactly what an external attacker with no login would see (open ports, service banners, and behaviour it can poke at from outside) and infers likely vulnerabilities from those outside signals alone. A credentialed (authenticated) scan is handed a real login to each target and can read the actual installed-patch level, exact package versions, and configuration directly from inside the system. The accuracy gap between the two is enormous: authenticated scanning is widely considered the single biggest accuracy improvement available, because the scanner can confirm whether a patch is genuinely installed instead of guessing from an externally visible version string. That guessing is the root of the scanner's most famous weakness, below.

What it does when it detects something, and this is the sharpest contrast in the whole room: nothing to the target. A scanner never blocks, quarantines, kills, drops, or isolates anything, under any policy, ever. This is a stronger statement than the EDR-on-Detection-Only case from Reading 1: that sensor could have blocked and was merely configured not to, whereas a scanner is structurally incapable of enforcement because it has no foothold in the traffic or process path to act from. Its only output is a report: a list of findings, each carrying a CVE (Common Vulnerabilities and Exposures) identifier where one exists, plus a CVSS (Common Vulnerability Scoring System) base score and severity rating that describe how serious that class of flaw is in general. Acting on that report (patching, reconfiguring, decommissioning, isolating) is a separate human-and-process step entirely, which is exactly why "the scanner found it" and "the risk was fixed" are two very different states, sometimes months apart.

Its blind spot is time, not position: a scan is a point-in-time snapshot. It tells you what was true at 02:00 last Tuesday, not what is true right now: a vulnerability introduced an hour after the scan finished stays invisible until the next scheduled run, which is why scanning is a periodic health check rather than the continuous monitoring EDR and NDR provide. It also cannot tell you whether anything it found is actually being exploited; that is the job of the detection products in the rest of this room. A scanner's output tells you where the unlocked doors are. It never tells you whether someone is currently walking through one.

Its two characteristic false positives are worth knowing by name, because they point in opposite directions:

- Backported-patch false positives. Many plugins detect a vulnerability purely from a software package's version number, without ever attempting to exploit it. But Red Hat, Debian, and Ubuntu all default to backporting, applying a security fix to an older package while deliberately leaving its version number unchanged for stability. A version-only, uncredentialed scan sees the old version string, matches it against a known CVE, and reports the host as vulnerable even though the fix was actually applied long ago. This is one of the most common false positives in all of vulnerability management, and it is precisely why credentialed scanning (which can read the distribution's real patch metadata instead of just the version string) exists.

- The scanner as everyone else's false positive. This is the flip side, and it is the exact situation the next task walks through: a scanner's own probing traffic (hundreds of connections to many ports and hosts in a short burst) is, by shape, indistinguishable from the reconnaissance phase of a real attack, so an IDS or NDR will dutifully raise "scan detected" alerts every single time an authorized scan runs. The scanner did nothing wrong and the IDS did nothing wrong; the traffic that is a scanner's entire legitimate purpose simply has the same shape as hostile reconnaissance. That is why an authorized scanner's schedule and source host must be known facts on the SOC floor, so those alerts can be triaged in seconds instead of chased for hours.`,
      codeExample:
        "TENABLE NESSUS -- REPRESENTATIVE FINDING (from the report, not an alert)\n" +
        "===========================================================\n" +
        "Host:            10.44.20.31\n" +
        "Plugin ID:       42873   (one Tenable plugin = one vulnerability check)\n" +
        "Plugin Name:     SSL Medium Strength Cipher Suites Supported (SWEET32)\n" +
        "Severity:        High\n" +
        "CVSS v3.1 Base:  7.5\n" +
        "CVE:             CVE-2016-2183\n" +
        "Plugin Output:   Negotiated a 64-bit block cipher (DES-CBC3-SHA)\n" +
        "===========================================================\n" +
        "A scanner FINDING is not an ALERT. Nothing was blocked, and\n" +
        "nothing is known to be under attack -- this is a report line\n" +
        "saying 'this weakness exists here,' carrying a CVE and a CVSS\n" +
        "base score, handed off to a remediation process that is\n" +
        "entirely separate from the scanner itself.\n" +
        "===========================================================\n\n" +
        "CREDENTIALED vs UNCREDENTIALED -- WHY IT DECIDES ACCURACY\n" +
        "===========================================================\n" +
        "Uncredentialed  -> sees only what an outside attacker sees:\n" +
        "                   open ports, banners, externally visible\n" +
        "                   version strings -> more false positives\n" +
        "Credentialed     -> logs in and reads the REAL installed-patch\n" +
        "                   state -> can tell a backported-but-patched\n" +
        "                   package from a genuinely vulnerable one\n" +
        "===========================================================",
      checkpoint: {
        question:
          "Why can a vulnerability scanner not block a vulnerability it finds, however aggressively it is configured: a stronger limitation than an EDR set to Detection Only?",
        options: [
          "It sits out-of-band on a tap like an IDS, so it reads only a copy of the traffic",
          "It has no position in any traffic or process path; it only probes and reports",
          "Blocking needs a credentialed scan, and most scans are run uncredentialed",
          "Its blocking feature acts only on findings that score a CVSS of 10.0",
        ],
        answer: 1,
        explanation:
          "A scanner is a prober, not a sensor: it reaches out, assesses targets and reports findings (a CVE with a CVSS score), and fixing them is a separate human step. The Detection Only EDR could have blocked and was configured not to; a scanner has nowhere to block from. “It sits out-of-band on a tap like an IDS” is wrong: a scanner does not read traffic at all, it generates its own connections. “Blocking needs a credentialed scan” confuses accuracy with enforcement: credentials let it read patch levels, not block anything. “Acts only on findings that score a CVSS of 10.0” invents a feature: a CVSS score rates severity and never triggers enforcement.",
      },
    },

    // ------------------------------------------------------------------
    // Analyst choice — vuln scanner triggers IDS alert (false positive)
    // ------------------------------------------------------------------
    {
      type: "analyst_choice",
      id: "secprod-ac1",
      heading: "Verdict: A Scanner Signature Firing at 2 AM",
      scenario:
        "SENSOR-CORE-02, Meridian's internal Suricata IDS, fired the alert below overnight. In the two minutes surrounding this event, the same source host generated 217 connection attempts across 40 distinct internal ports and hostnames: the kind of breadth that, on an unfamiliar host, would usually justify immediate escalation. Review the representative alert and the change-ticket note attached to it before deciding.",
      event: nessusScanIdsEvent,
      correct_verdict: "false_positive",
      explanation:
        "The signature name and the User-Agent field both point to the same conclusion: this is Tenable Nessus's own default HTTP User-Agent string, and the source IP belongs to Meridian's vulnerability-management host, not an unknown external actor. A confirmed, scheduled, credentialed weekly scan explains both the breadth (many ports and paths probed in a short window is exactly what a vulnerability scan does) and the specific signature that fired. Note what actually decides this: a User-Agent is set by the client and is trivially spoofed, so the Nessus string alone would never clear an alert. It is the change ticket and the confirmed source host (10.44.8.15, the vulnerability-management server) that do. alert.action: 'allowed' here reflects that this Suricata sensor runs in IDS, out-of-band mode (it reports what it saw, it did not and could not have blocked anything) which is a separate fact from whether the traffic was malicious. This is a textbook Vulnerability Scanner false positive on an IDS: the scanner is doing its authorized job of probing for weaknesses, and the IDS is doing its job of flagging scan-shaped traffic; neither is wrong, and neither indicates an attack.",
      fp_trap:
        "The volume alone (217 requests across 40 ports and paths from one host in two minutes) looks exactly like the reconnaissance phase of an intrusion, and 'ET SCAN' category alerts are trained into analysts as an early-attack signal. It's tempting to treat the sheer breadth as decisive on its own. But breadth is the shape of network scanning in general, and an organization's own authorized vulnerability scanner produces that exact shape every time it runs, which is often, as here, on a predictable schedule, from a known, dedicated host, against internal ranges nobody outside IT/security has any reason to be systematically probing. Escalating every 'ET SCAN' alert without first checking source host identity and IT verification is how legitimate, expected scanning traffic burns hours of investigation time that a genuine external reconnaissance attempt deserves instead.",
      xp: 30,
    },

    // ------------------------------------------------------------------
    // Reading 7 — NDR + DLP + Identity Protection/CASB
    // ------------------------------------------------------------------
    {
      type: "reading",
      id: "secprod-r7",
      heading: "NDR, DLP, and Identity Protection/CASB: Metadata, Content, and Identity Signals",
      content: `These three products sit in three different places again (the internal network, the egress path of data, and the cloud identity plane) and each answers a question none of the products covered so far can.

Network Detection and Response (NDR) sits out-of-band inside the network, typically reading a copy of traffic (much like an IDS) but focused specifically on east-west traffic: communication between internal hosts, not just traffic crossing the perimeter. Its distinguishing capability is detecting malicious patterns from connection metadata alone, even when the traffic itself is fully TLS-encrypted: things like beaconing (a host making outbound connections to the same destination at suspiciously regular intervals, characteristic of malware checking in with a command-and-control server), unusual data-transfer volumes between hosts that don't normally talk to each other, or a workstation suddenly making the kind of authentication requests normally only seen from servers. It doesn't need to decrypt anything to notice a pattern in when, how often, and how much data moves. Its blind spot is exactly what it trades away by working from metadata: it cannot tell you what was actually said inside an encrypted session, only that the conversation's shape is unusual, and, like an IDS, it is almost always out-of-band and therefore detect-only, not preventive. Its characteristic false positive is a legitimate but unusual internal service (a backup job, a monitoring agent, or a newly deployed internal API) whose regular polling interval looks statistically identical to a beacon.

Data Loss Prevention (DLP) sits on egress channels (email, USB, cloud uploads, web forms, print) and, unlike NDR, it does inspect content directly: file contents, form field values, clipboard data, depending on which channels are configured. It's built to recognize sensitive data patterns (a credit card number format, a national ID pattern, a labeled "Confidential" document classification, source code signatures) as that data attempts to leave through a monitored channel. Its blind spot is entirely a configuration question: DLP only watches the channels it has been explicitly told to watch. A channel nobody configured: a personal cloud-storage app not on the monitored list, a lesser-used file-sharing tool, a USB device class the policy forgot. Is completely invisible to it, not because the data pattern wasn't sensitive, but because nothing was ever inspecting that path. When it detects, DLP's action depends entirely on policy mode: it can block the transfer inline, or merely notify/log it, and a channel set to notify-only will let the sensitive data leave while still generating a record of it having done so. Its characteristic false positive is a legitimate business process that happens to move data matching a sensitive pattern: a payroll export to an approved third-party provider, or an internal report containing test data that matches a real PII pattern by coincidence.

Identity Protection tools (like Azure AD/Entra Identity Protection) and CASB (Cloud Access Security Broker) platforms sit inside the cloud identity and SaaS layer rather than on the network or an endpoint at all, reading sign-in logs, token issuance events, and OAuth consent grants directly from the identity provider and connected cloud applications. This gives them a vantage point nothing else in this room has: they can flag sign-in risk (an "impossible travel" pattern, the same account authenticating from two geographically distant locations closer together in time than travel allows), anomalous OAuth app consent (a user granting a new third-party application broad access to their mailbox or files), and session-token reuse patterns that never touch a corporate network or endpoint at all, because the whole transaction happened cloud-to-cloud. Their blind spot mirrors that strength: anything happening entirely within a device or network they have no visibility into a compromised account's activity in a SaaS app the CASB isn't integrated with, and they generally can't see what a user did before or after the specific sign-in or API event they're evaluating. Detection here is inline in one important sense: a risky sign-in can be blocked or forced into step-up MFA in real time by the identity provider itself, but investigating what happened afterward inside the application often requires pulling logs from that application directly. Their characteristic false positive is the "impossible travel" false alarm caused by a VPN: an employee connecting through a corporate VPN exit node in a different country produces a sign-in that looks geographically impossible compared to their last known location, when no travel happened at all.`,
      codeExample:
        "AZURE AD IDENTITY PROTECTION -- RISK DETECTION (representative)\n" +
        "===========================================================\n" +
        "riskEventType:      unfamiliarFeatures\n" +
        "riskLevel:          medium\n" +
        "riskState:          atRisk\n" +
        "ipAddress:          185.220.101.47\n" +
        "location:           Bucharest, Romania\n" +
        "userPrincipalName:  m.oduya@meridian-corp.com\n" +
        "correlationId:      7e3f1a92-8c4d-4b7e-9a1f-2d6c8e4a7f3b\n" +
        "===========================================================\n" +
        "This is a sign-in risk signal from the identity plane -- it\n" +
        "says nothing about what the user did inside any application\n" +
        "after signing in. That's a separate log, from a separate\n" +
        "product, at a separate layer.",
      checkpoint: {
        question: "What is the characteristic false positive for Identity Protection/CASB tools, per the NDR, DLP, and Identity Protection/CASB reading?",
        options: [
          "A newly deployed internal monitoring service whose regular polling interval statistically resembles a command-and-control beacon pattern",
          "An 'impossible travel' false alarm caused by an employee connecting through a corporate VPN exit node in a different country",
          "A DLP policy blocking a payroll export to an approved third-party provider that matches a sensitive-data pattern",
          "A WAF blocking a legitimate customer support form submission that happens to contain SQL-like text",
        ],
        answer: 1,
        explanation:
          "The NDR, DLP, and Identity Protection/CASB reading names this directly: a VPN exit node in a different country can make a sign-in look geographically impossible compared to the user's last known location, even though no actual travel happened -- this is the identity-layer tool's characteristic false positive, distinct from NDR's beacon-lookalike or DLP's/WAF's content-based false positives.",
      },
    },

    // ------------------------------------------------------------------
    // Reading 8 — SIEM + SOAR
    // ------------------------------------------------------------------
    {
      type: "reading",
      id: "secprod-r8",
      heading: "SIEM and SOAR: Seeing Only What Reaches Them",
      content: `Every product covered so far in this room generates its own telemetry from its own vantage point. SIEM and SOAR are different in kind: neither one observes anything directly at all. Their entire value comes from what other products send them.

A SIEM (Security Information and Event Management platform) has no sensor of its own: no agent on an endpoint, no tap on the network, no position in front of an application. It is a destination: logs and alerts from every product covered in this room get shipped to it (a step generally called log forwarding or ingestion), and the SIEM's job is to normalize that data into a common structure and run correlation rules across it, exactly the "47 failed logins from the Netherlands, then a success" example from the SOC Structure room's toolbox overview, where no single log looked alarming but the pattern across many did. Correlation across sources is the SIEM's whole reason to exist; a SIEM that only ever shows you what one product already told you, one alert at a time, isn't earning its place in the stack.

This is exactly why a SIEM's blind spot deserves to be internalized as a rule, not a footnote: if the SIEM has no data at all from a given source, a network segment whose firewall was never onboarded, a SaaS application whose audit logs were never connected, a legacy server nobody got around to installing a forwarder on, then an attack moving entirely through that gap will produce zero SIEM alerts, and it will look, from inside the SIEM, exactly like nothing happened. A gap in SIEM coverage is a missing log source, virtually always, not an absence of attack activity. When an investigation dead-ends with "the SIEM shows nothing," the correct next question is never "so nothing happened". It's "what wasn't being forwarded to it from that part of the environment."

A SOAR (Security Orchestration, Automation and Response) platform sits one layer further downstream still: it doesn't even receive raw telemetry the way a SIEM does. It acts on findings, usually SIEM alerts or alerts forwarded directly from individual tools, through playbooks: predefined sequences of automated steps like looking up an IP in threat intelligence, pulling additional context from an EDR platform, or (where confidence is high enough and the action is reversible) automatically isolating a host or disabling an account. Because some of those actions are consequential and not everything should happen without a human decision, mature SOAR playbooks include approval gates: steps that pause and wait for an analyst to confirm before an automated action proceeds, particularly for anything hard to reverse. A SOAR's "detection" capability is entirely borrowed. It has no visibility of its own, and a SOAR playbook that never gets triggered because the upstream SIEM or tool never fired in the first place will never run, no matter how well the playbook itself is built.`,
      codeExample:
        "WHAT A 'SIEM GAP' USUALLY MEANS -- A CHECKLIST\n" +
        "===========================================================\n" +
        "Symptom: no SIEM alerts for a suspected intrusion path\n" +
        "\n" +
        "Ask, in order:\n" +
        "1. Is this log source even being forwarded to the SIEM?\n" +
        "   (check the source/index list, not the alert rules)\n" +
        "2. If forwarded, is a correlation rule written for this\n" +
        "   pattern at all, or only for a different one?\n" +
        "3. If a rule exists, is it actually enabled and not muted\n" +
        "   from an earlier noise-reduction pass?\n" +
        "Only after all three come back 'yes' does 'nothing happened'\n" +
        "become a reasonable working theory -- not before.\n" +
        "===========================================================",
      diagram:
        "sequenceDiagram\n" +
        "  participant EmailGW as Email Gateway\n" +
        "  participant EDR as EDR (host)\n" +
        "  participant NGFW as NGFW / IPS\n" +
        "  participant NDR as NDR\n" +
        "  participant IDPCASB as Identity Protection/CASB\n" +
        "  participant DLP as DLP\n" +
        "  participant SIEM as SIEM\n" +
        "  Note over EmailGW: SEES the phishing message at delivery\n" +
        "  Note over EDR,DLP: Silent -- nothing to see yet\n" +
        "  EmailGW->>SIEM: forwards delivery log\n" +
        "  Note over EDR: SEES the malicious process created on click\n" +
        "  Note over NGFW,DLP: Silent -- their stage hasn't happened yet\n" +
        "  EDR->>SIEM: forwards process-create alert\n" +
        "  Note over NGFW: SEES the outbound C2 connection, can block if inline\n" +
        "  NGFW->>SIEM: forwards connection log\n" +
        "  Note over NDR: SEES lateral movement between internal hosts\n" +
        "  NDR->>SIEM: forwards beaconing pattern\n" +
        "  Note over IDPCASB: SEES the risky cloud sign-in with a stolen token\n" +
        "  IDPCASB->>SIEM: forwards risky sign-in event\n" +
        "  Note over DLP: SEES the sensitive file leaving on egress\n" +
        "  DLP->>SIEM: forwards exfil record\n" +
        "  Note over SIEM: Produced ZERO telemetry of its own at any step --\\nevery line above is it correlating what six other products chose to forward",
      diagramCaption: "One intrusion, many sensors: the silences are the point",
    },

    // ------------------------------------------------------------------
    // Question 3 — SIEM gap scenario
    // ------------------------------------------------------------------
    {
      type: "question",
      id: "secprod-q3",
      question:
        "An incident responder confirms an attacker moved laterally through a segment of the network for three days, but the SIEM shows zero alerts for that segment during the entire window. A junior analyst concludes 'the SIEM proves nothing happened here before day three.' What's wrong with that conclusion?",
      options: [
        "Nothing: three days without alerts shows that the segment had no attack activity",
        "A SIEM sees only what is forwarded, so first check whether that segment's logs arrive",
        "A SIEM correlates within one log source type only, so mixed telemetry never alerts",
        "Encrypted lateral movement suppresses the logon events the correlation rules need",
      ],
      answer: 1,
      explanation:
        "A SIEM only knows what is shipped to it, so silence from one segment fits “nothing forwarded” as well as “nothing happened”. Check that source's ingestion status before treating the silence as evidence. “Three days without alerts shows no attack activity” is contradicted by the responder's confirmed findings. “Correlates within one log source type only” is wrong: cross-source correlation is a core SIEM job when the logs actually flow in. “Encrypted lateral movement suppresses the logon events” is wrong: encryption hides payloads from network tools, but Windows still writes logon and process events on the hosts.",
      xp: 20,
    },

    // ------------------------------------------------------------------
    // Question 4 — prevent vs detect, LockBit tie-in
    // ------------------------------------------------------------------
    {
      type: "question",
      id: "secprod-q4",
      question:
        "Meridian's DLP inspects the web upload channel inline. It flags a high-confidence match of 2,000 customer records in a file a user uploads to a personal cloud drive and logs the event, but the upload completes. What best explains the outcome?",
      options: [
        "DLP reads only a copy of web traffic, so it can record an upload but never stop it",
        "That channel's policy is notify-only, so DLP logged the match and let the data go",
        "The match was below DLP's blocking confidence, so it could only log the event",
        "DLP scans a file after the upload completes, so it always sees the match too late",
      ],
      answer: 1,
      explanation:
        "This is the same lesson as the LockBit example, on a different product: DLP's action depends on its policy mode. On a notify-only channel it records the sensitive data leaving and lets it go. “Reads only a copy of web traffic” contradicts the setup: this DLP is inline on the channel and can block. “Below DLP's blocking confidence” contradicts the high-confidence match in the scenario. “Scans a file after the upload completes” is wrong: an inline DLP inspects the transfer as it passes, which is what lets it block when the policy says so.",
      xp: 20,
    },

    // ------------------------------------------------------------------
    // Matching — product to unique visibility
    // ------------------------------------------------------------------
    {
      type: "matching",
      id: "secprod-m1",
      heading: "Match Each Product to the One Thing Only It Sees",
      instructions:
        "Match each security product to the visibility that most uniquely belongs to it among everything covered in this room.",
      pairs: [
        { id: "av", left: "Antivirus", right: "Files on disk matched against known-malicious signatures and heuristics" },
        { id: "edr", left: "EDR/XDR", right: "Full process trees and command lines from kernel-level hooks on the specific host it's installed on" },
        { id: "ngfw", left: "NGFW", right: "Which application and which authenticated user generated a network connection, inline, able to block it" },
        { id: "ids", left: "IDS", right: "Signature matches against a copy of traffic, with no ability to stop the original packet" },
        { id: "waf", left: "WAF", right: "The actual HTTP request body reaching one specific web application" },
        { id: "email-gw", left: "Email Security Gateway", right: "Attachments, links and SPF/DKIM/DMARC on mail crossing its inspection point, usually inbound, not internal-to-internal" },
        { id: "ndr", left: "NDR", right: "Beaconing and east-west traffic patterns from connection metadata, even inside TLS" },
        { id: "identity-casb", left: "Identity Protection/CASB", right: "Sign-in risk, impossible travel, and OAuth consent events at the cloud identity layer" },
        { id: "siem", left: "SIEM", right: "Nothing on its own, only what every other product forwards to it, correlated together" },
      ],
      explanation:
        "Each pairing is the direct consequence of where the product sits, as covered across this room: file-scanning on disk (AV), kernel-level behavior on one host (EDR), inline network+identity awareness (NGFW), out-of-band packet copies (IDS), HTTP bodies in front of one app (WAF), mail-flow inspection (email gateway), metadata patterns on internal traffic (NDR), cloud identity signals (Identity Protection/CASB), and (the one that trips people up) nothing at all of its own for a SIEM, whose entire value is correlating everyone else's telemetry.",
      xp: 40,
    },

    // ------------------------------------------------------------------
    // Ordering — progression of visibility across an attack chain
    // ------------------------------------------------------------------
    {
      type: "ordering",
      id: "secprod-o1",
      heading: "Order the Products by When They'd First See a Phishing-to-Cloud-Exfiltration Attack",
      instructions:
        "An incident review lists what happened, in no particular order: customer data left through a monitored egress channel; the attacker hopped between internal servers; a stolen token was used for a cloud sign-in; a phishing email reached a user's inbox; the infected workstation opened a connection to a command-and-control server; the user opened the attachment and a malicious process started. Work out the real sequence of the attack, then order these products by which one would see its part of it first.",
      items: [
        { id: "email-gw", text: "Email Security Gateway" },
        { id: "edr", text: "EDR" },
        { id: "ngfw-ips", text: "NGFW/IPS" },
        { id: "ndr", text: "NDR" },
        { id: "identity-casb", text: "Identity Protection/CASB" },
        { id: "dlp", text: "DLP" },
      ],
      correct_order: ["email-gw", "edr", "ngfw-ips", "ndr", "identity-casb", "dlp"],
      explanation:
        "This follows the attack's own physical progression through the environment, and therefore through the products positioned at each stage: delivery is visible to the email gateway first, execution on the host to EDR next, the first network egress to the NGFW/IPS, movement between internal hosts to NDR, cloud identity abuse to Identity Protection/CASB, and finally data leaving through a monitored channel to DLP. A SIEM could, in principle, surface all six as correlated alerts, but it only does so because each of these six products fed it telemetry in this order first, which is exactly the SIEM and SOAR reading's point about a SIEM having no sensor of its own.",
      xp: 35,
    },

    // ------------------------------------------------------------------
    // Flag
    // ------------------------------------------------------------------
    {
      type: "flag",
      id: "secprod-f1",
      // Pin the WAF event so the flag shows the log it actually asks about. Without
      // this pin the room falls back to the nearest preceding log — the Nessus IDS
      // analyst_choice event, whose raw.http.length is 287 — and students read that
      // decoy off the card right above the question (the recurring wrong answer).
      // The prompt's "log-analysis" (hyphen, no number) doesn't match the "Log
      // Analysis N" resolver, so the event must be pinned explicitly.
      event: wafOversizeBypassEvent,
      prompt:
        "The AWS WAF event below ended in ALLOW, yet one managed rule DID match this request. Its action had been overridden, so it only recorded the match and the request went through. What is that rule's ID? Enter it exactly as it appears in the log.",
      answer: "SizeRestrictions_BODY",
      hint: "Look through ruleGroupList for a rule group whose list of matching rules is not empty.",
      xp: 25,
    },
  ],
};

export const roomsBatch23 = [securityProductsRoom];
