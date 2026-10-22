/**
 * Scenario pack: "Behavioural EDR alert on an engineering workstation"
 *
 * A FALSE POSITIVE, and the correct verdict is "no incident".
 *
 * A CrowdStrike Falcon behavioural rule fires HIGH on an engineering
 * workstation because an unsigned executable wrote itself into Program Files,
 * registered a LocalSystem service and opened a network connection inside a
 * minute. Every one of those observations is true, and together they are a
 * textbook dropper signature. They are also exactly what a packaged internal
 * tool does when the management agent installs it.
 *
 * Nothing in the telemetry says "approved", "expected" or "benign". The
 * exonerating evidence has to be assembled by the student out of four
 * independent records that were never written to explain each other:
 *
 *   - a change record with a package name, a target ring and a two-hour window;
 *   - a software-distribution assignment naming the same package and the same
 *     ring, with a deadline at the start of that window;
 *   - a process tree whose parent is the management agent and whose installer
 *     ran out of the agent's own download cache, at the deadline;
 *   - an install-status record putting this specific host inside that ring, and
 *     a prevalence review showing the same file arriving across the whole ring
 *     in one window with no detections anywhere.
 *
 * Deliberately, NO event in this pack carries a MITRE technique. Attaching one
 * to legitimate administrative activity is itself the mistake being taught.
 *
 * Registry note: register in scenarios.ts with difficulty "beginner"
 * (ScenarioBundle itself carries no difficulty field).
 */

import type { ScenarioBundle, TelemetryEvent, IOC, ScenarioQuestion } from "@/lib/sim/types";
import { makeSha256 } from "@/lib/sim/iocs";
import { csProcess, csFile, csDns, csNetwork, csAlert } from "@/lib/sim/emitters/crowdstrike";
import { infobloxDns } from "./nativeRecords.events";

export function buildSoftwareInstallFalsePositiveScenario(
  scenarioId = "software-install-false-positive-2026",
): ScenarioBundle {
  const B = new Date("2026-06-02T09:14:00Z").getTime();
  const T = (ms: number) => new Date(B + ms).toISOString();
  const SEC = 1_000;
  const MIN = 60_000;
  const HOUR = 3_600_000;

  // The deployment deadline is 21:00Z — 11h46m after the change record is cut.
  const W = 11 * HOUR + 46 * MIN;

  const host = { hostname: "WS-ENG-4471", ip: "10.30.44.71" };
  const primaryUser = "t.barzilai@nexacorp.com";
  const requester = "e.shani@nexacorp.com";

  const appId = "9d2b3f71-58ac-4c06-b1e4-27f5a0d63e88";
  const groupId = "c507aa14-6be8-4f92-8d37-1b0e64c9af25";
  const targetGroup = "ENG-Workstations-Ring2";
  const deploymentId = "DPL-40218";
  const changeTicket = "CHG0043912";

  // One hash per file. Neither is signed — this is an internally built tool.
  const setupHash = makeSha256("meshlink_collector_setup_2_4_1_internal_build");
  const binHash = makeSha256("meshlink_collector_service_binary_2_4_1_internal_build");
  const imeHash = makeSha256("microsoft_intune_management_extension_agent_signed_microsoft");

  // The Intune Management Extension agent and the folder it downloads installers into
  // (C:\Windows\IMECache\<appId>_<n>\, no braces).
  const IME_NAME = "Microsoft.Management.Services.IntuneWindowsAgent.exe";
  const IME_PATH = `C:\\Program Files (x86)\\Microsoft Intune Management Extension\\${IME_NAME}`;
  const imeCachePath = `C:\\Windows\\IMECache\\${appId}_1\\mlnk-collector-setup.exe`;
  const cx = { companyId: "nexacorp" as const };

  const collectorFqdn = "mesh-collect.corp.nexacorp.com";
  const collectorIp = "10.30.9.40";

  // EDR↔scenario integration (Phase 4): endpoint-only incident — a behavioural
  // Falcon detection on an in-house tool (MeshLink Collector) pushed by Intune,
  // which resolves to a FALSE POSITIVE. All artifacts are host-side (process/file
  // write, LocalSystem service, outbound session); the Intune/change records are
  // deployment context, not a separate identity plane. edr_scope "edr": the
  // investigation is entirely in the EDR console. The single Falcon behavioural
  // alert is the is_detection (av.verdict "clean" + estate prevalence make the FP);
  // the surrounding EDR process/file events are pivot-only telemetry.
  const INCIDENT = "inc:sifp:1";

  const events: TelemetryEvent[] = [
    // 0. The Intune Management Extension agent: a long-running service, started with the machine.
    csProcess({
      ...cx, id: "evt_sifp_00_ime_agent", ts: T(-3 * HOUR), host: host.hostname, user: "SYSTEM", srcIp: host.ip,
      processName: IME_NAME, processPath: IME_PATH, cmdline: `"${IME_PATH}"`,
      parentName: "services.exe", parentPid: 628, pid: 3096, sha256: imeHash, signed: true, signatureSubject: "Microsoft Corporation",
      runAsUser: "NT AUTHORITY\\SYSTEM", integrity: "system", severity: "informational",
      description: "Microsoft.Management.Services.IntuneWindowsAgent.exe, the Intune Management Extension service, was running on WS-ENG-4471 as NT AUTHORITY\\SYSTEM, parent services.exe.",
    }),

    // ---------------------------------------------------------------------
    // 1. A change record exists. It names a package, a ring and a window.
    //    It says nothing about any alert — it was written hours earlier.
    // ---------------------------------------------------------------------
    {
      id: "evt_sifp_01_change",
      ts: T(0),
      source: "soar",
      vendor: "ServiceNow ITSM",
      event_type: "policy_modification",
      severity: "informational",
      description:
        "Change record CHG0043912 was raised by Endpoint Engineering: deploy MeshLink Collector 2.4.1 to ENG-Workstations-Ring2 in a 21:00–23:00 window that evening.",
      raw: {
        "servicenow.table": "change_request",
        "servicenow.number": changeTicket,
        "servicenow.short_description":
          "Deploy MeshLink Collector 2.4.1 to engineering workstation ring 2",
        "servicenow.description":
          "Second-ring rollout of the in-house MeshLink Collector. Ring 1 piloted build 2.4.0; 2.4.1 is a new build with a new file hash. Package is distributed by Intune as a required app with an install deadline at the start of the window.",
        "servicenow.type": "Standard",
        "servicenow.std_change_producer_version": "Endpoint software rollout — v3",
        "servicenow.state": "Scheduled",
        "servicenow.category": "Software",
        "servicenow.risk": "Low",
        "servicenow.impact": "3 - Low",
        "servicenow.assignment_group": "Endpoint Engineering",
        "servicenow.requested_by": requester,
        "servicenow.assigned_to": requester,
        "servicenow.cmdb_ci": "Microsoft Intune — Software Distribution",
        "servicenow.u_target_group": targetGroup,
        "servicenow.u_package_name": "MeshLink Collector",
        "servicenow.u_package_version": "2.4.1",
        "servicenow.planned_start_date": "2026-06-02 21:00:00",
        "servicenow.planned_end_date": "2026-06-02 23:00:00",
        "servicenow.sys_created_on": "2026-06-02 09:14:00",
        "servicenow.sys_updated_on": "2026-06-02 09:14:00",
      },
    },

    // ---------------------------------------------------------------------
    // 2. The distribution system is told what to push, to whom, and by when.
    // ---------------------------------------------------------------------
    {
      id: "evt_sifp_02_intune_assign",
      ts: T(17 * MIN),
      source: "cloud_azure",
      vendor: "Microsoft Intune",
      event_type: "policy_modification",
      user_email: requester,
      severity: "informational",
      description:
        "MeshLink Collector 2.4.1 was assigned in Intune as a required install to ENG-Workstations-Ring2, 214 devices, with an install deadline of 21:00 UTC.",
      raw: {
        "intune.category": "Application",
        "intune.activityType": "Assign",
        "intune.activityOperationType": "Patch",
        "intune.activityResult": "Success",
        "intune.activityDateTime": T(17 * MIN),
        "intune.actor.userPrincipalName": requester,
        "intune.actor.applicationDisplayName": "Microsoft Intune Portal",
        "intune.actor.ipAddress": "10.30.12.8",
        "intune.resources.type": "MobileApp",
        "intune.targetObjectId": appId,
        "intune.targetDisplayName": "MeshLink Collector 2.4.1",
        "intune.deploymentId": deploymentId,
        "mobileApp.id": appId,
        "mobileApp.displayName": "MeshLink Collector 2.4.1",
        "mobileApp.publisher": "NexaCorp Engineering Platforms",
        "mobileApp.displayVersion": "2.4.1",
        "mobileApp.setupFilePath": "mlnk-collector-setup.exe",
        "mobileApp.installCommandLine": "mlnk-collector-setup.exe /quiet /norestart",
        "mobileApp.uninstallCommandLine": "mlnk-collector-setup.exe /uninstall /quiet",
        "mobileApp.installExperience.runAsAccount": "system",
        "mobileApp.detectionRules.path": "C:\\Program Files\\MeshLink\\bin",
        "mobileApp.detectionRules.fileOrFolderName": "mlnk-collector.exe",
        "assignment.intent": "required",
        "assignment.groupId": groupId,
        "assignment.groupDisplayName": targetGroup,
        "assignment.targetedDeviceCount": "214",
        "assignment.installTimeSettings.useLocalTime": "false",
        "assignment.installTimeSettings.deadlineDateTime": "2026-06-02T21:00:00Z",
        "assignment.restartSettings.gracePeriodInMinutes": "240",
      },
    },

    // ---------------------------------------------------------------------
    // 3. Execution. The parent process and the installer's folder are the
    //    two most important strings in this entire scenario.
    // ---------------------------------------------------------------------
    csProcess({
      ...cx, id: "evt_sifp_03_installer_run", ts: T(W), host: host.hostname, user: "SYSTEM", srcIp: host.ip,
      processName: "mlnk-collector-setup.exe", processPath: imeCachePath,
      cmdline: "mlnk-collector-setup.exe /quiet /norestart",
      parentName: IME_NAME, parentPid: 3096, pid: 7412, sha256: setupHash, signed: false,
      runAsUser: "NT AUTHORITY\\SYSTEM", integrity: "system", severity: "medium",
      description:
        "An unsigned installer, mlnk-collector-setup.exe, executed as NT AUTHORITY\\SYSTEM on WS-ENG-4471 at 21:00, parent Microsoft.Management.Services.IntuneWindowsAgent.exe.",
    }),

    // ---------------------------------------------------------------------
    // 4. AMBIGUOUS #1 — unsigned executable written into Program Files.
    // ---------------------------------------------------------------------
    csFile({
      ...cx, id: "evt_sifp_04_binary_written", ts: T(W + 38 * SEC), host: host.hostname, user: "SYSTEM", srcIp: host.ip,
      path: "C:\\Program Files\\MeshLink\\bin\\mlnk-collector.exe", sha256: binHash, size: 18_874_368, action: "file_create", signed: false,
      actorProcess: "mlnk-collector-setup.exe", actorPid: 7412, actorPath: imeCachePath, actorParentName: IME_NAME, actorParentPid: 3096,
      actorSha256: setupHash, actorSigned: "unsigned", actorIntegrity: "system", runAsUser: "NT AUTHORITY\\SYSTEM", severity: "medium",
      extra: {
        "file.directory": "C:\\Program Files\\MeshLink\\bin",
        "file.pe.company": "NexaCorp Engineering Platforms", "file.pe.description": "MeshLink Collector",
      },
      description:
        "An 18 MB executable with no Authenticode signature, mlnk-collector.exe, was written into C:\\Program Files\\MeshLink\\bin on WS-ENG-4471 by the installer process.",
    }),

    // ---------------------------------------------------------------------
    // 5. AMBIGUOUS #2 — a new auto-start service running as LocalSystem.
    // ---------------------------------------------------------------------
    {
      id: "evt_sifp_05_service_install",
      ts: T(W + 52 * SEC),
      source: "ad",
      vendor: "Windows Security",
      event_type: "service_install",
      hostname: host.hostname,
      severity: "medium",
      description:
        "The Service Control Manager on WS-ENG-4471 registered the service MeshLinkCollector, start type auto start, running as LocalSystem (Event 7045).",
      raw: {
        // Windows Event 7045 — A service was installed in the system
        "winlog.event_id": "7045",
        "winlog.channel": "System",
        "winlog.computer_name": "WS-ENG-4471.corp.nexacorp.com",
        "winlog.provider_name": "Service Control Manager",
        "winlog.record_id": "412886",
        "winlog.event_data.ServiceName": "MeshLinkCollector",
        "winlog.event_data.ImagePath":
          "\"C:\\Program Files\\MeshLink\\bin\\mlnk-collector.exe\" --service",
        "winlog.event_data.ServiceType": "user mode service",
        "winlog.event_data.StartType": "auto start",
        "winlog.event_data.AccountName": "LocalSystem",
        "event.code": "7045",
        "event.action": "service-installed",
        "event.outcome": "success",
      },
    },

    // 5b. The service starts: the process that makes the connection below.
    csProcess({
      ...cx, id: "evt_sifp_05b_service_start", ts: T(W + 53 * SEC), host: host.hostname, user: "SYSTEM", srcIp: host.ip,
      processName: "mlnk-collector.exe", processPath: "C:\\Program Files\\MeshLink\\bin\\mlnk-collector.exe",
      cmdline: "\"C:\\Program Files\\MeshLink\\bin\\mlnk-collector.exe\" --service",
      parentName: "services.exe", parentPid: 628, pid: 7560, sha256: binHash, signed: false,
      runAsUser: "NT AUTHORITY\\SYSTEM", integrity: "system", severity: "low",
      description:
        "The service MeshLinkCollector started on WS-ENG-4471: mlnk-collector.exe --service, parent services.exe, running as NT AUTHORITY\\SYSTEM.",
    }),

    // ---------------------------------------------------------------------
    // 6. Name resolution for whatever the new service is about to talk to.
    // ---------------------------------------------------------------------
    csDns({
      ...cx, id: "evt_sifp_06a_service_dns", ts: T(W + 60 * SEC), host: host.hostname, user: "SYSTEM", srcIp: host.ip,
      domain: collectorFqdn, resolvedIp: collectorIp, processName: "mlnk-collector.exe", pid: 7560,
      processPath: "C:\\Program Files\\MeshLink\\bin\\mlnk-collector.exe", parentName: "services.exe", parentPid: 628, sha256: binHash,
      severity: "low",
      description: "mlnk-collector.exe on WS-ENG-4471 requested mesh-collect.corp.nexacorp.com.",
    }),
    infobloxDns({
      id: "evt_sifp_06_dns", ts: T(W + 61 * SEC), host: host.hostname, srcIp: host.ip,
      query: collectorFqdn, answer: collectorIp, member: "DNS-CORE-02", zone: "corp.nexacorp.com",
      description:
        "WS-ENG-4471 resolved mesh-collect.corp.nexacorp.com to 10.30.9.40, answered NOERROR by the internal Infoblox view on DNS-CORE-02.",
    }),

    // ---------------------------------------------------------------------
    // 7. AMBIGUOUS #3 — the outbound connection the rule keyed on.
    // ---------------------------------------------------------------------
    csNetwork({
      ...cx, id: "evt_sifp_07a_service_conn", ts: T(W + 63 * SEC), host: host.hostname, user: "SYSTEM", srcIp: host.ip,
      remoteIp: collectorIp, remotePort: 8443, localPort: 50912, application: "tls",
      processName: "mlnk-collector.exe", pid: 7560, processPath: "C:\\Program Files\\MeshLink\\bin\\mlnk-collector.exe",
      cmdline: "\"C:\\Program Files\\MeshLink\\bin\\mlnk-collector.exe\" --service", parentName: "services.exe", parentPid: 628, sha256: binHash,
      severity: "low",
      description: "mlnk-collector.exe (pid 7560) on WS-ENG-4471 connected to 10.30.9.40 on port 8443 from local port 50912.",
    }),
    {
      id: "evt_sifp_07_connection",
      ts: T(W + 65 * SEC),
      source: "firewall",
      vendor: "Palo Alto Networks PAN-OS",
      event_type: "net_connection",
      hostname: host.hostname,
      src_ip: host.ip,
      dst_ip: collectorIp,
      dst_port: 8443,
      protocol: "tcp",
      severity: "low",
      network: { bytes_out: 3140, bytes_in: 986 },
      description:
        "A 2-second TLS session left WS-ENG-4471 for 10.30.9.40:8443, crossing from the USERS zone to SERVERS — 3,140 bytes sent, 986 received.",
      raw: {
        "pan.type": "TRAFFIC",
        "pan.subtype": "end",
        "pan.action": "allow",
        "pan.rule": "ENG-Workstations-to-Telemetry",
        "pan.src": host.ip,
        "pan.dst": collectorIp,
        "pan.sport": "50912",
        "pan.dport": "8443",
        "pan.proto": "tcp",
        "pan.app": "ssl",
        "pan.from_zone": "USERS",
        "pan.to_zone": "SERVERS",
        "pan.srcloc": "10.0.0.0-10.255.255.255",
        "pan.dstloc": "10.0.0.0-10.255.255.255",
        "pan.session_id": "2210447",
        "pan.bytes_sent": "3140",
        "pan.bytes_received": "986",
        "pan.packets": "18",
        "pan.elapsed_time": "2",
        "pan.category": "private-ip-addresses",
        action_result: "allow",
      },
    },

    // ---------------------------------------------------------------------
    // 8. THE ALARM. High. Accurate about what it saw, silent about why.
    // ---------------------------------------------------------------------
    {
      ...csAlert({
        ...cx, id: "evt_sifp_08_edr_alert", ts: T(W + 70 * SEC), host: host.hostname, user: "SYSTEM", srcIp: host.ip,
        threatName: "SuspiciousInstallChain",
        detail: "An unsigned executable was written to a protected program directory, registered an auto-start service running as LocalSystem, and initiated an outbound network session within seventy seconds of first execution.",
        action: "detected", severity: "high", isDetection: true, runAsUser: "NT AUTHORITY\\SYSTEM",
        processName: "mlnk-collector-setup.exe", processPath: imeCachePath, cmdline: "mlnk-collector-setup.exe /quiet /norestart",
        sha256: setupHash, pid: 7412,
        parentPath: `C:\\Program Files (x86)\\Microsoft Intune Management Extension\\${IME_NAME}`,
        extra: { "crowdstrike.PatternId": "41277", "crowdstrike.PatternDispositionValue": "10" },
        description:
          "Falcon raised a HIGH behavioural detection on WS-ENG-4471 — unsigned write to Program Files, LocalSystem service, network session within seventy seconds. Disposition: Detection, No Action.",
      }),
      edr_scope: "edr",   // endpoint-only incident → investigated entirely in the EDR console
    },

    // ---------------------------------------------------------------------
    // 9. The distribution system's own view of THIS host.
    // ---------------------------------------------------------------------
    {
      id: "evt_sifp_09_install_status",
      ts: T(W + 4 * MIN),
      source: "cloud_azure",
      vendor: "Microsoft Intune",
      event_type: "cloud_api_call",
      hostname: host.hostname,
      user_email: primaryUser,
      severity: "informational",
      description:
        "The Intune device install-status report lists WS-ENG-4471 under deployment DPL-40218: installState installed, errorCode 0, assigned group ENG-Workstations-Ring2.",
      raw: {
        "intune.report": "DeviceInstallStatusByApp",
        "intune.appId": appId,
        "intune.appDisplayName": "MeshLink Collector 2.4.1",
        "intune.appVersion": "2.4.1",
        "intune.deploymentId": deploymentId,
        "intune.deviceName": host.hostname,
        "intune.deviceId": "f21c8a0e-45db-4b77-9c31-6ea0d5382b19",
        "intune.userPrincipalName": primaryUser,
        "intune.platform": "Windows",
        "intune.osVersion": "10.0.22631.4317",
        "intune.assignedGroupId": groupId,
        "intune.assignedGroupDisplayName": targetGroup,
        "intune.installIntent": "required",
        "intune.installState": "installed",
        "intune.installStateDetail": "noAdditionalDetails",
        "intune.errorCode": "0",
        "intune.lastSyncDateTime": T(W + 4 * MIN),
        "intune.complianceState": "compliant",
      },
    },

    // ---------------------------------------------------------------------
    // 10. Prevalence review — how the same file behaved across the estate.
    //     Aggregates belong here, at the SIEM, not inside a device log.
    // ---------------------------------------------------------------------
    {
      id: "evt_sifp_10_prevalence",
      ts: T(W + 9 * MIN),
      source: "siem",
      vendor: "Microsoft Sentinel",
      event_type: "ueba_anomaly",
      hostname: host.hostname,
      severity: "medium",
      description:
        "Sentinel ran an estate-wide prevalence review of the mlnk-collector.exe hash: 197 hosts carry it, all inside ENG-Workstations-Ring2, with zero anti-malware detections across vendors.",
      raw: {
        "AlertName": "NewBinaryPrevalenceReview",
        "alert.rule.id": "SEN-END-0187",
        "file.name": "mlnk-collector.exe",
        "file.hash.sha256": binHash,
        "ExtendedProperties.Window Start": T(W),
        "ExtendedProperties.Window End": T(W + 9 * MIN),
        "ExtendedProperties.First Seen In Tenant": T(W),
        "ExtendedProperties.Distinct Hosts With Hash": 197,
        "ExtendedProperties.Host Groups Of Matching Hosts": [targetGroup],
        "ExtendedProperties.Hosts Outside That Group": 0,
        "ExtendedProperties.AV Detections Across Vendors": 0,
        "ExtendedProperties.Threat Intel Matches": 0,
        "ExtendedProperties.New Run Keys Count": 0,
        "ExtendedProperties.New Scheduled Tasks Count": 0,
        "ExtendedProperties.Credential Access Events": 0,
        "ExtendedProperties.Remote Logons Initiated Count": 0,
        "ExtendedProperties.LSASS Access Events": 0,
        "ExtendedProperties.External Destinations Contacted": [],
        "ExtendedProperties.Internal Destinations Contacted": [`${collectorIp}:8443`],
        "event.action": "correlation-review",
        "event.outcome": "reviewed",
      },
    },
  ];

  // Every event belongs to the one behavioural-detection investigation (correlation
  // key; also lets the EDR console build a single isolated case for it).
  for (const e of events) e.incident_id = INCIDENT;

  const iocs: IOC[] = [
    {
      type: "host",
      value: host.hostname,
      first_seen: T(W),
      last_seen: T(W + 9 * MIN),
      reputation: "clean",
      tags: ["engineering-workstation", "alert-source"],
    },
    {
      type: "sha256",
      value: setupHash,
      first_seen: T(W),
      last_seen: T(W + 70 * SEC),
      reputation: "clean",
      tags: ["unsigned", "installer", "management-agent-cache"],
    },
    {
      type: "sha256",
      value: binHash,
      first_seen: T(W + 38 * SEC),
      last_seen: T(W + 9 * MIN),
      reputation: "clean",
      tags: ["unsigned", "program-files", "service-image"],
    },
    {
      type: "ip",
      value: collectorIp,
      first_seen: T(W + 61 * SEC),
      last_seen: T(W + 65 * SEC),
      reputation: "clean",
      tags: ["internal", "rfc1918", "tls-8443"],
    },
    {
      type: "domain",
      value: collectorFqdn,
      first_seen: T(W + 61 * SEC),
      last_seen: T(W + 61 * SEC),
      reputation: "clean",
      tags: ["internal-zone"],
    },
    {
      type: "user",
      value: primaryUser,
      first_seen: T(W),
      last_seen: T(W + 4 * MIN),
      reputation: "clean",
      tags: ["device-primary-user"],
    },
  ];

  const questions: ScenarioQuestion[] = [
    {
      id: "q1",
      prompt:
        "Which PAIR of events, read together, shows the installer was handed to this machine by the software-distribution system rather than downloaded or dropped on it?",
      hint: "One event shows what launched the installer and from which folder; the other shows the distribution system reporting on this exact device.",
      kind: "single",
      options: [
        {
          value: "proc_status",
          label:
            "The installer launch + the Intune install-status report — a management-agent parent and cache folder, plus a matching device record",
        },
        {
          value: "file_service",
          label:
            "The Program Files write + the service registration — an unsigned binary placed on disk and then set to auto-start as LocalSystem",
        },
        {
          value: "dns_conn",
          label:
            "The DNS lookup + the outbound connection — the collector hostname resolved and a short TLS session opened to it straight after",
        },
        {
          value: "alert_prev",
          label:
            "The Falcon detection + the prevalence review — the behavioural alert and the estate-wide Sentinel hash query that followed it",
        },
      ],
      answer: "proc_status",
      xp: 50,
      explanation:
        "The process record shows mlnk-collector-setup.exe launched by Microsoft.Management.Services.IntuneWindowsAgent.exe, running out of C:\\Windows\\IMECache — the management extension's own download cache, which nothing else writes to. The install-status record then shows WS-ENG-4471 reporting back under deployment DPL-40218 with installState installed and errorCode 0. One says how it arrived, the other says the system that sent it knows this device by name. Pair (b) is the behaviour that fired the alert, so it cannot resolve it. Pair (c) tells you where it talked, not where it came from. Pair (d) is the alarm and its follow-up query.",
    },
    {
      id: "q2",
      prompt:
        "The change record names a package, a group and a window. What in the host telemetry actually corroborates it, rather than merely sitting next to it?",
      hint: "A ticket is only corroboration when something independent lines up with all of its specifics.",
      kind: "single",
      options: [
        {
          value: "all_three",
          label:
            "Execution at the 21:00 deadline, of the version named in the ticket, on a device the report places in ENG-Workstations-Ring2",
        },
        {
          value: "ticket_state",
          label:
            "The record is a Standard change in Scheduled state, raised that morning by the Endpoint Engineering group that owns workstations",
        },
        {
          value: "same_day",
          label:
            "The change was created the same day as the detection, which places the ticket and the alert inside one operational window",
        },
        {
          value: "pe_metadata",
          label:
            "The binary's PE metadata names the same company and product as the package in the change record, with a matching description",
        },
      ],
      answer: "all_three",
      xp: 60,
      explanation:
        "A ticket is a statement of intent; corroboration means independent records agreeing with its specifics. Three do: the installer ran at 21:00, which is the deadlineDateTime on the assignment and the planned start on the change; the version in the PE metadata, the assignment and the ticket is 2.4.1; and the install-status report places WS-ENG-4471 in ENG-Workstations-Ring2, the group the ticket targets. Option (b) is only the ticket describing itself. Option (c) is a coincidence of dates and would be true of an intrusion on a busy change day. Option (d) is real supporting evidence but PE company and product strings are attacker-controlled text — on its own it proves nothing.",
    },
    {
      id: "q3",
      prompt:
        "The binary is unsigned, which is the alert's strongest single point. Which finding most reduces the weight of that fact here?",
      kind: "single",
      options: [
        {
          value: "prevalence",
          label:
            "The same hash appeared on 197 hosts, all inside one device group, in one window, with no engine detecting it",
        },
        {
          value: "programfiles",
          label:
            "The file was written under C:\\Program Files, a protected directory that ordinary user processes and user-level droppers cannot write to",
        },
        {
          value: "system_ctx",
          label:
            "The whole chain ran as NT AUTHORITY\\SYSTEM, so no user account or interactive session was involved at any point",
        },
        {
          value: "no_block",
          label:
            "Falcon recorded the detection as 'Detection, No Action', indicating the sensor judged the behaviour not worth stopping",
        },
      ],
      answer: "prevalence",
      xp: 60,
      explanation:
        "Targeted intrusions do not arrive simultaneously on 197 machines that all happen to be members of one device group, and Sentinel counted zero hosts with that hash outside the group. Add zero anti-malware detections across vendors, zero threat-intel matches, no Run keys, no scheduled tasks, no LSASS access and no remote logons, and the unsigned binary stops looking like a dropper and starts looking like an in-house build. Option (b) shows the writer was privileged, which malware running as SYSTEM also is. Option (c) is the same observation restated, and running as SYSTEM makes things worse, not better. Option (d) is a common and dangerous misreading — 'Detection, No Action' is a policy setting, never a safety judgement.",
    },
    {
      id: "q4",
      prompt:
        "You are closing this as a false positive. Which finding, had it been present in the same telemetry, should have kept it open as an incident?",
      hint: "Ask what a genuine deployment can never look like.",
      kind: "single",
      options: [
        {
          value: "off_group_external",
          label:
            "The hash on hosts outside the assigned group, and the service session reaching a public internet address",
        },
        {
          value: "unsigned_system",
          label:
            "An unsigned executable installing an auto-start LocalSystem service with the whole chain running as SYSTEM",
        },
        {
          value: "late_hour",
          label:
            "The whole chain running at 21:00, well outside the hours the engineering team is normally working at their desks",
        },
        {
          value: "short_session",
          label:
            "The new service opening a TLS session only seconds after being registered, before any user activity",
        },
      ],
      answer: "off_group_external",
      xp: 70,
      explanation:
        "Those two facts have no benign reading together. A required-app assignment reaches the devices in its group and no others, so a hash on machines outside ENG-Workstations-Ring2 means something is spreading by another route; and the telemetry here shows the service talking only to 10.30.9.40 on 8443, an RFC1918 address resolved from the internal corp.nexacorp.com zone, in a session that never left the SERVERS zone. Swap that for a public destination and you have a candidate command channel. Options (b), (c) and (d) are all present in this incident and all fully explained: the package is an internal build, 21:00 is the deadline on the assignment, and an agent that starts and immediately checks in is doing its job. Write the closure the same way: name the deployment, the ticket, the parent process and the prevalence result, and name the finding that would have changed your mind.",
    },
  ];

  return {
    scenario_id: scenarioId,
    title: "Behavioural EDR alert on an engineering workstation",
    threat_actor: "None — benign software deployment activity",
    attack_kind: "false_positive",
    briefing:
      "CrowdStrike Falcon raised a HIGH behavioural detection on engineering workstation WS-ENG-4471 at 21:01: an unsigned executable written into Program Files, a new service running as LocalSystem, and an outbound network session, all within seventy seconds. Nothing was blocked. Determine what ran on the host and whether the workstation needs to be contained.",
    narrative: `At 21:01 CrowdStrike Falcon fires a HIGH detection on WS-ENG-4471, an engineering workstation. In the seventy seconds before it, an unsigned executable was written into C:\\Program Files\\MeshLink\\bin, a service called MeshLinkCollector was registered to auto-start as LocalSystem, and the host opened a TLS session — with no user process anywhere in the chain. Read on its own, that chain is a competent dropper, and the reflex is to isolate the machine.

The correct verdict here is that there is no incident, and reaching it takes more work than escalating would have. Four records that were never written to explain each other have to be lined up.

The first is a change record, CHG0043912, cut that morning by e.shani in Endpoint Engineering: push MeshLink Collector 2.4.1 to ring 2 of the engineering workstations, in a window from 21:00 to 23:00. The second is the Intune assignment made seventeen minutes later — the same package name, the same version, targeted at the group ENG-Workstations-Ring2 as a required install with a deadline of exactly 21:00, covering 214 devices, installing as system with the silent command line mlnk-collector-setup.exe /quiet /norestart.

The third is the process record itself. mlnk-collector-setup.exe did not appear from a browser download or a share. Its parent is Microsoft.Management.Services.IntuneWindowsAgent.exe, and it ran from C:\\Windows\\IMECache — the management extension's private download cache, which nothing but the agent populates. It ran at 21:00, the deadline on the assignment. The fourth is the install-status report four minutes later: WS-ENG-4471, deployment DPL-40218, member of ENG-Workstations-Ring2, installState installed, errorCode 0.

Two further checks close the remaining gaps. The connection that helped fire the rule was opened by the new service process itself, mlnk-collector.exe (pid 7560, local port 50912, the same port the firewall logged), and went to 10.30.9.40 on port 8443, an address the host resolved for mesh-collect.corp.nexacorp.com out of the internal authoritative zone — a private address, on an internal firewall rule, in a session that crossed from USERS to SERVERS and never touched the internet. And the estate-wide prevalence review found mlnk-collector.exe on 197 hosts, every one of them inside ENG-Workstations-Ring2 and none outside it, first seen in the tenant during that window, with no anti-malware detection from any vendor, no threat-intelligence match, no Run keys, no scheduled tasks, no credential access and no remote logons.

The unsigned binary is a real finding and belongs in the closure note as a recommendation: an internally built agent that installs as LocalSystem should be code-signed, so that the next ring does not cost the SOC another investigation. But the alert itself is a true description of behaviour and a false description of intent. Close it, cite CHG0043912, the deployment DPL-40218, the IntuneWindowsAgent.exe parent and the prevalence result, and record that a hash outside the assigned group or an external destination would have changed the verdict.`,
    learning_objectives: [
      "Close an alert as benign on positive evidence you gathered, and cite that evidence as rigorously as you would cite evidence of compromise",
      "Use parent process and install path — a management-agent parent running from its own download cache — to establish how a binary reached a host",
      "Corroborate a change record against independent telemetry on timing, version and target group instead of accepting the ticket at face value",
      "Read prevalence as evidence: one hash arriving across a single device group in one window, with no detections anywhere, does not describe a targeted intrusion",
      "Distinguish an internal destination on a private address from an external callout before treating a connection as command and control, and record in the closure which finding would have flipped the verdict",
    ],
    // alerts are attached by the catalogue wiring
    alerts: [],
    events,
    iocs,
    killchain: [
      { ts: T(0), phase: "Planned Change", action: `${changeTicket} raised — MeshLink Collector 2.4.1 to ${targetGroup}, 21:00–23:00 window` },
      { ts: T(17 * MIN), phase: "Distribution", action: `Intune assignment ${deploymentId} — required install, deadline 21:00, 214 devices` },
      { ts: T(W), phase: "Execution", action: "IntuneWindowsAgent.exe launches mlnk-collector-setup.exe from C:\\Windows\\IMECache as SYSTEM" },
      { ts: T(W + 38 * SEC), phase: "File Write", action: "Unsigned mlnk-collector.exe written to C:\\Program Files\\MeshLink\\bin" },
      { ts: T(W + 52 * SEC), phase: "Service Created", action: "MeshLinkCollector registered auto-start as LocalSystem (Event 7045)" },
      { ts: T(W + 53 * SEC), phase: "Service Start", action: "mlnk-collector.exe --service starts under services.exe as SYSTEM" },
      { ts: T(W + 63 * SEC), phase: "Check-in", action: "mlnk-collector.exe opens a TLS session to 10.30.9.40:8443, internal zone, USERS to SERVERS" },
      { ts: T(W + 70 * SEC), phase: "Detection", action: "Falcon fires HIGH behavioural detection — Detection, No Action" },
      { ts: T(W + 4 * MIN), phase: "Verification", action: `${deploymentId} reports WS-ENG-4471 installed, errorCode 0, in ${targetGroup}` },
      { ts: T(W + 9 * MIN), phase: "Prevalence", action: "197 hosts with the same hash, all inside the group, zero detections anywhere" },
    ],
    questions,
  };
}
