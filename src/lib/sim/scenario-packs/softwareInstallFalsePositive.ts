/**
 * Scenario pack: "Dropper Behaviour Alert — Engineering Workstation"
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

  const collectorFqdn = "mesh-collect.corp.nexacorp.com";
  const collectorIp = "10.30.9.40";

  const events: TelemetryEvent[] = [
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
        "A change record was raised by Endpoint Engineering to push version 2.4.1 of an internal telemetry collector to a named ring of engineering workstations, in a two-hour window that evening. Note the package name, the target group and the exact planned window — you will need all three later.",
      raw: {
        "servicenow.table": "change_request",
        "servicenow.number": changeTicket,
        "servicenow.short_description":
          "Deploy MeshLink Collector 2.4.1 to engineering workstation ring 2",
        "servicenow.description":
          "Second-ring rollout of the in-house MeshLink Collector build. Package is distributed by Intune as a required app with an install deadline at the start of the window.",
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
        "In the Intune console, an application was assigned as a required install to a device group, with an install deadline that evening. The record carries the publisher, the version, the silent install command line and how many devices the group contains.",
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
    {
      id: "evt_sifp_03_installer_run",
      ts: T(W),
      source: "edr",
      vendor: "CrowdStrike Falcon",
      event_type: "process_create",
      hostname: host.hostname,
      user_email: primaryUser,
      src_ip: host.ip,
      severity: "medium",
      description:
        "An unsigned installer executed as SYSTEM on WS-ENG-4471 at 21:00. Nobody was logged on interactively. Read the parent process and the folder the installer ran from — both of them tell you where the file came from.",
      process: {
        name: "mlnk-collector-setup.exe",
        pid: 7412,
        path: `C:\\Windows\\IMECache\\{${appId}}\\mlnk-collector-setup.exe`,
        parent_name: "Microsoft.Management.Services.IntuneWindowsAgent.exe",
        parent_pid: 3096,
        cmdline: "mlnk-collector-setup.exe /quiet /norestart",
        user: "NT AUTHORITY\\SYSTEM",
        integrity: "system",
        hash: { sha256: setupHash },
      },
      raw: {
        "crowdstrike.event_simplename": "ProcessRollup2",
        "crowdstrike.sensor.id": "7a1c53e9b0d24f68a35c1e70bd94f2a6",
        "crowdstrike.customer_id": "2b8f4d61c07e49a3b52f81d6a9c30e74",
        "event.action": "process_created",
        "process.name": "mlnk-collector-setup.exe",
        "process.pid": "7412",
        "process.executable": `C:\\Windows\\IMECache\\{${appId}}\\mlnk-collector-setup.exe`,
        "process.command_line": "mlnk-collector-setup.exe /quiet /norestart",
        "process.hash.sha256": setupHash,
        "process.parent.name": "Microsoft.Management.Services.IntuneWindowsAgent.exe",
        "process.parent.pid": "3096",
        "process.parent.executable":
          "C:\\Program Files (x86)\\Microsoft Intune Management Extension\\Microsoft.Management.Services.IntuneWindowsAgent.exe",
        "process.parent.user.name": "NT AUTHORITY\\SYSTEM",
        "user.name": "NT AUTHORITY\\SYSTEM",
        "host.name": host.hostname,
        "host.ip": host.ip,
        "file.signed": "false",
        "file.code_signature.status": "unsigned",
        "file.code_signature.subject_name": "",
        "process.integrity_level": "System",
        "user.session.interactive": "false",
        action_result: "allowed",
      },
    },

    // ---------------------------------------------------------------------
    // 4. AMBIGUOUS #1 — unsigned executable written into Program Files.
    // ---------------------------------------------------------------------
    {
      id: "evt_sifp_04_binary_written",
      ts: T(W + 38 * SEC),
      source: "edr",
      vendor: "CrowdStrike Falcon",
      event_type: "file_create",
      hostname: host.hostname,
      user_email: primaryUser,
      severity: "high",
      description:
        "An 18 MB executable with no Authenticode signature was written into C:\\Program Files\\MeshLink\\bin on WS-ENG-4471 by the installer process. An unsigned binary landing in a protected program directory is a genuine reason to look closer — it is not by itself a reason to conclude anything.",
      file: {
        path: "C:\\Program Files\\MeshLink\\bin\\mlnk-collector.exe",
        name: "mlnk-collector.exe",
        extension: "exe",
        sha256: binHash,
        size: 18_874_368,
      },
      raw: {
        "crowdstrike.event_simplename": "NewExecutableWritten",
        "crowdstrike.sensor.id": "7a1c53e9b0d24f68a35c1e70bd94f2a6",
        "event.action": "file_created",
        "file.name": "mlnk-collector.exe",
        "file.path": "C:\\Program Files\\MeshLink\\bin\\mlnk-collector.exe",
        "file.directory": "C:\\Program Files\\MeshLink\\bin",
        "file.size": "18874368",
        "file.hash.sha256": binHash,
        "file.signed": "false",
        "file.code_signature.status": "unsigned",
        "file.code_signature.subject_name": "",
        "file.pe.company": "NexaCorp Engineering Platforms",
        "file.pe.product": "MeshLink Collector",
        "file.pe.file_version": "2.4.1.0",
        "process.name": "mlnk-collector-setup.exe",
        "process.pid": "7412",
        "process.executable": `C:\\Windows\\IMECache\\{${appId}}\\mlnk-collector-setup.exe`,
        "user.name": "NT AUTHORITY\\SYSTEM",
        "host.name": host.hostname,
        action_result: "allowed",
      },
    },

    // ---------------------------------------------------------------------
    // 5. AMBIGUOUS #2 — a new auto-start service running as LocalSystem.
    // ---------------------------------------------------------------------
    {
      id: "evt_sifp_05_service_install",
      ts: T(W + 52 * SEC),
      source: "windows_security",
      vendor: "Windows Security",
      event_type: "service_install",
      hostname: host.hostname,
      severity: "high",
      description:
        "The Service Control Manager on WS-ENG-4471 registered a new service that starts automatically at boot and runs as LocalSystem. Persistence plus the highest local account is exactly the pair that a dropper wants — and also exactly what an agent-style product needs.",
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

    // ---------------------------------------------------------------------
    // 6. Name resolution for whatever the new service is about to talk to.
    // ---------------------------------------------------------------------
    {
      id: "evt_sifp_06_dns",
      ts: T(W + 61 * SEC),
      source: "dns",
      vendor: "Infoblox DNS",
      event_type: "dns_query",
      hostname: host.hostname,
      src_ip: host.ip,
      severity: "informational",
      dns: {
        query: collectorFqdn,
        query_type: "A",
        response: collectorIp,
        rcode: "NOERROR",
      },
      description:
        "WS-ENG-4471 resolved a hostname immediately after the service was registered. Look at which DNS zone answered and what address came back before deciding whether this is a callout worth worrying about.",
      raw: {
        "dns.question.name": collectorFqdn,
        "dns.question.type": "A",
        "dns.question.class": "IN",
        "dns.answers.data": collectorIp,
        "dns.answers.ttl": "300",
        "dns.response_code": "NOERROR",
        "dns.resolved_ip": collectorIp,
        "infoblox.view": "internal",
        "infoblox.zone": "corp.nexacorp.com",
        "infoblox.zone_type": "authoritative",
        "infoblox.member": "DNS-CORE-02",
        "infoblox.rpz_policy": "",
        "source.ip": host.ip,
        "event.action": "dns-query",
        "event.outcome": "success",
      },
    },

    // ---------------------------------------------------------------------
    // 7. AMBIGUOUS #3 — the outbound connection the rule keyed on.
    // ---------------------------------------------------------------------
    {
      id: "evt_sifp_07_connection",
      ts: T(W + 63 * SEC),
      source: "firewall",
      vendor: "Palo Alto Networks PAN-OS",
      event_type: "net_connection",
      hostname: host.hostname,
      src_ip: host.ip,
      dst_ip: collectorIp,
      dst_port: 8443,
      protocol: "tcp",
      severity: "medium",
      network: { bytes_out: 3140, bytes_in: 986 },
      description:
        "A short TLS session left WS-ENG-4471 seconds after the service was created. Check the destination address and which firewall zones the session crossed — 'made a network connection' is not the same finding as 'called out to the internet'.",
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
      id: "evt_sifp_08_edr_alert",
      ts: T(W + 70 * SEC),
      source: "edr",
      vendor: "CrowdStrike Falcon",
      event_type: "edr_alert",
      hostname: host.hostname,
      user_email: primaryUser,
      severity: "high",
      description:
        "CrowdStrike Falcon raised a HIGH behavioural detection on WS-ENG-4471: an unsigned executable written to a protected program directory, a LocalSystem service registered from it, and a network connection opened, all inside seventy seconds. The detection took no action — nothing was blocked, killed or quarantined.",
      raw: {
        "crowdstrike.event_simplename": "DetectionSummaryEvent",
        "crowdstrike.detection.id": "ldt:7a1c53e9b0d24f68a35c1e70bd94f2a6:5510884213",
        "crowdstrike.detection.description":
          "An unsigned executable was written to a protected program directory, registered an auto-start service running as LocalSystem, and initiated an outbound network session within seventy seconds of first execution.",
        "crowdstrike.detection.scenario": "suspicious_install_chain",
        "crowdstrike.detection.severity": "High",
        "crowdstrike.detection.pattern_id": "41277",
        "crowdstrike.detection.pattern_disposition": "10",
        "crowdstrike.detection.pattern_disposition_description": "Detection, No Action",
        "crowdstrike.behaviors":
          "Unsigned binary written to Program Files|Auto-start service created with LocalSystem account|Network session opened within 70 seconds of first execution|Chain executed with no interactive logon",
        "crowdstrike.sensor.id": "7a1c53e9b0d24f68a35c1e70bd94f2a6",
        "crowdstrike.network_containment_state": "Not Contained",
        "crowdstrike.detection.status": "new",
        "process.name": "mlnk-collector-setup.exe",
        "process.hash.sha256": setupHash,
        "file.hash.sha256": binHash,
        "host.name": host.hostname,
        "host.ip": host.ip,
        action_result: "detected",
      },
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
        "The device install-status report for the application lists WS-ENG-4471 with an install state and an error code, together with the group the device is a member of and the deployment it was pulled in by. This is the record that ties a specific machine to a specific rollout.",
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
        "Sentinel widened the question from one machine to the whole estate: where else this file appeared, when it first appeared, which device groups those machines belong to, what else the file did on them, and whether any anti-malware engine anywhere has an opinion about it.",
      raw: {
        "siem.rule_name": "NewBinaryPrevalenceReview",
        "siem.rule_id": "SEN-END-0187",
        "siem.window_start": T(W),
        "siem.window_end": T(W + 9 * MIN),
        "siem.file_name": "mlnk-collector.exe",
        "siem.file_sha256": binHash,
        "siem.first_seen_in_tenant": T(W),
        "siem.distinct_hosts_with_hash": 197,
        "siem.host_groups_of_matching_hosts": [targetGroup],
        "siem.hosts_outside_that_group": 0,
        "siem.av_detections_across_vendors": 0,
        "siem.threat_intel_matches": 0,
        "siem.new_run_keys_count": 0,
        "siem.new_scheduled_tasks_count": 0,
        "siem.credential_access_events": 0,
        "siem.remote_logons_initiated_count": 0,
        "siem.lsass_access_events": 0,
        "siem.external_destinations_contacted": [],
        "siem.internal_destinations_contacted": [`${collectorIp}:8443`],
        "event.action": "correlation-review",
        "event.outcome": "reviewed",
      },
    },
  ];

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
      reputation: "unknown",
      tags: ["unsigned", "installer", "management-agent-cache"],
    },
    {
      type: "sha256",
      value: binHash,
      first_seen: T(W + 38 * SEC),
      last_seen: T(W + 9 * MIN),
      reputation: "unknown",
      tags: ["unsigned", "program-files", "service-image"],
    },
    {
      type: "ip",
      value: collectorIp,
      first_seen: T(W + 61 * SEC),
      last_seen: T(W + 63 * SEC),
      reputation: "clean",
      tags: ["internal", "rfc1918", "tls-8443"],
    },
    {
      type: "domain",
      value: collectorFqdn,
      first_seen: T(W + 61 * SEC),
      last_seen: T(W + 61 * SEC),
      reputation: "clean",
      tags: ["internal-zone", "authoritative"],
    },
    {
      type: "user",
      value: primaryUser,
      first_seen: T(W),
      last_seen: T(W + 4 * MIN),
      reputation: "clean",
      tags: ["device-primary-user", "not-logged-on"],
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
            "evt_sifp_03_installer_run + evt_sifp_09_install_status — management-agent parent and cache folder, plus a matching device record",
        },
        {
          value: "file_service",
          label:
            "evt_sifp_04_binary_written + evt_sifp_05_service_install — an unsigned binary placed on disk and then registered as a service",
        },
        {
          value: "dns_conn",
          label:
            "evt_sifp_06_dns + evt_sifp_07_connection — a hostname resolved and a short TLS session opened straight afterwards",
        },
        {
          value: "alert_prev",
          label:
            "evt_sifp_08_edr_alert + evt_sifp_10_prevalence — the behavioural detection and the estate-wide review that followed it",
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
            "The record is a Standard change in Scheduled state, raised by the Endpoint Engineering group that owns workstations",
        },
        {
          value: "same_day",
          label:
            "The change was created the same day as the detection, which puts the two records in the same operational window",
        },
        {
          value: "pe_metadata",
          label:
            "The binary's PE metadata names the same company and product as the package described in the change record",
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
            "The file was written under C:\\Program Files, a directory ordinary user processes cannot write to",
        },
        {
          value: "system_ctx",
          label:
            "The whole chain ran as NT AUTHORITY\\SYSTEM, so no ordinary user account was involved at any point",
        },
        {
          value: "no_block",
          label:
            "Falcon recorded the detection with no action taken, indicating the sensor did not consider it worth stopping",
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
            "An unsigned executable installing a LocalSystem service while no user was logged on to the workstation",
        },
        {
          value: "late_hour",
          label:
            "The whole chain running at 21:00, outside the hours the engineering team is normally at their desks",
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
    title: "Dropper Behaviour Alert — Engineering Workstation",
    threat_actor: "None — benign software deployment activity",
    attack_kind: "false_positive",
    briefing:
      "CrowdStrike Falcon raised a HIGH behavioural detection on engineering workstation WS-ENG-4471 at 21:01: an unsigned executable written into Program Files, a new service running as LocalSystem, and an outbound network session, all within seventy seconds. Nothing was blocked. Determine what ran on the host and whether the workstation needs to be contained.",
    narrative: `At 21:01 CrowdStrike Falcon fires a HIGH detection on WS-ENG-4471, an engineering workstation. In the seventy seconds before it, an unsigned executable was written into C:\\Program Files\\MeshLink\\bin, a service called MeshLinkCollector was registered to auto-start as LocalSystem, and the host opened a TLS session — with nobody logged on interactively. Read on its own, that chain is a competent dropper, and the reflex is to isolate the machine.

The correct verdict here is that there is no incident, and reaching it takes more work than escalating would have. Four records that were never written to explain each other have to be lined up.

The first is a change record, CHG0043912, cut that morning by e.shani in Endpoint Engineering: push MeshLink Collector 2.4.1 to ring 2 of the engineering workstations, in a window from 21:00 to 23:00. The second is the Intune assignment made seventeen minutes later — the same package name, the same version, targeted at the group ENG-Workstations-Ring2 as a required install with a deadline of exactly 21:00, covering 214 devices, installing as system with the silent command line mlnk-collector-setup.exe /quiet /norestart.

The third is the process record itself. mlnk-collector-setup.exe did not appear from a browser download or a share. Its parent is Microsoft.Management.Services.IntuneWindowsAgent.exe, and it ran from C:\\Windows\\IMECache — the management extension's private download cache, which nothing but the agent populates. It ran at 21:00, the deadline on the assignment. The fourth is the install-status report four minutes later: WS-ENG-4471, deployment DPL-40218, member of ENG-Workstations-Ring2, installState installed, errorCode 0.

Two further checks close the remaining gaps. The connection that helped fire the rule went to 10.30.9.40 on port 8443, an address the host resolved for mesh-collect.corp.nexacorp.com out of the internal authoritative zone — a private address, on an internal firewall rule, in a session that crossed from USERS to SERVERS and never touched the internet. And the estate-wide prevalence review found mlnk-collector.exe on 197 hosts, every one of them inside ENG-Workstations-Ring2 and none outside it, first seen in the tenant during that window, with no anti-malware detection from any vendor, no threat-intelligence match, no Run keys, no scheduled tasks, no credential access and no remote logons.

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
      { ts: T(W + 63 * SEC), phase: "Check-in", action: "TLS session to 10.30.9.40:8443, internal zone, USERS to SERVERS" },
      { ts: T(W + 70 * SEC), phase: "Detection", action: "Falcon fires HIGH behavioural detection — Detection, No Action" },
      { ts: T(W + 4 * MIN), phase: "Verification", action: `${deploymentId} reports WS-ENG-4471 installed, errorCode 0, in ${targetGroup}` },
      { ts: T(W + 9 * MIN), phase: "Prevalence", action: "197 hosts with the same hash, all inside the group, zero detections anywhere" },
    ],
    questions,
  };
}
