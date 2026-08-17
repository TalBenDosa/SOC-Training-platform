/**
 * Scenario pack: "Slow Laptop — Coinminer Bundled with a Video Converter"
 *
 * BEGINNER tier. One user, one laptop, no lateral movement, no credential theft.
 * This one starts life as a service-desk ticket rather than a security alert:
 * a machine is slow and the fans never stop. It is the most common way a real
 * junior analyst first meets malware.
 *
 * The teaching point is what "impact" means. Nothing was stolen, no account was
 * touched, and every reflex an analyst has for grading severity — data at risk,
 * accounts compromised, lateral movement — returns nothing. The impact is that
 * the organisation's compute is being spent on someone else's behalf (T1496),
 * on a laptop that is also running the finance team's month-end close. Analysts
 * who score severity purely by "what did they take" will file this as low and
 * leave it running for weeks.
 *
 * NOTE: `difficulty: "beginner"` is declared on the SCENARIOS registry entry in
 * scenarios.ts (ScenarioBundle itself carries no difficulty field).
 */

import type { ScenarioBundle, TelemetryEvent, IOC, ScenarioQuestion } from "@/lib/sim/types";
import { makeSha256 } from "@/lib/sim/iocs";

export function buildBundledCryptominerScenario(
  scenarioId = "bundled-cryptominer-2026",
): ScenarioBundle {
  const B = new Date("2026-07-09T17:52:00Z").getTime();
  const T = (ms: number) => new Date(B + ms).toISOString();
  const MIN = 60_000;
  const HOUR = 60 * MIN;

  const host = { hostname: "LAP-1806", ip: "10.14.28.77" };
  const victim = { email: "o.mizrahi@nexacorp.com", name: "Oren Mizrahi", sam: "o.mizrahi" };

  const downloadSite = "videoconvert-pro.net";
  const pool = "eu1.pool-relay-mining.com";

  const installerHash = makeSha256("videoconvert_pro_setup_bundled_miner_2026");
  const minerHash     = makeSha256("svchost_helper_xmrig_variant_2026");
  const schtasksHash  = makeSha256("windows_system32_schtasks_exe_signed_microsoft");

  const events: TelemetryEvent[] = [
    // ---------------------------------------------------------------------
    // 1. The download, at the end of the working day.
    // ---------------------------------------------------------------------
    {
      id: "evt_bcm_01_download",
      ts: T(0),
      source: "firewall",
      vendor: "Palo Alto Networks PAN-OS",
      event_type: "http_request",
      hostname: host.hostname,
      user_email: victim.email,
      user_title: "Marketing Manager",
      src_ip: host.ip,
      severity: "low",
      description:
        "LAP-1806 downloaded VideoConvertPro_Setup.exe from videoconvert-pro.net at 17:52, allowed under the category shareware-and-freeware.",
      file: { name: "VideoConvertPro_Setup.exe", path: "/get/VideoConvertPro_Setup.exe", extension: "exe", size: 42_991_616, sha256: installerHash },
      network: {
        url: `https://${downloadSite}/get/VideoConvertPro_Setup.exe`,
        domain: downloadSite,
        method: "GET",
        status: 200,
        bytes_in: 42_991_616,
      },
      raw: {
        "pan.type": "THREAT",
        "pan.subtype": "file",
        "pan.action": "alert",
        "pan.rule": "CORP-WEB-OUTBOUND",
        "pan.src": host.ip,
        "pan.srcuser": `nexacorp\\${victim.sam}`,
        "pan.dst": "104.21.44.190",
        "pan.dport": "443",
        "pan.app": "web-browsing",
        "pan.category": "shareware-and-freeware",
        "pan.url": `${downloadSite}/get/VideoConvertPro_Setup.exe`,
        "pan.filename": "VideoConvertPro_Setup.exe",
        "pan.filetype": "pe",
        "pan.file_hash": installerHash,
        "pan.direction": "download",
        "pan.session_id": "941188",
        "source.ip": host.ip,
        "url.domain": downloadSite,
        "action_result": "alert",
      },
    },

    // ---------------------------------------------------------------------
    // 2. Installation.
    // ---------------------------------------------------------------------
    {
      id: "evt_bcm_02_install",
      ts: T(4 * MIN),
      source: "edr",
      vendor: "CrowdStrike Falcon",
      event_type: "process_create",
      hostname: host.hostname,
      user_email: victim.email,
      src_ip: host.ip,
      severity: "low",
      mitre_technique: "T1204.002",
      mitre_tactic: "Execution",
      description:
        "VideoConvertPro_Setup.exe ran from Downloads at 17:56, started by explorer.exe.",
      process: {
        name: "VideoConvertPro_Setup.exe",
        pid: 10_244,
        path: "C:\\Users\\o.mizrahi\\Downloads\\VideoConvertPro_Setup.exe",
        parent_name: "explorer.exe",
        parent_pid: 4108,
        cmdline: '"C:\\Users\\o.mizrahi\\Downloads\\VideoConvertPro_Setup.exe"',
        user: `NEXACORP\\${victim.sam}`,
        integrity: "high",
        hash: { sha256: installerHash },
      },
      raw: {
        "crowdstrike.event_simpleName": "ProcessRollup2",
        "crowdstrike.sensor.id": "d5f31c8072ba4e17a9026b41ce7d8355",
        "event.action": "process_created",
        "process.name": "VideoConvertPro_Setup.exe",
        "process.pid": "10244",
        "process.executable": "C:\\Users\\o.mizrahi\\Downloads\\VideoConvertPro_Setup.exe",
        "process.hash.sha256": installerHash,
        "process.signed": "false",
        "process.code_signature.status": "unsigned",
        "process.parent.name": "explorer.exe",
        "process.parent.pid": "4108",
        "user.name": `NEXACORP\\${victim.sam}`,
        "host.name": host.hostname,
        "host.ip": host.ip,
      },
    },

    // ---------------------------------------------------------------------
    // 3. A second binary, named to blend into a process list.
    // ---------------------------------------------------------------------
    {
      id: "evt_bcm_03_miner_written",
      ts: T(4 * MIN + 40_000),
      source: "edr",
      vendor: "CrowdStrike Falcon",
      event_type: "file_create",
      hostname: host.hostname,
      user_email: victim.email,
      src_ip: host.ip,
      severity: "medium",
      mitre_technique: "T1036.005",
      mitre_tactic: "Defense Evasion",
      description:
        "The installer wrote C:\\Users\\o.mizrahi\\AppData\\Local\\WinHost\\svchost_helper.exe, unsigned, 6.4 MB.",
      file: {
        name: "svchost_helper.exe",
        path: "C:\\Users\\o.mizrahi\\AppData\\Local\\WinHost\\svchost_helper.exe",
        extension: "exe",
        size: 6_710_886,
        sha256: minerHash,
      },
      raw: {
        "crowdstrike.event_simpleName": "PeFileWritten",
        "crowdstrike.sensor.id": "d5f31c8072ba4e17a9026b41ce7d8355",
        "event.action": "file_created",
        "file.name": "svchost_helper.exe",
        "file.path": "C:\\Users\\o.mizrahi\\AppData\\Local\\WinHost\\svchost_helper.exe",
        "file.size": "6710886",
        "file.hash.sha256": minerHash,
        "file.code_signature.status": "unsigned",
        "process.name": "VideoConvertPro_Setup.exe",
        "process.pid": "10244",
        "user.name": `NEXACORP\\${victim.sam}`,
        "host.name": host.hostname,
      },
    },

    // ---------------------------------------------------------------------
    // 4. Persistence via a scheduled task at logon.
    // ---------------------------------------------------------------------
    {
      id: "evt_bcm_04_scheduled_task",
      ts: T(4 * MIN + 45_000),
      source: "edr",
      vendor: "CrowdStrike Falcon",
      event_type: "scheduled_task",
      hostname: host.hostname,
      user_email: victim.email,
      src_ip: host.ip,
      severity: "high",
      mitre_technique: "T1053.005",
      mitre_tactic: "Persistence",
      description:
        "schtasks.exe registered a task named WinHostSync to run the AppData binary at every logon, with a five-minute delay.",
      process: {
        name: "schtasks.exe",
        pid: 10_388,
        path: "C:\\Windows\\System32\\schtasks.exe",
        parent_name: "VideoConvertPro_Setup.exe",
        parent_pid: 10_244,
        cmdline:
          'schtasks /create /tn "WinHostSync" /tr "C:\\Users\\o.mizrahi\\AppData\\Local\\WinHost\\svchost_helper.exe" /sc onlogon /delay 0005:00 /f',
        user: `NEXACORP\\${victim.sam}`,
        integrity: "high",
        hash: { sha256: schtasksHash },
      },
      raw: {
        "crowdstrike.event_simpleName": "ScheduledTaskRegistered",
        "crowdstrike.detection.tactic": "Persistence",
        "crowdstrike.detection.tactic_id": "TA0003",
        "crowdstrike.detection.technique": "Scheduled Task/Job: Scheduled Task",
        "crowdstrike.detection.technique_id": "T1053.005",
        "crowdstrike.detection.severity": "Medium",
        "crowdstrike.sensor.id": "d5f31c8072ba4e17a9026b41ce7d8355",
        "event.action": "scheduled_task_created",
        "process.name": "schtasks.exe",
        "process.pid": "10388",
        "process.command_line":
          'schtasks /create /tn "WinHostSync" /tr "C:\\Users\\o.mizrahi\\AppData\\Local\\WinHost\\svchost_helper.exe" /sc onlogon /delay 0005:00 /f',
        "process.hash.sha256": schtasksHash,
        "process.parent.name": "VideoConvertPro_Setup.exe",
        "process.parent.pid": "10244",
        // Falcon's own ScheduledTaskRegistered fields — not winlog.*, which is
        // the Windows Event Log shipper's namespace and is absent here because
        // this estate has no Sysmon/WEF on the endpoint.
        "crowdstrike.task_name": "WinHostSync",
        "crowdstrike.task_exec_command":
          "C:\\Users\\o.mizrahi\\AppData\\Local\\WinHost\\svchost_helper.exe",
        "crowdstrike.task_author": `NEXACORP\\${victim.sam}`,
        "crowdstrike.task_trigger": "AtLogon",
        "user.name": `NEXACORP\\${victim.sam}`,
        "host.name": host.hostname,
      },
    },

    // ---------------------------------------------------------------------
    // 5. The miner starts, and immediately looks for its pool.
    // ---------------------------------------------------------------------
    {
      id: "evt_bcm_05_miner_start",
      ts: T(10 * MIN),
      source: "edr",
      vendor: "CrowdStrike Falcon",
      event_type: "process_create",
      hostname: host.hostname,
      user_email: victim.email,
      src_ip: host.ip,
      severity: "high",
      mitre_technique: "T1496",
      mitre_tactic: "Impact",
      description:
        "svchost_helper.exe started at 18:02 with pool and wallet arguments on its command line, parented by taskeng.exe.",
      process: {
        name: "svchost_helper.exe",
        pid: 11_020,
        path: "C:\\Users\\o.mizrahi\\AppData\\Local\\WinHost\\svchost_helper.exe",
        parent_name: "taskeng.exe",
        parent_pid: 2044,
        cmdline:
          "svchost_helper.exe -o stratum+tcp://eu1.pool-relay-mining.com:3333 -u 48Hn2QkP9cRxVaLmT4dW --cpu-max-threads-hint=70 --background",
        user: `NEXACORP\\${victim.sam}`,
        integrity: "medium",
        hash: { sha256: minerHash },
      },
      raw: {
        "crowdstrike.event_simpleName": "ProcessRollup2",
        "crowdstrike.detection.tactic": "Impact",
        "crowdstrike.detection.tactic_id": "TA0040",
        "crowdstrike.detection.technique": "Resource Hijacking",
        "crowdstrike.detection.technique_id": "T1496",
        "crowdstrike.detection.severity": "High",
        "crowdstrike.detection.pattern_disposition": "10",
        "crowdstrike.detection.pattern_disposition_description": "Detection, No Action",
        "crowdstrike.sensor.id": "d5f31c8072ba4e17a9026b41ce7d8355",
        "event.action": "process_created",
        "process.name": "svchost_helper.exe",
        "process.pid": "11020",
        "process.executable": "C:\\Users\\o.mizrahi\\AppData\\Local\\WinHost\\svchost_helper.exe",
        "process.command_line":
          "svchost_helper.exe -o stratum+tcp://eu1.pool-relay-mining.com:3333 -u 48Hn2QkP9cRxVaLmT4dW --cpu-max-threads-hint=70 --background",
        "process.hash.sha256": minerHash,
        "process.code_signature.status": "unsigned",
        "process.parent.name": "taskeng.exe",
        "process.parent.pid": "2044",
        "user.name": `NEXACORP\\${victim.sam}`,
        "host.name": host.hostname,
        "host.ip": host.ip,
      },
    },

    // ---------------------------------------------------------------------
    // 6. The pool connection — long-lived, on a non-web port, and allowed.
    // ---------------------------------------------------------------------
    {
      id: "evt_bcm_06_pool_connection",
      ts: T(10 * MIN + 6_000),
      source: "firewall",
      vendor: "Palo Alto Networks PAN-OS",
      event_type: "net_connection",
      hostname: host.hostname,
      user_email: victim.email,
      src_ip: host.ip,
      dst_port: 3333,
      protocol: "tcp",
      severity: "high",
      mitre_technique: "T1496",
      mitre_tactic: "Impact",
      description:
        "A TCP/3333 session opened from LAP-1806 to eu1.pool-relay-mining.com and stayed up for 11 hours, allowed by the default outbound rule.",
      network: { domain: pool, bytes_out: 2_884_112, bytes_in: 941_320 },
      raw: {
        "pan.type": "TRAFFIC",
        "pan.subtype": "end",
        "pan.action": "allow",
        "pan.rule": "CORP-ANY-OUTBOUND",
        "pan.src": host.ip,
        "pan.srcuser": `nexacorp\\${victim.sam}`,
        "pan.dst": "51.15.204.88",
        "pan.dport": "3333",
        "pan.proto": "tcp",
        "pan.app": "unknown-tcp",
        "pan.category": "any",
        "pan.session_id": "941402",
        "pan.bytes_sent": "2884112",
        "pan.bytes_received": "941320",
        "pan.elapsed_time": "39602",
        "pan.dstloc": "FR",
        "source.ip": host.ip,
        "destination.port": "3333",
        "url.domain": pool,
        "action_result": "allow",
      },
    },

    // ---------------------------------------------------------------------
    // 7. The service-desk ticket. This is how the SOC actually finds out.
    // ---------------------------------------------------------------------
    {
      id: "evt_bcm_07_perf_telemetry",
      ts: T(15 * HOUR + 8 * MIN),
      source: "edr",
      vendor: "CrowdStrike Falcon",
      event_type: "edr_alert",
      hostname: host.hostname,
      user_email: victim.email,
      src_ip: host.ip,
      severity: "high",
      mitre_technique: "T1496",
      mitre_tactic: "Impact",
      description:
        "Falcon raised a Resource Hijacking detection on LAP-1806: svchost_helper.exe has run continuously since it launched the previous evening — through the night — holding a persistent mining-pool connection, a resource profile consistent with cryptomining.",
      raw: {
        "crowdstrike.event_simpleName": "DetectionSummaryEvent",
        "crowdstrike.detection.name": "CryptocurrencyMining",
        "crowdstrike.detection.description":
          "svchost_helper.exe (PID 11020) has run uninterrupted for roughly 15 hours, spanning overnight, and maintains a stratum connection to eu1.pool-relay-mining.com. The sustained, off-hours execution with a mining-pool session is consistent with unauthorised cryptocurrency mining.",
        "crowdstrike.detection.tactic": "Impact",
        "crowdstrike.detection.tactic_id": "TA0040",
        "crowdstrike.detection.technique": "Resource Hijacking",
        "crowdstrike.detection.technique_id": "T1496",
        "crowdstrike.detection.severity": "High",
        "crowdstrike.detection.confidence": "90",
        "crowdstrike.sensor.id": "d5f31c8072ba4e17a9026b41ce7d8355",
        "event.action": "detection",
        "process.name": "svchost_helper.exe",
        "process.pid": "11020",
        "process.executable": "C:\\Users\\o.mizrahi\\AppData\\Local\\WinHost\\svchost_helper.exe",
        "host.name": host.hostname,
        "user.name": `NEXACORP\\${victim.sam}`,
      },
    },

    // ---------------------------------------------------------------------
    // 8. The detection, with the asset context that decides severity.
    // ---------------------------------------------------------------------
    {
      id: "evt_bcm_08_edr_alert",
      ts: T(15 * HOUR + 20 * MIN),
      source: "edr",
      vendor: "CrowdStrike Falcon",
      event_type: "edr_alert",
      hostname: host.hostname,
      user_email: victim.email,
      src_ip: host.ip,
      severity: "high",
      description:
        "Falcon raised a High detection for an unsigned AppData process holding a long-lived stratum connection, with the host's asset context attached.",
      raw: {
        "crowdstrike.event_simpleName": "DetectionSummaryEvent",
        "crowdstrike.detection.name": "UnsignedProcessSustainedStratumConnection",
        "crowdstrike.detection.description":
          "An unsigned binary in a user AppData directory maintained a long-lived TCP/3333 session and sustained high CPU utilisation.",
        "crowdstrike.detection.severity": "High",
        "crowdstrike.detection.confidence": "90",
        "crowdstrike.detection.tactic": "Impact",
        "crowdstrike.detection.technique": "Resource Hijacking",
        "crowdstrike.detection.technique_id": "T1496",
        "crowdstrike.detection.pattern_disposition_description": "Detection, No Action",
        "crowdstrike.detection.process_tree": "taskeng.exe > svchost_helper.exe",
        "crowdstrike.sensor.id": "d5f31c8072ba4e17a9026b41ce7d8355",
        "crowdstrike.network_containment_state": "Not Contained",
        "event.action": "alert",
        "event.outcome": "detected",
        "host.name": host.hostname,
        "host.ip": host.ip,
        "user.name": `NEXACORP\\${victim.sam}`,
      },
    },

    // ---------------------------------------------------------------------
    // 9. Asset and blast-radius context. This is a SIEM enrichment record, not
    //    an EDR one — the EDR knows what ran on the host, but only the SIEM
    //    joins it to who else uses the machine and what the account touched.
    //    It is the event that decides severity, which is why it is separate.
    // ---------------------------------------------------------------------
    {
      id: "evt_bcm_09_siem_context",
      ts: T(15 * HOUR + 24 * MIN),
      source: "siem",
      vendor: "Microsoft Sentinel",
      event_type: "ueba_anomaly",
      hostname: host.hostname,
      user_email: victim.email,
      src_ip: host.ip,
      severity: "medium",
      description:
        "Sentinel attached the host's asset context to the detection: criticality, who else uses the machine, what was installed, and what the account touched in the window.",
      raw: {
        "AlertName": "HostResourceAnomaly_UnsignedProcess",
        "alert.rule.id": "SEN-IMPACT-0071",
        "alert.severity": "Medium",
        "host.name": host.hostname,
        "host.ip": host.ip,
        "target.user.name": `NEXACORP\\${victim.sam}`,
        "user.full_name": victim.name,
        "user.department": "Marketing",
        "ExtendedProperties.Asset Criticality": "Medium",
        "ExtendedProperties.Host Role": "Shared marketing laptop — also used for month-end close by Finance",
        "ExtendedProperties.Software Installed Yesterday": ["VideoConvert Pro 9.1 (unsigned)"],
        "ExtendedProperties.Persistence Added": ["Scheduled Task: WinHostSync"],
        "ExtendedProperties.Accounts Touched": "1 (o.mizrahi — local session only)",
        "ExtendedProperties.Data Accessed Outside Baseline": "none",
        "event.action": "correlation-alert",
        "event.outcome": "alerted",
      },
    },
  ];

  const iocs: IOC[] = [
    {
      type: "sha256",
      value: minerHash,
      first_seen: T(4 * MIN + 40_000),
      last_seen: T(15 * HOUR + 20 * MIN),
      reputation: "malicious",
      tags: ["coinminer", "unsigned", "appdata", "masquerading"],
    },
    {
      type: "sha256",
      value: installerHash,
      first_seen: T(0),
      last_seen: T(4 * MIN + 45_000),
      reputation: "malicious",
      tags: ["bundled-installer", "unsigned"],
    },
    {
      type: "domain",
      value: pool,
      first_seen: T(10 * MIN + 6_000),
      last_seen: T(15 * HOUR + 8 * MIN),
      reputation: "malicious",
      tags: ["mining-pool", "stratum"],
    },
    {
      type: "domain",
      value: downloadSite,
      first_seen: T(0),
      last_seen: T(0),
      reputation: "malicious",
      tags: ["freeware-distribution", "bundling"],
    },
    {
      type: "host",
      value: host.hostname,
      first_seen: T(0),
      last_seen: T(15 * HOUR + 20 * MIN),
      reputation: "unknown",
      tags: ["user-endpoint", "affected"],
    },
  ];

  const questions: ScenarioQuestion[] = [
    {
      id: "q1",
      prompt:
        "Which detail in evt_bcm_05_miner_start most clearly identifies this as a coinminer rather than any other unsigned background process?",
      kind: "single",
      options: [
        { value: "stratum_args", label: "The command line — a stratum+tcp pool URL, a wallet identifier, and a CPU-thread hint" },
        { value: "appdata", label: "It runs from AppData, where legitimate software is never installed" },
        { value: "unsigned", label: "It is unsigned, and unsigned binaries in a corporate estate are always malware" },
        { value: "parent", label: "Its parent is taskeng.exe, which only ever launches malicious tasks" },
      ],
      answer: "stratum_args",
      xp: 50,
      explanation:
        "The arguments name the activity outright: stratum+tcp is the mining-pool protocol, -u carries a wallet address, and --cpu-max-threads-hint=70 tells it how much of the machine to consume. Nothing else needs interpreting. The other three options overstate ordinary facts into rules that will burn you: plenty of legitimate software installs to AppData (Teams, Slack, Zoom), unsigned binaries are common in any estate that runs internal tooling, and taskeng.exe is the ordinary Windows task engine that launches every scheduled task on the machine, malicious or not.",
    },
    {
      id: "q2",
      prompt:
        "The firewall allowed the TCP/3333 session under CORP-ANY-OUTBOUND with pan.app 'unknown-tcp'. What is the lesson for detection?",
      kind: "single",
      options: [
        { value: "long_unknown", label: "A long-lived session on a non-standard port with an unidentified application is itself a detectable pattern" },
        { value: "block_3333", label: "Port 3333 should be blocked outbound, which would have prevented this entirely" },
        { value: "no_lesson", label: "None — the firewall behaved correctly, and this is purely an endpoint problem" },
        { value: "tls", label: "TLS inspection should have been enabled on this session so the payload could be read" },
      ],
      answer: "long_unknown",
      xp: 60,
      explanation:
        "pan.elapsed_time is 39,602 seconds — eleven hours on one session — with pan.app 'unknown-tcp', meaning the firewall could not identify the protocol at all. That combination is rare in normal traffic and cheap to alert on, and it does not depend on knowing this particular pool domain or port. Blocking 3333 (b) fixes exactly one port; miners move to 443 and to pool domains that look like CDNs, so port blocklists age badly. Option (d) misunderstands the traffic — stratum here is not HTTPS, so there is no TLS session to inspect.",
    },
    {
      id: "q3",
      prompt:
        "Accounts Touched is 1 and Data Accessed Outside Baseline is 'none'. How should you grade the severity?",
      kind: "single",
      options: [
        { value: "real_impact", label: "Genuinely serious — impact here is stolen compute and an unauthorised persistent foothold, not stolen data" },
        { value: "low", label: "Low — nothing was accessed and no account was compromised, so business impact is negligible" },
        { value: "critical", label: "Critical — assume data theft occurred and simply was not logged" },
        { value: "info", label: "Informational — this is a software-policy violation for IT, not a security incident" },
      ],
      answer: "real_impact",
      xp: 60,
      explanation:
        "MITRE puts Resource Hijacking under Impact for a reason: the harm is that the organisation's compute is being spent for someone else's profit, here with the miner tuned to 70% of CPU threads and running through the night on a machine Finance also uses for month-end close. There is a second, larger point. Something unsigned achieved execution and persistence on a corporate endpoint through a route nobody controlled — the same route delivers ransomware just as easily, and the miner is the visible symptom of an invisible gap. Option (b) is the grading error this scenario exists to correct. Option (c) invents evidence rather than reporting its absence. Option (d) hands a live persistence mechanism to the service desk as a slowness ticket.",
    },
    {
      id: "q4",
      prompt:
        "Which removal step is essential and most often forgotten?",
      kind: "single",
      options: [
        { value: "task", label: "Deleting the WinHostSync scheduled task — otherwise it relaunches the miner at the next logon" },
        { value: "kill", label: "Killing PID 11020, after which the machine is clean" },
        { value: "block_pool", label: "Blocking the pool domain, which stops the miner from doing any work" },
        { value: "uninstall", label: "Uninstalling VideoConvert Pro, which removes everything it installed" },
      ],
      answer: "task",
      xp: 50,
      explanation:
        "evt_bcm_04 is the event that makes this survive: a scheduled task set to AtLogon with a five-minute delay, running as the user. Kill the process (b) and it is back five minutes after the next login, which is how these tickets get reopened three times. Blocking the pool (c) idles the miner without removing it — the process still runs, still burns CPU, and still has persistence waiting for a new pool address. And uninstalling the parent application (d) is not the same as removing what it dropped; the miner lives in AppData under a different name and no uninstaller touches it.",
    },
  ];

  return {
    scenario_id: scenarioId,
    title: "Slow Laptop — Coinminer Bundled with a Video Converter",
    threat_actor: "Freeware bundler (cryptomining monetisation)",
    attack_kind: "bundled_cryptominer",
    briefing:
      "The service desk escalated LAP-1806 this morning: the machine is slow, the fans run constantly, and the battery is dead by lunchtime. CrowdStrike Falcon also has a High detection open on the same host from 09:12. Work out what is running, how it survives a reboot, and how serious this is.",
    narrative: `At 17:52 yesterday Oren Mizrahi downloaded VideoConvertPro_Setup.exe from videoconvert-pro.net. He had a conference video in the wrong format and needed it converted before the morning. He installed it at 17:56. The installer is unsigned; Windows warned him and he clicked through, which is what people do at ten to six.

Forty seconds into the install, a second binary was written: C:\\Users\\o.mizrahi\\AppData\\Local\\WinHost\\svchost_helper.exe, 6.4 MB, unsigned. The name is doing deliberate work — svchost is one of the most familiar strings in a Windows process list, and "helper" reads as harmless. Five seconds later schtasks.exe registered a task called WinHostSync to run it at every logon, five minutes after the desktop loads. The delay is not an accident; it puts the process start well away from the moment anyone would be watching the machine boot.

At 18:02 it started. Its command line names exactly what it is: stratum+tcp://eu1.pool-relay-mining.com:3333, a wallet identifier, and --cpu-max-threads-hint=70. The firewall let the connection out under the default outbound rule as pan.app "unknown-tcp", and that session stayed open for eleven hours.

The service-desk symptoms follow directly from that command line: --cpu-max-threads-hint=70 pins most of the CPU, so the fans run constantly and the battery drains by lunchtime. The session never closed and the process never idled — the laptop mined all night on a desk in an empty office, which is exactly what Falcon's Resource Hijacking detection flagged.

Nothing was stolen. One account was involved and only for its local session, and no data was touched outside baseline. The detection is still "Detection, No Action" — Falcon has been watching it run since 09:12 this morning, and the scheduled task is still registered.`,
    learning_objectives: [
      "Identify Resource Hijacking (T1496) from stratum pool arguments and a wallet identifier on a command line",
      "Recognise masquerading (T1036.005) — a binary named to blend into the Windows process list",
      "Use a long-lived 'unknown-tcp' session as a detection pattern independent of any specific port or domain",
      "Grade severity by impact type rather than by whether data was stolen",
      "Remove persistence (T1053.005) as well as the running process, or the incident reopens at the next logon",
    ],
    alerts: [],
    events,
    iocs,
    killchain: [
      { ts: T(0), phase: "Initial Access", action: `VideoConvertPro_Setup.exe downloaded from ${downloadSite}` },
      { ts: T(4 * MIN), phase: "Execution", action: "User runs the unsigned installer (T1204.002)" },
      { ts: T(4 * MIN + 40_000), phase: "Defense Evasion", action: "svchost_helper.exe written to AppData under a system-like name (T1036.005)" },
      { ts: T(4 * MIN + 45_000), phase: "Persistence", action: "Scheduled task WinHostSync registered at logon with a 5-minute delay (T1053.005)" },
      { ts: T(10 * MIN), phase: "Impact", action: "Miner starts with pool and wallet arguments (T1496)" },
      { ts: T(10 * MIN + 6_000), phase: "Impact", action: `11-hour TCP/3333 session to ${pool}, allowed as unknown-tcp` },
      { ts: T(15 * HOUR + 8 * MIN), phase: "Impact", action: "Miner runs uninterrupted overnight — sustained high CPU from --cpu-max-threads-hint=70" },
      { ts: T(15 * HOUR + 20 * MIN), phase: "Detection", action: "Falcon raises a High detection — detect only, nothing contained" },
    ],
    questions,
  };
}
