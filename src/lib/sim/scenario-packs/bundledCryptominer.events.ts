/**
 * Events-only half of the ./bundledCryptominer.ts scenario pack.
 *
 * The dashboard's live feed runs in the browser (attackStories.ts), so what it
 * imports ships in a public /_next/static chunk. The answer key (questions,
 * answers, explanations, IOCs, killchain, narrative) stays in the builder in
 * ./bundledCryptominer.ts, which composes this module on the server. Keep anything
 * answer-bearing out of this file: every visitor can read it.
 */
import type { TelemetryEvent } from "@/lib/sim/types";
import { makeSha256 } from "@/lib/sim/iocs";
import { csProcess, csFile, csAlert } from "@/lib/sim/emitters/crowdstrike";
import { panWeb, panConnection } from "@/lib/sim/emitters/paloalto";
import { sentinelAlert } from "@/lib/sim/emitters/sentinel";

/** Telemetry half of `buildBundledCryptominerScenario`: the events and the story title, no answer key. */
export function bundledCryptominerScenarioEvents() {
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

  // EDR↔scenario integration (Phase 4): one incident, endpoint-primary →
  // edr_scope "edr". Alert-grade rows: the Falcon Resource-Hijacking summary
  // that opens the ticket, plus the miner-start behavioural detection (the
  // crux). The rest is pivot-only telemetry in the process tree.
  const INCIDENT = "inc:bcm:1";

  const cx = { companyId: "nexacorp" as const, host: host.hostname, user: victim.email, srcIp: host.ip };
  const INSTALLER = "C:\\Users\\o.mizrahi\\Downloads\\VideoConvertPro_Setup.exe";
  const AGENT = "C:\\Users\\o.mizrahi\\AppData\\Local\\WinHost\\svchost_helper.exe";

  const events: TelemetryEvent[] = [
    // 1. The download.
    panWeb({
      ...cx, id: "evt_bcm_01_download", ts: T(0), url: `https://${downloadSite}/get/VideoConvertPro_Setup.exe`,
      domain: downloadSite, method: "GET", action: "alert", category: "shareware-and-freeware",
      dstIp: "104.21.44.190", status: 200, bytesIn: 42_991_616, userTitle: "Marketing Manager", severity: "low",
      file: { name: "VideoConvertPro_Setup.exe", path: "/get/VideoConvertPro_Setup.exe", sha256: installerHash, size: 42_991_616 },
      fileType: "pe",
      description:
        "LAP-1806 downloaded VideoConvertPro_Setup.exe from videoconvert-pro.net at 17:52, allowed under the category shareware-and-freeware.",
    }),

    // 2. Installation.
    csProcess({
      ...cx, id: "evt_bcm_02_install", ts: T(4 * MIN), processName: "VideoConvertPro_Setup.exe", processPath: INSTALLER,
      cmdline: '"C:\\Users\\o.mizrahi\\Downloads\\VideoConvertPro_Setup.exe"', parentName: "explorer.exe", pid: 10_244, parentPid: 4108,
      sha256: installerHash, signed: false, mitre: "T1204.002", tactic: "Execution", severity: "low",
      description: "VideoConvertPro_Setup.exe ran from Downloads at 17:56, started by explorer.exe.",
    }),

    // 3. The miner binary, masqueraded (T1036.005).
    csFile({
      ...cx, id: "evt_bcm_03_miner_written", ts: T(4 * MIN + 40_000), path: AGENT, sha256: minerHash, signed: false,
      mitre: "T1036.005", tactic: "Defense Evasion", severity: "medium",
      description: "The installer wrote C:\\Users\\o.mizrahi\\AppData\\Local\\WinHost\\svchost_helper.exe, unsigned, 6.4 MB.",
    }),

    // 4. Persistence via a scheduled task at logon (T1053.005).
    csProcess({
      ...cx, id: "evt_bcm_04_scheduled_task", ts: T(4 * MIN + 45_000), processName: "schtasks.exe", eventType: "scheduled_task",
      cmdline: 'schtasks /create /tn "WinHostSync" /tr "C:\\Users\\o.mizrahi\\AppData\\Local\\WinHost\\svchost_helper.exe" /sc onlogon /delay 0005:00 /f',
      parentName: "VideoConvertPro_Setup.exe", pid: 10_388, parentPid: 10_244, sha256: schtasksHash, signed: true,
      mitre: "T1053.005", tactic: "Persistence", severity: "high",
      description:
        "schtasks.exe registered a task named WinHostSync to run the AppData binary at every logon, with a five-minute delay.",
    }),

    // 5. The miner starts with pool + wallet arguments (T1496).
    csProcess({
      ...cx, id: "evt_bcm_05_miner_start", ts: T(10 * MIN), processName: "svchost_helper.exe", processPath: AGENT,
      cmdline: "svchost_helper.exe -o stratum+tcp://eu1.pool-relay-mining.com:3333 -u 48Hn2QkP9cRxVaLmT4dW --cpu-max-threads-hint=70 --background",
      parentName: "VideoConvertPro_Setup.exe", pid: 11_020, parentPid: 10_244, sha256: minerHash, signed: false, isDetection: true,
      mitre: "T1496", tactic: "Impact", severity: "high",
      description:
        "svchost_helper.exe started at 18:02 with pool and wallet arguments on its command line, launched by the installer VideoConvertPro_Setup.exe.",
    }),

    // 6. The mining-pool connection — long-lived, non-web port, allowed.
    panConnection({
      ...cx, id: "evt_bcm_06_pool_connection", ts: T(10 * MIN + 6_000), domain: pool, dstIp: "51.15.204.88", remotePort: 3333,
      app: "unknown-tcp", transport: "tcp", action: "allow", end: true, bytesOut: 2_884_112, bytesIn: 941_320,
      elapsedSec: 39_602, category: "any", mitre: "T1496", tactic: "Impact", severity: "high",
      description:
        "A TCP/3333 session opened from LAP-1806 to eu1.pool-relay-mining.com and stayed up for 11 hours, allowed by the default outbound rule.",
    }),

    // 7. Falcon Resource-Hijacking summary (precursor — not the ticket-opener).
    csAlert({
      ...cx, id: "evt_bcm_07_perf_telemetry", ts: T(15 * HOUR + 8 * MIN), threatName: "CryptocurrencyMining",
      mitre: "T1496", tactic: "Impact", technique: "Resource Hijacking", malwareCategory: "cryptominer",
      action: "detected", isDetection: false, severity: "high",
      detail:
        "svchost_helper.exe (PID 11020) has run uninterrupted for roughly 15 hours, spanning overnight, and maintains a stratum connection to eu1.pool-relay-mining.com. The sustained, off-hours execution with a mining-pool session is consistent with unauthorised cryptocurrency mining.",
      description:
        "Falcon raised a Resource Hijacking detection on LAP-1806: svchost_helper.exe has run continuously since it launched the previous evening — through the night — holding a persistent mining-pool connection, a resource profile consistent with cryptomining.",
    }),

    // 8. The detection that opens the ticket.
    {
      ...csAlert({
        ...cx, id: "evt_bcm_08_edr_alert", ts: T(15 * HOUR + 20 * MIN), threatName: "UnsignedProcessSustainedStratumConnection",
        mitre: "T1496", tactic: "Impact", technique: "Resource Hijacking", malwareCategory: "cryptominer",
        action: "detected", severity: "high",
        processTree: "VideoConvertPro_Setup.exe > svchost_helper.exe",
        detail:
          "An unsigned binary in a user AppData directory maintained a long-lived TCP/3333 session and sustained high CPU utilisation.",
        description:
          "Falcon raised a High detection for an unsigned AppData process holding a long-lived stratum connection, with the host's asset context attached.",
      }),
      edr_scope: "edr",
    },

    // 9. SIEM asset + blast-radius context — the record that decides severity.
    sentinelAlert({
      ...cx, id: "evt_bcm_09_siem_context", ts: T(15 * HOUR + 24 * MIN), alertName: "HostResourceAnomaly_UnsignedProcess",
      ruleId: "SEN-IMPACT-0071", severity: "medium", eventType: "ueba_anomaly",
      fullName: victim.name, department: "Marketing",
      extendedProperties: {
        "Asset Criticality": "Medium",
        "Host Role": "Shared marketing laptop — also used for month-end close by Finance",
        "Software Installed Yesterday": ["VideoConvert Pro 9.1 (unsigned)"],
        "Persistence Added": ["Scheduled Task: WinHostSync"],
        "Accounts Touched": "1 (o.mizrahi — local session only)",
        "Data Accessed Outside Baseline": "none",
      },
      description:
        "Sentinel attached the host's asset context to the detection: criticality, who else uses the machine, what was installed, and what the account touched in the window.",
    }),
  ];

  // Every event belongs to the one incident.
  for (const e of events) e.incident_id = INCIDENT;

  return { title: "Slow Laptop — Coinminer Bundled with a Video Converter", events, T, MIN, HOUR, host, downloadSite, pool, installerHash, minerHash };
}
