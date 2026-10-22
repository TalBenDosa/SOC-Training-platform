/**
 * Events-only half of the ./trojanizedInstallerKeylogger.ts scenario pack.
 *
 * The dashboard's live feed runs in the browser (attackStories.ts), so what it
 * imports ships in a public /_next/static chunk. The answer key (questions,
 * answers, explanations, IOCs, killchain, narrative) stays in the builder in
 * ./trojanizedInstallerKeylogger.ts, which composes this module on the server. Keep anything
 * answer-bearing out of this file: every visitor can read it.
 */
import type { TelemetryEvent } from "@/lib/sim/types";
import { makeSha256 } from "@/lib/sim/iocs";
import { csProcess, csFile, csRegistry, csProcessAccess, csDetection, csDns, csNetwork } from "@/lib/sim/emitters/crowdstrike";
import { panWeb } from "@/lib/sim/emitters/paloalto";
import { sentinelAlert } from "@/lib/sim/emitters/sentinel";

/** Telemetry half of `buildTrojanizedInstallerKeyloggerScenario`: the events and the story title, no answer key. */
export function trojanizedInstallerKeyloggerScenarioEvents() {
  const B = new Date("2026-06-25T10:05:00Z").getTime();
  const T = (ms: number) => new Date(B + ms).toISOString();
  const MIN = 60_000;

  const host = { hostname: "LAP-2290", ip: "10.14.31.44" };
  const victim = { email: "y.karni@nexacorp.com", name: "Yael Karni", sam: "y.karni" };

  const downloadSite = "pdf-tools-free.io";
  const downloadIp = "172.67.201.18";
  const c2 = "stat-collect-eu.com";
  const c2Ip = "85.209.11.37";     // this story's own collection host

  const installerHash = makeSha256("swiftpdf_setup_trojanized_installer_2026");
  const keyloggerHash = makeSha256("winupd_helper_keylogger_binary_2026");
  const realToolHash  = makeSha256("swiftpdf_merge_legitimate_component_2026");

  // EDR↔scenario integration (SPEC-edr-scenario-integration, Phase 1b): one
  // incident. Endpoint-primary → edr_scope "edr" (the firewall download/exfil are
  // transport evidence, not a separate control-plane investigation). The Falcon
  // detections are alert-grade rows; the rest of the EDR process/file/registry
  // events are pivot-only telemetry surfaced inside the process tree.
  const INCIDENT = "inc:tik:1";

  // Shared emitter context: NexaCorp is a Defender shop, but this pack is authored on
  // CrowdStrike (the emitters render the correct Falcon fields either way). Host, user
  // and IP are pinned to the narrative's values; the emitter renders NEXACORP\y.karni,
  // the raw block and the structured process/file/registry from these.
  const cs = { companyId: "nexacorp", host: host.hostname, user: victim.email, srcIp: host.ip };

  // Process identities pinned once so every event of the story names the same process.
  const CHROME = { name: "chrome.exe", pid: 5012, path: "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe" };
  const EXPLORER_PID = 3204;
  const INSTALLER_PATH = "C:\\Users\\y.karni\\Downloads\\SwiftPDF_Setup.exe";
  const LOGGER_PATH = "C:\\Users\\y.karni\\AppData\\Roaming\\WinUpd\\winupd_helper.exe";
  const LOGGER_PID = 7688;

  // One POST every ten minutes carrying the latest keystroke batch (≈4 KB each).
  const exfilPost = (id: string, ms: number, severity: TelemetryEvent["severity"], description: string) =>
    panWeb({
      ...cs, id, ts: T(ms), severity,
      method: "POST", url: `https://${c2}/v1/report`, domain: c2, category: "unknown",
      action: "allow", dstIp: c2Ip, status: 200, bytesOut: 4_216, bytesIn: 118,
      repeatCount: 1, mitre: "T1041", tactic: "Exfiltration", description,
    });
  const loggerConnect = (id: string, ms: number) =>
    csNetwork({
      ...cs, id, ts: T(ms), severity: "medium",
      remoteIp: c2Ip, remotePort: 443, application: "tls", domain: c2,
      processName: "winupd_helper.exe", pid: LOGGER_PID, processPath: LOGGER_PATH,
      cmdline: "winupd_helper.exe -svc", parentName: "SwiftPDF_Setup.exe", parentPid: 7120, sha256: keyloggerHash,
      description: `winupd_helper.exe (pid ${LOGGER_PID}) opened an outbound connection to ${c2Ip}:443.`,
    });

  const events: TelemetryEvent[] = [
    // ---------------------------------------------------------------------
    // 1. The download. Ordinary category, ordinary user, ordinary need. (PAN emitter)
    // ---------------------------------------------------------------------
    csDns({
      ...cs, id: "evt_tik_00_dns_download", ts: T(-2_000), severity: "low",
      domain: downloadSite, resolvedIp: downloadIp,
      processName: CHROME.name, pid: CHROME.pid, processPath: CHROME.path, parentName: "explorer.exe", parentPid: EXPLORER_PID,
      description: "chrome.exe on LAP-2290 resolved pdf-tools-free.io.",
    }),
    panWeb({
      ...cs, id: "evt_tik_01_download", ts: T(0), severity: "low",
      url: `https://${downloadSite}/dl/SwiftPDF_Setup.exe`, domain: downloadSite,
      category: "shareware-and-freeware", action: "alert", dstIp: downloadIp,
      status: 200, bytesIn: 18_442_240, userTitle: "Contracts Administrator",
      file: { name: "SwiftPDF_Setup.exe", path: "/dl/SwiftPDF_Setup.exe", sha256: installerHash, size: 18_442_240 },
      description: "LAP-2290 downloaded SwiftPDF_Setup.exe from pdf-tools-free.io at 10:05, allowed under the category shareware-and-freeware.",
    }),

    // The installer lands in Downloads, written by the browser.
    csFile({
      ...cs, id: "evt_tik_01b_installer_landed", ts: T(4_000),
      path: INSTALLER_PATH, sha256: installerHash, size: 18_442_240, signed: true, severity: "low",
      actorProcess: CHROME.name, actorPid: CHROME.pid, actorPath: CHROME.path, actorParentName: "explorer.exe", actorParentPid: EXPLORER_PID,
      description: "chrome.exe wrote C:\\Users\\y.karni\\Downloads\\SwiftPDF_Setup.exe to disk.",
    }),

    // ---------------------------------------------------------------------
    // 2-7. The endpoint chain - CrowdStrike Falcon telemetry, generated by the
    //      typed emitters (src/lib/sim/emitters/crowdstrike.ts). Each call renders
    //      a field-correct DetectionSummary / ProcessRollup2 / PeFileWritten /
    //      AsepValueUpdate / hook raw block, with the host, user (NEXACORP\y.karni),
    //      PIDs and hashes threaded consistently through the whole tree.
    // ---------------------------------------------------------------------

    // 2. Installation. Signed, standard user, completely normal-looking (a GUI installer the user clicks through).
    csProcess({
      ...cs, id: "evt_tik_02_installer_run", ts: T(2 * MIN + 30_000),
      processName: "SwiftPDF_Setup.exe", pid: 7120,
      processPath: INSTALLER_PATH,
      cmdline: `"${INSTALLER_PATH}"`,
      parentName: "explorer.exe", parentPid: EXPLORER_PID, sha256: installerHash, signed: true, integrity: "medium",
      mitre: "T1204.002", tactic: "Execution", severity: "low",
      description: "SwiftPDF_Setup.exe ran from Downloads at 10:07:30, started by explorer.exe at medium integrity (TokenElevationTypeLimited, the account is not a local admin).",
    }),

    // 3. The real product is installed. It works, not a decoy.
    csFile({
      ...cs, id: "evt_tik_03_real_component", ts: T(2 * MIN + 51_000),
      path: "C:\\Users\\y.karni\\AppData\\Local\\Programs\\SwiftPDF\\SwiftPDF.exe", sha256: realToolHash, signed: true, severity: "low",
      actorProcess: "SwiftPDF_Setup.exe", actorPid: 7120, actorPath: INSTALLER_PATH, actorSha256: installerHash,
      description: "SwiftPDF_Setup.exe (pid 7120) wrote C:\\Users\\y.karni\\AppData\\Local\\Programs\\SwiftPDF\\SwiftPDF.exe, the working PDF application (a per-user install, no admin rights needed).",
    }),

    // 4. A second binary, to AppData, with a name that borrows Windows' vocabulary.
    csFile({
      ...cs, id: "evt_tik_04_second_binary", ts: T(2 * MIN + 54_000),
      path: LOGGER_PATH, sha256: keyloggerHash, signed: false, severity: "medium",
      actorProcess: "SwiftPDF_Setup.exe", actorPid: 7120, actorPath: INSTALLER_PATH, actorSha256: installerHash,
      description: "Three seconds later SwiftPDF_Setup.exe (pid 7120) wrote C:\\Users\\y.karni\\AppData\\Roaming\\WinUpd\\winupd_helper.exe, unsigned.",
    }),

    // 5. Persistence, a Run key, in the user hive, no admin rights needed.
    csRegistry({
      ...cs, id: "evt_tik_05_run_key", ts: T(2 * MIN + 56_000),
      keyPath: "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
      valueName: "WindowsUpdateHelper",
      valueData: LOGGER_PATH,
      writerProcess: "SwiftPDF_Setup.exe", mitre: "T1547.001", tactic: "Persistence", severity: "high",
      description: "A value named WindowsUpdateHelper was written to the user's Run key, pointing at the AppData binary.",
    }),

    // 5a. The user launches the app the installer just put in place (the "genuine, working tool").
    csProcess({
      ...cs, id: "evt_tik_05a_swiftpdf_run", ts: T(3 * MIN + 20_000),
      processName: "SwiftPDF.exe", pid: 6820,
      processPath: "C:\\Users\\y.karni\\AppData\\Local\\Programs\\SwiftPDF\\SwiftPDF.exe",
      cmdline: '"C:\\Users\\y.karni\\AppData\\Local\\Programs\\SwiftPDF\\SwiftPDF.exe"',
      parentName: "explorer.exe", parentPid: EXPLORER_PID, sha256: realToolHash, signed: true, integrity: "medium",
      severity: "low",
      description: "explorer.exe started SwiftPDF.exe, the application the installer wrote.",
    }),

    // 5b. The helper starts (the installer launches it), the process the Run key will start at every logon.
    csProcess({
      ...cs, id: "evt_tik_05b_helper_start", ts: T(4 * MIN + 8_000),
      processName: "winupd_helper.exe", pid: LOGGER_PID,
      processPath: LOGGER_PATH,
      cmdline: "winupd_helper.exe -svc", parentName: "SwiftPDF_Setup.exe", parentPid: 7120, sha256: keyloggerHash, signed: false, integrity: "medium",
      severity: "medium",
      description: "SwiftPDF_Setup.exe (pid 7120) started winupd_helper.exe -svc from AppData\\Roaming\\WinUpd.",
    }),

    // 6. THE EVENT THAT MATTERS, the helper reads another process's input. Falcon scores
    //    the hook on its own as a Medium, low-confidence detection; it is the exfil that
    //    later raises the same detection to Critical (evt_tik_09).
    csProcessAccess({
      ...cs, id: "evt_tik_06_keylog_hook", ts: T(4 * MIN + 12_000),
      processName: "winupd_helper.exe", pid: LOGGER_PID,
      processPath: LOGGER_PATH,
      cmdline: "winupd_helper.exe -svc", parentName: "SwiftPDF_Setup.exe", parentPid: 7120,
      sha256: keyloggerHash, signed: false, targetProcess: "chrome.exe", targetPid: CHROME.pid,
      api: "SetWindowsHookExW", threatName: "UnsignedUserlandKeyboardHook",
      mitre: "T1056.001", tactic: "Collection", technique: "Input Capture: Keylogging",
      severity: "medium", isDetection: true,
      description: "winupd_helper.exe (pid 7688, parent SwiftPDF_Setup.exe) called SetWindowsHookExW against chrome.exe (pid 5012).",
    }),

    // 6b. First batch leaves ten minutes after the hook: DNS then connection, both from pid 7688.
    csDns({
      ...cs, id: "evt_tik_06b_dns_c2", ts: T(9 * MIN + 59_000), severity: "medium",
      domain: c2, resolvedIp: c2Ip,
      processName: "winupd_helper.exe", pid: LOGGER_PID, processPath: LOGGER_PATH,
      cmdline: "winupd_helper.exe -svc", parentName: "SwiftPDF_Setup.exe", parentPid: 7120, sha256: keyloggerHash,
      description: "winupd_helper.exe (pid 7688) resolved stat-collect-eu.com.",
    }),
    loggerConnect("evt_tik_06c_connect_c2", 10 * MIN),
    exfilPost("evt_tik_08a_exfil", 10 * MIN + 1_000, "high",
      "At 10:15 LAP-2290 POSTed about 4 KB to stat-collect-eu.com/v1/report (85.209.11.37) as NEXACORP\\y.karni, allowed under the category unknown."),

    // 7. A local buffer file grows in the same folder (no hash, a growing data buffer).
    csFile({
      ...cs, id: "evt_tik_07_buffer_file", ts: T(38 * MIN),
      path: "C:\\Users\\y.karni\\AppData\\Roaming\\WinUpd\\cache.dat", sha256: null, size: 62_464, action: "file_modify",
      actorProcess: "winupd_helper.exe", actorPid: LOGGER_PID, actorPath: LOGGER_PATH, actorSha256: keyloggerHash,
      mitre: "T1074.001", tactic: "Collection", severity: "high",
      description: "winupd_helper.exe (pid 7688) repeatedly appended to C:\\Users\\y.karni\\AppData\\Roaming\\WinUpd\\cache.dat, which reached 61 KB over 34 minutes.",
    }),

    // ---------------------------------------------------------------------
    // 8. The batches leave the building every ten minutes, small, regular POSTs. (PAN emitter)
    // ---------------------------------------------------------------------
    exfilPost("evt_tik_08b_exfil", 20 * MIN + 1_000, "high",
      "At 10:25 LAP-2290 POSTed about 4 KB to stat-collect-eu.com/v1/report (85.209.11.37) as NEXACORP\\y.karni."),
    exfilPost("evt_tik_08c_exfil", 30 * MIN + 1_000, "high",
      "At 10:35 LAP-2290 POSTed about 4 KB to stat-collect-eu.com/v1/report (85.209.11.37) as NEXACORP\\y.karni."),
    exfilPost("evt_tik_08_exfil", 40 * MIN, "critical",
      "At 10:45 LAP-2290 POSTed about 4 KB to stat-collect-eu.com/v1/report (85.209.11.37), as NEXACORP\\y.karni, allowed under the category unknown. The fourth identical POST at ten-minute intervals."),

    // ---------------------------------------------------------------------
    // 9. The detection that opened the ticket - Falcon DetectionSummaryEvent,
    //    endpoint-primary (edr_scope "edr" → investigated in the EDR console).
    // ---------------------------------------------------------------------
    {
      ...csDetection({
        ...cs, id: "evt_tik_09_edr_alert", ts: T(41 * MIN), eventType: "edr_alert",
        processName: "winupd_helper.exe", pid: LOGGER_PID, parentPid: 7120, parentName: "SwiftPDF_Setup.exe",
        processPath: LOGGER_PATH,
        cmdline: "winupd_helper.exe -svc", sha256: keyloggerHash,
        threatName: "UnsignedUserlandKeyboardHook", action: "detected", expectedVerdict: "tp",
        mitre: "T1056.001", tactic: "Collection", technique: "Input Capture: Keylogging", severity: "critical",
        description: "Falcon raised a Critical detection on LAP-2290 for winupd_helper.exe (unsigned, in AppData\\Roaming) holding a low-level keyboard hook against chrome.exe, now also sending data out to stat-collect-eu.com.",
      }),
      edr_scope: "edr",
    },

    // ---------------------------------------------------------------------
    // 10. The host's software and entitlement context, from the SIEM rather
    //     than the EDR, what was installed today, what autoruns appeared, and
    //     whether this user could have needed admin rights for any of it. (Sentinel emitter)
    // ---------------------------------------------------------------------
    sentinelAlert({
      ...cs, id: "evt_tik_10_siem_context", ts: T(43 * MIN), severity: "high", eventType: "ueba_anomaly",
      alertName: "EndpointSoftwareChange_UnsignedPersistence", ruleId: "SEN-ENDPOINT-0139",
      fullName: victim.name, department: "Legal", title: "Contracts Administrator",
      extendedProperties: {
        "Software Installed Today": ["SwiftPDF 4.2 (Nordvale Software Solutions OU)"],
        "Installer Signer": "Nordvale Software Solutions OU",
        "Installer Signature Status": "Valid",
        "Certificate Valid From": "2026-05-29",
        "Certificate Issuer": "Sectigo Public Code Signing CA R36",
        "Installer Prevalence": "1 device in the tenant",
        "Autoruns Added Today": ["HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\WindowsUpdateHelper"],
        "Local Admin Rights": "false",
      },
      description: "Sentinel enriched the detection with the host's change history for the day and the account's local-privilege state.",
    }),
  ];

  // Story order: the log is read oldest-first.
  events.sort((a, b) => a.ts.localeCompare(b.ts));

  // Falcon's real disposition strings: a detect-only alert is "Detection, standard detection."
  for (const e of events) {
    if (e.raw?.["crowdstrike.PatternDispositionDescription"] === "Detection only, no action taken") {
      e.raw["crowdstrike.PatternDispositionDescription"] = "Detection, standard detection.";
    }
  }

  // Every event in this pack belongs to the one keylogger incident (correlation
  // key; also lets the EDR console build a single isolated case for it).
  for (const e of events) e.incident_id = INCIDENT;

  return { title: "Critical alert after a free PDF tool install", events, T, MIN, host, downloadSite, c2, c2Ip, installerHash, keyloggerHash };
}
