/**
 * Events-only half of the ./seoPoisonedInstaller.ts scenario pack.
 *
 * The dashboard's live feed runs in the browser (attackStories.ts), so what it
 * imports ships in a public /_next/static chunk. The answer key (questions,
 * answers, explanations, IOCs, killchain, narrative) stays in the builder in
 * ./seoPoisonedInstaller.ts, which composes this module on the server. Keep anything
 * answer-bearing out of this file: every visitor can read it.
 */
import type { TelemetryEvent } from "@/lib/sim/types";
import { makeSha256 } from "@/lib/sim/iocs";
import { mdeProcess, mdeFile, mdeAlert, mdeNetwork, mdeDns, mdeDetection } from "@/lib/sim/emitters/mde";
import { panWeb } from "@/lib/sim/emitters/paloalto";
import { intelLookup } from "./corroboratingTelemetry.events";

/** Telemetry half of `buildSeoPoisonedInstallerScenario`: the events and the story title, no answer key. */
export function seoPoisonedInstallerScenarioEvents() {
  const B = new Date("2026-03-11T14:20:00Z").getTime();
  const T = (ms: number) => new Date(B + ms).toISOString();
  const MIN = 60_000;

  const host = { hostname: "LAP-3312", ip: "10.14.19.63" };
  const victim = { email: "d.avraham@nexacorp.com", name: "Dor Avraham", sam: "d.avraham" };

  const lookalike = "puttysoftware-download.com";
  const c2 = "cdn-assets-relay92.net";

  const installerHash = makeSha256("puttysoftware_download_fake_putty_installer_2026");
  const stealerHash = makeSha256("cdn_assets_relay92_stealer_payload_upd_helper_2026");

  // EDR↔scenario integration (Phase 1b): one incident, endpoint-primary (the
  // infostealer runs on the host; the firewall ad-click/download/fetch/exfil are
  // the web-redirect transport chain). edr_scope "edr". Alert-grade rows: the
  // credential-store copy (the crux) and the Defender incident. The intermediate
  // MDE file/process events are pivot-only telemetry in the process tree, where
  // the chrome.exe → installer → payload redirect/fetch chain is walked.
  const INCIDENT = "inc:spi:1";

  // Shared emitter context, the Microsoft Defender for Endpoint telemetry on one NexaCorp
  // laptop. Host/user/IP pinned to the narrative; the emitter renders NEXACORP\d.avraham,
  // the Advanced-Hunting raw and the structured process/file from these.
  const mde = { companyId: "nexacorp", host: host.hostname, user: victim.email, srcIp: host.ip };

  // The processes of the story, pinned once so every event that names one names the same pid.
  const CHROME = { name: "chrome.exe", pid: 5512, path: "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe", parent: "explorer.exe", parentPid: 3392 };
  const INSTALLER = { name: "PuTTY-0.83-installer.exe", pid: 7744, path: "C:\\Users\\d.avraham\\Downloads\\PuTTY-0.83-installer.exe", parent: "explorer.exe", parentPid: 3392 };
  const STEALER = { name: "upd_helper.exe", pid: 7801, path: "C:\\Users\\d.avraham\\AppData\\Local\\Temp\\sysdata\\upd_helper.exe", parent: "PuTTY-0.83-installer.exe", parentPid: 7744 };
  /** Attach the initiating process to a file / network / DNS record (DeviceFileEvents, DeviceNetworkEvents carry it as InitiatingProcess*). */
  const initiatedBy = (e: TelemetryEvent, p: { name: string; pid: number; path: string; parent: string; parentPid: number }, cmdline?: string): TelemetryEvent => {
    const cmd = cmdline ?? `"${p.path}"`;
    const initiating = { InitiatingProcessFileName: p.name, InitiatingProcessId: String(p.pid), InitiatingProcessFolderPath: p.path, InitiatingProcessCommandLine: cmd };
    return {
      ...e,
      process: { pid: p.pid, name: p.name, path: p.path, cmdline: cmd, parent_name: p.parent, parent_pid: p.parentPid, user: `NEXACORP\\${victim.sam}`, integrity: "medium" },
      raw: Object.assign({}, e.raw, initiating),
    };
  };

  const events: TelemetryEvent[] = [
    // ---------------------------------------------------------------------
    // 1-2. The sponsored result and the download from the lookalike host. (PAN emitter)
    // ---------------------------------------------------------------------
    panWeb({
      ...mde, id: "evt_spi_01_ad_click", ts: T(0), severity: "medium",
      url: `https://${lookalike}/download`, domain: lookalike, category: "newly-registered-domain",
      action: "alert", dstIp: "146.70.108.44", status: 200, bytesIn: 41_280,
      referer: "https://www.googleadservices.com/pagead/aclk?sa=L&ai=DChc&adurl=https://puttysoftware-download.com/download",
      userAgent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/126.0.0.0 Safari/537.36",
      userTitle: "Systems Administrator", mitre: "T1608.006", tactic: "Resource Development",
      description: "LAP-3312 landed on puttysoftware-download.com at 14:20, a domain unrelated to the official PuTTY project, with a googleadservices.com/pagead/aclk ad-click URL as its referer.",
    }),

    panWeb({
      ...mde, id: "evt_spi_02_download", ts: T(45_000), severity: "medium",
      url: `https://${lookalike}/download/PuTTY-0.83-installer.exe`, domain: lookalike,
      category: "newly-registered-domain", action: "alert", dstIp: "146.70.108.44",
      status: 200, bytesIn: 1_812_224, mitre: "T1608.006", tactic: "Resource Development",
      file: { name: "PuTTY-0.83-installer.exe", path: "/download/PuTTY-0.83-installer.exe", sha256: installerHash, size: 1_812_224 },
      description: "Forty-five seconds later the same browser session downloaded PuTTY-0.83-installer.exe from puttysoftware-download.com.",
    }),

    // ---------------------------------------------------------------------
    // 3-8. The endpoint chain - Microsoft Defender for Endpoint telemetry,
    //      generated by the typed emitters (src/lib/sim/emitters/mde.ts). The
    //      chrome -> installer -> payload -> credential-copy chain keeps its exact
    //      PIDs and hashes; each raw block uses only Advanced-Hunting / ECS fields.
    // ---------------------------------------------------------------------

    // 3. The file lands in Downloads, written by chrome.exe.
    initiatedBy(mdeFile({
      ...mde, id: "evt_spi_03_file_write", ts: T(50_000),
      path: "C:\\Users\\d.avraham\\Downloads\\PuTTY-0.83-installer.exe", sha256: installerHash, size: 1_812_224,
      initiatingProcess: "chrome.exe", severity: "low",
      description: "chrome.exe wrote C:\\Users\\d.avraham\\Downloads\\PuTTY-0.83-installer.exe at 14:20:50.",
    }), CHROME, `"${CHROME.path}"`),

    // 3a. DNS for the lookalike, from the browser (the lookup precedes the first request).
    initiatedBy(mdeDns({
      ...mde, id: "evt_spi_00_dns_lookalike", ts: T(-2_000), severity: "low",
      domain: lookalike, resolvedIp: "146.70.108.44",
      description: "chrome.exe on LAP-3312 resolved puttysoftware-download.com.",
    }), CHROME, `"${CHROME.path}"`),

    // 4. She runs it. Unsigned, elevated on the UAC prompt she accepted.
    mdeProcess({
      ...mde, id: "evt_spi_04_execute", ts: T(3 * MIN + 10_000),
      processName: "PuTTY-0.83-installer.exe", pid: 7744,
      processPath: "C:\\Users\\d.avraham\\Downloads\\PuTTY-0.83-installer.exe",
      cmdline: '"C:\\Users\\d.avraham\\Downloads\\PuTTY-0.83-installer.exe"',
      parentName: "explorer.exe", parentPid: 3392, sha256: installerHash, signed: false, integrity: "Medium",
      mitre: "T1204.002", tactic: "Execution", severity: "high",
      description: "At 14:23:10 explorer.exe started PuTTY-0.83-installer.exe, unsigned, from the Downloads folder, at medium integrity (no elevation, the stealer reads the user's own Chrome profile).",
    }),

    // ---------------------------------------------------------------------
    // 5. Four seconds into running, the installer fetches its real payload. (PAN emitter, and the
    //    endpoint's own record of the connection, attributed to the installer's pid 7744)
    // ---------------------------------------------------------------------
    initiatedBy(mdeDns({
      ...mde, id: "evt_spi_05a_dns_c2", ts: T(3 * MIN + 13_000), severity: "medium",
      domain: c2, resolvedIp: "185.212.44.19", mitre: "T1105", tactic: "Command and Control",
      description: "PuTTY-0.83-installer.exe on LAP-3312 resolved cdn-assets-relay92.net.",
    }), INSTALLER),
    initiatedBy(mdeNetwork({
      ...mde, id: "evt_spi_05b_stage2_conn", ts: T(3 * MIN + 14_000), severity: "high",
      remoteIp: "185.212.44.19", remotePort: 443, application: "tls", domain: c2,
      url: `https://${c2}/dist/upd_helper.exe`, initiatingProcess: "PuTTY-0.83-installer.exe",
      mitre: "T1105", tactic: "Command and Control",
      description: "PuTTY-0.83-installer.exe (pid 7744) connected to 185.212.44.19:443 and requested https://cdn-assets-relay92.net/dist/upd_helper.exe.",
    }), INSTALLER),
    panWeb({
      ...mde, id: "evt_spi_05_stage2_fetch", ts: T(3 * MIN + 14_000), severity: "critical",
      url: `https://${c2}/dist/upd_helper.exe`, domain: c2, category: "unknown",
      action: "alert", dstIp: "185.212.44.19", status: 200, bytesIn: 3_251_712,
      mitre: "T1105", tactic: "Command and Control",
      file: { name: "upd_helper.exe", path: "/dist/upd_helper.exe", sha256: stealerHash, size: 3_251_712 },
      description: "At 14:23:14 the installer process fetched upd_helper.exe, 3.1 MB, from cdn-assets-relay92.net, infrastructure with no relationship to puttysoftware-download.com.",
    }),

    // 6. The payload lands on disk, in a folder the installer created for itself.
    initiatedBy(mdeFile({
      ...mde, id: "evt_spi_06_stealer_write", ts: T(3 * MIN + 18_000),
      path: "C:\\Users\\d.avraham\\AppData\\Local\\Temp\\sysdata\\upd_helper.exe", sha256: stealerHash, signed: false, size: 3_251_712,
      initiatingProcess: "PuTTY-0.83-installer.exe", severity: "medium",
      description: "PuTTY-0.83-installer.exe wrote C:\\Users\\d.avraham\\AppData\\Local\\Temp\\sysdata\\upd_helper.exe, unsigned.",
    }), INSTALLER),

    // 7. It runs, parented by the installer; the installer exits with a fake error.
    mdeProcess({
      ...mde, id: "evt_spi_07_stealer_exec", ts: T(3 * MIN + 22_000),
      processName: "upd_helper.exe", pid: 7801,
      processPath: "C:\\Users\\d.avraham\\AppData\\Local\\Temp\\sysdata\\upd_helper.exe",
      cmdline: "upd_helper.exe", parentName: "PuTTY-0.83-installer.exe", parentPid: 7744,
      sha256: stealerHash, signed: false, integrity: "Medium", severity: "high",
      description: "upd_helper.exe started, parented by the installer process. PuTTY-0.83-installer.exe exited seconds later reporting \"Setup failed, please try again.\"",
    }),

    // 8. THE EVENT THAT MATTERS, a copy of Chrome's own credential-store filename
    //    (no hash logged for the copied DB) appears outside the browser's profile.
    initiatedBy(mdeFile({
      ...mde, id: "evt_spi_08_cred_copy", ts: T(6 * MIN + 40_000),
      path: "C:\\Users\\d.avraham\\AppData\\Local\\Temp\\sysdata\\Chrome_Default\\Login Data", sha256: null, size: 122_880,
      initiatingProcess: "upd_helper.exe", initiatingCmdline: "upd_helper.exe",
      mitre: "T1555.003", tactic: "Credential Access", severity: "critical", isDetection: true,
      description: "upd_helper.exe created C:\\Users\\d.avraham\\AppData\\Local\\Temp\\sysdata\\Chrome_Default\\Login Data, 120 KB, the same filename Chrome uses for its own SQLite credential store, which was still open and locked in the running browser.",
    }), STEALER, "upd_helper.exe"),
    ...[
      { n: "a", ms: 6 * MIN + 41_000, name: "Cookies", size: 1_310_720 },
      { n: "b", ms: 6 * MIN + 42_000, name: "Web Data", size: 188_416 },
      { n: "c", ms: 6 * MIN + 44_000, name: "Local State", size: 3_104 },
    ].map(f => initiatedBy(mdeFile({
      ...mde, id: `evt_spi_08${f.n}_profile_copy`, ts: T(f.ms),
      path: `C:\\Users\\d.avraham\\AppData\\Local\\Temp\\sysdata\\Chrome_Default\\${f.name}`, sha256: null, size: f.size,
      initiatingProcess: "upd_helper.exe", initiatingCmdline: "upd_helper.exe",
      mitre: "T1555.003", tactic: "Credential Access", severity: "high",
      description: `upd_helper.exe created C:\\Users\\d.avraham\\AppData\\Local\\Temp\\sysdata\\Chrome_Default\\${f.name} in the same folder as the Login Data copy.`,
    }), STEALER, "upd_helper.exe")),

    // ---------------------------------------------------------------------
    // 9. It leaves the building. (PAN emitter, outbound exfil POST)
    // ---------------------------------------------------------------------
    panWeb({
      ...mde, id: "evt_spi_09_exfil", ts: T(7 * MIN), severity: "critical",
      method: "POST", url: `https://${c2}/collect`, domain: c2, category: "unknown",
      action: "allow", dstIp: "185.212.44.19", status: 200, bytesOut: 348_112, bytesIn: 96,
      mitre: "T1041", tactic: "Exfiltration",
      description: "At 14:27:00 the host POSTed a 340 KB multipart payload to cdn-assets-relay92.net/collect, allowed under the category unknown.",
    }),

    initiatedBy(mdeNetwork({
      ...mde, id: "evt_spi_09b_exfil_conn", ts: T(6 * MIN + 59_800), severity: "critical",
      remoteIp: "185.212.44.19", remotePort: 443, application: "tls", domain: c2,
      url: `https://${c2}/collect`, initiatingProcess: "upd_helper.exe",
      mitre: "T1041", tactic: "Exfiltration",
      description: "upd_helper.exe (pid 7801) connected to 185.212.44.19:443 and requested https://cdn-assets-relay92.net/collect.",
    }), STEALER, "upd_helper.exe"),

    // Defender's antivirus engine quarantines the payload; the file leaves disk.
    {
      ...initiatedBy(mdeDetection({
        ...mde, id: "evt_spi_10a_av_detection", ts: T(7 * MIN + 19_000), severity: "high",
        processName: "upd_helper.exe", processPath: STEALER.path, cmdline: "upd_helper.exe", parentName: "PuTTY-0.83-installer.exe",
        sha256: stealerHash, threatName: "Trojan:Win32/Rhadesta.SP!MTB", category: "Malware", action: "quarantined",
        mitre: "T1555.003", tactic: "Credential Access",
        description: "Microsoft Defender Antivirus detected Trojan:Win32/Rhadesta.SP!MTB in upd_helper.exe and quarantined it at 14:27:19.",
      }), STEALER, "upd_helper.exe"),
      is_detection: true,
    },
    initiatedBy(mdeFile({
      ...mde, id: "evt_spi_10b_payload_removed", ts: T(7 * MIN + 21_000), action: "file_delete",
      path: STEALER.path, sha256: stealerHash, initiatingProcess: "MsMpEng.exe", severity: "medium",
      description: "MsMpEng.exe removed C:\\Users\\d.avraham\\AppData\\Local\\Temp\\sysdata\\upd_helper.exe (quarantine).",
    }), { name: "MsMpEng.exe", pid: 3120, path: "C:\\ProgramData\\Microsoft\\Windows Defender\\Platform\\4.18.24090.11-0\\MsMpEng.exe", parent: "services.exe", parentPid: 668 }, `"C:\\ProgramData\\Microsoft\\Windows Defender\\Platform\\4.18.24090.11-0\\MsMpEng.exe"`),

    // ---------------------------------------------------------------------
    // 10. The incident, once Defender's behavioural engine caught up. (MDE alert emitter  - 
    //     a Defender incident summary; no process node of its own.)
    // ---------------------------------------------------------------------
    {
      ...mdeAlert({
        ...mde, id: "evt_spi_10_alert", ts: T(7 * MIN + 20_000), severity: "high",
        alertTitle: "Infostealer detected, browser credential store copied and exfiltrated",
        category: "CredentialAccess", detectionSource: "AntivirusBehavior", evidenceRole: "Impacted",
        mdeIncidentId: "38821", sha256: stealerHash,
        malwareCategory: "infostealer", malwareName: "Trojan:Win32/Rhadesta.SP!MTB", alertSeverity: "High",
        mitre: "T1555.003", techniqueName: "Credentials from Web Browsers",
        remediation: "Quarantine", expectedVerdict: "tp",
        description: "Defender raised a High-severity infostealer incident on LAP-3312, tying the unsigned dropper to the Chrome credential-store copy and the outbound POST; it quarantined upd_helper.exe at 14:27:20, after the exfiltration POST at 14:27:00 had already completed.",
      }),
      edr_scope: "edr",
      process: { pid: STEALER.pid, name: STEALER.name, path: STEALER.path, cmdline: "upd_helper.exe", parent_name: STEALER.parent, parent_pid: STEALER.parentPid, user: `NEXACORP\\${victim.sam}`, hash: { sha256: stealerHash } },
      file: { name: STEALER.name, path: STEALER.path, sha256: stealerHash },
    },

    // Threat-intelligence enrichment for the two domains (an analyst lookup, after the alert).
    intelLookup({
      id: "evt_spi_11_ti_enrichment", ts: T(8 * MIN), incidentId: INCIDENT, severity: "medium",
      message: "Entity lookup: puttysoftware-download.com, cdn-assets-relay92.net.",
      rows: [
        { entity: lookalike, type: "InternetDomainName", riskScore: 65, riskString: "2/12",
          evidence: [{ rule: "Recently Registered Domain", criticality: "Suspicious" }, { rule: "Typosquat of a Popular Software Project", criticality: "Suspicious" }],
          registration: { created: "2026-03-04", registrar: "NameSilo, LLC", ageDays: 7 } },
        { entity: c2, type: "InternetDomainName", riskScore: 78, riskString: "3/12",
          evidence: [{ rule: "Recently Registered Domain", criticality: "Suspicious" }, { rule: "Linked to Malware Distribution", criticality: "Malicious" }],
          registration: { created: "2026-03-05", registrar: "NameSilo, LLC", ageDays: 6 } },
      ],
      description: "Recorded Future lookup of puttysoftware-download.com and cdn-assets-relay92.net returned both as recently registered domains with risk scores above the alerting threshold.",
    }),
  ];

  // Story order: the log is read oldest-first.
  events.sort((a, b) => a.ts.localeCompare(b.ts));

  // Every event belongs to the one infostealer incident.
  for (const e of events) e.incident_id = INCIDENT;

  return { title: "High-severity Defender incident on an admin laptop", events, T, MIN, host, lookalike, c2, installerHash, stealerHash };
}
