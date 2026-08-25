/**
 * Scenario pack: "Sponsored Result — SEO-Poisoned PuTTY Installer with an Infostealer"
 *
 * FOUNDATION tier. One user, one laptop, no lateral movement, no cross-account
 * credential theft, no cloud pivot. A systems administrator searches for PuTTY,
 * a genuine and extremely common admin tool, and clicks the sponsored result
 * instead of the organic one. The paid ad slot was bought by an attacker and
 * points at a lookalike download site, not the real PuTTY project — this is
 * malvertising / SEO poisoning of a search result (T1608.006), which is a
 * distinct initial-access story from a compromised legitimate site serving a
 * drive-by, and from a phishing email.
 *
 * The installer she downloads is a loader: it opens, briefly shows a setup
 * window, then fails with a generic error and leaves no working copy of PuTTY
 * on the machine. In the four seconds it ran, it fetched a second-stage payload
 * from its own infrastructure (T1105) and launched it. That payload is an
 * infostealer, and the discriminating evidence for what it does is one file
 * event: it recreates a file named "Login Data" — Chrome's own credential
 * database filename — inside a Temp folder that has nothing to do with Chrome,
 * because the real one is locked while the browser holds it open (T1555.003).
 *
 * Covers T1608.006 (Stage Capabilities: SEO Poisoning), T1204.002 (User
 * Execution: Malicious File), T1105 (Ingress Tool Transfer) and T1555.003
 * (Credentials from Password Stores: Credentials from Web Browsers).
 *
 * SOURCE-LIGHT: only `edr` (Microsoft Defender for Endpoint) and `firewall`
 * (Palo Alto Networks NGFW) events.
 *
 * NOTE: `difficulty: "foundation"` is declared on the SCENARIOS registry entry
 * in scenarios.ts (ScenarioBundle itself carries no difficulty field).
 */

import type { ScenarioBundle, TelemetryEvent, IOC, ScenarioQuestion } from "@/lib/sim/types";
import { makeSha256 } from "@/lib/sim/iocs";

export function buildSeoPoisonedInstallerScenario(
  scenarioId = "seo-poisoned-installer-2026",
): ScenarioBundle {
  const B = new Date("2026-03-11T14:20:00Z").getTime();
  const T = (ms: number) => new Date(B + ms).toISOString();
  const MIN = 60_000;

  const host = { hostname: "LAP-3312", ip: "10.14.19.63" };
  const victim = { email: "d.avraham@nexacorp.com", name: "Dor Avraham", sam: "d.avraham" };
  const deviceId = "224e37355dd22197935d79f9a23781bb07bd0c1a";

  const lookalike = "puttysoftware-download.com";
  const c2 = "cdn-assets-relay92.net";

  const installerHash = makeSha256("puttysoftware_download_fake_putty_installer_2026");
  const stealerHash = makeSha256("cdn_assets_relay92_stealer_payload_upd_helper_2026");

  const events: TelemetryEvent[] = [
    // ---------------------------------------------------------------------
    // 1. The sponsored result. Nothing here is a known-bad domain.
    // ---------------------------------------------------------------------
    {
      id: "evt_spi_01_ad_click",
      ts: T(0),
      source: "firewall",
      vendor: "Palo Alto Networks NGFW",
      event_type: "http_request",
      hostname: host.hostname,
      user_email: victim.email,
      user_title: "Systems Administrator",
      src_ip: host.ip,
      severity: "medium",
      mitre_technique: "T1608.006",
      mitre_tactic: "Resource Development",
      description:
        "LAP-3312 followed the sponsored result for \"putty ssh client download\" at 14:20 and landed on puttysoftware-download.com — a domain unrelated to the official PuTTY project — carrying a Google search results page as its referer.",
      network: {
        url: `https://${lookalike}/download`,
        domain: lookalike,
        method: "GET",
        status: 200,
        bytes_in: 41_280,
        user_agent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/126.0.0.0 Safari/537.36",
      },
      raw: {
        "pan.type": "THREAT",
        "pan.subtype": "url",
        "pan.action": "alert",
        "pan.rule": "CORP-WEB-OUTBOUND",
        "pan.src": host.ip,
        "pan.srcuser": `nexacorp\\${victim.sam}`,
        "pan.dst": "146.70.108.44",
        "pan.dport": "443",
        "pan.app": "web-browsing",
        "pan.category": "newly-registered-domain",
        "pan.url": `${lookalike}/download`,
        "pan.referer": "https://www.google.com/search?q=putty+ssh+client+download",
        "pan.http_method": "GET",
        "pan.from_zone": "TRUST",
        "pan.to_zone": "UNTRUST",
        "pan.session_id": "702214",
        "source.ip": host.ip,
        "url.domain": lookalike,
        "http.response.status_code": "200",
        "action_result": "alert",
      },
    },

    // ---------------------------------------------------------------------
    // 2. The download from the same lookalike host.
    // ---------------------------------------------------------------------
    {
      id: "evt_spi_02_download",
      ts: T(45_000),
      source: "firewall",
      vendor: "Palo Alto Networks NGFW",
      event_type: "http_request",
      hostname: host.hostname,
      user_email: victim.email,
      src_ip: host.ip,
      severity: "medium",
      mitre_technique: "T1608.006",
      mitre_tactic: "Resource Development",
      description:
        "Forty-five seconds later the same browser session downloaded PuTTY-0.83-installer.exe from puttysoftware-download.com.",
      file: {
        name: "PuTTY-0.83-installer.exe",
        path: "/download/PuTTY-0.83-installer.exe",
        extension: "exe",
        size: 1_812_224,
        sha256: installerHash,
      },
      network: {
        url: `https://${lookalike}/download/PuTTY-0.83-installer.exe`,
        domain: lookalike,
        method: "GET",
        status: 200,
        bytes_in: 1_812_224,
      },
      raw: {
        "pan.type": "THREAT",
        "pan.subtype": "file",
        "pan.action": "alert",
        "pan.rule": "CORP-WEB-OUTBOUND",
        "pan.src": host.ip,
        "pan.srcuser": `nexacorp\\${victim.sam}`,
        "pan.dst": "146.70.108.44",
        "pan.dport": "443",
        "pan.app": "web-browsing",
        "pan.category": "newly-registered-domain",
        "pan.url": `${lookalike}/download/PuTTY-0.83-installer.exe`,
        "pan.filename": "PuTTY-0.83-installer.exe",
        "pan.filetype": "pe",
        "pan.file_hash": installerHash,
        "pan.direction": "download",
        "pan.session_id": "702214",
        "source.ip": host.ip,
        "url.domain": lookalike,
        "action_result": "alert",
      },
    },

    // ---------------------------------------------------------------------
    // 3. The file lands in Downloads, as the endpoint saw it.
    // ---------------------------------------------------------------------
    {
      id: "evt_spi_03_file_write",
      ts: T(50_000),
      source: "edr",
      vendor: "Microsoft Defender for Endpoint",
      event_type: "file_create",
      hostname: host.hostname,
      user_email: victim.email,
      src_ip: host.ip,
      severity: "low",
      description:
        "chrome.exe wrote C:\\Users\\d.avraham\\Downloads\\PuTTY-0.83-installer.exe at 14:20:50.",
      file: {
        name: "PuTTY-0.83-installer.exe",
        path: "C:\\Users\\d.avraham\\Downloads\\PuTTY-0.83-installer.exe",
        extension: "exe",
        size: 1_812_224,
        sha256: installerHash,
      },
      raw: {
        "mde.ActionType": "FileCreated",
        "mde.DeviceName": host.hostname,
        "mde.DeviceId": deviceId,
        "mde.ReportId": "184402",
        "file.name": "PuTTY-0.83-installer.exe",
        "file.path": "C:\\Users\\d.avraham\\Downloads\\PuTTY-0.83-installer.exe",
        "file.extension": "exe",
        "file.size": "1812224",
        "file.hash.sha256": installerHash,
        "mde.InitiatingProcessFileName": "chrome.exe",
        "user.name": `NEXACORP\\${victim.sam}`,
        "host.name": host.hostname,
        "host.ip": host.ip,
      },
    },

    // ---------------------------------------------------------------------
    // 4. She runs it. Unsigned, elevated on the UAC prompt she accepted.
    // ---------------------------------------------------------------------
    {
      id: "evt_spi_04_execute",
      ts: T(3 * MIN + 10_000),
      source: "edr",
      vendor: "Microsoft Defender for Endpoint",
      event_type: "process_create",
      hostname: host.hostname,
      user_email: victim.email,
      src_ip: host.ip,
      severity: "high",
      mitre_technique: "T1204.002",
      mitre_tactic: "Execution",
      description:
        "At 14:23:10 explorer.exe started PuTTY-0.83-installer.exe, unsigned, from the Downloads folder.",
      process: {
        name: "PuTTY-0.83-installer.exe",
        pid: 7744,
        path: "C:\\Users\\d.avraham\\Downloads\\PuTTY-0.83-installer.exe",
        parent_name: "explorer.exe",
        parent_pid: 3392,
        cmdline: '"C:\\Users\\d.avraham\\Downloads\\PuTTY-0.83-installer.exe"',
        user: `NEXACORP\\${victim.sam}`,
        integrity: "high",
        hash: { sha256: installerHash },
      },
      raw: {
        "mde.ActionType": "ProcessCreated",
        "mde.DeviceName": host.hostname,
        "mde.DeviceId": deviceId,
        "mde.ReportId": "184418",
        "process.name": "PuTTY-0.83-installer.exe",
        "process.pid": "7744",
        "process.executable": "C:\\Users\\d.avraham\\Downloads\\PuTTY-0.83-installer.exe",
        "process.command_line": '"C:\\Users\\d.avraham\\Downloads\\PuTTY-0.83-installer.exe"',
        "process.hash.sha256": installerHash,
        "process.code_signature.status": "unsigned",
        "process.integrity_level": "High",
        "process.parent.name": "explorer.exe",
        "process.parent.pid": "3392",
        "mde.AccountName": victim.sam,
        "user.name": `NEXACORP\\${victim.sam}`,
        "host.name": host.hostname,
        "host.ip": host.ip,
      },
    },

    // ---------------------------------------------------------------------
    // 5. Four seconds into running, the installer fetches its real payload.
    // ---------------------------------------------------------------------
    {
      id: "evt_spi_05_stage2_fetch",
      ts: T(3 * MIN + 14_000),
      source: "firewall",
      vendor: "Palo Alto Networks NGFW",
      event_type: "http_request",
      hostname: host.hostname,
      user_email: victim.email,
      src_ip: host.ip,
      severity: "critical",
      mitre_technique: "T1105",
      mitre_tactic: "Command and Control",
      description:
        "At 14:23:14 the installer process fetched upd_helper.exe, 3.1 MB, from cdn-assets-relay92.net — infrastructure with no relationship to puttysoftware-download.com.",
      file: { name: "upd_helper.exe", path: "/dist/upd_helper.exe", extension: "exe", size: 3_251_712, sha256: stealerHash },
      network: {
        url: `https://${c2}/dist/upd_helper.exe`,
        domain: c2,
        method: "GET",
        status: 200,
        bytes_in: 3_251_712,
      },
      raw: {
        "pan.type": "THREAT",
        "pan.subtype": "file",
        "pan.action": "alert",
        "pan.rule": "CORP-WEB-OUTBOUND",
        "pan.src": host.ip,
        "pan.srcuser": `nexacorp\\${victim.sam}`,
        "pan.dst": "185.212.44.19",
        "pan.dport": "443",
        "pan.app": "web-browsing",
        "pan.category": "unknown",
        "pan.url": `${c2}/dist/upd_helper.exe`,
        "pan.filename": "upd_helper.exe",
        "pan.filetype": "pe",
        "pan.file_hash": stealerHash,
        "pan.direction": "download",
        "pan.session_id": "702239",
        "source.ip": host.ip,
        "url.domain": c2,
        "action_result": "alert",
      },
    },

    // ---------------------------------------------------------------------
    // 6. It lands on disk, in a folder the installer created for itself.
    // ---------------------------------------------------------------------
    {
      id: "evt_spi_06_stealer_write",
      ts: T(3 * MIN + 18_000),
      source: "edr",
      vendor: "Microsoft Defender for Endpoint",
      event_type: "file_create",
      hostname: host.hostname,
      user_email: victim.email,
      src_ip: host.ip,
      severity: "medium",
      description:
        "PuTTY-0.83-installer.exe wrote C:\\Users\\d.avraham\\AppData\\Local\\Temp\\sysdata\\upd_helper.exe, unsigned.",
      file: {
        name: "upd_helper.exe",
        path: "C:\\Users\\d.avraham\\AppData\\Local\\Temp\\sysdata\\upd_helper.exe",
        extension: "exe",
        size: 3_251_712,
        sha256: stealerHash,
      },
      raw: {
        "mde.ActionType": "FileCreated",
        "mde.DeviceName": host.hostname,
        "mde.DeviceId": deviceId,
        "mde.ReportId": "184431",
        "file.name": "upd_helper.exe",
        "file.path": "C:\\Users\\d.avraham\\AppData\\Local\\Temp\\sysdata\\upd_helper.exe",
        "file.extension": "exe",
        "file.size": "3251712",
        "file.hash.sha256": stealerHash,
        "file.signature.status": "unsigned",
        "mde.InitiatingProcessFileName": "PuTTY-0.83-installer.exe",
        "process.parent.pid": "7744",
        "user.name": `NEXACORP\\${victim.sam}`,
        "host.name": host.hostname,
      },
    },

    // ---------------------------------------------------------------------
    // 7. It runs. The installer window closes with a generic setup error —
    //    she never gets a working copy of PuTTY.
    // ---------------------------------------------------------------------
    {
      id: "evt_spi_07_stealer_exec",
      ts: T(3 * MIN + 22_000),
      source: "edr",
      vendor: "Microsoft Defender for Endpoint",
      event_type: "process_create",
      hostname: host.hostname,
      user_email: victim.email,
      src_ip: host.ip,
      severity: "high",
      description:
        "upd_helper.exe started, parented by the installer process. PuTTY-0.83-installer.exe exited seconds later reporting \"Setup failed — please try again.\"",
      process: {
        name: "upd_helper.exe",
        pid: 7801,
        path: "C:\\Users\\d.avraham\\AppData\\Local\\Temp\\sysdata\\upd_helper.exe",
        parent_name: "PuTTY-0.83-installer.exe",
        parent_pid: 7744,
        cmdline: "upd_helper.exe",
        user: `NEXACORP\\${victim.sam}`,
        integrity: "medium",
        hash: { sha256: stealerHash },
      },
      raw: {
        "mde.ActionType": "ProcessCreated",
        "mde.DeviceName": host.hostname,
        "mde.DeviceId": deviceId,
        "mde.ReportId": "184440",
        "process.name": "upd_helper.exe",
        "process.pid": "7801",
        "process.executable": "C:\\Users\\d.avraham\\AppData\\Local\\Temp\\sysdata\\upd_helper.exe",
        "process.command_line": "upd_helper.exe",
        "process.hash.sha256": stealerHash,
        "process.code_signature.status": "unsigned",
        "process.integrity_level": "Medium",
        "process.parent.name": "PuTTY-0.83-installer.exe",
        "process.parent.pid": "7744",
        "user.name": `NEXACORP\\${victim.sam}`,
        "host.name": host.hostname,
        "host.ip": host.ip,
      },
    },

    // ---------------------------------------------------------------------
    // 8. THE EVENT THAT MATTERS — a copy of Chrome's own credential store
    //    filename appears in a folder that has nothing to do with Chrome.
    // ---------------------------------------------------------------------
    {
      id: "evt_spi_08_cred_copy",
      ts: T(6 * MIN + 40_000),
      source: "edr",
      vendor: "Microsoft Defender for Endpoint",
      event_type: "file_create",
      hostname: host.hostname,
      user_email: victim.email,
      src_ip: host.ip,
      severity: "critical",
      mitre_technique: "T1555.003",
      mitre_tactic: "Credential Access",
      description:
        "upd_helper.exe created C:\\Users\\d.avraham\\AppData\\Local\\Temp\\sysdata\\Chrome_Default\\Login Data, 120 KB — the same filename Chrome uses for its own SQLite credential store, which was still open and locked in the running browser. Cookies and Web Data followed in the same burst.",
      file: {
        name: "Login Data",
        path: "C:\\Users\\d.avraham\\AppData\\Local\\Temp\\sysdata\\Chrome_Default\\Login Data",
        size: 122_880,
      },
      raw: {
        "mde.ActionType": "FileCreated",
        "mde.DeviceName": host.hostname,
        "mde.DeviceId": deviceId,
        "mde.ReportId": "184501",
        "file.name": "Login Data",
        "file.path": "C:\\Users\\d.avraham\\AppData\\Local\\Temp\\sysdata\\Chrome_Default\\Login Data",
        "file.size": "122880",
        "mde.InitiatingProcessFileName": "upd_helper.exe",
        "mde.InitiatingProcessCommandLine": "upd_helper.exe",
        "user.name": `NEXACORP\\${victim.sam}`,
        "host.name": host.hostname,
        "host.ip": host.ip,
      },
    },

    // ---------------------------------------------------------------------
    // 9. It leaves the building.
    // ---------------------------------------------------------------------
    {
      id: "evt_spi_09_exfil",
      ts: T(7 * MIN),
      source: "firewall",
      vendor: "Palo Alto Networks NGFW",
      event_type: "http_request",
      hostname: host.hostname,
      user_email: victim.email,
      src_ip: host.ip,
      severity: "critical",
      mitre_technique: "T1041",
      mitre_tactic: "Exfiltration",
      description:
        "At 14:27:00 the host POSTed a 340 KB multipart payload to cdn-assets-relay92.net/collect, allowed under the category unknown.",
      network: {
        url: `https://${c2}/collect`,
        domain: c2,
        method: "POST",
        status: 200,
        bytes_out: 348_112,
        bytes_in: 96,
      },
      raw: {
        "pan.type": "TRAFFIC",
        "pan.subtype": "end",
        "pan.action": "allow",
        "pan.rule": "CORP-WEB-OUTBOUND",
        "pan.src": host.ip,
        "pan.srcuser": `nexacorp\\${victim.sam}`,
        "pan.dst": "185.212.44.19",
        "pan.dport": "443",
        "pan.app": "web-browsing",
        "pan.category": "unknown",
        "pan.url": `${c2}/collect`,
        "pan.http_method": "POST",
        "pan.bytes_sent": "348112",
        "pan.bytes_received": "96",
        "pan.session_id": "702318",
        "source.ip": host.ip,
        "url.domain": c2,
        "http.request.method": "POST",
        "action_result": "allow",
      },
    },

    // ---------------------------------------------------------------------
    // 10. The incident, once Defender's behavioural engine caught up.
    // ---------------------------------------------------------------------
    {
      id: "evt_spi_10_alert",
      mitre_technique: "T1555.003",
      ts: T(7 * MIN + 20_000),
      source: "edr",
      vendor: "Microsoft Defender for Endpoint",
      event_type: "edr_alert",
      hostname: host.hostname,
      user_email: victim.email,
      src_ip: host.ip,
      severity: "critical",
      description:
        "Defender raised a High-severity infostealer incident on LAP-3312, tying the unsigned dropper to the Chrome credential-store copy and the outbound POST, and quarantined upd_helper.exe after the transfer had already completed.",
      raw: {
        "mde.AlertTitle": "Infostealer detected — browser credential store copied and exfiltrated",
        "mde.Category": "CredentialAccess",
        "mde.DetectionSource": "AntivirusBehavior",
        "mde.EvidenceRole": "Impacted",
        "mde.IncidentId": "38821",
        "mde.DeviceName": host.hostname,
        "mde.DeviceId": deviceId,
        "mde.ReportId": "184522",
        "mde.SHA256": stealerHash,
        "malware.category": "infostealer",
        "malware.name": "Trojan:Win32/Rhadesta.SP!MTB",
        "alert.severity": "High",
        "alert.category": "CredentialAccess",
        "threat.technique.id": "T1555.003",
        "threat.technique.name": "Credentials from Web Browsers",
        "remediation.action": "Quarantine",
        "remediation.status": "Completed",
        "user.name": `NEXACORP\\${victim.sam}`,
        "host.name": host.hostname,
        "host.ip": host.ip,
        "event.action": "alert",
      },
    },
  ];

  const iocs: IOC[] = [
    {
      type: "domain",
      value: lookalike,
      first_seen: T(0),
      last_seen: T(45_000),
      reputation: "malicious",
      tags: ["malvertising", "lookalike-domain", "fake-installer"],
    },
    {
      type: "domain",
      value: c2,
      first_seen: T(3 * MIN + 14_000),
      last_seen: T(7 * MIN),
      reputation: "malicious",
      tags: ["c2", "payload-staging", "outbound-post-target"],
    },
    {
      type: "sha256",
      value: installerHash,
      first_seen: T(45_000),
      last_seen: T(3 * MIN + 22_000),
      reputation: "malicious",
      tags: ["dropper", "unsigned", "loader"],
    },
    {
      type: "sha256",
      value: stealerHash,
      first_seen: T(3 * MIN + 14_000),
      last_seen: T(7 * MIN + 20_000),
      reputation: "malicious",
      tags: ["infostealer", "unsigned"],
    },
    {
      type: "host",
      value: host.hostname,
      first_seen: T(0),
      last_seen: T(7 * MIN + 20_000),
      reputation: "unknown",
      tags: ["user-endpoint", "affected"],
    },
  ];

  const questions: ScenarioQuestion[] = [
    {
      id: "q1",
      prompt:
        "The domain in evt_spi_01 had no abuse history and isn't a compromised legitimate site. How should this initial-access step be classified?",
      hint: "Look at pan.referer — the traffic arrived from a search results page, not from a link on another publisher's site.",
      kind: "single",
      options: [
        { value: "seo_poisoning", label: "SEO poisoning / malvertising — a paid or manipulated search result pointed directly at attacker infrastructure" },
        { value: "driveby", label: "Drive-by compromise — a legitimate site was hacked and served the download without her clicking anything" },
        { value: "phishing", label: "Phishing — she followed a malicious link delivered by email" },
        { value: "supply_chain", label: "Supply-chain compromise — the real PuTTY project's build pipeline was tampered with" },
      ],
      answer: "seo_poisoning",
      xp: 50,
      explanation:
        "The referer is a Google search results page, and the destination is a domain built specifically to look like a software download site — not a hacked publisher. That combination is the signature of a poisoned or purchased search result (T1608.006): the attacker doesn't need to compromise anything, only to outrank or outbid the real project for the query she typed. Drive-by compromise (b) requires a genuine site to be hijacked, which nothing here shows. Phishing (c) requires an email or message as the delivery channel — there is none in this chain. Supply-chain compromise (d) would mean the real chiark.greenend.org.uk build process was tampered with, which is a far larger claim than the evidence supports.",
    },
    {
      id: "q2",
      prompt:
        "pan.category on evt_spi_01 is 'newly-registered-domain', yet pan.action is 'alert', not 'block'. What does that tell you about this environment's firewall policy?",
      kind: "single",
      options: [
        { value: "log_only", label: "The newly-registered-domain category is configured to log and allow, not block — visibility without prevention" },
        { value: "tls_bypass", label: "TLS inspection was bypassed for this session, so the firewall couldn't act on it" },
        { value: "misconfigured", label: "The rule is broken; newly-registered-domain should always hard-block and this is a bug" },
        { value: "allowlisted", label: "puttysoftware-download.com must be on an explicit corporate allowlist" },
      ],
      answer: "log_only",
      xp: 40,
      explanation:
        "pan.action: 'alert' is a deliberate outcome, not an error — many organisations log risky categories like newly-registered-domain without hard-blocking them, because the false-positive rate on legitimate new sites is high. The firewall did its job: it captured the URL, the file, and the hash for exactly this kind of after-the-fact investigation. Option (b) is contradicted by the log itself, which has full URLs and filenames — TLS inspection was clearly active. Option (c) assumes a policy bug without evidence; 'alert' is a valid, common policy choice. Option (d) has nothing supporting it and doesn't fit a domain the log itself still categorises as risky.",
    },
    {
      id: "q3",
      prompt:
        "Which pair of events together shows that PuTTY-0.83-installer.exe was a loader rather than a simple standalone trojan?",
      hint: "Compare the process that started at 14:23:10 with what happened four seconds later.",
      kind: "single",
      options: [
        { value: "exec_and_fetch", label: "evt_spi_04_execute and evt_spi_05_stage2_fetch — the installer process itself reached out and pulled a second binary seconds after it started" },
        { value: "download_and_write", label: "evt_spi_02_download and evt_spi_03_file_write — the installer was downloaded and then written to disk" },
        { value: "write_and_exec", label: "evt_spi_06_stealer_write and evt_spi_07_stealer_exec — the second binary was written and then run" },
        { value: "copy_and_exfil", label: "evt_spi_08_cred_copy and evt_spi_09_exfil — credentials were staged and then sent out" },
      ],
      answer: "exec_and_fetch",
      xp: 60,
      explanation:
        "A plain trojan would simply run the malicious code that was already inside the file the user downloaded. Here, evt_spi_04 shows PuTTY-0.83-installer.exe (PID 7744) starting, and evt_spi_05 shows that same session reaching out to entirely different infrastructure — cdn-assets-relay92.net, unrelated to puttysoftware-download.com — four seconds later to retrieve upd_helper.exe. That fetch-after-execution pattern is Ingress Tool Transfer (T1105): the first-stage file's job was only to get a second file onto the host and run it. (b) shows delivery, not loader behaviour; (c) shows the second stage executing, which is a consequence of the loader step, not the loader step itself; (d) is the credential-theft and exfiltration pair, three technique-slots later in the chain.",
    },
    {
      id: "q4",
      prompt:
        "evt_spi_08_cred_copy shows a file named exactly 'Login Data' being created inside a Temp subfolder. Why is that specific detail, on its own, enough to call this credential theft?",
      kind: "single",
      options: [
        { value: "filename_outside_chrome", label: "'Login Data' is Chrome's own credential-database filename, and it has no legitimate reason to exist outside Chrome's own profile folder" },
        { value: "file_size", label: "120 KB is an unusually large file for a Temp folder to contain" },
        { value: "medium_integrity", label: "The initiating process was running at medium integrity, which it shouldn't be able to do" },
        { value: "parent_process", label: "Its parent process was the original installer, which proves malicious intent by itself" },
      ],
      answer: "filename_outside_chrome",
      xp: 60,
      explanation:
        "Chrome stores its saved-password database at a fixed path under the browser's own profile, using the exact filename 'Login Data'. That name reappearing under AppData\\Local\\Temp\\sysdata\\Chrome_Default, created by an unrelated unsigned process, has essentially one explanation: the process copied the real database out of its locked location — attackers do this because Chrome holds Login Data open while it runs, so a direct read fails and a copy succeeds (T1555.003). 120 KB (b) is an ordinary size for that database, not a red flag by itself. Medium integrity (c) is normal for a standard user process and doesn't indicate anything wrong on its own. The parent process (d) is useful corroborating context, but the filename match is what actually identifies the technique — a differently-named file in the same location would not tell you the same story.",
    },
    {
      id: "q5",
      prompt:
        "You're scoping the response. Login Data holds every saved website password in that Chrome profile, not just corporate ones. What does that mean for remediation?",
      kind: "single",
      options: [
        { value: "full_reset", label: "Reset her corporate password and also have her personally re-secure every non-corporate account saved in that browser profile" },
        { value: "corp_only", label: "Resetting her domain password is sufficient — the browser store is a local artifact and doesn't extend the exposure" },
        { value: "wipe_only", label: "Reimaging the laptop resolves the exposure; no passwords need to be changed" },
        { value: "wait_confirm", label: "Wait for confirmation the attacker actually used the data before resetting anything, to avoid unnecessary disruption" },
      ],
      answer: "full_reset",
      xp: 60,
      explanation:
        "A browser credential store isn't scoped to one application — it holds whatever the user saved, which routinely includes personal banking, webmail, shopping and social accounts alongside corporate SSO. evt_spi_09 shows the staged data already left the host, so you have to assume everything in that store is exposed and act on all of it, not just the domain account. (b) draws a boundary the attacker's collection method didn't respect. (c) fixes the endpoint but does nothing about credentials that already left before the reimage. (d) trades a known compromise for confirmation you're very unlikely to get — attacker infrastructure doesn't report back on what it did with stolen data.",
    },
  ];

  return {
    scenario_id: scenarioId,
    title: "Sponsored Result — SEO-Poisoned PuTTY Installer with an Infostealer",
    threat_actor: "Commodity infostealer distributor (malvertising / SEO poisoning)",
    attack_kind: "seo_poisoned_installer",
    briefing:
      "Microsoft Defender for Endpoint raised a High-severity infostealer incident on LAP-3312 at 14:27. The user says she was installing PuTTY this afternoon for a routine SSH task. Work out how the installer got onto the machine, what it actually did, and what has left the building.",
    narrative: `At 14:20 Dor Avraham, a systems administrator, searched for "putty ssh client download" and clicked the sponsored result rather than the organic one. It took her to puttysoftware-download.com — a domain with no connection to the real PuTTY project, and no abuse history either, because it was registered for exactly this purpose. The firewall logged it under newly-registered-domain and let it through: that category is set to log, not block.

Forty-five seconds later she downloaded PuTTY-0.83-installer.exe from the same host, and ran it at 14:23:10. The file is unsigned. Four seconds after it started, the installer process itself reached out to a second, unrelated domain — cdn-assets-relay92.net — and pulled down upd_helper.exe, 3.1 MB. The original installer was never going to install PuTTY; its only job was to fetch this.

upd_helper.exe ran, and the installer window closed a moment later with a generic "Setup failed" message. She never got a working copy of PuTTY. What she did get, over the next few minutes, was a new folder under her own Temp directory — AppData\\Local\\Temp\\sysdata\\Chrome_Default — containing a file named Login Data, 120 KB, the same filename and size class as Chrome's own saved-password database. Chrome holds that file open and locked while it runs, so upd_helper.exe copied it instead of reading it directly. Cookies and Web Data followed in the same burst.

At 14:27 the host POSTed a 340 KB payload to cdn-assets-relay92.net/collect. The firewall allowed it — the domain's category is unknown, which carries no blocking policy. Defender's behavioural engine caught up twenty seconds later and raised the incident, quarantining upd_helper.exe. By then the credential store had already left the building.`,
    learning_objectives: [
      "Recognise SEO-poisoned / malvertised search results (T1608.006) as an initial-access vector distinct from compromised-site drive-by or phishing email",
      "Read a firewall's category-vs-action fields to understand log-only policies on risky-but-unconfirmed domains",
      "Correlate a user-execution event with the process's own outbound fetch seconds later to identify a loader performing Ingress Tool Transfer (T1105)",
      "Identify local browser-credential-store theft (T1555.003) from a copied database filename appearing outside the browser's own profile directory",
      "Scope the blast radius of a browser credential-store compromise correctly — every saved site, not only the corporate account",
    ],
    alerts: [],
    events,
    iocs,
    killchain: [
      { ts: T(0), phase: "Resource Development", action: `Sponsored search result routes to lookalike domain ${lookalike} (T1608.006)` },
      { ts: T(45_000), phase: "Resource Development", action: "PuTTY-0.83-installer.exe downloaded" },
      { ts: T(3 * MIN + 10_000), phase: "Execution", action: "User runs the unsigned installer, elevated on UAC consent (T1204.002)" },
      { ts: T(3 * MIN + 14_000), phase: "Command and Control", action: `Installer process fetches upd_helper.exe from ${c2} (T1105)` },
      { ts: T(3 * MIN + 22_000), phase: "Execution", action: "Second-stage payload executes; original installer exits with a fake setup error" },
      { ts: T(6 * MIN + 40_000), phase: "Credential Access", action: "Copy of Chrome's Login Data created outside the browser's own profile (T1555.003)" },
      { ts: T(7 * MIN), phase: "Exfiltration", action: `Harvested data POSTed to ${c2}/collect (T1041)` },
      { ts: T(7 * MIN + 20_000), phase: "Detection", action: "Defender raises a High-severity infostealer incident and quarantines the payload" },
    ],
    questions,
  };
}
