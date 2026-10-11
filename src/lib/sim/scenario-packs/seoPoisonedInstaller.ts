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
 * (Palo Alto Networks PAN-OS) events.
 *
 * NOTE: `difficulty: "foundation"` is declared on the SCENARIOS registry entry
 * in scenarios.ts (ScenarioBundle itself carries no difficulty field).
 */

import type { ScenarioBundle, IOC, ScenarioQuestion } from "@/lib/sim/types";
import { seoPoisonedInstallerScenarioEvents } from "./seoPoisonedInstaller.events";

export function buildSeoPoisonedInstallerScenario(
  scenarioId = "seo-poisoned-installer-2026",
): ScenarioBundle {
  const { title, events, T, MIN, host, lookalike, c2, installerHash, stealerHash } = seoPoisonedInstallerScenarioEvents();

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
      hint: "Look at pan.referer — the traffic arrived through a googleadservices.com ad click-tracker, not from a link on another publisher's site.",
      kind: "single",
      options: [
        { value: "seo_poisoning", label: "SEO poisoning / malvertising — a paid or manipulated search result pointed directly at attacker infrastructure" },
        { value: "driveby", label: "Drive-by compromise — a legitimate software site was hacked and pushed the installer to her browser without a deliberate click" },
        { value: "phishing", label: "Phishing — she followed a malicious link delivered by email or chat that took her straight to the fake download page" },
        { value: "supply_chain", label: "Supply-chain compromise — the official PuTTY project's build pipeline was tampered with and shipped a trojanized 0.83 release" },
      ],
      answer: "seo_poisoning",
      xp: 50,
      explanation:
        "The referer is a googleadservices.com/pagead/aclk ad click-tracker, and the destination is a domain built specifically to look like a software download site — not a hacked publisher. That combination is the signature of a poisoned or purchased search result (T1608.006): the attacker doesn't need to compromise anything, only to outrank or outbid the real project for the query she typed. Drive-by compromise (b) requires a genuine site to be hijacked, which nothing here shows. Phishing (c) requires an email or message as the delivery channel — there is none in this chain. Supply-chain compromise (d) would mean the real chiark.greenend.org.uk build process was tampered with, which is a far larger claim than the evidence supports.",
    },
    {
      id: "q2",
      prompt:
        "pan.category on evt_spi_01 is 'newly-registered-domain', yet pan.action is 'alert', not 'block'. What does that tell you about this environment's firewall policy?",
      kind: "single",
      options: [
        { value: "log_only", label: "The newly-registered-domain category is configured to log and allow rather than block — visibility without prevention" },
        { value: "tls_bypass", label: "TLS decryption was bypassed for this session, so the firewall could only observe the connection and had no way to act on it" },
        { value: "misconfigured", label: "The rule is broken — newly-registered-domain is meant to hard-block, so an alert outcome here is a policy bug to escalate" },
        { value: "allowlisted", label: "puttysoftware-download.com sits on an explicit corporate allowlist for admin tooling, which overrides the category action" },
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
        { value: "exec_and_fetch", label: "The installer starting and, four seconds later, that same process pulling upd_helper.exe from a second, unrelated domain" },
        { value: "download_and_write", label: "The installer being downloaded from the lookalike site and then written to Downloads by chrome.exe — a staged delivery" },
        { value: "write_and_exec", label: "upd_helper.exe being written under Temp\\sysdata and then started with the installer as its parent — the second binary running" },
        { value: "copy_and_exfil", label: "The Login Data copy into Temp\\sysdata followed by the 340 KB POST to cdn-assets-relay92.net — credentials staged, then sent" },
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
        { value: "filename_outside_chrome", label: "'Login Data' is Chrome's own credential-database filename, and it has no legitimate reason to exist outside Chrome's profile folder" },
        { value: "file_size", label: "Its 120 KB size is far larger than the small cache and scratch files that normally accumulate in a user's Temp folder" },
        { value: "medium_integrity", label: "The initiating process ran at Medium integrity yet obtained a file Chrome keeps locked, which only a High-integrity process can do" },
        { value: "parent_process", label: "Its initiating process descends from the original unsigned installer, and that lineage alone proves malicious intent for the write" },
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
        { value: "wipe_only", label: "Reimaging the laptop resolves it — once the stealer and its staged copies are destroyed, none of the saved passwords stay exposed" },
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
    title,
    threat_actor: "Commodity infostealer distributor (malvertising / SEO poisoning)",
    attack_kind: "seo_poisoned_installer",
    briefing:
      "Microsoft Defender for Endpoint raised a High-severity infostealer incident on LAP-3312 at 14:27. The user says she was installing PuTTY this afternoon for a routine SSH task. Work out how the installer got onto the machine, what it actually did, and what has left the building.",
    narrative: `At 14:20 Dor Avraham, a systems administrator, searched for "putty ssh client download" and clicked the sponsored result rather than the organic one. The click went through Google's own ad click-tracker — the landing request's referer is a googleadservices.com/pagead/aclk URL — to puttysoftware-download.com, a domain with no connection to the real PuTTY project and no abuse history, because it was registered for exactly this purpose. The firewall logged it under newly-registered-domain and let it through: that category is set to log, not block.

Forty-five seconds later she downloaded PuTTY-0.83-installer.exe from the same host, and ran it at 14:23:10. The file is unsigned, and it ran at medium integrity — reading her own Chrome profile needs no elevation. Four seconds after it started, the installer process itself reached out to a second, unrelated domain — cdn-assets-relay92.net — and pulled down upd_helper.exe, 3.1 MB. The original installer was never going to install PuTTY; its only job was to fetch this.

upd_helper.exe ran, and the installer window closed a moment later with a generic "Setup failed" message. She never got a working copy of PuTTY. What she did get, over the next few minutes, was a new folder under her own Temp directory — AppData\\Local\\Temp\\sysdata\\Chrome_Default — containing a file named Login Data, 120 KB, the same filename and size class as Chrome's own saved-password database. Chrome holds that file open and locked while it runs, so upd_helper.exe copied it instead of reading it directly. Cookies and Web Data followed in the same burst.

At 14:27 the host POSTed a 340 KB payload to cdn-assets-relay92.net/collect. The firewall allowed it — the domain's category is unknown, which carries no blocking policy. Defender's behavioural engine caught up twenty seconds later, raised the incident and quarantined upd_helper.exe at 14:27:20 — but the exfiltration POST had completed at 14:27:00, so this is a detection after the fact, not a prevention. By then the credential store had already left the building.`,
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
      { ts: T(3 * MIN + 10_000), phase: "Execution", action: "User runs the unsigned installer at medium integrity, no elevation (T1204.002)" },
      { ts: T(3 * MIN + 14_000), phase: "Command and Control", action: `Installer process fetches upd_helper.exe from ${c2} (T1105)` },
      { ts: T(3 * MIN + 22_000), phase: "Execution", action: "Second-stage payload executes; original installer exits with a fake setup error" },
      { ts: T(6 * MIN + 40_000), phase: "Credential Access", action: "Copy of Chrome's Login Data created outside the browser's own profile (T1555.003)" },
      { ts: T(7 * MIN), phase: "Exfiltration", action: `Harvested data POSTed to ${c2}/collect (T1041)` },
      { ts: T(7 * MIN + 20_000), phase: "Detection", action: "Defender detects the infostealer and quarantines the payload — 20 s after exfil completed" },
    ],
    questions,
  };
}
