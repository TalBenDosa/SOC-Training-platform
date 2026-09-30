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

import type { ScenarioBundle, IOC, ScenarioQuestion } from "@/lib/sim/types";
import { gwsPhishingAttachmentScenarioEvents } from "./gwsPhishingAttachment.events";

export function buildGwsPhishingAttachmentScenario(
  scenarioId = "gws-phishing-attachment-2026",
): ScenarioBundle {
  const { title, events, T, MIN, host, supplier, c2, attachmentHash, droppedHash } = gwsPhishingAttachmentScenarioEvents();

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
        { value: "safe", label: "The message is legitimate; all three passing means the sender and its content have been verified" },
        { value: "spoofed", label: "The sender forged the results by writing them into the message headers along with the rest" },
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
        { value: "missing_logs", label: "Firewall logging was down during that window, so the download happened but was simply not recorded" },
        { value: "usb", label: "The file arrived by some other route, such as a USB stick or an AirDrop transfer that bypasses the firewall" },
        { value: "cached", label: "The file was served from the browser cache after an earlier visit, so no new network request was needed" },
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
        { value: "parent_and_cmd", label: "Its parent is an unnotarized app on a mounted volume, and its arguments pipe a password prompt to a remote host" },
        { value: "signature", label: "Apple had revoked the signing certificate for this build of osascript, so Gatekeeper no longer trusted it" },
        { value: "root", label: "It ran as root, and osascript running with root privileges is a strong indicator of privilege escalation" },
        { value: "hash", label: "The binary's hash did not match Apple's published value for this macOS build, so it had been tampered with" },
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
        { value: "purge_and_call", label: "Purge the two unopened copies and phone the supplier out-of-band — their mailbox is compromised" },
        { value: "block_domain", label: "Block northline-print.co.uk at the mail gateway so that no further messages from the supplier can arrive" },
        { value: "reply", label: "Reply on the same thread asking the supplier to confirm whether they really sent the invoice attachment" },
        { value: "nothing", label: "Nothing further — the payload was blocked on LAP-003, so the other delivered copies pose no real risk" },
      ],
      answer: "purge_and_call",
      xp: 50,
      explanation:
        "evt_gws_08 shows the same attachment sitting unopened in two other mailboxes, so there is live exposure to remove — and 'the payload was blocked' (d) only describes what happened on the one host where a user opened it. The supplier needs telling, but not by replying to the thread (c): the attacker is reading that mailbox, and a reply tips them off and reaches them rather than the supplier. Use a phone number you already have on file. Blocking the domain (b) is the tempting reflex and the wrong one — it severs genuine invoicing with a real business partner to solve a problem that a purge plus a phone call solves better, and it does nothing about the mailbox actually being under someone else's control.",
    },
  ];

  return {
    scenario_id: scenarioId,
    title,
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
