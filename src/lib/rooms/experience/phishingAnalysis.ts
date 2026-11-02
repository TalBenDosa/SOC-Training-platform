import type { RoomExperience } from "./types";

// Pilot experience for the "phishing-analysis" room (rooms-batch-10.ts).
// Station task ids must match the room's task order exactly (see getRoomExperience).
//
// The briefing labs teach the three readings hands-on. Their example mail is a
// fictional "Northwind Bank" (203.0.113.0/24 is the RFC 5737 documentation
// range) so nothing here overlaps the graded log, questions or flag.
export const PHISHING_ANALYSIS: RoomExperience = {
  roomId: "phishing-analysis",
  codename: "Operation Dead Letter",
  theme: "mailroom",
  handler: { name: "Dana Reyes", role: "SOC Lead, Night Shift" },
  briefing: [
    "02:14. The mail gateway has been noisy all night.",
    "Someone is writing to our people pretending to be someone else.",
    "Learn how mail really travels. Then work the evidence.",
    "Every station you clear brings us closer to the sender.",
  ],
  stations: [
    {
      id: "archive",
      label: "The Archive",
      tagline: "Hands-on briefings: headers, links, the investigation playbook",
      building: "archive",
      taskIds: ["phishing-r1", "phishing-r2", "phishing-r3"],
    },
    {
      id: "sorting",
      label: "Sorting Plant",
      tagline: "Three locked terminals. Open them with what you learned",
      building: "factory",
      taskIds: ["phishing-q1", "phishing-q2", "phishing-q3"],
    },
    {
      id: "lab",
      label: "Evidence Lab",
      tagline: "A gateway alert on the bench. Work the raw log",
      building: "lab",
      taskIds: ["phishing-la1"],
    },
    {
      id: "desk",
      label: "Triage Office",
      tagline: "A new alert at the desk. Make the call",
      building: "office",
      taskIds: ["phishing-ac1"],
    },
    {
      id: "vault",
      label: "The Vault",
      tagline: "Final lock: pull the decisive value from the evidence",
      building: "vault",
      taskIds: ["phishing-flag1"],
      boss: true,
    },
  ],
  personas: {
    "phishing-ac1": {
      name: "R. Thomas",
      role: "Account Manager · Sales",
      line: "I got a Microsoft security notice this morning about a new device. Do I need to do anything?",
    },
  },
  briefings: {
    // ── Reading 1: headers and the three authentication checks ──────────────
    "phishing-r1": [
      {
        kind: "inspect",
        title: "Open the envelope",
        prompt: "A user forwarded this \"bank security\" email. Open every header and decide who wrote it: the sender, or the mail servers.",
        artifact: "Raw headers · \"Show original\"",
        items: [
          { id: "from", text: "From: Northwind Bank Security <security@northwind-bank.com>", tag: "Typed by the sender", tone: "warn",
            note: "This is ink on the envelope. The sender can type any name and any address here, so on its own it proves nothing about who sent the mail." },
          { id: "rp", text: "Return-Path: <bounce@relay7.hostdeal-mail.net>", tag: "Set at delivery", tone: "warn",
            note: "Where bounces really go. It points at hostdeal-mail.net, not northwind-bank.com: the sender wants replies and failures routed somewhere else. First red flag." },
          { id: "rcv-top", text: "Received: from mx1.yourco.com by inbox.yourco.com; 02:11:09", tag: "Added by a server", tone: "info",
            note: "Each server stamps its own Received line ON TOP. The top line was added last: it is the hop closest to your mailbox." },
          { id: "rcv-bottom", text: "Received: from [203.0.113.45] by relay7.hostdeal-mail.net; 02:11:02", tag: "Added by a server", tone: "trust",
            note: "The bottom Received line was added first, so it shows where the mail really entered the system: 203.0.113.45. That IP is what you look up in threat intelligence." },
          { id: "xoip", text: "X-Originating-IP: 203.0.113.45", tag: "Added by a server", tone: "trust",
            note: "Some webmail systems stamp the sender's real IP here. It matches the bottom Received hop, so two independent stamps agree on the origin." },
          { id: "msgid", text: "Message-ID: <7731.a81f2@relay7.hostdeal-mail.net>", tag: "Set by the sending system", tone: "warn",
            note: "The Message-ID names the platform that actually created the message. A real Northwind Bank mail would carry a Northwind (or its provider's) domain here." },
          { id: "auth", text: "Authentication-Results: spf=fail; dkim=none; dmarc=fail (p=reject)", tag: "Added by your server", tone: "trust",
            note: "Your own mail server's verdict on the three checks. SPF failed, there is no DKIM signature, and DMARC failed: this mail had no right to use northwind-bank.com." },
        ],
      },
      {
        kind: "sequence",
        title: "Trace the route",
        prompt: "These Received lines appear top to bottom, as in the header. Tap them in the order the email actually travelled, from where it started to your inbox.",
        items: [
          { id: "h3", text: "from mx1.yourco.com by inbox.yourco.com", note: "Hop 3: your own edge server hands it to the mailbox." },
          { id: "h2", text: "from relay7.hostdeal-mail.net by mx1.yourco.com", note: "Hop 2: the relay delivers to your edge server." },
          { id: "h1", text: "from [203.0.113.45] by relay7.hostdeal-mail.net", note: "Hop 1: the origin. The sender's machine hands the mail to a bulk relay." },
        ],
        order: ["h1", "h2", "h3"],
        doneNote: "Servers stack their Received line on top of the previous one, so you read the chain bottom → top. The bottom hop is the origin you investigate.",
      },
      {
        kind: "simulate",
        title: "The three guards",
        prompt: "Pick a scenario and watch SPF, DKIM and DMARC check the message. Try all three.",
        checks: [
          { name: "SPF", question: "Is this sending IP on the domain's published list of allowed senders?" },
          { name: "DKIM", question: "Does the message carry a valid signature from the domain's key?" },
          { name: "DMARC", question: "Did SPF or DKIM pass for the SAME domain shown in From:?" },
        ],
        scenarios: [
          {
            id: "genuine", label: "Genuine bank mail",
            detail: "From: alerts@northwind-bank.com, sent by Northwind's own mail service.",
            results: ["pass", "pass", "pass"],
            why: ["The bank lists its mail service in its SPF record.", "Signed with northwind-bank.com's private key.", "Both checks passed for northwind-bank.com, the From domain."],
            verdict: "Authenticated and aligned. The message really comes from the domain it shows.",
          },
          {
            id: "spoof", label: "Spoofed From",
            detail: "From: security@northwind-bank.com, but sent from 203.0.113.45 through a bulk relay.",
            results: ["fail", "fail", "fail"],
            why: ["203.0.113.45 is not in northwind-bank.com's SPF record.", "No valid northwind-bank.com signature exists.", "Nothing passed for the From domain, so DMARC fails and the bank's policy (reject) applies."],
            verdict: "The sender claimed a domain it has no right to use. This is the classic spoof the checks were built to stop.",
          },
          {
            id: "lookalike", label: "Look-alike domain",
            detail: "From: security@northwind-bank-support.com, a domain the attacker registered and configured.",
            results: ["pass", "pass", "pass"],
            why: ["The attacker published SPF for their own domain.", "They sign with their own domain's key.", "Both passed for northwind-bank-support.com, which IS the From domain."],
            verdict: "All three pass, and it is still phishing. The checks only prove the sender controls THAT domain. Always read the domain itself.",
          },
        ],
      },
    ],

    // ── Reading 2: links, look-alike domains, weaponised attachments ────────
    "phishing-r2": [
      {
        kind: "sort",
        title: "Hover, don't click",
        prompt: "Each link shows friendly text. Hover (or tap \"reveal\") to see where it really goes, then sort it.",
        buckets: [
          { id: "honest", label: "Goes where it says" },
          { id: "liar", label: "Lies about its destination" },
        ],
        items: [
          { id: "l1", text: "View your statement", hidden: "https://online.northwind-bank.com/statements", bucket: "honest",
            why: "online. is just a subdomain; the registered domain is northwind-bank.com." },
          { id: "l2", text: "Verify your account", hidden: "http://northwind-bank.com.verify-login.co/session", bucket: "liar",
            why: "Read the domain from the right: the registered domain is verify-login.co. \"northwind-bank.com\" is only a subdomain label." },
          { id: "l3", text: "https://www.northwind-bank.com/help", hidden: "https://bit.ly/3xQk9pz", bucket: "liar",
            why: "The visible text is a URL too, but the real href is a shortener that hides the destination. Expand it with a URL expander, never by clicking." },
          { id: "l4", text: "Contact support", hidden: "https://www.northwind-bank.com/contact", bucket: "honest",
            why: "Text and destination agree, on the real domain." },
        ],
      },
      {
        kind: "sort",
        title: "Find the real domain",
        prompt: "Which of these addresses really belong to northwind-bank.com?",
        buckets: [
          { id: "real", label: "northwind-bank.com" },
          { id: "fake", label: "Someone else's domain" },
        ],
        items: [
          { id: "d1", text: "login.northwind-bank.com", bucket: "real", why: "A subdomain of the real registered domain." },
          { id: "d2", text: "northwind-bank.com.secure-check.net", bucket: "fake", why: "The registered domain is secure-check.net. Everything to its left is a label the attacker chose." },
          { id: "d3", text: "nоrthwind-bank.com", hidden: "Punycode: xn--nrthwind-bank-i7k.com", bucket: "fake",
            why: "Homograph: the \"о\" is Cyrillic (U+043E). The Punycode form exposes it as a completely different domain." },
          { id: "d4", text: "northwind-bank.co", bucket: "fake", why: "Different top-level domain (.co, not .com): a separate registration anyone can buy." },
          { id: "d5", text: "https://northwind-bank-support.com", bucket: "fake", why: "A hyphenated look-alike. HTTPS only means the connection is encrypted, not that the site is the bank." },
        ],
      },
      {
        kind: "match",
        title: "Attachment X-ray",
        prompt: "Match each attachment to the trick it plays.",
        pairs: [
          { id: "xlsm", left: "Invoice.xlsm", right: "Macros run once the user clicks \"Enable Content\"", why: "The m in .xlsm means macro-enabled. The blurred \"enable editing to view\" page is the lure." },
          { id: "zip", left: "Docs.zip + \"password: Inv2024\"", right: "The scanner can't open it; the key is in the email body", why: "Encryption blinds the gateway's scan, and the password travels right next to it." },
          { id: "iso", left: "Shipment.iso", right: "A disk image whose contents could dodge the Mark-of-the-Web warning on older Windows", why: "Files inside the mounted image did not inherit the downloaded-file flag before the fix." },
          { id: "pdf", left: "Statement.pdf", right: "A clean file whose only job is to carry the victim to a credential page", why: "The PDF itself may scan clean. The link inside it is the attack." },
        ],
      },
    ],

    // ── Reading 3: the investigation workflow ───────────────────────────────
    "phishing-r3": [
      {
        kind: "sequence",
        title: "Run the playbook",
        prompt: "A suspicious email lands in the queue. Tap the steps in the order a disciplined analyst runs them.",
        items: [
          { id: "s5", text: "Analyse the attachment", note: "Hash it, check the hash, sandbox it; olevba / pdfid without opening it." },
          { id: "s2", text: "Extract the headers safely", note: "Export raw headers from the gateway console. Never open the mail yourself." },
          { id: "s7", text: "Contain", note: "Block sender and URLs, hunt other recipients, isolate anyone who clicked." },
          { id: "s1", text: "Triage", note: "Did anyone click or open? Does the sender match the claimed organisation?" },
          { id: "s4", text: "Detonate URLs in a sandbox", note: "URLScan / VirusTotal / a sandbox, never your corporate browser." },
          { id: "s6", text: "Document and decide", note: "Benign, spam, phishing, or targeted (spear phishing / BEC)." },
          { id: "s3", text: "Investigate the sender IP", note: "Reputation, abuse reports, what it runs, who owns it." },
        ],
        order: ["s1", "s2", "s3", "s4", "s5", "s6", "s7"],
        doneNote: "Assess from a distance, gather, test remotely, then decide and contain: the bomb-disposal order that keeps you from detonating the payload yourself.",
      },
      {
        kind: "match",
        title: "Pick the right tool",
        prompt: "Each question needs a different tool. Match them.",
        pairs: [
          { id: "abuse", left: "Has this IP been reported for abuse?", right: "AbuseIPDB", why: "A community database of abuse reports per IP." },
          { id: "shodan", left: "What services is this IP running?", right: "Shodan", why: "Shows open ports and banners: a mail server, or a VPS that should not be sending mail?" },
          { id: "whois", left: "Who owns this IP range?", right: "Whois / RIPE / ARIN lookup", why: "Registration data names the provider or organisation behind the range." },
          { id: "urlscan", left: "What does this page look like, without visiting it?", right: "URLScan.io", why: "It loads the page for you and returns a screenshot and analysis." },
          { id: "olevba", left: "What macro code is inside this .xlsm?", right: "olevba (oletools)", why: "Extracts VBA source without executing it." },
          { id: "vt", left: "Do security vendors flag this file hash?", right: "VirusTotal", why: "Checks the hash against dozens of engines." },
        ],
      },
      {
        kind: "sort",
        title: "Call it",
        prompt: "Sort each case into the verdict it deserves.",
        buckets: [
          { id: "benign", label: "Benign" },
          { id: "spam", label: "Spam" },
          { id: "phish", label: "Phishing" },
          { id: "bec", label: "Spear phishing / BEC" },
        ],
        items: [
          { id: "c1", text: "The vendor newsletter you subscribed to; passes SPF, DKIM and DMARC for the vendor's own domain.", bucket: "benign", why: "Expected, authenticated, no malicious content: no action needed." },
          { id: "c2", text: "\"Cheap watches\" sent to 4,000 random addresses, no links to login pages.", bucket: "spam", why: "Bulk and untargeted. Report it to the gateway and move on." },
          { id: "c3", text: "\"Your mailbox is full\" sent to 300 staff, linking to a fake Microsoft 365 sign-in page.", bucket: "phish", why: "A credential-harvesting campaign: block the sender and URL, and check who clicked." },
          { id: "c4", text: "A message to the finance lead in the CFO's name asking for an urgent, confidential wire to a new account.", bucket: "bec", why: "Targeted and aimed at money: escalate to incident response and notify management." },
        ],
      },
      {
        kind: "sort",
        title: "Someone clicked",
        prompt: "The phish is confirmed and one user clicked the link. Which actions belong in the response?",
        buckets: [
          { id: "do", label: "Do it" },
          { id: "dont", label: "Don't" },
        ],
        items: [
          { id: "a1", text: "Block the sender domain and IP at the email gateway", bucket: "do", why: "Stops more of the same campaign arriving." },
          { id: "a2", text: "Search mail logs for the same Message-ID, sender IP or attachment hash", bucket: "do", why: "Finds every other recipient of the campaign, not just the reporter." },
          { id: "a3", text: "Isolate the clicker's workstation and check EDR for execution", bucket: "do", why: "A click can mean a payload ran. Contain first, then confirm." },
          { id: "a4", text: "Open the link on your own workstation to see what it does", bucket: "dont", why: "Even visiting can trigger a drive-by download. Use a sandbox." },
          { id: "a5", text: "Forward the email to all staff as a warning, link included", bucket: "dont", why: "You would deliver the live link to everyone. Warn with a description or screenshot." },
          { id: "a6", text: "Delete the reporter's copy and close the ticket", bucket: "dont", why: "Other recipients still have it, and the click still needs investigating." },
        ],
      },
    ],
  },
};
