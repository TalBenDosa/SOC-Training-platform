import type { RoomExperience } from "./types";

// Pilot experience for the "phishing-analysis" room (rooms-batch-10.ts).
// Station task ids must match the room's task order exactly (see getRoomExperience).
//
// The briefing labs teach the three readings hands-on. Their example mail is a
// fictional "Northwind Bank" (203.0.113.0/24 is the RFC 5737 documentation
// range) so nothing here overlaps the graded log, questions or flag.
const FILMS = "https://wrxhxtdllbctsawvewue.supabase.co/storage/v1/object/public/lesson-videos/operation/phishing-analysis";

export const PHISHING_ANALYSIS: RoomExperience = {
  roomId: "phishing-analysis",
  codename: "Operation Dead Letter",
  scene: "facilityphishinganalysis",
  layout: "facility",
  theme: "mailroom",
  handler: { name: "Dana Reyes", role: "SOC Lead, Night Shift" },
  briefing: [
    "02:14. The mail gateway has been noisy all night.",
    "Someone is writing to our people pretending to be someone else.",
    "Learn how mail really travels. Then work the evidence.",
    "Every station you clear brings us closer to the sender.",
  ],
  mission: "A wave of fake bank and executive mail is reaching our people. Learn how mail really travels, work the evidence, and stop the sender.",
  estimate: "~60 min",
  look: { primary: "#22d3ee", secondary: "#a78bfa", warn: "#fb7185" },
  // Approved films in the lesson-videos bucket; names carry a content hash.
  story: {
    intro: { title: "02:14", src: `${FILMS}/dead-letter-intro-cb2adf7f.mp4`, poster: `${FILMS}/dead-letter-intro-f7c3b8cb.jpg` },
    afterStation: {
      sorting: { title: "The Pattern", src: `${FILMS}/dead-letter-ch2-dc47fb4c.mp4`, poster: `${FILMS}/dead-letter-ch2-6ac505a6.jpg` },
      lab: { title: "Every Copy", src: `${FILMS}/dead-letter-ch4-88f5692d.mp4`, poster: `${FILMS}/dead-letter-ch4-e2e5d785.jpg` },
      ticket: { title: "Dead Letter", src: `${FILMS}/dead-letter-finale-ee674c63.mp4`, poster: `${FILMS}/dead-letter-finale-1c6037fe.jpg` },
    },
  },
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
      id: "desk",
      label: "Triage Office",
      tagline: "A user is at the desk with a scary Microsoft notice. Make the call",
      building: "office",
      taskIds: ["phishing-ac1"],
    },
    {
      id: "lab",
      label: "Evidence Lab",
      tagline: "A fake CFO wants a wire today. Work the raw log and pull the decisive value",
      building: "lab",
      taskIds: ["phishing-la1", "phishing-flag1"],
    },
    {
      id: "control",
      label: "Control Room",
      tagline: "Hunt every copy of the campaign, then contain it in the right order",
      building: "control",
      taskIds: ["phishing-qf1", "phishing-la2", "phishing-ord1"],
    },
    {
      id: "ticket",
      label: "Close the Ticket",
      tagline: "Final step: write the summary the case owner signs off",
      building: "ticket",
      taskIds: ["phishing-wr1"],
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
        prompt: "A user forwarded this \"bank security\" email. Open every header: who wrote it, and how far can you trust it?",
        artifact: "Raw headers · \"Show original\"",
        items: [
          { id: "from", text: "From: Northwind Bank Security <security@northwind-bank.com>", tag: "Typed by the sender", tone: "warn",
            note: "Ink on the envelope. The sender can type any name and any address here, so on its own it proves nothing about who sent the mail." },
          { id: "replyto", text: "Reply-To: northwind.secure@outlook-mail.example", tag: "Typed by the sender · strong signal", tone: "warn",
            note: "Where your user's reply would go. It points to an unrelated domain, not northwind-bank.com: the sender wants the answer to reach them. This mismatch is a much stronger red flag than Return-Path, and a classic BEC trick." },
          { id: "rp", text: "Return-Path: <bounce-7731@em.bulkmailer.example>", tag: "Envelope sender · weak on its own", tone: "info",
            note: "Where bounces (delivery failures) go, and the domain SPF checks. A mismatch with From is weak by itself: legitimate bulk mail sent through providers routinely uses the provider's bounce domain. Note it and weigh it with the rest." },
          { id: "rcv-top", text: "Received: from mx1.yourco.com by inbox.yourco.com; 02:11:09", tag: "Your internal hop", tone: "info",
            note: "Each server stamps its Received line ON TOP of the previous one. This top line is internal: your own edge server handing the mail to the mailbox." },
          { id: "rcv-edge", text: "Received: from relay7.bulkmailer.example [198.51.100.23] by mx1.yourco.com; 02:11:04", tag: "Stamped by YOUR boundary server · trust this", tone: "trust",
            note: "Your own boundary server wrote this line, so the IP it recorded is the most trustworthy origin: 198.51.100.23 is the machine that actually handed the message to you. That is the IP to look up in threat intelligence." },
          { id: "rcv-bottom", text: "Received: from [203.0.113.45] by relay7.bulkmailer.example; 02:11:02", tag: "Written on the sender's side", tone: "warn",
            note: "Lines below your boundary hop were written by the sending side, so they can be forged or show private addresses. Read them as the sender's claim, not as proof." },
          { id: "msgid", text: "Message-ID: <7731.a81f2@em.bulkmailer.example>", tag: "Set by the sending system", tone: "info",
            note: "The Message-ID names the platform that actually created the message: a bulk mailer, not northwind-bank.com." },
          { id: "auth", text: "Authentication-Results: spf=pass smtp.mailfrom=em.bulkmailer.example; dkim=none; dmarc=fail action=quarantine header.from=northwind-bank.com", tag: "Added by your server", tone: "trust",
            note: "Your own server's verdict. SPF passed, but only for em.bulkmailer.example, the envelope sender's domain: the bulk mailer may send its own mail, nothing more. There is no DKIM signature. DMARC failed because nothing passed for northwind-bank.com, the domain the user sees, so this mail had no right to use it. The bank's policy is quarantine, which is why this copy landed in Junk before the user forwarded it." },
        ],
      },
      {
        kind: "sequence",
        title: "Trace the route",
        prompt: "These Received lines appear top to bottom, as in the header. Tap them in the order the email actually travelled, from where it started to the mailbox.",
        items: [
          { id: "h3", text: "from mx1.yourco.com by inbox.yourco.com", note: "Internal: your edge server hands it to the mailbox." },
          { id: "h2", text: "from relay7.bulkmailer.example [198.51.100.23] by mx1.yourco.com", note: "Your boundary server receives it. Written by YOUR side: the IP here is the trustworthy origin." },
          { id: "h1", text: "from [203.0.113.45] by relay7.bulkmailer.example", note: "Sender side: the claimed first hop. It could be forged." },
        ],
        order: ["h1", "h2", "h3"],
        doneNote: "Servers stack Received lines on top, so you read bottom → top. Then find the first hop stamped by YOUR server: the IP it received from is the true external origin. Everything below it is the sender's word.",
      },
      {
        kind: "simulate",
        title: "The three guards",
        prompt: "Pick a scenario and watch SPF, DKIM and DMARC check the message. Try all three.",
        checks: [
          { name: "SPF", question: "Is the sending server on the published allow-list of the envelope sender's domain?" },
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
            detail: "From and envelope sender both say northwind-bank.com, but the mail comes from a server the bank never authorised.",
            results: ["fail", "fail", "fail"],
            why: ["The sending server is not on northwind-bank.com's published SPF list.", "No valid northwind-bank.com signature exists.", "Nothing passed for the From domain, so DMARC fails and the bank's published policy (quarantine or reject) decides the message's fate."],
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
        kind: "deduce",
        title: "Who forged the bank?",
        prompt: "Six senders reached the queue tonight, all dressed as Northwind Bank. Only one actually forged the bank's real domain. The others are the bank itself or someone else's look-alike. Strike suspects out as the clues arrive, then accuse.",
        nameColumn: "Sender",
        columns: ["Shown in From", "Registered domain", "SPF", "DKIM"],
        suspects: [
          { id: "alerts", name: "alerts@northwind-bank.com", cells: ["alerts@northwind-bank.com", "northwind-bank.com", "pass, aligned", "pass d=northwind-bank.com"] },
          { id: "forged", name: "security@northwind-bank.com", cells: ["security@northwind-bank.com", "northwind-bank.com", "pass for em.mailpush.example only", "none"] },
          { id: "suffix", name: "notice@northwind-bank.com.secure-check.net", cells: ["notice@northwind-bank.com.secure-check.net", "secure-check.net", "pass, aligned", "pass d=secure-check.net"] },
          { id: "tld", name: "service@northwind-bank.co", cells: ["service@northwind-bank.co", "northwind-bank.co", "pass, aligned", "pass d=northwind-bank.co"] },
          { id: "homo", name: "info@ with a look-alike letter o", cells: ["info@northwind-bank.com (a Cyrillic o)", "xn--nrthwind-bank-i7k.com", "pass, aligned", "pass d=xn--nrthwind-bank-i7k.com"] },
          { id: "sub", name: "statements@online.northwind-bank.com", cells: ["statements@online.northwind-bank.com", "northwind-bank.com", "pass, aligned (relaxed)", "none"] },
        ],
        clues: [
          "Forging the bank means claiming the bank's real registered domain. A sender whose registered domain belongs to someone else is a look-alike, not a forgery.",
          "The forged copy carries no DKIM signature from the bank.",
          "Its SPF passes only for the bulk mailer that sent it, not for the domain in the From line.",
        ],
        culprit: "forged",
        why: "security@northwind-bank.com uses the bank's real registered domain but SPF passes for another domain and nothing is signed, so DMARC fails: a true forgery. The look-alikes (secure-check.net, the .co, the Cyrillic o) pass every check because they own their own domains. The subdomain statements@online is the bank's own, unsigned but aligned through SPF. The registered domain, read from the right, decides who owns the name.",
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
          { id: "s8", text: "Contain", note: "Isolate where it ran, purge the copies, block re-delivery, fix credentials, notify." },
          { id: "s9", text: "Close the ticket", note: "What happened, the real indicators, who was hit, what you did, the verdict." },
          { id: "s7", text: "Scope the campaign", note: "Hunt every recipient (EmailEvents), see where each copy sits, and who clicked or opened." },
          { id: "s1", text: "Triage", note: "Did anyone click or open? Does the sender match the claimed organisation?" },
          { id: "s4", text: "Detonate URLs in a sandbox", note: "URLScan / VirusTotal / a sandbox, never your corporate browser." },
          { id: "s6", text: "Document and decide", note: "Benign, spam, phishing, or targeted (spear phishing / BEC)." },
          { id: "s3", text: "Investigate the sender IP", note: "Reputation, abuse reports, what it runs, who owns it." },
        ],
        order: ["s1", "s2", "s3", "s4", "s5", "s6", "s7", "s8", "s9"],
        doneNote: "Assess from a distance, gather, test remotely, decide, find every copy, contain, then write it down: the bomb-disposal order that keeps you from detonating the payload yourself.",
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
        kind: "intercept",
        title: "Reported Mail Queue",
        prompt: "Dana's night shift has a queue of messages staff reported with the Report button. Each one is a whole message, not a header. Remove and escalate the ones that are an attack, and release the ones that are safe or merely annoying, thanking the reporter.",
        protect: "the reported-mail queue",
        blockLabel: "Remove and escalate",
        passLabel: "Release",
        seconds: 12,
        items: [
          { id: "q1", text: "'Your mailbox is full' · sent to 300 staff", sub: "Link text 'Keep my mailbox' goes to mail-quota.verify-login.example · sender outside", bad: true, why: "A credential-harvesting campaign: a fake sign-in page behind friendly link text, sent in bulk. Block the sender and URL, purge every copy, and check who clicked." },
          { id: "q2", text: "'Password expires in 3 days' · from the IT notices mailbox", sub: "dmarc pass · link to the company single sign-on page, same as every quarter", bad: false, why: "Reporting was right, but this is the genuine quarterly notice: authenticated sender, real destination, expected timing. Release it and thank the user; reports that turn out safe still train the habit." },
          { id: "q3", text: "'Quick favour' · from the CFO to the finance lead", sub: "No link, no attachment · Reply-To differs from From · asks for an urgent confidential wire to a new account", bad: true, why: "Spear phishing aimed at money (BEC): nothing technical to scan, just a trusted name, urgency and a changed reply path. Escalate to incident response and tell management." },
          { id: "q4", text: "'Autumn offers' · supplier newsletter", sub: "dmarc pass · unsubscribe goes to the supplier's own domain · the user does not remember subscribing", bad: false, why: "Authenticated, honest and unwanted is spam or marketing, not an attack. Unsubscribe or add a gateway rule; nothing to purge or escalate." },
          { id: "q5", text: "'Updated invoice' · reply inside an existing thread with a known supplier", sub: "dmarc pass · Invoice.xlsm · the page asks to 'Enable Content'", bad: true, why: "A real supplier mailbox taken over and used to deliver a macro-enabled file. Authentication passing says the account is real, not that the person is. Contain and check the supplier." },
          { id: "q6", text: "'Mandatory security training' · from the awareness platform", sub: "X-PhishTest header · sender in the gateway allow-list · a simulated phish", bad: false, why: "Your own phishing exercise. The user passed it by reporting; release and record the result so the reporter is counted." },
          { id: "q7", text: "'Shared a document with you' · from a colleague's real address", sub: "Link to docs-share.example · the colleague says they never sent it", bad: true, why: "A taken-over mailbox sending phish to its contacts: an account compromise. Remove every copy, reset the sender's credentials and check their rules and sessions." },
          { id: "q8", text: "'Delivery attempt failed' · from the courier", sub: "dmarc pass · link on the courier's own domain · matches the order the user placed this morning", bad: false, why: "The registered domain is the courier's, the timing fits an order the user confirms and authentication aligns. Checking the destination and the context is what makes this safe, not the courier's name." },
          { id: "q9", text: "'Scan to re-enable MFA' · outside sender", sub: "A QR code image only, no link text · dmarc fail", bad: true, why: "Quishing: the link is hidden in a picture so the scanner reads nothing. It points a phone, outside your web filtering, at a sign-in page. Remove it and block the destination." },
          { id: "q10", text: "'Out of office until Monday' · from a partner contact", sub: "Threaded to a message the user sent yesterday", bad: false, why: "An automatic reply to the user's own message, in thread and expected. It looks odd only because the user forgot writing to the contact." },
        ],
        lesson: "A reported message is a whole picture: sender, authentication, destination, context and ask. Authenticated and wrong is a takeover, unauthenticated but unwanted is spam, and a real notice in an expected thread is simply safe. Say so, and thank the reporter either way.",
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
          { id: "a7", text: "The user typed their password on the page: reset it and revoke their sessions", bucket: "do", why: "AiTM kits steal the session cookie too, so a password reset alone leaves the attacker logged in." },
          { id: "a8", text: "The user typed their password on the page: reset it, and that is enough", bucket: "dont", why: "A stolen session cookie survives a password reset. Revoke the sessions and check for new MFA methods and inbox rules." },
          { id: "a4", text: "Open the link on your own workstation to see what it does", bucket: "dont", why: "Even visiting can trigger a drive-by download. Use a sandbox." },
          { id: "a5", text: "Forward the email to all staff as a warning, link included", bucket: "dont", why: "You would deliver the live link to everyone. Warn with a description or screenshot." },
          { id: "a6", text: "Delete the reporter's copy and close the ticket", bucket: "dont", why: "Other recipients still have it, and the click still needs investigating." },
        ],
      },
    ],
  },
};
