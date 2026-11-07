import type { BriefingLab, RoomExperience } from "./types";

// "Operation Return Path" for the "email-protocols-forensics" room.
// Script: docs/campaign/77-email-protocols-forensics.md.
// Station task ids must match the room's task order exactly (see getRoomExperience).
//
// NEW TASK ORDER (the room's own order keeps all six readings first, so it cannot be staged):
// email-r1, email-o1, email-r2, email-q1 | email-r3, email-q3 |
// email-r4, email-r5, email-r6, email-q2, email-m1 |
// email-la1, email-f1, email-qf1, email-la2 | email-ac1
// o1 follows the SMTP reading; q1 follows envelope vs header; q3 follows the Received reading; q2
// and m1 need DMARC and ARC; f1 and qf1 both say they read la1; la2 follows la1 as the reading
// says ("unlike the previous investigation"); ac1 is the boss.
//
// Saffron Road Imports (fictional), not the graded tasks' solvix records.
// Signature: Read the Received Chain Backwards. A pathway walks the Received lines from the mailbox
// to the last fact your own server recorded, and a spotdiff sets a genuine invoice beside a forged
// replay whose lower chain and DKIM-Signature were pasted from it.
// Game mix: codebreak + pathway + spotdiff. No terminal.
// Lab data differs from the graded tasks: a customs broker's bank change, never a CFO wire or a
// payroll deposit; the wire session has two RCPT TO and a pasted chain from ops@hostline.example at
// 198.51.100.44, never bounce-8841 at 203.0.113.201 (r1, la1, f1); the mismatch sheet is five
// supplier messages, and its Return-Path example is a mail vendor (q1); the worked chain has five
// lines with a boundary at inbound1 (q3); SPF is evaluated by CIDR and qualifier, and the lookup
// count reaches 11 for one vendor, never 12 for two (r4 checkpoint); the DMARC sheet carries p=none,
// p=quarantine with pct=25, p=quarantine with a local override and strict DKIM, never p=reject with
// dis=none (la1, r6 checkpoint); the either-or rule is shown through forwarding (q2); the lookalike
// adds a word and a hyphen, 6 days old, for a bank change, never a swapped letter, 2 days old, or
// direct deposit (la2); the KQL sheet counts rows and uses CompAuth, outside every graded blank
// (qf1); the verdict drill uses trade lists with a trusted external sealer, an unknown sealer and
// a pasted signature, never an internal engineering list (ac1).

type Packet = Extract<BriefingLab, { kind: "pcap" }>["packets"][number];

const GW = "203.0.113.25";
const BROKER = "203.0.113.140";
const VPS = "198.51.100.44";
const PORT: Record<string, number> = { [BROKER]: 51544, [VPS]: 40212 };

function pkt(no: number, time: string, src: string, dst: string, proto: string, len: number, info: string, lines: string[], data?: string): Packet {
  const [sport, dport] = src === GW ? [25, PORT[dst]] : [PORT[src], 25];
  return {
    no, time, src, dst, proto, len, info,
    tree: [`Internet Protocol Version 4, Src: ${src}, Dst: ${dst}`, `Transmission Control Protocol, Src Port: ${sport}, Dst Port: ${dport}`, ...lines],
    ...(data ? { data } : {}),
  };
}
const smtpC = (no: number, time: string, src: string, cmd: string, len: number) =>
  pkt(no, time, src, GW, "SMTP", len, `C: ${cmd}`, ["Simple Mail Transfer Protocol", `Command Line: ${cmd}`], `${cmd}\r\n`);
const smtpS = (no: number, time: string, dst: string, reply: string, len: number, lines: string[] = [reply]) =>
  pkt(no, time, GW, dst, "SMTP", len, `S: ${lines.join(" | ")}`, ["Simple Mail Transfer Protocol", ...lines.map(l => `Response: ${l}`)], `${lines.join("\r\n")}\r\n`);
const EHLO_REPLY = ["250-inbound1.saffronroad.example", "250-PIPELINING", "250-SIZE 52428800", "250-STARTTLS", "250 8BITMIME"];

// Pasted from a real October invoice: the two lower Received lines and the DKIM-Signature.
const R_MTA = "Received: from billing1.brightquay.example ([10.8.0.12]) by mta4.brightquay.example with ESMTP id 71C2A; Mon, 5 Oct 2026 08:02:09 +0000";
const R_BILL = "Received: from ws-22.brightquay.example ([10.8.4.40]) by billing1.brightquay.example with ESMTP id 3FA90; Mon, 5 Oct 2026 08:02:08 +0000";
const DKIM = "DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed; d=brightquay.example; s=bq2026; t=1791187327; h=from:to:subject:date:message-id; bh=vNgWj7DODA0hJuAU4tizpa4B8XXSrAOwyrMLeFdfh7A=; b=Yx3pQe0dLk7vTnR2...fQ==";
const FROM = "From: \"Brightquay Customs Accounts\" <accounts@brightquay.example>";
const FORGED_REPLY_TO = "Reply-To: <accounts.brightquay@mailbox-desk.example>";
const TO = "To: <d.ferro@saffronroad.example>";
const SUBJECT = "Subject: Duty invoice and remittance details";
const DATE = "Date: Mon, 5 Oct 2026 08:02:07 +0000";
const MSGID = "Message-ID: <20261005080207.3FA90@billing1.brightquay.example>";

const FORGED_DATA = [R_MTA, R_BILL, DKIM, FROM, FORGED_REPLY_TO, TO, SUBJECT, DATE, MSGID, "", "Please note our new remittance account for all duty payments from today.", "IBAN and reference are in the attached statement.", "."].join("\r\n");

export const EMAIL_PROTOCOLS_FORENSICS: RoomExperience = {
  roomId: "email-protocols-forensics",
  codename: "Operation Return Path",
  theme: "returnpath",
  handler: { name: "Ikaika Moretti", role: "Email Forensics Analyst, Saffron Road Imports" },
  briefing: [
    "Saffron Road Imports. Sixty-four people, one bonded warehouse, and a container of saffron and cardamom held at the port until the duty is paid.",
    "On Tuesday morning an email from Brightquay Customs Brokers gave accounts payable a new bank account, three days before the deadline.",
    "The name is right and the wording is right. The headers disagree with each other.",
    "Ikaika Moretti has the raw message. Start at the mailbox, read backwards, and find out what can really be trusted.",
  ],
  mission: "Read a raw SMTP session, walk a Received chain back to the last line you can trust, work out SPF by hand, break DKIM on purpose, follow what survives forwarding, set a genuine message beside a forged one, then rule on the graded case.",
  estimate: "~75 min",
  look: { primary: "#ee9b3e", secondary: "#9fb8ff", warn: "#f0516e" },
  scene: "facilityreturnpath",
  layout: "facility",
  stations: [
    {
      id: "envelope",
      label: "The Envelope",
      topic: "The SMTP conversation · envelope-from vs header-from · display names",
      tagline: "Two senders, one message",
      building: "reception",
      taskIds: ["email-r1", "email-o1", "email-r2", "email-q1"],
    },
    {
      id: "chain",
      label: "The Chain",
      topic: "Reading the Received chain · who wrote each line · timestamps and gaps",
      tagline: "Start at your own door",
      building: "archive",
      taskIds: ["email-r3", "email-q3"],
    },
    {
      id: "seals",
      label: "The Seals",
      topic: "SPF qualifiers and lookups · DKIM body and header hashes · DMARC alignment · ARC",
      tagline: "What each seal really covers",
      building: "vault",
      taskIds: ["email-r4", "email-r5", "email-r6", "email-q2", "email-m1"],
    },
    {
      id: "sidebyside",
      label: "Side by Side",
      topic: "Genuine and forged headers · response scope · detection in KQL · lookalike domains",
      tagline: "One invoice, two stories",
      building: "lab",
      taskIds: ["email-la1", "email-f1", "email-qf1", "email-la2"],
    },
    {
      id: "returnpath",
      label: "Return Path",
      topic: "Weighing one failed check into a verdict",
      tagline: "It failed. But failed how?",
      building: "ticket",
      taskIds: ["email-ac1"],
      boss: true,
    },
  ],
  personas: {
    "email-o1": { name: "Ikaika Moretti", role: "Email Forensics Analyst", line: "Put the session back in the order it ran on the wire." },
    "email-q1": { name: "Ikaika Moretti", role: "Email Forensics Analyst", line: "Two sender addresses, and they disagree. Walk me through it." },
    "email-q3": { name: "Ikaika Moretti", role: "Email Forensics Analyst", line: "Three lines, three authors. Which one do you lean on?" },
    "email-q2": { name: "Ikaika Moretti", role: "Email Forensics Analyst", line: "Three results on one line. Tell me how you read them." },
    "email-m1": { name: "Ikaika Moretti", role: "Email Forensics Analyst", line: "Before the next case, tell me what each field is for." },
    "email-la1": { name: "Ikaika Moretti", role: "Email Forensics Analyst", line: "Read the raw fields, not the name on the message." },
    "email-f1": { name: "Ikaika Moretti", role: "Email Forensics Analyst", line: "Give me the exact string, copied from the header." },
    "email-qf1": { name: "Ikaika Moretti", role: "Email Forensics Analyst", line: "You've read it by hand. Now write it so a rule can read it." },
    "email-la2": { name: "Ikaika Moretti", role: "Email Forensics Analyst", line: "Another message, same questions. Look at it the way you looked at the last." },
    "email-ac1": { name: "Ikaika Moretti", role: "Email Forensics Analyst", line: "A rule fired and people are asking. Your call." },
  },
  briefings: {
    // ── Reading 1: the SMTP conversation ──
    "email-r1": [
      {
        kind: "pcap",
        title: "Read the SMTP Session on the Wire",
        prompt: "Tuesday, 09:14. Saffron Road's gateway keeps a rolling capture on its outside interface, and Ikaika Moretti has pulled two sessions from it: Brightquay's real server at 09:11, then the session that delivered the new bank details at 09:14. Read what each sender said before any header existed.",
        capture: "inbound1-outside-0903.pcapng",
        packets: [
          pkt(1, "09:11:02.114", BROKER, GW, "TCP", 74, "51544 → 25 [SYN] Seq=0", []),
          smtpS(2, "09:11:02.139", BROKER, "220 inbound1.saffronroad.example ESMTP", 94),
          smtpC(3, "09:11:02.163", BROKER, "EHLO mta4.brightquay.example", 96),
          smtpS(4, "09:11:02.188", BROKER, "", 162, EHLO_REPLY),
          smtpC(5, "09:11:02.212", BROKER, "STARTTLS", 76),
          smtpS(6, "09:11:02.236", BROKER, "220 2.0.0 Ready to start TLS", 98),
          pkt(7, "09:11:02.261", BROKER, GW, "TLSv1.3", 583, "Client Hello", ["Transport Layer Security", "TLSv1.3 Record Layer: Handshake Protocol: Client Hello"]),
          pkt(8, "09:11:02.289", GW, BROKER, "TLSv1.3", 1514, "Server Hello, Change Cipher Spec, Application Data", ["Transport Layer Security", "TLSv1.3 Record Layer: Handshake Protocol: Server Hello"]),
          pkt(9, "09:11:02.334", BROKER, GW, "TLSv1.3", 118, "Application Data", ["Transport Layer Security", "TLSv1.3 Record Layer: Application Data Protocol"]),
          pkt(10, "09:14:05.201", VPS, GW, "TCP", 74, "40212 → 25 [SYN] Seq=0", []),
          smtpS(11, "09:14:05.244", VPS, "220 inbound1.saffronroad.example ESMTP", 94),
          smtpC(12, "09:14:05.287", VPS, "EHLO mta4.brightquay.example", 96),
          smtpS(13, "09:14:05.330", VPS, "", 162, EHLO_REPLY),
          smtpC(14, "09:14:05.374", VPS, "MAIL FROM:<ops@hostline.example>", 100),
          smtpS(15, "09:14:05.418", VPS, "250 2.1.0 Ok", 80),
          smtpC(16, "09:14:05.461", VPS, "RCPT TO:<d.ferro@saffronroad.example>", 104),
          smtpS(17, "09:14:05.505", VPS, "250 2.1.5 Ok", 80),
          smtpC(18, "09:14:05.548", VPS, "RCPT TO:<s.haddad@saffronroad.example>", 105),
          smtpS(19, "09:14:05.592", VPS, "250 2.1.5 Ok", 80),
          smtpC(20, "09:14:05.636", VPS, "DATA", 72),
          smtpS(21, "09:14:05.679", VPS, "354 End data with <CR><LF>.<CR><LF>", 103),
          pkt(22, "09:14:05.812", VPS, GW, "SMTP", FORGED_DATA.length + 66, `C: DATA fragment, ${FORGED_DATA.length} bytes`, ["Simple Mail Transfer Protocol", `DATA fragment, ${FORGED_DATA.length} bytes`], FORGED_DATA),
          smtpS(23, "09:14:06.041", VPS, "250 2.0.0 Ok: queued as 4Hq2Lx7mZk", 102),
          smtpC(24, "09:14:06.085", VPS, "QUIT", 72),
          smtpS(25, "09:14:06.128", VPS, "221 2.0.0 Bye", 81),
        ],
        objectives: [
          { id: "env", task: "Follow the 09:14 session. What envelope sender did it declare?", hint: "\"MAIL FROM\"", answer: ["ops@hostline.example", "<ops@hostline.example>"], why: "MAIL FROM is the envelope sender. Bounces go there, and it's the domain SPF evaluates: hostline.example. The sender typed it, and the receiver accepted it with a plain 250." },
          { id: "hdr", task: "Open the DATA fragment. Which domain will the reader see in the From: line?", hint: "ip.addr==198.51.100.44", answer: ["brightquay.example", "accounts@brightquay.example"], why: "The From: line is just text inside DATA, sent long after MAIL FROM. Two addresses, set at two moments, and nothing in SMTP makes them agree." },
          { id: "rcpt", task: "The To: line in packet 22 names one person. How many mailboxes did this session really deliver to?", hint: "\"RCPT TO\"", answer: ["2", "two"], why: "Each RCPT TO is one delivery. s.haddad is on the wire but in no header, which is what a blind copy is. Whoever cleans this up has to search the gateway, not read the To: line." },
          { id: "tls", task: "The 09:11 session stops being readable after packet 6. Which command caused that?", hint: "\"STARTTLS\"", answer: ["starttls"], why: "STARTTLS upgrades the same connection to TLS, and the sender then says EHLO again inside the tunnel. MAIL FROM and DATA are in there too, so a capture of a good session shows little. The 09:14 sender never upgraded, which is why you can read it." },
          { id: "ip", task: "Packets 3 and 12 give the same EHLO name. What source IP did packet 12 really come from?", hint: "\"EHLO\"", answer: ["198.51.100.44"], why: "EHLO is a claim that nothing checks. Two machines gave the same name, and the IP is what tells them apart. The IP comes from the connection, the name comes from the sender." },
        ],
        primer: {
          title: "One conversation, two kinds of address",
          fold: true,
          points: [
            "SMTP (Simple Mail Transfer Protocol) is a plain-text dialogue between servers. `C:` is the sending side, `S:` the receiving side, and every step gets a numeric reply.",
            "`EHLO` gives a hostname that **nobody verifies**. If the reply lists STARTTLS, the sender may send `STARTTLS`, build TLS, and must say `EHLO` again inside it.",
            "`MAIL FROM` declares the **envelope sender**. `RCPT TO` names one recipient, and can repeat. A blind copy is only an extra RCPT TO.",
            "`DATA` carries the message: headers, a blank line, the body, then a lone `.` on its own line. The **header From** is inside this block.",
            "`QUIT` ends the session. Port 25 is server to server; 587 is a client submitting mail with a login.",
          ],
          example: {
            label: "Worked example: a tea merchant's session",
            lines: [
              "`C: EHLO relay.oolong.example` : a claim",
              "`S: 250-STARTTLS`, then `C: STARTTLS`, `S: 220 Ready`, TLS, `C: EHLO relay.oolong.example` again",
              "`C: MAIL FROM:<returns@oolong.example>` : envelope sender",
              "`C: RCPT TO:<buyer@teahouse.example>`, then `C: DATA`",
              "`From: Sales <sales@oolong.example>` : header sender, typed inside DATA",
            ],
          },
        },
      },
    ],
    // ── Reading 2: envelope-from vs header-from ──
    "email-r2": [
      {
        kind: "sort",
        title: "Which Sender Field Does What?",
        prompt: "d.ferro saw a name, an address and a Reply button, and thought that was one sender. There are four separate fields behind them. Put each fact on the field it belongs to.",
        buckets: [
          { id: "env", label: "Envelope sender (MAIL FROM)" },
          { id: "hdr", label: "Header From address" },
          { id: "name", label: "Display name" },
          { id: "reply", label: "Reply-To" },
        ],
        items: [
          { id: "s1", text: "SPF evaluates this domain", bucket: "env", why: "SPF asks whether the connecting IP may send for the MAIL FROM domain. That design grew out of bounce handling, so it follows the envelope." },
          { id: "s2", text: "Non-delivery reports are sent here", bucket: "env", why: "Bounces go to the envelope sender, never to the address the reader sees." },
          { id: "s3", text: "The last server records it as Return-Path", bucket: "env", why: "Return-Path is the envelope sender written down at delivery. That's how you read it after the fact." },
          { id: "s4", text: "DMARC requires a passing domain to match this one", bucket: "hdr", why: "DMARC exists to tie SPF and DKIM to the address a person sees. Neither of them does that alone." },
          { id: "s5", text: "Typed inside DATA and shown as the sender's address", bucket: "hdr", why: "It is message text, so the sender writes whatever it likes unless the domain owner enforces DMARC." },
          { id: "s6", text: "The words before the angle brackets", bucket: "name", why: "It's free text. It doesn't have to match the address beside it, and no authentication check reads it." },
          { id: "s7", text: "On many phones, the only sender shown", bucket: "name", why: "Mobile mail apps often hide the address until you tap, so this field alone can carry the attack." },
          { id: "s8", text: "Pressing Reply sends here, not to From", bucket: "reply", why: "If it's set, replies leave for this address. A forger uses it to keep the conversation away from the real sender." },
          { id: "s9", text: "Usually absent, and no check compares it to the sender", bucket: "reply", why: "SPF, DKIM and DMARC never ask whether it agrees with From, so a different domain here passes everything." },
        ],
        primer: {
          title: "The field a person reads is the weakest one",
          fold: true,
          points: [
            "The **envelope sender** is declared to the server. The **header From** is shown to the person. They are set separately.",
            "The **display name** is free text next to the address. The **Reply-To** header, if there is one, redirects replies.",
            "Because MAIL FROM is the sender's own claim, an attacker who owns any domain can pass SPF for that domain and still show any From they like.",
          ],
          example: {
            label: "Worked example: one message, four fields",
            lines: [
              "`Return-Path: <b@mail.vendor.example>` : envelope, read by SPF",
              "`From: \"Oolong Sales\" <sales@oolong.example>` : display name, then header From",
              "`Reply-To: <orders@oolong.example>` : where the Reply button goes",
            ],
          },
        },
      },
      {
        kind: "worksheet",
        title: "Does a Return-Path Mismatch Prove Anything?",
        prompt: "After Tuesday, somebody in accounts wants a rule that bins every message whose Return-Path differs from From. Before Ikaika Moretti answers, count what that rule would have done to this week's supplier mail.",
        caption: "Gateway summary · inbound to Saffron Road · this week",
        columns: ["Msg", "header.from", "Return-Path domain", "SPF", "DKIM d=", "DKIM", "DMARC"],
        rows: [
          ["A", "harbourtea.example", "em.postrelay.example", "pass", "harbourtea.example", "pass", "pass"],
          ["B", "kettleandleaf.example", "kettleandleaf.example", "pass", "kettleandleaf.example", "pass", "pass"],
          ["C", "brightquay.example", "hostline.example", "fail", "brightquay.example", "fail", "fail"],
          ["D", "malabarspice.example", "news.malabarspice.example", "pass", "-", "none", "pass"],
          ["E", "cardamomtraders.example", "mailer.fastsend.example", "pass", "mailer.fastsend.example", "pass", "fail"],
        ],
        questions: [
          { id: "count", q: "How many of the five have a Return-Path domain that isn't identical to the From domain?", hint: "Compare the two domain columns row by row, character by character.", answer: ["4", "four"], why: "A, C, D and E, and only C is the forgery. A is a price list sent through a mail vendor, D is a subdomain that aligns, and E is a question for the next step. The rule would have binned good mail, because a mismatch alone proves nothing either way." },
          { id: "stand", q: "On message A, the Return-Path is a mail vendor's. Which check ties the message to harbourtea.example itself? (SPF or DKIM)", hint: "Which row value matches the From domain?", answer: ["dkim"], why: "SPF passed for em.postrelay.example, which says nothing about harbourtea.example. The DKIM d= is harbourtea.example, which matches From, so DKIM carries DMARC here." },
          { id: "align", q: "Message E passes SPF and passes DKIM, and DMARC still fails. What is missing? (one word)", hint: "Compare the domains that passed with the From domain.", answer: ["alignment", "align", "aligned"], why: "Both checks passed for fastsend's domain, and neither domain matches From. That is the question DMARC asks. When SPF passes for another domain, alignment is the next thing to read." },
        ],
        primer: {
          title: "What SPF says, and what alignment adds",
          fold: true,
          points: [
            "SPF checks one thing: may this IP send for the **MAIL FROM** domain? It says nothing about the From a person sees.",
            "DKIM proves a domain, named in `d=`, signed the message.",
            "DMARC adds **alignment**: a domain that passed must match the header From domain.",
            "Relaxed alignment, the default, accepts the same organisational domain, so a subdomain aligns. Strict needs an exact match.",
            "A mismatch between Return-Path and From is a question, not an answer. Legitimate senders do it, and so do attackers.",
          ],
          example: {
            label: "Worked example: a newsletter sent through a vendor",
            lines: [
              "`From: news@oolong.example`, `Return-Path: <b@mail.vendor.example>`",
              "`spf=pass smtp.mailfrom=mail.vendor.example` : true, and silent about oolong.example",
              "`dkim=pass header.d=oolong.example` : matches From",
              "`dmarc=pass` : one aligned pass is enough",
            ],
          },
        },
      },
    ],
    // ── Reading 3: the Received chain ──
    "email-r3": [
      {
        kind: "anatomy",
        title: "Anatomy of One Received Line",
        prompt: "Before the suspect chain, Ikaika Moretti opens a dull one: a tea supplier's routine message, one Received line. Every chain is a stack of lines shaped like this. Learn the two halves.",
        source: "Raw headers · m.oyelaran's mailbox · one line, unfolded",
        fields: [
          { key: "from", value: "mail2.harbourtea.example", label: "Claimed name", note: "The name the connecting server gave in EHLO. Nobody checked it. It is what the sender says about itself." },
          { key: "reverse DNS", value: "mail2.harbourtea.example", label: "Looked up", note: "The receiver looked up the PTR record of the connecting IP. It matches the claim here. The word unknown in this spot means the lookup failed, and most real mail servers have a working PTR record." },
          { key: "IP", value: "203.0.113.77", label: "Connecting IP", note: "Taken from the TCP connection, not from anything the sender said. It's a fact only if you trust the server that wrote this line." },
          { key: "by", value: "inbound1.saffronroad.example", label: "The writer", note: "The server that wrote this line. Everything on the line is that server's account of what it saw." },
          { key: "with", value: "ESMTPS", label: "Protocol", note: "The S means this hop used TLS. A means authenticated submission, so ESMTPSA is both. Encryption protects the hop and says nothing about who the sender is." },
          { key: "id", value: "4Hp8Dq1XyT", label: "Queue ID", note: "This server's own tracking number. It's what you search for in that server's mail log." },
          { key: "for", value: "<m.oyelaran@saffronroad.example>", label: "This hop's recipient", note: "Servers often leave this out when a message has several recipients, partly so a blind copy doesn't leak." },
          { key: "date", value: "Wed, 28 Oct 2026 10:22:41 +0000", label: "Stamp", note: "When this server handled it, with its own UTC offset. Compare it with the line below: seconds apart is normal." },
        ],
        summary: "Every Received line has two halves. After by is the writer. After from is what the writer saw of the other side, and that mixes a claim (the name) with an observation (the reverse DNS and IP). A mismatch between the claimed name and the reverse DNS, or the word unknown, is a lead worth noting. So is a chain far shorter than a big provider's real path. No line is worth more than the server that wrote it.",
      },
      {
        kind: "pathway",
        title: "Read the Received Chain Backwards",
        prompt: "d.ferro's copy has five Received lines. Start at the mailbox and work back through them. Stop at the last fact a server of your own recorded, because below that you're reading what the sender typed.",
        goal: "Reach the last fact your own server recorded",
        nodes: [
          { id: "mailbox", label: "d.ferro mailbox", sub: "start here", x: 90, y: 14 },
          { id: "h1", label: "Received 1 (top)", sub: "by mbx2, from scan1 [10.20.1.9]", x: 68, y: 14 },
          { id: "from", label: "From: line", sub: "accounts@brightquay.example", x: 90, y: 50 },
          { id: "h2", label: "Received 2", sub: "by scan1, from inbound1 [10.20.1.5]", x: 68, y: 50 },
          { id: "h3", label: "Received 3", sub: "by inbound1, from mta4 [198.51.100.44]", x: 44, y: 32 },
          { id: "ip", label: "198.51.100.44", sub: "the peer inbound1 saw", x: 18, y: 14 },
          { id: "ehlo", label: "EHLO name", sub: "mta4.brightquay.example", x: 44, y: 60 },
          { id: "h4", label: "Received 4", sub: "by mta4, from billing1 [10.8.0.12]", x: 18, y: 50 },
          { id: "h5", label: "Received 5 (bottom)", sub: "by billing1, from ws-22 [10.8.4.40]", x: 68, y: 86 },
        ],
        edges: [["mailbox", "h1"], ["mailbox", "from"], ["mailbox", "h5"], ["h1", "h2"], ["h2", "from"], ["h2", "h3"], ["h3", "ip"], ["h3", "h4"], ["h3", "ehlo"], ["h4", "h5"]],
        route: ["mailbox", "h1", "h2", "h3", "ip"],
        notes: {
          mailbox: "Each server adds its line on top, so the top line is the newest. Start at the top, and you are walking the journey in reverse.",
          h1: "Your mailbox server wrote this, and it names your own filter on a private address. Both ends are yours, so step down.",
          h2: "Your filter wrote this, and the other side is the inside leg of your own gateway. Still your ground.",
          h3: "This is the boundary: by inbound1.saffronroad.example is the last line a server of yours wrote. The from half is the outside world as your gateway saw it. The name is a claim, and the reverse DNS already disagrees with it.",
          ip: "This address came from the TCP connection your gateway really accepted. A completed handshake can't be typed into a message. Nothing below this point has that standing, so stop here and investigate outward from this fact.",
        },
        traps: {
          from: "The From: line isn't a hop. It's text from DATA, and no server recorded it. The chain is the Received lines.",
          h5: "Bottom first gives you time order, and you'll want that. But you can't weigh the bottom line until you know where your trust ends, so start at the top and find the boundary.",
          h4: "Below the boundary. inbound1 didn't write this line: it arrived inside DATA, and the sender could have typed every word of it. This one is dated four weeks before the top of the chain.",
          ehlo: "That's what the sender called itself. Reverse DNS on the same connection says vps-88.hostline.example. The name is the claim, the IP is the fact.",
        },
        lesson: "Bottom to top gives you the order things claim to have happened: the bottom line was written first, and its from name is what the earliest machine called itself. Top to bottom tells you how far to believe it. Walk down until the by host stops being yours. The line above that drop is the one your own server wrote about a stranger, and it's the most trustworthy line in the message. Below it, every line is a lead, not proof.",
        primer: {
          title: "Who wrote which line",
          fold: true,
          points: [
            "Each server **prepends** one Received line, so the stack grows upward: bottom is oldest, top is newest.",
            "A sender controls everything in DATA, including any Received lines it wants to include. Those lines arrive looking just like real ones.",
            "A sender can't control what your own server writes about the connection it accepted.",
            "So find the **boundary**: the lowest line whose `by` host is yours. Its connecting IP is the fact you can build on.",
            "TLS on a hop (`ESMTPS`) doesn't move the boundary, and neither does a famous name in a lower line.",
          ],
          example: {
            label: "Worked example: three lines at oolong.example",
            lines: [
              "`from filter.oolong.example ([10.1.1.4]) by store.oolong.example` : yours, keep going",
              "`from relay.vendor.example (relay.vendor.example [203.0.113.9]) by edge.oolong.example` : boundary, 203.0.113.9 is the fact",
              "`from pc7 ([10.9.9.7]) by relay.vendor.example` : not yours, a lead at best",
            ],
          },
        },
      },
      {
        kind: "worksheet",
        title: "Read the Clocks Down the Chain",
        prompt: "Times are the other half of a chain. Here's Thursday's order confirmation from a spice exporter in Kochi, with lines in the order they sit in the message. Line 4 looks as if it happened five hours after line 3. Work out what really happened.",
        caption: "Received chain · top line first · offsets as written",
        columns: ["Line", "from (claimed)", "by", "Stamp"],
        rows: [
          ["1", "scan1.saffronroad.example", "mbx2.saffronroad.example", "Thu, 29 Oct 2026 09:03:27 +0000"],
          ["2", "inbound1.saffronroad.example", "scan1.saffronroad.example", "Thu, 29 Oct 2026 09:03:25 +0000"],
          ["3", "mail.malabarspice.example", "inbound1.saffronroad.example", "Thu, 29 Oct 2026 08:16:09 +0000"],
          ["4", "app1.malabarspice.example", "mail.malabarspice.example", "Thu, 29 Oct 2026 13:46:05 +0530"],
          ["5", "pc-billing3.malabarspice.example", "app1.malabarspice.example", "Thu, 29 Oct 2026 13:46:02 +0530"],
        ],
        questions: [
          { id: "utc", q: "What time did line 4's server stamp the message, in UTC? (hh:mm:ss)", hint: "Subtract the offset: +0530 means five and a half hours ahead of UTC.", answer: ["08:16:05", "8:16:05"], why: "13:46:05 at +0530 is 08:16:05 UTC. The clock only looked backwards. Always normalise before you call a chain impossible." },
          { id: "hop", q: "So how many seconds did the step from line 4 to line 3 take?", hint: "Compare both stamps in UTC.", answer: ["4", "four"], why: "From 08:16:05 to 08:16:09: four seconds, ordinary relay speed. A real backwards step, after converting, would mean a skewed clock or a fabricated line." },
          { id: "gap", q: "How many whole minutes passed between line 3 and line 2?", hint: "09:03:25 minus 08:16:09.", answer: ["47", "forty-seven", "forty seven"], why: "47 minutes, and both lines are yours, so you can find out why: your own sandbox held the attachment. A long gap always gets a question. Below the boundary, nobody can answer it for you." },
          { id: "first", q: "Which name did the machine at the earliest hop claim for itself?", hint: "Earliest means the bottom line. The claim is the name after from.", answer: ["pc-billing3.malabarspice.example"], why: "The bottom line was written first, and the name after from is what the connecting machine said. It's the sender's side of the story, so note it and don't lean on it." },
        ],
        primer: {
          title: "Every stamp carries its own offset",
          fold: true,
          points: [
            "Each server writes local time plus an offset. To compare two stamps, convert both to UTC.",
            "Adjacent hops are normally seconds apart. A gap of minutes or hours means a queue, a hold or a sandbox, or a line that was invented.",
            "After converting, a stamp earlier than the line below it needs an explanation: a skewed clock, or a fabricated line.",
          ],
          example: {
            label: "Worked example",
            lines: [
              "`Fri, 6 Nov 2026 01:10:00 -0500` = 06:10:00 UTC",
              "`Fri, 6 Nov 2026 15:40:02 +0930` = 06:10:02 UTC",
              "Two seconds apart, though the printed hours look far from each other.",
            ],
          },
        },
      },
    ],
    // ── Reading 4: SPF ──
    "email-r4": [
      {
        kind: "codebreak",
        title: "Work Out the SPF Result",
        prompt: "The IP is a fact now, so ask the next question: was it allowed? Ikaika Moretti gives you a published SPF record and a connecting IP. Evaluate the record the way a receiver does, and type the result it would record.",
        rounds: [
          { id: "c1", clue: "harbourtea.example publishes: v=spf1 ip4:203.0.113.64/27 ~all. Connecting IP: 198.51.100.9. What result?", answer: "SOFTFAIL", why: "A /27 from 203.0.113.64 covers .64 to .95, and 198.51.100.9 isn't in it. Evaluation reaches ~all, so softfail: treat with suspicion, usually still delivered. Domains often use it while rolling SPF out." },
          { id: "c2", clue: "kettleandleaf.example publishes: v=spf1 ip4:203.0.113.8 ?all. Connecting IP: 203.0.113.99. What result?", answer: "NEUTRAL", why: "The IP doesn't match, and ?all makes no statement at all. The domain is declining to say. That's a long way from a pass." },
          { id: "c3", clue: "brightquay.example publishes: v=spf1 ip4:203.0.113.128/26 -all. Connecting IP: 203.0.113.140. What result?", answer: "PASS", why: "A /26 from .128 covers .128 to .191, so .140 matches, and a mechanism with no qualifier means +. The -all is never reached. It only applies to whatever is left over." },
          { id: "c4", clue: "malabarspice.example publishes: v=spf1 include:spf.cargoportal.example -all. The DNS query for spf.cargoportal.example timed out. What result?", answer: "TEMPERROR", why: "The check couldn't finish because of a passing DNS problem, so the result is temperror, and a retry may succeed. A record that can never be evaluated gets a permanent error instead." },
        ],
        lesson: "Read left to right, stop at the first match, and let its qualifier give the result. all is only the fallback. And keep the scope in mind: a pass says this IP may send for this envelope domain, and nothing about the From line, the content or the reputation of a domain somebody registered an hour ago.",
        primer: {
          title: "How a receiver evaluates SPF",
          fold: true,
          points: [
            "SPF is a DNS TXT record on the **envelope domain**. It is read left to right, and the first mechanism matching the connecting IP decides.",
            "Qualifier gives the result: `+` pass (the default when none is written), `-` fail, `~` softfail, `?` neutral.",
            "`ip4:` with a slash is a range. A /28 is 16 addresses, a /27 is 32, a /26 is 64.",
            "`include:` runs another domain's record. A DNS failure along the way gives **temperror**, which may clear on a retry.",
            "A record that can't be evaluated, such as one with bad syntax or more than 10 DNS lookups, gives **permerror**.",
          ],
          example: {
            label: "Worked example: v=spf1 ip4:203.0.113.32/28 -all",
            lines: [
              "IP 203.0.113.40: inside .32 to .47, the mechanism matches, no qualifier, so pass",
              "IP 203.0.113.50: no match, evaluation reaches -all, so fail",
            ],
          },
        },
      },
      {
        kind: "worksheet",
        title: "Count the SPF DNS Lookups",
        prompt: "Saffron Road's own record has grown one vendor at a time. SPF allows 10 DNS lookups for one check, nested ones included. The warehouse wants a new freight portal added on Monday. Count what the record already costs.",
        caption: "v=spf1 ip4:203.0.113.25 a:mail.saffronroad.example mx include:spf.officemail.example include:_spf.cargoportal.example include:spf.erpcloud.example -all",
        columns: ["Mechanism", "Own lookup", "Nested lookups inside it"],
        rows: [
          ["ip4:203.0.113.25", "0", "-"],
          ["a:mail.saffronroad.example", "1", "-"],
          ["mx", "1", "-"],
          ["include:spf.officemail.example", "1", "3"],
          ["include:_spf.cargoportal.example", "1", "1"],
          ["include:spf.erpcloud.example", "1", "0"],
          ["-all", "0", "-"],
        ],
        questions: [
          { id: "total", q: "How many DNS lookups does the record cost today?", hint: "Add both number columns.", answer: ["9", "nine"], why: "1 + 1 + 4 + 2 + 1 = 9. It's inside the limit, with one to spare. Vendors don't announce changes to their own nested includes, so this number can move without anyone touching your record." },
          { id: "after", q: "The new include has one nested include of its own. What is the total now?", hint: "One for the include, one for what's inside it.", answer: ["11", "eleven"], why: "Eleven is over the limit of 10, so receivers return permerror, and most treat that like a fail, even for a server you listed. The cause is your own sprawl, not an attacker, so check the lookup count before you read a sudden wave of failures as an attack." },
          { id: "free", q: "How many mechanisms in this record cost no lookup at all?", hint: "Look for a zero in the first number column.", answer: ["2", "two"], why: "ip4 and all need no DNS query. Replacing an include with the vendor's published ranges is how teams get back under the limit, at the cost of tracking those ranges by hand." },
        ],
        primer: {
          title: "What costs a lookup",
          fold: true,
          points: [
            "`include`, `a`, `mx`, `ptr`, `exists` and `redirect` each cost one DNS lookup.",
            "`ip4`, `ip6` and `all` cost none.",
            "Nested lookups inside an include share the same budget of 10.",
          ],
          example: {
            label: "Worked example: v=spf1 mx include:a.example include:b.example -all",
            lines: [
              "`mx` = 1, `include:a.example` = 1, and a.example has 2 includes = 2",
              "`include:b.example` = 1, and b.example has none",
              "Total: 5",
            ],
          },
        },
      },
    ],
    // ── Reading 5: DKIM ──
    "email-r5": [
      {
        kind: "anatomy",
        title: "Anatomy of a DKIM Signature",
        prompt: "SPF is about the connection. DKIM is about the message. Ikaika Moretti opens the signature on a routine supplier message, because Tuesday's forgery carries one too, and you need to know exactly what it does and doesn't promise.",
        source: "Raw headers · DKIM-Signature, unfolded · harbourtea.example",
        fields: [
          { key: "v", value: "1", label: "Version" },
          { key: "a", value: "rsa-sha256", label: "Algorithm" },
          { key: "c", value: "relaxed/relaxed", label: "Canonicalization", note: "Header rule, then body rule. Relaxed forgives case in header names, re-folding and spare whitespace. Simple forgives almost nothing." },
          { key: "d", value: "harbourtea.example", label: "Signing domain", note: "Who is vouching. This is the value DMARC compares with the From domain, and it doesn't have to be the From domain." },
          { key: "s", value: "oct2026", label: "Selector", note: "Picks the public key. The receiver fetches a TXT record at oct2026._domainkey.harbourtea.example, which lets a domain rotate keys." },
          { key: "t", value: "1793182959", label: "Signed at", note: "Seconds since 1970, in UTC. A signature is not bound to the day it arrives, so a stolen signed message can be sent again later." },
          { key: "h", value: "from:to:subject:date:message-id:mime-version", label: "Signed headers", note: "Only these are protected. Reply-To isn't listed here, so one can be added after signing and the signature still verifies." },
          { key: "bh", value: "1RlyM22g89pbbMfCESEIYYLxDjy9+qSZM6/GfY1Gt3c=", label: "Body hash", note: "SHA-256 of the canonicalized body. The receiver recomputes it first. A mismatch is reported as body hash did not verify." },
          { key: "b", value: "pT7mWc1eLq9sJx4Z...3w==", label: "Signature", note: "Made with the private key over the headers in h= and this DKIM-Signature line, bh= included. Change a signed header and this fails, reported as signature did not verify." },
        ],
        summary: "There are two checks in one line. bh= protects the body. b= protects the signed headers, and because it also covers bh=, it locks the two together. So the failure text tells you which part changed. A pass means whoever holds the key for d= signed these bytes. It doesn't say the domain is honest, and it doesn't say the message arrived by a sensible path.",
        primer: {
          title: "A seal on the message, not on the path",
          fold: true,
          points: [
            "DKIM (DomainKeys Identified Mail) signs each message with a private key. The public key sits in DNS.",
            "The receiver reads `d=` and `s=`, fetches the key, recomputes the hashes and compares.",
            "Because it depends on the bytes and not on the connection, it can survive extra hops. SPF can't.",
          ],
          example: {
            label: "Worked example: where the key lives",
            lines: [
              "`d=oolong.example; s=jan2026` gives the lookup `jan2026._domainkey.oolong.example`",
              "TXT answer: `v=DKIM1; k=rsa; p=MIIBIjANBgkq...`",
            ],
          },
        },
      },
      {
        kind: "reactor",
        title: "Which DKIM Hash Does This Break?",
        prompt: "A message signed with c=relaxed/relaxed and h=from:to:subject:date rides the belt, and each card changes something on the way. Send it to what that change does to the signature. A failed DKIM check is a record that something changed, and this is how you work out what.",
        reactors: [
          { id: "body", label: "Body hash (bh=)", sub: "the bytes after the blank line changed" },
          { id: "sig", label: "Signature (b=)", sub: "a header listed in h= changed" },
          { id: "none", label: "Neither", sub: "DKIM still verifies" },
        ],
        items: [
          { id: "k1", text: "A forwarding gateway adds a legal disclaimer under the text", reactor: "body", why: "The body has new bytes, so the hash no longer matches: body hash did not verify. An ordinary gateway can cause this." },
          { id: "k2", text: "A service rewrites every link in the body for click scanning", reactor: "body", why: "A rewritten URL is a changed body. If it happens before the final check, the hash fails with no attacker involved." },
          { id: "k3", text: "An old relay converts the 8-bit body to quoted-printable", reactor: "body", why: "The text reads the same to a person, but the bytes differ. Relaxed body rules only forgive whitespace." },
          { id: "k4", text: "A relay puts [Trade] in front of the Subject", reactor: "sig", why: "Subject is listed in h=, so the header hash changes and b= fails: signature did not verify. The body hash still matches." },
          { id: "k5", text: "A relay rewrites the To: line to an internal alias", reactor: "sig", why: "To is listed in h=. A list of signed headers is a list of things nobody may touch." },
          { id: "k6", text: "A relay adds its own Received line", reactor: "none", why: "Received isn't in h=, and new ones are added at every hop. That's why DKIM can survive a journey." },
          { id: "k7", text: "Somebody adds a Reply-To after signing", reactor: "none", why: "Reply-To isn't in h=, so the signature still verifies with a new reply address on it. A DKIM pass doesn't cover what h= leaves out." },
          { id: "k8", text: "A server re-folds the long Subject across two lines", reactor: "none", why: "Relaxed header rules unfold before hashing. With c=simple for headers, the same harmless change would break b=." },
          { id: "k9", text: "A relay strips the blank lines at the very end of the body", reactor: "none", why: "Body canonicalization ignores trailing empty lines, in simple and in relaxed. The hash comes out the same." },
        ],
        primer: {
          title: "Two hashes, two failure messages",
          fold: true,
          points: [
            "`dkim=fail (body hash did not verify)`: the body changed after signing.",
            "`dkim=fail (signature did not verify)`: a signed header changed, or the key doesn't match.",
            "Anything outside `h=`, and any new header, is not covered.",
            "Neither failure tells you who changed it. Benign gateways do this every day, and so does a forger reusing an old signature.",
          ],
          example: {
            label: "Worked example: h=from:subject",
            lines: [
              "Change the Subject: `b=` fails, `bh=` still matches",
              "Add a line to the body: `bh=` fails",
              "Add an `X-Scanned: yes` header: nothing fails",
            ],
          },
        },
      },
    ],
    // ── Reading 6: DMARC and ARC ──
    "email-r6": [
      {
        kind: "simulate",
        title: "What Survives Forwarding?",
        prompt: "The same broker message takes five different roads to a Saffron Road mailbox. Run each one and watch which seal holds. Header From is brightquay.example every time.",
        checks: [
          { name: "Aligned SPF", question: "Did the IP pass for the envelope domain, and does that domain align with From?" },
          { name: "Aligned DKIM", question: "Did a signature verify, and does its d= align with From?" },
          { name: "DMARC", question: "Did at least one of the two pass and align?" },
        ],
        scenarios: [
          {
            id: "direct", label: "Sent direct",
            detail: "MAIL FROM:<bq-invoices@mta.brightquay.example>   d=brightquay.example   connecting: mta4.brightquay.example",
            results: ["pass", "pass", "pass"],
            why: ["The IP is listed for mta.brightquay.example, and that subdomain aligns under relaxed rules.", "Nothing changed after signing, and d= matches From.", "Two aligned passes. Only one was needed."],
            verdict: "The baseline. Every other road below is this message with something done to it.",
          },
          {
            id: "forward", label: "Plain forward",
            detail: "A buyer's old trade-body address auto-forwards. Envelope unchanged, body unchanged, connecting IP is now the forwarder's.",
            results: ["fail", "pass", "pass"],
            why: ["The forwarder's IP isn't in Brightquay's record. SPF is tied to the path, and the path changed.", "Not one byte changed, so both hashes still match. DKIM is tied to the message.", "One aligned pass is enough, whichever check supplies it."],
            verdict: "SPF almost never survives forwarding. DKIM usually does. That's why a domain that signs its mail keeps passing DMARC through a forward.",
          },
          {
            id: "srs", label: "Forward with SRS",
            detail: "MAIL FROM:<SRS0=x7Qa=RK=mta.brightquay.example=bq-invoices@relay.tradebody.example>",
            results: ["fail", "pass", "pass"],
            why: ["SRS (Sender Rewriting Scheme) puts the forwarder's domain in the envelope, so SPF passes for relay.tradebody.example. That domain doesn't align with From, so it adds nothing here.", "Still unchanged, still aligned.", "DKIM again."],
            verdict: "SRS keeps bounces working and stops the SPF failure, but it can't make SPF align. A green spf=pass here tells you about the forwarder.",
          },
          {
            id: "list", label: "List with a tag and footer",
            detail: "A trade mailing list adds [Spice-Market] and a footer, then sends from its own server with its own envelope.",
            results: ["fail", "fail", "fail"],
            why: ["SPF is checked against the list's envelope domain, which doesn't align with From.", "The tag and footer broke the signature.", "Neither aligned pass is left."],
            verdict: "An honest list broke both seals, and DMARC can't tell this from a forgery. This gap is what ARC was built for: see the next lab.",
          },
          {
            id: "forged", label: "Forged from a VPS",
            detail: "MAIL FROM:<ops@hostline.example>   pasted DKIM-Signature d=brightquay.example   new body   connecting: 198.51.100.44",
            results: ["fail", "fail", "fail"],
            why: ["The IP fails for hostline.example, and that domain wouldn't align anyway.", "The old signature can't cover a new body.", "Nothing passed and aligned."],
            verdict: "The same three fails as the honest list. The DMARC line alone can't separate them, so read why each one failed and what else the headers show.",
          },
        ],
        primer: {
          title: "Why forwarding hurts each check differently",
          fold: true,
          points: [
            "**SPF follows the path.** A new hop means a new IP, so a forward usually breaks it.",
            "**DKIM follows the bytes.** It survives a hop if nothing signed changes.",
            "**DMARC needs one** of them to pass and align with From. One failure doesn't cancel the other's pass.",
            "Relaxed alignment accepts the same organisational domain. A different organisational domain never aligns.",
          ],
          example: {
            label: "Worked example: oolong.example through a forwarder",
            lines: [
              "`spf=fail smtp.mailfrom=oolong.example` : the forwarder's IP isn't listed",
              "`dkim=pass header.d=oolong.example` : bytes untouched",
              "`dmarc=pass header.from=oolong.example` : DKIM carried it",
            ],
          },
        },
      },
      {
        kind: "anatomy",
        title: "Anatomy of an ARC Set",
        prompt: "Last Friday's market report reached m.oyelaran through a trade list, and both seals look broken. The list added three more headers on the way. Read them: this is how a message carries a record of what it looked like before someone changed it.",
        source: "Raw headers · message via lists.spicetrade.example · unfolded",
        fields: [
          { key: "Authentication-Results", value: "inbound1.saffronroad.example; spf=pass smtp.mailfrom=lists.spicetrade.example; dkim=fail (body hash did not verify) header.d=malabarspice.example; arc=pass (i=1); dmarc=fail (p=quarantine dis=none) header.from=malabarspice.example", label: "Your verdict", note: "Your own gateway wrote this. SPF passed for the list, which doesn't align. DKIM failed. The dis=none means the gateway delivered it anyway, because it trusts this sealer." },
          { key: "ARC-Authentication-Results", value: "i=1; mx.spicetrade.example; spf=pass smtp.mailfrom=malabarspice.example; dkim=pass header.d=malabarspice.example; dmarc=pass header.from=malabarspice.example", label: "The list's witness statement", note: "What the list saw when the message arrived, before it changed anything. Everything passed there. This is the line that explains your failure." },
          { key: "ARC-Message-Signature", value: "i=1; a=rsa-sha256; c=relaxed/relaxed; d=spicetrade.example; s=arc2026; t=1793342478; h=from:to:subject:date; bh=X4mxgewX+0O9VueMewS2hkZhmdjRRM7I+KG9bY3nJXk=; b=hR2vNz8cUk0d...Lw==", label: "The sealer's own signature", note: "Works like DKIM, but it is made after the list's edits and it covers the message as the list sent it. Its d= is the list, not the author." },
          { key: "ARC-Seal", value: "i=1; a=rsa-sha256; t=1793342478; cv=none; d=spicetrade.example; s=arc2026; b=Qm4tJp7xGa2y...8A==", label: "The seal", note: "Locks this ARC set. i=1 means the first intermediary, and each further one adds i=2 and so on. cv=none is normal on the first set. Later sets say cv=pass if the chain so far validates, or cv=fail." },
          { key: "List-Id", value: "Market report <market-report.lists.spicetrade.example>", label: "List marker", note: "Set by mailing-list software. On its own it's only a header anyone could type, but it fits the Subject tag and the sealer." },
          { key: "Subject", value: "[Spice-Market] Weekly cardamom prices", label: "The change you can see", note: "The tag and the footer are the list's edits, and the footer is why the body hash failed." },
        ],
        summary: "ARC (Authenticated Received Chain) isn't a pass. It's a signed witness statement: this is what we saw before we changed it. It's only worth what the witness is worth, because anyone can seal their own mail with a valid signature. Trust it when the sealer is one you already know. Then read ARC-Authentication-Results, not the seal, to learn what was true upstream. It's the field that turns a failed DKIM from a mystery into an explanation.",
        primer: {
          title: "Why a forwarder writes things down",
          fold: true,
          points: [
            "A list or forwarder that edits a message breaks DKIM, and its new path breaks SPF alignment.",
            "ARC lets that intermediary record the results it saw on arrival, and sign that record.",
            "A later receiver that trusts the intermediary can use the record instead of failing the message outright.",
          ],
          example: {
            label: "Worked example: two sets on one message",
            lines: [
              "`ARC-Seal: i=1; cv=none; d=first-list.example` : first intermediary",
              "`ARC-Seal: i=2; cv=pass; d=second-relay.example` : second one, the chain so far validated",
            ],
          },
        },
      },
      {
        kind: "worksheet",
        title: "Read Policy Against Disposition",
        prompt: "A domain publishes what it wants done with failures. Your gateway decides what actually happens. Ikaika Moretti wants to know where those two came apart in last week's failed mail, so compare each DMARC record with what the gateway did.",
        caption: "Failed DMARC · last week · record, verdict and destination",
        columns: ["Msg", "_dmarc record", "dmarc= in Authentication-Results", "Went to"],
        rows: [
          ["1", "v=DMARC1; p=none; rua=mailto:r@harbourtea.example", "fail (p=none dis=none)", "Inbox"],
          ["2", "v=DMARC1; p=quarantine; pct=100", "fail (p=quarantine dis=quarantine)", "Junk"],
          ["3", "v=DMARC1; p=quarantine; pct=25", "fail (p=quarantine dis=none)", "Inbox"],
          ["4", "v=DMARC1; p=quarantine; pct=100", "fail (p=quarantine dis=none)", "Inbox"],
          ["5", "v=DMARC1; p=reject; adkim=s; aspf=s", "fail (p=reject dis=reject)", "Refused"],
        ],
        questions: [
          { id: "mon", q: "Which message's domain is only monitoring, and asks for nothing to be done?", hint: "Look for the policy that takes no action.", answer: ["1", "msg 1", "message 1"], why: "p=none collects reports and enforces nothing. Delivery to the inbox is what that owner asked for." },
          { id: "tag", q: "Message 3 has dis=none and went to the inbox. Which tag in its record explains that?", hint: "Which tag differs from message 4's record?", answer: ["pct", "pct=25"], why: "pct=25 applies the policy to a quarter of failing mail. The rest is treated one step down, so dis=none here is what the owner's own rollout setting produced. On p=reject the unselected share drops to quarantine, never to none, so pct alone can't produce dis=none there." },
          { id: "gap", q: "Which message was delivered although nothing in its own record allows it?", hint: "Same p= and dis= as the row above it. What's different about the record?", answer: ["4", "msg 4", "message 4"], why: "Full policy, 100 percent, and dis=none. dis= records what the receiver really did, so the gap is local: an allow rule or override on your own gateway. Take that to whoever runs it." },
          { id: "strict", q: "Under a record with adkim=s like message 5's, does d=news.harbourtea.example align with From harbourtea.example? (yes/no)", hint: "s means strict.", answer: ["no"], why: "Strict alignment needs an exact match, so a subdomain doesn't count. Under the default relaxed mode the same pair would align, because they share an organisational domain." },
        ],
        primer: {
          title: "p= asks, dis= answers",
          fold: true,
          points: [
            "A domain publishes DMARC at `_dmarc.<domain>`. `p=` is the request: `none` (monitor), `quarantine` (treat as junk), `reject` (refuse).",
            "`pct=` applies the policy to that share of failing mail. Its default is 100.",
            "`adkim=` and `aspf=` set alignment: `r` relaxed, the default, or `s` strict.",
            "In a receiver's Authentication-Results, `dis=` records what was **actually done**.",
            "So `p=` is for the domain owner to write, and `dis=` is for the receiver to answer. When they differ, find out why.",
          ],
          example: {
            label: "Worked example",
            lines: [
              "`_dmarc.oolong.example TXT \"v=DMARC1; p=quarantine; rua=mailto:r@oolong.example\"`",
              "`dmarc=fail (p=quarantine dis=quarantine) header.from=oolong.example` : request honoured",
            ],
          },
        },
      },
    ],
    // ── Side by Side ──
    "email-la1": [
      {
        kind: "spotdiff",
        title: "Set a Genuine Invoice Beside a Forged One",
        prompt: "Ikaika Moretti has pulled Brightquay's real October invoice from the archive and set it beside the message d.ferro released from quarantine, both as they reached your gateway. The verdict line is removed, so you read the facts first. Tap the lines that really tell them apart.",
        goodTitle: "Genuine: Brightquay invoice, 5 October",
        suspectTitle: "Suspect: released from quarantine, 3 November",
        good: [
          "Return-Path: <bq-invoices@mta.brightquay.example>",
          "X-Gateway-Scan-Id: gw-20261005-81734",
          "X-Spam-Score: 1.2",
          "Received: from mta4.brightquay.example (mta4.brightquay.example [203.0.113.140]) by inbound1.saffronroad.example with ESMTPS id 4Gk9Tz2VnR; Mon, 5 Oct 2026 08:02:11 +0000",
          R_MTA, R_BILL, DKIM, FROM,
          "Reply-To: <accounts@brightquay.example>",
          TO, SUBJECT, DATE, MSGID,
        ],
        suspect: [
          "Return-Path: <ops@hostline.example>",
          "X-Gateway-Scan-Id: gw-20261103-22109",
          "X-Spam-Score: 1.8",
          "Received: from mta4.brightquay.example (vps-88.hostline.example [198.51.100.44]) by inbound1.saffronroad.example with ESMTP id 4Hq2Lx7mZk; Tue, 3 Nov 2026 09:14:06 +0000",
          R_MTA, R_BILL, DKIM, FROM,
          FORGED_REPLY_TO,
          TO, SUBJECT, DATE, MSGID,
        ],
        diffs: [
          { line: 0, why: "Both Return-Paths differ from the From address, so a mismatch alone isn't the tell. The genuine one is a Brightquay subdomain, which aligns. This one is hostline.example, a VPS host with no link to the broker." },
          { line: 3, why: "Your own gateway wrote this. The claimed name is the same because anyone can type it, but the reverse DNS and IP came from the connection: vps-88.hostline.example, not Brightquay's server. And no TLS: ESMTP, not ESMTPS." },
          { line: 8, why: "The Reply button leaves for a third domain now: From, Return-Path and Reply-To are all different. A pasted signature doesn't mind, because reply-to isn't in h=." },
        ],
        decoys: [
          { line: 1, why: "Different, and meaningless. Your gateway gives every message its own scan ID." },
          { line: 2, why: "A spam score moves a little on every message. 1.8 against 1.2 decides nothing." },
        ],
        hud: "Tap the lines that give the forgery away",
        sameLine: "That line is identical in both copies. It was pasted across, so it proves nothing about the sender.",
        winTitle: "Forgery read",
        howTo: ["Read the genuine message on the left, then the suspect on the right, line by line.", "Tap each line that really tells the two apart.", "A line that differs for a harmless reason, or doesn't differ at all, costs a life."],
        lesson: "The identical lines are the clue you can't tap. The two lower Received lines and the DKIM-Signature were pasted from a real October invoice, which is why the chain jumps 29 days at your own boundary. The gateway's verdict agrees: dkim=fail (body hash did not verify), because an old signature can't cover a new body. Compare what your own server recorded first, then ask what the sender could simply have typed.",
        primer: {
          title: "Compare facts, not claims",
          fold: true,
          points: [
            "Start with what your own gateway recorded: the top outside Received line. The sender can't touch it.",
            "**Identical doesn't mean genuine.** A sender can paste old Received lines and an old DKIM-Signature into DATA.",
            "Read three addresses together: From (shown), Return-Path (SPF), Reply-To (where answers go). Three unrelated domains on one message is a pattern worth stopping for.",
            "Some lines change on every message, such as scan IDs and scores. Those differences mean nothing.",
          ],
          example: {
            label: "Worked example: two messages from oolong.example",
            lines: [
              "`Received: from relay.oolong.example (relay.oolong.example [203.0.113.9])` : claim and lookup agree",
              "`Received: from relay.oolong.example (unknown [198.51.100.3])` : same claim, a different machine",
              "`X-Scan: 8841` and `X-Scan: 2207` : a counter, ignore it",
            ],
          },
        },
      },
      {
        kind: "queue",
        title: "Scope the Response to Each Message",
        prompt: "Reading the headers is half the job. Four messages are waiting, and each one needs a different size of response. Doing too little leaves copies behind, and doing too much bins a supplier.",
        console: "Mail security · analyst queue",
        actions: [
          { id: "close", label: "Close", tone: "close" },
          { id: "call", label: "Call a number you already hold", tone: "escalate" },
          { id: "purge", label: "Purge all copies, block, warn", tone: "contain" },
        ],
        alerts: [
          {
            id: "a1", time: "09:32", severity: "High", rule: "Failed authentication, released from quarantine", entity: "d.ferro",
            fields: [{ k: "From", v: "accounts@brightquay.example" }, { k: "Return-Path", v: "ops@hostline.example" }, { k: "Reply-To", v: "accounts.brightquay@mailbox-desk.example" }, { k: "To", v: "d.ferro" }, { k: "Gateway recipients", v: "2" }, { k: "Connecting IP", v: "198.51.100.44" }, { k: "dmarc", v: "fail (p=quarantine dis=quarantine)" }],
            context: "d.ferro reported it after releasing it. The To line names one person. The gateway log names two.",
            answer: "purge",
            why: "Search the gateway and purge every copy, including s.haddad's blind copy. Block the IP and both domains. Warn accounts payable about the pretext, and tell whoever owns quarantine that a user could release this. Replying is the one move to avoid: Reply-To goes straight to the attacker.",
          },
          {
            id: "a2", time: "10:05", severity: "Low", rule: "Return-Path differs from From", entity: "m.oyelaran",
            fields: [{ k: "From", v: "offers@harbourtea.example" }, { k: "Return-Path", v: "b7731@em.postrelay.example" }, { k: "dkim", v: "pass header.d=harbourtea.example" }, { k: "dmarc", v: "pass" }, { k: "First seen", v: "2 years ago" }],
            context: "The monthly price list, through the same mail vendor as always.",
            answer: "close",
            why: "A vendor's bounce domain is normal, and DKIM ties the message to the sender. No bank change, no new reply address, a long history. Closing it is the work.",
          },
          {
            id: "a3", time: "10:40", severity: "Medium", rule: "Payment details changed in mail", entity: "s.haddad",
            fields: [{ k: "From", v: "ledger@kettleandleaf.example" }, { k: "spf / dkim / dmarc", v: "pass / pass / pass, aligned" }, { k: "Reply-To", v: "(none)" }, { k: "First seen", v: "3 years ago" }, { k: "Body", v: "Please use our new account for future invoices" }],
            context: "A real supplier, from its real server. Authentication can't tell a person from someone inside that person's mailbox.",
            answer: "call",
            why: "Every check passed and the domain is theirs, so there's nothing to block yet. A payment change is confirmed out of band, on a number already on file, never one from the message. If the supplier didn't send it, this becomes their compromised mailbox and your purge.",
          },
          {
            id: "a4", time: "11:15", severity: "High", rule: "Own domain failed DMARC, delivered", entity: "warehouse staff",
            fields: [{ k: "From", v: "warehouse@saffronroad.example" }, { k: "Return-Path", v: "ops@hostline.example" }, { k: "dmarc", v: "fail (p=quarantine dis=none)" }, { k: "Matched rule", v: "Allow: partner relay (2023)" }, { k: "Gateway recipients", v: "9" }],
            context: "Your own policy asked for quarantine. An old allow rule on your gateway overrode it.",
            answer: "purge",
            why: "Nine copies, so purge them all, block the sender, and warn the warehouse. Then fix the cause: dis=none against your own policy points at the allow rule, so that goes to whoever runs the gateway. Cleaning one mailbox leaves the door open.",
          },
        ],
        primer: {
          title: "Four questions before you act",
          fold: true,
          points: [
            "**Who else has it?** Search the gateway. The To line misses every blind copy.",
            "**What do you block?** The source IP and the whole domain. Whoever owns a domain can change the address in seconds.",
            "**Who needs to know?** The team the pretext targets, and the owner of any control that failed.",
            "**How do you confirm?** Never by replying. Use a phone number or thread you already had.",
          ],
          example: {
            label: "Worked example: a fake courier notice",
            lines: [
              "To line shows 1 person, gateway shows 14 recipients: purge 14",
              "Sender rotates addresses on parcels-track.example: block the domain, not one address",
              "Warn reception, who open parcel mail all day",
            ],
          },
        },
      },
    ],
    "email-qf1": [
      {
        kind: "worksheet",
        title: "What Would This KQL Return?",
        prompt: "Ikaika Moretti wants the forged-sender pattern as a detection, not as a Tuesday memory. Before you write a rule, work out by hand what a filter keeps from these five rows, including your own mail.",
        caption: "EmailEvents, five rows whose From address claims saffronroad.example | extend AD = parse_json(AuthenticationDetails)",
        columns: ["Row", "SenderMailFromDomain", "AuthenticationDetails", "DeliveryAction"],
        rows: [
          ["1", "saffronroad.example", "{\"SPF\":\"pass\",\"DKIM\":\"pass\",\"DMARC\":\"pass\",\"CompAuth\":\"pass\"}", "Delivered"],
          ["2", "saffronroad.example", "{\"SPF\":\"fail\",\"DKIM\":\"pass\",\"DMARC\":\"pass\",\"CompAuth\":\"pass\"}", "Delivered"],
          ["3", "hostline.example", "{\"SPF\":\"fail\",\"DKIM\":\"none\",\"DMARC\":\"fail\",\"CompAuth\":\"fail\"}", "Junked"],
          ["4", "saffronroad.example", "{\"SPF\":\"pass\",\"DKIM\":\"fail\",\"DMARC\":\"pass\",\"CompAuth\":\"pass\"}", "Delivered"],
          ["5", "mailbox-desk.example", "{\"SPF\":\"softfail\",\"DKIM\":\"none\",\"DMARC\":\"fail\",\"CompAuth\":\"fail\"}", "Junked"],
        ],
        questions: [
          { id: "spf", q: "How many rows does | where tostring(AD.SPF) =~ \"softfail\" return?", hint: "=~ matches the whole value, ignoring case, so fail isn't softfail.", answer: ["1", "one"], why: "Row 5 only. Rows 2 and 3 hold a different value, so this filter skips them. Each SPF result is its own value, and a rule has to name the ones it means." },
          { id: "clear", q: "Row 2 is your own newsletter through a partner relay. Which verdict in it shows a real Saffron Road signature survived? (SPF, DKIM or DMARC)", hint: "SPF follows the path. What follows the message?", answer: ["dkim"], why: "The relay broke SPF, but DKIM verified. A rule that stops at the SPF verdict fires on your own mail, so a good rule also reads whether DKIM cleared the message." },
          { id: "comp", q: "How many rows does | where tostring(AD.CompAuth) !~ \"pass\" return?", hint: "!~ keeps every row where the value is not that word.", answer: ["2", "two"], why: "Rows 3 and 5, the two that really don't belong. CompAuth is Microsoft's composite verdict, and it's useful as a second opinion on top of the individual checks." },
        ],
        primer: {
          title: "Reading AuthenticationDetails",
          fold: true,
          points: [
            "In Defender's EmailEvents table, every verdict sits in one string column, `AuthenticationDetails`, as JSON.",
            "`parse_json()` unpacks it, and `tostring(AD.SPF)` reads one verdict as text.",
            "`=~` means equals, ignoring case. `!~` means does not equal, ignoring case.",
            "`where` keeps a row only if its condition is true. Two `where` lines must both hold.",
          ],
          example: {
            label: "Worked example: one row",
            lines: [
              "`{\"SPF\":\"pass\",\"DKIM\":\"none\",\"DMARC\":\"pass\"}`",
              "`where tostring(AD.DKIM) =~ \"none\"` : kept",
              "`where tostring(AD.SPF) !~ \"pass\"` : dropped",
            ],
          },
        },
      },
    ],
    "email-la2": [
      {
        kind: "hotspot",
        title: "Everything Passed. What Still Gives It Away?",
        prompt: "Thursday, 11:02. The forged invoice failed, so somebody came back with a better one. Here's the new message to d.ferro, and for the first time every check on it passes. Find what still gives it away, in the fields nobody has authenticated.",
        artifact: "Raw headers · inbound to d.ferro · Thu, 5 Nov 2026 11:02",
        finish: "Nothing here failed authentication, and that's the lesson. The evidence is the domain, its age, first contact and the request.",
        parts: [
          { id: "p1", style: "meta", flag: false, text: "Authentication-Results: inbound1.saffronroad.example; spf=pass smtp.mailfrom=brightquay-clearance.example; dkim=pass header.d=brightquay-clearance.example; dmarc=pass (p=none dis=none) header.from=brightquay-clearance.example", note: "All true. All three checks compared one domain with itself. Whoever owns it published SPF, a DKIM key and a DMARC record, which takes about ten minutes." },
          { id: "p2", style: "meta", flag: false, text: "Received: from mail.brightquay-clearance.example (mail.brightquay-clearance.example [198.51.100.212]) by inbound1.saffronroad.example with ESMTPS id 4Hs6Bw3KpN; Thu, 5 Nov 2026 11:02:14 +0000", note: "A tidy line: claim and reverse DNS agree, TLS was used. Anyone who runs their own server properly gets this. It tells you where the mail came from, not whose it is." },
          { id: "p3", style: "meta", flag: true, text: "From: \"Brightquay Customs Accounts\" <accounts@brightquay-clearance.example>", note: "The broker's real domain is brightquay.example. Adding a word and a hyphen makes a different organisational domain, so DMARC protects the broker from forgery and does nothing about this. Relaxed alignment doesn't connect the two either." },
          { id: "p4", style: "meta", flag: true, text: "X-Gateway-Intel: sender-domain-age=6d; first-contact=true", note: "Your gateway's own enrichment, from its records of domains and past senders. SPF, DKIM and DMARC only compare published DNS records with the message, so none of them ever reads a domain's age or history." },
          { id: "p5", style: "meta", flag: false, text: "Message-ID: <20261105110212.8841A@mail.brightquay-clearance.example>", note: "Well formed and consistent with its domain. Consistency isn't legitimacy." },
          { id: "p6", style: "subject", flag: true, text: "Correction: use the account below before Friday's duty deadline", note: "A changed bank account plus a deadline. No header ever proves a request like this is real. It gets a phone call to a number you already hold." },
          { id: "p7", style: "body", flag: false, text: "Dear Accounts, please find attached the statement for your held container.", note: "The tone and the container reference are convincing, but the attacker has read a real invoice. Good wording isn't evidence either way." },
        ],
        primer: {
          title: "What a pass can't see",
          fold: true,
          points: [
            "SPF, DKIM and DMARC check that a domain is **consistent with itself**. They have no idea what brand it resembles.",
            "An attacker can register a new domain and set all three up correctly. Everything will pass, and every pass will be true.",
            "A **cousin domain** is close to a real one by adding a word, a hyphen or a similar letter. It's a separate organisational domain, so alignment doesn't apply.",
            "When authentication passes, the case rests on other signals: age, first contact, the request itself.",
          ],
          example: {
            label: "Worked example: a cousin of oolong.example",
            lines: [
              "`From: sales@oolong-trading.example`",
              "`dmarc=pass header.from=oolong-trading.example` : true, and about that domain only",
              "Registered this week, never mailed you before: that is your evidence",
            ],
          },
        },
      },
    ],
    // ── Return Path: the boss ──
    "email-ac1": [
      {
        kind: "worksheet",
        title: "Which DKIM Failure Can You Explain?",
        prompt: "Friday, 07:30. Since Tuesday, the whole company reads \"DKIM fail\" as \"attack\", and four more messages have been reported. Ikaika Moretti's question is the same for each: what failed, and does anything in the headers explain it?",
        caption: "Reported this morning · all four show dkim=fail",
        columns: ["Msg", "List-Id", "Subject", "Failure text", "ARC-Authentication-Results i=1", "Sealer"],
        rows: [
          ["A", "market-report.lists.spicetrade.example", "[Spice-Market] Weekly prices", "body hash did not verify", "spf=pass dkim=pass dmarc=pass", "spicetrade.example, trusted since 2023"],
          ["B", "(none)", "Duty invoice and remittance details", "body hash did not verify", "(none)", "(none)"],
          ["C", "offers.dealhub.example", "[Deals] Last chance pricing", "body hash did not verify", "spf=pass dkim=pass dmarc=pass", "dealhub.example, never seen before"],
          ["D", "buyers.teaguild.example", "[Tea-Buyers] Auction calendar", "signature did not verify", "spf=pass dkim=pass dmarc=pass", "teaguild.example, trusted since 2024"],
        ],
        questions: [
          { id: "same", q: "A and B show identical failure text. Which one has a recorded pass from before the change?", hint: "Which column would show a result from an earlier hop?", answer: ["a", "msg a", "message a"], why: "A carries a statement from a sealer you trust: the message was clean on arrival at the list. B has no list, no ARC and nothing to explain why its body changed. The same words, for two very different reasons." },
          { id: "what", q: "On D the failure text is different. Which header's change does the row point to?", hint: "Which column shows something a list adds to a signed header?", answer: ["subject", "the subject"], why: "signature did not verify means a signed header changed, and the [Tea-Buyers] tag is the visible edit. The failure text, the tag and the List-Id all tell one story." },
          { id: "count", q: "How many of the four would you treat as explained by a list you trust?", hint: "C has the same results as A. Compare the Sealer column.", answer: ["2", "two"], why: "A and D. C's ARC set may verify perfectly, but anyone can seal their own mail, and you've never seen this sealer. A signature you can check from a witness you don't know proves nothing." },
        ],
      },
      {
        kind: "sort",
        title: "Fired Right, or Fired Wrong?",
        prompt: "One question remains after what failed: what do you call it? The word matters, because it decides what happens to the rule next. Sort this month's mail alerts by what really happened.",
        buckets: [
          { id: "tp", label: "True positive" },
          { id: "btp", label: "Benign true positive" },
          { id: "fp", label: "False positive" },
        ],
        items: [
          { id: "v1", text: "DKIM, SPF and DMARC all failed, with no list headers or ARC, and the body asks for a bank change.", bucket: "tp", why: "The condition is real and so is the harm. Contain it." },
          { id: "v2", text: "DKIM failed on mail between two Saffron Road offices. IT's archive gateway stamps a retention notice on the body, as its change ticket says.", bucket: "btp", why: "The signature really broke, so the rule was right. The cause is an owned, authorized change. Close it with that justification, and if it's noisy add a narrow exclusion for that gateway." },
          { id: "v3", text: "The rule flagged a DKIM failure, yet the message reads dkim=pass. The rule's pattern matched the word fail in the Subject.", bucket: "fp", why: "What the rule claimed never happened. The fix belongs in the rule's logic." },
          { id: "v4", text: "A lookalike-domain rule fired on harbourtea-events.example. The real supplier registered it two years ago and lists it on its own site.", bucket: "btp", why: "It does look like a cousin domain, so the rule did its job. The owner is real and confirmed, so close it with the reason." },
          { id: "v5", text: "A new-domain rule fired on a four-day-old cousin of a supplier asking to change payment details. Every check passed.", bucket: "tp", why: "Passing authentication doesn't change the verdict. It's a real attack, and the rule caught it." },
          { id: "v6", text: "An alert says SPF failed, but the gateway logged spf=pass. A parser update shifted the fields by one column.", bucket: "fp", why: "The event never happened as described. Calling this benign would hide a broken parser." },
        ],
        primer: {
          title: "Three words, three different next steps",
          fold: true,
          points: [
            "**True positive:** the activity is real and it's bad. Respond.",
            "**Benign true positive:** the rule fired correctly on something real, and that something is authorized. Close it with the justification, ideally confirmed by the owner.",
            "**False positive:** what the rule reported didn't really happen, or the rule misread it. Fix the rule.",
            "Calling a correct alert a false positive invites someone to weaken a rule that works.",
          ],
          example: {
            label: "Worked example: a rule for new mailbox forwarding",
            lines: [
              "Attacker forwards a director's mail outside: true positive",
              "IT sets a ticketed forward for a leaver's manager: benign true positive",
              "Rule fires because a log field says forwarding=false: false positive",
            ],
          },
        },
      },
    ],
  },
};
