import type { RoomExperience } from "./types";

// "Operation Postmark" for the "email-security" room.
// Script: docs/campaign/27-email-security.md.
// Station task ids must match the room's task order exactly (see getRoomExperience).
//
// Rivermead Construction (fictional), not the graded tasks' corp.com. Lab data
// differs from the graded tasks: the header sheet traces Received hops, it
// never compares a DKIM d= with From (q1) or reads an spf=fail (q2); the dig
// console reads Rivermead's own records and never evaluates forwarding
// alignment (q4); the hijacked-thread hotspot is a vendor's real mailbox, not
// a CFO wire request to classify (q3); and the drill is a Defender EmailEvents
// record, not la1's corp-secure.com lookalike or its SPF domain (flag1).
export const EMAIL_SECURITY: RoomExperience = {
  roomId: "email-security",
  codename: "Operation Postmark",
  theme: "email",
  handler: { name: "Hannah Cole", role: "Email Security Analyst, Rivermead Construction" },
  briefing: [
    "Rivermead Construction. Hundreds of subcontractors, thousands of invoices, and an inbox that moves real money.",
    "Every email carries a travel log in its headers and three seals that say who really sent it. Most people never look at either.",
    "Hannah Cole reads them all day. She'll show you where a message really came from, what the DNS says about the sender, and what a hijacked thread looks like.",
    "Read the postmarks.",
  ],
  mission: "Trace a message hop by hop through its Received headers, query SPF, DKIM and DMARC records with dig, spot the tells in a hijacked supplier thread, and read a Defender email event field by field.",
  estimate: "~40 min",
  look: { primary: "#f59e0b", secondary: "#38bdf8", warn: "#f43f5e" },
  scene: "postmark",
  layout: "stage",
  story: {
    intro: { title: "Every Email Has a Travel Log", src: "https://wrxhxtdllbctsawvewue.supabase.co/storage/v1/object/public/lesson-videos/operation/email-security/postmark-intro-898d07ea.mp4", poster: "https://wrxhxtdllbctsawvewue.supabase.co/storage/v1/object/public/lesson-videos/operation/email-security/postmark-intro-841b9e62.jpg" },
    afterStation: {
      envelope: { title: "What the Seals Prove", src: "https://wrxhxtdllbctsawvewue.supabase.co/storage/v1/object/public/lesson-videos/operation/email-security/postmark-ch2-f9c0c483.mp4", poster: "https://wrxhxtdllbctsawvewue.supabase.co/storage/v1/object/public/lesson-videos/operation/email-security/postmark-ch2-149a313e.jpg" },
      seals: { title: "A Real Mailbox, a Fake Request", src: "https://wrxhxtdllbctsawvewue.supabase.co/storage/v1/object/public/lesson-videos/operation/email-security/postmark-ch3-0427a240.mp4", poster: "https://wrxhxtdllbctsawvewue.supabase.co/storage/v1/object/public/lesson-videos/operation/email-security/postmark-ch3-3d4d4fe5.jpg" },
      wire: { title: "Two Senders", src: "https://wrxhxtdllbctsawvewue.supabase.co/storage/v1/object/public/lesson-videos/operation/email-security/postmark-finale-3a5e8c96.mp4", poster: "https://wrxhxtdllbctsawvewue.supabase.co/storage/v1/object/public/lesson-videos/operation/email-security/postmark-finale-32776ed8.jpg" },
    },
  },
  stations: [
    {
      id: "envelope",
      label: "The Travel Log",
      topic: "SMTP, MX records and how a message moves · reading headers",
      tagline: "Trace a message back to the server that sent it",
      building: "archive",
      taskIds: ["email-sec-r1"],
    },
    {
      id: "seals",
      label: "Three Seals",
      topic: "SPF, DKIM, DMARC · alignment · what each one proves",
      tagline: "Ask DNS what a domain allows",
      building: "vault",
      taskIds: ["email-sec-r2", "email-sec-q1", "email-sec-q2", "email-sec-q4"],
    },
    {
      id: "con",
      label: "The Con",
      topic: "Phishing, spear phishing, whaling, BEC · the analysis workflow",
      tagline: "Find the tells in a hijacked thread",
      building: "office",
      taskIds: ["email-sec-r3", "email-sec-q3"],
    },
    {
      id: "wire",
      label: "The Wire Request",
      topic: "Putting headers, authentication and content together",
      tagline: "Read a gateway's record before the graded one",
      building: "ticket",
      taskIds: ["email-sec-la1", "email-sec-flag1"],
      boss: true,
    },
  ],
  personas: {
    "email-sec-q1": { name: "Hannah Cole", role: "Email Security Analyst", line: "dkim=pass, but the signature says d=newsletter-tool.com and From says corp.com. What does that mean?" },
    "email-sec-q2": { name: "Hannah Cole", role: "Email Security Analyst", line: "'From: the CEO' with spf=fail. Read that for me." },
    "email-sec-q3": { name: "Hannah Cole", role: "Email Security Analyst", line: "The CFO's real mailbox asks payables to wire $80,000. No link, no attachment. What is it?" },
    "email-sec-q4": { name: "Hannah Cole", role: "Email Security Analyst", line: "A forwarded newsletter: SPF fails, DKIM passes and aligns, p=reject. What does DMARC do?" },
  },
  briefings: {
    // ── Reading 1: how email moves ──
    "email-sec-r1": [
      {
        kind: "rush",
        title: "Travel Log Blitz",
        prompt: "Hannah keeps a wall of postmarks and calls out claims about how mail travels. True or false, fast. Received headers are the travel log: know which stamps you can trust.",
        seconds: 60,
        target: 10,
        trueLabel: "True",
        falseLabel: "False",
        cards: [
          { id: "k1", text: "Read Received headers from the bottom up to follow a message.", answer: true, why: "Each server adds its stamp on top, so the origin is at the bottom and your own server is at the top." },
          { id: "k2", text: "The top Received line is stamped by your own server.", answer: true, why: "Your server wrote it, so the connecting IP in it is evidence you can trust." },
          { id: "k3", text: "Every Received line below your own server can be trusted as written.", answer: false, why: "Lower lines were written by servers you do not control, and a sender can forge them. Trust begins at your own stamp." },
          { id: "k4", text: "ESMTPSA in a hop means the sender logged in to that server.", answer: true, why: "The A is for authenticated. It shows a real account sent it, not that the person behind the account is genuine." },
          { id: "k5", text: "Return-Path always matches the visible From address.", answer: false, why: "Return-Path is the envelope sender, which SPF checks. Mailing tools routinely put a different domain there." },
          { id: "k6", text: "An MX record says where a domain's incoming mail is delivered.", answer: true, why: "MX points to the receiving servers. It says nothing about who may send as the domain; that is SPF." },
          { id: "k7", text: "A 7-second gap across three hops is a sign of forgery.", answer: false, why: "Seconds between hops are normal. Long gaps or times that run backwards are the oddities to chase." },
          { id: "k8", text: "Going from bottom to top, hop times should not run backwards.", answer: true, why: "A hop earlier than the one below it suggests queuing, clock drift or a forged lower header." },
          { id: "k9", text: "The IP in your own server's stamp comes from the real connection.", answer: true, why: "Your server saw the TCP connection itself, so that IP was observed, not claimed." },
          { id: "k10", text: "The hostname after 'from' in a Received line is always verified.", answer: false, why: "It is whatever the connecting host announced. The IP in brackets is the part to rely on." },
          { id: "k11", text: "Servers hand mail to each other over SMTP, usually on port 25.", answer: true, why: "Server to server SMTP is port 25. Users' apps submit on 587 after logging in." },
          { id: "k12", text: "A Message-ID proves who wrote the message.", answer: false, why: "It is a unique label added by the sending system and is easy to set to anything." },
          { id: "k13", text: "Each server a message passes through adds its own Received line.", answer: true, why: "That is why a longer header can be traced hop by hop." },
          { id: "k14", text: "A From of a trusted supplier proves the supplier wrote it.", answer: false, why: "From is typed by the sender. Only SPF, DKIM and DMARC say anything about it, and even a real mailbox can be taken over." },
        ],
        lesson: "Trust the stamp your own server wrote, read upward from it with suspicion, and remember that hostnames, From and Message-ID are all claims while the connecting IP in your own stamp is an observation.",
      },
    ],
    // ── Reading 2: SPF, DKIM, DMARC ──
    "email-sec-r2": [
      {
        kind: "intercept",
        title: "The Gateway Seals",
        prompt: "You are on Rivermead's mail gateway. Rivermead publishes SPF with -all, its approved senders are Microsoft 365 and the invoicing platform, DMARC is p=quarantine with strict DKIM, and the suppliers publish what they publish. Each message arrives with its authentication results. Quarantine the ones the seals do not back and deliver the rest.",
        protect: "the mail gateway",
        blockLabel: "Quarantine",
        passLabel: "Deliver",
        seconds: 11,
        items: [
          { id: "g1", text: "From billing@hollins-steel.example · envelope hollins-steel.example", sub: "spf pass, aligned · dkim pass d=hollins-steel.example · dmarc pass", bad: false, why: "Both seals pass and align with the visible From, so the message really comes from that domain. It says nothing about whether the content is right, only whose it is." },
          { id: "g2", text: "From accounts@rivermead.example · envelope bounce@mailer-77.example", sub: "spf pass for mailer-77.example · dkim none · dmarc fail", bad: true, why: "SPF passed, but for the envelope domain, not the From domain. DMARC needs alignment: a pass that does not align with From proves nothing about rivermead.example." },
          { id: "g3", text: "From finance@rivermead.example · sent through the invoicing platform", sub: "spf pass, include:_spf.invoicing-saas.example · dkim pass d=rivermead.example · dmarc pass", bad: false, why: "A third party sending as us is allowed because we listed it in SPF and it signs with our domain. An unfamiliar sending IP is fine when the include covers it." },
          { id: "g4", text: "From it@rivermead.example · envelope it@rivermead.example · IP 203.0.113.99", sub: "spf fail (-all) · dkim none · dmarc fail", bad: true, why: "Our own domain from an address not on our list: SPF fails under -all, there is no signature, and DMARC fails. A plain spoof of the domain." },
          { id: "g5", text: "From hr@rivermead.example · a disclaimer added in transit", sub: "spf pass, aligned · dkim fail (body hash) · dmarc pass", bad: false, why: "DMARC passes if either SPF or DKIM passes and aligns. A broken signature from a footer added in transit is common when SPF still carries the message." },
          { id: "g6", text: "From accounts@rivermead-pay.example", sub: "spf pass · dkim pass d=rivermead-pay.example · dmarc pass", bad: true, why: "Every seal passes, for a domain someone registered to look like ours. Authentication proves who owns the domain, not that we know them: check the lookalike, not the seals." },
          { id: "g7", text: "From orders@smallsupplier.example · first mail from this supplier", sub: "spf none · dkim none · dmarc none (no records published)", bad: false, why: "No records means no policy to fail against. A small supplier with no email authentication is not an attack on its own; judge it on the content and the history." },
          { id: "g8", text: "From payroll@rivermead.example · IP 203.0.113.10", sub: "spf pass (ip4 listed) · dkim pass d=rivermead.example · dmarc pass", bad: false, why: "Our own listed address with our own signature: every seal passes and aligns. Unusual wording would be a content question, not an authentication one." },
          { id: "g9", text: "From Rivermead Payroll <payroll.rivermead@freemail.example>", sub: "spf pass · dkim pass d=freemail.example · dmarc pass", bad: true, why: "The display name carries our brand and the address is a free mailbox. The seals pass for freemail.example, which is not our domain: a display-name impersonation passes every check." },
          { id: "g10", text: "From accounts@hollins-steel.example · DNS lookup timed out", sub: "spf temperror · dkim pass d=hollins-steel.example · dmarc pass", bad: false, why: "A temperror means DNS did not answer, not that the sender failed. The aligned DKIM pass carries DMARC; retrying later or acting on temperror alone would delay good mail." },
        ],
        lesson: "Judge the seals together and against the visible From: a pass that is not aligned proves nothing, a failure of one seal is covered by the other, no records is not a spoof, and all seals passing for a lookalike domain still means a stranger.",
      },
    ],
    // ── Reading 3: attacks and the workflow ──
    "email-sec-r3": [
      {
        kind: "hotspot",
        title: "The Hijacked Thread",
        prompt: "A real supplier, a real thread about steel deliveries, and a new message in it. Click everything that should stop you paying.",
        artifact: "Re: Block C steel delivery, invoice 2291",
        parts: [
          { id: "from", text: "From: Mark Hollins <m.hollins@hollins-steel.example>", flag: false, note: "The genuine address, and it passed SPF, DKIM and DMARC. This is his real mailbox, which is why authentication can't save you.", style: "meta" },
          { id: "reply", text: "Reply-To: accounts@hollins-steeI.example", flag: true, note: "A capital I instead of a lowercase l. Your reply would go to the attacker, not to Hollins.", style: "meta" },
          { id: "thread", text: "Following our call on Monday about the Block C delivery schedule...", flag: false, note: "Real history from the thread. The attacker read the mailbox before writing.", style: "body" },
          { id: "bank", text: "Please note our bank details have changed. Use the account below for invoice 2291.", flag: true, note: "The core of business email compromise: a payment redirected to a new account, inside a thread you trust.", style: "body" },
          { id: "urgent", text: "The payment must go today or the delivery slot will be lost.", flag: true, note: "Urgency to stop you calling to check.", style: "body" },
          { id: "sig", text: "Mark Hollins · Operations · Hollins Steel Ltd", flag: false, note: "Copied from his real signature." },
        ],
      },
    ],
    // Drill before the graded gateway record: a Defender EmailEvents row.
    "email-sec-la1": [
      {
        kind: "anatomy",
        title: "Anatomy of an Email Event",
        prompt: "Before the graded record: how Microsoft Defender for Office 365 logs one inbound message in advanced hunting.",
        source: "Defender XDR · EmailEvents · rivermead.example",
        fields: [
          { key: "SenderFromAddress", value: "billing@rivermead-payments.example", label: "From (shown to user)", note: "The header From. A lookalike of rivermead.example." },
          { key: "SenderMailFromAddress", value: "bounce@mailer-77.example", label: "Envelope sender", note: "The MAIL FROM that SPF actually checks. Different from what the user sees." },
          { key: "SenderIPv4", value: "198.51.100.61", label: "Sending IP" },
          { key: "RecipientEmailAddress", value: "payables@rivermead.example" },
          { key: "Subject", value: "Overdue: statement for October" },
          { key: "AuthenticationDetails", value: "{\"SPF\":\"pass\",\"DKIM\":\"none\",\"DMARC\":\"none\",\"CompAuth\":\"fail\"}", label: "Seals", note: "SPF passes for mailer-77.example, not for the From domain. CompAuth, Microsoft's composite verdict, fails." },
          { key: "UrlCount", value: "1", label: "Links" },
          { key: "ThreatTypes", value: "Phish", label: "Verdict" },
          { key: "DeliveryAction", value: "Junked", label: "What happened", note: "Delivered to Junk, not blocked. A user can still open it from there." },
        ],
        summary: "Two different sender addresses, a pass that proves nothing about the visible From, and a message that still reached a folder. Now read the graded gateway record.",
      },
    ],
  },
};
