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
        kind: "worksheet",
        title: "Read the Travel Log",
        prompt: "Received headers are stamped by each server, newest on top. Read them from the bottom up to follow the message from its origin.",
        caption: "Headers of 'Updated drawings, Block C' to s.patel@rivermead.example",
        columns: ["#", "header"],
        rows: [
          ["1 (top)", "Received: from mx2.rivermead.example (10.20.1.12) by mbx01.rivermead.example; Tue, 4 Nov 2026 09:14:09 +0000"],
          ["2", "Received: from mail.hollins-steel.example (203.0.113.41) by mx2.rivermead.example with ESMTPS; Tue, 4 Nov 2026 09:14:07 +0000"],
          ["3 (bottom)", "Received: from [10.8.4.22] by mail.hollins-steel.example with ESMTPSA (authenticated user m.hollins); Tue, 4 Nov 2026 09:14:02 +0000"],
          ["", "Return-Path: <m.hollins@hollins-steel.example>"],
          ["", "From: Mark Hollins <m.hollins@hollins-steel.example>"],
        ],
        questions: [
          { id: "origin", q: "Which public IP handed the message to Rivermead?", hint: "The hop where Rivermead's MX received it from outside.", answer: ["203.0.113.41"], why: "Header 2: Rivermead's own server recorded who connected to it. That stamp can be trusted; anything below it was written by servers you don't control." },
          { id: "auth", q: "Did the sender log in to their own mail server to send it? (yes/no)", hint: "Look for ESMTPSA and 'authenticated user' in header 3.", answer: ["yes"], why: "ESMTPSA means an authenticated submission: m.hollins logged in. A real account, so the next question is whether it's really him." },
          { id: "hops", q: "How many seconds from first hop to delivery?", hint: "09:14:02 to 09:14:09.", answer: ["7", "7 seconds", "seven"], why: "Normal. Long gaps or out-of-order times can mean queuing or forged lower headers." },
        ],
      },
    ],
    // ── Reading 2: SPF, DKIM, DMARC ──
    "email-sec-r2": [
      {
        kind: "terminal",
        title: "Ask DNS About the Sender",
        prompt: "Rivermead's own domain is often spoofed. Check what its DNS records actually say.",
        shell: "bash",
        host: "hannah@mailsec:~$",
        commands: [
          { match: "dig\\s+(\\+short\\s+)?txt\\s+rivermead\\.example(\\s+\\+short)?", help: "dig +short TXT rivermead.example                     the SPF record",
            output: "\"v=spf1 include:spf.protection.outlook.com include:_spf.invoicing-saas.example ip4:203.0.113.10 -all\"\n\"google-site-verification=Q2bX9...\"" },
          { match: "dig\\s+(\\+short\\s+)?txt\\s+_dmarc\\.rivermead\\.example(\\s+\\+short)?", help: "dig +short TXT _dmarc.rivermead.example              the DMARC policy",
            output: "\"v=DMARC1; p=quarantine; pct=100; rua=mailto:dmarc-reports@rivermead.example; adkim=s; aspf=r\"" },
          { match: "dig\\s+(\\+short\\s+)?txt\\s+selector1\\._domainkey\\.rivermead\\.example(\\s+\\+short)?", help: "dig +short TXT selector1._domainkey.rivermead.example   the DKIM public key",
            output: "\"v=DKIM1; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAu8Qw...IDAQAB\"" },
          { match: "dig\\s+(\\+short\\s+)?mx\\s+rivermead\\.example(\\s+\\+short)?", help: "dig +short MX rivermead.example                      where its mail is delivered",
            output: "0 rivermead-example.mail.protection.outlook.com." },
        ],
        objectives: [
          { id: "end", task: "What does Rivermead's SPF say about servers not on its list? (the mechanism at the end)", hint: "dig +short TXT rivermead.example", answer: ["-all", "fail", "hard fail", "hardfail"], why: "-all is a hard fail: anything else claiming to send as rivermead.example is not allowed. ~all would only soft-fail." },
          { id: "saas", task: "Which third-party service may also send as Rivermead?", hint: "Look at the include: entries.", answer: ["invoicing-saas.example", "_spf.invoicing-saas.example"], why: "Their invoicing platform. Every include is a supplier you trust to send in your name." },
          { id: "policy", task: "What does DMARC tell receivers to do with failing mail?", hint: "dig +short TXT _dmarc.rivermead.example", answer: ["quarantine", "p=quarantine"], why: "Quarantine: deliver to spam. p=reject would refuse it outright. rua= is where receivers send reports." },
          { id: "strict", task: "Is DKIM alignment strict or relaxed?", hint: "adkim=", answer: ["strict", "s", "adkim=s"], why: "adkim=s: the DKIM d= must match the From domain exactly, not just share a parent domain." },
        ],
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
