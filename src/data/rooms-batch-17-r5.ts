/**
 * Learning Rooms — Batch 17 (Room 5)
 *
 * "Email Protocols & Header Forensics" (email-protocols-forensics)
 *
 * Advanced deep dive into email: the SMTP conversation itself, envelope vs
 * header From, reading the full Received-header chain, SPF/DKIM/DMARC
 * mechanics (alignment, pass/fail semantics, why DMARC can pass on a phish),
 * ARC, and step-by-step header forensics of a spoofed message.
 */

import type { TelemetryEvent } from "@/lib/sim/types";
import { KQL_PRIMER } from "@/data/kqlPrimer";

// ── Log analysis event 1: spoofed message with envelope/header mismatch ─────
const spoofedHeaderEvent: TelemetryEvent = {
  id: "evt-email-la1-001",
  ts: "2026-06-02T13:41:07.000Z",
  source: "email_gateway",
  vendor: "Proofpoint",
  event_type: "email_received",
  severity: "high",
  description:
    "An inbound message addressed to k.osei@solvix.com displays the sender name 'Marcus Whitfield, CFO' with a solvix.com-formatted signature block; the message's Return-Path and Reply-To domains differ from both the displayed name's implied domain and from each other",
  network: { user_agent: "-" },
  raw: {
    "header.from": "\"Marcus Whitfield, CFO\" <m.whitfield@solvix.com>",
    "header.return_path": "<bounce-8841@sv-notify-relay.net>",
    "header.reply_to": "m.whitfield.cfo@outlook-secure-mail.com",
    "header.subject": "Time-sensitive wire authorization needed today",
    "header.message_id": "<8841c2f0-a913@sv-notify-relay.net>",
    "header.received_chain": [
      "from sv-notify-relay.net (unknown [154.16.88.201]) by mx1.solvix.com with ESMTPS id 8841c2f0 for <k.osei@solvix.com>; Tue, 02 Jun 2026 13:41:05 +0000",
      "from mail-relay-09.sv-notify-relay.net (mail-relay-09.sv-notify-relay.net [154.16.88.201]) by sv-notify-relay.net with ESMTP id 44a2; Tue, 02 Jun 2026 13:41:02 +0000",
    ],
    "header.authentication_results":
      "mx1.solvix.com; spf=fail smtp.mailfrom=sv-notify-relay.net; dkim=none; dmarc=fail (p=reject dis=none) header.from=solvix.com",
    "envelope.mail_from": "bounce-8841@sv-notify-relay.net",
    "envelope.rcpt_to": "k.osei@solvix.com",
    "connecting_ip": "154.16.88.201",
    "connecting_ip_reverse_dns": "no-ptr-record",
  },
};

// ── Log analysis event 2: DMARC-passing lookalike-domain phish ──────────────
const dmarcPassPhishEvent: TelemetryEvent = {
  id: "evt-email-la2-001",
  ts: "2026-06-05T08:12:44.000Z",
  source: "o365",
  vendor: "Microsoft Defender for Office 365",
  event_type: "email_received",
  severity: "high",
  description:
    "An inbound message addressed to a.nakamura@solvix.com displays the sender name 'Solvix Payroll Team' and passes SPF, DKIM, and DMARC alignment checks for its own header-From domain",
  raw: {
    "header.from": "\"Solvix Payroll Team\" <notifications@solvix-payr0ll.com>",
    "header.return_path": "<bounce@solvix-payr0ll.com>",
    "header.reply_to": "notifications@solvix-payr0ll.com",
    "header.subject": "Action required: update your direct deposit details",
    "header.message_id": "<7f2e-9a41@solvix-payr0ll.com>",
    "header.authentication_results":
      "mx1.solvix.com; spf=pass smtp.mailfrom=solvix-payr0ll.com; dkim=pass header.d=solvix-payr0ll.com; dmarc=pass (p=quarantine) header.from=solvix-payr0ll.com",
    "envelope.mail_from": "bounce@solvix-payr0ll.com",
    "envelope.rcpt_to": "a.nakamura@solvix.com",
    "connecting_ip": "198.51.100.77",
    domain_first_seen_days_ago: 2,
    domain_registrar: "NiceNIC",
  },
};

const emailRoom = {
  id: "email-protocols-forensics",
  title: "Email Protocols & Header Forensics",
  description:
    "Go past 'check SPF/DKIM/DMARC' into the protocol mechanics behind email spoofing: the raw SMTP conversation itself, why envelope-from and header-From are two entirely different things, how to read a full Received-header chain correctly (bottom to top), the precise alignment and qualifier rules that make SPF, DKIM, and DMARC work, and exactly why DMARC can legitimately pass on a phishing email that a careless analyst would otherwise trust, plus ARC, and a full step-by-step header forensics walkthrough.",
  difficulty: "advanced" as const,
  category: "Network Security" as const,
  estimatedMinutes: 65,
  xp: 405,
  icon: "✉️",
  prerequisites: ["email-security", "phishing-analysis"],
  tasks: [
    // ── Reading 1: the SMTP conversation ──────────────────────────────────────
    {
      type: "reading" as const,
      id: "email-r1",
      heading: "The SMTP Conversation, Step by Step",
      content:
        `Every email you've ever received was delivered through a plain-text conversation between two mail servers that looks a lot like a scripted chat, and reading that conversation directly is the fastest way to understand exactly where in the process spoofing becomes possible.\n\n` +
        `**The conversation, command by command**\n\n` +
        `1. **Connect**: the sending server opens a TCP connection to the receiving server's mail exchanger, typically on port 25 (server-to-server) or 587 (authenticated client submission).\n` +
        `2. **EHLO/HELO**: the sending server introduces itself by hostname ("EHLO mail-relay-09.example.com"). Critically: nothing about this step is verified or authenticated at the protocol level, a sending server can claim to be any hostname it wants here, and the receiving server has no built-in way to confirm it's telling the truth. If the receiver's EHLO reply advertises STARTTLS (as in the transcript below), the sender can issue STARTTLS to encrypt the session and must then send EHLO again before continuing.\n` +
        `3. **MAIL FROM**, the sending server declares the **envelope sender** ("MAIL FROM: <bounce@example.com>"). This is the address bounce/non-delivery notifications will be sent to, and, as you'll see in Reading 4, it's the exact address SPF checks, and it is NOT necessarily the same address the recipient will ever see displayed in their inbox.\n` +
        `4. **RCPT TO**, the sending server declares the recipient ("RCPT TO: <k.osei@solvix.com>"). A single message can have multiple RCPT TO commands (for multiple recipients, including blind-copied ones the visible headers won't reveal).\n` +
        `5. **DATA**, the sending server transmits the actual message: all of its headers (From, To, Subject, Date, and dozens of others) followed by a blank line, followed by the message body, terminated by a line containing just a single period.\n` +
        `6. **QUIT**: the connection closes.\n\n` +
        `**The single most important structural fact: two completely separate "from" addresses**\n\n` +
        `Notice that MAIL FROM (step 3, the **envelope sender**, also called the Return-Path once recorded) and the **From:** header (buried inside the DATA block in step 5, the **header sender**. This is what your email client actually displays to you) are two, entirely independent pieces of data, set independently, with nothing in the base SMTP protocol requiring them to match at all. A sending server is free to declare MAIL FROM: <bounce@totally-different-domain.com> and then, inside the message body it transmits during DATA, include a From: header claiming to be anyone at all. This gap: envelope sender vs. header sender, is the single most important structural fact in all of email security, and it's exactly what the rest of this room is built around: SPF checks one of these two addresses, DMARC exists specifically to require them to agree, and a careless reader who only ever looks at the "From" name shown in their inbox is looking at the one field with the least protocol-level verification behind it.`,
      codeExample:
        "A RAW SMTP CONVERSATION (SIMPLIFIED)\n" +
        "=======================================================\n" +
        "S: 220 mx1.solvix.com ESMTP ready\n" +
        "C: EHLO mail-relay-09.sv-notify-relay.net\n" +
        "S: 250-mx1.solvix.com Hello\n" +
        "S: 250 STARTTLS\n" +
        "C: MAIL FROM:<bounce-8841@sv-notify-relay.net>\n" +
        "S: 250 OK\n" +
        "C: RCPT TO:<k.osei@solvix.com>\n" +
        "S: 250 OK\n" +
        "C: DATA\n" +
        "S: 354 Start mail input; end with <CRLF>.<CRLF>\n" +
        "C: From: \"Marcus Whitfield, CFO\" <m.whitfield@solvix.com>\n" +
        "C: To: k.osei@solvix.com\n" +
        "C: Subject: Time-sensitive wire authorization needed today\n" +
        "C: \n" +
        "C: [message body text here]\n" +
        "C: .\n" +
        "S: 250 OK: queued\n" +
        "C: QUIT\n" +
        "=======================================================\n\n" +
        "TWO SEPARATE \"FROM\" ADDRESSES -- NOTHING FORCES A MATCH\n" +
        "=======================================================\n" +
        "MAIL FROM (step 3)   -> envelope sender / Return-Path\n" +
        "                        what SPF checks\n" +
        "From: header (step 5) -> header sender\n" +
        "                        what the recipient's inbox displays\n" +
        "=======================================================",
      checkpoint: {
        question:
          "mx1.solvix.com ran an SPF check on the message in this reading's transcript. Which line of the transcript supplied the domain that SPF evaluated?",
        options: [
          "EHLO mail-relay-09.sv-notify-relay.net",
          "MAIL FROM:<bounce-8841@sv-notify-relay.net>",
          "RCPT TO:<k.osei@solvix.com>",
          "From: “Marcus Whitfield, CFO” <m.whitfield@solvix.com>",
        ],
        answer: 1,
        explanation:
          "SPF evaluates the envelope sender declared by MAIL FROM (recorded later as the Return-Path): the smtp.mailfrom value names it. The From: header line is the most common wrong answer: it is what the recipient sees, but it travels inside DATA and SPF never looks at it (aligning it is DMARC's job). The EHLO line is only the server's unverified self-introduction, and RCPT TO names the recipient, not the sender.",
      },
    },

    // ── Reading 2: envelope vs header From ────────────────────────────────────
    {
      type: "reading" as const,
      id: "email-r2",
      heading: "Envelope-From vs. Header-From: the Core of Email Spoofing",
      content:
        `Building directly on Reading 1's structural gap, this is worth dwelling on because nearly every email authentication concept in this room exists specifically to address it.\n\n` +
        `**Why SPF checks the envelope, not the header**\n\n` +
        `SPF (covered fully in Reading 4) validates whether the CONNECTING SERVER'S IP address is authorized to send mail on behalf of the domain in the **envelope sender** (MAIL FROM / Return-Path), not the domain in the header From. This was a deliberate original design choice: SPF was built around the bounce-handling infrastructure of SMTP (where do non-delivery reports go), which is inherently tied to the envelope, not the displayed header. The practical consequence: an attacker who owns or controls ANY domain with a valid, passing SPF record (including a domain they registered themselves an hour ago) can set MAIL FROM to that domain and pass SPF cleanly, while their header From still displays whatever name and address they want the recipient to see. **SPF passing tells you nothing whatsoever about the header From domain.**\n\n` +
        `**Display name spoofing: the simplest attack of all**\n\n` +
        `Separate from any of this, the "display name" portion of a From header ("Marcus Whitfield, CFO" in "Marcus Whitfield, CFO" <m.whitfield@solvix.com>) is completely free text. It doesn't need to match the email address next to it, doesn't need to match any domain, and isn't checked by SPF, DKIM, or DMARC at all, since none of them look at display names. An attacker can set the display name to any real executive's name while using an email address at any domain they control; on a mobile device, where many clients show ONLY the display name and hide the actual address unless you tap to expand it, this attack alone is often enough.\n\n` +
        `**Why this matters for triage**\n\n` +
        `The field most recipients look at (the displayed sender name, sometimes the displayed From address) is the field with the LEAST protocol-level verification behind it. A message can have a header From that says anything at all, and pass SPF, and still be entirely fraudulent. This is exactly why DMARC (Reading 6) was created specifically to require the envelope domain and header domain to actually **align**, closing this gap when properly enforced, and exactly why an analyst reading raw headers always checks BOTH the envelope sender (Return-Path) AND the header From, and compares them, rather than trusting either alone.`,
      codeExample:
        "WHAT EACH FIELD ACTUALLY PROTECTS AGAINST\n" +
        "=======================================================\n" +
        "Field              Checked by      What it verifies\n" +
        "-------------------------------------------------------\n" +
        "Envelope/MAIL FROM SPF             Is the connecting IP\n" +
        "(Return-Path)                      authorized to send for\n" +
        "                                   THIS domain?\n" +
        "\n" +
        "Header From        DMARC alignment Does the domain shown\n" +
        "                   (NOT SPF/DKIM   to the recipient match\n" +
        "                   directly)       what SPF/DKIM actually\n" +
        "                                   verified?\n" +
        "\n" +
        "Display name       NOTHING         Free text, unchecked\n" +
        "(\"Marcus Whitfield,                by any authentication\n" +
        " CFO\")                             mechanism whatsoever\n" +
        "=======================================================\n\n" +
        "A MESSAGE CAN LOOK LIKE THIS AND STILL PASS SPF CLEANLY\n" +
        "=======================================================\n" +
        "MAIL FROM: <bounce-8841@sv-notify-relay.net>   <- SPF checks this\n" +
        "From: \"Marcus Whitfield, CFO\" <m.whitfield@solvix.com>  <- recipient sees this\n" +
        "=======================================================",
    },

    // ── Reading 3: reading the Received chain ─────────────────────────────────
    {
      type: "reading" as const,
      id: "email-r3",
      heading: "Reading the Full Received-Header Chain: Bottom to Top Is Chronological",
      content:
        `Every mail server a message passes through: the originating server, any relay/forwarding hop, and finally your own organization's inbound mail gateway. Prepends its own **Received:** header to the top of the message, on its way through. This means the message accumulates a stack of Received headers, one per hop, and critically: **the header physically at the bottom of the stack was added FIRST (closest to the true origin), and each one above it was added later, by a server closer to you.** Reading the chain in the correct order, bottom to top, is what lets you reconstruct the actual path a message took.\n\n` +
        `**Anatomy of a single Received header**\n\n` +
        `Each Received header typically records: the hostname the CONNECTING server claimed via its HELO/EHLO ("from sv-notify-relay.net"), the actual reverse-DNS-resolved hostname and/or raw IP address the connection genuinely came from, in parentheses or brackets ("(unknown [154.16.88.201])". Note "unknown" here means reverse DNS lookup FAILED, itself often a minor red flag since most legitimate mail infrastructure has a working PTR record), which server received it ("by mx1.solvix.com"), the protocol used ("with ESMTPS"), an internal message ID, the specific recipient this hop processed ("for <k.osei@solvix.com>"), and a timestamp.\n\n` +
        `**What to look for when reading the chain**\n\n` +
        `- **The earliest (bottom-most) hop is the one that matters most**: this is closest to the message's true origin, before your own organization's infrastructure got involved. Everything above your own gateway's own added header is infrastructure you control and can trust; everything below it is what you're actually investigating.\n` +
        `- **HELO/EHLO claimed hostname vs. the actual connecting IP's reverse DNS.** A mismatch (the server claims to be "mail.solvix.com" but connects from an IP whose reverse DNS resolves to something completely unrelated, or fails to resolve at all) is a classic forgery indicator. Legitimate mail infrastructure is generally configured so these two facts agree.\n` +
        `- **Timestamp consistency and gaps.** Each hop's timestamp should be equal to or (very slightly) later than the hop below it, in a tight sequence consistent with normal server-to-server relay speed (seconds, not hours). A large, unexplained gap between two adjacent hops, or timestamps that run backwards, suggests either a header was fabricated/inserted, or the message sat somewhere unusual (a queue, a hold, a scanning sandbox) worth understanding.\n` +
        `- **An unexpectedly short chain.** A message that claims to have originated from a large, well-known provider's infrastructure but shows only one or two Received headers total (far fewer hops than that provider's real infrastructure typically produces) can indicate a forged, manually-inserted "fake earliest hop" designed to make the message look like it originated somewhere more trustworthy than it actually did.\n\n` +
        `**Why attackers can't simply forge every part of this chain undetected**\n\n` +
        `An attacker fully controls what they write into the message body and even most header CONTENT during their own SMTP DATA transmission, but they do NOT control what YOUR OWN receiving mail server independently observes and writes into the header IT adds (the true connecting IP address, verified via the TCP connection itself, not anything the client claimed). This is why the header added by your own organization's gateway, typically the topmost one, is the single most trustworthy hop in the entire chain: it reflects what your infrastructure actually, independently observed, not anything an attacker was able to claim.`,
      codeExample:
        "READING A RECEIVED CHAIN -- BOTTOM TO TOP = CHRONOLOGICAL\n" +
        "=======================================================\n" +
        "[TOP, added LAST -- by YOUR OWN infrastructure, most trusted]\n" +
        "Received: from sv-notify-relay.net (unknown [154.16.88.201])\n" +
        "          by mx1.solvix.com with ESMTPS id 8841c2f0\n" +
        "          for <k.osei@solvix.com>; Tue, 02 Jun 2026 13:41:05 +0000\n" +
        "\n" +
        "[BOTTOM, added FIRST -- closest to true origin]\n" +
        "Received: from mail-relay-09.sv-notify-relay.net\n" +
        "          (mail-relay-09.sv-notify-relay.net [154.16.88.201])\n" +
        "          by sv-notify-relay.net with ESMTP id 44a2;\n" +
        "          Tue, 02 Jun 2026 13:41:02 +0000\n" +
        "=======================================================\n" +
        "Read order: BOTTOM header first (13:41:02, true origin)\n" +
        "            then TOP header (13:41:05, your own gateway)\n" +
        "            3-second gap -- normal relay speed\n" +
        "=======================================================\n\n" +
        "RED FLAGS WITHIN A SINGLE Received HEADER\n" +
        "=======================================================\n" +
        "\"(unknown [IP])\"        Reverse DNS lookup FAILED for\n" +
        "                        the connecting IP -- most\n" +
        "                        legitimate mail infra has a\n" +
        "                        working PTR record\n" +
        "HELO hostname vs.        Claimed hostname doesn't match\n" +
        "  reverse-DNS mismatch   what the connecting IP actually\n" +
        "                        resolves to\n" +
        "Unusually short chain    Fewer hops than the claimed\n" +
        "                        origin's real infrastructure\n" +
        "                        would normally produce\n" +
        "=======================================================",
      checkpoint: {
        question:
          "In this reading's two-hop example, which Received header records the EARLIEST hop of the message's journey?",
        options: [
          "The top one (by mx1.solvix.com), since servers append headers in arrival order",
          "The bottom one (by sv-notify-relay.net), since each server prepends its header",
          "The top one, since the first server to handle a message writes the first line",
          "The one whose HELO name matches the From domain, since that is the sender",
        ],
        answer: 1,
        explanation:
          "Each server PREPENDS its Received header, so the bottom header (by sv-notify-relay.net, 13:41:02) was written first and the top one (by mx1.solvix.com, 13:41:05) last. Both “top” options assume headers are appended or that the first writer goes on top: the reverse of how the stack grows; the timestamps confirm it. “The HELO name that matches the From domain” trusts a claim the sender controls: neither hop here even mentions solvix.com as a sender, and HELO names are unverified.",
      },
    },

    // ── Reading 4: SPF mechanics ────────────────────────────────────────────
    {
      type: "reading" as const,
      id: "email-r4",
      heading: "SPF Mechanics in Depth: Qualifiers, the 10-Lookup Limit, and Why SPF Can Pass on a Phish",
      content:
        `**What SPF actually checks, precisely**\n\n` +
        `SPF (Sender Policy Framework) answers exactly one narrow question: "is the IP address that just connected to my mail server authorized, according to a DNS TXT record published by the ENVELOPE SENDER'S domain, to send mail claiming that envelope sender?" As established in Reading 2, this is the MAIL FROM/Return-Path domain, not the header From domain a recipient sees.\n\n` +
        `**Anatomy of an SPF record and its qualifiers**\n\n` +
        `A domain publishes SPF as a DNS TXT record listing authorized sources, each prefixed with a qualifier: **+** (Pass, the default if no qualifier is written), **-** (Fail, hard fail (reject/strongly distrust anything not matching), **~** (SoftFail) mark as suspicious/accept-but-flag rather than reject outright, commonly used while an organization is still rolling out or testing its SPF policy), and **?** (Neutral. Explicitly no assertion either way). The record ends with an "all" mechanism carrying one of these qualifiers, determining what happens to anything not explicitly matched by an earlier mechanism: v=spf1 ... -all is a strict, fully-enforced policy; v=spf1 ... ~all is a much softer, transitional one.\n\n` +
        `**The 10-DNS-lookup limit, and why it matters operationally**\n\n` +
        `SPF evaluation is capped at 10 DNS lookups per check (each "include:", "a", "mx", "ptr", or "exists" mechanism typically costs one lookup, and nested includes count against the same total budget). Exceeding this limit causes SPF to return a **PermError** (permanent error). Treated by most receivers as equivalent to a fail, REGARDLESS of whether the actual sending IP was legitimately authorized. This is a genuinely common, self-inflicted operational problem: organizations that accumulate too many third-party mail-sending vendors (marketing platforms, CRM tools, support ticketing systems), each requiring their own "include:" mechanism, can silently break their own domain's legitimate mail delivery by exceeding this limit. Worth knowing so you don't mistake a PermError for evidence of an attack when it might just be SPF record sprawl.\n\n` +
        `**Why SPF passing does NOT mean the message is legitimate: the core lesson of this reading**\n\n` +
        `SPF validates a domain's INFRASTRUCTURE authorization, not the message's trustworthiness or the identity a human reader sees. An attacker who registers their own domain (freshly, an hour before sending) and correctly publishes a valid SPF record for their own sending infrastructure will pass SPF perfectly. SPF has no concept of "is this domain reputable" or "is this domain trying to impersonate someone else" built into it at all. SPF passing only ever proves: this specific IP was authorized by this specific envelope domain's own DNS record, full stop. This is precisely why the DMARC-passing phishing example later in this room is possible, and why "SPF: Pass" in a header should never, by itself, be read by an analyst as "this email is safe."`,
      codeExample:
        "SPF RECORD ANATOMY\n" +
        "=======================================================\n" +
        "v=spf1 include:_spf.google.com include:mail.solvix.com\n" +
        "       ip4:203.0.113.42 ~all\n" +
        "\n" +
        "  v=spf1              Version marker\n" +
        "  include:X           Trust whatever X's own SPF record\n" +
        "                      authorizes (1 DNS lookup each)\n" +
        "  ip4:203.0.113.42    Explicitly trust this IP\n" +
        "  ~all                SoftFail for anything else (not a\n" +
        "                      hard reject)\n" +
        "=======================================================\n\n" +
        "SPF QUALIFIERS\n" +
        "=======================================================\n" +
        "+  Pass       (default if unspecified)\n" +
        "-  Fail        Hard fail -- reject/strongly distrust\n" +
        "~  SoftFail    Accept but flag as suspicious\n" +
        "?  Neutral     No assertion either way\n" +
        "=======================================================\n\n" +
        "WHAT \"SPF: PASS\" ACTUALLY PROVES -- AND DOESN'T\n" +
        "=======================================================\n" +
        "PROVES:      This IP is authorized by THIS envelope\n" +
        "             domain's own DNS record\n" +
        "DOES NOT     Whether that domain is reputable\n" +
        "PROVE:       Whether the header From matches this domain\n" +
        "             Whether the message content is legitimate\n" +
        "=======================================================",
      checkpoint: {
        question:
          "Solvix adds two more marketing vendors to its SPF record with include: mechanisms, pushing evaluation to 12 DNS lookups. Mail sent from its own authorized servers starts failing. What SPF result are receivers recording?",
        options: [
          "SoftFail: the receiver falls back to the record's ~all qualifier",
          "PermError, which most receivers treat like a fail, even for an authorized IP",
          "TempError: the receiver defers the message and retries the lookups later",
          "Neutral: evaluation stops at the tenth lookup with no assertion either way",
        ],
        answer: 1,
        explanation:
          "Exceeding the 10-lookup cap returns a PermError, which most receivers treat as a fail even when the sending IP is genuinely authorized: the self-inflicted vendor-sprawl problem the reading describes, and a reason not to read every SPF failure as an attack. “SoftFail via ~all” would apply to an IP that evaluation completed and found unlisted, not to a record that could not be evaluated. “TempError” describes a transient DNS problem worth retrying, but an over-limit record fails the same way on every retry. “Neutral” is the result of an explicit ?all, not of a broken record.",
      },
    },

    // ── Reading 5: DKIM mechanics ───────────────────────────────────────────
    {
      type: "reading" as const,
      id: "email-r5",
      heading: "DKIM Mechanics: Signature Fields, Canonicalization, and Why Forwarding Can Break It",
      content:
        `**What DKIM proves that SPF doesn't**\n\n` +
        `DKIM (DomainKeys Identified Mail) answers a completely different question than SPF: not "was this connection authorized," but "was this specific message cryptographically signed by the claimed domain, and has it been altered since signing?" The sending domain generates a public/private key pair, publishes the PUBLIC key in DNS at a specific subdomain, and signs each outgoing message with the PRIVATE key, adding a **DKIM-Signature** header to prove it.\n\n` +
        `**The DKIM-Signature header, field by field**\n\n` +
        `- **v**: DKIM version.\n` +
        `- **a**: the signing algorithm (e.g. rsa-sha256).\n` +
        `- **d**, the **signing domain**, this is the domain actually asserting "I signed this," and it's the field DMARC alignment checks against the header From domain (covered next reading).\n` +
        `- **s**: the **selector**, a short string identifying WHICH public key (of potentially several a domain publishes over time, for key rotation) was used, combined with d= to build the DNS lookup path (selector._domainkey.signingdomain) where the receiving server fetches the actual public key.\n` +
        `- **c**: **canonicalization**, specified separately for headers and body (e.g. "relaxed/relaxed"). Canonicalization defines how much minor formatting variation (whitespace changes, line-ending differences) is tolerated before the signature is considered broken. "Simple" canonicalization tolerates almost no change at all; "relaxed" tolerates common, harmless reformatting.\n` +
        `- **h**: the list of header fields that were included in the signature (Subject, From, Date, To, and others. Importantly, headers NOT listed here can be added, removed, or modified after signing without breaking the signature, which is itself worth knowing when evaluating how strong a given DKIM signature actually is).\n` +
        `- **bh**, the **body hash**: a hash of the message body at signing time, allowing the receiver to detect if the body was altered afterward.\n` +
        `- **b**: the actual cryptographic **signature** value itself.\n\n` +
        `**Verification, step by step**\n\n` +
        `The receiving server reads d= and s=, fetches the corresponding public key from DNS, recomputes the hash of the (canonicalized) headers listed in h= and the body, and checks that against the b= signature and bh= body hash using the fetched public key. If everything matches, DKIM passes and the receiver knows with cryptographic confidence: this exact message content was signed by someone holding the private key for domain d=, and it wasn't altered since.\n\n` +
        `**Why forwarding and mailing lists legitimately break DKIM: an operational nuance, not necessarily an attack**\n\n` +
        `Mailing lists and some forwarding services often modify a message in transit, prepending "[list-name]" to the Subject line, adding a footer to the body, or rewriting headers. Any of which, if that field is covered by h= or the body hash bh=, invalidates the original signature. This is a completely ordinary, expected side effect of legitimate forwarding infrastructure, NOT evidence of tampering by a malicious party, which is exactly the operational headache that led to the ARC mechanism covered in the next reading, and exactly why "DKIM: fail" alone, without further context, should prompt investigation rather than an automatic malicious verdict.`,
      codeExample:
        "DKIM-Signature HEADER -- FIELD BY FIELD\n" +
        "=======================================================\n" +
        "DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;\n" +
        "  d=solvix.com; s=selector1;\n" +
        "  h=From:To:Subject:Date;\n" +
        "  bh=47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=;\n" +
        "  b=Kx8f2Qz...longBase64Signature...==\n" +
        "\n" +
        "  v   Version\n" +
        "  a   Signing algorithm\n" +
        "  d   SIGNING DOMAIN (what DMARC alignment checks)\n" +
        "  s   Selector -- which key, combined with d= to build:\n" +
        "      selector1._domainkey.solvix.com (DNS lookup path)\n" +
        "  h   Which headers are covered by the signature\n" +
        "  bh  Hash of the message body\n" +
        "  b   The actual signature value\n" +
        "=======================================================\n\n" +
        "WHY MAILING-LIST FORWARDING BREAKS DKIM (NOT MALICIOUS)\n" +
        "=======================================================\n" +
        "Original body hashed  ->  bh=47DEQpj8...\n" +
        "List adds a footer    ->  body no longer matches bh=\n" +
        "Receiver recomputes    ->  hash mismatch -> DKIM: fail\n" +
        "  This is expected, ordinary forwarding behavior --\n" +
        "  not evidence of an attacker altering the message\n" +
        "=======================================================",
    },

    // ── Reading 6: DMARC alignment + ARC ────────────────────────────────────
    {
      type: "reading" as const,
      id: "email-r6",
      heading: "DMARC Alignment, Policy Enforcement, and ARC",
      content:
        `**DMARC's actual job: forcing SPF/DKIM to relate to the header From**\n\n` +
        `Recall Reading 4's core lesson: SPF validates the envelope domain, and Reading 5's DKIM validates whatever domain signed the message (d=). Neither one, by itself, says anything about the header From domain a human actually sees. **DMARC (Domain-based Message Authentication, Reporting, and Conformance)** exists specifically to close that gap by requiring **alignment**: the domain that passed SPF (or DKIM) must actually MATCH (be the same as, or in "relaxed" mode a subdomain/parent of) the domain in the header From. A domain publishes its DMARC policy as a DNS TXT record at _dmarc.domain.com, specifying p= (the policy: none = monitor only and take no enforcement action, quarantine = treat failing mail as likely spam, reject = refuse it outright), and optionally pct= (what percentage of failing mail the policy applies to, useful for a gradual rollout). In a receiver's Authentication-Results header the dmarc= verdict can carry both the published policy and dis=, the disposition the receiver actually applied to this message. Receivers may override the published policy with local rules, so "dmarc=fail (p=reject dis=none)" means the domain asked for rejection but the message was delivered anyway.\n\n` +
        `**Strict vs. relaxed alignment**\n\n` +
        `DMARC alignment can be configured strict (the domains must match EXACTLY, character for character) or relaxed (the default, and far more common: mail.solvix.com in the envelope or DKIM d= aligns fine with solvix.com in the header From, since they share the same organizational root domain). Relaxed alignment is practical for organizations running mail through multiple subdomains, but it does mean DMARC's protection is scoped to the organizational domain, not to an exact hostname match.\n\n` +
        `**DMARC only needs ONE of SPF or DKIM to pass AND align. This is the mechanism behind the "DMARC passes on a phish" scenario**\n\n` +
        `DMARC evaluates as passing if EITHER SPF passes and aligns with the header From domain, OR DKIM passes and aligns with the header From domain (it doesn't require both). This is where the critical, easy-to-miss lesson of this entire room lands: **DMARC alignment only checks whether the domains MATCH each other. It has no concept of whether that domain is a legitimate brand, a lookalike, or a brand-new registration.** An attacker who registers solvix-payr0ll.com (a lookalike domain, note the zero substituted for the letter O), and correctly, properly configures SPF, DKIM, and even DMARC for THEIR OWN domain, will have every one of those checks pass cleanly and align perfectly, because the header From domain (solvix-payr0ll.com) genuinely does match the SPF/DKIM-validated domain (also solvix-payr0ll.com, since the attacker owns and correctly configured both). DMARC was never designed to, and cannot, verify that a domain isn't impersonating a similar-looking brand. That's an entirely separate problem (domain reputation, age, visual similarity/lookalike detection) that DMARC alignment simply does not address.\n\n` +
        `**ARC: preserving authentication results through legitimate forwarding**\n\n` +
        `**ARC (Authenticated Received Chain)** was built specifically to solve the mailing-list/forwarding problem from Reading 5: when a message passes through an intermediary (a mailing list, a forwarding service) that legitimately breaks the original DKIM signature or changes the envelope in a way that would break SPF, that intermediary can add ARC headers (**ARC-Seal**, **ARC-Message-Signature**, and **ARC-Authentication-Results**) that cryptographically preserve a record of what the authentication results WERE at the point the intermediary received the message, before its own modifications. A receiving server that trusts the intermediary can then take the ARC-preserved results into account, rather than unfairly failing a message purely because of expected, legitimate forwarding-related changes. This is exactly what lets Google Groups, many corporate mailing lists, and similar forwarding services keep DMARC-protected mail working reliably even though they modify messages in transit.`,
      codeExample:
        "Authentication-Results HEADER (WHAT THE RECEIVER CONCLUDED)\n" +
        "=======================================================\n" +
        "Authentication-Results: mx1.solvix.com;\n" +
        "  spf=pass smtp.mailfrom=solvix-payr0ll.com;\n" +
        "  dkim=pass header.d=solvix-payr0ll.com;\n" +
        "  dmarc=pass (p=quarantine) header.from=solvix-payr0ll.com\n" +
        "\n" +
        "  -- Every check passes AND aligns, because the attacker\n" +
        "     legitimately owns and correctly configured\n" +
        "     solvix-payr0ll.com. DMARC has no way to know this\n" +
        "     domain is impersonating \"solvix.com\" -- that's a\n" +
        "     lookalike-domain problem, not an alignment problem.\n" +
        "=======================================================\n\n" +
        "DMARC POLICY (_dmarc.solvix.com TXT RECORD)\n" +
        "=======================================================\n" +
        "v=DMARC1; p=reject; pct=100; rua=mailto:dmarc-rpt@solvix.com\n" +
        "  p=reject    Enforcement: refuse mail that fails alignment\n" +
        "  pct=100     Apply to 100% of failing mail\n" +
        "  rua=        Where aggregate pass/fail reports get sent\n" +
        "=======================================================\n\n" +
        "ARC HEADERS -- PRESERVING RESULTS THROUGH FORWARDING\n" +
        "=======================================================\n" +
        "ARC-Seal: i=1; a=rsa-sha256; d=list.example.com; ...\n" +
        "ARC-Message-Signature: i=1; a=rsa-sha256; ...\n" +
        "ARC-Authentication-Results: i=1; mx.list.example.com;\n" +
        "  spf=pass; dkim=pass; dmarc=pass\n" +
        "  -- records what authentication looked like BEFORE the\n" +
        "     forwarding intermediary's own modifications\n" +
        "=======================================================",
      checkpoint: {
        question:
          "A message has header From solvix.com. SPF passes for the envelope domain mail.solvix.com, and DKIM fails. solvix.com uses the default alignment mode. What does DMARC return?",
        options: [
          "Fail: the envelope domain is not identical to the header From domain",
          "Pass: mail.solvix.com shares the organizational domain, so SPF aligns",
          "Fail: DMARC needs DKIM to pass and align, and DKIM failed on this message",
          "Pass: SPF passed, and DMARC accepts any SPF pass whatever its domain",
        ],
        answer: 1,
        explanation:
          "The default is relaxed alignment, under which mail.solvix.com aligns with solvix.com because they share the organizational domain; one aligned pass (here SPF) is enough. “Not identical” applies strict alignment, which is not the default. “Needs DKIM” misstates the rule: DMARC requires SPF OR DKIM to pass and align, not both. “Any SPF pass whatever its domain” drops the alignment requirement that is the whole point of DMARC: an SPF pass for an unrelated envelope domain would not count.",
      },
    },

    // ── Question 1 ────────────────────────────────────────────────────────
    {
      type: "question" as const,
      id: "email-q1",
      question:
        "An email's Return-Path shows bounce@random-marketing-relay.net while the header From shows billing@solvix.com. What does this mismatch, by itself, tell an analyst?",
      options: [
        "It confirms spoofing: a genuine solvix.com message would carry a solvix.com Return-Path",
        "The two senders differ, so SPF says nothing about solvix.com; DMARC alignment is the next check",
        "It is benign, marketing relays send on a domain's behalf, so the mismatch can be closed as normal",
        "It shows the message came through a mailing list, which rewrites the Return-Path when forwarding",
      ],
      answer: 1,
      explanation:
        "Envelope sender and header From are independent fields (Reading 2), so the mismatch alone proves nothing either way, but it means an SPF result, which validates only the envelope domain, says nothing about solvix.com. DMARC alignment is the check built for exactly this relationship. “It confirms spoofing” and “It is benign” both jump to a verdict from one field: legitimate email service providers do send with their own envelope domain, yet attackers use the same gap. “It shows a mailing list” picks one possible cause with no evidence for it in the headers given.",
      xp: 25,
    },

    // ── Question 2 ────────────────────────────────────────────────────────
    {
      type: "question" as const,
      id: "email-q2",
      question:
        "A message from billing@solvix.com arrives with “spf=pass smtp.mailfrom=solvix.com; dkim=fail header.d=solvix.com; dmarc=pass”. What is the most reasonable initial interpretation?",
      options: [
        "Contradictory: a failed DKIM signature vetoes DMARC, so this header was altered or misreported",
        "Explainable: aligned SPF alone satisfies DMARC; something in the path likely modified the message",
        "Tampering: a failed DKIM signature proves the content was deliberately changed after signing",
        "An engine error: the gateway must have skipped DKIM, so its DMARC verdict reflects SPF only",
      ],
      answer: 1,
      explanation:
        "DMARC passes when EITHER SPF or DKIM passes and aligns (Reading 6); here SPF passed for solvix.com, which aligns with the From domain. DKIM failures are often benign: a gateway footer, disclaimer or list tag added in transit breaks the body hash or a signed header (Reading 5), so this pattern is explainable, though you still weigh the other signals. “A failed DKIM signature vetoes DMARC” misstates the either/or rule. “Proves deliberate tampering” over-reads a DKIM fail, which records that something changed, not that someone malicious changed it. “The engine skipped DKIM” contradicts the header itself, which reports an evaluated dkim=fail.",
      xp: 25,
    },

    // ── Question 3 ────────────────────────────────────────────────────────
    {
      type: "question" as const,
      id: "email-q3",
      question:
        "You are reading a Received-header chain with three hops. Which header in the chain should you generally trust the MOST regarding the true, verified connecting IP address, and why?",
      options: [
        "The bottom-most header: it is added first, before the sender can influence anything, so the originating hop is accurate",
        "The header marked ESMTPS: the encrypted session means the source IP was authenticated against a trusted certificate",
        "The header added by your own mail infrastructure (typically the topmost). It records the TCP connection your server actually received",
        "The header from the largest relay in the chain. Big providers stamp the connecting IP from their own logs",
      ],
      answer: 2,
      explanation:
        "“The bottom-most header” is closest to the origin, but it is written by infrastructure the sender may control, so it can be fabricated. “The ESMTPS header” confuses transport encryption with sender authentication. TLS does not verify who the connecting party is. “The largest relay” trusts a header you did not write; a forger can claim any provider's name in it. " +
        "As covered in Reading 3, an attacker can claim anything they want in the parts of the message they control (the DATA content, and, on infrastructure THEY operate, the Received headers their own servers add), but they have no ability to alter what your own organization's mail gateway independently records about the connection it directly observed. This is exactly why the header your own infrastructure adds is the single most trustworthy hop, and why chains can otherwise be partially or fully fabricated on infrastructure the sender controls.",
      xp: 25,
    },

    // ── Log Analysis 1: spoofed header investigation ──────────────────────────
    {
      type: "log_analysis" as const,
      id: "email-la1",
      heading: "Investigating a Message Claiming to Be From the CFO",
      context:
        "k.osei is a finance team member who received a message this morning appearing to be from the company's CFO, requesting an urgent wire authorization. Review the raw header fields captured by the mail gateway below.",
      event: spoofedHeaderEvent,
      questions: [
        {
          question:
            "header.from shows 'm.whitfield@solvix.com' but header.return_path shows 'bounce-8841@sv-notify-relay.net', and header.reply_to shows a completely different third domain, 'outlook-secure-mail.com'. What does having THREE different domains across these three fields indicate?",
          options: [
            "Normal bulk-sender behaviour: an ESP's bounce domain differs from From, so this can be closed",
            "Replies would leave Solvix for an unrelated domain while SPF checked a third: a spoofing pattern",
            "A forwarding artefact: a relay on the path rewrote Reply-To while passing the message along",
            "The sender is verified: the Return-Path domain passed SPF, whatever the Reply-To field says",
          ],
          answer: 1,
          explanation:
            "From (solvix.com, what k.osei sees), Return-Path (sv-notify-relay.net, what SPF checks) and Reply-To (outlook-secure-mail.com, where a reply would go) are three unrelated domains: a reply to “the CFO” would leave Solvix entirely. “Normal bulk-sender behaviour” explains a differing Return-Path, but not a Reply-To at a third unrelated domain on an internal wire request. “A forwarding artefact” has no support: nothing in the Received chain shows a forwarding service, and forwarders do not normally rewrite Reply-To. “The Return-Path passed SPF” misreads the record: Authentication-Results shows spf=fail, and even a pass would say nothing about solvix.com.",
          xp: 25,
        },
        {
          question:
            "header.authentication_results shows 'spf=fail ... dkim=none ... dmarc=fail (p=reject dis=none) header.from=solvix.com'. Given that solvix.com's own DMARC policy is p=reject, why did this message still reach k.osei's inbox instead of being blocked outright?",
          options: [
            "The gateway applied dis=none instead of the published reject: a gap in local enforcement",
            "solvix.com's pct= setting exempted this message from the reject policy, so it was delivered",
            "With dkim=none, DMARC could not be evaluated, so no policy was applied to the message",
            "p=reject belongs to the envelope domain, sv-notify-relay.net, which publishes no DMARC policy",
          ],
          answer: 0,
          explanation:
            "dis= records the disposition the receiver actually applied (Reading 6): p=reject with dis=none means solvix.com asked for rejection but mx1.solvix.com delivered the message anyway, an enforcement gap to escalate to whoever runs the gateway. “pct= exempted it” is ruled out by solvix.com's own record in Reading 6 (pct=100). “DMARC could not be evaluated” misreads the header: dmarc=fail is a completed evaluation, and DMARC needs only one of SPF or DKIM, not both. “p=reject belongs to the envelope domain” gets DMARC backwards: the policy applied is the header From domain's, which the header itself names (header.from=solvix.com).",
          xp: 30,
        },
        {
          question:
            "Given connecting_ip_reverse_dns shows 'no-ptr-record' and the Received chain shows only two hops both from the same 154.16.88.201 address claiming to be sv-notify-relay.net, what is the appropriate response?",
          options: [
            "Close it: a missing PTR record is a minor DNS issue, and the message has already been delivered",
            "Treat as BEC: purge it from every mailbox, block the IP and domain, warn finance, fix enforcement",
            "Have k.osei reply asking the CFO to confirm the wire request before the SOC decides anything",
            "Delete it from k.osei's mailbox and close: the message was addressed to k.osei alone",
          ],
          answer: 1,
          explanation:
            "Three unrelated sender domains, SPF and DMARC failing against a reject policy, no PTR record, and an urgent wire request from “the CFO” make this a Business Email Compromise (BEC) attempt: remove it from every mailbox, block 154.16.88.201 and sv-notify-relay.net, warn finance about the pretext, and close the dis=none enforcement gap. “A missing PTR is minor” is true in isolation but ignores every other failed check, and delivered mail can still be purged. “Have k.osei reply” sends the reply to outlook-secure-mail.com: straight to the attacker. “Delete it from k.osei's mailbox alone” is the right first action with too narrow a scope: the visible To line does not reveal other or blind-copied recipients (Reading 1), so the gateway must be searched for every copy.",
          xp: 30,
        },
      ],
    },

    // ── Log Analysis 2: DMARC-passing lookalike phish ────────────────────────
    {
      type: "log_analysis" as const,
      id: "email-la2",
      heading: "A Message That Passes SPF, DKIM, AND DMARC, and Is Still a Phish",
      context:
        "a.nakamura received a payroll-themed message asking to update direct deposit details. Unlike the previous investigation, every authentication check on this message technically passed. Review the raw header fields below.",
      event: dmarcPassPhishEvent,
      questions: [
        {
          question:
            "header.authentication_results shows spf=pass, dkim=pass, and dmarc=pass, all aligned to header.from=solvix-payr0ll.com. Given everything you learned in Reading 6, why does a full DMARC pass NOT mean this message is safe?",
          options: [
            "It does mean safe: a DMARC pass shows the From domain belongs to the brand its name suggests",
            "DMARC checks only that the authenticated domain matches From, not that the domain is legitimate",
            "The pass is weak because p=quarantine is a monitoring-only policy that does not validate mail",
            "Relaxed alignment let solvix-payr0ll.com align with solvix.com, so the pass is really solvix.com's",
          ],
          answer: 1,
          explanation:
            "DMARC only checks that the SPF/DKIM-validated domain AGREES with the header From domain (Reading 6). The attacker owns solvix-payr0ll.com (a zero for the letter O) and configured it correctly, so every check passes for the wrong domain. Lookalike detection is a separate capability. “Belongs to the brand its name suggests” is exactly the trust DMARC cannot give. “p=quarantine is monitoring-only” confuses it with p=none; and the published policy affects what happens to FAILING mail, not whether a pass is meaningful. “Relaxed alignment let it align with solvix.com” misreads relaxed mode: it accepts subdomains of the same organizational domain, and solvix-payr0ll.com is a different organizational domain, the pass here is for solvix-payr0ll.com itself.",
          xp: 25,
        },
        {
          question:
            "domain_first_seen_days_ago shows 2, and domain_registrar shows 'NiceNIC'. Since none of this appears in the Authentication-Results header at all, why does it matter to the investigation?",
          options: [
            "It adds little: registration data sits outside the authentication results the verdict rests on",
            "A 2-day-old domain imitating an internal brand is a phishing sign that DMARC structurally cannot see",
            "The registrar alone settles it: a domain from a budget registrar is malicious whatever its age",
            "It matters only when authentication fails; once every check passes, domain age changes nothing",
          ],
          answer: 1,
          explanation:
            "Domain age catches what DMARC cannot (Reading 6's closing point: lookalike and reputation checks are a separate capability): a domain first seen 2 days ago, imitating “Solvix Payroll” and asking for direct-deposit changes, is a purpose-built phishing sign that the passing authentication results never warned about. “It adds little” treats authentication as the whole verdict: the exact blind spot this task exists to show. “The registrar alone settles it” over-reads one weak signal; registrar reputation supports a verdict but cannot make it alone. “It matters only when authentication fails” has it backwards: a full pass is precisely when non-authentication signals like age carry the case.",
          xp: 25,
        },
        {
          question:
            "What is the correct response, given that this message technically passes every standard authentication check?",
          options: [
            "Release it: a full SPF/DKIM/DMARC pass is the strongest legitimacy signal email can carry",
            "Quarantine it, block the lookalike domain, warn payroll staff, and add domain-age/lookalike checks",
            "Reply to the sender asking them to confirm their identity before acting on the deposit request",
            "Block this sender address only and close: the domain passed every authentication check",
          ],
          answer: 1,
          explanation:
            "Passing authentication is necessary but not sufficient: a freshly registered lookalike domain plus a pretext built to redirect salary payments is phishing. Contain it (quarantine, block the domain), warn the targeted staff, and close the filtering gap with domain-age/lookalike detection. “Release it” treats the pass as proof of legitimacy, the exact error this task teaches. “Reply to the sender” sends the question to the attacker's own mailbox at solvix-payr0ll.com. “Block this sender address only” is too narrow: the attacker owns the whole domain and can send from any other address on it.",
          xp: 30,
        },
      ],
    },

    // ── Analyst Choice: legitimate mailing-list DKIM-fail forward FP trap ────
    {
      type: "analyst_choice" as const,
      id: "email-ac1",
      heading: "Verdict: A DKIM Failure on Mail to the Engineering Team",
      scenario:
        "A detection rule flagged a message delivered to several engineering staff because its DKIM signature failed validation at mx1.solvix.com. Review the headers below (including the Subject, the list identifier and any ARC results) and the verification note, then decide.",
      event: {
        id: "evt-email-ac1-001",
        ts: "2026-06-08T09:00:00.000Z",
        source: "email_gateway",
        vendor: "Proofpoint",
        event_type: "email_received",
        severity: "low",
        it_verify_result: "confirmed",
        it_verify_message: "eng-news@solvix.com is the internal engineering newsletter distribution list, active for 3 years. Subject-tag and footer modification is expected list behavior.",
        description:
          "A message from eng-updates@solvix.com, received by several engineering staff, failed DKIM validation at mx1.solvix.com",
        raw: {
          "header.from": "\"Solvix Engineering\" <eng-updates@solvix.com>",
          "header.return_path": "<eng-news-bounces@solvix.com>",
          "header.subject": "[Eng-News] Q3 platform migration timeline",
          "header.authentication_results":
            "mx1.solvix.com; spf=pass smtp.mailfrom=solvix.com; dkim=fail (body hash did not verify) header.d=solvix.com; dmarc=pass (p=reject) header.from=solvix.com",
          "header.arc_authentication_results":
            "i=1; mx-list.solvix.com; spf=pass smtp.mailfrom=solvix.com; dkim=pass header.d=solvix.com; dmarc=pass (p=reject) header.from=solvix.com",
          "envelope.mail_from": "eng-news-bounces@solvix.com",
          list_id: "eng-news.solvix.com",
        },
      },
      correct_verdict: "false_positive",
      explanation:
        "The headers show an ordinary mailing-list modification, the benign DKIM-failure cause from Readings 5 and 6: the list_id (eng-news.solvix.com) and the “[Eng-News]” Subject tag show the message was redistributed by a list, and the failure reason is “body hash did not verify”, the list's added footer changed the signed body. The envelope sender, header From and DMARC alignment are all solvix.com (no lookalike or external domain), DMARC still passes on aligned SPF, the ARC-Authentication-Results written by mx-list.solvix.com record spf=pass, dkim=pass, dmarc=pass before the list's modification, and IT confirms the list has operated for 3 years with this exact tag-and-footer behaviour.",
      fp_trap:
        "'DKIM: fail' can look alarming on its own, especially right after learning how central DKIM is to verifying message integrity, but Reading 5 was explicit that mailing-list and forwarding modifications are a common, benign cause of exactly this failure pattern, and this scenario is a clean example: internal sender, internal list, ARC headers confirming the original message's authentication was clean, and IT-confirmed legitimate list history. Escalating every DKIM failure without checking whether ARC headers explain it, or whether the actual envelope/header domains are internal and legitimate, would generate constant noise from an organization's own routine mailing-list traffic: exactly the kind of false-positive pattern that erodes trust in a detection program.",
      xp: 30,
    },

    // ── Matching: header field <-> what it reveals ────────────────────────────
    {
      type: "matching" as const,
      id: "email-m1",
      heading: "Match Each Email Field to What It Actually Tells an Investigator",
      instructions: "Match each header/protocol field to the correct description of what it reveals during forensic analysis.",
      pairs: [
        { id: "returnpath", left: "Return-Path (envelope sender / MAIL FROM)", right: "Where bounce notifications go, and the exact address SPF validates. Independent of the header From a recipient sees" },
        { id: "receivedchain", left: "Received-header chain", right: "The hop-by-hop server path a message traveled; read bottom-to-top for chronological order, with your own gateway's own added header being the most trustworthy" },
        { id: "dkimd", left: "DKIM-Signature d= field", right: "The domain that actually cryptographically signed the message. What DMARC alignment compares against the header From domain" },
        { id: "authresults", left: "Authentication-Results header", right: "The receiving server's own aggregated verdict on SPF, DKIM, and DMARC for this specific message" },
        { id: "replyto", left: "Reply-To", right: "Where a reply the recipient sends will actually be delivered, often different from both From and Return-Path, and unchecked by SPF/DKIM/DMARC entirely" },
        { id: "arc", left: "ARC-Authentication-Results", right: "A preserved record of what authentication results looked like BEFORE a legitimate forwarding intermediary's own modifications" },
      ],
      explanation:
        "Each of these fields answers a distinct forensic question: Return-Path is what SPF actually checks; the Received chain reconstructs the true path a message took; DKIM's d= field is what DMARC alignment compares against the header From; Authentication-Results is the receiver's own summary verdict; Reply-To reveals where responses actually go (a favorite spoofing vector, since it's checked by nothing); and ARC preserves legitimate pre-forwarding authentication context that would otherwise be lost.",
      xp: 40,
    },

    // ── Ordering: SMTP conversation sequence ────────────────────────────────
    {
      type: "ordering" as const,
      id: "email-o1",
      heading: "Order the Raw SMTP Conversation for Delivering One Message",
      instructions: "Arrange these SMTP steps into the correct order, as they would actually occur on the wire.",
      items: [
        { id: "connect", text: "Sending server opens a TCP connection to the receiving mail server" },
        { id: "ehlo", text: "Sending server issues EHLO, announcing its hostname (unverified at the protocol level)" },
        { id: "starttls", text: "Sending server issues STARTTLS to encrypt the session, then repeats EHLO" },
        { id: "mailfrom", text: "Sending server issues MAIL FROM, declaring the envelope sender" },
        { id: "rcptto", text: "Sending server issues RCPT TO, declaring the recipient" },
        { id: "data", text: "Sending server issues DATA, transmits headers, a blank line and the body, and ends with a lone period" },
        { id: "quit", text: "Sending server issues QUIT, closing the connection" },
      ],
      correct_order: ["connect", "ehlo", "starttls", "mailfrom", "rcptto", "data", "quit"],
      explanation:
        "This is the actual, literal sequence of commands that deliver every email: connect, identify (unverified), upgrade to TLS only after the receiver's EHLO reply has advertised STARTTLS (and identify again inside the encrypted session), declare the envelope sender, declare the recipient, then transmit the full message content (including the header From, which is set here, independently of the earlier MAIL FROM step) before closing. Understanding this order is exactly what makes clear why MAIL FROM and the header From are two structurally separate pieces of data, set at two different points in the conversation, with nothing forcing them to agree.",
      xp: 35,
    },

    // ── Query Fill: KQL against EmailEvents for domain/alignment mismatch ────
    {
      type: "query_fill" as const,
      id: "email-qf1",
      heading: "Write It Yourself: Surface DMARC-Failing Mail Impersonating Internal Domains in KQL",
      language: "kql",
      context: KQL_PRIMER +
        "Note on this table: Defender XDR's EmailEvents has no separate SPF/DKIM/DMARC columns. All the verdicts live in one string column, AuthenticationDetails, holding JSON such as {\"SPF\":\"fail\",\"DKIM\":\"none\",\"DMARC\":\"fail\",\"CompAuth\":\"fail\"}. You unpack it with `extend AD = parse_json(AuthenticationDetails)` and then read each verdict as `tostring(AD.SPF)`, `tostring(AD.DKIM)` and so on (the values are lowercase: pass, fail, none…).\n\n" +
        "Using the pattern from Log Analysis 1 (a message whose header From claims an internal solvix.com identity but fails SPF and DMARC), write the KQL a detection engineer would deploy to catch messages exactly like it.",
      template:
        "EmailEvents\n| where SenderFromDomain =~ \"{{domain}}\"\n| extend AD = parse_json(AuthenticationDetails)\n| where tostring(AD.SPF) =~ \"{{spfresult}}\" or tostring(AD.DMARC) =~ \"{{dmarcresult}}\"\n| where tostring(AD.DKIM) !~ \"{{dkimresult}}\"",
      blanks: [
        { id: "domain", answers: ["solvix.com", "SOLVIX.COM", "Solvix.com"], placeholder: "internal domain being impersonated" },
        { id: "spfresult", answers: ["Fail", "fail", "FAIL"], placeholder: "SPF outcome to flag" },
        { id: "dmarcresult", answers: ["Fail", "fail", "FAIL"], placeholder: "DMARC outcome to flag" },
        { id: "dkimresult", answers: ["Pass", "pass", "PASS"], placeholder: "DKIM outcome that would clear the message" },
      ],
      explanation:
        "This mirrors exactly the case you investigated in Log Analysis 1: filter to messages whose header From claims your own protected internal domain, unpack the AuthenticationDetails JSON column (EmailEvents stores every SPF/DKIM/DMARC/CompAuth verdict there rather than in separate columns), then flag any that failed SPF or DMARC and did NOT independently pass DKIM either. Since a genuine internal message would be expected to pass at least one of SPF or DKIM aligned to that domain. A message claiming to be from solvix.com that fails all three is exactly the spoofing pattern this query is designed to surface for review.",
      xp: 35,
    },

    // ── Flag ──────────────────────────────────────────────────────────────
    {
      type: "flag" as const,
      id: "email-f1",
      prompt:
        "In Log Analysis 1's Received chain, find the EARLIEST hop of the spoofed CFO message. What hostname did the connecting server claim for itself in that hop? Enter the full hostname.",
      answer: "mail-relay-09.sv-notify-relay.net",
      hint: "Work out which Received header was written first, then find the name that comes right after “from” in it: the self-announced name, not the receiving server.",
      xp: 25,
    },
  ],
};

export default [emailRoom];
