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
    "Go past 'check SPF/DKIM/DMARC' into the protocol mechanics behind email spoofing: the raw SMTP conversation itself, why envelope-from and header-From are two entirely different things, how to read a full Received-header chain correctly (bottom to top), the precise alignment and qualifier rules that make SPF, DKIM, and DMARC work — and exactly why DMARC can legitimately pass on a phishing email that a careless analyst would otherwise trust — plus ARC, and a full step-by-step header forensics walkthrough.",
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
        `Every email you've ever received was delivered through a plain-text conversation between two mail servers that looks a lot like a scripted chat — and reading that conversation directly is the fastest way to understand exactly where in the process spoofing becomes possible.\n\n` +
        `**The conversation, command by command**\n\n` +
        `1. **Connect** — the sending server opens a TCP connection to the receiving server's mail exchanger, typically on port 25 (server-to-server) or 587 (authenticated client submission).\n` +
        `2. **EHLO/HELO** — the sending server introduces itself by hostname ("EHLO mail-relay-09.example.com"). Critically: nothing about this step is verified or authenticated at the protocol level — a sending server can claim to be any hostname it wants here, and the receiving server has no built-in way to confirm it's telling the truth.\n` +
        `3. **MAIL FROM** — the sending server declares the **envelope sender** ("MAIL FROM: <bounce@example.com>"). This is the address bounce/non-delivery notifications will be sent to, and, as you'll see in Reading 4, it's the exact address SPF checks — and it is NOT necessarily the same address the recipient will ever see displayed in their inbox.\n` +
        `4. **RCPT TO** — the sending server declares the recipient ("RCPT TO: <k.osei@solvix.com>"). A single message can have multiple RCPT TO commands (for multiple recipients, including blind-copied ones the visible headers won't reveal).\n` +
        `5. **DATA** — the sending server transmits the actual message: all of its headers (From, To, Subject, Date, and dozens of others) followed by a blank line, followed by the message body, terminated by a line containing just a single period.\n` +
        `6. **QUIT** — the connection closes.\n\n` +
        `**The single most important structural fact: two completely separate "from" addresses**\n\n` +
        `Notice that MAIL FROM (step 3, the **envelope sender**, also called the Return-Path once recorded) and the **From:** header (buried inside the DATA block in step 5, the **header sender** — this is what your email client actually displays to you) are two, entirely independent pieces of data, set independently, with nothing in the base SMTP protocol requiring them to match at all. A sending server is free to declare MAIL FROM: <bounce@totally-different-domain.com> and then, inside the message body it transmits during DATA, include a From: header claiming to be anyone at all. This gap — envelope sender vs. header sender — is the single most important structural fact in all of email security, and it's exactly what the rest of this room is built around: SPF checks one of these two addresses, DMARC exists specifically to require them to agree, and a careless reader who only ever looks at the "From" name shown in their inbox is looking at the one field with the least protocol-level verification behind it.`,
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
    },

    // ── Reading 2: envelope vs header From ────────────────────────────────────
    {
      type: "reading" as const,
      id: "email-r2",
      heading: "Envelope-From vs. Header-From: the Core of Email Spoofing",
      content:
        `Building directly on Reading 1's structural gap, this is worth dwelling on because nearly every email authentication concept in this room exists specifically to address it.\n\n` +
        `**Why SPF checks the envelope, not the header**\n\n` +
        `SPF (covered fully in Reading 4) validates whether the CONNECTING SERVER'S IP address is authorized to send mail on behalf of the domain in the **envelope sender** (MAIL FROM / Return-Path) — not the domain in the header From. This was a deliberate original design choice: SPF was built around the bounce-handling infrastructure of SMTP (where do non-delivery reports go), which is inherently tied to the envelope, not the displayed header. The practical consequence: an attacker who owns or controls ANY domain with a valid, passing SPF record — including a domain they registered themselves an hour ago — can set MAIL FROM to that domain and pass SPF cleanly, while their header From still displays whatever name and address they want the recipient to see. **SPF passing tells you nothing whatsoever about the header From domain.**\n\n` +
        `**Display name spoofing: the simplest attack of all**\n\n` +
        `Separate from any of this, the "display name" portion of a From header ("Marcus Whitfield, CFO" in "Marcus Whitfield, CFO" <m.whitfield@solvix.com>) is completely free text — it doesn't need to match the email address next to it, doesn't need to match any domain, and isn't checked by SPF, DKIM, or DMARC at all, since none of them look at display names. An attacker can set the display name to any real executive's name while using an email address at any domain they control; on a mobile device, where many clients show ONLY the display name and hide the actual address unless you tap to expand it, this attack alone is often enough.\n\n` +
        `**Why this matters for triage**\n\n` +
        `The field most recipients look at (the displayed sender name, sometimes the displayed From address) is the field with the LEAST protocol-level verification behind it. A message can have a header From that says anything at all, and pass SPF, and still be entirely fraudulent — this is exactly why DMARC (Reading 6) was created specifically to require the envelope domain and header domain to actually **align**, closing this gap when properly enforced, and exactly why an analyst reading raw headers always checks BOTH the envelope sender (Return-Path) AND the header From, and compares them, rather than trusting either alone.`,
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
      heading: "Reading the Full Received-Header Chain — Bottom to Top Is Chronological",
      content:
        `Every mail server a message passes through — the originating server, any relay/forwarding hop, and finally your own organization's inbound mail gateway — prepends its own **Received:** header to the top of the message, on its way through. This means the message accumulates a stack of Received headers, one per hop, and critically: **the header physically at the bottom of the stack was added FIRST (closest to the true origin), and each one above it was added later, by a server closer to you.** Reading the chain in the correct order — bottom to top — is what lets you reconstruct the actual path a message took.\n\n` +
        `**Anatomy of a single Received header**\n\n` +
        `Each Received header typically records: the hostname the CONNECTING server claimed via its HELO/EHLO ("from sv-notify-relay.net"), the actual reverse-DNS-resolved hostname and/or raw IP address the connection genuinely came from, in parentheses or brackets ("(unknown [154.16.88.201])" — note "unknown" here means reverse DNS lookup FAILED, itself often a minor red flag since most legitimate mail infrastructure has a working PTR record), which server received it ("by mx1.solvix.com"), the protocol used ("with ESMTPS"), an internal message ID, the specific recipient this hop processed ("for <k.osei@solvix.com>"), and a timestamp.\n\n` +
        `**What to look for when reading the chain**\n\n` +
        `- **The earliest (bottom-most) hop is the one that matters most** — this is closest to the message's true origin, before your own organization's infrastructure got involved. Everything above your own gateway's own added header is infrastructure you control and can trust; everything below it is what you're actually investigating.\n` +
        `- **HELO/EHLO claimed hostname vs. the actual connecting IP's reverse DNS.** A mismatch (the server claims to be "mail.solvix.com" but connects from an IP whose reverse DNS resolves to something completely unrelated, or fails to resolve at all) is a classic forgery indicator — legitimate mail infrastructure is generally configured so these two facts agree.\n` +
        `- **Timestamp consistency and gaps.** Each hop's timestamp should be equal to or (very slightly) later than the hop below it, in a tight sequence consistent with normal server-to-server relay speed (seconds, not hours). A large, unexplained gap between two adjacent hops, or timestamps that run backwards, suggests either a header was fabricated/inserted, or the message sat somewhere unusual (a queue, a hold, a scanning sandbox) worth understanding.\n` +
        `- **An unexpectedly short chain.** A message that claims to have originated from a large, well-known provider's infrastructure but shows only one or two Received headers total — far fewer hops than that provider's real infrastructure typically produces — can indicate a forged, manually-inserted "fake earliest hop" designed to make the message look like it originated somewhere more trustworthy than it actually did.\n\n` +
        `**Why attackers can't simply forge every part of this chain undetected**\n\n` +
        `An attacker fully controls what they write into the message body and even most header CONTENT during their own SMTP DATA transmission — but they do NOT control what YOUR OWN receiving mail server independently observes and writes into the header IT adds (the true connecting IP address, verified via the TCP connection itself, not anything the client claimed). This is why the header added by your own organization's gateway — typically the topmost one — is the single most trustworthy hop in the entire chain: it reflects what your infrastructure actually, independently observed, not anything an attacker was able to claim.`,
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
    },

    // ── Reading 4: SPF mechanics ────────────────────────────────────────────
    {
      type: "reading" as const,
      id: "email-r4",
      heading: "SPF Mechanics in Depth: Qualifiers, the 10-Lookup Limit, and Why SPF Can Pass on a Phish",
      content:
        `**What SPF actually checks, precisely**\n\n` +
        `SPF (Sender Policy Framework) answers exactly one narrow question: "is the IP address that just connected to my mail server authorized, according to a DNS TXT record published by the ENVELOPE SENDER'S domain, to send mail claiming that envelope sender?" As established in Reading 2, this is the MAIL FROM/Return-Path domain — not the header From domain a recipient sees.\n\n` +
        `**Anatomy of an SPF record and its qualifiers**\n\n` +
        `A domain publishes SPF as a DNS TXT record listing authorized sources, each prefixed with a qualifier: **+** (Pass, the default if no qualifier is written), **-** (Fail, hard fail — reject/strongly distrust anything not matching), **~** (SoftFail — mark as suspicious/accept-but-flag rather than reject outright, commonly used while an organization is still rolling out or testing its SPF policy), and **?** (Neutral — explicitly no assertion either way). The record ends with an "all" mechanism carrying one of these qualifiers, determining what happens to anything not explicitly matched by an earlier mechanism — v=spf1 ... -all is a strict, fully-enforced policy; v=spf1 ... ~all is a much softer, transitional one.\n\n` +
        `**The 10-DNS-lookup limit — and why it matters operationally**\n\n` +
        `SPF evaluation is capped at 10 DNS lookups per check (each "include:", "a", "mx", "ptr", or "exists" mechanism typically costs one lookup, and nested includes count against the same total budget). Exceeding this limit causes SPF to return a **PermError** (permanent error) — treated by most receivers as equivalent to a fail, REGARDLESS of whether the actual sending IP was legitimately authorized. This is a genuinely common, self-inflicted operational problem: organizations that accumulate too many third-party mail-sending vendors (marketing platforms, CRM tools, support ticketing systems), each requiring their own "include:" mechanism, can silently break their own domain's legitimate mail delivery by exceeding this limit — worth knowing so you don't mistake a PermError for evidence of an attack when it might just be SPF record sprawl.\n\n` +
        `**Why SPF passing does NOT mean the message is legitimate — the core lesson of this reading**\n\n` +
        `SPF validates a domain's INFRASTRUCTURE authorization, not the message's trustworthiness or the identity a human reader sees. An attacker who registers their own domain (freshly, an hour before sending) and correctly publishes a valid SPF record for their own sending infrastructure will pass SPF perfectly — SPF has no concept of "is this domain reputable" or "is this domain trying to impersonate someone else" built into it at all. SPF passing only ever proves: this specific IP was authorized by this specific envelope domain's own DNS record — full stop. This is precisely why the DMARC-passing phishing example later in this room is possible, and why "SPF: Pass" in a header should never, by itself, be read by an analyst as "this email is safe."`,
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
    },

    // ── Reading 5: DKIM mechanics ───────────────────────────────────────────
    {
      type: "reading" as const,
      id: "email-r5",
      heading: "DKIM Mechanics: Signature Fields, Canonicalization, and Why Forwarding Can Break It",
      content:
        `**What DKIM proves that SPF doesn't**\n\n` +
        `DKIM (DomainKeys Identified Mail) answers a completely different question than SPF: not "was this connection authorized," but "was this specific message cryptographically signed by the claimed domain, and has it been altered since signing?" The sending domain generates a public/private key pair, publishes the PUBLIC key in DNS at a specific subdomain, and signs each outgoing message with the PRIVATE key — adding a **DKIM-Signature** header to prove it.\n\n` +
        `**The DKIM-Signature header, field by field**\n\n` +
        `- **v** — DKIM version.\n` +
        `- **a** — the signing algorithm (e.g. rsa-sha256).\n` +
        `- **d** — the **signing domain** — this is the domain actually asserting "I signed this," and it's the field DMARC alignment checks against the header From domain (covered next reading).\n` +
        `- **s** — the **selector**, a short string identifying WHICH public key (of potentially several a domain publishes over time, for key rotation) was used, combined with d= to build the DNS lookup path (selector._domainkey.signingdomain) where the receiving server fetches the actual public key.\n` +
        `- **c** — **canonicalization**, specified separately for headers and body (e.g. "relaxed/relaxed"). Canonicalization defines how much minor formatting variation (whitespace changes, line-ending differences) is tolerated before the signature is considered broken. "Simple" canonicalization tolerates almost no change at all; "relaxed" tolerates common, harmless reformatting.\n` +
        `- **h** — the list of header fields that were included in the signature (Subject, From, Date, To, and others — importantly, headers NOT listed here can be added, removed, or modified after signing without breaking the signature, which is itself worth knowing when evaluating how strong a given DKIM signature actually is).\n` +
        `- **bh** — the **body hash**: a hash of the message body at signing time, allowing the receiver to detect if the body was altered afterward.\n` +
        `- **b** — the actual cryptographic **signature** value itself.\n\n` +
        `**Verification, step by step**\n\n` +
        `The receiving server reads d= and s=, fetches the corresponding public key from DNS, recomputes the hash of the (canonicalized) headers listed in h= and the body, and checks that against the b= signature and bh= body hash using the fetched public key. If everything matches, DKIM passes and the receiver knows with cryptographic confidence: this exact message content was signed by someone holding the private key for domain d=, and it wasn't altered since.\n\n` +
        `**Why forwarding and mailing lists legitimately break DKIM — an operational nuance, not necessarily an attack**\n\n` +
        `Mailing lists and some forwarding services often modify a message in transit — prepending "[list-name]" to the Subject line, adding a footer to the body, or rewriting headers — any of which, if that field is covered by h= or the body hash bh=, invalidates the original signature. This is a completely ordinary, expected side effect of legitimate forwarding infrastructure, NOT evidence of tampering by a malicious party — which is exactly the operational headache that led to the ARC mechanism covered in the next reading, and exactly why "DKIM: fail" alone, without further context, should prompt investigation rather than an automatic malicious verdict.`,
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
        `Recall Reading 4's core lesson: SPF validates the envelope domain, and Reading 5's DKIM validates whatever domain signed the message (d=) — neither one, by itself, says anything about the header From domain a human actually sees. **DMARC (Domain-based Message Authentication, Reporting, and Conformance)** exists specifically to close that gap by requiring **alignment**: the domain that passed SPF (or DKIM) must actually MATCH — be the same as, or in "relaxed" mode a subdomain/parent of — the domain in the header From. A domain publishes its DMARC policy as a DNS TXT record at _dmarc.domain.com, specifying p= (the policy: none = monitor only and take no enforcement action, quarantine = treat failing mail as likely spam, reject = refuse it outright), and optionally pct= (what percentage of failing mail the policy applies to, useful for a gradual rollout).\n\n` +
        `**Strict vs. relaxed alignment**\n\n` +
        `DMARC alignment can be configured strict (the domains must match EXACTLY, character for character) or relaxed (the default, and far more common: mail.solvix.com in the envelope or DKIM d= aligns fine with solvix.com in the header From, since they share the same organizational root domain). Relaxed alignment is practical for organizations running mail through multiple subdomains, but it does mean DMARC's protection is scoped to the organizational domain, not to an exact hostname match.\n\n` +
        `**DMARC only needs ONE of SPF or DKIM to pass AND align — this is the mechanism behind the "DMARC passes on a phish" scenario**\n\n` +
        `DMARC evaluates as passing if EITHER SPF passes and aligns with the header From domain, OR DKIM passes and aligns with the header From domain (it doesn't require both). This is where the critical, easy-to-miss lesson of this entire room lands: **DMARC alignment only checks whether the domains MATCH each other — it has no concept of whether that domain is a legitimate brand, a lookalike, or a brand-new registration.** An attacker who registers solvix-payr0ll.com (a lookalike domain, note the zero substituted for the letter O), and correctly, properly configures SPF, DKIM, and even DMARC for THEIR OWN domain, will have every one of those checks pass cleanly and align perfectly — because the header From domain (solvix-payr0ll.com) genuinely does match the SPF/DKIM-validated domain (also solvix-payr0ll.com, since the attacker owns and correctly configured both). DMARC was never designed to, and cannot, verify that a domain isn't impersonating a similar-looking brand — that's an entirely separate problem (domain reputation, age, visual similarity/lookalike detection) that DMARC alignment simply does not address.\n\n` +
        `**ARC: preserving authentication results through legitimate forwarding**\n\n` +
        `**ARC (Authenticated Received Chain)** was built specifically to solve the mailing-list/forwarding problem from Reading 5: when a message passes through an intermediary (a mailing list, a forwarding service) that legitimately breaks the original DKIM signature or changes the envelope in a way that would break SPF, that intermediary can add ARC headers — **ARC-Seal**, **ARC-Message-Signature**, and **ARC-Authentication-Results** — that cryptographically preserve a record of what the authentication results WERE at the point the intermediary received the message, before its own modifications. A receiving server that trusts the intermediary can then take the ARC-preserved results into account, rather than unfairly failing a message purely because of expected, legitimate forwarding-related changes — this is exactly what lets Google Groups, many corporate mailing lists, and similar forwarding services keep DMARC-protected mail working reliably even though they modify messages in transit.`,
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
    },

    // ── Question 1 ────────────────────────────────────────────────────────
    {
      type: "question" as const,
      id: "email-q1",
      question:
        "An email's Return-Path shows bounce@random-marketing-relay.net while the header From shows billing@solvix.com. What does this mismatch, by itself, tell an analyst?",
      options: [
        "Nothing at all — Return-Path and header From are always identical by protocol design",
        "The envelope sender (what SPF actually checks) and the header sender (what the recipient sees displayed) are different domains — this alone doesn't prove malicious intent (some legitimate bulk-mail/marketing platforms send on a domain's behalf this way), but it means SPF passing for random-marketing-relay.net says nothing about whether billing@solvix.com is legitimate, and DMARC alignment specifically is what needs to be checked next",
            "This proves the message passed both SPF and DKIM successfully",
        "This mismatch can only occur if the message was manually forwarded by the recipient",
      ],
      answer: 1,
      explanation:
        "As established in Reading 2, the envelope sender and header From are structurally independent fields with nothing forcing them to match. A mismatch alone is not automatically proof of an attack (legitimate email service providers routinely send on a domain's behalf using their own envelope infrastructure) — but it means SPF's pass/fail result, which only ever validates the envelope domain, tells you nothing about the header From domain's legitimacy. The next and correct step is checking DMARC alignment specifically, which is the mechanism designed to evaluate exactly this relationship.",
      xp: 25,
    },

    // ── Question 2 ────────────────────────────────────────────────────────
    {
      type: "question" as const,
      id: "email-q2",
      question:
        "A message shows spf=pass, dkim=fail, dmarc=pass in its Authentication-Results header. Given that DMARC only requires ONE of SPF or DKIM to pass and align, and recalling that mailing-list forwarding commonly breaks DKIM specifically, what is the most reasonable initial interpretation?",
      options: [
        "This is impossible — DMARC cannot pass if DKIM fails, under any circumstances",
        "SPF passed and aligned with the header From domain, which alone is sufficient for DMARC to pass even with DKIM failing — this pattern is fully consistent with legitimate mail (including forwarded mail where DKIM broke due to in-transit modification) and should not be treated as inherently suspicious on this basis alone",
        "DKIM failing always indicates the message was sent by an attacker regardless of what SPF or DMARC report",
        "This combination means the message bypassed all authentication checks entirely",
      ],
      answer: 1,
      explanation:
        "DMARC's 'pass if EITHER aligns' design (Reading 6) means SPF alone succeeding and aligning is enough for a DMARC pass verdict, independent of DKIM's outcome. Combined with Reading 5's point that DKIM failures are common and often benign (forwarding, mailing-list modification), spf=pass/dkim=fail/dmarc=pass is a normal, explainable pattern — not, by itself, grounds for suspicion. An analyst should still weigh other signals (Received chain, domain reputation, message content) rather than reading DKIM's failure in isolation as damning.",
      xp: 25,
    },

    // ── Question 3 ────────────────────────────────────────────────────────
    {
      type: "question" as const,
      id: "email-q3",
      question:
        "You are reading a Received-header chain with three hops. Which header in the chain should you generally trust the MOST regarding the true, verified connecting IP address, and why?",
      options: [
        "The bottom-most header, because attackers never bother forging the earliest hop",
        "Whichever header contains the word 'ESMTPS', since that always indicates an encrypted, verified connection",
        "The header your OWN organization's mail infrastructure added (typically the topmost one) — because while an attacker fully controls what they write into headers and content during their own SMTP session, they cannot control what YOUR server independently observed and recorded about the actual TCP connection it received",
        "All headers in the chain are equally trustworthy since Received headers cannot be forged by design",
      ],
      answer: 2,
      explanation:
        "As covered in Reading 3, an attacker can claim anything they want in the parts of the message they control (the DATA content, and, on infrastructure THEY operate, the Received headers their own servers add) — but they have no ability to alter what your own organization's mail gateway independently records about the connection it directly observed. This is exactly why the header your own infrastructure adds is the single most trustworthy hop, and why chains can otherwise be partially or fully fabricated on infrastructure the sender controls.",
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
            "This is completely normal — every legitimate email has three different domains across these fields",
            "The header From domain (what the recipient sees, solvix.com) does not match either the envelope/Return-Path domain (what SPF actually checks) or the Reply-To domain (where any reply the recipient sends would actually go) — this three-way mismatch is a strong structural indicator of spoofing, since a genuine solvix.com message would have no reason to route replies to an unrelated third domain",
            "Reply-To fields are ignored by all modern email clients and have no security relevance",
            "This proves the message passed DKIM validation",
          ],
          answer: 1,
          explanation:
            "As covered in Readings 1 and 2, having the envelope sender differ from the header From is sometimes benign (legitimate bulk senders), but here a THIRD domain also appears in Reply-To — meaning if k.osei had simply hit 'reply' to what looks like a message from the CFO, the response would go to outlook-secure-mail.com, an address with no relationship to Solvix at all. Three unrelated domains across From/Return-Path/Reply-To, especially combined with a header.authentication_results showing spf=fail and dmarc=fail (p=reject), is a strong structural spoofing indicator.",
          xp: 25,
        },
        {
          question:
            "header.authentication_results shows 'spf=fail ... dkim=none ... dmarc=fail (p=reject dis=none) header.from=solvix.com'. Given that solvix.com's own DMARC policy is p=reject, why did this message still reach k.osei's inbox instead of being blocked outright?",
          options: [
            "dis=none in the DMARC result indicates the receiving system logged the failure and the applicable enforcement disposition was 'none' was actually applied for this delivery, rather than the domain's stated reject policy — meaning a gap exists between solvix.com's DMARC policy and what the receiving mail gateway actually enforced, which is itself worth escalating to whoever manages the gateway's DMARC enforcement configuration",
            "A dmarc=fail result always means the message was already deleted before reaching any inbox, so this must be a logging error",
            "spf=fail and dmarc=fail messages are always delivered normally by design, since DMARC is purely advisory and never blocks anything",
            "The message must have been manually forwarded by someone inside Solvix, bypassing all filtering",
          ],
          answer: 0,
          explanation:
            "The dis= (disposition) field in a DMARC authentication result records what enforcement action was actually taken for THIS delivery, which can differ from the domain's published policy for a range of legitimate operational reasons (local override rules, quarantine folder delivery rather than outright rejection, or a receiving-side policy configuration gap). Seeing dis=none alongside an explicit p=reject published policy is worth flagging to whoever administers the mail gateway's enforcement settings — the message reaching an inbox despite a failing DMARC check against a reject policy indicates enforcement isn't fully matching the domain's stated intent.",
          xp: 30,
        },
        {
          question:
            "Given connecting_ip_reverse_dns shows 'no-ptr-record' and the Received chain shows only two hops both from the same 154.16.88.201 address claiming to be sv-notify-relay.net, what is the appropriate response?",
          options: [
            "Deliver the message normally since it already reached the inbox, and take no further action",
            "Treat this as a confirmed spoofing/BEC (Business Email Compromise) attempt: quarantine/remove the message from k.osei's inbox and any other recipients, block the sending infrastructure (154.16.88.201 and sv-notify-relay.net), alert the finance team about the specific wire-authorization pretext being used, and review the mail gateway's DMARC enforcement gap identified above",
            "Reply to the message asking 'is this really you?' to verify the CFO's identity directly",
            "Take no action since the missing PTR record could just mean the sender's DNS provider has a minor configuration issue",
          ],
          answer: 1,
          explanation:
            "The combination of a three-way domain mismatch (From/Return-Path/Reply-To), a failing SPF and DMARC result against a domain with a stated reject policy, a missing reverse-DNS record, and a financially-motivated pretext (urgent wire authorization, impersonating the CFO) is a textbook BEC (Business Email Compromise) / CEO-fraud attempt. The correct response is full containment (remove the message, block the infrastructure), user awareness (alert the targeted team to the specific pretext, since similar messages may be sent to other finance staff), and fixing the underlying enforcement gap so future messages failing DMARC against a reject policy are actually rejected rather than delivered.",
          xp: 30,
        },
      ],
    },

    // ── Log Analysis 2: DMARC-passing lookalike phish ────────────────────────
    {
      type: "log_analysis" as const,
      id: "email-la2",
      heading: "A Message That Passes SPF, DKIM, AND DMARC — and Is Still a Phish",
      context:
        "a.nakamura received a payroll-themed message asking to update direct deposit details. Unlike the previous investigation, every authentication check on this message technically passed. Review the raw header fields below.",
      event: dmarcPassPhishEvent,
      questions: [
        {
          question:
            "header.authentication_results shows spf=pass, dkim=pass, and dmarc=pass, all aligned to header.from=solvix-payr0ll.com. Given everything you learned in Reading 6, why does a full DMARC pass NOT mean this message is safe?",
          options: [
            "DMARC passing always guarantees the sender is a legitimate, trusted brand — this must be a false alarm",
            "DMARC alignment only verifies that the SPF/DKIM-validated domain matches the header From domain — it has no concept of whether that domain itself is a legitimate brand or a lookalike impersonating one; here, the attacker registered and correctly configured their OWN domain (solvix-payr0ll.com, using a zero in place of the letter O), so every check passes cleanly against a domain that was never legitimate to begin with",
            "The message must have been sent internally by an actual Solvix employee, since only internal senders can pass DMARC for header.from values ending in a domain that looks similar to solvix.com",
            "DKIM cannot pass unless the message content has been manually reviewed and approved by a human at the receiving organization",
          ],
          answer: 1,
          explanation:
            "This is the core lesson of Reading 6: DMARC only checks that two domains AGREE with each other, not that either domain is legitimate. An attacker who owns solvix-payr0ll.com outright and correctly configures SPF/DKIM/DMARC for it will pass every check, because the header From domain genuinely does match the domain that was actually authenticated — it's simply the WRONG domain, a lookalike (0 instead of O) that DMARC has no mechanism to detect, since domain-similarity/lookalike detection is an entirely separate defensive capability.",
          xp: 25,
        },
        {
          question:
            "domain_first_seen_days_ago shows 2, and domain_registrar shows 'NiceNIC'. Since none of this appears in the Authentication-Results header at all, why does it matter to the investigation?",
          options: [
            "It doesn't matter — authentication header results are the only fields worth checking in any email investigation",
            "Domain age is exactly the kind of signal that catches what DMARC structurally cannot: a domain registered only 2 days ago, used for a message impersonating a well-established internal brand (Solvix Payroll), is a strong indicator of a purpose-built phishing domain, entirely independent of and complementary to the authentication results, which by themselves gave no warning at all",
            "NiceNIC is a domain registrar exclusively used by Fortune 500 companies, making this registration inherently trustworthy",
            "Domain age can only be determined through full packet capture, not through any available metadata",
          ],
          answer: 1,
          explanation:
            "This is exactly why Reading 4's DGA-adjacent point about domain age/reputation, and this reading's DMARC limitation, matter together: a domain that is 2 days old, closely mimicking a trusted internal name via a character substitution, and used to request sensitive account changes (direct deposit details) is a strong phishing indicator that lives entirely outside what SPF/DKIM/DMARC can ever tell you. This is precisely why mature detection pipelines layer domain-reputation and age checks on top of, not instead of, authentication results.",
          xp: 25,
        },
        {
          question:
            "What is the correct response, given that this message technically passes every standard authentication check?",
          options: [
            "Deliver the message normally, since a full SPF/DKIM/DMARC pass is the highest bar of legitimacy an email can meet",
            "Treat this as a confirmed phishing attempt based on the lookalike domain, its 2-day registration age, and its sensitive-data-change pretext; quarantine the message, block/sinkhole the domain, and alert payroll and broader staff about this specific lookalike-domain pattern — and separately, flag to the security team that authentication-only email filtering rules should be supplemented with domain-age/lookalike detection specifically because of cases exactly like this one",
            "Escalate this as a false positive, since 'the technical checks all passed' should always override any other signal",
            "Reply to notifications@solvix-payr0ll.com asking them to confirm their identity before taking any action",
          ],
          answer: 1,
          explanation:
            "This scenario exists precisely to teach the limitation directly: technical authentication passing is necessary but not sufficient for trusting a message. Given the freshly-registered lookalike domain and a pretext specifically designed to harvest sensitive financial account changes, this should be treated as a confirmed phishing attempt requiring containment and user notification, and it should also prompt a broader review of whether the organization's email filtering relies too heavily on authentication results alone without complementary domain-reputation/age/lookalike checks.",
          xp: 30,
        },
      ],
    },

    // ── Analyst Choice: legitimate mailing-list DKIM-fail forward FP trap ────
    {
      type: "analyst_choice" as const,
      id: "email-ac1",
      heading: "Verdict: An Internal Newsletter Forward With a Failing DKIM Signature",
      scenario:
        "A detection rule flagged an internal message to several engineering staff because its DKIM signature failed validation. Investigation shows the message originated from Solvix's own internal engineering newsletter mailing list (eng-news@solvix.com), which prepends a '[Eng-News]' tag to the Subject line and appends an unsubscribe footer to every message body before redistributing it — both of which are covered by the original sender's DKIM h= and body hash, and therefore break the original signature upon redistribution. ARC headers added by the mailing list server show the pre-modification authentication results were spf=pass, dkim=pass, dmarc=pass.",
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
          "A message from the internal engineering newsletter list, redistributed with a modified Subject line and an appended footer, fails DKIM validation on the redistributed copy but carries ARC headers recording a pass at the point the list server received the original message",
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
        "This is exactly the scenario Reading 5 and Reading 6 describe as an expected, benign cause of DKIM failure: the internal mailing list modifies the Subject line and body (both covered by the original signature), which legitimately breaks DKIM upon redistribution — not because of tampering by a malicious party, but because of ordinary list behavior. Critically, the message's own envelope sender, header From, and DMARC alignment are all still internal solvix.com domains throughout (not a lookalike or external domain), IT has confirmed the list's identity and 3-year operating history, and the ARC-Authentication-Results header independently confirms the pre-modification message passed every check cleanly at the point the list server received it.",
      fp_trap:
        "'DKIM: fail' can look alarming on its own, especially right after learning how central DKIM is to verifying message integrity — but Reading 5 was explicit that mailing-list and forwarding modifications are a common, benign cause of exactly this failure pattern, and this scenario is a clean example: internal sender, internal list, ARC headers confirming the original message's authentication was clean, and IT-confirmed legitimate list history. Escalating every DKIM failure without checking whether ARC headers explain it, or whether the actual envelope/header domains are internal and legitimate, would generate constant noise from an organization's own routine mailing-list traffic — exactly the kind of false-positive pattern that erodes trust in a detection program.",
      xp: 30,
    },

    // ── Matching: header field <-> what it reveals ────────────────────────────
    {
      type: "matching" as const,
      id: "email-m1",
      heading: "Match Each Email Field to What It Actually Tells an Investigator",
      instructions: "Match each header/protocol field to the correct description of what it reveals during forensic analysis.",
      pairs: [
        { id: "returnpath", left: "Return-Path (envelope sender / MAIL FROM)", right: "Where bounce notifications go, and the exact address SPF validates — independent of the header From a recipient sees" },
        { id: "receivedchain", left: "Received-header chain", right: "The hop-by-hop server path a message traveled; read bottom-to-top for chronological order, with your own gateway's own added header being the most trustworthy" },
        { id: "dkimd", left: "DKIM-Signature d= field", right: "The domain that actually cryptographically signed the message — what DMARC alignment compares against the header From domain" },
        { id: "authresults", left: "Authentication-Results header", right: "The receiving server's own aggregated verdict on SPF, DKIM, and DMARC for this specific message" },
        { id: "replyto", left: "Reply-To", right: "Where a reply the recipient sends will actually be delivered — often different from both From and Return-Path, and unchecked by SPF/DKIM/DMARC entirely" },
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
        { id: "mailfrom", text: "Sending server issues MAIL FROM, declaring the envelope sender" },
        { id: "rcptto", text: "Sending server issues RCPT TO, declaring the recipient" },
        { id: "data", text: "Sending server issues DATA, then transmits headers, a blank line, and the message body" },
        { id: "enddata", text: "Sending server ends the DATA block with a line containing a single period" },
        { id: "quit", text: "Sending server issues QUIT, closing the connection" },
      ],
      correct_order: ["connect", "ehlo", "mailfrom", "rcptto", "data", "enddata", "quit"],
      explanation:
        "This is the actual, literal sequence of commands that deliver every email: connect, identify (unverified), declare the envelope sender, declare the recipient, then transmit the full message content (including the header From, which is set here, independently of the earlier MAIL FROM step) before closing. Understanding this order is exactly what makes clear why MAIL FROM and the header From are two structurally separate pieces of data, set at two different points in the conversation, with nothing forcing them to agree.",
      xp: 35,
    },

    // ── Query Fill: KQL against EmailEvents for domain/alignment mismatch ────
    {
      type: "query_fill" as const,
      id: "email-qf1",
      heading: "Write It Yourself: Surface DMARC-Failing Mail Impersonating Internal Domains in KQL",
      language: "kql",
      context:
        "Using the pattern from Log Analysis 1 (a message whose header From claims an internal solvix.com identity but fails SPF and DMARC), write the KQL a detection engineer would deploy to catch messages exactly like it.",
      template:
        "EmailEvents\n| where SenderFromDomain == \"{{domain}}\"\n| where SPFResult == \"{{spfresult}}\" or DMARCResult == \"{{dmarcresult}}\"\n| where DKIMResult != \"{{dkimresult}}\"",
      blanks: [
        { id: "domain", answers: ["solvix.com"], placeholder: "internal domain being impersonated" },
        { id: "spfresult", answers: ["Fail", "fail"], placeholder: "SPF outcome to flag" },
        { id: "dmarcresult", answers: ["Fail", "fail"], placeholder: "DMARC outcome to flag" },
        { id: "dkimresult", answers: ["Pass", "pass"], placeholder: "DKIM outcome that would clear the message" },
      ],
      explanation:
        "This mirrors exactly the case you investigated in Log Analysis 1: filter to messages whose header From claims your own protected internal domain, then flag any that failed SPF or DMARC and did NOT independently pass DKIM either — since a genuine internal message would be expected to pass at least one of SPF or DKIM aligned to that domain. A message claiming to be from solvix.com that fails all three is exactly the spoofing pattern this query is designed to surface for review.",
      xp: 35,
    },

    // ── Flag ──────────────────────────────────────────────────────────────
    {
      type: "flag" as const,
      id: "email-f1",
      prompt:
        "Look at Log Analysis 1, the spoofed CFO message investigation. What is the exact domain shown in the header.reply_to field? Enter it exactly as shown (the address portion after the @ symbol).",
      answer: "outlook-secure-mail.com",
      hint: "Look at the header.reply_to field in the raw log — it's a different domain from both header.from and header.return_path.",
      xp: 25,
    },
  ],
};

export default [emailRoom];
