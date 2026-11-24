/**
 * Learning Rooms — Batch 06
 * Exchange Online Security, SharePoint & Teams Monitoring,
 * Endpoint Security Fundamentals, Microsoft Defender XDR
 *
 * Audience: absolute beginners progressing toward cloud threat detection.
 * Style: TryHackMe-style rooms with readings, MCQs, log analysis, and flags.
 */

import type { TelemetryEvent } from "@/lib/sim/types";
import type { Room, ReadingTask, QuestionTask, LogAnalysisTask, FlagTask, AnalystChoiceTask } from "@/data/rooms";

// ---------------------------------------------------------------------------
// Room 1 — Exchange Online Security
// ---------------------------------------------------------------------------

const exchangeOnlineSecurity: Room = {
  id: "exchange-online-security",
  title: "Exchange Online Security",
  description:
    "Learn how Microsoft's cloud email platform works, how attackers exploit it, and how SOC analysts detect phishing, Business Email Compromise, and malicious inbox rules. No prior email-server experience required.",
  difficulty: "intermediate",
  category: "Cloud Security",
  estimatedMinutes: 45,
  xp: 220,
  icon: "📧",
  prerequisites: ["microsoft-365-security"],
  tasks: [
    // ── Reading 1: Exchange Online & Email Flow ───────────────────────────────
    {
      type: "reading",
      id: "exch-sec-r1",
      heading: "How Exchange Online Works: The Journey of Every Email",
      content: `**Exchange Online** is Microsoft's cloud-hosted email service. It is the email backbone for any organisation using Microsoft 365. Instead of running their own on-premises mail servers, companies pay Microsoft to host their email infrastructure in Azure datacentres. Today, hundreds of millions of mailboxes run on Exchange Online.

**Why does a SOC analyst care about email?**
Email is one of the most common initial-access vectors for attackers: industry breach reports such as the Verizon DBIR consistently rank phishing alongside stolen credentials and exploited vulnerabilities as a leading way in. Understanding how email flows through Microsoft's infrastructure (and where it can be inspected) is essential knowledge for any blue-team professional.

**The Journey of an Inbound Email**

Think of email delivery like a package moving through several inspection checkpoints at an airport:

1. **Sender's mail server**: The attacker or legitimate sender composes a message and their mail server transmits it outbound.
2. **MX Record lookup**: The sending server queries DNS for the recipient domain's **MX record** (Mail Exchanger). The MX record says "send mail for corp.com to mail.protection.outlook.com." This tells the internet that Microsoft is handling email for that domain.
3. **Exchange Online Protection (EOP)**: Every inbound message first hits EOP, Microsoft's built-in filtering layer. EOP performs connection filtering (blocking known-bad IP ranges), anti-spam analysis, anti-malware scanning, and email authentication checks (SPF, DKIM, DMARC).
4. **Microsoft Defender for Office 365 (MDO)**: If the organisation has licenced MDO (formerly Advanced Threat Protection), the message additionally passes through **Safe Attachments** (detonates attachments in a sandbox) and **Safe Links** (rewrites URLs and checks them at click-time).
5. **Mailbox delivery**: If the message passes all checks, it lands in the recipient's inbox. If it is flagged as spam or malicious, it goes to the **Quarantine** instead.

**Exchange Online Protection (EOP): The Free First Line**

Every Exchange Online subscription includes EOP at no extra cost. EOP provides:
- **Connection filtering**: Blocks emails from IP addresses that appear on known-bad reputation lists.
- **Anti-spam**: Assigns a **Spam Confidence Level (SCL)** from -1 (bypass, explicitly whitelisted) to 9 (high-confidence spam). SCL 5 and above usually routes to the Junk folder.
- **Bulk mail filtering**: A separate **Bulk Complaint Level (BCL)** score (0–9) identifies mass-marketing mail.
- **Anti-malware**: Scans attachments for known malware signatures.
- **Zero-hour Auto Purge (ZAP)**: Even after delivery, if a message is later reclassified as malware or phishing, ZAP retroactively moves it out of the inbox.

**Microsoft Defender for Office 365 (MDO): The Premium Layer**

MDO adds behaviour-based, sandboxed inspection on top of EOP:
- **Safe Attachments**: Opens every attachment inside a detonation environment (a virtual machine) and observes what happens. Malicious behaviour = block.
- **Safe Links**: Rewrites URLs inside emails and Teams messages to pass through Microsoft's real-time reputation check. If a URL turns malicious after delivery, Safe Links blocks it when the user clicks it.
- **Anti-phishing / Impersonation Protection**: Detects look-alike sender names and domains designed to impersonate executives or trusted brands.

**The Exchange Admin Center (EAC): admin.exchange.microsoft.com**

The EAC is the web portal where administrators manage Exchange Online. A SOC analyst uses the **Message Trace** feature here to track the delivery status of any individual email, where it came from, what happened to it, whether it was blocked, quarantined, or delivered.

**Key takeaway for analysts**: Email filtering is not perfect. Attackers constantly evolve their techniques to bypass filters. Your job as a SOC analyst is to recognise the indicators that a message slipped through, or that something suspicious happened after delivery (like a user clicking a link or forwarding rules being created).`,
      checkpoint: {
        question: "Message Trace shows that a phishing email reached a user's inbox with SCL -1. What does that value tell you about how EOP handled it?",
        options: [
          "Spam filtering was skipped because the sender was explicitly allowed",
          "EOP scored it as high-confidence spam, but delivery overrode the score",
          "Safe Attachments detonated the attachment and found nothing malicious",
          "EOP could not score the message because the SPF lookup returned an error",
        ],
        answer: 0,
        explanation:
          "SCL -1 is the bypass value: the message was explicitly allowed, so spam filtering did not apply. Find out who created that allow and why. “High-confidence spam” is the other end of the scale (SCL 9), and anything at 5 or above would normally have gone to Junk. Safe Attachments is an MDO sandbox verdict, not part of the SCL score. An SPF lookup error shows up in the Authentication-Results header; it does not produce SCL -1.",
      },
    } satisfies ReadingTask,

    // ── Reading 2: SPF, DKIM, DMARC ──────────────────────────────────────────
    {
      type: "reading",
      id: "exch-sec-r2",
      heading: "Email Authentication: SPF, DKIM, and DMARC Explained",
      content: `One of the biggest problems with email is that it was invented before anyone thought about security. By default, **anyone can send an email claiming to be from any address**. This is called **email spoofing**, and it is the foundation of almost every phishing and Business Email Compromise (BEC) attack.

Three protocols were invented to fix this: SPF, DKIM, and DMARC. Together they let a receiving mail server verify whether an email really came from where it claims to come from. Think of them as the email equivalent of a passport, a seal of authenticity, and a border policy.

---

**SPF: Sender Policy Framework**

SPF is a DNS record that answers the question: **"Which mail servers are authorised to send email on behalf of this domain?"**

The domain owner publishes an SPF record in DNS. It looks something like:
\`v=spf1 include:spf.protection.outlook.com -all\`

This means: "Only Microsoft's mail servers (protection.outlook.com) are allowed to send email from our domain. Reject everything else."

When a receiving server gets an email claiming to be from corp.com, it checks the SPF record and asks: "Did this email come from one of the approved servers?" If yes → **SPF pass**. If no → **SPF fail**.

**Limitation: SPF checks the envelope, not the From: line the user reads**

Every email carries two sender addresses, and they sit in different places. Think of a paper letter: the return address on the **envelope** is what the post office reads, and the name on the **letterhead** inside is what the reader sees. Nothing forces the two to match.

- The **envelope sender** (also called MAIL FROM or Return-Path, and the **P1 sender** in Microsoft's logs) is handed to the receiving server during the SMTP conversation, before the message itself is sent. Bounces go back to it. **SPF checks this domain.**
- The **header From:** (the **P2 sender**) is a line inside the message. It is what Outlook shows as the sender. SPF never looks at it.

This is what it looks like on the wire. The sending server talks to Exchange Online in plain SMTP commands. The envelope is the \`MAIL FROM\` command; the From: the user will see is just one line of the message text sent after \`DATA\`:

\`\`\`smtp
220 AM4PEPF00027A6C.mail.protection.outlook.com Microsoft ESMTP MAIL Service ready
EHLO mta1.mailer-x.example
250-AM4PEPF00027A6C.mail.protection.outlook.com Hello [203.0.113.81]
MAIL FROM:<bounce-7731@mailer-x.example>
250 2.1.0 Sender OK
RCPT TO:<ap@corp.com>
250 2.1.5 Recipient OK
DATA
354 Start mail input; end with <CRLF>.<CRLF>
From: "Dana Levi, CFO" <dana.levi@corp.com>
To: <ap@corp.com>
Subject: Updated bank details for this week's payments

.
250 2.6.0 Queued mail for delivery
\`\`\`

The user never sees that conversation. Exchange Online keeps the envelope sender in two headers anyone can open: \`Return-Path:\` and the \`smtp.mailfrom=\` part of Authentication-Results. The From: domain is recorded next to it as \`header.from=\`:

\`\`\`headers
Return-Path: bounce-7731@mailer-x.example
Authentication-Results: spf=pass (sender IP is 203.0.113.81)
 smtp.mailfrom=mailer-x.example; dkim=none (message not signed)
 header.d=none;dmarc=fail action=none header.from=corp.com;compauth=fail
 reason=001
From: "Dana Levi, CFO" <dana.levi@corp.com>
\`\`\`

**Where you find each address**

- **Outlook and Outlook on the web** show only the header From: (the P2 sender). The envelope never appears in the reading pane.
- **The message headers** show both. In classic Outlook: open the message, then File > Properties > Internet headers. In Outlook on the web: the More actions menu (...) > View > View message details.
- **Microsoft Defender** shows both side by side. In Advanced hunting, the \`EmailEvents\` table has \`SenderMailFromAddress\` (envelope, P1) and \`SenderFromAddress\` (visible From:, P2). In the Microsoft 365 audit records for email threats, the same pair is \`P1Sender\` and \`P2Sender\`, so a field such as \`P2SenderDomain\` holds the domain the recipient actually saw.

The figure at the end of this reading puts the envelope, the message and those three places together.

**The attacker's side: how this gap is used**

The example above is a complete attack, and every step is cheap:

1. The attacker registers a throwaway domain (\`mailer-x.example\`) and rents one server (\`203.0.113.81\`).
2. They publish an honest SPF record for their own domain: \`v=spf1 ip4:203.0.113.81 -all\`.
3. They send with the envelope on their own domain and type the CFO's address into From:.
4. The receiving server checks SPF for **mailer-x.example**, the envelope domain. The server is listed, so the result is **spf=pass**. corp.com's own SPF record is never consulted.
5. The accounts-payable clerk sees "Dana Levi, CFO" in the inbox, and anyone who glances at the header sees spf=pass.

This is exactly the gap DMARC alignment closes (next section): the passing SPF domain, mailer-x.example, does not match the visible corp.com, so DMARC fails and corp.com's published policy decides what happens. With \`p=none\` the message is still delivered, as in the header above.

Once a domain enforces DMARC (\`p=reject\`), forging its exact address stops working, so attackers step sideways:

- **A lookalike domain** they really own, such as \`corp-com.example\`, with its own SPF, DKIM and DMARC. Every check passes and aligns, because it is a real domain sending its own mail. Authentication proves which domain sent the message, not that it is the domain you expected, so read the domain itself.
- **Display-name spoofing**: \`"Dana Levi, CFO" <dana.levi.cfo@gmail.com>\`. The address is an honest Gmail address that passes everything for gmail.com; only the name lies, and many phone mail apps show only the name.
- **A compromised real mailbox**: every check passes because it really is the domain's own mail. The next reading covers it.

**Analyst habit**: on every reported message, compare \`smtp.mailfrom\` with \`header.from\`. If they differ, find out who owns the envelope domain (a known mailing service, or a domain registered last week?). Then check the From: domain itself, letter by letter.

---

**DKIM: DomainKeys Identified Mail**

DKIM adds a **cryptographic signature** to every outgoing email. Think of it like a wax seal on a letter. It proves the message has not been tampered with in transit and really originated from the claimed domain.

The sending organisation has a private key (kept secret on their mail servers) and publishes the corresponding public key in DNS. When the email arrives, the receiving server retrieves the public key from DNS and verifies the signature.

If the signature checks out → **DKIM pass**. If the email was modified in transit or the signature is missing → **DKIM fail** or **DKIM none**.

DKIM survives email forwarding better than SPF, because it is tied to the message content, not the sending server's IP address.

---

**DMARC: Domain-based Message Authentication, Reporting & Conformance**

DMARC is the **policy layer** that sits on top of SPF and DKIM. It answers two questions:
1. **What should receiving servers do when SPF or DKIM fail?**
2. **How should failures be reported back to the domain owner?**

A DMARC record in DNS looks like:
\`v=DMARC1; p=reject; rua=mailto:dmarc-reports@corp.com\`

The **p= (policy) field** is the most important:
- \`p=none\`: Monitor only; take no action on failures. Used when first deploying DMARC.
- \`p=quarantine\`: Send failing emails to spam/junk folder.
- \`p=reject\`: Block and discard failing emails entirely. This is the most protective setting.

**DMARC Alignment** is a critical concept: for DMARC to pass, either the SPF domain or the DKIM signing domain must **align** (match) with the visible "From:" header domain. This closes the SPF loophole mentioned above.

---

**Reading the Authentication-Results Header**

Every email received by Exchange Online gets an **Authentication-Results** header added to it. This is where SOC analysts look to quickly check the authentication status of a suspicious email.

Example:
\`Authentication-Results: spf=fail (sender IP is 203.0.113.81); dkim=none; dmarc=fail action=none header.from=corp.com\`

Breaking this down:
- **spf=fail**: The sending IP (203.0.113.81) is NOT in corp.com's SPF record. This IP is not authorised.
- **dkim=none**: No DKIM signature was present at all. Legitimate email from Microsoft 365 always has DKIM.
- **dmarc=fail**: Because both SPF and DKIM failed, DMARC also fails.
- **action=none**: The DMARC policy is \`p=none\`, so the email was delivered anyway (just monitored). That policy is the one published by the domain in the visible From: header, not by the company receiving the mail, so an attacker who owns the sending domain sets it themselves.

**Key insight for analysts**: An email with \`dmarc=fail action=none\` was delivered to the inbox despite failing authentication. This is a critical finding, especially if the "From:" domain appears to be a trusted organisation like your CEO's company.

**Microsoft's 2025 enforcement update**: In May 2025, Microsoft began rejecting bulk email from senders who lack proper DMARC, SPF, and DKIM alignment when sending to consumer Microsoft addresses (Outlook.com, Hotmail). Enterprise tenants can enforce stricter policies in their own anti-phishing policies.`,
      image: {
        src: "/lesson-images/email/envelope-vs-header-from.svg",
        alt: "One spoofed message drawn as an envelope and the letter inside it. The envelope carries MAIL FROM bounce-7731@mailer-x.example, the P1 sender that SPF checks; the letter carries From: Dana Levi, CFO at dana.levi@corp.com, the P2 sender Outlook shows. Beside it, where each address appears: the Outlook inbox shows only the CFO's name, the message headers show Return-Path and smtp.mailfrom for the envelope and header.from for the visible sender, and Advanced hunting EmailEvents shows SenderMailFromAddress and SenderFromAddress. The result: SPF passes for the attacker's own domain and DMARC fails because it does not align with corp.com.",
        caption: "The envelope (P1) is what SPF checks; the From: line (P2) is what the user reads. Compare them in the headers or in EmailEvents.",
        credit: "Figure authored for this course.",
      },
      checkpoint: {
        question: "A legitimate, signed newsletter is auto-forwarded from an employee's personal mailbox to their work inbox. Which check is most likely to still pass at the work inbox, and why?",
        options: [
          "SPF, because forwarding leaves the envelope-from domain unchanged",
          "SPF, because the forwarding server inherits the sender's approval",
          "DKIM, because its signature is tied to the content, not the server IP",
          "DMARC, because its policy is evaluated before SPF and DKIM run",
        ],
        answer: 2,
        explanation:
          "DKIM signs the message content, so an unmodified forward still verifies even though a different server delivered it. An unchanged envelope-from does not save SPF: SPF checks the connecting server's IP, and the forwarder's IP is not in the original sender's SPF record. Forwarding servers do not “inherit” approval; only the IPs listed in the record are authorised. DMARC is not evaluated first; it is the policy layer that uses the SPF and DKIM results.",
      },
    } satisfies ReadingTask,

    // ── Question 1 ────────────────────────────────────────────────────────────
    {
      type: "question",
      id: "exch-sec-q1",
      question: "An email arrives at your company with the following header:\n\n`Authentication-Results: spf=pass; dkim=pass; dmarc=fail action=quarantine`\n\nWhat does this indicate?",
      options: [
        "SPF and DKIM both passed, so DMARC must have passed too: a false alarm",
        "SPF and DKIM passed for a domain that does not match the visible From: domain",
        "The DMARC record could not be fetched, so the message was quarantined",
        "The message body was altered after signing, which DMARC detects separately"
      ],
      answer: 1,
      explanation: "DMARC needs **alignment**: the SPF domain or the DKIM signing domain must match the visible From: domain. An attacker can pass SPF and DKIM for a domain they own while showing a different domain in From:, so DMARC fails. “DMARC must have passed too” is the misconception this header disproves: two passes are not enough without alignment. The record was clearly fetched: action=quarantine is the From domain's published p=quarantine policy, which the receiver could only apply after reading it. A body changed after signing would break DKIM itself, and here dkim=pass. action=quarantine means the From domain's policy sent the message to junk.",
      xp: 30,
    } satisfies QuestionTask,

    // ── Reading 3: BEC Detection & Monitoring ─────────────────────────────────
    {
      type: "reading",
      id: "exch-sec-r3",
      heading: "Detecting BEC Attacks and Monitoring Exchange Online",
      content: `**Business Email Compromise (BEC)** is one of the most financially damaging cyber threats facing organisations today. The FBI's Internet Crime Complaint Center (IC3) reports billions of dollars in BEC losses every year. Unlike ransomware, BEC doesn't need malware: it relies on deception.

**How BEC Works**

In a typical BEC scenario:
1. An attacker identifies a target organisation (e.g. Acme Corp) and researches its executives (LinkedIn, company website).
2. The attacker spoofs or typosquats the CEO's email address. Typosquatting means registering a domain that looks similar: \`acm3corp.com\` instead of \`acmecorp.com\`, or \`acmecorρ.com\` (using a Greek letter that looks like 'p').
3. The attacker emails the CFO or Finance team, impersonating the CEO: "I need an urgent wire transfer of $450,000 to this account. I'm in a meeting and cannot talk, just do it now."
4. The sense of urgency, combined with authority, causes the victim to act without verifying.

**Key BEC Detection Signals**

As a SOC analyst, watch for these in your email security tools:

- **DMARC/SPF/DKIM failures on executive-looking domains**: A message appearing to be from the CEO but with \`dmarc=fail\` is a major red flag.
- **Lookalike sender domains**: Compare the P2 sender domain (displayed to the user) against your internal domain list. Is \`c0rp.com\` (with a zero) trying to look like \`corp.com\`?
- **Urgency keywords in subjects**: "URGENT", "Wire Transfer", "Payment Required", "Confidential" are classic BEC subject line patterns.
- **Mismatch between display name and email address**: The From display says "John Smith (CEO)" but the actual email address is \`ceo@randomdomain.ru\`.
- **Reply-To header manipulation**: The visible From address looks legitimate but the Reply-To points to an attacker-controlled address.

**Malicious Inbox Rules: The Silent Forwarder**

A sophisticated attacker who successfully compromises a mailbox often creates **inbox rules** to maintain persistence and steal information silently. A common rule:
- Forward all incoming emails to an external address (attacker's mailbox)
- Delete the forwarded emails from Sent Items and Inbox so the victim doesn't notice
- Move security alerts or IT emails to Deleted Items automatically

These rules appear in the **Unified Audit Log** under different operation names depending on how they were made: \`New-InboxRule\` (rule created in Outlook on the web or with PowerShell), \`Set-InboxRule\` (existing rule changed the same way) and \`UpdateInboxRules\` (rule created or changed from the Outlook desktop client). Search for all three: the operation name tells you which client was used, but the rule's content (external forwarding, deletion, moving security mail) is what makes it suspicious.

Forwarding does not even need a rule: an attacker with admin rights, or a user in the mailbox settings, can set mailbox-level forwarding to an external address. That change is logged as the \`Set-Mailbox\` operation with the \`ForwardingSmtpAddress\` parameter.

**Monitoring Exchange Online: Key Tools**

| Tool | Where | What SOC Analysts Use It For |
|---|---|---|
| **Message Trace** | admin.exchange.microsoft.com → Mail flow → Message trace | Track individual emails: was it delivered, quarantined, or blocked? What was the spam confidence level? |
| **Quarantine Review** | security.microsoft.com → Email & collaboration → Quarantine | Review and release quarantined messages; look for false positives or attacker-released malware |
| **Unified Audit Log** | Microsoft Purview portal (purview.microsoft.com → Audit) or via Search-UnifiedAuditLog | Find MailItemsAccessed, SendAs, AddDelegate, New-InboxRule, UpdateInboxRules, Set-Mailbox events |
| **Threat Explorer** | security.microsoft.com → Email & collaboration → Explorer | Hunt for phishing campaigns, see email delivery status, trace URLs clicked by users |
| **Alert Policies** | security.microsoft.com → Alerts | Pre-built alerts for forwarding rules, unusual send volumes, impersonation detection |

**Key Audit Log Operations to Know**

- \`MailItemsAccessed\`: Someone accessed specific emails (critical for OAuth token compromise investigations)
- \`SendAs\`: Someone sent email as another user
- \`AddDelegate\`: A delegate (another user) was given access to a mailbox
- \`New-InboxRule\` / \`Set-InboxRule\`: An inbox rule was created / changed from Outlook on the web or PowerShell (check the forwarding and delete parameters)
- \`UpdateInboxRules\`: An inbox rule was created or modified from the Outlook desktop client (check the external address in the rule details)
- \`Set-Mailbox\`: Mailbox settings changed; with \`ForwardingSmtpAddress\` it means mailbox-level forwarding, no inbox rule needed

**Practical Analyst Workflow for Suspicious Email**

1. Open **Message Trace** and find the email by sender, recipient, or subject.
2. Check the **Authentication-Results**: did SPF, DKIM, DMARC pass?
3. Check the **SCL score**: was it filtered but delivered anyway?
4. Check the **P2SenderDomain** field: does it match the display name domain?
5. Search the **Unified Audit Log** for \`New-InboxRule\`, \`Set-InboxRule\`, \`UpdateInboxRules\` and \`Set-Mailbox\` for that user in the past 30 days.
6. If the user clicked a link, check **Safe Links** reports in Threat Explorer.
7. If mailbox compromise is suspected, check \`MailItemsAccessed\` for unusual activity.`,
    } satisfies ReadingTask,

    // ── Question 2 ────────────────────────────────────────────────────────────
    {
      type: "question",
      id: "exch-sec-q2",
      question: "A finance employee reports receiving an urgent email from the CEO asking for a $200,000 wire transfer. The email passed SPF and DKIM, and its From: address is `ceo@c0rp.com`. Your company's domain is `corp.com`. What attack technique is this?",
      options: [
        "Exact-domain spoofing: a forged From: address that SPF failed to catch",
        "Typosquatting: the attacker registered their own domain and authenticated it",
        "Account takeover: the CEO's real mailbox was compromised and used to send it",
        "Display-name spoofing: only the name shown was faked, on an unrelated domain"
      ],
      answer: 1,
      explanation: "This is a **lookalike (typosquatted) domain**. The attacker registered `c0rp.com` and published SPF and DKIM for it, so authentication passes: the checks prove the mail really came from c0rp.com. DMARC is evaluated for the From domain, c0rp.com, which the attacker controls, so corp.com's own DMARC policy plays no part. Only lookalike/impersonation protection (MDO anti-phishing) or a careful look at the P2 sender domain catches it. Exact-domain spoofing would show corp.com in From:, and SPF would then fail. A taken-over CEO mailbox would send from the real corp.com address. Display-name spoofing pairs a CEO display name with an unrelated domain; here the domain itself imitates corp.com.",
      xp: 30,
    } satisfies QuestionTask,

    // ── Question 3 ────────────────────────────────────────────────────────────
    {
      type: "question",
      id: "exch-sec-q3",
      question: "A compromised user's incoming mail is being copied to an external Gmail address. You searched the Unified Audit Log for New-InboxRule, Set-InboxRule and UpdateInboxRules on that mailbox and found nothing. Which operation should you search for next to explain the forwarding?",
      options: [
        "MailItemsAccessed",
        "SendAs",
        "Set-Mailbox",
        "AddDelegate"
      ],
      answer: 2,
      explanation: "Forwarding without any inbox rule is **mailbox-level forwarding**, logged as **Set-Mailbox** with the ForwardingSmtpAddress parameter. That is why an empty search for the three rule operations does not close the question. MailItemsAccessed records items being read (important for scoping what the attacker saw) but it does not create a forwarding path. SendAs records mail sent as another user, which is outbound impersonation, not a copy of incoming mail. AddDelegate gives another user access to the mailbox inside the tenant; it does not push mail to an external address.",
      xp: 30,
    } satisfies QuestionTask,

    // ── Log Analysis: BEC email with failed DMARC ─────────────────────────────
    {
      type: "log_analysis",
      id: "exch-sec-la1",
      heading: "Suspicious Email: Wire Transfer Request",
      context: "You are a SOC analyst at Corp Inc. The email security system has flagged an inbound message received by the Finance team. You pulled the message's internet headers (the ones Exchange Online Protection stamped on it at delivery) from the Finance mailbox. Analyse them and answer the questions.",
      event: {
        id: "exch-la1-001",
        ts: "2025-11-14T09:23:41.000Z",
        source: "exchange",
        event_type: "email_received",
        severity: "high",
        description: "Inbound email to finance team: authentication failures detected",
        hostname: "mail.protection.outlook.com",
        user_email: "finance@corp.com",
        mitre_technique: "T1566.002",
        mitre_tactic: "Initial Access",
        vendor: "Microsoft Defender for Office 365",
        // The internet headers Exchange Online Protection stamped on the delivered message.
        // The Unified Audit Log does not record received mail; the headers are where SCL,
        // BCL and Authentication-Results live.
        raw: {
          "email.headers.Received": "from mail.c0rp.com (198.51.100.27) by AM6EUR05FT012.mail.protection.outlook.com (10.167.240.12) with Microsoft SMTP Server (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.8158.14 via Frontend Transport; Fri, 14 Nov 2025 09:23:41 +0000",
          "email.headers.Received-SPF": "Fail (protection.outlook.com: domain of c0rp.com does not designate 198.51.100.27 as permitted sender) receiver=protection.outlook.com; client-ip=198.51.100.27; helo=mail.c0rp.com;",
          "email.headers.Authentication-Results": "spf=fail (sender IP is 198.51.100.27) smtp.mailfrom=c0rp.com; dkim=none (message not signed) header.d=none;dmarc=fail action=none header.from=c0rp.com;",
          "email.headers.From": "\"Daniel Hayes\" <ceo@c0rp.com>",
          "email.headers.To": "finance@corp.com",
          "email.headers.Subject": "URGENT: Wire Transfer Required, Confidential",
          "email.headers.Date": "Fri, 14 Nov 2025 09:23:38 +0000",
          "email.headers.Message-ID": "<7f3a9b21@mail.c0rp.com>",
          "email.headers.Return-Path": "ceo@c0rp.com",
          "email.headers.X-MS-Exchange-Organization-Network-Message-Id": "ae9f2c1d-4b77-4e3a-9123-fa8d2b3c9e01",
          "email.headers.X-MS-Exchange-Organization-SCL": "1",
          "email.headers.X-Forefront-Antispam-Report": "CIP:198.51.100.27;CTRY:NL;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:mail.c0rp.com;PTR:mail.c0rp.com;CAT:NONE;SFS:(13230040)(4636009)(376014);DIR:INB;",
          "email.headers.X-Microsoft-Antispam": "BCL:0;"
        },
      } satisfies TelemetryEvent,
      questions: [
        {
          question: "The email was delivered to the Finance inbox despite failing SPF and DMARC. Based on the record, what is the most likely reason it was not stopped?",
          options: [
            "EOP was not filtering this tenant's mail, so no policy was evaluated",
            "c0rp.com's DMARC policy is p=none, so its DMARC failure triggered no action",
            "corp.com's DMARC policy is p=none, so lookalikes of corp.com go unenforced",
            "A tenant allow entry for the sender overrode the authentication failures"
          ],
          answer: 1,
          explanation: "DMARC is evaluated for the From domain, c0rp.com, and `dmarc=fail action=none` means that domain publishes `p=none`, so the failure carried no reject or quarantine instruction. Here p=none is the attacker's own choice for a domain they control. With SCL 1 the spam filter judged the content clean (below the Junk threshold of 5), so nothing else stopped it. EOP was clearly running: it produced the SCL, BCL and Authentication-Results values in this record. corp.com's DMARC policy plays no part, because the message never claims to come from corp.com. An allow entry would have bypassed filtering and shown SCL -1, not SCL 1.",
          xp: 40,
        },
        {
          question: "Which field in this record most directly shows that the message is pretending to come from your own company?",
          options: [
            "Authentication-Results: corp.com's SPF record does not list the sending IP",
            "From: c0rp.com uses a zero where your corp.com domain has an o",
            "Message-ID: the ID was generated by a server outside your tenant",
            "X-Forefront-Antispam-Report: SFV:NSPM shows a spoofed corp.com message got through"
          ],
          answer: 1,
          explanation: "`From` (also `header.from` in Authentication-Results) is the address the recipient sees, and `c0rp.com` swaps the letter o for a zero to pass as `corp.com`: a typosquatted lookalike built to fool a reader at a glance. The SPF result is for c0rp.com, not corp.com (the header says the IP is not in c0rp.com's SPF), so it says nothing about your own domain. Every external email has a Message-ID from a server outside your tenant, so that field is normal. SFV:NSPM only says the spam filter judged the message not spam; nothing in the record shows corp.com being spoofed.",
          xp: 40,
        },
      ],
    } satisfies LogAnalysisTask,

    // ── Flag Task ─────────────────────────────────────────────────────────────
    {
      type: "flag",
      id: "exch-sec-f1",
      prompt: "Blocking the lookalike domain is not enough: the mail-flow team also wants to block the infrastructure that delivered this message. Using the log above, what is the IP address of the server that actually sent it to Exchange Online?",
      answer: "198.51.100.27",
      hint: "SPF judges the server that connected to EOP, not the From: address.",
      xp: 50,
    } satisfies FlagTask,

  ],
};

// ---------------------------------------------------------------------------
// Room 2 — SharePoint & Teams Security Monitoring
// ---------------------------------------------------------------------------

const sharepointTeamsMonitoring: Room = {
  id: "sharepoint-teams-monitoring",
  title: "SharePoint & Teams Security Monitoring",
  description:
    "Discover how attackers exploit Microsoft's collaboration tools to steal data, conduct phishing via Teams chat, and abuse external sharing. Learn to detect bulk data theft, insider threats, and guest-account abuse.",
  difficulty: "intermediate",
  category: "Cloud Security",
  estimatedMinutes: 60,
  xp: 220,
  icon: "💬",
  prerequisites: ["microsoft-365-security"],
  tasks: [
    // ── Reading 1: SharePoint & OneDrive Structure ────────────────────────────
    {
      type: "reading",
      id: "spt-teams-r1",
      heading: "SharePoint and OneDrive: Where Files Live and Who Can Reach Them",
      content: `**SharePoint Online** is the Microsoft 365 service that stores and shares an organisation's files. Team files live in SharePoint sites, and each person's own files live in OneDrive, which is built on SharePoint too.
By the end of this reading you can read any SharePoint or OneDrive URL from a log: whose data it is, who could reach it, and which records prove what happened.

### The map in one picture

Picture one company's office building. The **tenant** is the building. Each **site** is a locked suite with its own key list. A **library** is a filing cabinet in a suite, a **folder** is a drawer, and a **file** is the document. **OneDrive** is a separate wing of personal lockers, one per employee. The figure at the end of this reading draws the whole map.

There are three levels, and each one owns different things:

| Level | What it is | What it owns | Where you see it in a log |
|---|---|---|---|
| 1. Tenant | Your organisation's single Microsoft 365 instance | The directory of people, the admin settings, the sharing ceiling for every site | \`OrganizationId\`, the tenant's GUID (globally unique identifier), on every record |
| 2. Site | A container with its own owners, members, storage and sharing setting | Who can get in | \`SiteUrl\` |
| 3. Library, folder, file | The content inside one site | The files, their versions, and any exceptions to the site's permissions | \`SourceRelativeUrl\`, \`SourceFileName\`, \`ObjectId\`, \`ListItemUniqueId\` |

### Three planes: who, how, and what

Every cloud investigation in Microsoft 365 crosses three planes. Each plane has its own job and its own logs, and you need all three to tell one story.

| Plane | What it decides or holds | Main parts | Where its activity is logged |
|---|---|---|---|
| Identity plane | Who someone is, and whether they may sign in | Microsoft Entra ID: users, guests, Microsoft 365 Groups, apps and service principals, Conditional Access | Entra sign-in logs (interactive, non-interactive, service principal) and the Entra audit log, for example Consent to application |
| Control plane | How the services are configured | The SharePoint and Teams admin centers, each site's settings, the sharing policy | Admin operations in the Unified Audit Log, for example SharingPolicyChanged and SiteCollectionAdminAdded |
| Data plane | The content itself | Sites, libraries, folders, files, chat and channel messages | File, sharing and Teams operations in the Unified Audit Log |

SharePoint never decides who you are; it applies what the identity plane says. That is why a leak case always ends up in two places: the file records and the sign-in records of whoever touched the file.

### Level 1: the tenant

A tenant has exactly one directory and one SharePoint service. The directory is **Microsoft Entra ID**, Microsoft's identity service. It holds every user, every guest and every group. SharePoint keeps no list of people of its own; it asks Entra ID.

Three things live at tenant level:
- **The SharePoint admin center**, at nexacorp-admin.sharepoint.com for a tenant named nexacorp. Admins create and delete sites and set tenant-wide policy there.
- **The tenant sharing setting.** It is the ceiling for every site and every OneDrive. A tenant starts at the most open level, Anyone, until an admin changes it.
- **Microsoft 365 Groups.** A group is one membership list that unlocks a shared mailbox, a calendar, a team site and, when a team is created, a team in Teams.
- **Apps.** An app registered in Entra ID is an identity too. Granted a permission such as Sites.Read.All or Files.Read.All, it can read every site with no person signed in, until someone removes the app or its permission.

### Level 2: sites, and the five kinds you will meet

A **site** is the unit of access: it has its own owners, its own members and its own sharing setting. Microsoft's older name for it is **site collection**, and admin tools still use that term. Modern SharePoint is flat: sites sit side by side, not inside each other. Older tenants may still have subsites, which share their parent site's URL.

| Kind of site | Used for | Who controls access | URL pattern |
|---|---|---|---|
| Team site (group-connected) | Collaboration for a team or project. One is created with every Microsoft 365 Group, so every team in Teams has one | The Microsoft 365 Group: group owners become site Owners, group members become site Members | nexacorp.sharepoint.com/sites/BidTeam (admins can choose /teams/ instead of /sites/) |
| Channel site | The files of one private or shared channel in Teams | The channel's own owners and members, managed only from Teams | nexacorp.sharepoint.com/sites/BidTeam-Pricing: the team name, a hyphen, the channel name |
| Communication site | Publishing to many readers: the intranet, news, policies | The site's own SharePoint groups. No Microsoft 365 Group sits behind it | nexacorp.sharepoint.com/sites/Intranet |
| OneDrive | One personal site per user | The user, plus whatever the user shares | nexacorp-my.sharepoint.com/personal/d_levi_nexacorp_com |
| Hub site | A team or communication site that an admin registered as the centre of a family of sites | Its own permissions, like any other site | The URL of the site it is built on |

Two of these need a closer look.

**OneDrive lives on a different host name.** Personal sites use the tenant name plus -my. The path is the owner's sign-in name with the @ and every dot turned into underscores. So d.levi@nexacorp.com owns /personal/d_levi_nexacorp_com. Audit records from a OneDrive carry \`Workload\` OneDrive, not SharePoint.

**A hub is an association, not a container.** Joining a site to a hub adds shared navigation, a shared look and hub-wide search. It does not move the site, and it does not change who can open it. A file "in the Projects hub" really sits in one specific site, with that site's permissions. Joining is audited as \`HubSiteJoined\`.

### Level 3: inside a site

- **List**: a table of rows that the site stores, like a shared spreadsheet. Each row is an **item**. Task trackers and contact lists are lists.
- **Document library**: a list whose items are files. Every team site starts with one library called **Documents**. In URLs and audit records its name is **Shared Documents**. In a OneDrive the library is simply **Documents**.
- **Folder**: a drawer inside a library. Teams creates one folder per standard channel.
- **File**: the document. It has a unique ID, logged as \`ListItemUniqueId\`, and a **version history**. Each save can keep an earlier copy, so a file that was later emptied or overwritten may still be recoverable.

### How Teams sits on top of SharePoint

Teams stores almost none of its own data. It is a window onto three other services: Entra ID for membership, SharePoint and OneDrive for files, and Exchange Online for messages.

| What you see in Teams | Where it is really stored | Where you search |
|---|---|---|
| A team | A Microsoft 365 Group in Entra ID, plus a group-connected team site | The group's membership, then the team site's audit records |
| A standard channel's files | A folder named after the channel, in the team site's Documents library. Every team has a General channel, so most team sites have a General folder | The team site's \`SiteUrl\`, with the channel's folder in \`SourceRelativeUrl\` |
| A private channel's files | A separate channel site that only the channel's members can open | A different \`SiteUrl\`, ending in -ChannelName |
| A shared channel's files | A separate channel site too. People from other organisations reach it with their home account through Entra B2B direct connect, without a guest account | The channel site's \`SiteUrl\` |
| A file sent in a 1:1 or group chat | The sender's OneDrive, in a folder named Microsoft Teams Chat Files, shared only with the people in that chat | The sender's OneDrive URL, never a team site |
| A meeting recording | The organiser's OneDrive, in Recordings. For a channel meeting: a Recordings folder in that channel's library | The organiser's OneDrive, or the channel's site |
| Chat and channel messages | Exchange Online. Chats: a copy in each participant's mailbox. Channel posts: the team's group mailbox | An eDiscovery content search of mailboxes, not the SharePoint audit records |

### Who can reach a file: the permission model

Think of building badges. Each site hands out three standard badges, and a sharing link is a visitor pass for one door.

**The three default groups.** Every site gets three SharePoint groups.

| SharePoint group | Default permission level | What it allows | Who is in it on a team site |
|---|---|---|---|
| Owners | Full Control | Everything, including changing permissions and sharing settings | The Microsoft 365 Group's owners |
| Members | Edit | Add, change and delete files, folders and lists | The group's members |
| Visitors | Read | View and download | Nobody by default. Microsoft 365 Groups have no read-only role, so readers are added here directly |

Two more facts change who is really inside:
- **Public teams.** On a public team's site, the built-in group "Everyone except external users" sits in Members. Every employee can then open and edit the site's files.
- **Site collection administrators** have full control of the whole site. Global admins and SharePoint admins can add themselves, which is logged as \`SiteCollectionAdminAdded\`. The same event appears when an admin gives themselves access to a user's OneDrive.

**Inheritance.** Permissions flow downward: site, then library, then folder, then file. A suite key opens every drawer in the suite. An owner can **break inheritance** on a library, folder or file and give it unique permissions, which is logged as \`SharingInheritanceBroken\`. Sharing one file with someone who has no access breaks inheritance on that file automatically.

**Sharing links and Limited Access.** When someone shares one file, SharePoint creates the link and a hidden SharePoint group behind it, whose name starts with SharingLinks. and carries IDs for the file and the link. SharePoint also gives the recipients **Limited Access** on the library and site above the file. Limited Access lets them reach that one file and nothing else. So a person shown with Limited Access on a site had something inside shared with them. It does not mean they can read the site.

**Guests.** When an outsider accepts an invitation to a site or a team, Entra ID creates a **guest** account for them. With SharePoint's Entra B2B integration turned on, sharing a single file does the same. The guest's sign-in name is their own address with @ turned into _, then #EXT#, then your tenant's onmicrosoft.com domain. So partner@fabrikam.example becomes partner_fabrikam.example#EXT#@nexacorp.onmicrosoft.com. From then on, a guest gets access exactly as an employee does: through a group, a site membership or a link.

**The layering rule.** Sharing settings stack in three layers. Each layer can be as open as the layer above it, or tighter, never wider.
1. **Tenant**: the SharePoint setting, plus a OneDrive setting that can be equal or tighter.
2. **Site**: each site's own setting, equal to the tenant's or tighter.
3. **Link**: a user can only create the link types that the site allows.

The four sharing levels have the same names at tenant and at site level:

| Level in the admin center | PowerShell value (SharingCapability) | What people can do |
|---|---|---|
| Anyone | ExternalUserAndGuestSharing | Create links that work with no sign-in, and invite guests |
| New and existing guests | ExternalUserSharingOnly | Invite new outsiders, who must sign in or enter a one-time code |
| Existing guests | ExistingExternalUserSharingOnly | Share only with guests already in the directory |
| Only people in your organization | Disabled | No external sharing at all |

The settings that decide reach are visible with one PowerShell command, Get-SPOTenant. These are the ones to compare during a case:

| Get-SPOTenant setting | What it controls |
|---|---|
| SharingCapability | The tenant ceiling for SharePoint sites, using the four values above |
| OneDriveSharingCapability | The ceiling for every OneDrive, equal to SharingCapability or tighter |
| DefaultSharingLinkType | The link the sharing dialog offers first: Direct (Specific people), Internal (your organisation), AnonymousAccess (Anyone), or None (the widest type allowed) |
| DefaultLinkPermission | Whether that first link offers View or Edit |
| RequireAnonymousLinksExpireInDays | The longest an Anyone link may live, from 1 to 730 days. 0 removes the limit |
| ExternalUserExpirationRequired and ExternalUserExpireInDays | Whether guests lose site access automatically, and after how many days (30 to 730) |

The tenant does not announce that it became more open, but the audit log does. Every change is a SharingPolicyChanged record, and its ModifiedProperties name the setting with its old and new values. From that record you know who changed it and when, and you check that admin's sign-in next.

An example. The tenant allows Anyone, but the Finance site is set to Only people in your organization. Then nobody can share a Finance file outside, even by mistake. In an investigation, the site's level tells you which kinds of link were even possible.

**The four kinds of sharing link.** These are the choices in the sharing dialog.

| Link type | Works for | Sign-in needed? | What the audit log records |
|---|---|---|---|
| Anyone with the link | Whoever holds the URL, including anyone it was forwarded to | No | \`AnonymousLinkCreated\` when made. \`AnonymousLinkUsed\` on each use, with ClientIP and UserAgent but no named person |
| People in your organization | Any member of your directory who has the link. It does not work for guests | Yes | \`CompanyLinkCreated\`, then \`CompanyLinkUsed\` |
| Specific people | Only the named recipients, inside or outside the organisation. Forwarding it gives nobody else access | Yes, as that recipient | \`SecureLinkCreated\`, plus \`AddedToSecureLink\` naming the recipient in TargetUserOrGroupName. An outsider's use then shows as \`FileAccessed\` |
| People with existing access (newer dialogs say "Only people added to the file have access") | Only people who can already open the file | Yes | Nothing new is granted: it is a pointer, not a permission |

Two more sharing records complete the set. Sharing straight with a named person already in your directory logs \`SharingSet\`. Inviting an outsider to a whole site logs \`SharingInvitationCreated\`, then \`SharingInvitationAccepted\` when they accept.

### Reading a SharePoint audit record

You met the Unified Audit Log (UAL) and Purview audit search in the prerequisite room. Here is what a SharePoint or OneDrive record says, field by field. Three fields split one file path into parts:

\`\`\`text
ObjectId           https://nexacorp.sharepoint.com/sites/BidTeam/Shared Documents/Design/Stadium_v3.pdf
SiteUrl            https://nexacorp.sharepoint.com/sites/BidTeam/
SourceRelativeUrl  Shared Documents/Design
SourceFileName     Stadium_v3.pdf
\`\`\`

SiteUrl, then SourceRelativeUrl, then SourceFileName, joined together, give ObjectId. Read a path from the outside in: the host (with -my or without), then /sites/ or /personal/, then the site name, then the library and folders.

| Field | What it tells you |
|---|---|
| Workload | SharePoint or OneDrive. The first fork: a shared site, or one person's own storage |
| RecordType | 6 for file operations (SharePointFileOperation), 14 for sharing (SharePointSharingOperation), 4 for other SharePoint events such as permission changes |
| Operation | What happened: FileDownloaded, AnonymousLinkCreated, AddedToGroup and so on |
| UserId | Who did it. A name containing #EXT# is a guest. On AnonymousLinkUsed it is anonymous, or an ID starting with urn:spo:anon, never a person. app@sharepoint means an app with SharePoint app-only access acted, not a person |
| UserType | What kind of identity acted: 0 a regular user, 2 an admin, 4 the system, 5 an application, 6 a service principal. A 5 or a 6 means software acted, not a person at a keyboard |
| ClientIP | The address SharePoint saw: an office egress, a home connection, a VPN or a cloud host |
| UserAgent | The client: a browser, the OneDrive sync app, or a script or tool |
| EventSource | SharePoint or ObjectModel: which part of SharePoint raised the event |
| ApplicationDisplayName and ApplicationId | The app that acted. An unfamiliar app pulling many files is a lead to check in Entra ID's enterprise applications |
| ListItemUniqueId | The file's ID. Filter on it to collect every record about that one file |
| AppAccessContext.AADSessionId | The Entra session behind the action. Match it to the sign-in log to find the sign-in, and often the device, that the action came from |
| TargetUserOrGroupName and TargetUserOrGroupType | Sharing records only: who received access, and whether that is a Member, Guest, SharePointGroup, SecurityGroup or Partner |

Know the limits of the log before you trust a gap in it:
- **It is on by default** for enterprise tenants, but some records need Audit (Premium) licences.
- **It is late.** For SharePoint, OneDrive and Teams, records typically arrive 60 to 90 minutes after the event, and sometimes later. A search five minutes after an alert can come back empty.
- **It expires.** Audit (Standard) keeps 180 days. With Audit (Premium), SharePoint, OneDrive, Exchange and Entra records are kept one year.
- **You can query it in four places:** Purview Audit search, Search-UnifiedAuditLog in Exchange Online PowerShell, the OfficeActivity table in Microsoft Sentinel, and CloudAppEvents in Microsoft Defender XDR advanced hunting.

The operations you will use most, grouped by what they mean:

| Group | Operations | Note |
|---|---|---|
| Reading | FileAccessed, FilePreviewed | FileAccessed is not logged again for the same user and file within five minutes |
| Taking a copy | FileDownloaded (browser), FileSyncDownloadedFull (OneDrive sync app), FileCopied, FileMoved | Count all of them, not only FileDownloaded |
| Changing | FileUploaded, FileSyncUploadedFull, FileModified, FileRenamed, FileDeleted, FileRecycled, FileRestored | A burst of FileModified and FileRenamed to an unknown extension can mean ransomware |
| Sharing | AnonymousLinkCreated, AnonymousLinkUsed, AnonymousLinkRemoved, CompanyLinkCreated, SecureLinkCreated, AddedToSecureLink, SharingSet, SharingInvitationCreated, SharingInvitationAccepted, SharingRevoked | All carry RecordType 14 |
| Permissions | AddedToGroup, GroupAdded, SiteCollectionAdminAdded, SharingInheritanceBroken | GroupAdded also fires the first time a user creates a sharing link in their OneDrive |
| Admin | SharingPolicyChanged, SiteCollectionCreated, HubSiteJoined | SharingPolicyChanged lists the changed setting in ModifiedProperties |

### Why it matters in an investigation: scoping a leak

When a file turns up where it should not be, four questions come before any judgement of how bad it is. The architecture answers each one.

| Question | What answers it | Evidence |
|---|---|---|
| 1. Which container held it? | The host and path: team site, channel site, communication site or OneDrive | SiteUrl, Workload, ObjectId |
| 2. Who could reach it? | The site's membership (the Microsoft 365 Group, the three SharePoint groups, Everyone except external users on a public team), any unique permissions, and every link on the file | Group membership in Entra ID, the site's permissions page, and the sharing records for that ObjectId |
| 3. What was touched? | Every read, copy and share of the file, and everything else the same identity or link touched | Operation, ObjectId and ListItemUniqueId, counted per UserId |
| 4. From where? | The network and client behind each access | ClientIP and UserAgent, then the user's sign-in log at the same time |

A worked example. NexaCorp's file Stadium_v3.pdf turns up at a rival firm.
1. Its FileDownloaded records carry SiteUrl /sites/BidTeam-Pricing. That is a private channel's site, so the starting reach is the channel's 6 members, not the team's 40.
2. Sharing records for the same ObjectId show AnonymousLinkCreated by one channel member, three days earlier. Now the reach is anyone who ever held that URL.
3. AnonymousLinkUsed shows two uses from 198.51.100.77 with a desktop browser UserAgent, and no named user.
4. Next: ask the link's creator why it was made, remove the link, look for every other Anyone link that person created, and pull their sign-in log around the creation time.

### Classic pitfalls

- **"The file was posted in the team's chat, so check the team site."** A file sent in a 1:1 or group chat is in the sender's OneDrive, under Microsoft Teams Chat Files. The team site has no record of it.
- **"The team has 40 members, so 40 people could see it."** A private or shared channel is a separate site with its own members. Check whether the SiteUrl ends in a channel name.
- **"There is an Anyone link, so the file leaked."** A link is exposure. Only AnonymousLinkUsed proves access. Never report one as the other.
- **"No sign-in at that time, so the user did not do it."** A stolen session token acts without any new interactive sign-in. Check the non-interactive sign-in log and AADSessionId.
- **"Limited Access means they could read the site."** It only means that one item inside was shared with them.
- **"The site is in the Projects hub, so the hub's members could open it."** A hub changes navigation and search, never permissions.
- **"There is no FileDownloaded, so nothing was copied."** The sync app logs FileSyncDownloadedFull, and opening a file in a desktop app can log only FileAccessed. Count all three.
- **"A public team is open only to its members."** Its Members group contains Everyone except external users, so every employee can open and edit its files.
- **"The chat messages will be in SharePoint too."** Messages are in Exchange mailboxes. Search them with eDiscovery, not with the SharePoint audit records.`,
      image: {
        src: "/lesson-images/m365/sharepoint-tenant-map.svg",
        alt: "Map of one Microsoft 365 tenant. The tenant at the top holds the SharePoint admin center, the tenant sharing setting that caps every site, and the Entra ID directory of users, guests and groups. Below it sit four flat sites with their URLs and who controls access: a group-connected team site with its Documents library, standard-channel folders and a file; a private or shared channel site with its own members; a communication site with its Owners, Members and Visitors groups; and a OneDrive holding Microsoft Teams Chat Files and Recordings. A dashed hub bar links two sites as an association only. A table at the bottom maps a team, a standard channel, a private or shared channel, a chat file, a meeting recording and messages to where each is really stored.",
        caption: "The whole map: one tenant, flat sites with their own permissions, what sits inside a site, and where each part of Teams is really stored.",
        credit: "Figure authored for this course.",
      },
      checkpoint: {
        question: "An employee sent Pricing_Model.xlsx to a colleague in a 1:1 Teams chat, and the file later leaked. Where do the audit records for that copy of the file point?",
        options: [
          "To the team site's Documents library, inside the General folder",
          "To the colleague's Exchange mailbox, next to the chat message",
          "To the sender's OneDrive, in the Microsoft Teams Chat Files folder",
          "To the private channel site that the bid team uses for pricing",
        ],
        answer: 2,
        explanation:
          "A file sent in a 1:1 or group chat is uploaded to the sender's OneDrive, into Microsoft Teams Chat Files, and shared with the people in that chat. Its records carry Workload OneDrive and a SiteUrl under -my.sharepoint.com/personal/. The team site's General folder holds files posted in the General channel, not chat files. The colleague's mailbox holds a copy of the chat message, not the file. A private channel's site holds only that channel's own files.",
      },
    } satisfies ReadingTask,

    // ── Question 1 ────────────────────────────────────────────────────────────
    {
      type: "question",
      id: "spt-teams-q1",
      question: "An attacker creates an anonymous 'Anyone' link for a sensitive financial spreadsheet in SharePoint and shares the URL externally. What is the primary security limitation of this sharing method from a SOC analyst's perspective?",
      options: [
        "Anyone links grant view-only access, so the file itself cannot be downloaded",
        "Anyone links expire after 24 hours by default, so the access evidence disappears",
        "Anyone links need no sign-in, so logged access cannot be tied to a named person",
        "Anyone links bypass the Unified Audit Log, so creation and use are not recorded"
      ],
      answer: 2,
      explanation: "An **Anyone** link needs no authentication, so anyone holding the URL can open the file. Creation (`AnonymousLinkCreated`) and use (`AnonymousLinkUsed`, with client IP and user agent) are logged, but the use records have no identity: you can see that and from where the file was opened, not by whom. View-only is a choice made when the link is created, not a property of all Anyone links, and edit/download links are common. Expiry is an admin setting, not a fixed 24-hour default, and an expired link does not delete the audit records already written. The log does record both events, so the problem is attribution, not missing records.",
      xp: 30,
    } satisfies QuestionTask,

    // ── Reading 2: Microsoft Teams Security ───────────────────────────────────
    {
      type: "reading",
      id: "spt-teams-r2",
      heading: "Microsoft Teams: How Outsiders Reach Your Users, and What the Logs Show",
      content: `**Microsoft Teams** is Microsoft 365's chat, call and meeting service, and attackers use it as a phishing channel that never passes the mail filter.
By the end of this reading you can name the four ways outsiders reach your users, read who acted from a record's fields, and scope a Teams phishing campaign.

### Teams in one line

The previous reading covered storage. A team is a Microsoft 365 Group plus a team site; files live in SharePoint and OneDrive; messages live in Exchange mailboxes. This reading is about **people**: who can talk to your users, and who can get into your teams.

### The four ways an outsider reaches your users

Think of your office building again. **External access** is the intercom at the front door: anyone outside can buzz, but nobody comes in. **Guest access** is a visitor badge for one floor. A **shared channel** is one meeting room with its own street door. An **anonymous meeting join** is a seat at a public talk.

| Path | What the outsider can do | Account in your directory? | What your user sees | Audit records it leaves |
|---|---|---|---|---|
| External access (federation between tenants) | Chat, call and meet with your users. No access to your teams, channels or files | No. They stay signed in to their own tenant | An External label. A first contact arrives as a message request the user must Accept | ChatCreated, MessageSent, UserAccepted |
| Guest access (Entra B2B collaboration) | Join a team as a member with the Guest role: its channels, its files, its team site | Yes: a guest account with #EXT# in its name | The person's name marked as a guest | MemberAdded on the team, with the #EXT# name in Members, and AddedToGroup on the team site |
| Shared channel (Entra B2B direct connect) | Work in one shared channel and its channel site, nothing else in the team | No. They sign in at home, and the channel shows their organisation | The person in the channel, marked as external | InviteSent and InviteeResponded, then file records on the channel site |
| Anonymous meeting join | Join one meeting from its link, without signing in | No | A participant who is not verified | MeetingParticipantDetail |

Only a guest is ever inside your tenant. An external access contact has no account in your Entra ID and cannot open your files.

### Who acted? Read it from the record

Every audit record names its actor. Never work it out by elimination ("nobody else signed in, so it must be..."). Read the fields:

| Actor | How it shows in the record | What it can reach |
|---|---|---|
| Member (employee) | A UPN (user principal name, the sign-in address) in your own domain, UserType 0 | Whatever its groups, sites and links allow |
| Guest | A UPN with #EXT#, for example partner_fabrikam.example#EXT#@nexacorp.onmicrosoft.com | The teams and sites it was added to |
| External access contact | The sender's own UPN in another tenant's domain, often a name.onmicrosoft.com. It appears in chat records only | Chats, calls and meetings. Never your files |
| Shared channel participant | Their home tenant's UPN, with no guest account in your directory | One shared channel and its site |
| App, bot or service principal | UserType 5 (application) or 6 (service principal), with the app named in AppAccessContext.ClientAppName or ApplicationDisplayName | Whatever permissions it was granted at install or consent, until someone removes it |
| Anonymous | No named identity, for example on AnonymousLinkUsed | Whatever the link opens |

**Apps and bots act on their own.** Bots, connectors, incoming webhooks and Workflows can post into channels under their own identity. A Graph app with the right permission can read messages in bulk, which writes MessagesListed or ChatRetrieved, records that only exist for Graph calls. So for any app you find, look for how it arrived: AppInstalled, BotAddedToTeam or ConnectorAdded in the audit log, and Consent to application in the Entra audit log.

**Tokens act without a new sign-in.** An attacker holding a stolen session cookie or refresh token works with no interactive sign-in at all. A quiet interactive sign-in log proves nothing: check the non-interactive sign-in log for the same user and time.

### The defaults that decide your exposure

- **External access is open by default.** Teams allows chat with every external domain until an admin switches to an allow list or blocks domains.
- **Blocking a domain does not block its subdomains**, unless the admin also sets BlockAllSubdomains.
- **Tenants with only trial licences are blocked by default** (ExternalAccessWithTrialTenants is Blocked). Tenants that pay, including compromised ones, are not.
- **Unmanaged Teams accounts** (personal Microsoft accounts) have their own switch, with a separate option for whether those people may start a conversation.

One command shows all of it. Run it at the start of any Teams phishing case:

\`\`\`powershell
Get-CsTenantFederationConfiguration | Format-List AllowFederatedUsers, AllowedDomains, BlockedDomains, BlockAllSubdomains, AllowTeamsConsumer, AllowTeamsConsumerInbound, ExternalAccessWithTrialTenants
\`\`\`

### How attackers use Teams

Phishing over a chat service is MITRE ATT&CK technique T1566.003, Spearphishing via Service. These are the patterns you will meet:

| Pattern | How it works | Seen in the wild | What to look for |
|---|---|---|---|
| Fake help desk over external access | The attacker renames a tenant, or adds an onmicrosoft.com subdomain with a security-sounding name, then messages staff as IT support | Midnight Blizzard, 2023: compromised small-business tenants, and a request to type a code into a Microsoft Authenticator prompt, which approved the attacker's own sign-in | A message request from an External sender, then a successful sign-in for the same user from an unfamiliar IP |
| Inbox flood, then a help-desk chat or call | The user's mailbox is buried in junk mail. The "help desk" offers to fix it and asks the user to start Quick Assist, Windows' built-in remote support tool, then installs remote management tools | Storm-1811, 2024, ending in ransomware | quickassist.exe, then a remote management tool, starting on the endpoint soon after an external chat. Remote access tools are technique T1219 |
| Mass phishing with a tool | TeamsPhisher, a public red-team tool, sends messages and file links to many users in another tenant | Storm-0324, 2023. Storm-1674 used tools like it to spread the DarkGate malware | Many ChatCreated records from one external sender to many users within minutes |
| Phishing from a hijacked colleague | A taken-over internal account messages coworkers, who trust the name. Internal spearphishing, T1534 | Common after any account compromise | Messages with links from a user whose sign-in log shows an unfamiliar location |
| Guest abuse | A guest account that is stolen, or one left behind after a project, reads everything in the team site | Any long-lived partner team | FileDownloaded by a #EXT# UserId on a team site, and guests that no one has reviewed |
| A risky app | A user is tricked into consenting to an app, or adds an app or bot to a team, and it then acts with whatever permissions it was granted | OAuth consent phishing | Consent to application in the Entra audit log, AppInstalled or BotAddedToTeam on the team, then records where that app is the actor |

In Microsoft Defender XDR, the advanced hunting tables MessageEvents, MessagePostDeliveryEvents, MessageUrlInfo and UrlClickEvents cover Teams messages and link clicks. CloudAppEvents carries Teams activity collected by Defender for Cloud Apps.

### The Teams audit records you will use

Every Teams record in the Unified Audit Log carries \`Workload\` MicrosoftTeams. Know what each one means, and when it is not written.

| Operation | What it means | Watch out |
|---|---|---|
| ChatCreated | A new chat was created | For a chat with another organisation, every participating tenant gets the record |
| MessageSent | A message was posted in a chat or a channel | For chats, it is written only when guests, external users or anonymous users take part. A chat between two employees leaves none |
| MessageCreatedHasLink, MessageEditedHasLink | A message containing a URL was sent, or a URL was added by an edit | The address is in MessageURLs |
| UserAccepted, UserBlocked | The user accepted, or blocked, a message from someone they had never contacted | Accepting an External stranger is the moment a lure lands |
| TeamsImpersonationDetected | Teams flagged an external sender as a possible impersonator | ImpersonationType says whether of a brand, a domain or a user |
| MemberAdded, MemberRemoved, MemberRoleChanged | A member was added to, removed from, or changed in a team, channel or group chat | A #EXT# name in Members is a guest |
| TeamCreated, ChannelAdded | A team or a channel was created | A new private or shared channel also creates a new site |
| AppInstalled, BotAddedToTeam, ConnectorAdded | An app, a bot or a connector was added | AddOnName names it. Check who added it, and what it is allowed to do |
| TeamsSessionStarted | A user signed in to a Teams client | Token refreshes are not captured |
| MessageDeleted | A chat or channel message was deleted | Written only with Audit (Premium) licences |
| MessagesListed, MessageHostedContentsListed, ChatRetrieved, MessagesExported | Messages, or the images and files inside them, were read in bulk or exported | Written only when done through the Microsoft Graph API, so they point to an app or a script, not to the Teams client |

### Why it matters in an investigation: scoping a reported chat

A user reports a strange Teams chat. You work from records, not from the chat window. Five questions, in order, each with its own log.

1. **Who is the sender, really?** Ignore the display name: the attacker typed it. Read the sender's address and domain, and check whether the chat carried the External label. An onmicrosoft.com address in another tenant is not your IT department.
2. **Did the user engage?** Look for UserAccepted, and for MessageSent records from your user in that chat. A user who never accepted saw only a preview.
3. **What was asked, and was it done?** For a link: MessageCreatedHasLink and UrlClickEvents. For a code typed into an MFA prompt: the user's sign-in logs around the chat time, interactive and non-interactive, looking for a success from an unfamiliar IP. For remote support: quickassist.exe or another remote tool starting on the user's device, in your EDR (endpoint detection and response) process events.
4. **Who else did the sender reach?** Search ChatCreated and MessageSent for the same external domain across all users. A campaign hits dozens of people, and often only one reports.
5. **Contain.** Block the domain in Teams external access, or in Defender's Tenant Allow/Block List if your admins let the security team manage it. Revoke sessions and reset the password if an MFA prompt was approved. Isolate the device if a remote session was granted.

### Classic pitfalls

- **"The display name says Microsoft Security."** A display name is text chosen by whoever owns the other tenant. The domain and the External label are the evidence.
- **"No sign-in at that time, so it wasn't them."** A stolen token needs no new interactive sign-in. Read the non-interactive sign-in log, and read the record's own actor fields.
- **"There is no MessageSent, so they never talked."** Chats between two employees never write MessageSent. The messages themselves are in Exchange mailboxes, so use an eDiscovery content search.
- **"The external contact must be in Entra ID."** An external access contact has no account in your tenant. A file they "attach" is a link into their own tenant's storage, which your audit log never sees.
- **"We blocked example.com, so login.example.com is blocked too."** Not unless subdomain blocking is on.
- **"A guest and an external contact are the same thing."** A guest has a #EXT# account and real access to a team's files. A compromised guest is a data incident, not just a phishing case.`,
      diagram: `flowchart LR
  OUT["Person in another organisation"]
  OUT -->|"External access"| CHAT["Chats, calls and meetings with your users"]
  OUT -->|"Guest access"| GUEST["Guest account in your Entra ID"]
  GUEST --> TEAM["Membership of one team"]
  TEAM --> SITE["That team's site and files"]
  OUT -->|"Shared channel"| CH["One shared channel, signed in at home"]
  CH --> CHS["That channel's own site only"]
  OUT -->|"Anonymous join"| MEET["One meeting, from its link"]`,
      diagramCaption: "Four doors for an outsider, and how far each one reaches",
      checkpoint: {
        question: "An employee gets a Teams chat from “IT Help Desk”, a sender in another organisation's tenant. That sender is not a member of any of your teams. Which Teams feature delivered the message?",
        options: [
          "External Access, which lets other tenants start chats with your users",
          "Guest Access, through a B2B guest account added to one of your teams",
          "A compromised internal account renamed to look like the help desk",
          "A Teams app installed in your tenant that posts messages as a bot",
        ],
        answer: 0,
        explanation:
          "External Access (federation between tenants) lets anyone in another tenant start a chat with your users, and by default it is open. That is the path abused by fake help-desk tenants and by tools like TeamsPhisher. Guest Access would require the sender to be added to one of your teams as a #EXT# guest, which the scenario rules out. A compromised internal account would sit in your own tenant, not another organisation's. A bot from an installed app is also part of your tenant and would show up as an AppInstalled event, not as an external sender.",
      },
    } satisfies ReadingTask,

    // ── Question 2 ────────────────────────────────────────────────────────────
    {
      type: "question",
      id: "spt-teams-q2",
      question: "FileDownloaded events on your Finance SharePoint site show the user `vendor_externalco.com#EXT#@corp.onmicrosoft.com`. What does this UPN tell you, and what should you check first?",
      options: [
        "A sync service principal; check which permissions the app registration holds",
        "A B2B guest from externalco.com; check which team or site granted it access",
        "A hybrid-synced on-prem account; check AD Connect for a broken UPN rewrite",
        "An External Access chat contact; check the Teams federation allow list"
      ],
      answer: 1,
      explanation: "`#EXT#` marks an **Entra ID (Azure AD) B2B guest**: an external user (vendor@externalco.com, with @ replaced by _) invited into your tenant. Guests reach files through the team or site they were added to, so the first question is which membership gave this vendor access to Finance data. A service principal has no UPN of this form. A hybrid-synced employee keeps a normal corp.com-style UPN. External Access contacts chat from their own tenant and get no account in yours, so they cannot appear as a user downloading your SharePoint files.",
      xp: 30,
    } satisfies QuestionTask,

    // ── Reading 3: DLP and Insider Threat ─────────────────────────────────────
    {
      type: "reading",
      id: "spt-teams-r3",
      heading: "Purview DLP and Insider Risk: What People Do With Access They Already Have",
      content: `**Data Loss Prevention (DLP)** in Microsoft Purview inspects content while people use it, and acts when sensitive data heads somewhere it should not go. **Insider risk** is the threat from people who already have legitimate access.
By the end of this reading you can read a DLP record, tell an override from a policy change, and work a bulk-download case to the hand-off to HR and Legal.

### How a DLP policy is built

An airport scanner checks what is in the bag, not who carries it. DLP does the same with content: it looks inside the file or message, whoever sends it.

A **policy** says where it applies and holds one or more **rules**. Each rule has conditions and actions.

| Part | What it is | Concrete examples |
|---|---|---|
| What to look for | Sensitive information types (SITs): patterns plus supporting evidence. Each match is scored High, Medium or Low confidence, and counted | Credit card number, IBAN (international bank account number), U.S. Social Security number, U.K. National Insurance number, a custom pattern for your own project codes. A sensitivity label on the file can also be a condition |
| Where | The locations the policy covers | Exchange email, SharePoint sites, OneDrive accounts, Teams chat and channel messages, Windows and macOS devices (Endpoint DLP), on-premises file shares, Power BI, Microsoft 365 Copilot |
| How much | A threshold in the condition | "10 or more credit card numbers at high confidence, shared with people outside the organisation" |
| What to do | The actions | Audit only. Show a policy tip. Block, but let the user override with a justification. Block outright. Remove access for people outside the organisation. On devices, audit or block a copy to USB |
| Who hears about it | Alerts and notifications | An alert with a severity, an incident report by email, a notice to the user |

A policy can run in **simulation mode** first. It then logs matches but takes no action, so a match from a simulated policy was never blocked.

### The DLP records in the audit log

Every DLP match goes to the Unified Audit Log and to Purview's Activity explorer. DLP records always carry UserKey DlpAgent. Three operations matter:

| Operation | Where it exists | What it means |
|---|---|---|
| DlpRuleMatch | Exchange, SharePoint, OneDrive, Teams, devices | A rule matched. The record names the policy and rule, the actions taken, the severity, and each sensitive type found with its count and confidence |
| DlpRuleUndo | SharePoint and OneDrive only | An action taken earlier was lifted. ExceptionInfo.Reason says why: Override, Document Change or Policy Change. For an override, Justification holds the user's own words |
| DlpInfo | SharePoint and OneDrive only | The user marked a match as a false positive, and no action was lifted |

In Exchange there is no separate undo record: the override and false-positive details sit inside DlpRuleMatch itself. In Teams, a blocked message is hidden from its recipients, and the sender is told it was blocked.

Here is a trimmed DlpRuleMatch for a SharePoint file, with the fields you read first:

\`\`\`json
{
  "CreationTime": "2026-11-18T13:52:07",
  "Operation": "DlpRuleMatch",
  "RecordType": 11,
  "Workload": "SharePoint",
  "UserKey": "DlpAgent",
  "UserId": "r.haddad@nexacorp.com",
  "ObjectId": "https://nexacorp.sharepoint.com/sites/Payroll/Shared Documents/Bonus_2026.xlsx",
  "PolicyDetails": [{
    "PolicyName": "Payroll data",
    "Rules": [{
      "RuleName": "Bank details shared outside",
      "Severity": "High",
      "RuleMode": "Enforce",
      "ConditionsMatched": { "SensitiveInformation": [{
        "SensitiveInformationTypeName": "International Banking Account Number (IBAN)",
        "Count": 212,
        "Confidence": 85
      }]}
    }]
  }],
  "SharePointMetaData": { "IsViewableByExternalUsers": true }
}
\`\`\`

How to read it:
- **Count and confidence.** One low-confidence card number in a chat is often noise. 212 high-confidence IBANs in one file means the file is the payroll data itself.
- **RuleMode.** Enforce means the actions ran. Audit modes mean the match was only recorded.
- **IsViewableByExternalUsers: true.** Someone outside the organisation can already open this file. That changes the priority at once.
- **Where alerts live.** DLP alerts stay 30 days in Purview's DLP Alerts dashboard and six months in the Defender portal. Activity explorer shows 30 days. The audit log keeps the records for its own retention period, which you met in the prerequisite room.

### Insider risk: the threat from within

An **insider** is a current or former employee, contractor or partner who misuses legitimate access to steal, damage or expose data. Three things make insiders hard to catch:
- They need no break-in: their access is already approved.
- They know where the valuable files are.
- Each action looks like work. Only the pattern, compared with their own normal, gives them away.

**Microsoft Purview Insider Risk Management** is a separate tool from DLP. It joins signals into a risk score per user, and shows users under pseudonyms by default to protect privacy. Each policy starts from a template:

| Template | What starts the scoring | Signals it then weighs |
|---|---|---|
| Data theft by departing users | A resignation or end date imported by the HR connector, or the account being deleted from Entra ID | Downloads from SharePoint, printing, copies to USB or to personal cloud storage |
| Data leaks | A high-severity DLP alert, or chosen indicators | Sharing and exfiltration activity after the trigger |
| Data leaks by risky users, or by priority users | HR signals such as a performance improvement plan, or membership of a group marked as priority | The same signals, scored higher |
| Security policy violations | Alerts from Microsoft Defender for Endpoint | Attempts to disable or evade security tools, installing unwanted software |

### Behavioural indicators you can find in the audit log yourself

You do not need Insider Risk Management to spot these. There is no universal "normal" number of downloads: measure each person against their own history and their peers. Each indicator has a benign look-alike, which is why one signal alone is never a verdict.

| Indicator | How to measure it | Example | Benign look-alike |
|---|---|---|---|
| Bulk copying | Count FileDownloaded, FileSyncDownloadedFull and FileCopied per user per session, and compare with that person's own last 30 days and with peers in the same role | Far more files in one evening than the user's usual month | A records clerk archiving a finished project |
| New territory | Sites or folders the user did not open in the previous 30 days | A sales account opening Legal and HR libraries | A new role, or a project handover |
| Unusual hours | Activity outside the user's normal hours, in their own time zone | 02:00 on a Saturday | Travel, a deadline, shift work |
| Sensitive sources | Activity on Finance, HR, Legal or research sites | Downloads from /sites/Payroll | The user's own team works there |
| Outbound sharing | AnonymousLinkCreated, or SecureLinkCreated with AddedToSecureLink naming a personal address | A Specific people link to a webmail address with the user's own surname | A link to a real client's corporate address |
| Whole-library sync | Many FileSyncDownloadedFull records from a library the user rarely opens | A full bids library synced to a laptop | Setting up a new laptop |
| Repeated overrides | DlpRuleUndo with Reason Override, several times | "client asked for it", three times in a day | A real client request, confirmed by the account owner |

Microsoft Defender for Cloud Apps watches some of these for you. Its policy template **Mass download by a single user** alerts at more than 50 downloads in one minute by default. **File shared with personal email addresses** catches the outbound pattern. Its anomaly detections also flag unusual file download and file share activity per user, and OAuth apps that download files unusually.

### What a download proves, and what it does not

Be precise about what a download proves. It only moves files from SharePoint onto a device. MITRE ATT&CK (the public catalogue of attacker behaviour) files that under the Collection tactic: gathering data the attacker wants, here technique T1213.002. It counts as Exfiltration, the tactic for stealing data out of the organisation, only once you have evidence of that next step. That evidence is a USB copy, an upload to personal cloud storage (T1567.002) or a large outbound email.

Two blind spots matter here:
- **The sync label can be faked.** The OneDrive sync app logs FileSyncDownloadedFull, while a browser download logs FileDownloaded. A tool that sends the sync app's UserAgent (it contains "SkyDriveSync") gets its downloads recorded as sync events. Count both kinds in any volume rule.
- **Open in app.** Opening a file through the desktop app's link can be logged only as FileAccessed, with no download record. Microsoft treats this as by design.

### Practical investigation workflow

When a DLP alert or a bulk-download alert arrives:

1. **Read the alert.** Note the user, the policy and rule, the counts and the confidence, and whether the content is viewable by outsiders.
2. **Search the audit log.** In Microsoft Purview (purview.microsoft.com, then Audit), search the user's FileDownloaded, FileSyncDownloadedFull, FileCopied and FileAccessed operations for the last 24 to 72 hours. Search a normal week before it too, as a baseline.
3. **Group by container.** Group the records by SiteUrl. Which sites, and are they ones this user normally works in?
4. **Check where from.** Read ClientIP and UserAgent: the corporate egress or a home connection, a managed laptop or an unknown device, the sync app or a browser.
5. **Look for sharing.** Search the same user for AnonymousLinkCreated, SecureLinkCreated with AddedToSecureLink, and SharingInvitationCreated to outside addresses.
6. **Follow the next hop.** On the endpoint: USB copies, archives, uploads to personal cloud storage. In mail: large messages to personal addresses.
7. **Get context through the right door.** Ask HR whether the person is leaving, on an improvement plan, or under investigation. Then escalate to HR and Legal together. Preserve the evidence, and never confront the employee yourself: insider cases carry legal and employment consequences.

In Microsoft Sentinel, steps 2 and 3 are one query. The same records sit in the OfficeActivity table, where SharePoint's SiteUrl is called Site_Url. This lists everyone who took a copy from a site, by any route:

\`\`\`kql
OfficeActivity
| where TimeGenerated > ago(3d)
| where Site_Url has "Payroll"
| where Operation in ("FileDownloaded", "FileSyncDownloadedFull", "FileCopied")
| summarize count() by UserId
\`\`\``,
      diagram: `flowchart LR
  A["User shares, uploads or sends content"] --> B{"Does a DLP rule match?"}
  B -->|"No"| Z["No DLP record"]
  B -->|"Yes"| C["DlpRuleMatch in the audit log"]
  C --> D["Actions: tip, block, or block with override"]
  D -->|"User overrides"| E["DlpRuleUndo, Reason Override, with justification"]
  D -->|"False positive, nothing lifted"| F["DlpInfo"]
  C -->|"Rule raises an alert"| G["Alert in Purview and the Defender portal"]
  G --> H["Analyst: audit search, sharing records, endpoint, then HR"]`,
      diagramCaption: "One DLP match, the records it writes, and where the analyst picks it up",
      checkpoint: {
        question: "A SharePoint file's DlpRuleUndo record shows ExceptionInfo.Reason set to Document Change. What happened?",
        options: [
          "The user overrode the policy tip and typed a business justification",
          "An admin edited the DLP policy, and the file was evaluated again",
          "The file was edited until it no longer matched, so the action was lifted",
          "The user marked the match as a false positive, and nothing was lifted",
        ],
        answer: 2,
        explanation:
          "Document Change means the content itself changed so that the rule no longer matched, for example the sensitive numbers were removed, and the earlier action was lifted. A user override carries Reason Override and the user's justification. A policy edit that triggers re-evaluation carries Reason Policy Change. A false positive that lifts nothing is logged as DlpInfo, not as DlpRuleUndo.",
      },
    } satisfies ReadingTask,

    // ── Question 3 ────────────────────────────────────────────────────────────
    {
      type: "question",
      id: "spt-teams-q3",
      question: "HR suspects that a departing employee copied Finance files from SharePoint last week. No alert fired. Where do you look for that user's FileDownloaded operations?",
      options: [
        "Message Trace in the Exchange Admin Center",
        "The user's Entra ID sign-in logs for last week",
        "Audit search (Unified Audit Log) in Microsoft Purview",
        "The tenant sharing settings in the SharePoint Admin Center"
      ],
      answer: 2,
      explanation: "SharePoint file operations such as `FileDownloaded`, `FileSyncDownloadedFull` and `AnonymousLinkCreated` are recorded in the **Unified Audit Log**, which you search in the Microsoft Purview portal (purview.microsoft.com → Audit). They are there whether or not an alert fired. Message Trace tracks email delivery, not file activity. Sign-in logs show when and from where the user authenticated, not which files they took. The SharePoint Admin Center sharing page sets tenant policy (for example, whether Anyone links are allowed) and holds no record of user activity.",
      xp: 30,
    } satisfies QuestionTask,

    // ── Log Analysis: Bulk SharePoint Download ────────────────────────────────
    {
      type: "log_analysis",
      id: "spt-teams-la1",
      heading: "Mass File Download Alert: SharePoint",
      context: "You are reviewing alerts in the Microsoft Purview compliance portal. A bulk-download alert has fired for a user in the Finance department. The alert counted 847 FileDownloaded operations from the Finance site in 4 minutes; below is one of them, the audit record exactly as the Unified Audit Log stores it. The user's last day of employment is in 3 days according to HR records. The office reaches Microsoft 365 through one public egress address, 203.0.113.60.",
      event: {
        id: "spt-la1-001",
        ts: "2025-11-21T22:47:15.000Z",
        source: "sharepoint",
        event_type: "sharepoint_download",
        severity: "high",
        description: "FileDownloaded on the Finance SharePoint site by departing.employee@corp.com",
        user_email: "departing.employee@corp.com",
        src_ip: "203.0.113.60",
        mitre_technique: "T1213.002",
        mitre_tactic: "Collection",
        vendor: "Microsoft 365 Unified Audit Log",
        // One SharePoint FileDownloaded record (Unified Audit Log, as the SIEM indexes it). The
        // count of 847 is the Purview alert's, in the context; a single record never carries it.
        raw: {
          "data.office365.CreationTime": "2025-11-21T22:47:15",
          "data.office365.Id": "9b3e6f12-7c44-4d0a-a1e5-2f8c6d07b341",
          "data.office365.Operation": "FileDownloaded",
          "data.office365.OrganizationId": "5c2a8e41-0d6b-4f3e-9a17-b84c2e9d6f03",
          "data.office365.RecordType": "6",
          "data.office365.UserType": "0",
          "data.office365.Version": "1",
          "data.office365.Workload": "SharePoint",
          "data.office365.UserId": "departing.employee@corp.com",
          "data.office365.ClientIP": "203.0.113.60",
          "data.office365.UserAgent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36 Edg/130.0.0.0",
          "data.office365.EventSource": "SharePoint",
          "data.office365.ItemType": "File",
          "data.office365.ObjectId": "https://corp.sharepoint.com/sites/Finance/Shared Documents/Q4_Revenue_Report.xlsx",
          "data.office365.SiteUrl": "https://corp.sharepoint.com/sites/Finance/",
          "data.office365.SourceRelativeUrl": "Shared Documents",
          "data.office365.SourceFileName": "Q4_Revenue_Report.xlsx",
          "data.office365.SourceFileExtension": "xlsx",
          "data.office365.ListItemUniqueId": "a7f9c2e1-3b5d-4e86-9c01-6d2f8a4b7e53"
        },
      } satisfies TelemetryEvent,
      questions: [
        {
          question: "Using the alert, the raw record and the HR context, how should you classify this event?",
          options: [
            "Benign: the OneDrive sync client re-downloading the library after a laptop refresh",
            "Likely insider data theft before departure; escalate to IR, HR and Legal now",
            "Expected: Finance staff pull large report sets during the month-end close",
            "Low priority: the client IP is the office's own egress, so the files stayed inside the company network"
          ],
          answer: 1,
          explanation: "The signals converge: 847 files in 4 minutes from the Finance site, late in the evening (22:47 UTC), by a user who leaves in 3 days. That is the classic pre-departure pattern, so escalate and preserve evidence. A sync-client re-download is the plausible benign story, but the sync client logs `FileSyncDownloadedFull`, and this record's Operation is `FileDownloaded`, a direct download. 21 November is not month-end, and month-end work would not explain this volume at this hour. The office egress address only shows the download came from inside the office; from the laptop that made it, the files can still go out by USB, personal cloud or email.",
          xp: 40,
        },
        {
          question: "The alert only captures FileDownloaded operations inside SharePoint. Which MITRE ATT&CK tactic does this bulk-download activity fall under, and what would you still need to confirm to prove data actually left the organisation?",
          options: [
            "Exfiltration: a FileDownloaded record means the files have already left the company",
            "Collection: data is gathered onto a device; a later transfer out still needs proof",
            "Discovery: the user is enumerating the site's contents before choosing what to take",
            "Initial Access: the T1213.002 mapping marks how the user first reached the site"
          ],
          answer: 1,
          explanation: "Pulling files out of a repository such as SharePoint onto a device is **Collection** (T1213.002 is a Collection technique). The data is gathered, but nothing in this record shows it leaving the organisation. To prove exfiltration you need follow-on evidence such as a USB copy, an upload to personal cloud storage or a large outbound email. Calling it exfiltration already is the common misreading: the download went to a device behind the office egress. Discovery would be browsing or listing content, but here the files themselves were downloaded. The user already had legitimate access, so there is no Initial Access, and T1213.002 is not an Initial Access technique.",
          xp: 40,
        },
      ],
    } satisfies LogAnalysisTask,

    // ── Flag Task ─────────────────────────────────────────────────────────────
    {
      type: "flag",
      id: "spt-teams-f1",
      prompt: "To prove exfiltration you must find the endpoint that now holds the downloaded Finance files, then check its USB, personal-cloud and email activity. Using the bulk-download log above, which address do you look up in the firewall's NAT log for 22:43 to 22:47 UTC to find that endpoint?",
      answer: "203.0.113.60",
      hint: "The audit record notes where each download request came from: the office's public egress, which the firewall's NAT log maps back to the internal laptop.",
      xp: 50,
    } satisfies FlagTask,

  ],
};

// ---------------------------------------------------------------------------
// Room 3 — Endpoint Security Fundamentals
// ---------------------------------------------------------------------------

const endpointSecurityFundamentals: Room = {
  id: "endpoint-security-fundamentals",
  title: "Endpoint Security Fundamentals",
  description:
    "Learn what an endpoint is, how security technology evolved from simple antivirus to modern EDR and XDR, how to read an EDR alert, and how analysts use endpoint tools to investigate and contain threats.",
  difficulty: "beginner",
  category: "Endpoint Security",
  estimatedMinutes: 45,
  xp: 220,
  icon: "💻",
  prerequisites: ["windows-fundamentals"],
  tasks: [
    // ── Reading 1: AV Evolution ───────────────────────────────────────────────
    {
      type: "reading",
      id: "ep-sec-r1",
      heading: "From Antivirus to EDR: The Evolution of Endpoint Security",
      content: `**What is an Endpoint?**

An **endpoint** is any device that connects to a network and can be a target for attack. In a corporate environment, this includes:
- **Laptops and desktops**: The most common endpoints. Used by employees daily.
- **Servers**: High-value targets. They host applications, databases, and sensitive data.
- **Mobile devices**: Smartphones and tablets that connect to company email and apps.
- **IoT devices**: Security cameras, badge readers, smart thermostats, industrial sensors. These are increasingly connected to corporate networks and often have weak security.

**Why Endpoints?**

Attackers target endpoints because they are where humans interact with technology. A human can be tricked into clicking a phishing link, downloading a malicious file, or entering credentials on a fake website. Once an attacker has code running on an endpoint, they can steal data, move to other systems, or deploy ransomware.

---

**Generation 1: Traditional Antivirus (AV), The Signature Era (1987–2010s)**

Traditional antivirus works like a criminal wanted-poster database. Every known piece of malware is given a unique "fingerprint" called a **signature**: a pattern of bytes found in that specific malware file. When the AV scans a file, it compares it against this database of signatures. If there is a match → malware detected.

**Limitation**: Traditional AV is completely blind to **new malware it has never seen before** (zero-day malware). Attackers figured out that if they change the malware slightly (polymorphic malware) or pack it differently, the signature no longer matches and AV misses it entirely. By the early 2010s, attackers were generating thousands of new malware variants per day, and signature databases simply couldn't keep up.

---

**Generation 2: NGAV, Next-Generation Antivirus (2012–present)**

**NGAV** abandoned pure signature matching in favour of:
- **Behavioural detection**: Instead of asking "does this file match a known bad signature?", NGAV asks "is this process *behaving* like malware?", for example, does it enumerate all files and start encrypting them? That behaviour pattern is ransomware, even if the file has never been seen before.
- **Machine learning**: Models trained on millions of malware samples can detect new malware based on subtle characteristics, even without an exact signature match.
- **Memory scanning**: Detecting malicious code that runs only in memory without ever writing to disk (fileless malware).
- **Exploit prevention**: Blocking exploitation techniques like buffer overflows and code injection, regardless of the specific vulnerability being exploited.

Products like **CrowdStrike Falcon Prevent**, **SentinelOne Singularity**, and **Microsoft Defender Antivirus** are NGAV solutions.

---

**Generation 3: EDR, Endpoint Detection & Response (2013–present)**

**EDR** is a quantum leap beyond NGAV. Think of NGAV as an alarm system that beeps when someone breaks in. EDR is an alarm system *plus* a full security camera system *plus* a recording of everything that happened before and after the break-in.

EDR's defining characteristic is **continuous monitoring and telemetry recording**. An EDR agent on every endpoint silently records everything:
- Every process that starts (name, command line, parent process, user)
- Every file created, modified, or deleted
- Every network connection made (destination IP, port, process that made it)
- Every registry key changed
- Every PowerShell or script executed

This **telemetry stream** flows to a central cloud platform where it is analysed in real time. This enables:

1. **Threat detection**: Alert when a behaviour pattern matches a known attack technique.
2. **Investigation**: When an alert fires, analysts can look back through the recorded telemetry to understand exactly what happened, a full **process tree** showing parent → child process chains.
3. **Remote response**: Isolate a compromised laptop from the network with one click, kill a malicious process, delete a malicious file, all without touching the physical device.

**Key EDR vendors today (2026)**:
- **CrowdStrike Falcon Insight XDR**: Industry-leading threat intelligence and process telemetry depth.
- **SentinelOne Singularity**: Best autonomous response (can auto-remediate without analyst intervention, including ransomware rollback).
- **Microsoft Defender for Endpoint Plan 2 (MDE)**: Excellent value for Microsoft 365 E5 customers; deep Windows integration; native integration with Entra ID and Purview.
- **Palo Alto Cortex XDR**: Strong in mixed-OS environments (Windows, macOS, Linux).
- **VMware Carbon Black**: Popular in regulated industries.

---

**Generation 4: XDR, Extended Detection & Response (2019–present)**

**XDR** takes the EDR concept and extends it beyond the endpoint:
- **EDR**: Endpoint telemetry only
- **XDR**: Endpoint + Network + Identity + Email + Cloud in one unified platform

Instead of having separate tools for each domain that analysts must correlate manually, XDR correlates telemetry across all these sources automatically. An attack that starts with a phishing email → compromised credentials → lateral movement via PowerShell → data exfiltration to cloud storage can be visualised as a single correlated incident timeline in XDR, rather than scattered alerts across five different tools.

**Microsoft Defender XDR** is Microsoft's XDR platform, combining: Defender for Endpoint, Defender for Office 365, Defender for Identity, and Defender for Cloud Apps.`,
      checkpoint: {
        question: "According to the reading, what is the key limitation of traditional signature-based antivirus?",
        options: [
          "It can only inspect files on removable media such as USB drives, so malware written straight to the system drive is never scanned",
          "It is blind to new malware it has never seen before, and easily evaded by slightly modified (polymorphic) malware",
          "It runs only on Windows, because signature matching depends on NTFS alternate data streams that Linux and macOS filesystems do not provide",
          "It cannot function without a live internet connection, because every file hash must be checked against the vendor's cloud before the file is allowed to open",
        ],
        answer: 1,
        explanation:
          "Signature-based AV compares files against a database of known malware fingerprints, so it misses zero-day malware and can be evaded simply by changing the malware slightly so the signature no longer matches.",
      },
    } satisfies ReadingTask,

    // ── Question 1 ────────────────────────────────────────────────────────────
    {
      type: "question",
      id: "ep-sec-q1",
      question: "What is the fundamental difference between traditional signature-based antivirus and EDR (Endpoint Detection & Response)?",
      options: [
        "Traditional AV is a cloud-only service with no device software, while EDR runs wholly locally with no cloud console",
        "Traditional AV matches files against known-bad signatures; EDR records endpoint activity and detects behaviour for hunting",
        "EDR works only on Windows because it relies on ETW, so AV remains the only option for Linux and macOS",
        "Traditional AV can isolate a host on demand, whereas EDR is passive alerting with no containment"
      ],
      answer: 1,
      explanation: "The key difference is **scope and approach**. Traditional AV relies on known-bad **signatures**. It cannot detect new malware it has never seen before. EDR continuously records all endpoint telemetry (processes, files, network connections, registry changes) and applies **behavioural analysis** to detect threats regardless of whether they have known signatures. EDR also provides **visibility** for investigation (process trees, command lines, timelines) and **response** capabilities (host isolation, remote shell) that traditional AV completely lacks.",
      xp: 25,
    } satisfies QuestionTask,

    // ── Question 4 ────────────────────────────────────────────────────────────
    {
      type: "question",
      id: "ep-sec-q4",
      question: "What does XDR (Extended Detection & Response) add compared to EDR (Endpoint Detection & Response)?",
      options: [
        "XDR is the same endpoint-only telemetry as EDR behind a nicer incident dashboard",
        "XDR extends beyond the endpoint to network, identity, email and cloud data, correlated in one platform",
        "XDR replaces EDR's behavioural detection with a much larger signature database",
        "XDR is the mobile-device tier of EDR, covering iOS and Android handsets"
      ],
      answer: 1,
      explanation: "The 'X' in **XDR** stands for 'Extended'. It extends detection and response **across multiple security domains** beyond just the endpoint. While EDR sees only what happens on a single device, XDR correlates telemetry from endpoints, network traffic, identity systems (Active Directory, Entra ID), email (Exchange, phishing), and cloud workloads (AWS, Azure). This cross-domain correlation allows XDR to detect multi-stage attacks that would appear as disconnected, low-confidence signals in isolated tools. Microsoft Defender XDR, CrowdStrike Falcon XDR, and SentinelOne Singularity XDR are current examples.",
      xp: 25,
    } satisfies QuestionTask,

    // ── Reading 2: EDR Deep Dive ───────────────────────────────────────────────
    {
      type: "reading",
      id: "ep-sec-r2",
      heading: "EDR Deep Dive: What It Collects and What Analysts Do With It",
      content: `Now that you understand *what* EDR is, let's go deeper into *how* it works and what a SOC analyst actually does with EDR data.

**The EDR Agent**

Every endpoint protected by EDR has a small software program installed on it called an **agent** (also called a sensor or client). This agent runs silently in the background, consuming minimal CPU and memory, and does two things:
1. **Collects telemetry**: Records every process, file, network, and registry event.
2. **Enforces prevention**: Can block malicious behaviour in real-time (NGAV function).

The agent sends telemetry to a central **cloud platform** (e.g. CrowdStrike's Threat Graph, SentinelOne's SentinelCloud, or Microsoft's Defender for Endpoint in Azure). This is where detection rules run and analysts investigate.

**The Process Tree: The Most Powerful Investigation Tool**

Imagine you get an alert: "Suspicious PowerShell command detected on LAPTOP-JSMITH." You open the EDR console and see the **process tree**:

\`\`\`
explorer.exe (PID 1824)  ← User's desktop shell (normal)
  └─ outlook.exe (PID 3312)  ← Email client (normal)
       └─ winword.exe (PID 4456)  ← Word opened an attachment (suspicious!)
            └─ cmd.exe (PID 4892)  ← Word spawned a command prompt (very suspicious!)
                 └─ powershell.exe (PID 5102)  ← PowerShell with encoded command (malicious!)
\`\`\`

This chain tells an incredibly clear story: **a Word document was opened from Outlook, the document ran a macro that spawned cmd.exe, which then ran a malicious PowerShell command**. This is the classic "malicious Office macro" attack chain. Without a process tree, you'd just see a PowerShell alert with no context.

**EDR Telemetry Data Types**

| Data Type | Fields Recorded | Why It Matters |
|---|---|---|
| **Process events** | Process name, PID, parent process, command line, file hash, user, integrity level | Core of investigation, who ran what? |
| **File events** | File path, operation (create/modify/delete), hash, process that caused it | Detect malware being written to disk |
| **Network connections** | Process that made the connection, destination IP and port, bytes transferred | Detect C2 (command-and-control) communications |
| **Registry events** | Key path, operation, new value, process that changed it | Detect persistence mechanisms (malware setting itself to run at boot) |
| **User activity** | Login/logout events, authentication method | Detect lateral movement via stolen credentials |
| **DNS queries** | Domain queried, response IP, process that made the query | Detect malicious domain lookups |

**EDR Response Capabilities**

EDR platforms give analysts powerful remote response capabilities, all from a browser, without touching the physical machine:

- **Network Isolation (Host Isolation)**: Cuts the endpoint off from the network (except for the EDR management channel). The machine cannot talk to anything, not even internal servers. Used when a host is confirmed compromised, to prevent lateral movement. Technically it is one click in the console.
- **Kill Process**: Immediately terminate a malicious process running on the endpoint.
- **Delete File**: Remove a malicious file from the endpoint.
- **Live Response / Remote Shell**: Open a remote command-line shell on the endpoint for in-depth forensic investigation. SOC analysts can run commands, collect files, and examine artefacts without physically touching the device.
- **Run Containment Script**: Push a custom script to the endpoint (e.g. to disable a compromised service or quarantine a file).
- **Collect Forensic Package**: Collect a bundle of artefacts (event logs, memory dump, prefetch files, registry hives) from the endpoint for offline analysis.

**"One click" is the technical cost, not the real one.** This is the part that separates a console operator from an analyst, so be clear-eyed about it: isolation is an *outage you are choosing to cause*. Isolating a developer's laptop costs that person an afternoon. Isolating a domain controller, a database server, a payment gateway, or the PC running a hospital ward's medication system can be more damaging than the malware you are containing, and on a busy shift, under pressure, that is a genuinely easy mistake to make.

So before you isolate, answer three questions:
- **What does this asset do?** A hostname alone tells you nothing. Check the asset inventory or CMDB for its role, its business owner, and its criticality tier.
- **Who has to know?** Most organisations require the system owner to be notified, and many require a change/emergency-change approval for production systems. Some run a standing pre-authorisation for endpoints but not for servers: learn where that line sits in *your* environment, before you need it.
- **Is there a lighter option that still stops the bleeding?** Killing the malicious process, blocking one destination at the firewall, or disabling the compromised account will sometimes contain the incident without taking the whole host offline.

None of this means "hesitate while an attacker encrypts your file server." When the evidence is strong and the spread is active, isolate and explain afterwards: a short outage beats a domain-wide compromise. The point is that isolation is a *decision with a cost on both sides*, and a good analyst can say out loud why they judged the cost of acting to be lower than the cost of waiting.

**Endpoint Hardening, Reducing the Attack Surface**

EDR detects threats *after* they start. **Endpoint hardening** reduces the attack surface so fewer threats can start:
- **Attack Surface Reduction (ASR) rules** in Microsoft Defender: Block Office macros from spawning processes, block credential theft from LSASS, block executable content in email.
- **Application allowlisting**: Only run approved software. If it's not on the approved list, it can't run.
- **Least privilege**: Users run as standard users, not local administrators. Malware running as the user has limited rights.
- **BitLocker**: Full-disk encryption so stolen laptops don't expose data.
- **Patch management**: Keep the OS and applications updated to close known vulnerabilities.`,
      checkpoint: {
        question: "An analyst triggers Host Isolation on a laptop from the EDR console. With no exceptions configured, what can that laptop still talk to?",
        options: [
          "Internal servers, but nothing on the internet",
          "The EDR management channel, and nothing else",
          "The internet, but no other internal hosts",
          "Nothing at all, not even the EDR platform",
        ],
        answer: 1,
        explanation:
          "Host Isolation cuts the machine off from everything on the network, even internal servers, and the internet goes with it. Only the EDR management channel stays alive, because analysts still have to investigate and remediate remotely. Cutting that channel too would leave nobody able to reach the device without touching it.",
      },
    } satisfies ReadingTask,

    // ── Question 3 ────────────────────────────────────────────────────────────
    {
      type: "question",
      id: "ep-sec-q3",
      question: "A user's laptop is confirmed to be infected with malware that is actively spreading to other machines on the network. What is the most important immediate EDR response action?",
      options: [
        "Delete the malware file from disk, which also terminates the running instance",
        "Run a full antivirus scan of the laptop before touching the network",
        "Network-isolate the host with EDR to stop further lateral movement",
        "Reboot the laptop so the malware is cleared from memory"
      ],
      answer: 2,
      explanation: "**Host isolation** (also called network isolation or containment) is the single most important immediate action when a host is actively spreading malware. Isolation cuts the device off from all network communication (except the EDR management channel), preventing the malware from reaching additional hosts, communicating with a command-and-control server, or exfiltrating data. Deleting the malware file and rebooting are secondary steps that come after containment. A full AV scan is also secondary and may miss fileless malware.\n\nNote what makes this an easy call: it is a **user's laptop**, and the spread is **confirmed and active**. Both halves matter. Change either one: a production database server instead of a laptop, or a single suspicious process instead of confirmed spreading, and the calculation shifts, because isolation is an outage you are deliberately causing. Reading 2 covers the questions to ask first when the asset is business-critical.",
      xp: 25,
    } satisfies QuestionTask,

    // ── Reading 3: Reading EDR Alerts ─────────────────────────────────────────
    {
      type: "reading",
      id: "ep-sec-r3",
      heading: "How to Read an EDR Alert: A Step-by-Step Approach",
      content: `When an alert appears in your EDR console, it can feel overwhelming at first. There's a lot of information. This reading walks you through a structured approach to reading any EDR alert.

**The Anatomy of a CrowdStrike Alert**

CrowdStrike Falcon is one of the most widely deployed EDR platforms. When it fires an alert, the key fields are:

| Field | What It Is | Example |
|---|---|---|
| \`event_simpleName\` | Event type (a detection is a DetectionSummaryEvent) | "DetectionSummaryEvent" |
| \`SeverityName\` | How bad CrowdStrike thinks it is | Critical, High, Medium, Low |
| \`Tactic\` / \`Technique\` | MITRE ATT&CK tactic and technique, by name | "Execution" / "PowerShell" |
| \`threat.technique.id\` | The MITRE technique ID: an ECS field beside the Falcon ones (sub-technique in \`threat.technique.subtechnique.id\`) | T1059 / T1059.001 |
| \`FileName\` | The process that triggered the alert | powershell.exe |
| \`ParentBaseFileName\` | What launched the alerting process | cmd.exe |
| \`CommandLine\` | The exact command that was run | powershell.exe -NoP -NonI -W Hidden -Exec Bypass -Enc JAB... |
| \`UserName\` | Who was logged in | CORP\\j.smith |
| \`ComputerName\` | Which machine | LAPTOP-JSMITH |
| \`LocalIP\` | IP address of the machine | 10.0.1.55 |
| \`SHA256HashData\` | Cryptographic hash of the process executable | a1b2c3... |
| \`PatternDispositionDescription\` | What the sensor did about it | "Prevention, process killed." |
| confidence (console / Alerts API) | How confident CrowdStrike is (0–100) | 95 |

**Step-by-Step Alert Analysis**

**Step 1: Read the alert title and technique**
What is the alert about, broadly? If it says "T1059.001: PowerShell" you know you're looking at PowerShell abuse, which is extremely common in attacks. If it says "T1003, OS Credential Dumping" (a technique under the Credential Access tactic, TA0006) you know someone tried to dump credentials.

**Step 2: Identify the affected host and user**
Who and what machine are affected? Is this a finance server (critical) or a developer laptop (important but lower blast radius)? Is the user an administrator or a regular employee?

**Step 3: Examine the command line**
The command line is often the most revealing field. For PowerShell alerts, look for:
- \`-Enc\` or \`-EncodedCommand\`: The command is Base64-encoded to hide what it's doing. Frequently abused and always worth decoding, but management tools (SCCM/ConfigMgr, Intune, many RMM agents) use it too, so judge by the parent process and the decoded content.
- \`-ExecutionPolicy Bypass\` or \`-Exec Bypass\`: Bypassing PowerShell's script execution policy. Attackers use it constantly, but so do legitimate management tools: again, the parent process and what the script does decide it.
- \`-NoP\` or \`-NoProfile\`: Skips loading the user's profile scripts, giving a clean, predictable session. It does NOT switch off PowerShell logging. Script Block Logging, Module Logging and Transcription are set by Group Policy and still record the session. Common in both admin tooling and malware.
- \`-NonI\` or \`-NonInteractive\`: Running without user interaction, indicates automated/scripted execution.
- \`-W Hidden\` or \`-WindowStyle Hidden\`: Hiding the PowerShell window from the user. Malware doesn't want to be seen.
- \`IEX\` or \`Invoke-Expression\`: Executing a string as a command, often used to execute code downloaded from the internet.
- \`DownloadString\` or \`WebClient\`: Downloading code from the internet.

**Step 4: Check the process tree**
Who launched this process? Normal PowerShell usage might be launched by an admin tool or the Windows Task Scheduler. **PowerShell launched by Word, Excel, or Outlook is a major red flag**. It means a document executed malicious code.

**Step 5: Check the hash against threat intelligence**
Copy the SHA256 hash and paste it into **VirusTotal** (virustotal.com) or your threat intelligence platform. If 40 out of 72 antivirus engines flag it as malicious, that confirms the alert.

**Step 6: Look for follow-on activity**
EDR alert timelines let you look at what happened before and after the alert. Did the PowerShell process make any network connections? Did it create any files? Did it spawn any child processes? This tells you whether the attacker succeeded or was caught early.

**Step 7: Determine the response action**
Based on your analysis:
- **Clearly malicious with active threat**: Isolate the host immediately, kill the process, escalate.
- **Suspicious but uncertain**: Escalate to senior analyst, collect forensic package, investigate further.
- **Benign true positive** (the activity really happened and is authorized, e.g. an admin script under a change ticket): Close it citing that justification; at most add a narrow, owned exclusion, never a weaker rule.
- **False positive** (the rule misfired on something it was not meant to catch): Document why and tune the detection rule if needed.

**Common PowerShell Flags and Their Meaning**

| Flag | Short Form | Meaning | Malware Use |
|---|---|---|---|
| \`-NoProfile\` | \`-NoP\` | Skip loading the user's PowerShell profile scripts | A clean, predictable session free of user customisations (does not disable Script Block Logging) |
| \`-NonInteractive\` | \`-NonI\` | Run without prompting the user for input | Automated/scripted execution |
| \`-WindowStyle Hidden\` | \`-W Hidden\` | Hide the PowerShell console window | Don't show the user a black window |
| \`-ExecutionPolicy Bypass\` | \`-Exec Bypass\` | Skip PowerShell script execution policy | Run scripts blocked by policy |
| \`-EncodedCommand\` | \`-Enc\` | Accept a Base64-encoded command | Obfuscate the command from simple string-matching |`,
    } satisfies ReadingTask,

    // ── Question 2 ────────────────────────────────────────────────────────────
    {
      type: "question",
      id: "ep-sec-q2",
      question: "An EDR alert shows the following process tree: `winword.exe → cmd.exe → powershell.exe -Enc JAB...`. What does this process chain most likely indicate?",
      options: [
        "A legitimate Office macro running a system administration script",
        "A malicious Word macro launching PowerShell with an obfuscated encoded command",
        "An Office update component calling PowerShell through cmd.exe to install patches",
        "A Word add-in installer running an encoded PowerShell setup routine"
      ],
      answer: 1,
      explanation: "**winword.exe spawning cmd.exe which spawns powershell.exe** is one of the most classic malicious process chains in endpoint security. Word does not normally spawn command prompts or PowerShell shells during legitimate use. This chain indicates a **malicious Office macro** (embedded in a document) that executed system commands. The `-Enc` flag on PowerShell means the actual command is Base64-encoded: a strong obfuscation indicator. This should be treated as a high-priority true positive.",
      xp: 25,
    } satisfies QuestionTask,

    // ── Log Analysis: CrowdStrike Alert — Malicious PowerShell ────────────────
    {
      type: "log_analysis",
      id: "ep-sec-la1",
      heading: "CrowdStrike Alert: Suspicious PowerShell Execution",
      context: "You are a Tier 1 SOC analyst. A CrowdStrike Falcon alert has just appeared in your queue. The alert was generated on an employee's laptop. The Falcon console shows the alert with Confidence 95 (a property of the alert in the console and Alerts API; the detection event below does not carry it). Your task is to analyse the alert details and answer the investigation questions below.",
      event: {
        id: "ep-la1-001",
        ts: "2025-11-19T14:32:07.000Z",
        source: "edr",
        vendor: "CrowdStrike Falcon",
        event_type: "edr_alert",
        severity: "high",
        description: "CrowdStrike: Suspicious encoded PowerShell execution, possible post-exploitation",
        hostname: "LAPTOP-JSMITH",
        user_email: "j.smith@corp.com",
        src_ip: "10.0.1.55",
        mitre_technique: "T1059.001",
        mitre_tactic: "Execution",
        process: {
          name: "powershell.exe",
          pid: 4892,
          parent_name: "cmd.exe",
          cmdline: "powershell.exe -NoP -NonI -W Hidden -Exec Bypass -Enc JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMAUAB...",
          hash: { sha256: "505e6a45917684bf24f4603e189a29713c196e734821c6df2b104e7147d53ff0" }
        },
        // Field names follow the same Falcon schema as malware-analysis (batch-07)
        // and edr-detection-investigation (batch-28): event_simpleName,
        // SeverityName, ParentBaseFileName, SHA256String, DetectId. An
        // earlier version used AlertType / Severity / SHA256 / ContextProcessParentName,
        // which meant a student meeting CrowdStrike in two different rooms saw two
        // conflicting sets of "real" field names for the same product.
        raw: {
          "crowdstrike.event_simpleName": "DetectionSummaryEvent",
          "crowdstrike.DetectId": "ldt:8f3c1a92b7e44d05:44117",
          "crowdstrike.SeverityName": "High",
          "crowdstrike.Tactic": "Execution",
          "crowdstrike.Technique": "PowerShell",
          "threat.technique.id": "T1059",
          "threat.technique.subtechnique.id": "T1059.001",
          "crowdstrike.PatternDispositionDescription": "Prevention, process killed.",
          "crowdstrike.FileName": "powershell.exe",
          "crowdstrike.ContextProcessId": "4892",
          "crowdstrike.ParentBaseFileName": "cmd.exe",
          "crowdstrike.CommandLine": "powershell.exe -NoP -NonI -W Hidden -Exec Bypass -Enc JABjAGwAaQBlAG4AdAAgAD0A...",
          "crowdstrike.UserName": "CORP\\j.smith",
          "crowdstrike.ComputerName": "LAPTOP-JSMITH",
          "crowdstrike.LocalIP": "10.0.1.55",
          "crowdstrike.SHA256String": "505e6a45917684bf24f4603e189a29713c196e734821c6df2b104e7147d53ff0",
          "crowdstrike.FalconHostLink": "https://falcon.crowdstrike.com/activity/detections/detail/8f3c1a92",
        },
      } satisfies TelemetryEvent,
      questions: [
        {
          question: "CrowdStrike's confidence score for this alert is 95. What does this score indicate?",
          options: [
            "95 % of the malware's capabilities have already executed on the host",
            "CrowdStrike is 95 % confident the activity is malicious, based on ML models and threat intelligence",
            "95 % of the detection engines the sensor consulted agreed it is malicious",
            "The alert's business-impact severity is 95 on a 0–100 scale"
          ],
          answer: 1,
          explanation: "In CrowdStrike, the **Confidence score (0–100)** represents how certain CrowdStrike's detection models are that the observed activity is malicious, based on machine-learning analysis, Threat Graph intelligence, and pattern matching against known attack techniques. A score of 95 is very high. This is almost certainly malicious activity and should be treated as a true positive pending analyst confirmation. Low confidence scores (below 50) warrant more careful evaluation for false positives.",
          xp: 35,
        },
        {
          question: "The command line includes `-W Hidden`. What is the purpose of this flag in the context of this attack?",
          options: [
            "It runs PowerShell with elevated rights that are hidden from access controls",
            "It hides the PowerShell console window so the logged-in user cannot see it running",
            "It hides the script's network connections from the host firewall logs",
            "It writes the command's output to a hidden file instead of the console"
          ],
          answer: 1,
          explanation: "`-WindowStyle Hidden` (shortened to `-W Hidden`) instructs PowerShell to launch with a hidden window style, meaning no black PowerShell console window appears on screen. Legitimate PowerShell scripts sometimes use this for cleaner UX, but in the context of malware, it is used to hide the malicious activity from the victim user sitting at the keyboard. Combined with `-NoP` (no profile), `-NonI` (non-interactive), and `-Exec Bypass` (bypass execution policy), this is a textbook malicious PowerShell execution pattern.",
          xp: 35,
        },
      ],
    } satisfies LogAnalysisTask,

    // ── Flag Task ─────────────────────────────────────────────────────────────
    {
      type: "flag",
      id: "ep-sec-f1",
      prompt: "Look at the CrowdStrike alert log above. Falcon killed the process, but your ticket still has to say what the script actually did, and from this alert alone, you can't. One of the flags in the PowerShell command line is the reason. Enter that flag exactly as it appears in the command line (the flag only, without the value that follows it).",
      answer: "-Enc",
      hint: "Read the crowdstrike.CommandLine field flag by flag. Most of the flags change HOW PowerShell runs (profile, prompts, window, policy); only one changes whether a human can READ what it ran. The 'Common PowerShell Flags' table in the reading maps each short form to its meaning.",
      xp: 50,
    } satisfies FlagTask,

  ],
};

// ---------------------------------------------------------------------------
// Room 4 — Microsoft Defender XDR
// ---------------------------------------------------------------------------

const defenderXdr: Room = {
  id: "defender-xdr",
  title: "Microsoft Defender XDR",
  description:
    "Master Microsoft's unified security platform. Learn to investigate incidents across Defender for Endpoint, Office 365, and Identity. Write KQL Advanced Hunting queries and detect lateral movement, credential theft, and cloud-based attacks.",
  difficulty: "intermediate",
  category: "Endpoint Security",
  estimatedMinutes: 55,
  xp: 320,
  icon: "🛡️",
  prerequisites: ["endpoint-security-fundamentals", "microsoft-365-security", "security-products-behaviour"],
  tasks: [
    // ── Reading 1: MDE Overview & Onboarding ──────────────────────────────────
    {
      type: "reading",
      id: "def-xdr-r1",
      heading: "Microsoft Defender XDR: The Unified Security Platform",
      content: `**Microsoft Defender XDR** (formerly Microsoft 365 Defender) is Microsoft's integrated extended detection and response platform. It is accessed at **security.microsoft.com** and unifies multiple security products into a single portal with correlated incidents, a shared alert queue, and cross-domain threat hunting.

**The Components of Microsoft Defender XDR**

Think of Defender XDR as the "mother platform" that aggregates signals from four specialised products:

| Component | What It Protects | Key Capability |
|---|---|---|
| **Defender for Endpoint (MDE)** | Windows, macOS, Linux, mobile devices | EDR telemetry, device risk score, live response, vulnerability management |
| **Defender for Office 365 (MDO)** | Exchange email, Teams, SharePoint, OneDrive | Anti-phishing, Safe Attachments, Safe Links, Threat Explorer |
| **Defender for Identity (MDI)** | Active Directory Domain Controllers, Entra ID | Detect Kerberoasting, DCSync, lateral movement, Pass-the-Hash |
| **Defender for Cloud Apps (MDCA)** | SaaS apps (Salesforce, Box, Dropbox, ServiceNow, etc.) | Shadow IT discovery, anomaly detection, Cloud App policies |

When an attack spans multiple domains (e.g. phishing email → compromised account → lateral movement via PSEXEC), Defender XDR automatically **correlates** all the related alerts from all components into a single **incident**. This is what sets XDR apart from standalone tools.

---

**Microsoft Defender for Endpoint (MDE): Deep Dive**

**MDE Onboarding**: Getting devices under MDE management:

- **GPO (Group Policy)**: Deploy the MDE onboarding package to domain-joined Windows machines via Active Directory Group Policy. Most common in enterprise environments.
- **Microsoft Intune / Endpoint Manager**: Mobile Device Management (MDM) deployment, ideal for modern cloud-managed devices (Azure AD-joined laptops, BYOD).
- **Microsoft Configuration Manager (SCCM/MECM)**: For organisations with existing SCCM infrastructure.
- **Local script**: Download and run the onboarding script manually. Used for testing or very small deployments.
- **Linux / macOS**: Manual package deployment or management tool-based deployment.

Once onboarded, each device appears in the **Device Inventory** (security.microsoft.com → Assets → Devices).

**Device Inventory: What You See**

Each device in the inventory shows:
- **Device name and OS**: LAPTOP-JSMITH, Windows 11 22H2
- **Risk Level**: Critical / High / Medium / Low. Calculated from active alerts and unpatched vulnerabilities
- **Exposure Score**: How vulnerable is this device to known attack techniques? (0–100)
- **Onboarding status**: Whether the MDE agent is active and reporting
- **Last seen**: When the device last checked in
- **Installed software**: Complete software inventory for vulnerability management

**Alert Queue and Incident Page**

MDE generates alerts when it detects suspicious behaviour. Each alert shows:
- **Severity**: Critical, High, Medium, Low, Informational
- **Detection source**: EDR (behavioural detection), Antivirus, Network protection, Threat Intelligence
- **MITRE ATT&CK mapping**: The technique (e.g. T1055: Process Injection) and tactic (e.g. Stealth; a console not yet updated to ATT&CK v19 may still show its former name, Defense Evasion)
- **Affected entity**: Device name and user

Multiple related alerts are automatically grouped into **Incidents**. The incident page shows:
- **Incident graph**: A visual map of affected devices, users, email addresses, and processes, with connecting lines showing relationships
- **Evidence**: All files, IPs, domains, and users involved across all correlated alerts
- **Timeline**: Chronological sequence of events across all affected devices
- **Recommendations**: Automated response suggestions (isolate device, run antivirus scan)

**MDE Timeline: The Investigator's Best Friend**

Every onboarded device has a **Timeline** view (Device page → Timeline tab). This shows every recorded event on that device in chronological order, going back up to 180 days. SOC analysts use the timeline to:
- Find the initial access event (when did the attacker first appear on this device?)
- Trace the attack chain (what happened step by step?)
- Identify the patient-zero device (was this machine the first compromised or was the malware spread from elsewhere?)

**Live Response: Remote Forensics**

MDE Live Response provides a remote interactive shell to any onboarded endpoint, including one that MDE has network-isolated (isolation keeps the device's connection to the Defender service open). From security.microsoft.com, analysts can:
- Browse the file system
- Collect specific files for analysis
- Run investigative commands (\`processes\`, \`connections\`, \`dir\`)
- Upload and execute response scripts
- Collect memory dumps

This eliminates the need for physical access to investigate a compromised device.`,
      checkpoint: {
        question: "A laptop was network-isolated through MDE an hour ago. You now need a copy of a suspicious file from its disk, and nobody can reach the laptop physically. What is the best way to get it?",
        options: [
          "Use Live Response; it still connects to an isolated device",
          "Export the file from the device Timeline entry that shows it",
          "Query DeviceFileEvents in Advanced Hunting to retrieve the file",
          "Release isolation briefly and copy the file over an SMB share",
        ],
        answer: 0,
        explanation:
          "Live Response works on any onboarded device, including an isolated one, because isolation keeps the connection to the Defender service open; collecting files is one of its core functions. The Timeline shows that the file event happened, but it does not hold the file's contents. Advanced Hunting tables hold metadata (name, path, hashes), not the file. Releasing isolation reconnects a possibly compromised host to the network just to copy a file that Live Response can collect safely.",
      },
    } satisfies ReadingTask,

    // ── Question 1 ────────────────────────────────────────────────────────────
    {
      type: "question",
      id: "def-xdr-q1",
      question: "From a contractor laptop that has no MDE agent, someone requests Kerberos service tickets for 40 different service accounts within one minute. No malware runs. Which Defender XDR component can still raise an alert on this?",
      options: [
        "Defender for Endpoint, from the ticket requests recorded on the laptop",
        "Defender for Office 365, by tracing the phishing email that began it",
        "Defender for Identity, whose domain-controller sensors see the requests",
        "Defender for Cloud Apps, which inspects Entra ID token issuance"
      ],
      answer: 2,
      explanation: "This is the Kerberoasting pattern (T1558.003), and the ticket requests are answered by the domain controllers. **Defender for Identity** runs its sensors on the DCs, so it sees them whatever the client is. That is why it still alerts when the source laptop is unmanaged. Defender for Endpoint needs its agent on the device, and this laptop has none. Defender for Office 365 covers email and collaboration; even if a phishing email started the attack, it does not see Kerberos traffic. Defender for Cloud Apps watches SaaS and cloud activity, while these tickets are issued by on-premises Active Directory, not by Entra ID.",
      xp: 35,
    } satisfies QuestionTask,

    // ── Question 3 ────────────────────────────────────────────────────────────
    {
      type: "question",
      id: "def-xdr-q3",
      question: "You receive a Defender XDR incident containing 12 alerts across 4 devices and 3 user accounts. What is the main advantage of Defender XDR automatically grouping these into one incident rather than 12 separate alerts?",
      options: [
        "The incident can be closed as soon as its highest-severity alert is resolved",
        "Alerts from different products are linked into one attack story with its full scope",
        "Duplicate detections of one event are merged, so 11 of the alerts can be ignored",
        "The alerts are ranked, so only the most severe one needs to be investigated"
      ],
      answer: 1,
      explanation: "The value of **XDR correlation** is reconstructing the attack story. A phishing alert (Defender for Office 365), a suspicious logon (Defender for Identity) and PowerShell and PsExec alerts on two devices (MDE) each look moderate alone. Together, in one incident with its graph, they show phishing → credential compromise → lateral movement across 4 devices and 3 accounts. Resolving the most severe alert does not resolve the others: each can be a separate step that needs its own containment. The 12 alerts are related detections, not duplicates of one event, so none can be ignored. Severity ordering helps you choose where to start, but scoping still needs every alert.",
      xp: 35,
    } satisfies QuestionTask,

    // ── Reading 2: Alert Investigation ────────────────────────────────────────
    {
      type: "reading",
      id: "def-xdr-r2",
      heading: "Investigating Incidents in Microsoft Defender XDR",
      content: `A new incident in Defender XDR can look overwhelming at first. This reading gives you a structured investigation methodology and explains each component of the incident page.

**The Defender XDR Incident Workflow**

When an incident is assigned to you:

**1. Read the Incident Summary**

The incident title usually tells you the primary alert that triggered grouping. Example: "Multi-stage attack using PowerShell and network reconnaissance". Look at:
- **Severity**: How urgent is this?
- **Number of alerts**: How many individual detections were grouped?
- **Number of affected devices and users**: What is the blast radius?
- **Attack categories**: What did the attacker do? (Initial Access, Execution, Persistence, Lateral Movement)

**2. Examine the Incident Graph**

The incident graph visually connects the dots. You might see:
- An email (Defender for Office 365 flagged a phishing email)
- A user account (the same user authenticated from an unusual location)
- A device (the user's laptop where malware ran)
- An external IP (the command-and-control server the malware contacted)
- Another device (where the attacker moved laterally)

This graph answers: **how are all the pieces connected?**

**3. Investigate Each Alert**

Click into each alert within the incident. For an MDE alert:
- **Process details**: What was the exact command line?
- **Process tree**: What spawned what?
- **File details**: What files were created or modified?
- **Network activity**: What external connections were made?

**4. Check the Device Timeline**

From the affected device page, open the Timeline. Filter the timeline around the time of the first alert and look 30–60 minutes earlier. Attackers often perform reconnaissance before their loudest action. Look for:
- Unusual process executions before the alert time
- Network connections to external IPs
- Credential access attempts

**5. Check for Lateral Movement**

In the incident graph, look for additional devices. If the attacker moved from Device A to Device B, you'll see alerts on both. Common lateral movement tools:
- **PsExec**: Sysinternals tool that allows remote command execution. Abused constantly. It copies a service binary, \`PSEXESVC.exe\`, to the target and starts it as a service, so the account used must already be a local administrator there. On the target, the remote command appears as a child process of \`PSEXESVC.exe\`. By default it runs as the connecting account; with PsExec's \`-s\` option it runs as \`NT AUTHORITY\\SYSTEM\` instead.
- **WMI (Windows Management Instrumentation)**: Built-in Windows remote management.
- **RDP (Remote Desktop Protocol)**: If the attacker has credentials, they can RDP to other machines.
- **SMB (Server Message Block)**: File sharing protocol often used to deploy malware to network shares.

**6. Identify the Attack Timeline (ATT&CK Tactics)**

Map the events to MITRE ATT&CK tactics (the attack stages; not to be confused with Lockheed Martin's separate Cyber Kill Chain model):
- **Initial Access**: How did they get in? (Phishing? VPN with stolen credentials? Exploited vulnerability?)
- **Execution**: What code did they run? (Malicious macro, PowerShell, scheduled task?)
- **Persistence**: How did they ensure they survive a reboot? (Registry run key, scheduled task, new service?)
- **Privilege Escalation**: Did they move from a normal user to admin?
- **Stealth**: Did they try to hide or blend in? (Use LOLBins, Living Off the Land Binaries? Masquerade as legitimate files? Delete their tools?)
- **Defense Impairment**: Did they break the defences? (Disable AV/EDR, add exclusions, clear or stop event logs?) ATT&CK v19 split the former Defense Evasion tactic into these two.
- **Credential Access**: Did they steal credentials? (LSASS dump, Kerberoasting?)
- **Discovery**: Did they map the network? (Port scans, AD enumeration?)
- **Lateral Movement**: Did they move to other machines? (PsExec, WMI, RDP?)
- **Collection & Exfiltration**: Did they steal data?

**7. Containment and Response**

Based on your investigation:
- **Isolate compromised devices** (MDE network isolation with one click)
- **Reset compromised accounts** (via Entra ID or Active Directory)
- **Block IOCs** (Add malicious IPs, domains, and file hashes to the MDE indicators list for automatic blocking)
- **Run AV scan** on affected devices
- **Revoke active sessions** for compromised accounts (Entra ID → Users → select the user → Revoke sessions)
- **Revoke OAuth consent** granted to a malicious app, because the app's tokens are separate from the user's password

**Two cloud identity attacks to recognise**

- **Illicit consent grant (consent phishing)**: the user is tricked into approving a malicious OAuth app that asks for permissions such as Mail.Read or Mail.ReadWrite. The app then reads the mailbox with its own tokens, which keep working after a password reset until the consent is revoked. In telemetry: a consent event for a new, unverified app shortly after a risky sign-in.
- **Adversary-in-the-middle (AiTM) phishing**: a phishing page relays the real Microsoft sign-in, so the user enters their password and approves their own MFA prompt while the attacker captures the session. In telemetry: a successful sign-in with MFA from an unfamiliar IP or unmanaged device. A quick MFA approval therefore does not prove the sign-in was legitimate; it fits AiTM as well as a fatigued user tapping Approve.

**Defender for Identity (MDI) Alerts**

MDI monitors your on-premises Active Directory domain controllers and Azure Entra ID for identity-based attacks. Key alerts SOC analysts see from MDI:

| MDI Alert | Attack Technique |
|---|---|
| Suspected Kerberoasting activity | T1558.003, Kerberoasting: request TGS tickets for service accounts to crack offline |
| Suspected DCSync attack | T1003.006, DCSync: simulate a DC to replicate all password hashes from AD |
| Lateral movement path to sensitive entity | Graph-based lateral movement risk |
| Pass-the-Hash / Pass-the-Ticket | T1550: Credential reuse without the plaintext password |
| Reconnaissance using LDAP queries | T1087: Account enumeration via LDAP |
| Suspicious additions to sensitive groups | T1098, Adding a backdoor account to Domain Admins |`,
      checkpoint: {
        question: "An MDE alert fires at 14:05 for a PsExec launch on a workstation. Why should you open the device Timeline well before 14:05 instead of starting at the alert time?",
        options: [
          "Quieter reconnaissance usually comes before the loud action that fired the alert",
          "The Timeline keeps only the events from the hour before an alert is raised",
          "Alert times are shown in UTC, so the real activity happened hours earlier",
          "Events after the alert are already summarised in the incident graph instead",
        ],
        answer: 0,
        explanation:
          "Alerts usually fire on the loudest step. Reconnaissance, credential access and the first execution often happen quietly beforehand, so starting earlier (the reading suggests 30–60 minutes) shows how the attacker got there. The Timeline goes back up to 180 days, not one hour. UTC is a display-format question: converting time zones does not uncover earlier activity. The incident graph shows how entities are connected; it does not replace reading the events that came before the alert.",
      },
    } satisfies ReadingTask,

    // ── Log Analysis: MDE — PsExec Lateral Movement ───────────────────────────
    {
      type: "log_analysis",
      id: "def-xdr-la1",
      heading: "MDE Alert: Lateral Movement via PsExec",
      context: "You are investigating a Defender XDR incident. Its lateral-movement alert says that at 03:17 the service account CORP\\svc-backup authenticated from a developer workstation (WS-DEV-09, 10.0.5.21) to the file server SRV-FILE01 and started a remote process there. Below is the DeviceProcessEvents record from SRV-FILE01 that the alert points to. Analyse it and answer the questions.",
      event: {
        id: "def-xdr-la1-001",
        ts: "2025-11-22T03:17:44.000Z",
        source: "edr",
        vendor: "Microsoft Defender for Endpoint",
        event_type: "process_create",
        severity: "high",
        description: "MDE DeviceProcessEvents on SRV-FILE01: cmd.exe created at 03:17, linked to a lateral-movement alert from WS-DEV-09",
        hostname: "SRV-FILE01",
        user_email: "svc-backup@corp.com",
        src_ip: "10.0.5.21",
        dst_ip: "10.0.10.5",
        mitre_technique: "T1021.002",
        mitre_tactic: "Lateral Movement",
        process: {
          name: "cmd.exe",
          pid: 7712,
          parent_name: "PSEXESVC.exe",
          parent_pid: 5340,
          cmdline: "\"cmd.exe\"",
          user: "NT AUTHORITY\\SYSTEM",
          integrity: "system",
        },
        raw: {
          "Timestamp": "2025-11-22T03:17:44.000Z",
          "DeviceId": "4c1e7a925b3d4f089e6a2d7f1b0c8e35a7d10b64",
          "DeviceName": "srv-file01.corp.local",
          "ActionType": "ProcessCreated",
          "FileName": "cmd.exe",
          "FolderPath": "C:\\Windows\\System32\\cmd.exe",
          "ProcessId": 7712,
          "ProcessCommandLine": "\"cmd.exe\"",
          "ProcessIntegrityLevel": "System",
          "AccountDomain": "nt authority",
          "AccountName": "system",
          "AccountSid": "S-1-5-18",
          "InitiatingProcessFileName": "PSEXESVC.exe",
          "InitiatingProcessFolderPath": "C:\\Windows\\PSEXESVC.exe",
          "InitiatingProcessId": 5340,
          "InitiatingProcessCommandLine": "C:\\Windows\\PSEXESVC.exe",
          "InitiatingProcessParentFileName": "services.exe",
          "InitiatingProcessAccountDomain": "nt authority",
          "InitiatingProcessAccountName": "system",
          "ReportId": 30417
        },
      } satisfies TelemetryEvent,
      questions: [
        {
          question: "The alert says the remote connection authenticated as svc-backup, yet the shell on SRV-FILE01 runs as nt authority\\system. What best explains this, and what does it tell you about svc-backup?",
          options: [
            "PsExec always maps service accounts to SYSTEM; svc-backup may be unprivileged",
            "PsExec was run with -s; svc-backup must already be a local admin on SRV-FILE01",
            "A local scheduled task started the shell; svc-backup was not involved in it",
            "The record is mis-attributed; MDE logs PsExec children under the service name"
          ],
          answer: 1,
          explanation: "On the target, PsExec's remote command runs as a child of `PSEXESVC.exe` (shown here), and it runs as the connecting account unless the `-s` option is used, which makes it run as SYSTEM. Installing PSEXESVC requires local administrator rights, so svc-backup already had admin on SRV-FILE01: that is a finding in itself, and it widens the blast radius of the stolen credential. PsExec does not map service accounts to SYSTEM; without -s, the shell would run as svc-backup. A scheduled task would be started by the task scheduler service, not by PSEXESVC.exe, so the parent rules it out. MDE records the real account of each process (AccountName/AccountSid S-1-5-18); nothing in the record suggests mis-attribution.",
          xp: 45,
        },
        {
          question: "svc-backup is a legitimate service account, normally used only by the overnight backup job that runs from the backup server. How should you read this 03:17 activity?",
          options: [
            "Expected: the backup window is overnight, so svc-backup activity at 03:17 is normal",
            "A misconfigured backup task that launched PsExec with the wrong command by mistake",
            "Likely stolen credentials: a backup job has no need for a SYSTEM shell from a dev PC",
            "Lower priority: svc-backup is already privileged, so a SYSTEM shell adds little"
          ],
          answer: 2,
          explanation: "The time fits the account, but nothing else does. The connection comes from a developer workstation (WS-DEV-09), not the backup server, and the result is an interactive SYSTEM `cmd.exe` through PsExec, not backup traffic. Attackers pick service accounts precisely because activity in their usual window looks normal. Treating it as expected judges the time and ignores the source host and the action. A misconfigured backup task would run from the backup server, not from a dev PC. A SYSTEM shell on a file server gives full control of the host and its data, so the account's existing privilege raises the priority rather than lowering it.",
          xp: 45,
        },
      ],
    } satisfies LogAnalysisTask,

    // ── Flag Task ─────────────────────────────────────────────────────────────
    {
      type: "flag",
      id: "def-xdr-f1",
      prompt: "Next you want the SRV-FILE01 timeline to show everything else the PsExec service process did there (other child processes, files written, network connections). Using the record above, what is the process ID of the process that launched the SYSTEM shell?",
      answer: "5340",
      hint: "The record describes two processes: the one that was created and the one that created it.",
      xp: 60,
    } satisfies FlagTask,

    // ── Reading 3: Advanced Hunting KQL ───────────────────────────────────────
    {
      type: "reading",
      id: "def-xdr-r3",
      heading: "Advanced Hunting with KQL: Proactive Threat Hunting",
      content: `**Advanced Hunting** is one of the most powerful features in Microsoft Defender XDR. It allows analysts to write queries against raw telemetry data to proactively search for threats, even before an alert fires. Advanced Hunting is accessed at: **security.microsoft.com → Hunting → Advanced Hunting**.

**KQL: Kusto Query Language**

Advanced Hunting queries are written in **KQL (Kusto Query Language)**, which is also used by Microsoft Sentinel (Microsoft's SIEM). KQL is designed to be readable, intuitive, and powerful for security analysis.

**KQL Basics**

A KQL query follows this general structure:
\`\`\`kql
TableName
| where Timestamp > ago(7d)               // Filter: last 7 days
| where ColumnName == "value"              // Filter by a specific column
| project ColumnA, ColumnB, ColumnC       // Select which columns to show
| summarize Count = count() by ColumnA    // Aggregate (count per group)
| order by Count desc                     // Sort results
| limit 100                               // Return top 100 results
\`\`\`

KQL uses the **pipe operator** (\`|\`): each step transforms the result of the previous step. Advanced Hunting tables use the \`Timestamp\` column for event time; the same data in Microsoft Sentinel uses \`TimeGenerated\`.

**The Advanced Hunting Tables**

Defender XDR exposes raw telemetry in structured tables. Key tables:

| Table | Contains |
|---|---|
| \`DeviceProcessEvents\` | Process creation events: name, command line, parent, user, SHA256 |
| \`DeviceNetworkEvents\` | Network connections: process, remote IP, remote port, URL |
| \`DeviceFileEvents\` | File creation, modification, deletion events |
| \`DeviceRegistryEvents\` | Registry key reads and writes |
| \`DeviceLogonEvents\` | Sign-ins on the device: account, logon type (interactive, network, RDP), remote IP and device |
| \`DeviceEvents\` | Miscellaneous security events: ASR and exploit-protection events, antivirus detections, PowerShell commands and more |
| \`AlertInfo\` / \`AlertEvidence\` | Alerts from all Defender products, and the devices, files, users and IPs attached to each alert |
| \`EmailEvents\` | Email delivery events (from Defender for Office 365) |
| \`EmailAttachmentInfo\` | Attachment metadata for emails |
| \`IdentityLogonEvents\` | Identity authentication events (AD, Entra ID) |
| \`CloudAppEvents\` | Activity from cloud apps monitored by MDCA |

**Practical Example Queries**

**Query 1: Find all PowerShell with encoded commands in the last 7 days**
\`\`\`kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where FileName =~ "powershell.exe"
| where ProcessCommandLine matches regex @"(?i)\\s-(e|ec|en|enc\\w*)\\s"   // -e, -ec, -enc, -EncodedCommand…
| project Timestamp, DeviceName, AccountName, ProcessCommandLine, InitiatingProcessFileName
| order by Timestamp desc
\`\`\`
Encoded PowerShell is worth reviewing, because attackers use it to hide script content. It is not malicious by itself: management tools such as Configuration Manager (CcmExec.exe) and Intune also launch encoded commands. Decode the content and check the parent process and account; an Office application, a browser or an unusual account as the parent deserves priority. The regex catches the short forms (-e, -ec, -enc) that a plain match on "-Enc" would miss.

**Query 2: Find processes making network connections to rare external IPs**
\`\`\`kql
DeviceNetworkEvents
| where Timestamp > ago(24h)
| where RemoteIPType == "Public"
| where InitiatingProcessFileName !in~ ("chrome.exe", "msedge.exe", "firefox.exe", "outlook.exe")
| summarize DeviceCount = dcount(DeviceName), Devices = make_set(DeviceName) by RemoteIP, InitiatingProcessFileName
| where DeviceCount < 3   // rare: fewer than 3 devices contacted this IP
| order by DeviceCount asc
\`\`\`

**Query 3: Detect PsExec lateral movement**
\`\`\`kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where FileName =~ "PSEXESVC.exe" or ProcessCommandLine has "psexec"
| project Timestamp, DeviceName, AccountName, ProcessCommandLine, InitiatingProcessFileName
| order by Timestamp desc
\`\`\`

**Query 4: Join tables, find processes that made network connections (hunting for C2)**
\`\`\`kql
DeviceProcessEvents
| where Timestamp > ago(1d)
| where FileName =~ "powershell.exe"
| join kind=inner DeviceNetworkEvents on DeviceId, $left.ProcessId == $right.InitiatingProcessId
| where RemoteIPType == "Public"
| project Timestamp, DeviceName, AccountName, ProcessCommandLine, RemoteIP, RemotePort, RemoteUrl
| order by Timestamp desc
\`\`\`
This joins process events with network events to find PowerShell processes that made outbound connections: a strong C2 indicator.

**Custom Detection Rules**

Advanced Hunting queries can be saved as **Custom Detection Rules** that run on a schedule (every hour, every day) and automatically create alerts when the query returns results. This is how threat hunters turn hunting queries into continuous monitoring. Go to: Advanced Hunting → Create detection rule.

**Microsoft Secure Score: Endpoint Contribution**

**Microsoft Secure Score** (security.microsoft.com → Secure Score) measures your organisation's security posture as a score from 0 to the maximum possible points. The endpoint section includes points for:
- Percentage of devices onboarded to MDE
- Percentage of devices with antivirus enabled
- Percentage of devices with Attack Surface Reduction rules enabled
- Percentage of devices with BitLocker encryption
- Vulnerability management: percentage of critical vulnerabilities remediated

SOC analysts often track Secure Score as a KPI for endpoint security health.`,
    } satisfies ReadingTask,

    // ── Question 2 ────────────────────────────────────────────────────────────
    {
      type: "question",
      id: "def-xdr-q2",
      question: "In a KQL Advanced Hunting query, you want to find all PowerShell processes that made outbound network connections to public IPs in the last 24 hours. Which two tables would you join to answer this question?",
      options: [
        "AlertEvidence and DeviceNetworkEvents",
        "DeviceProcessEvents and DeviceNetworkEvents",
        "DeviceProcessEvents and DeviceLogonEvents",
        "IdentityLogonEvents and DeviceNetworkEvents"
      ],
      answer: 1,
      explanation: "To tie **which process** to **which connection**, join:\n- **DeviceProcessEvents**: process creation, with the process name (powershell.exe), command line and ProcessId.\n- **DeviceNetworkEvents**: connections, with RemoteIP, RemotePort, RemoteIPType and the InitiatingProcessId of the process that opened them.\nJoin on DeviceId and ProcessId = InitiatingProcessId, as in Query 4. AlertEvidence only holds entities attached to alerts that already fired, so it misses unalerted activity, which is what hunting is for. DeviceLogonEvents records sign-ins, not connections to public IPs. IdentityLogonEvents records authentication against AD/Entra ID, not which process on a device opened a connection.",
      xp: 35,
    } satisfies QuestionTask,

    // ── Question 4 (bonus) ────────────────────────────────────────────────────
    {
      type: "question",
      id: "def-xdr-q4",
      question: "A hunter runs Query 1 from the reading (encoded PowerShell, last 7 days). It returns 40 rows: 36 have InitiatingProcessFileName = CcmExec.exe (the Configuration Manager client) spread across hundreds of devices, and 4 have InitiatingProcessFileName = WINWORD.EXE on two Finance laptops. How should the hunter handle the results?",
      options: [
        "Escalate all 40 at once: encoded PowerShell is rarely legitimate, whatever the parent",
        "Prioritise the 4 WINWORD.EXE rows; decode and baseline the CcmExec.exe rows",
        "Close all 40: Defender would already have alerted on any malicious encoded script",
        "Treat the WINWORD.EXE rows as benign: Office add-ins routinely run encoded scripts"
      ],
      answer: 1,
      explanation: "Encoded PowerShell is a lead, not a verdict. Configuration Manager's CcmExec.exe legitimately launches encoded commands across the fleet, so those rows are decoded and baselined rather than escalated. Word spawning encoded PowerShell on two Finance laptops is the classic macro-delivery pattern, so it comes first. Escalating everything treats management tooling as an attack and buries the 4 real leads. Closing everything assumes an alert would already exist, but hunting exists to find what did not alert. Office applications launching encoded PowerShell are a top-priority signal, not routine add-in behaviour.",
      xp: 35,
    } satisfies QuestionTask,

    // ── Analyst Choice: risky sign-in + new OAuth app consent ────────────────
    {
      type: "analyst_choice",
      id: "def-xdr-ac1",
      heading: "Verdict: High-Risk Sign-In Followed by a New OAuth App Consent",
      scenario:
        "Defender XDR groups three signals into one incident at 04:47 AM: (1) Entra ID Identity Protection flags a High-risk sign-in for the CFO's account (m.reyes@corp.com) that nonetheless succeeded, including MFA, from an IP address never associated with this account before; (2) two minutes later the same account grants OAuth consent to a newly-registered third-party application requesting Mail.Read and Mail.ReadWrite permissions; (3) Defender for Cloud Apps flags the application as an unverified publisher, first seen today across the whole tenant. Review the Unified Audit Log sign-in record below and render your verdict.",
      event: {
        id: "def-xdr-ac1-evt-001",
        ts: "2026-02-11T04:47:03Z",
        source: "o365",
        vendor: "Microsoft 365 Unified Audit Log",
        event_type: "auth_success",
        severity: "high",
        user_email: "m.reyes@corp.com",
        description:
          "High-risk sign-in succeeded for m.reyes@corp.com from a previously unseen IP address; the MFA push notification was approved 4 seconds after being sent",
        mitre_technique: "T1078.004",
        mitre_tactic: "Initial Access",
        authentication: {
          method: "OAuth2",
          mfa_type: "push",
          result: "Success",
        },
        raw: {
          "data.office365.Operation": "UserLoggedIn",
          "data.office365.UserId": "m.reyes@corp.com",
          "data.office365.CreationTime": "2026-02-11T04:47:03",
          "data.office365.RecordType": "15",
          "data.office365.ActorIpAddress": "198.51.100.143",
          "data.office365.ClientIP": "198.51.100.143",
          "data.office365.ResultStatus": "Succeeded",
          "data.office365.Workload": "AzureActiveDirectory",
          "data.office365.AzureActiveDirectoryEventType": 1,
          "GeoLocation.country_name": "Romania",
          "GeoLocation.city_name": "Cluj-Napoca",
          "data.office365.ExtendedProperties": [
            { Name: "ResultStatusDetail", Value: "Success" },
            { Name: "UserAgent", Value: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36" },
            { Name: "UserAuthenticationMethod", Value: "16457" },
            { Name: "RequestType", Value: "OAuth2:Authorize" },
            { Name: "KeepMeSignedIn", Value: "True" },
          ],
          "data.office365.DeviceProperties": [
            { Name: "OS", Value: "Windows 10" },
            { Name: "IsCompliant", Value: "false" },
            { Name: "TrustType", Value: "Unknown" },
          ],
          "rule.description": "Office 365: Secure Token Service (STS) logon events in Azure Active Directory.",
          "rule.level": "3",
          "rule.groups": ["office365", "AzureActiveDirectoryStsLogon"],
        },
      } satisfies TelemetryEvent,
      correct_verdict: "true_positive",
      explanation:
        "On its own, a High-risk sign-in from Identity Protection is a probabilistic signal, not proof of compromise: travel or a new device can also trigger it. The combination removes the ambiguity. The sign-in comes from an IP and country this account has never used. The device is unmanaged and non-compliant (IsCompliant: false, TrustType: Unknown). MFA was satisfied, but a fast approval on an unfamiliar sign-in is not reassurance: it fits a fatigued user tapping Approve, and it fits adversary-in-the-middle phishing, where the user approves their own prompt while a proxy captures the session. Most decisive of all, two minutes later the same account granted OAuth consent to a brand-new, unverified app requesting Mail.Read and Mail.ReadWrite. That is the illicit consent grant pattern from the reading: the app's tokens keep reading the mailbox even after a password reset. Correct response: revoke the app's consent and the user's sessions and refresh tokens, reset the password and re-register MFA for m.reyes, and review the mailbox for forwarding rules or further OAuth grants.",
      fp_trap:
        "Treating any High-risk sign-in as automatically meaning “attack” would generate constant false alarms, because risk detections also fire on routine events such as a new laptop or a business trip. The trap here runs the other way: it is easy to see “MFA satisfied” and assume the sign-in must be legitimate. But MFA only proves that a prompt was approved, not who was behind the session. With AiTM phishing the real user approves their own prompt, and a rushed or fatigued tap looks the same in the log. It is the full chain (unfamiliar IP and country, non-compliant device, and an unverified app granted mailbox read/write two minutes later) that turns an ambiguous risk score into a confirmed compromise.",
      xp: 30,
    } satisfies AnalystChoiceTask,

  ],
};

// ---------------------------------------------------------------------------
// Export
// ---------------------------------------------------------------------------

const rooms = [
  exchangeOnlineSecurity,
  sharepointTeamsMonitoring,
  endpointSecurityFundamentals,
  defenderXdr,
];

export default rooms;
