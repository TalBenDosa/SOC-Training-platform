/**
 * Learning Rooms — Batch 06
 * Exchange Online Security, SharePoint & Teams Monitoring,
 * Endpoint Security Fundamentals, Microsoft Defender XDR
 *
 * Audience: absolute beginners progressing toward cloud threat detection.
 * Style: TryHackMe-style rooms with readings, MCQs, log analysis, and flags.
 */

import type { TelemetryEvent } from "@/lib/sim/types";
import type { Room, ReadingTask, QuestionTask, LogAnalysisTask, FlagTask } from "@/data/rooms";

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
      heading: "How Exchange Online Works — The Journey of Every Email",
      content: `**Exchange Online** is Microsoft's cloud-hosted email service. It is the email backbone for any organisation using Microsoft 365. Instead of running their own on-premises mail servers, companies pay Microsoft to host their email infrastructure in Azure datacentres. Today, hundreds of millions of mailboxes run on Exchange Online.

**Why does a SOC analyst care about email?**
Email is the number-one initial-access vector for attackers. According to Microsoft's own telemetry, more than 90 % of ransomware campaigns begin with a phishing email. Understanding how email flows through Microsoft's infrastructure — and where it can be inspected — is essential knowledge for any blue-team professional.

**The Journey of an Inbound Email**

Think of email delivery like a package moving through several inspection checkpoints at an airport:

1. **Sender's mail server** — The attacker or legitimate sender composes a message and their mail server transmits it outbound.
2. **MX Record lookup** — The sending server queries DNS for the recipient domain's **MX record** (Mail Exchanger). The MX record says "send mail for corp.com to mail.protection.outlook.com." This tells the internet that Microsoft is handling email for that domain.
3. **Exchange Online Protection (EOP)** — Every inbound message first hits EOP, Microsoft's built-in filtering layer. EOP performs connection filtering (blocking known-bad IP ranges), anti-spam analysis, anti-malware scanning, and email authentication checks (SPF, DKIM, DMARC).
4. **Microsoft Defender for Office 365 (MDO)** — If the organisation has licenced MDO (formerly Advanced Threat Protection), the message additionally passes through **Safe Attachments** (detonates attachments in a sandbox) and **Safe Links** (rewrites URLs and checks them at click-time).
5. **Mailbox delivery** — If the message passes all checks, it lands in the recipient's inbox. If it is flagged as spam or malicious, it goes to the **Quarantine** instead.

**Exchange Online Protection (EOP) — The Free First Line**

Every Exchange Online subscription includes EOP at no extra cost. EOP provides:
- **Connection filtering**: Blocks emails from IP addresses that appear on known-bad reputation lists.
- **Anti-spam**: Assigns a **Spam Confidence Level (SCL)** from -1 (bypass, explicitly whitelisted) to 9 (high-confidence spam). SCL 5 and above usually routes to the Junk folder.
- **Bulk mail filtering**: A separate **Bulk Complaint Level (BCL)** score (0–9) identifies mass-marketing mail.
- **Anti-malware**: Scans attachments for known malware signatures.
- **Zero-hour Auto Purge (ZAP)**: Even after delivery, if a message is later reclassified as malware or phishing, ZAP retroactively moves it out of the inbox.

**Microsoft Defender for Office 365 (MDO) — The Premium Layer**

MDO adds behaviour-based, sandboxed inspection on top of EOP:
- **Safe Attachments**: Opens every attachment inside a detonation environment (a virtual machine) and observes what happens. Malicious behaviour = block.
- **Safe Links**: Rewrites URLs inside emails and Teams messages to pass through Microsoft's real-time reputation check. If a URL turns malicious after delivery, Safe Links blocks it when the user clicks it.
- **Anti-phishing / Impersonation Protection**: Detects look-alike sender names and domains designed to impersonate executives or trusted brands.

**The Exchange Admin Center (EAC) — admin.exchange.microsoft.com**

The EAC is the web portal where administrators manage Exchange Online. A SOC analyst uses the **Message Trace** feature here to track the delivery status of any individual email — where it came from, what happened to it, whether it was blocked, quarantined, or delivered.

**Key takeaway for analysts**: Email filtering is not perfect. Attackers constantly evolve their techniques to bypass filters. Your job as a SOC analyst is to recognise the indicators that a message slipped through, or that something suspicious happened after delivery (like a user clicking a link or forwarding rules being created).`,
    } satisfies ReadingTask,

    // ── Reading 2: SPF, DKIM, DMARC ──────────────────────────────────────────
    {
      type: "reading",
      id: "exch-sec-r2",
      heading: "Email Authentication — SPF, DKIM, and DMARC Explained",
      content: `One of the biggest problems with email is that it was invented before anyone thought about security. By default, **anyone can send an email claiming to be from any address**. This is called **email spoofing**, and it is the foundation of almost every phishing and Business Email Compromise (BEC) attack.

Three protocols were invented to fix this: SPF, DKIM, and DMARC. Together they let a receiving mail server verify whether an email really came from where it claims to come from. Think of them as the email equivalent of a passport, a seal of authenticity, and a border policy.

---

**SPF — Sender Policy Framework**

SPF is a DNS record that answers the question: **"Which mail servers are authorised to send email on behalf of this domain?"**

The domain owner publishes an SPF record in DNS. It looks something like:
\`v=spf1 include:spf.protection.outlook.com -all\`

This means: "Only Microsoft's mail servers (protection.outlook.com) are allowed to send email from our domain. Reject everything else."

When a receiving server gets an email claiming to be from corp.com, it checks the SPF record and asks: "Did this email come from one of the approved servers?" If yes → **SPF pass**. If no → **SPF fail**.

**Limitation**: SPF only checks the hidden "envelope from" address (used during SMTP delivery), not the visible "From:" header that users see. Attackers can exploit this mismatch.

---

**DKIM — DomainKeys Identified Mail**

DKIM adds a **cryptographic signature** to every outgoing email. Think of it like a wax seal on a letter — it proves the message has not been tampered with in transit and really originated from the claimed domain.

The sending organisation has a private key (kept secret on their mail servers) and publishes the corresponding public key in DNS. When the email arrives, the receiving server retrieves the public key from DNS and verifies the signature.

If the signature checks out → **DKIM pass**. If the email was modified in transit or the signature is missing → **DKIM fail** or **DKIM none**.

DKIM survives email forwarding better than SPF, because it is tied to the message content, not the sending server's IP address.

---

**DMARC — Domain-based Message Authentication, Reporting & Conformance**

DMARC is the **policy layer** that sits on top of SPF and DKIM. It answers two questions:
1. **What should receiving servers do when SPF or DKIM fail?**
2. **How should failures be reported back to the domain owner?**

A DMARC record in DNS looks like:
\`v=DMARC1; p=reject; rua=mailto:dmarc-reports@corp.com\`

The **p= (policy) field** is the most important:
- \`p=none\` — Monitor only; take no action on failures. Used when first deploying DMARC.
- \`p=quarantine\` — Send failing emails to spam/junk folder.
- \`p=reject\` — Block and discard failing emails entirely. This is the most protective setting.

**DMARC Alignment** is a critical concept: for DMARC to pass, either the SPF domain or the DKIM signing domain must **align** (match) with the visible "From:" header domain. This closes the SPF loophole mentioned above.

---

**Reading the Authentication-Results Header**

Every email received by Exchange Online gets an **Authentication-Results** header added to it. This is where SOC analysts look to quickly check the authentication status of a suspicious email.

Example:
\`Authentication-Results: spf=fail (sender IP is 185.234.5.6); dkim=none; dmarc=fail action=none header.from=corp.com\`

Breaking this down:
- **spf=fail** — The sending IP (185.234.5.6) is NOT in corp.com's SPF record. This IP is not authorised.
- **dkim=none** — No DKIM signature was present at all. Legitimate email from Microsoft 365 always has DKIM.
- **dmarc=fail** — Because both SPF and DKIM failed, DMARC also fails.
- **action=none** — The DMARC policy is \`p=none\`, so the email was delivered anyway (just monitored).

**Key insight for analysts**: An email with \`dmarc=fail action=none\` was delivered to the inbox despite failing authentication. This is a critical finding — especially if the "From:" domain appears to be a trusted organisation like your CEO's company.

**Microsoft's 2025 enforcement update**: In May 2025, Microsoft began rejecting bulk email from senders who lack proper DMARC, SPF, and DKIM alignment when sending to consumer Microsoft addresses (Outlook.com, Hotmail). Enterprise tenants can enforce stricter policies in their own anti-phishing policies.`,
    } satisfies ReadingTask,

    // ── Reading 3: BEC Detection & Monitoring ─────────────────────────────────
    {
      type: "reading",
      id: "exch-sec-r3",
      heading: "Detecting BEC Attacks and Monitoring Exchange Online",
      content: `**Business Email Compromise (BEC)** is one of the most financially damaging cyber threats facing organisations today. The FBI's Internet Crime Complaint Center (IC3) reports billions of dollars in BEC losses every year. Unlike ransomware, BEC doesn't need malware — it relies on deception.

**How BEC Works**

In a typical BEC scenario:
1. An attacker identifies a target organisation (e.g. Acme Corp) and researches its executives (LinkedIn, company website).
2. The attacker spoofs or typosquats the CEO's email address. Typosquatting means registering a domain that looks similar: \`acm3corp.com\` instead of \`acmecorp.com\`, or \`acmecorρ.com\` (using a Greek letter that looks like 'p').
3. The attacker emails the CFO or Finance team, impersonating the CEO: "I need an urgent wire transfer of $450,000 to this account. I'm in a meeting and cannot talk — just do it now."
4. The sense of urgency, combined with authority, causes the victim to act without verifying.

**Key BEC Detection Signals**

As a SOC analyst, watch for these in your email security tools:

- **DMARC/SPF/DKIM failures on executive-looking domains**: A message appearing to be from the CEO but with \`dmarc=fail\` is a major red flag.
- **Lookalike sender domains**: Compare the P2 sender domain (displayed to the user) against your internal domain list. Is \`c0rp.com\` (with a zero) trying to look like \`corp.com\`?
- **Urgency keywords in subjects**: "URGENT", "Wire Transfer", "Payment Required", "Confidential" are classic BEC subject line patterns.
- **Mismatch between display name and email address**: The From display says "John Smith (CEO)" but the actual email address is \`ceo@randomdomain.ru\`.
- **Reply-To header manipulation**: The visible From address looks legitimate but the Reply-To points to an attacker-controlled address.

**Malicious Inbox Rules — The Silent Forwarder**

A sophisticated attacker who successfully compromises a mailbox often creates **inbox rules** to maintain persistence and steal information silently. A common rule:
- Forward all incoming emails to an external address (attacker's mailbox)
- Delete the forwarded emails from Sent Items and Inbox so the victim doesn't notice
- Move security alerts or IT emails to Deleted Items automatically

These rules appear in the **Exchange Unified Audit Log** as the \`UpdateInboxRules\` or \`Set-InboxRule\` operations.

**Monitoring Exchange Online — Key Tools**

| Tool | Where | What SOC Analysts Use It For |
|---|---|---|
| **Message Trace** | admin.exchange.microsoft.com → Mail flow → Message trace | Track individual emails: was it delivered, quarantined, or blocked? What was the spam confidence level? |
| **Quarantine Review** | security.microsoft.com → Email & collaboration → Quarantine | Review and release quarantined messages; look for false positives or attacker-released malware |
| **Unified Audit Log** | compliance.microsoft.com or via Search-UnifiedAuditLog | Find MailItemsAccessed, SendAs, AddDelegate, UpdateInboxRules events |
| **Threat Explorer** | security.microsoft.com → Email & collaboration → Explorer | Hunt for phishing campaigns, see email delivery status, trace URLs clicked by users |
| **Alert Policies** | security.microsoft.com → Alerts | Pre-built alerts for forwarding rules, unusual send volumes, impersonation detection |

**Key Audit Log Operations to Know**

- \`MailItemsAccessed\` — Someone accessed specific emails (critical for OAuth token compromise investigations)
- \`SendAs\` — Someone sent email as another user
- \`AddDelegate\` — A delegate (another user) was given access to a mailbox
- \`UpdateInboxRules\` — An inbox rule was created or modified (check External Address in the rule details)
- \`Set-InboxRule\` — PowerShell-based inbox rule creation (more suspicious than GUI-based)

**Practical Analyst Workflow for Suspicious Email**

1. Open **Message Trace** and find the email by sender, recipient, or subject.
2. Check the **Authentication-Results**: did SPF, DKIM, DMARC pass?
3. Check the **SCL score**: was it filtered but delivered anyway?
4. Check the **P2SenderDomain** field: does it match the display name domain?
5. Search the **Unified Audit Log** for \`UpdateInboxRules\` by that user in the past 30 days.
6. If the user clicked a link, check **Safe Links** reports in Threat Explorer.
7. If mailbox compromise is suspected, check \`MailItemsAccessed\` for unusual activity.`,
    } satisfies ReadingTask,

    // ── Question 1 ────────────────────────────────────────────────────────────
    {
      type: "question",
      id: "exch-sec-q1",
      question: "An email arrives at your company with the following header:\n\n`Authentication-Results: spf=pass; dkim=pass; dmarc=fail action=quarantine`\n\nWhat does this indicate?",
      options: [
        "Both SPF and DKIM passed, so DMARC must have also passed — this is a false alarm",
        "SPF and DKIM passed but the domains do not align with the visible From: header, so DMARC failed",
        "The email server could not reach DNS and had to quarantine the message as a precaution",
        "DMARC failure means the email was definitely sent by an attacker"
      ],
      answer: 1,
      explanation: "DMARC can fail even if SPF and DKIM individually pass, because DMARC requires **alignment** — the SPF domain or DKIM signing domain must match the visible From: header domain. Without alignment, an attacker can pass SPF/DKIM on their own domain while spoofing a different domain in the From: header. The action=quarantine means the email went to spam/junk rather than the inbox.",
      xp: 30,
    } satisfies QuestionTask,

    // ── Question 2 ────────────────────────────────────────────────────────────
    {
      type: "question",
      id: "exch-sec-q2",
      question: "A finance employee reports receiving an urgent email from the CEO asking for a $200,000 wire transfer. The email passed SPF and DKIM. However, you notice the sender domain in the email is `c0rp.com` (with a zero) not `corp.com`. What attack technique is this?",
      options: [
        "Credential stuffing — the attacker used stolen passwords to access the CEO mailbox",
        "Typosquatting / lookalike domain — registering a visually similar domain to impersonate a trusted sender",
        "Replay attack — the attacker replayed a previously legitimate email with modified content",
        "DNS hijacking — the attacker redirected the corp.com DNS records to their own server"
      ],
      answer: 1,
      explanation: "This is a classic **typosquatting** (lookalike domain) BEC attack. The attacker registered `c0rp.com` (with a zero instead of the letter O) and configured valid SPF and DKIM for that domain — so authentication checks pass. DMARC would only fail if the victim's domain has DMARC alignment enforcement. The P2SenderDomain field in Exchange logs and the visible From: address are the key places to spot this.",
      xp: 30,
    } satisfies QuestionTask,

    // ── Question 3 ────────────────────────────────────────────────────────────
    {
      type: "question",
      id: "exch-sec-q3",
      question: "You're investigating a possible account compromise. Which Exchange audit log operation most directly indicates that an attacker created a silent forwarding rule to exfiltrate emails to an external address?",
      options: [
        "MailItemsAccessed",
        "SendAs",
        "UpdateInboxRules",
        "AddPermission"
      ],
      answer: 2,
      explanation: "**UpdateInboxRules** (or Set-InboxRule) is logged whenever an inbox rule is created or modified. A common BEC persistence technique is creating a rule that forwards all incoming email to an external attacker-controlled address and deletes the copies. MailItemsAccessed shows that emails were read, SendAs means email was sent as another user, and AddPermission grants mailbox access — all suspicious, but UpdateInboxRules is the most direct indicator of a forwarding-rule backdoor.",
      xp: 30,
    } satisfies QuestionTask,

    // ── Log Analysis: BEC email with failed DMARC ─────────────────────────────
    {
      type: "log_analysis",
      id: "exch-sec-la1",
      heading: "Suspicious Email — Wire Transfer Request",
      context: "You are a SOC analyst at Corp Inc. The email security system has flagged an inbound message received by the Finance team. The message trace log below was pulled from the Exchange Admin Center. Analyse the event and answer the questions.",
      event: {
        id: "exch-la1-001",
        ts: "2025-11-14T09:23:41.000Z",
        source: "exchange",
        event_type: "email_received",
        severity: "high",
        description: "Inbound email to finance team — authentication failures detected",
        hostname: "mail.protection.outlook.com",
        user_email: "finance@corp.com",
        mitre_technique: "T1566.002",
        mitre_tactic: "Initial Access",
        vendor: "Microsoft 365 Unified Audit Log",
        raw: {
          "data.office365.Operation": "MessageReceived",
          "data.office365.InternetMessageId": "<7f3a9b21@mail.c0rp.com>",
          "data.office365.SenderAddress": "ceo@c0rp.com",
          "data.office365.RecipientAddress": "finance@corp.com",
          "data.office365.Subject": "URGENT: Wire Transfer Required — Confidential",
          "data.office365.AuthenticationResults": "spf=fail (sender IP is 185.234.91.7 not in c0rp.com SPF); dkim=none; dmarc=fail action=none",
          "data.office365.SCL": "5",
          "data.office365.BCL": "0",
          "data.office365.P2SenderDomain": "c0rp.com",
          "data.office365.DeliveryAction": "Delivered",
          "data.office365.DeliveryLocation": "Inbox",
          "data.office365.NetworkMessageId": "ae9f2c1d-4b77-4e3a-9123-fa8d2b3c9e01",
          "data.office365.ClientIP": "185.234.91.7"
        },
      } satisfies TelemetryEvent,
      questions: [
        {
          question: "The email was delivered to the Finance inbox despite authentication failures. What is the most likely reason it was not blocked?",
          options: [
            "Exchange Online Protection is not enabled for this tenant",
            "The DMARC policy for the sender domain is p=none (monitor only), so no action was taken",
            "The SCL score of 5 is below the threshold for blocking",
            "SPF failure always results in delivery to the inbox"
          ],
          answer: 1,
          explanation: "The Authentication-Results header shows `dmarc=fail action=none`. The `action=none` means the sender's DMARC policy is set to `p=none` — monitoring only, no enforcement. This is common for domains that have just started deploying DMARC. EOP respects this policy and delivers the email. The SCL of 5 also contributed (borderline spam threshold), but the DMARC policy is the key reason a flagged BEC email was delivered.",
          xp: 40,
        },
        {
          question: "Looking at the raw log, what is the most suspicious indicator that this is a BEC (Business Email Compromise) attempt impersonating your CEO?",
          options: [
            "The SCL score is 5, which is the highest possible value",
            "The P2SenderDomain is c0rp.com (with a zero) instead of corp.com — a lookalike domain",
            "The email was sent at 09:23 local time, outside business hours",
            "The message was delivered to the Junk folder rather than the inbox"
          ],
          answer: 1,
          explanation: "The `P2SenderDomain` field shows `c0rp.com` — with the letter O replaced by the number zero (0). This is a classic **typosquatting** technique designed to visually fool users and bypass some email filters. The attacker registered this lookalike domain and configured email on it. From the Finance employee's perspective, the display name probably says 'CEO' and the domain looks legitimate at a glance. This is the primary BEC indicator in this log.",
          xp: 40,
        },
      ],
    } satisfies LogAnalysisTask,

    // ── Flag Task ─────────────────────────────────────────────────────────────
    {
      type: "flag",
      id: "exch-sec-f1",
      prompt: "Look at the log analysis event above. The attacker registered a lookalike domain to impersonate your CEO. What is the exact sender domain used in this BEC attempt? (Copy it exactly as it appears in the P2SenderDomain field.)",
      answer: "c0rp.com",
      hint: "Look at the raw log field called data.office365.P2SenderDomain. It looks almost like 'corp.com' but one character is different.",
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
    "Discover how attackers exploit Microsoft's collaboration tools to steal data, conduct phishing via Teams chat, and abuse external sharing. Learn to detect bulk exfiltration, insider threats, and guest-account abuse.",
  difficulty: "intermediate",
  category: "Cloud Security",
  estimatedMinutes: 40,
  xp: 220,
  icon: "💬",
  prerequisites: ["microsoft-365-security"],
  tasks: [

    // ── Reading 1: SharePoint & OneDrive Structure ────────────────────────────
    {
      type: "reading",
      id: "spt-teams-r1",
      heading: "SharePoint Online & OneDrive — How Data Lives in Microsoft 365",
      content: `**SharePoint Online** is Microsoft's cloud-based document management and collaboration platform. If you've ever seen a shared company folder in a browser that looks like a file explorer, chances are it was SharePoint. In a Microsoft 365 organisation, SharePoint is where teams store, share, and collaborate on documents. It integrates tightly with Teams (every Teams channel has a SharePoint library behind it), Outlook, and OneDrive.

**The SharePoint Architecture You Need to Know**

Understanding how SharePoint is organised helps you understand where data lives and how it can be leaked:

- **Tenant** — The entire organisation's Microsoft 365 environment. Everything lives under one tenant.
- **Site Collections / Sites** — Think of these as top-level department folders. Example: \`corp.sharepoint.com/sites/Finance\`, \`corp.sharepoint.com/sites/HR\`, \`corp.sharepoint.com/sites/Engineering\`.
- **Document Libraries** — Inside each site, there are document libraries. A library is like a folder that can have sub-folders, metadata, permissions, and version history.
- **OneDrive for Business** — Every individual employee gets their own personal SharePoint site for personal work files. This is OneDrive. URL pattern: \`corp-my.sharepoint.com/personal/john_smith_corp_com/\`.

**External Sharing — The Biggest Security Risk**

SharePoint makes it very easy to share files with people outside your organisation. This is useful for collaboration with clients and partners, but it is also a major data leakage risk. There are four levels of external sharing:

1. **Anyone links (Anonymous links)** — The most dangerous setting. A link is created that anyone with the link can access, with no authentication required. No sign-in, no audit trail of who viewed the file.
2. **Specific people links (external)** — A link sent to a specific external email address. The recipient must authenticate, and access is logged.
3. **Existing external guests** — Sharing with people already added as Azure AD guest accounts.
4. **Only people in your organisation** — Internal only; no external sharing.

**Key Audit Events in SharePoint**

Every action in SharePoint is logged in the Microsoft 365 Unified Audit Log (accessible at compliance.microsoft.com). The operations a SOC analyst watches for:

| Operation | What it Means |
|---|---|
| \`FileAccessed\` | A file was opened/viewed |
| \`FileDownloaded\` | A file was downloaded to the user's device |
| \`FileUploaded\` | A file was uploaded to SharePoint |
| \`FileCopied\` | A file was copied within SharePoint |
| \`SharingInvitationCreated\` | A sharing invitation was sent to an external user |
| \`AnonymousLinkCreated\` | An "Anyone" link was created (high risk!) |
| \`AnonymousLinkUsed\` | An "Anyone" link was used to access a file |
| \`SensitiveFileRead\` | A file classified as sensitive (by DLP) was accessed |

**Bulk Downloads — The Classic Data Exfiltration Pattern**

A disgruntled or compromised user exfiltrating data from SharePoint will typically download hundreds or thousands of files in a short time window. Normal user behaviour might be 5–20 file downloads per day. Downloading 500+ files in a single session is highly anomalous.

Microsoft Purview (formerly Compliance Center) can generate alerts when bulk download activity is detected. When you see a \`FileDownloaded\` event storm from a single user, check:
- Is this user leaving the company soon? (Departing employees are a common insider threat vector)
- Are the files from sensitive sites (Finance, HR, Legal, Engineering)?
- What is the user's normal download baseline?
- Is the client IP internal or external?

**Tenant-Level External Sharing Controls**

Administrators can control external sharing at the SharePoint Admin Center (admin.microsoft.com → SharePoint → Policies → Sharing). SOC analysts should know whether their organisation allows "Anyone" links — if so, any created "Anyone" link is an unmonitorable exfiltration channel once the URL is shared externally.`,
    } satisfies ReadingTask,

    // ── Reading 2: Microsoft Teams Security ───────────────────────────────────
    {
      type: "reading",
      id: "spt-teams-r2",
      heading: "Microsoft Teams Security Risks and Monitoring",
      content: `Microsoft Teams has become one of the most widely used business communication platforms in the world. With hundreds of millions of daily active users, it is also an increasingly attractive target for attackers. SOC analysts need to understand how Teams works and how it can be abused.

**Teams Architecture Basics**

- **Teams** contain **Channels**. Each channel is a conversation thread plus a shared file library (backed by SharePoint).
- **Chats** are direct messages between individuals or small groups. These are separate from channels.
- **Files** shared in Teams are actually stored in the team's SharePoint library or in the sender's OneDrive.
- **External Access** allows Teams users to message people in other organisations' Teams tenants. This is a legitimate feature for business collaboration.
- **Guest Access** allows external people to be added as full members of a specific Team. They get an Azure AD guest account (B2B).

**Teams Attack Vectors**

**1. Phishing via Teams Chat**
Attackers have increasingly pivoted from email phishing to Teams phishing. The reasoning: employees are trained to be suspicious of phishing emails, but they often have lower guard in Teams chat. Techniques include:
- Sending malicious links in Teams messages to internal users (if an internal account is compromised)
- Using External Access to message employees from a fake external tenant (e.g. a tenant named "Microsoft Support")
- Adding external guests to a Team and using that access to harvest data or spread malware

The attack tool **TeamsPhisher** (seen in red-team exercises and actual attacks by groups like Midnight Blizzard) automates sending phishing links via Teams to large numbers of users by abusing the External Access feature.

**2. Guest Account Abuse**
When an external guest is added to a Team, they can access all files in that team's SharePoint library. A compromised or malicious guest account can exfiltrate documents. Guest accounts appear in audit logs with a UPN suffix like \`user_externalcompany.com#EXT#@corp.onmicrosoft.com\`.

**3. External Access Abuse**
External Access (federation between tenants) allows anyone from any tenant to initiate a Teams chat with your employees by default. Attackers set up Microsoft 365 tenants with names like "Microsoft Help Desk" and message your employees claiming to be IT support.

**Key Teams Audit Events**

| Operation | Significance |
|---|---|
| \`MessageSent\` | A message was sent in a channel or chat |
| \`MessageDeleted\` | A message was deleted (suspicious if done in bulk) |
| \`GuestAdded\` | An external guest was added to a Team |
| \`TeamCreated\` | A new Team was created |
| \`MemberAdded\` | A member was added to an existing Team |
| \`FileSyncUploadedFull\` | A file was synced/uploaded via OneDrive sync client |
| \`AppInstalled\` | A Teams app was installed (could be malicious app) |

**Microsoft Defender for Cloud Apps (MDCA) Integration**

Microsoft Defender for Cloud Apps (formerly Cloud App Security) can monitor Teams activity and generate alerts. It integrates with the Microsoft 365 audit log and applies machine-learning-based anomaly detection. Relevant MDCA policies for Teams:
- **Mass download by a single user**: Triggers when a user downloads far more files than their peers.
- **Activity from infrequent country**: A Teams login from a country the user has never been in before.
- **Suspicious app consent**: A third-party Teams app was granted broad permissions.

**DLP in Teams**

Microsoft Purview DLP policies can inspect Teams messages and files shared in Teams for sensitive data types (credit card numbers, Social Security Numbers, custom regex patterns). When a policy matches, Teams will show a warning to the user or block the message entirely. SOC analysts see these as \`DlpRuleMatch\` events in the audit log, with the Teams workload.`,
    } satisfies ReadingTask,

    // ── Reading 3: DLP and Insider Threat ─────────────────────────────────────
    {
      type: "reading",
      id: "spt-teams-r3",
      heading: "DLP and Insider Threat Detection in Microsoft 365",
      content: `**Data Loss Prevention (DLP)** is a set of policies and technologies designed to detect and prevent the movement of sensitive information outside your organisation. In Microsoft 365, DLP is managed through **Microsoft Purview** (compliance.microsoft.com → Data loss prevention).

**How Microsoft Purview DLP Works**

DLP policies define three things:
1. **What to protect** — Sensitive information types (e.g. credit card numbers, UK National Insurance numbers, patient health information, company-defined custom patterns like project codes).
2. **Where to protect it** — Which services to monitor: Exchange email, SharePoint, OneDrive, Teams chats, Endpoint devices, Power BI.
3. **What to do when a match occurs** — Options include: notify the user with a policy tip (warning), block the action (prevent sending/uploading), notify the admin, log the event for audit.

**Key DLP Audit Operations**

- \`DlpRuleMatch\` — A DLP policy rule was triggered. The audit log entry includes: the policy name, the rule that matched, the workload (Exchange/SharePoint/Teams), the user who triggered it, the sensitive information type(s) detected, and the confidence level and count.
- \`DlpRuleUndo\` — A user acknowledged a policy tip and provided a justification to override the block.
- \`DlpRuleActivated\` — A DLP rule was enabled or changed.

**Insider Threat — The Risk from Within**

Insider threats come from current or former employees (or contractors) who misuse their legitimate access to steal, damage, or expose data. They are especially dangerous because:
- They already have authorised access — no need to "break in"
- They know where sensitive data lives
- Their activity can look legitimate until you look closely

**Microsoft Purview Insider Risk Management**

Microsoft Purview offers a dedicated **Insider Risk Management** module (separate from DLP) that uses machine learning to score users based on risky behaviours:
- **Data theft by departing employees**: Triggered when HR feeds show a user's resignation date is approaching and that user starts downloading unusually large amounts of data.
- **Data leaks**: High volume of file uploads to personal cloud storage or email to personal accounts.
- **Security policy violations**: Attempting to access restricted sites or disabling security tools.

The module requires integration with HR systems and applies a risk score to users. High-scoring users appear in the Insider Risk dashboard.

**Behavioural Indicators of Insider Threat in SharePoint**

Even without Purview Insider Risk Management, SOC analysts can identify suspicious insider behaviour by looking for these patterns in the Unified Audit Log:

| Indicator | Description |
|---|---|
| **Bulk download** | User downloads hundreds of files in a short time window (e.g. 847 files in 4 minutes) |
| **Access to previously unvisited folders** | User suddenly accesses Finance or Legal folders they have never touched in 12 months |
| **Off-hours access** | Downloads at 2 AM on a Saturday are unusual for a normal employee |
| **Download from sensitive sites** | Focus on Finance, HR, Legal, Engineering IP repositories |
| **External sharing spike** | Sudden creation of many "Anyone" links or sharing invitations to personal email addresses |
| **OneDrive sync of entire libraries** | Syncing a whole SharePoint library to a personal laptop for offline access |

**Practical Investigation Workflow**

When you receive a DLP alert or a bulk-download alert:

1. Go to **compliance.microsoft.com → Audit** and search for the user's \`FileDownloaded\` operations in the last 24–72 hours.
2. Count the volume and look at the file paths — were they from sensitive sites like /Finance/ or /HR/?
3. Check the **ClientIP** field — is this the user's normal corporate IP or an unusual external IP?
4. Cross-reference with **HR systems** — is this employee on a performance improvement plan, under investigation, or about to leave?
5. Check for **external sharing** by the same user: search for \`AnonymousLinkCreated\` or \`SharingInvitationCreated\` with external email addresses.
6. If warranted, **escalate to HR and Legal** — insider threat cases have legal and HR implications beyond technical response.`,
    } satisfies ReadingTask,

    // ── Question 1 ────────────────────────────────────────────────────────────
    {
      type: "question",
      id: "spt-teams-q1",
      question: "An attacker creates an anonymous 'Anyone' link for a sensitive financial spreadsheet in SharePoint and shares the URL externally. What is the primary security limitation of this sharing method from a SOC analyst's perspective?",
      options: [
        "The file cannot be downloaded via an Anyone link, only viewed in browser",
        "Anyone links expire after 24 hours by default and cannot be extended",
        "There is no authentication requirement, so audit logs cannot track who accessed the file after the link is shared externally",
        "Anyone links are restricted to SharePoint Online and do not work in OneDrive"
      ],
      answer: 2,
      explanation: "**Anyone links** (anonymous links) are the most dangerous sharing mode because they require no authentication. The SharePoint audit log records when the link is **created** (`AnonymousLinkCreated`) and potentially when it is **used** (`AnonymousLinkUsed`), but if the attacker downloads the file using the link and then shares the file itself or its contents externally, there is no record of that. More critically, any person who receives the link can access the file — there is no identity binding, so the audit trail ends at the link creator.",
      xp: 30,
    } satisfies QuestionTask,

    // ── Question 2 ────────────────────────────────────────────────────────────
    {
      type: "question",
      id: "spt-teams-q2",
      question: "You see a user with the UPN `vendor_externalco.com#EXT#@corp.onmicrosoft.com` downloading files from your Finance SharePoint site. What type of account is this?",
      options: [
        "A service account used by an automated process",
        "An Azure AD guest account — an external user who was invited to your tenant",
        "A compromised internal employee account that has been renamed by the attacker",
        "A Microsoft Graph API account used for reporting"
      ],
      answer: 1,
      explanation: "The `#EXT#` suffix in a UPN is the unmistakable marker of an **Azure AD B2B guest account**. When you invite an external user to your tenant (to a Team, SharePoint site, or application), Microsoft creates a guest account with this naming convention: `<original-email-with-@-replaced-by-underscore>#EXT#@<your-tenant>.onmicrosoft.com`. Seeing a guest account accessing sensitive Finance files is a red flag — guest accounts should have tightly scoped access and their activity should be reviewed.",
      xp: 30,
    } satisfies QuestionTask,

    // ── Question 3 ────────────────────────────────────────────────────────────
    {
      type: "question",
      id: "spt-teams-q3",
      question: "Which Microsoft 365 portal is the primary place for a SOC analyst to search the Unified Audit Log for SharePoint file download events?",
      options: [
        "admin.microsoft.com (Microsoft 365 Admin Center)",
        "admin.exchange.microsoft.com (Exchange Admin Center)",
        "compliance.microsoft.com (Microsoft Purview compliance portal)",
        "security.microsoft.com (Microsoft Defender XDR portal)"
      ],
      answer: 2,
      explanation: "The **Microsoft Purview compliance portal** (compliance.microsoft.com → Audit) is the central location for searching the Microsoft 365 Unified Audit Log. This log contains SharePoint `FileDownloaded`, `FileAccessed`, `AnonymousLinkCreated`, Exchange `UpdateInboxRules`, Teams `GuestAdded`, and thousands of other operation types from across all Microsoft 365 services. The Defender portal (security.microsoft.com) focuses on security alerts and threat hunting; the Exchange Admin Center focuses on email flow; the Admin Center focuses on user management.",
      xp: 30,
    } satisfies QuestionTask,

    // ── Log Analysis: Bulk SharePoint Download ────────────────────────────────
    {
      type: "log_analysis",
      id: "spt-teams-la1",
      heading: "Mass File Download Alert — SharePoint",
      context: "You are reviewing alerts in the Microsoft Purview compliance portal. A bulk-download alert has fired for a user in the Finance department. The alert aggregated 847 individual FileDownloaded operations into this summary event. The user's last day of employment is in 3 days according to HR records.",
      event: {
        id: "spt-la1-001",
        ts: "2025-11-21T22:47:15.000Z",
        source: "sharepoint",
        event_type: "sharepoint_download",
        severity: "high",
        description: "Mass file download alert — possible data exfiltration by departing employee",
        user_email: "departing.employee@corp.com",
        src_ip: "10.0.1.55",
        mitre_technique: "T1213.002",
        mitre_tactic: "Collection",
        vendor: "Microsoft 365 Unified Audit Log",
        raw: {
          "data.office365.Operation": "FileDownloaded",
          "data.office365.UserId": "departing.employee@corp.com",
          "data.office365.ClientIP": "10.0.1.55",
          "data.office365.ObjectId": "https://corp.sharepoint.com/sites/Finance/Shared Documents/Q4_Revenue_Report.xlsx",
          "data.office365.Workload": "SharePoint",
          "data.office365.SourceFileName": "Q4_Revenue_Report.xlsx",
          "data.office365.SourceRelativeUrl": "/sites/Finance/Shared Documents/",
          "rule.description": "Mass file download detected — 847 files in 4 minutes",
          "data.office365.SiteUrl": "https://corp.sharepoint.com/sites/Finance",
          "data.office365.EventData": "{\"ListItemUniqueId\":\"a7f9c2e1-...\",\"DestinationUrl\":\"\"}",
          "rule.level": "high"
        },
      } satisfies TelemetryEvent,
      questions: [
        {
          question: "Given the context (847 files, 4 minutes, departing employee, Finance site), what is the most likely classification of this event?",
          options: [
            "False positive — employees routinely download large numbers of files when setting up new machines",
            "True positive — this shows strong indicators of insider data theft, likely pre-departure exfiltration",
            "Informational — bulk downloads are expected from Finance users at month-end",
            "Low priority — since the IP address is internal (10.x.x.x), data cannot leave the network"
          ],
          answer: 1,
          explanation: "This is a **true positive** with multiple converging risk signals: (1) 847 files in 4 minutes is far outside normal human download behaviour — this is the speed of a script or mass-sync, (2) the user is departing in 3 days — a classic **pre-departure exfiltration** scenario, (3) the site is Finance, which contains sensitive financial data. The internal IP (10.0.1.55) does not rule out exfiltration — the user could have downloaded to a laptop and then transferred via personal cloud storage, USB, or email. This needs immediate investigation.",
          xp: 40,
        },
        {
          question: "The alert only captures FileDownloaded operations inside SharePoint. Which MITRE ATT&CK tactic does this bulk-download activity fall under, and what would you still need to confirm to prove data actually left the organisation?",
          options: [
            "Command and Control — the downloads themselves prove a C2 channel exists between the attacker and the file server",
            "Collection — the downloads gather data locally onto the user's device; you would still need to check for a follow-on transfer (e.g. USB, personal cloud upload, or email) to confirm exfiltration",
            "Initial Access — file downloads are how the attacker first got into the SharePoint site",
            "Persistence — repeatedly downloading the same files is how the attacker maintains access to the account"
          ],
          answer: 1,
          explanation: "Downloading files out of a repository like SharePoint onto a local device is the **Collection** tactic — the attacker (or insider) is gathering data, not yet moving it out of the organisation. To confirm actual **exfiltration**, you would need corroborating evidence of the data leaving the network entirely, such as DLP alerts for USB transfer, uploads to personal cloud storage, or large outbound email attachments. Seeing only the download operation tells you data was collected locally — it does not by itself prove the data left the company.",
          xp: 40,
        },
      ],
    } satisfies LogAnalysisTask,

    // ── Flag Task ─────────────────────────────────────────────────────────────
    {
      type: "flag",
      id: "spt-teams-f1",
      prompt: "Look at the bulk-download log analysis above. According to the alert, exactly how many files were downloaded in this incident?",
      answer: "847",
      hint: "The count is in the task's opening context, and again in the rule.description field.",
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
      heading: "From Antivirus to EDR — The Evolution of Endpoint Security",
      content: `**What is an Endpoint?**

An **endpoint** is any device that connects to a network and can be a target for attack. In a corporate environment, this includes:
- **Laptops and desktops** — The most common endpoints. Used by employees daily.
- **Servers** — High-value targets. They host applications, databases, and sensitive data.
- **Mobile devices** — Smartphones and tablets that connect to company email and apps.
- **IoT devices** — Security cameras, badge readers, smart thermostats, industrial sensors. These are increasingly connected to corporate networks and often have weak security.

**Why Endpoints?**

Attackers target endpoints because they are where humans interact with technology. A human can be tricked into clicking a phishing link, downloading a malicious file, or entering credentials on a fake website. Once an attacker has code running on an endpoint, they can steal data, move to other systems, or deploy ransomware.

---

**Generation 1: Traditional Antivirus (AV) — The Signature Era (1987–2010s)**

Traditional antivirus works like a criminal wanted-poster database. Every known piece of malware is given a unique "fingerprint" called a **signature** — a pattern of bytes found in that specific malware file. When the AV scans a file, it compares it against this database of signatures. If there is a match → malware detected.

**Limitation**: Traditional AV is completely blind to **new malware it has never seen before** (zero-day malware). Attackers figured out that if they change the malware slightly (polymorphic malware) or pack it differently, the signature no longer matches and AV misses it entirely. By the early 2010s, attackers were generating thousands of new malware variants per day, and signature databases simply couldn't keep up.

---

**Generation 2: NGAV — Next-Generation Antivirus (2012–present)**

**NGAV** abandoned pure signature matching in favour of:
- **Behavioural detection**: Instead of asking "does this file match a known bad signature?", NGAV asks "is this process *behaving* like malware?" — for example, does it enumerate all files and start encrypting them? That behaviour pattern is ransomware, even if the file has never been seen before.
- **Machine learning**: Models trained on millions of malware samples can detect new malware based on subtle characteristics, even without an exact signature match.
- **Memory scanning**: Detecting malicious code that runs only in memory without ever writing to disk (fileless malware).
- **Exploit prevention**: Blocking exploitation techniques like buffer overflows and code injection, regardless of the specific vulnerability being exploited.

Products like **CrowdStrike Falcon Prevent**, **SentinelOne Singularity**, and **Microsoft Defender Antivirus** are NGAV solutions.

---

**Generation 3: EDR — Endpoint Detection & Response (2013–present)**

**EDR** is a quantum leap beyond NGAV. Think of NGAV as an alarm system that beeps when someone breaks in. EDR is an alarm system *plus* a full security camera system *plus* a recording of everything that happened before and after the break-in.

EDR's defining characteristic is **continuous monitoring and telemetry recording**. An EDR agent on every endpoint silently records everything:
- Every process that starts (name, command line, parent process, user)
- Every file created, modified, or deleted
- Every network connection made (destination IP, port, process that made it)
- Every registry key changed
- Every PowerShell or script executed

This **telemetry stream** flows to a central cloud platform where it is analysed in real time. This enables:

1. **Threat detection**: Alert when a behaviour pattern matches a known attack technique.
2. **Investigation**: When an alert fires, analysts can look back through the recorded telemetry to understand exactly what happened — a full **process tree** showing parent → child process chains.
3. **Remote response**: Isolate a compromised laptop from the network with one click, kill a malicious process, delete a malicious file — all without touching the physical device.

**Key EDR vendors today (2026)**:
- **CrowdStrike Falcon Insight XDR** — Industry-leading threat intelligence and process telemetry depth.
- **SentinelOne Singularity** — Best autonomous response (can auto-remediate without analyst intervention, including ransomware rollback).
- **Microsoft Defender for Endpoint Plan 2 (MDE)** — Excellent value for Microsoft 365 E5 customers; deep Windows integration; native integration with Entra ID and Purview.
- **Palo Alto Cortex XDR** — Strong in mixed-OS environments (Windows, macOS, Linux).
- **VMware Carbon Black** — Popular in regulated industries.

---

**Generation 4: XDR — Extended Detection & Response (2019–present)**

**XDR** takes the EDR concept and extends it beyond the endpoint:
- **EDR**: Endpoint telemetry only
- **XDR**: Endpoint + Network + Identity + Email + Cloud in one unified platform

Instead of having separate tools for each domain that analysts must correlate manually, XDR correlates telemetry across all these sources automatically. An attack that starts with a phishing email → compromised credentials → lateral movement via PowerShell → data exfiltration to cloud storage can be visualised as a single correlated incident timeline in XDR, rather than scattered alerts across five different tools.

**Microsoft Defender XDR** is Microsoft's XDR platform, combining: Defender for Endpoint, Defender for Office 365, Defender for Identity, and Defender for Cloud Apps.`,
    } satisfies ReadingTask,

    // ── Reading 2: EDR Deep Dive ───────────────────────────────────────────────
    {
      type: "reading",
      id: "ep-sec-r2",
      heading: "EDR Deep Dive — What It Collects and What Analysts Do With It",
      content: `Now that you understand *what* EDR is, let's go deeper into *how* it works and what a SOC analyst actually does with EDR data.

**The EDR Agent**

Every endpoint protected by EDR has a small software program installed on it called an **agent** (also called a sensor or client). This agent runs silently in the background, consuming minimal CPU and memory, and does two things:
1. **Collects telemetry** — Records every process, file, network, and registry event.
2. **Enforces prevention** — Can block malicious behaviour in real-time (NGAV function).

The agent sends telemetry to a central **cloud platform** (e.g. CrowdStrike's Threat Graph, SentinelOne's SentinelCloud, or Microsoft's Defender for Endpoint in Azure). This is where detection rules run and analysts investigate.

**The Process Tree — The Most Powerful Investigation Tool**

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
| **Process events** | Process name, PID, parent process, command line, file hash, user, integrity level | Core of investigation — who ran what? |
| **File events** | File path, operation (create/modify/delete), hash, process that caused it | Detect malware being written to disk |
| **Network connections** | Process that made the connection, destination IP and port, bytes transferred | Detect C2 (command-and-control) communications |
| **Registry events** | Key path, operation, new value, process that changed it | Detect persistence mechanisms (malware setting itself to run at boot) |
| **User activity** | Login/logout events, authentication method | Detect lateral movement via stolen credentials |
| **DNS queries** | Domain queried, response IP, process that made the query | Detect malicious domain lookups |

**EDR Response Capabilities**

EDR platforms give analysts powerful remote response capabilities — all from a browser, without touching the physical machine:

- **Network Isolation (Host Isolation)**: Cuts the endpoint off from the network (except for the EDR management channel). The machine cannot talk to anything — not even internal servers. Used immediately when a host is confirmed compromised to prevent lateral movement. One click in the console.
- **Kill Process**: Immediately terminate a malicious process running on the endpoint.
- **Delete File**: Remove a malicious file from the endpoint.
- **Live Response / Remote Shell**: Open a remote command-line shell on the endpoint for in-depth forensic investigation. SOC analysts can run commands, collect files, and examine artefacts without physically touching the device.
- **Run Containment Script**: Push a custom script to the endpoint (e.g. to disable a compromised service or quarantine a file).
- **Collect Forensic Package**: Collect a bundle of artefacts (event logs, memory dump, prefetch files, registry hives) from the endpoint for offline analysis.

**Endpoint Hardening — Reducing the Attack Surface**

EDR detects threats *after* they start. **Endpoint hardening** reduces the attack surface so fewer threats can start:
- **Attack Surface Reduction (ASR) rules** in Microsoft Defender: Block Office macros from spawning processes, block credential theft from LSASS, block executable content in email.
- **Application allowlisting**: Only run approved software. If it's not on the approved list, it can't run.
- **Least privilege**: Users run as standard users, not local administrators. Malware running as the user has limited rights.
- **BitLocker**: Full-disk encryption so stolen laptops don't expose data.
- **Patch management**: Keep the OS and applications updated to close known vulnerabilities.`,
    } satisfies ReadingTask,

    // ── Reading 3: Reading EDR Alerts ─────────────────────────────────────────
    {
      type: "reading",
      id: "ep-sec-r3",
      heading: "How to Read an EDR Alert — A Step-by-Step Approach",
      content: `When an alert appears in your EDR console, it can feel overwhelming at first. There's a lot of information. This reading walks you through a structured approach to reading any EDR alert.

**The Anatomy of a CrowdStrike Alert**

CrowdStrike Falcon is one of the most widely deployed EDR platforms. When it fires an alert, the key fields are:

| Field | What It Is | Example |
|---|---|---|
| \`AlertType\` | Category of the alert | "Process", "Network", "File" |
| \`Severity\` | How bad CrowdStrike thinks it is | Critical, High, Medium, Low |
| \`Technique\` | MITRE ATT&CK technique ID | T1059.001 |
| \`TechniqueName\` | Human name of the technique | "Command and Scripting Interpreter: PowerShell" |
| \`ContextProcessName\` | The process that triggered the alert | powershell.exe |
| \`ContextProcessParentName\` | What launched the alerting process | cmd.exe |
| \`CommandLine\` | The exact command that was run | powershell.exe -NoP -NonI -W Hidden -Exec Bypass -Enc JAB... |
| \`UserName\` | Who was logged in | CORP\\j.smith |
| \`HostName\` | Which machine | LAPTOP-JSMITH |
| \`LocalIP\` | IP address of the machine | 10.0.1.55 |
| \`SHA256\` | Cryptographic hash of the process executable | a1b2c3... |
| \`Confidence\` | How confident CrowdStrike is (0–100) | 95 |

**Step-by-Step Alert Analysis**

**Step 1: Read the alert title and technique**
What is the alert about, broadly? If it says "T1059.001 — PowerShell" you know you're looking at PowerShell abuse, which is extremely common in attacks. If it says "T1003 — Credential Access" you know someone tried to dump credentials.

**Step 2: Identify the affected host and user**
Who and what machine are affected? Is this a finance server (critical) or a developer laptop (important but lower blast radius)? Is the user an administrator or a regular employee?

**Step 3: Examine the command line**
The command line is often the most revealing field. For PowerShell alerts, look for:
- \`-Enc\` or \`-EncodedCommand\`: The command is Base64-encoded to hide what it's doing. This is almost always malicious.
- \`-ExecutionPolicy Bypass\` or \`-Exec Bypass\`: Bypassing PowerShell's safety restrictions. Legitimate scripts rarely need to do this.
- \`-NoP\` or \`-NoProfile\`: Skipping the user profile to avoid PowerShell logging.
- \`-NonI\` or \`-NonInteractive\`: Running without user interaction — indicates automated/scripted execution.
- \`-W Hidden\` or \`-WindowStyle Hidden\`: Hiding the PowerShell window from the user. Malware doesn't want to be seen.
- \`IEX\` or \`Invoke-Expression\`: Executing a string as a command — often used to execute code downloaded from the internet.
- \`DownloadString\` or \`WebClient\`: Downloading code from the internet.

**Step 4: Check the process tree**
Who launched this process? Normal PowerShell usage might be launched by an admin tool or the Windows Task Scheduler. **PowerShell launched by Word, Excel, or Outlook is a major red flag** — it means a document executed malicious code.

**Step 5: Check the hash against threat intelligence**
Copy the SHA256 hash and paste it into **VirusTotal** (virustotal.com) or your threat intelligence platform. If 40 out of 72 antivirus engines flag it as malicious, that confirms the alert.

**Step 6: Look for follow-on activity**
EDR alert timelines let you look at what happened before and after the alert. Did the PowerShell process make any network connections? Did it create any files? Did it spawn any child processes? This tells you whether the attacker succeeded or was caught early.

**Step 7: Determine the response action**
Based on your analysis:
- **Clearly malicious with active threat**: Isolate the host immediately, kill the process, escalate.
- **Suspicious but uncertain**: Escalate to senior analyst, collect forensic package, investigate further.
- **False positive**: Document why and tune the detection rule if needed.

**Common PowerShell Flags and Their Meaning**

| Flag | Short Form | Meaning | Malware Use |
|---|---|---|---|
| \`-NoProfile\` | \`-NoP\` | Skip loading the user's PowerShell profile | Avoid detection by profile-based monitoring |
| \`-NonInteractive\` | \`-NonI\` | Run without prompting the user for input | Automated/scripted execution |
| \`-WindowStyle Hidden\` | \`-W Hidden\` | Hide the PowerShell console window | Don't show the user a black window |
| \`-ExecutionPolicy Bypass\` | \`-Exec Bypass\` | Skip PowerShell script execution policy | Run scripts blocked by policy |
| \`-EncodedCommand\` | \`-Enc\` | Accept a Base64-encoded command | Obfuscate the command from simple string-matching |`,
    } satisfies ReadingTask,

    // ── Question 1 ────────────────────────────────────────────────────────────
    {
      type: "question",
      id: "ep-sec-q1",
      question: "What is the fundamental difference between traditional signature-based antivirus and EDR (Endpoint Detection & Response)?",
      options: [
        "Traditional AV is cloud-based while EDR runs only locally on the device",
        "Traditional AV matches files against a database of known-bad signatures; EDR continuously records all endpoint activity and detects threats through behavioural analysis and threat hunting",
        "EDR only works on Windows devices while traditional AV supports all operating systems",
        "Traditional AV can isolate infected hosts; EDR can only alert without taking action"
      ],
      answer: 1,
      explanation: "The key difference is **scope and approach**. Traditional AV relies on known-bad **signatures** — it cannot detect new malware it has never seen before. EDR continuously records all endpoint telemetry (processes, files, network connections, registry changes) and applies **behavioural analysis** to detect threats regardless of whether they have known signatures. EDR also provides **visibility** for investigation (process trees, command lines, timelines) and **response** capabilities (host isolation, remote shell) that traditional AV completely lacks.",
      xp: 25,
    } satisfies QuestionTask,

    // ── Question 2 ────────────────────────────────────────────────────────────
    {
      type: "question",
      id: "ep-sec-q2",
      question: "An EDR alert shows the following process tree: `winword.exe → cmd.exe → powershell.exe -Enc JAB...`. What does this process chain most likely indicate?",
      options: [
        "A legitimate Microsoft Office macro running a system administration script",
        "A malicious Word document containing a macro that launched PowerShell with an obfuscated encoded command — a classic malware delivery technique",
        "A Windows Update process triggered by Office that needs PowerShell to install patches",
        "CrowdStrike EDR running a built-in diagnostic script"
      ],
      answer: 1,
      explanation: "**winword.exe spawning cmd.exe which spawns powershell.exe** is one of the most classic malicious process chains in endpoint security. Word does not normally spawn command prompts or PowerShell shells during legitimate use. This chain indicates a **malicious Office macro** (embedded in a document) that executed system commands. The `-Enc` flag on PowerShell means the actual command is Base64-encoded — a strong obfuscation indicator. This should be treated as a high-priority true positive.",
      xp: 25,
    } satisfies QuestionTask,

    // ── Question 3 ────────────────────────────────────────────────────────────
    {
      type: "question",
      id: "ep-sec-q3",
      question: "A user's laptop is confirmed to be infected with malware that is actively spreading to other machines on the network. What is the most important immediate EDR response action?",
      options: [
        "Delete the malware file from the infected laptop",
        "Run a full antivirus scan on the laptop",
        "Isolate (network-isolate) the host from the network to prevent further lateral movement",
        "Reboot the laptop to clear the malware from memory"
      ],
      answer: 2,
      explanation: "**Host isolation** (also called network isolation or containment) is the single most important immediate action when a host is actively spreading malware. Isolation cuts the device off from all network communication (except the EDR management channel), preventing the malware from reaching additional hosts, communicating with a command-and-control server, or exfiltrating data. Deleting the malware file and rebooting are secondary steps that come after containment. A full AV scan is also secondary and may miss fileless malware.",
      xp: 25,
    } satisfies QuestionTask,

    // ── Question 4 ────────────────────────────────────────────────────────────
    {
      type: "question",
      id: "ep-sec-q4",
      question: "What does XDR (Extended Detection & Response) add compared to EDR (Endpoint Detection & Response)?",
      options: [
        "XDR adds a graphical user interface to EDR alerts",
        "XDR extends telemetry collection beyond the endpoint to include network, identity, email, and cloud data — correlating across all sources in a single platform",
        "XDR provides better antivirus signatures than EDR",
        "XDR is simply the mobile-device version of EDR"
      ],
      answer: 1,
      explanation: "The 'X' in **XDR** stands for 'Extended' — it extends detection and response **across multiple security domains** beyond just the endpoint. While EDR sees only what happens on a single device, XDR correlates telemetry from endpoints, network traffic, identity systems (Active Directory, Entra ID), email (Exchange, phishing), and cloud workloads (AWS, Azure). This cross-domain correlation allows XDR to detect multi-stage attacks that would appear as disconnected, low-confidence signals in isolated tools. Microsoft Defender XDR, CrowdStrike Falcon XDR, and SentinelOne Singularity XDR are current examples.",
      xp: 25,
    } satisfies QuestionTask,

    // ── Log Analysis: CrowdStrike Alert — Malicious PowerShell ────────────────
    {
      type: "log_analysis",
      id: "ep-sec-la1",
      heading: "CrowdStrike Alert — Suspicious PowerShell Execution",
      context: "You are a Tier 1 SOC analyst. A CrowdStrike Falcon alert has just appeared in your queue. The alert was generated on an employee's laptop. Your task is to analyse the alert details and answer the investigation questions below.",
      event: {
        id: "ep-la1-001",
        ts: "2025-11-19T14:32:07.000Z",
        source: "edr",
        vendor: "CrowdStrike Falcon",
        event_type: "edr_alert",
        severity: "high",
        description: "CrowdStrike: Suspicious encoded PowerShell execution — possible post-exploitation",
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
          hash: { sha256: "a1b2c3d4e5f6789abcdef0123456789abcdef0123456789abcdef0123456789ab" }
        },
        raw: {
          "crowdstrike.AlertType": "Process",
          "crowdstrike.Severity": "High",
          "crowdstrike.Technique": "T1059.001",
          "crowdstrike.TechniqueName": "PowerShell",
          "crowdstrike.ContextProcessName": "powershell.exe",
          "crowdstrike.ContextProcessId": "4892",
          "crowdstrike.ContextProcessParentName": "cmd.exe",
          "crowdstrike.CommandLine": "powershell.exe -NoP -NonI -W Hidden -Exec Bypass -Enc JABjAGwAaQBlAG4AdAAgAD0A...",
          "crowdstrike.UserName": "CORP\\j.smith",
          "crowdstrike.HostName": "LAPTOP-JSMITH",
          "crowdstrike.LocalIP": "10.0.1.55",
          "crowdstrike.SHA256": "a1b2c3d4e5f6789abcdef0123456789abcdef0123456789abcdef0123456789ab",
          "crowdstrike.Confidence": "95"
        },
      } satisfies TelemetryEvent,
      questions: [
        {
          question: "CrowdStrike's confidence score for this alert is 95. What does this score indicate?",
          options: [
            "95 % of the malware's capabilities have been executed",
            "CrowdStrike is 95 % confident this activity is malicious, based on its machine-learning models and threat intelligence",
            "The malware has infected 95 % of files on the endpoint",
            "The alert was triggered by 95 different detection rules simultaneously"
          ],
          answer: 1,
          explanation: "In CrowdStrike, the **Confidence score (0–100)** represents how certain CrowdStrike's detection models are that the observed activity is malicious, based on machine-learning analysis, Threat Graph intelligence, and pattern matching against known attack techniques. A score of 95 is very high — this is almost certainly malicious activity and should be treated as a true positive pending analyst confirmation. Low confidence scores (below 50) warrant more careful evaluation for false positives.",
          xp: 35,
        },
        {
          question: "The command line includes `-W Hidden`. What is the purpose of this flag in the context of this attack?",
          options: [
            "It instructs PowerShell to run with higher system privileges (hidden from access controls)",
            "It hides the PowerShell console window from the logged-in user so they cannot see it running",
            "It enables hidden network mode to bypass firewall rules",
            "It tells PowerShell to write output to a hidden log file instead of the screen"
          ],
          answer: 1,
          explanation: "`-WindowStyle Hidden` (shortened to `-W Hidden`) instructs PowerShell to launch with a hidden window style — meaning no black PowerShell console window appears on screen. Legitimate PowerShell scripts sometimes use this for cleaner UX, but in the context of malware, it is used to hide the malicious activity from the victim user sitting at the keyboard. Combined with `-NoP` (no profile), `-NonI` (non-interactive), and `-Exec Bypass` (bypass execution policy), this is a textbook malicious PowerShell execution pattern.",
          xp: 35,
        },
      ],
    } satisfies LogAnalysisTask,

    // ── Flag Task ─────────────────────────────────────────────────────────────
    {
      type: "flag",
      id: "ep-sec-f1",
      prompt: "Look at the CrowdStrike alert log above. The PowerShell command uses a specific flag to hide the console window from the user. What is the **short form** of the WindowStyle flag used in the command line? (e.g. `-W Hidden` — enter just the flag name starting with `-W`)",
      answer: "-W Hidden",
      hint: "Look at the crowdstrike.CommandLine field in the raw log. Find the flag that controls the window style. It is two characters followed by a space and a word.",
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
  xp: 290,
  icon: "🛡️",
  prerequisites: ["endpoint-security-fundamentals", "microsoft-365-security"],
  tasks: [

    // ── Reading 1: MDE Overview & Onboarding ──────────────────────────────────
    {
      type: "reading",
      id: "def-xdr-r1",
      heading: "Microsoft Defender XDR — The Unified Security Platform",
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

**Microsoft Defender for Endpoint (MDE) — Deep Dive**

**MDE Onboarding** — Getting devices under MDE management:

- **GPO (Group Policy)**: Deploy the MDE onboarding package to domain-joined Windows machines via Active Directory Group Policy. Most common in enterprise environments.
- **Microsoft Intune / Endpoint Manager**: Mobile Device Management (MDM) deployment, ideal for modern cloud-managed devices (Azure AD-joined laptops, BYOD).
- **Microsoft Configuration Manager (SCCM/MECM)**: For organisations with existing SCCM infrastructure.
- **Local script**: Download and run the onboarding script manually. Used for testing or very small deployments.
- **Linux / macOS**: Manual package deployment or management tool-based deployment.

Once onboarded, each device appears in the **Device Inventory** (security.microsoft.com → Assets → Devices).

**Device Inventory — What You See**

Each device in the inventory shows:
- **Device name and OS**: LAPTOP-JSMITH, Windows 11 22H2
- **Risk Level**: Critical / High / Medium / Low — calculated from active alerts and unpatched vulnerabilities
- **Exposure Score**: How vulnerable is this device to known attack techniques? (0–100)
- **Onboarding status**: Whether the MDE agent is active and reporting
- **Last seen**: When the device last checked in
- **Installed software**: Complete software inventory for vulnerability management

**Alert Queue and Incident Page**

MDE generates alerts when it detects suspicious behaviour. Each alert shows:
- **Severity**: Critical, High, Medium, Low, Informational
- **Detection source**: EDR (behavioural detection), Antivirus, Network protection, Threat Intelligence
- **MITRE ATT&CK mapping**: The technique (e.g. T1055 — Process Injection) and tactic (e.g. Defense Evasion)
- **Affected entity**: Device name and user

Multiple related alerts are automatically grouped into **Incidents**. The incident page shows:
- **Incident graph**: A visual map of affected devices, users, email addresses, and processes, with connecting lines showing relationships
- **Evidence**: All files, IPs, domains, and users involved across all correlated alerts
- **Timeline**: Chronological sequence of events across all affected devices
- **Recommendations**: Automated response suggestions (isolate device, run antivirus scan)

**MDE Timeline — The Investigator's Best Friend**

Every onboarded device has a **Timeline** view (Device page → Timeline tab). This shows every recorded event on that device in chronological order, going back up to 180 days. SOC analysts use the timeline to:
- Find the initial access event (when did the attacker first appear on this device?)
- Trace the attack chain (what happened step by step?)
- Identify the patient-zero device (was this machine the first compromised or was the malware spread from elsewhere?)

**Live Response — Remote Forensics**

MDE Live Response provides a remote interactive shell to an isolated endpoint. From security.microsoft.com, analysts can:
- Browse the file system
- Collect specific files for analysis
- Run investigative commands (\`tasklist\`, \`netstat\`, \`dir\`)
- Upload and execute response scripts
- Collect memory dumps

This eliminates the need for physical access to investigate a compromised device.`,
    } satisfies ReadingTask,

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

From the affected device page, open the Timeline. Filter the timeline around the time of the first alert and look 30–60 minutes earlier — attackers often perform reconnaissance before their loudest action. Look for:
- Unusual process executions before the alert time
- Network connections to external IPs
- Credential access attempts

**5. Check for Lateral Movement**

In the incident graph, look for additional devices. If the attacker moved from Device A to Device B, you'll see alerts on both. Common lateral movement tools:
- **PsExec**: Sysinternals tool that allows remote command execution. Abused constantly.
- **WMI (Windows Management Instrumentation)**: Built-in Windows remote management.
- **RDP (Remote Desktop Protocol)**: If the attacker has credentials, they can RDP to other machines.
- **SMB (Server Message Block)**: File sharing protocol often used to deploy malware to network shares.

**6. Identify the Attack Timeline (Kill Chain)**

Map the events to the MITRE ATT&CK Kill Chain stages:
- **Initial Access**: How did they get in? (Phishing? VPN with stolen credentials? Exploited vulnerability?)
- **Execution**: What code did they run? (Malicious macro, PowerShell, scheduled task?)
- **Persistence**: How did they ensure they survive a reboot? (Registry run key, scheduled task, new service?)
- **Privilege Escalation**: Did they move from a normal user to admin?
- **Defense Evasion**: Did they try to avoid detection? (Disable AV, delete logs, use LOLBins — Living Off the Land Binaries?)
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
- **Revoke active sessions** for compromised accounts (Entra ID → Sign-in logs → Revoke sessions)

**Defender for Identity (MDI) Alerts**

MDI monitors your on-premises Active Directory domain controllers and Azure Entra ID for identity-based attacks. Key alerts SOC analysts see from MDI:

| MDI Alert | Attack Technique |
|---|---|
| Suspected Kerberoasting activity | T1558.003 — Kerberoasting: request TGS tickets for service accounts to crack offline |
| Suspected DCSync attack | T1003.006 — DCSync: simulate a DC to replicate all password hashes from AD |
| Lateral movement path to sensitive entity | Graph-based lateral movement risk |
| Pass-the-Hash / Pass-the-Ticket | T1550 — Credential reuse without the plaintext password |
| Reconnaissance using LDAP queries | T1087 — Account enumeration via LDAP |
| Suspicious additions to sensitive groups | T1098 — Adding a backdoor account to Domain Admins |`,
    } satisfies ReadingTask,

    // ── Reading 3: Advanced Hunting KQL ───────────────────────────────────────
    {
      type: "reading",
      id: "def-xdr-r3",
      heading: "Advanced Hunting with KQL — Proactive Threat Hunting",
      content: `**Advanced Hunting** is one of the most powerful features in Microsoft Defender XDR. It allows analysts to write queries against raw telemetry data to proactively search for threats — even before an alert fires. Advanced Hunting is accessed at: **security.microsoft.com → Hunting → Advanced Hunting**.

**KQL — Kusto Query Language**

Advanced Hunting queries are written in **KQL (Kusto Query Language)**, which is also used by Microsoft Sentinel (Microsoft's SIEM). KQL is designed to be readable, intuitive, and powerful for security analysis.

**KQL Basics**

A KQL query follows this general structure:
\`\`\`kql
TableName
| where TimeGenerated > ago(7d)           // Filter: last 7 days
| where ColumnName == "value"              // Filter by a specific column
| project ColumnA, ColumnB, ColumnC       // Select which columns to show
| summarize Count = count() by ColumnA    // Aggregate (count per group)
| order by Count desc                     // Sort results
| limit 100                               // Return top 100 results
\`\`\`

KQL uses the **pipe operator** (\`|\`) — each step transforms the result of the previous step.

**The Advanced Hunting Tables**

Defender XDR exposes raw telemetry in structured tables. Key tables:

| Table | Contains |
|---|---|
| \`DeviceProcessEvents\` | Process creation events: name, command line, parent, user, SHA256 |
| \`DeviceNetworkEvents\` | Network connections: process, remote IP, remote port, URL |
| \`DeviceFileEvents\` | File creation, modification, deletion events |
| \`DeviceRegistryEvents\` | Registry key reads and writes |
| \`DeviceEvents\` | Generic catch-all: logon events, Defender actions, script execution |
| \`DeviceAlertEvents\` | MDE alerts associated with devices |
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
| where ProcessCommandLine has "-Enc" or ProcessCommandLine has "-EncodedCommand"
| project Timestamp, DeviceName, AccountName, ProcessCommandLine, InitiatingProcessFileName
| order by Timestamp desc
\`\`\`
This is one of the most valuable hunting queries — encoded PowerShell is almost always malicious.

**Query 2: Find processes making network connections to rare external IPs**
\`\`\`kql
DeviceNetworkEvents
| where Timestamp > ago(24h)
| where RemoteIPType == "Public"
| where InitiatingProcessFileName !in~ ("chrome.exe", "msedge.exe", "firefox.exe", "outlook.exe")
| summarize ConnectionCount = count(), Devices = make_set(DeviceName) by RemoteIP, InitiatingProcessFileName
| where ConnectionCount < 3   // rare connections (less than 3 devices contacted this IP)
| order by ConnectionCount asc
\`\`\`

**Query 3: Detect PsExec lateral movement**
\`\`\`kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where FileName =~ "PSEXESVC.exe" or ProcessCommandLine has "psexec"
| project Timestamp, DeviceName, AccountName, ProcessCommandLine, InitiatingProcessFileName
| order by Timestamp desc
\`\`\`

**Query 4: Join tables — find processes that made network connections (hunting for C2)**
\`\`\`kql
DeviceProcessEvents
| where Timestamp > ago(1d)
| where FileName =~ "powershell.exe"
| join kind=inner DeviceNetworkEvents on DeviceId, $left.ProcessId == $right.InitiatingProcessId
| where RemoteIPType == "Public"
| project Timestamp, DeviceName, AccountName, ProcessCommandLine, RemoteIP, RemotePort, RemoteUrl
| order by Timestamp desc
\`\`\`
This joins process events with network events to find PowerShell processes that made outbound connections — a strong C2 indicator.

**Custom Detection Rules**

Advanced Hunting queries can be saved as **Custom Detection Rules** that run on a schedule (every hour, every day) and automatically create alerts when the query returns results. This is how threat hunters turn hunting queries into continuous monitoring. Go to: Advanced Hunting → Create detection rule.

**Microsoft Secure Score — Endpoint Contribution**

**Microsoft Secure Score** (security.microsoft.com → Secure Score) measures your organisation's security posture as a score from 0 to the maximum possible points. The endpoint section includes points for:
- Percentage of devices onboarded to MDE
- Percentage of devices with antivirus enabled
- Percentage of devices with Attack Surface Reduction rules enabled
- Percentage of devices with BitLocker encryption
- Vulnerability management: percentage of critical vulnerabilities remediated

SOC analysts often track Secure Score as a KPI for endpoint security health.`,
    } satisfies ReadingTask,

    // ── Question 1 ────────────────────────────────────────────────────────────
    {
      type: "question",
      id: "def-xdr-q1",
      question: "Which Microsoft Defender XDR component is specifically designed to detect attacks against on-premises Active Directory, such as Kerberoasting and DCSync?",
      options: [
        "Microsoft Defender for Endpoint (MDE)",
        "Microsoft Defender for Office 365 (MDO)",
        "Microsoft Defender for Identity (MDI)",
        "Microsoft Defender for Cloud Apps (MDCA)"
      ],
      answer: 2,
      explanation: "**Microsoft Defender for Identity (MDI)** is specifically designed to monitor Active Directory Domain Controllers and Azure Entra ID for identity-based attacks. It ingests AD authentication events (Kerberos TGT/TGS requests, NTLM, LDAP queries) and detects attack patterns like Kerberoasting (requesting TGS tickets for service accounts), DCSync (simulating a domain controller to replicate password hashes), Pass-the-Hash, lateral movement, and AD reconnaissance. MDI is not installed on endpoints — it has sensors deployed on your Domain Controllers.",
      xp: 35,
    } satisfies QuestionTask,

    // ── Question 2 ────────────────────────────────────────────────────────────
    {
      type: "question",
      id: "def-xdr-q2",
      question: "In a KQL Advanced Hunting query, you want to find all PowerShell processes that made outbound network connections to public IPs in the last 24 hours. Which two tables would you join to answer this question?",
      options: [
        "DeviceAlertEvents and EmailEvents",
        "DeviceProcessEvents and DeviceNetworkEvents",
        "DeviceFileEvents and DeviceRegistryEvents",
        "CloudAppEvents and IdentityLogonEvents"
      ],
      answer: 1,
      explanation: "To correlate **which process** made a **network connection**, you need:\n- **DeviceProcessEvents**: Contains process creation events including the process name (powershell.exe), command line, and ProcessId.\n- **DeviceNetworkEvents**: Contains network connection events including RemoteIP, RemotePort, and the InitiatingProcessId (the process that made the connection).\nYou join these two tables on DeviceId and the process ID (ProcessId from DeviceProcessEvents matches InitiatingProcessId in DeviceNetworkEvents) to find PowerShell processes that made outbound connections — a classic command-and-control hunting technique.",
      xp: 35,
    } satisfies QuestionTask,

    // ── Question 3 ────────────────────────────────────────────────────────────
    {
      type: "question",
      id: "def-xdr-q3",
      question: "You receive a Defender XDR incident containing 12 alerts across 4 devices and 3 user accounts. What is the main advantage of Defender XDR automatically grouping these into one incident rather than 12 separate alerts?",
      options: [
        "Grouping reduces the number of alerts the analyst must respond to, so they can close 12 issues with one click",
        "Grouping correlates related events from multiple sources into a unified attack story, allowing analysts to understand the full scope and chain of the attack rather than investigating 12 isolated signals",
        "Grouping ensures that only the most severe alert is investigated, discarding the lower-severity ones",
        "Grouping is purely cosmetic and has no analytical benefit beyond visual organisation"
      ],
      answer: 1,
      explanation: "The core value of **XDR incident correlation** is **attack story reconstruction**. A single attacker's campaign might generate a phishing alert (Defender for Office 365), a suspicious logon alert (Defender for Identity), a PowerShell execution alert (MDE on Device 1), and a PsExec alert (MDE on Device 2). In isolation, each alert looks moderate. Correlated into one incident with an incident graph, they reveal a complete picture: phishing → credential compromise → lateral movement. This dramatically improves investigation efficiency and ensures analysts see the full scope, not just isolated symptoms.",
      xp: 35,
    } satisfies QuestionTask,

    // ── Log Analysis: MDE — PsExec Lateral Movement ───────────────────────────
    {
      type: "log_analysis",
      id: "def-xdr-la1",
      heading: "MDE Alert — Lateral Movement via PsExec",
      context: "You are investigating a Defender XDR incident. One of the alerts within the incident is a process creation event on a file server (SRV-FILE01). The alert indicates lateral movement. The initiating activity came from a developer workstation (WS-DEV-09) using a service account. Analyse the alert and answer the questions.",
      event: {
        id: "def-xdr-la1-001",
        ts: "2025-11-22T03:17:44.000Z",
        source: "edr",
        vendor: "Microsoft Defender for Endpoint",
        event_type: "process_create",
        severity: "high",
        description: "MDE: Lateral movement via PsExec detected — service account used to execute commands remotely on file server at 03:17 AM",
        hostname: "SRV-FILE01",
        user_email: "svc-backup@corp.com",
        src_ip: "10.0.5.21",
        dst_ip: "10.0.10.5",
        mitre_technique: "T1021.002",
        mitre_tactic: "Lateral Movement",
        process: {
          name: "PSEXESVC.exe",
          pid: 7712,
          parent_name: "services.exe",
          cmdline: "psexec \\\\SRV-FILE01 -s cmd.exe",
          user: "CORP\\svc-backup",
        },
        raw: {
          "data.ms365.AlertTitle": "Lateral Movement via PsExec",
          "data.ms365.AlertSeverity": "High",
          "data.ms365.Category": "LateralMovement",
          "data.ms365.MitreTechnique": "T1021.002",
          "data.ms365.DeviceName": "SRV-FILE01",
          "data.ms365.ProcessName": "PSEXESVC.exe",
          "data.ms365.ProcessCommandLine": "psexec \\\\SRV-FILE01 -s cmd.exe",
          "data.ms365.AccountDomain": "CORP",
          "data.ms365.AccountName": "svc-backup",
          "data.ms365.InitiatingProcessName": "cmd.exe",
          "data.ms365.InitiatingDeviceName": "WS-DEV-09"
        },
      } satisfies TelemetryEvent,
      questions: [
        {
          question: "The command includes the `-s` flag: `psexec \\\\SRV-FILE01 -s cmd.exe`. What does the `-s` flag do in PsExec, and why is it significant from a security perspective?",
          options: [
            "The -s flag silences output so the command runs invisibly without displaying results",
            "The -s flag runs the remote process as the SYSTEM account — the highest-privilege account on a Windows system — escalating from the service account's privileges to SYSTEM on the target server",
            "The -s flag specifies the source device from which the command originates",
            "The -s flag enables secure mode, encrypting the PsExec traffic to avoid network detection"
          ],
          answer: 1,
          explanation: "The **PsExec -s flag** runs the remote process as the **NT AUTHORITY\\SYSTEM** account — the most privileged account on a Windows machine, with complete control over the OS. By running `psexec \\\\SRV-FILE01 -s cmd.exe`, the attacker launches a command prompt on SRV-FILE01 that runs as SYSTEM, regardless of what privileges the `svc-backup` account had. This is a privilege escalation + lateral movement combination: compromise a service account → use PsExec -s to get SYSTEM on the target. This technique is heavily used by ransomware operators and APT groups.",
          xp: 45,
        },
        {
          question: "This activity occurred at 03:17 AM. The `svc-backup` account is a legitimate service account normally used only by the overnight backup job. What does this timing and account combination most likely indicate?",
          options: [
            "The backup job is running overtime and using PsExec to access the file server — this is expected and should be closed as a false positive",
            "A scheduled task was accidentally configured with the wrong account, causing the backup to run PsExec",
            "The svc-backup account credentials have likely been compromised; an attacker is using them at 3 AM to perform lateral movement under the cover of expected backup activity",
            "MDE alerts at off-hours are always false positives because legitimate security tools run during maintenance windows"
          ],
          answer: 2,
          explanation: "Service accounts are attractive targets for attackers precisely because their normal activity provides cover. The `svc-backup` account is expected to be active at 3 AM — but legitimate backup jobs do not use **PsExec to launch interactive command prompts**. Backup software uses specific APIs and protocols, not `cmd.exe` via PsExec. This is a classic attacker technique: steal a service account's credentials (via Kerberoasting, password spray, or credential dumping) and use it during its expected activity window. The account activity looks plausible at 3 AM, but the specific action (interactive cmd.exe via PsExec) is not consistent with legitimate backup behaviour.",
          xp: 45,
        },
      ],
    } satisfies LogAnalysisTask,

    // ── Flag Task ─────────────────────────────────────────────────────────────
    {
      type: "flag",
      id: "def-xdr-f1",
      prompt: "Look at the PsExec lateral movement log analysis above. The MITRE ATT&CK technique for this attack is listed in the raw log. What is the exact MITRE technique ID for this lateral movement method? (Format: T followed by numbers and a dot, e.g. T1234.001)",
      answer: "T1021.002",
      hint: "Look at the raw log field called data.ms365.MitreTechnique. It starts with T and has a dot separating two number groups.",
      xp: 60,
    } satisfies FlagTask,

    // ── Question 4 (bonus) ────────────────────────────────────────────────────
    {
      type: "question",
      id: "def-xdr-q4",
      question: "A threat hunter writes the following KQL query in Advanced Hunting:\n\n```kql\nDeviceProcessEvents\n| where Timestamp > ago(7d)\n| where FileName =~ \"powershell.exe\"\n| where ProcessCommandLine has \"-Enc\"\n| project Timestamp, DeviceName, AccountName, ProcessCommandLine\n```\n\nWhat specific threat does this query hunt for?",
      options: [
        "PowerShell processes that download files from the internet using WebClient or Invoke-WebRequest",
        "PowerShell processes launched with Base64-encoded commands, which attackers use to obfuscate malicious scripts from simple text inspection",
        "PowerShell processes running as the SYSTEM account on domain controllers",
        "PowerShell processes that were blocked by Defender's script block logging"
      ],
      answer: 1,
      explanation: "The query filters for `powershell.exe` processes where the command line **contains `-Enc`** (short for `-EncodedCommand`). The `-EncodedCommand` flag accepts a Base64-encoded string as the command to execute. Attackers use this to **obfuscate their malicious PowerShell** — the raw command line shows only `powershell.exe -Enc JABjAG...` rather than the actual code. Security tools that only look for obvious strings like `Invoke-Mimikatz` or `DownloadString` are bypassed. This is one of the most valuable and productive hunting queries for detecting post-exploitation PowerShell activity.",
      xp: 35,
    } satisfies QuestionTask,

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
