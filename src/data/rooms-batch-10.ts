import type { TelemetryEvent } from "@/lib/sim/types";

const rooms = [
  // ─────────────────────────────────────────────
  // ROOM 1 — Phishing Analysis
  // ─────────────────────────────────────────────
  {
    id: "phishing-analysis",
    title: "Phishing Analysis",
    description:
      "Learn to dissect malicious emails like a forensics expert — decode spoofed headers, failed authentication records, weaponised attachments, and Business Email Compromise patterns.",
    difficulty: "intermediate",
    category: "Threat Detection",
    estimatedMinutes: 45,
    xp: 180,
    icon: "🎣",
    prerequisites: ["email-security"],
    tasks: [
      // ── Reading 1 ──
      {
        type: "reading",
        id: "phishing-r1",
        heading: "Email Headers: The Return Address on a Letter You Should Never Trust",
        content:
          "Imagine receiving a letter in your mailbox. The envelope has a return address that says \"Internal Revenue Service, Washington DC\". But if you look at the postmark stamp on the envelope, you can see the letter was actually mailed from a post office in Romania. The text printed on the envelope (the \"From\" field) is just ink — anyone can write anything there. The postmark stamp, however, is added by the postal system itself and is much harder to fake.\n\nEmail works exactly the same way. The **From:** field you see in your inbox is just text that the sender typed. It can say anything — absolutely anything. A criminal can make it say ceo@yourcompany.com with zero technical effort. What you need to examine are the **email headers** — the equivalent of postmarks and handling stamps added by every mail server that touched the message on its journey to you.\n\n**What headers reveal**\n\nEvery email carries a block of metadata called headers, hidden by default in most email clients. When you open headers (\"View Source\" or \"Show Original\" in Gmail), you see a log of every server the email passed through, timestamps, and authentication results.\n\n- **Return-Path:** — This is the real address where bounce messages go. If someone spoofs ceo@bigbank.com but the Return-Path says attacker@gmail-helpdesk.ru, you have your first major red flag. The sender wants replies to go somewhere else.\n\n- **Received:** headers — These are added by each mail server in **reverse order** (the bottom Received header was added first, the top one last). Each line shows: the sending server IP, the receiving server, and a timestamp. By reading the bottom Received header, you find where the email actually originated.\n\n- **X-Originating-IP:** — Some webmail systems (Yahoo, older Hotmail) stamp the sender's actual IP address here. This is investigative gold — you can look it up in threat intelligence to see if it belongs to a known spam infrastructure or compromised host.\n\n- **Message-ID:** — A unique identifier assigned by the originating mail server. A message claiming to come from google.com but with a Message-ID like <random@sendinblue.fr> tells you the true sending platform.\n\n**SPF, DKIM, and DMARC — the three authentication shields**\n\nThink of these as three different security guards checking the letter before it gets to you.\n\n**SPF (Sender Policy Framework)** — The domain owner publishes a list in DNS saying \"only these IP addresses are allowed to send email for us\". When a receiving server gets a message claiming to be from bigbank.com, it looks up bigbank.com's SPF record and checks whether the sending IP is on the approved list. If not: **SPF FAIL**.\n\n**DKIM (DomainKeys Identified Mail)** — The sending server cryptographically signs the email with a private key. The receiving server looks up the public key in DNS and verifies the signature. If the email was altered in transit (or if a criminal is forging the domain), the DKIM signature will not match: **DKIM FAIL**. A valid DKIM signature is very hard to fake.\n\n**DMARC (Domain-based Message Authentication, Reporting & Conformance)** — DMARC ties the other two together. It tells receiving servers what to do when SPF or DKIM fails (quarantine, reject, or do nothing) and requires that the domain in the From: header aligns with the SPF/DKIM domains. When you see **DMARC FAIL**, it means the email claimed to be from a domain it had no right to send on behalf of.\n\nIn a phishing email, you will very commonly see all three failing, or you will see SPF passing (because the attacker registered a look-alike domain like bigbank-support.com and set up valid SPF for it) while the DMARC check flags the mismatch between that domain and the real company name.\n\n**Practical workflow for header analysis**\n\nStep 1: Find the bottom-most **Received:** header — that is the origin.\nStep 2: Extract the IP address from that header and look it up on VirusTotal, AbuseIPDB, or Shodan.\nStep 3: Check **Return-Path** — does it match the claimed From domain?\nStep 4: Read the **Authentication-Results** header — look for spf=fail, dkim=fail, dmarc=fail.\nStep 5: Check the **Message-ID** domain — does it match the From domain?\n\nA legitimate email from your bank will pass all three authentication checks, have a Return-Path matching the bank's domain, and originate from an IP address owned by the bank or its email provider. A phishing email will almost always fail at least one of these tests.",
      },

      // ── Reading 2 ──
      {
        type: "reading",
        id: "phishing-r2",
        heading: "URLs, Attachments, and the Anatomy of a Phishing Kit",
        content:
          "Imagine a fake storefront that looks exactly like your favourite pharmacy — same logo, same colour scheme, same product photos. But the address above the door is slightly wrong: \"CVS-Pharmacy-Support.net\" instead of cvs.com. And the door leads to a back room where someone collects your credit card details. That is a phishing kit.\n\n**URL analysis: what to look for before you click**\n\nThe single most important rule in phishing analysis is: **never click a suspicious link from your normal workstation**. Instead, analysts examine URLs without visiting them.\n\n- **Hover, don't click** — In most email clients, hovering over a hyperlink reveals the actual destination URL in the status bar. The text shown (\"Click here to verify your account\") can say anything; the underlying href tells the truth.\n\n- **URL shorteners** — Links like bit.ly/xk3p9q hide the real destination. Analysts use services like CheckShortURL or URLScan.io to expand shortened URLs without visiting them. Attackers use shorteners specifically to hide malicious destinations.\n\n- **Homograph attacks** — Unicode allows characters that look identical to Latin letters. The Cyrillic letter \"а\" (U+0430) looks exactly like Latin \"a\" (U+0061). A URL like pаypal.com (with a Cyrillic а) looks perfect in an email but resolves to a completely different domain. Always check the raw ASCII or Punycode representation (pаypal.com becomes xn--pypal-4ve.com in Punycode).\n\n- **Subdomain tricks** — paypal.com.attacker.net is NOT paypal.com. The actual domain (the part before the last dot before the TLD) is attacker.net. Victims read from left to right and see \"paypal.com\" and stop.\n\n- **HTTPS does NOT mean safe** — Many people believe the padlock icon means a website is trustworthy. It only means the connection is encrypted. Criminals routinely obtain free TLS certificates (Let's Encrypt) for their phishing domains.\n\n**Analysing attachments without triggering them**\n\nAttachments are another major phishing delivery vector. Common weaponised attachment types:\n\n- **Macro-enabled Office documents (.docm, .xlsm)** — These contain embedded VBA macros that execute when the user clicks \"Enable Content\". Macros can download malware, execute PowerShell commands, and establish persistence. **Red flags:** document asks you to enable macros, document content is blurred or says \"enable editing to view\", document was received from an unexpected sender.\n\n- **Password-protected ZIPs** — Attackers package malware in a ZIP and provide the password in the email body. This bypasses automated email scanning because the scanner cannot open the ZIP without the password. The password is always in the email — \"please use password: Invoice2024 to open the attached file\".\n\n- **ISO and IMG files** — Disk image files can contain executables and, on Windows 10 before a recent patch, could bypass the Mark-of-the-Web (MOTW) security flag that warns users about downloaded files.\n\n- **PDF with embedded links** — PDFs containing links to credential harvesting pages. The PDF itself is clean but acts as a vehicle to get victims to click.\n\n**Business Email Compromise (BEC) — the most expensive phishing variant**\n\nBEC does not always involve malware or malicious URLs. Instead, an attacker who has compromised or spoofed an executive's email account sends a convincing email to someone in finance: \"I need you to urgently wire $85,000 to our new vendor account. This is confidential — please process today.\"\n\nBEC characteristics to look for:\n- **Urgency and secrecy** — real executives rarely demand secret urgent wire transfers\n- **Reply-to mismatch** — the From field shows the CEO but Reply-To redirects to attacker@gmail.com\n- **Timing** — BEC attacks often happen on Fridays before holidays when the target executive is harder to reach for verbal confirmation\n- **Slightly wrong domain** — ceo@company-corp.com vs ceo@company.com\n\n**Analysing the phishing kit itself**\n\nSometimes analysts obtain the actual phishing kit — the ZIP archive the attacker uploaded to a compromised server. These kits reveal: which legitimate site they are impersonating, how stolen credentials are exfiltrated (usually emailed to the attacker or posted to a Telegram bot), which IP addresses are whitelisted (attackers block known security company IPs from seeing the phishing page), and reused code that links kits to known threat actors.",
      },

      // ── Reading 3 ──
      {
        type: "reading",
        id: "phishing-r3",
        heading: "Phishing Investigation Workflow: From Alert to Verdict",
        content:
          "Think of a bomb disposal technician. They do not grab a suspicious package and shake it. They follow a strict, safe procedure: assess from a distance, gather information, use tools remotely, then make a decision. Phishing analysis works the same way — a disciplined process keeps you from accidentally detonating the payload.\n\n**Step 1: Triage — is this actually a phishing attempt?**\n\nWhen a user reports a suspicious email, or your email gateway flags one, start by asking:\n- Did the user click anything or open any attachment? (If yes, this is now potentially an incident — escalate)\n- Does the sender domain match the claimed organisation?\n- Is there urgency, threat, or unusual request language?\n- Does the email address a real need the user has, or is it unsolicited?\n\nNot every flagged email is malicious. Bulk marketing email, misconfigured legitimate systems, and aggressive spam filters all produce false positives.\n\n**Step 2: Safe header extraction**\n\nUse your email security gateway console (Proofpoint, Mimecast, Microsoft Defender for Office 365) to export the raw email headers **without delivering or opening the email yourself**. Copy the headers to a plain text editor.\n\nKey fields to extract and document:\n- Full Received chain (all hops)\n- Return-Path\n- Authentication-Results (SPF, DKIM, DMARC verdicts)\n- X-Originating-IP (if present)\n- Message-ID\n- Date and timezone\n\n**Step 3: Sender IP investigation**\n\nTake the originating IP (from the bottom Received header or X-Originating-IP) and check:\n- **VirusTotal** — has this IP been flagged by security vendors?\n- **AbuseIPDB** — has this IP been reported for abuse?\n- **Shodan** — what services is this IP running? Is it a mail server or a VPS that should not be sending email?\n- **Whois / ARIN/RIPE lookup** — who owns this IP? Is it registered to a known spam hosting provider?\n\n**Step 4: URL detonation (sandboxed)**\n\nIf the email contains URLs, submit them to:\n- **URLScan.io** — takes a screenshot and analysis of the page without you visiting it\n- **VirusTotal** — checks the URL against dozens of security vendors\n- **ANY.RUN or Hybrid Analysis** — full dynamic sandbox if you need to see what the page does\n\nNever visit suspicious URLs in your corporate browser. Even visiting a page can sometimes trigger drive-by download exploits.\n\n**Step 5: Attachment analysis**\n\nIf there is an attachment:\n- Calculate the **SHA256 hash** of the file and check it on VirusTotal\n- Submit to a sandbox (ANY.RUN, Cuckoo, Joe Sandbox) for dynamic analysis\n- For Office documents: tools like **olevba** (part of oletools) extract and display VBA macro code without executing it\n- For PDFs: **pdfid** and **pdf-parser** extract embedded JavaScript and URLs\n\n**Step 6: Document and decide**\n\nAfter gathering evidence, make a verdict:\n- **Benign** — legitimate email, no action needed\n- **Spam** — bulk marketing, not targeted, report to gateway\n- **Phishing** — credential harvesting attempt, block sender, block URLs, notify users, check if anyone clicked\n- **Spear phishing / BEC** — targeted attack, escalate to incident response, notify management\n\n**Step 7: Containment actions**\n\nFor confirmed phishing:\n- Block the sender domain and IP in your email gateway\n- Block the malicious URLs in your web proxy\n- Search your email logs for other recipients of the same campaign (same Message-ID, same sender IP, same attachment hash)\n- If any user clicked: isolate their workstation, check EDR telemetry for signs of execution\n- Notify affected users and provide security awareness guidance\n\n**Key metrics to track**\n\nA mature SOC tracks: phishing volume by day/week, click-through rate (what percentage of users who received a phishing email actually clicked), time-to-detection, time-to-containment, and repeat reporter names (users who proactively report phishing deserve recognition).",
      },

      // ── Question 1 ──
      {
        type: "question",
        id: "phishing-q1",
        question:
          "An email arrives claiming to be from support@paypal.com. The Authentication-Results header shows: spf=fail, dkim=fail, dmarc=fail. What does this most likely indicate?",
        options: [
          "PayPal's mail servers are temporarily offline",
          "The email is spoofing the PayPal domain and was not sent by PayPal's authorised infrastructure",
          "The receiving mail server has a misconfigured DNS resolver",
          "DMARC failures are normal and can be safely ignored",
        ],
        answer: 1,
        explanation:
          "SPF fail means the sending IP is not listed in PayPal's SPF record. DKIM fail means the email's cryptographic signature is invalid or absent. DMARC fail means the From domain does not align with any passing authentication. All three failing together is a strong indicator of domain spoofing — the email was not sent by PayPal's legitimate infrastructure. This is the classic signature of a phishing attempt impersonating a trusted brand.",
        xp: 20,
      },

      // ── Question 2 ──
      {
        type: "question",
        id: "phishing-q2",
        question:
          "A user reports a suspicious email with an attachment named 'Invoice_Q4_2024.xlsm'. When they opened it, a yellow bar appeared asking them to 'Enable Content'. What happened and what should the SOC analyst do first?",
        options: [
          "The file is a standard Excel spreadsheet — enable content and proceed",
          "The .xlsm extension indicates a macro-enabled workbook; the analyst should check if the user clicked Enable Content and if so, check EDR telemetry for malicious process spawns",
          "XLSM files cannot contain malware — only executable files are dangerous",
          "Immediately wipe the user's machine without investigation",
        ],
        answer: 1,
        explanation:
          ".xlsm files are macro-enabled Excel workbooks. The 'Enable Content' prompt is exactly how macro-based malware operates — it asks the user to disable the security control that blocks macro execution. The first priority is determining whether the user clicked Enable Content. If they did, VBA macros may have executed and could have downloaded malware or established persistence. The analyst must check EDR telemetry for child processes spawned by EXCEL.EXE, especially powershell.exe, cmd.exe, or wscript.exe.",
        xp: 20,
      },

      // ── Question 3 ──
      {
        type: "question",
        id: "phishing-q3",
        question:
          "In a Business Email Compromise (BEC) attack, an email appears to come from the CEO requesting an urgent wire transfer. Which single technical indicator is most useful for detecting this attack?",
        options: [
          "The email has a large attachment",
          "The email was sent on a Friday afternoon",
          "The Reply-To header points to a different domain than the From header",
          "The email body contains the word 'urgent'",
        ],
        answer: 2,
        explanation:
          "The Reply-To header mismatch is a key technical indicator of BEC. Attackers set From: to appear as the CEO's legitimate address (to pass visual inspection) but set Reply-To: to an attacker-controlled address so that when finance replies, the response goes to the attacker. While Friday timing and urgency language are behavioural indicators worth noting, the Reply-To mismatch is a technical, measurable, low-false-positive signal that email security tools can automatically detect and alert on.",
        xp: 20,
      },

      // ── Log Analysis ──
      {
        type: "log_analysis",
        id: "phishing-la1",
        heading: "Analysing a Suspicious Email Gateway Alert",
        context:
          "Your organisation's email security gateway has flagged an inbound email and generated the following telemetry. The email claims to be from the CFO of a partner company. A junior analyst has escalated it to you for review. Examine the log carefully — pay close attention to the Received headers, authentication results, and attachment details.",
        event: {
          id: "evt-phish-001",
          ts: "2026-06-24T08:47:32.000Z",
          source: "email_gateway",
          event_type: "email_received",
          hostname: "mailgw-01.contoso.com",
          severity: "high",
          vendor: "Microsoft 365 Unified Audit Log",
          raw: {
            "data.office365.Operation": "MessageReceived",
            "data.office365.UserId": "alice.chen@contoso.com",
            "data.office365.ClientIP": "185.220.101.47",
            "data.office365.SourceFileName": "Urgent_Wire_Request_Q2.xlsm",
            "email.from.address": "cfo@globalpartners.com",
            "email.from.name": "Robert Harrington CFO",
            "email.reply_to": "robert.harrington.cfo@gmail-secure-mail.com",
            "email.subject": "URGENT: Wire Transfer Required Before EOD",
            "email.return_path": "bounce@sendinblue-relay247.net",
            "email.message_id": "<20260624.84729@sendinblue-relay247.net>",
            "email.headers.received": [
              "from mail.contoso.com (mail.contoso.com [52.96.112.17]) by mailgw-01.contoso.com with ESMTPS; 24 Jun 2026 08:47:30 +0000",
              "from smtp.sendinblue-relay247.net (smtp.sendinblue-relay247.net [185.220.101.47]) by mail.contoso.com with ESMTP; 24 Jun 2026 08:47:28 +0000",
              "from [10.44.22.8] by smtp.sendinblue-relay247.net; 24 Jun 2026 08:47:21 +0000",
            ],
            "email.authentication_results": {
              spf: "fail",
              spf_detail: "185.220.101.47 is not permitted to send for globalpartners.com",
              dkim: "fail",
              dkim_detail: "signature verification failed",
              dmarc: "fail",
              dmarc_policy: "reject",
            },
            "email.attachment.name": "Urgent_Wire_Request_Q2.xlsm",
            "email.attachment.size_bytes": 487291,
            "email.attachment.sha256":
              "a3f8c2e1d4b9a7f6e5c3d2b1a0f9e8d7c6b5a4f3e2d1c0b9a8f7e6d5c4b3a2f1e0",
            "email.attachment.type": "application/vnd.ms-excel.sheet.macroEnabled.12",
            "email.attachment.vt_detections": "38/72",
            "email.x_originating_ip": "185.220.101.47",
            "rule.name": "BEC_Attachment_Phishing_High_Confidence",
            "rule.level": 12,
            "rule.description": "Email with macro-enabled attachment failed all authentication checks and has Reply-To mismatch",
          },
        },
        questions: [
          {
            question:
              "Looking at the Received headers in the log, what is the IP address where this email actually originated (the true sending server)?",
            options: [
              "52.96.112.17 (mail.contoso.com — the internal mail relay)",
              "185.220.101.47 (smtp.sendinblue-relay247.net — the external origin server)",
              "10.44.22.8 (the private IP in the last hop)",
              "The originating IP cannot be determined from Received headers",
            ],
            answer: 1,
            explanation:
              "Received headers are added in reverse order — the bottom-most Received header represents the first hop (origin). Reading the Received chain: the email went from 185.220.101.47 (sendinblue-relay247.net) → mail.contoso.com → mailgw-01.contoso.com. Therefore 185.220.101.47 is the originating IP. This matches the X-Originating-IP field and the SPF failure detail, which specifically calls out 185.220.101.47 as not being permitted to send for globalpartners.com.",
            xp: 25,
          },
          {
            question:
              "What combination of indicators makes this email most suspicious from a Business Email Compromise perspective?",
            options: [
              "Large attachment size and Friday timing",
              "Reply-To pointing to a Gmail-lookalike domain, SPF/DKIM/DMARC all failing, macro-enabled attachment with 38/72 VirusTotal detections, and Return-Path from a relay service unrelated to globalpartners.com",
              "The email subject contains the word URGENT",
              "The email was delivered to alice.chen who is likely in the finance department",
            ],
            answer: 1,
            explanation:
              "The combination of technical red flags here is damning: (1) Reply-To is gmail-secure-mail.com — a fake Gmail lookalike — not the actual globalpartners.com domain. (2) All three email authentication checks (SPF, DKIM, DMARC) failed, meaning the email is not from globalpartners.com's authorised infrastructure. (3) The attachment is a macro-enabled Excel file (.xlsm) detected as malicious by 38 of 72 antivirus engines on VirusTotal. (4) The Return-Path points to sendinblue-relay247.net, not globalpartners.com. Each of these alone warrants investigation; all four together is a confirmed BEC phishing attempt.",
            xp: 25,
          },
        ],
      },

      // ── Analyst Choice ──
      {
        type: "analyst_choice" as const,
        id: "phishing-ac1",
        heading: "Verdict: Real Phishing or Legitimate Alert?",
        scenario: "At 10:23 AM your SIEM generated a medium-severity alert on an email delivered to r.thomas@contoso.com. The email claims to be a Microsoft account security alert. The email passed SPF, DKIM, and DMARC. The PDF attachment had 0 detections on VirusTotal. No URL was blocked by the email gateway. What is your verdict?",
        event: {
          id: "evt-phish-ac-001",
          ts: "2026-06-24T10:23:15.000Z",
          source: "email_gateway" as const,
          vendor: "Microsoft Defender for Office 365",
          event_type: "email_received" as const,
          severity: "medium" as const,
          hostname: "mail-gw-01.contoso.com",
          user_email: "r.thomas@contoso.com",
          description: "Email from lookalike Microsoft domain — all auth checks passed, clean attachment",
          mitre_technique: "T1566.001",
          mitre_tactic: "Initial Access",
          raw: {
            "data.office365.Operation": "EmailReceived",
            "data.office365.UserId": "r.thomas@contoso.com",
            "email.from.address": "noreply@microsoft-account-security.org",
            "email.from.display": "Microsoft Account Security",
            "email.subject": "Your Microsoft account was accessed from a new device",
            "email.reply_to": "noreply@microsoft-account-security.org",
            "email.return_path": "bounce@microsoft-account-security.org",
            "AuthenticationResults.spf": "pass",
            "AuthenticationResults.spf_detail": "microsoft-account-security.org SPF record authorized this sender",
            "AuthenticationResults.dkim": "pass",
            "AuthenticationResults.dmarc": "pass",
            "email.x_originating_ip": "185.220.101.47",
            "domain.registered_date": "2026-06-21",
            "domain.registrar": "Namecheap",
            "email.attachment.name": "DeviceAccessAlert.pdf",
            "email.attachment.sha256": "b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3",
            "email.attachment.vt_detections": "0/72",
            "email.embedded_url": "https://microsoft-account-security.org/verify?token=xK9pQ3mR7nT2",
            "email.url_category": "Uncategorized",
            "rule.name": "Email_Lookalike_Domain_All_Auth_Pass",
            "rule.level": 7,
          },
        },
        correct_verdict: "true_positive",
        explanation: "This is a true positive phishing attempt. The key evidence: (1) The sending domain is 'microsoft-account-security.org' — not microsoft.com. The SPF/DKIM/DMARC checks passing only verify the attacker's domain is correctly configured — not that it belongs to Microsoft. (2) The domain was registered just 3 days ago (June 21) — brand-new domains are a strong phishing indicator. (3) The originating IP 185.220.101.47 is a known Tor-adjacent VPS used in previous attacks. (4) The embedded URL points to the same attacker-controlled domain. The 0/72 VirusTotal result is expected — the PDF is just a delivery vehicle for the link, not malware itself.",
        fp_trap: "All three authentication checks (SPF, DKIM, DMARC) passed — which looks reassuring. But these checks only validate that the sender legitimately controls the domain microsoft-account-security.org. They say nothing about whether that domain belongs to Microsoft. The PDF attachment being clean on VirusTotal is also misleading — it is a clean PDF that redirects to a phishing page, not a malicious file.",
        xp: 30,
      },

      // ── Flag ──
      {
        type: "flag",
        id: "phishing-flag1",
        prompt:
          "Examine the Received headers in the email gateway log above. What is the IP address of the server that first injected this email into the mail delivery chain (the true origin IP)? Enter the IP address exactly as it appears in the log.",
        answer: "185.220.101.47",
        hint: "Read the Received headers from bottom to top. The last one (bottom of the list) represents the first hop — where the email entered the internet mail system. Look for the IP address in square brackets on that line.",
        xp: 40,
      },
    ],
  },

  // ─────────────────────────────────────────────
  // ROOM 2 — VPN Monitoring
  // ─────────────────────────────────────────────
  {
    id: "vpn-monitoring",
    title: "VPN Monitoring",
    description:
      "Understand what VPN logs reveal about user behaviour, detect impossible travel scenarios, identify brute-force authentication patterns, and analyse Cisco AnyConnect and Palo Alto GlobalProtect telemetry.",
    difficulty: "intermediate",
    category: "Log Analysis",
    estimatedMinutes: 35,
    xp: 175,
    icon: "🔒",
    prerequisites: ["networking-protocols", "siem-fundamentals"],
    tasks: [
      // ── Reading 1 ──
      {
        type: "reading",
        id: "vpn-r1",
        heading: "What VPN Logs Actually Tell You",
        content:
          "Think of a VPN (Virtual Private Network) like the secure entrance tunnel to a high-security office building. Employees park their cars in the public car park (the internet), walk through the secure tunnel, and emerge inside the building where all the company resources are. A guard station at the tunnel entrance logs every single person who enters: their name, what badge they used, what time they arrived, how long they stayed, and how many boxes they carried in and out.\n\nVPN logs are that guard station logbook. Every time an employee connects through your corporate VPN, a record is created. For SOC analysts, this data is invaluable because VPN is often the front door that attackers target — and the last layer of perimeter control standing between an attacker and your internal network.\n\n**What fields appear in VPN logs?**\n\n- **Username** — who authenticated (or who's credentials were used)\n- **Source IP / Client IP** — the public internet IP address the connection came from. This reveals the geographic location of the connecting device\n- **VPN Gateway** — which VPN concentrator was used (useful in large organisations with regional gateways)\n- **Authentication Method** — password only, MFA, certificate, SAML/SSO\n- **Connection Start Time / End Time / Duration** — when did the session begin and end, how long did it last\n- **Bytes In / Bytes Out** — how much data flowed in each direction. Large bytes_out (from the user's perspective, meaning data leaving your network) can indicate data exfiltration\n- **Tunnel Type** — full tunnel (all traffic goes through VPN) vs split tunnel (only corporate traffic goes through VPN, personal browsing bypasses it)\n- **Assigned Internal IP** — the IP address the VPN server assigned to the session inside the corporate network\n- **Authentication result** — success, failure, MFA denied, certificate invalid\n- **Disconnect Reason** — idle timeout, user disconnected, connection lost, admin terminated\n\n**Split tunnelling: the SOC analyst's blind spot**\n\nWhen split tunnelling is enabled, traffic to your corporate systems goes through the encrypted VPN tunnel — but everything else (Netflix, personal email, general web browsing) goes directly to the internet, bypassing all corporate security controls: the web proxy, the IDS/IPS, URL filtering, DLP. A user could be connected to VPN and simultaneously downloading malware via their split-tunnel personal traffic, and your security stack would have zero visibility.\n\nThis matters especially for endpoint security: if a remote worker's home machine gets infected, and they connect to VPN, that infected machine is now inside your network perimeter — regardless of whether split tunnelling is enabled.\n\n**What normal VPN behaviour looks like**\n\nBaseline behaviour varies by organisation, but healthy patterns typically include:\n- Users connecting from consistent geographic locations (their home country)\n- Connection times matching working hours in the user's time zone\n- Reasonable session durations (hours, not weeks)\n- Bytes out consistent with normal work activity (documents, emails) not massive bulk data transfers\n- Consistent authentication methods (if Alice always uses MFA, a session where only password was used is anomalous)\n- Consistent device (certificate-based VPN can tie sessions to specific enrolled devices)",
      },

      // ── Reading 2 ──
      {
        type: "reading",
        id: "vpn-r2",
        heading: "Impossible Travel, Brute Force, and Other VPN Attack Patterns",
        content:
          "Imagine you stamp your passport at customs in New York at 9:00 AM. Then at 9:45 AM the same morning, your passport is stamped in London. That is impossible — you cannot cross the Atlantic Ocean in 45 minutes. If someone is presenting your passport in London while you're still in New York, either your passport has been cloned, or someone stole it.\n\nThis exact logic is the foundation of one of the most powerful security detections in modern SOC work: **impossible travel**.\n\n**Impossible travel detection**\n\nImpossible travel occurs when the same user account authenticates from two locations that are geographically too far apart to be physically possible given the time between logins.\n\nThe calculation: distance between Location A and Location B ÷ time between logins = required travel speed. If required speed > maximum possible travel speed (approximately 1,000 km/h for commercial aviation), then it is impossible travel.\n\nFor example:\n- 09:12 — user@company.com logs into VPN from Tel Aviv, Israel (IP: 212.143.x.x)\n- 09:41 — user@company.com logs into VPN from Moscow, Russia (IP: 95.173.x.x)\n- Distance Tel Aviv → Moscow: approximately 2,760 km\n- Time elapsed: 29 minutes\n- Required speed: 2,760 km ÷ 0.48 hours = 5,750 km/h\n\nThis is physically impossible. The conclusion is one of: the account credentials were stolen and an attacker is using them from a different location; a shared account is being used by two different people simultaneously; or the user is using a VPN/proxy (the apparent location is not their real location).\n\n**VPN authentication brute force**\n\nBrute force against VPN endpoints is extremely common. Attackers use stolen username lists and either known passwords from data breaches (credential stuffing) or systematically try common passwords (password spraying).\n\nSigns of VPN brute force in logs:\n- Many **auth_failure** events for the same username from the same IP in a short window — this is classic brute force (targeting one account)\n- Many auth_failures for **different usernames** from the same IP — this is credential stuffing (trying a breach list)\n- Many auth_failures for different usernames each trying a **common password** (e.g., Summer2024!) from distributed IPs — this is password spraying (slow and distributed to evade lockout policies)\n- A burst of failures followed immediately by a success — compromise confirmed\n\n**Anomalous session behaviour post-authentication**\n\nOnce connected, what does the attacker do? Look for:\n- **Abnormally large bytes_out** — exfiltrating data through the VPN tunnel\n- **Connection at unusual hours** — 3:00 AM local time for a finance employee\n- **Connecting from a new country never seen before** for that user\n- **Persistent long-duration sessions** — an attacker might keep a VPN session alive for days\n- **Many rapid successive logins and logouts** — automated probing\n\n**GlobalProtect and AnyConnect specifics**\n\nPalo Alto GlobalProtect logs appear in PAN-OS system logs and include: gateway, machine, user, public-ip, private-ip, protocol, auth-method, bytes-sent, bytes-received, duration, reason (for disconnect).\n\nCisco AnyConnect logs appear in ASA or FTD syslogs (event IDs: 113039 for auth failure, 113004 for auth success) and include: username, group, IP address, protocol, bytes_in, bytes_out, duration, reason.\n\nBoth vendors export to SIEM via syslog, and modern SIEM platforms correlate VPN authentication events with other log sources (Office 365 sign-ins, EDR, badge access) to detect impossible travel even when an attacker uses a different authentication method on each platform.",
      },

      // ── Reading 3 ──
      {
        type: "reading",
        id: "vpn-r3",
        heading: "Building a VPN Monitoring Detection Strategy",
        content:
          "A good security operations centre does not just wait for VPN alerts to arrive — it builds a systematic monitoring strategy that defines what 'normal' looks like for each user and then automatically flags deviations. This approach is sometimes called **User and Entity Behaviour Analytics (UEBA)**.\n\nThink of it like a bank's fraud detection system for your debit card. The bank knows that you typically spend money in your home city, in amounts under a certain threshold, at certain types of merchants. When a transaction comes in from a foreign country at 3 AM for an unusual amount, the fraud system flags it — not because it has a specific rule that says 'this is fraud', but because it knows your baseline and this deviates significantly.\n\n**Building a VPN baseline per user**\n\nFor each VPN user, you want to establish:\n- **Typical source countries** — Alice always connects from Israel or occasionally from the US when travelling\n- **Typical connection hours** — Bob always connects between 07:00-19:00 UTC+2\n- **Typical session duration** — average 4-6 hours for knowledge workers\n- **Typical bytes transferred** — normal range for their role (developers transfer more than HR staff)\n- **Device fingerprint** — specific certificate or device ID used\n\n**Key VPN detection rules to implement in your SIEM**\n\n1. **Impossible travel** — flag when the same account authenticates from two locations where the implied travel speed exceeds 800 km/h (allowing for some tolerance below speed of sound)\n\n2. **New country first seen** — alert when a user connects from a country they have never connected from before\n\n3. **VPN brute force** — alert on more than 5 authentication failures from the same IP targeting the same account within 10 minutes\n\n4. **Credential stuffing** — alert on more than 20 authentication failures across different accounts from the same IP within 5 minutes\n\n5. **Large data transfer post-VPN** — correlate VPN session data with file server and DLP logs; alert if a user downloads unusually large volumes after establishing a VPN connection\n\n6. **VPN success after multiple failures** — alert when an authentication failure burst is followed by a success (probable compromise)\n\n7. **Non-working-hours connection from foreign country** — alert when a user connects at 2 AM local time from a country other than their home country\n\n**Responding to a VPN compromise alert**\n\nWhen you suspect an account's VPN credentials have been compromised:\n\nStep 1: Immediately disable the account or terminate the suspicious VPN session\nStep 2: Force a password reset\nStep 3: Review what the attacker accessed during the session — what internal systems, files, and services were reached from the VPN-assigned internal IP\nStep 4: Check other authentication systems (Office 365, cloud console) for signs of the same stolen credentials being used\nStep 5: Check if the legitimate user's device shows any signs of info-stealing malware that may have exfiltrated the VPN credentials\nStep 6: Review the VPN gateway logs for other sessions from the same source IP — the attacker may have targeted other accounts from the same infrastructure\n\n**The impossible travel false positive problem**\n\nNot every impossible travel alert represents a compromise. Common benign explanations:\n- **Shared accounts** (service accounts, departmental logins) used by different people in different locations — not a good security practice, but it happens\n- **Legitimate use of personal VPN** — the user's traffic appears to come from a country where their VPN provider has servers, not their actual location\n- **IPv6 geolocation errors** — geolocation databases are imperfect, especially for IPv6 addresses\n- **Rapid IP reassignment** — ISPs sometimes reassign IP blocks, causing geolocation to show a brief impossible jump\n\nWhen investigating impossible travel, always contact the user (through a verified channel, not email — the email might be compromised) to ask: \"Are you currently travelling? Did you log into the VPN from [Location]?\"",
      },

      // ── Question 1 ──
      {
        type: "question",
        id: "vpn-q1",
        question:
          "A user account shows the following VPN authentication events: 14:22 UTC — successful login from São Paulo, Brazil (IP: 177.84.x.x); 14:55 UTC — successful login from Tokyo, Japan (IP: 203.104.x.x). The distance between São Paulo and Tokyo is approximately 18,000 km. What is the correct assessment?",
        options: [
          "This is normal — users can use split tunnelling which changes their apparent location",
          "This is impossible travel — 18,000 km in 33 minutes requires a speed of ~32,727 km/h, far exceeding any known transport. This likely indicates credential compromise.",
          "Only authentication failures indicate account compromise, not successful logins",
          "Geographic logins from two different countries are always expected for global companies",
        ],
        answer: 1,
        explanation:
          "18,000 km ÷ (33/60) hours = ~32,727 km/h. The speed of sound is ~1,235 km/h and the fastest aircraft ever built (SR-71 Blackbird) reaches ~3,540 km/h. This is physically impossible travel and strongly indicates credential compromise — an attacker in Tokyo is using the same credentials the legitimate user used from São Paulo 33 minutes earlier. This should trigger immediate account suspension and investigation.",
        xp: 20,
      },

      // ── Question 2 ──
      {
        type: "question",
        id: "vpn-q2",
        question:
          "Your SIEM detects 47 VPN authentication failures from IP 91.195.240.33 targeting 47 different usernames over a 3-minute window, each attempt using the password 'Welcome1!'. What attack technique does this describe?",
        options: [
          "Brute force — systematically trying all possible passwords against one account",
          "Password spraying — trying a single common password against many accounts to avoid lockouts",
          "Credential stuffing — using username/password pairs from a data breach",
          "Pass-the-hash — using captured NTLM hashes to authenticate without knowing the plaintext password",
        ],
        answer: 1,
        explanation:
          "Password spraying is characterised by: one (or a few) common passwords tried against many different accounts. The goal is to avoid account lockout thresholds — most organisations lock accounts after 5-10 consecutive failures, but if you only try one password per account, you never trigger the lockout. 'Welcome1!' is exactly the kind of common password attackers use in spraying attacks (common word + number + capital = meets most complexity requirements). Credential stuffing uses matched username+password pairs from breaches. Brute force targets one account with many passwords.",
        xp: 20,
      },

      // ── Question 3 ──
      {
        type: "question",
        id: "vpn-q3",
        question:
          "Split tunnelling on a corporate VPN means that:",
        options: [
          "The VPN connection is split between two different users simultaneously",
          "Only traffic destined for corporate resources goes through the VPN; all other internet traffic bypasses it and misses corporate security controls",
          "The VPN tunnel is encrypted in two separate layers for additional security",
          "Corporate traffic is split equally between two redundant VPN gateways",
        ],
        answer: 1,
        explanation:
          "With split tunnelling enabled, a remote employee's traffic is split: corporate traffic (e.g., connections to 10.0.0.0/8) goes through the encrypted VPN tunnel and is subject to corporate security controls. Everything else (YouTube, personal email, general web browsing) goes directly to the internet from their home connection, completely bypassing the corporate web proxy, URL filter, DLP, and IDS/IPS. This is a significant security risk because the corporate device may be browsing malicious sites with zero visibility from the SOC.",
        xp: 20,
      },

      // ── Log Analysis ──
      {
        type: "log_analysis",
        id: "vpn-la1",
        heading: "Investigating a Suspicious VPN Login Sequence",
        context:
          "Your SIEM has correlated two VPN authentication events for the same user account within a short time window and generated an impossible travel alert. The events below represent both VPN sessions for user david.miller@contoso.com. Examine the timestamps, geolocations, and session details carefully.",
        event: {
          id: "evt-vpn-impossible-001",
          ts: "2026-06-24T06:12:44.000Z",
          source: "vpn",
          event_type: "vpn_login",
          hostname: "vpn-gw-emea.contoso.com",
          severity: "critical",
          raw: {
            "event.category": "authentication",
            "event.action": "vpn_session_established",
            "vpn.username": "david.miller@contoso.com",
            "vpn.gateway": "vpn-gw-emea.contoso.com",
            "vpn.auth_method": "password_only",
            "vpn.tunnel_type": "full_tunnel",
            "vpn.client_ip_session_1": "91.108.4.22",
            "vpn.assigned_internal_ip_session_1": "10.200.45.88",
            "vpn.session_1_start": "2026-06-24T06:12:44Z",
            "vpn.session_1_duration_minutes": 8,
            "vpn.bytes_in_session_1": 48200,
            "vpn.bytes_out_session_1": 9842000,
            "vpn.client_ip_session_2": "5.200.35.117",
            "vpn.assigned_internal_ip_session_2": "10.200.45.91",
            "vpn.session_2_start": "2026-06-24T06:41:17Z",
            "vpn.session_2_duration_minutes": 120,
            "vpn.bytes_in_session_2": 1240000,
            "vpn.bytes_out_session_2": 54000,
            "vpn.session_2_country": "Israel",
            "vpn.session_2_city": "Tel Aviv",
            "vpn.auth_method_session_2": "mfa_totp",
            "GeoLocation.session_1.country_name": "Russia",
            "GeoLocation.session_1.city": "Moscow",
            "GeoLocation.session_1.lat": 55.7558,
            "GeoLocation.session_1.lon": 37.6173,
            "GeoLocation.session_2.country_name": "Israel",
            "GeoLocation.session_2.city": "Tel Aviv",
            "GeoLocation.session_2.lat": 32.0853,
            "GeoLocation.session_2.lon": 34.7818,
            "correlation.alert": "IMPOSSIBLE_TRAVEL_DETECTED",
            "correlation.distance_km": 2760,
            "correlation.time_gap_minutes": 28,
            "correlation.required_speed_kmh": 5914,
            "rule.name": "UEBA_ImpossibleTravel_VPN",
            "rule.level": 15,
          },
        },
        questions: [
          {
            question:
              "Looking at Session 1 (the Moscow session), what combination of factors makes this the suspicious session — not the Tel Aviv session?",
            options: [
              "Session 1 used password_only authentication while Session 2 used MFA; Session 1 had nearly 10 MB bytes_out (possible data exfil) while Session 2 had 1.2 MB bytes_in (consistent with normal work); Session 1 lasted only 8 minutes and came from Russia",
              "Session 1 had a shorter duration, which always indicates malicious activity",
              "Session 2 came from Israel, which is a high-risk country",
              "Both sessions are equally suspicious and neither can be ruled out without more evidence",
            ],
            answer: 0,
            explanation:
              "Multiple indicators point to Session 1 (Moscow) as the malicious session: (1) Password-only auth — the attacker did not have the MFA token, but they had the password. Session 2 used MFA TOTP which the legitimate user can complete on their phone. (2) Session 1 bytes_out is 9,842,000 bytes (~9.4 MB) — significant outbound data transfer in only 8 minutes, consistent with data exfiltration. Session 2 shows 1.24 MB in and 54 KB out, consistent with normal work. (3) Session 1 comes from Moscow which the attacker's compromised infrastructure is likely based in. Session 2 comes from Tel Aviv, which matches where david.miller is likely based (EMEA VPN gateway). The 8-minute short session followed by massive bytes_out is a classic smash-and-grab data theft pattern.",
            xp: 25,
          },
          {
            question:
              "What is the time difference in minutes between Session 1 start (06:12:44 UTC) and Session 2 start (06:41:17 UTC)?",
            options: [
              "19 minutes",
              "28 minutes",
              "33 minutes",
              "41 minutes",
            ],
            answer: 1,
            explanation:
              "06:41:17 minus 06:12:44 = 28 minutes and 33 seconds, which rounds to 28 minutes. This matches the correlation.time_gap_minutes field in the log. The log also shows correlation.required_speed_kmh: 5914, which is calculated from 2,760 km ÷ (28.55/60 hours) ≈ 5,800 km/h — far exceeding any form of commercial transport and confirming impossible travel.",
            xp: 25,
          },
        ],
      },

      // ── Analyst Choice ──
      {
        type: "analyst_choice" as const,
        id: "vpn-ac1",
        heading: "Verdict: Legitimate Business Travel or Account Takeover?",
        scenario: "09:15 AM Monday. A SIEM alert fires: VPN login for j.petrov@contoso.com from Thailand (Bangkok, 169.62.14.9). His registered work location is London. HR has no travel request on file. The user has been with the company 4 years, no prior security incidents. Yesterday was Sunday. What is your verdict?",
        event: {
          id: "evt-vpn-ac-001",
          ts: "2026-06-22T09:15:33.000Z",
          source: "vpn" as const,
          vendor: "Cisco AnyConnect",
          event_type: "vpn_login" as const,
          severity: "high" as const,
          hostname: "vpn-gw-apac.contoso.com",
          user_email: "j.petrov@contoso.com",
          description: "VPN login from Thailand — user normally connects from London, no travel request filed",
          mitre_technique: "T1078.004",
          mitre_tactic: "Initial Access",
          raw: {
            "vpn.username": "j.petrov@contoso.com",
            "vpn.client_ip": "169.62.14.9",
            "vpn.gateway": "vpn-gw-apac.contoso.com",
            "vpn.auth_method": "mfa_totp",
            "vpn.auth_result": "success",
            "vpn.tunnel_type": "split_tunnel",
            "vpn.session_start": "2026-06-22T09:15:33Z",
            "GeoLocation.country_name": "Thailand",
            "GeoLocation.city": "Bangkok",
            "GeoLocation.lat": 13.7563,
            "GeoLocation.lon": 100.5018,
            "user.registered_location": "London, United Kingdom",
            "user.last_vpn_country": "United Kingdom",
            "user.last_vpn_date": "2026-06-20T17:42:00Z",
            "user.department": "Engineering",
            "user.account_age_days": 1461,
            "hr.travel_request": "none_on_file",
            "risk.geo_anomaly": true,
            "risk.mfa_completed": true,
            "rule.name": "VPN_Geo_Anomaly_New_Country",
            "rule.level": 9,
          },
        },
        correct_verdict: "escalate",
        explanation: "Escalation to Tier 2 is the correct action. The evidence is ambiguous: MFA was successfully completed (which means the attacker either has the MFA token, or this IS the real user). Thailand is a common holiday destination. The user has a clean 4-year history. But no travel request was filed and this is a Monday morning login — possibly the first workday of a vacation. Without contacting the user or their manager to confirm travel, you cannot make a TP/FP decision. A Tier-2 analyst should call the user directly, check badge access to the London office, and review what resources were accessed during the VPN session.",
        fp_trap: "MFA was successfully completed — many analysts close this as false positive because 'if the user approved MFA, it must be them'. But MFA fatigue attacks or SIM-swapping can bypass MFA. More importantly, the right process is to verify, not assume. The absence of a travel request is a meaningful gap that requires confirmation.",
        xp: 30,
      },

      // ── Flag ──
      {
        type: "flag",
        id: "vpn-flag1",
        prompt:
          "Based on the VPN log above, what is the time difference in minutes between the two VPN login sessions for david.miller@contoso.com? The log shows the exact calculated value in the correlation fields. Enter the number of minutes as a whole number.",
        answer: "28",
        hint: "Look at the correlation fields in the raw log. There is a field that explicitly states the time gap between the two sessions.",
        xp: 35,
      },
    ],
  },

  // ─────────────────────────────────────────────
  // ROOM 3 — Firewall Log Analysis
  // ─────────────────────────────────────────────
  {
    id: "firewall-log-analysis",
    title: "Firewall Log Analysis",
    description:
      "Master the art of reading firewall logs — identify port scans, C2 beacon patterns, and blocked outbound threats across FortiGate, Palo Alto, and Check Point NGFW telemetry.",
    difficulty: "intermediate",
    category: "Log Analysis",
    estimatedMinutes: 40,
    xp: 175,
    icon: "🧱",
    prerequisites: ["firewall-network-security", "siem-fundamentals"],
    tasks: [
      // ── Reading 1 ──
      {
        type: "reading",
        id: "fw-r1",
        heading: "Understanding Firewall Logs: The Security Guard's Logbook",
        content:
          "Imagine the firewall as the security guard at the entrance to a very large office building. Every person (packet) that wants to enter or leave must pass the guard's desk. The guard checks ID (source IP), checks the destination (destination IP and port), and compares them against a rulebook. If the rulebook says 'allow', the person is let through; if it says 'deny' or 'drop', they are turned away or quietly ignored. The guard writes down every single interaction in a logbook.\n\nFirewall logs are that logbook. And for a SOC analyst, it is one of the richest sources of network visibility you have.\n\n**Core firewall log fields**\n\nEvery firewall, regardless of vendor, captures some version of these fields:\n\n- **srcip (source IP)** — where the traffic originates. For outbound traffic, this is the internal machine's IP. For inbound, this is the internet IP attacking you.\n- **dstip (destination IP)** — where the traffic is going. For outbound, this is the internet server being contacted. For inbound, this is your server being targeted.\n- **srcport** — the source port (usually ephemeral, 1024-65535 for outbound connections)\n- **dstport / service** — the destination port. Port 80 = HTTP, 443 = HTTPS, 22 = SSH, 3389 = RDP, 3306 = MySQL. The port tells you what service or protocol is involved.\n- **proto / protocol** — TCP, UDP, or ICMP\n- **action** — allow, deny, drop, reject, reset. **Allow** = traffic was permitted. **Deny/Block** = traffic was stopped (a response was sent to the sender). **Drop** = traffic was silently discarded (no response, useful against scanners). **Reset** = TCP reset sent to terminate connection.\n- **bytes sent / bytes received** — payload size. Large bytes_sent in a normally-small-traffic session can indicate data exfiltration. Consistent tiny payloads at regular intervals can indicate C2 beaconing.\n- **duration** — how long the session lasted\n- **rule_name / rule_uid** — which specific firewall rule was triggered. Rule hit counts in dashboards show which rules are most active.\n- **policy_name** — the policy set that the rule belongs to\n\n**Stateful vs stateless inspection**\n\nA **stateless** firewall checks each packet individually against rules. It is fast but can be fooled by packet fragmentation and does not understand context.\n\nA **stateful** firewall tracks the **state** of network connections. It knows whether a packet is part of an established connection or a new one. For example: if your internal machine initiates a TCP connection to a web server, the firewall allows the response packets back in automatically because it knows those are part of an established session. This prevents attacks that try to inject malicious traffic disguised as return traffic.\n\nAll modern enterprise firewalls (FortiGate, Palo Alto, Check Point, Cisco FTD) are stateful. In fact, they are Next-Generation Firewalls (NGFW) that also do deep packet inspection, SSL decryption, application identification, and IPS/IDS integration.\n\n**Reading FortiGate logs**\n\nFortiGate uses a key-value format in syslogs. Important fields:\n- `logid` — a numeric log identifier (e.g., 0000000013 = traffic forward)\n- `type=traffic` and `subtype=forward` — standard traffic log\n- `action` — accept, deny, drop, close, server-rst\n- `vd` — virtual domain (VDOM) the traffic passed through\n- `sentbyte` / `rcvdbyte` — bytes sent by source / received from destination\n- `srccountry` / `dstcountry` — geographic lookup of source/destination IPs\n- `policyid` — which policy number matched (maps to rule_name in the policy table)\n\n**Reading Palo Alto PAN-OS logs**\n\nPAN-OS uses CSV or syslog format with a defined field order:\n- `TRAFFIC` log type\n- `rule` — the rule name that matched\n- `from`/`to` — security zones (e.g., Trust → Untrust)\n- `app` — application identified by App-ID (e.g., ssl, web-browsing, bittorent)\n- `bytes_sent`/`bytes_received`\n- `session_end_reason` — tcp-fin, aged-out, policy-deny, threat\n\n**Reading Check Point logs**\n\nCheck Point uses SmartConsole log fields:\n- `rule_name` — the matched rule\n- `inzone`/`outzone` — traffic direction\n- `ProductFamily` — which blade generated the log (Firewall, VPN, IPS, Application Control)\n- `Action` — Accept, Drop, Reject, Encrypt",
      },

      // ── Reading 2 ──
      {
        type: "reading",
        id: "fw-r2",
        heading: "Detecting Threats in Firewall Logs: Scans, Beacons, and Inbound Attacks",
        content:
          "A skilled attacker uses the internet the same way you do — making network connections to servers. The difference is what they're connecting to, what port they're using, and what data they send. Your firewall sees all of it. The challenge for the SOC analyst is finding the malicious needle in a haystack of millions of legitimate connections.\n\n**Port scanning signatures**\n\nBefore attacking a target, adversaries typically run reconnaissance — they scan the target's IP address on many ports to find which services are running. A port scan looks like this in firewall logs:\n\n- Many connection attempts from the **same source IP** to the **same destination IP** but on **many different destination ports** in a very short time\n- Most attempts result in **deny/drop/reject** actions (closed ports)\n- Traffic is typically **TCP SYN** packets (small payload, no full handshake)\n- Could be sequential (port 1, 2, 3... or 22, 23, 80, 443...) or random order\n\nA SIEM rule might trigger on: \"more than 50 distinct dstport values from the same srcip to the same dstip within 60 seconds\".\n\nImportant: internal-to-internal scanning (a machine inside your network scanning other internal machines) is often more alarming than external scanning, as it may indicate a compromised internal host doing lateral movement reconnaissance.\n\n**C2 beacon patterns — the ticking clock**\n\nOnce malware infects a machine, it calls home to the Command and Control (C2) server to receive instructions and report results. This \"calling home\" is called beaconing. Beacons have distinctive characteristics in firewall logs:\n\n- **Regularity** — beacons happen at consistent time intervals. The malware is programmed to check in every 30 seconds, or every 5 minutes, or every hour. In firewall logs, you see connections to the same external IP at very regular intervals.\n- **Small, consistent payload** — the initial beacon is usually small (just a \"hello, here's my ID, any instructions?\"). Bytes values are consistently tiny unless data is being exfiltrated.\n- **Unusual ports** — C2 malware often uses port 443 (HTTPS) or port 80 (HTTP) to blend in with legitimate traffic. But some malware uses high ephemeral ports like 4444, 8080, or 8888.\n- **Long-lived pattern** — the connections may continue for days, weeks, or months\n- **Non-browser User-Agent** (if HTTP/S and you have proxy logs) — the HTTP request doesn't look like a normal browser\n\nNext-generation firewalls with App-ID can sometimes detect that a connection using port 443 is not actually TLS/HTTPS — it's some other protocol tunnelled inside.\n\n**Inbound threats to watch for**\n\n- **RDP brute force**: many authentication failures from external IPs to your RDP servers (port 3389). If an attacker gets in via RDP, they have full graphical access to the desktop.\n- **SSH brute force**: similar pattern on port 22 from external IPs\n- **Web application attacks**: your WAF and firewall may both see large volumes of HTTP requests from the same IP, many resulting in 4xx/5xx error responses, probing for SQL injection or vulnerabilities\n- **SMB exploitation**: connections from external IPs trying port 445 (SMB) — a firewall that allows inbound port 445 from the internet has a catastrophic misconfiguration (EternalBlue/WannaCry exploited this)\n\n**Distinguishing outbound vs inbound threats**\n\nA critical mental model: the direction of the threat matters.\n\n**Inbound** — external IP trying to reach your internal systems. You are the target. Your firewall's job is to block this.\n\n**Outbound** — your internal IP connecting to an external system. Either a legitimate user/service, or a compromised internal host (malware) calling out to C2. Your firewall may allow port 80/443 outbound by default — this is the blind spot C2 malware exploits.\n\n**Lateral movement** — an internal IP scanning or connecting to other internal IPs. Your internal firewall segments (microsegmentation) should catch this, but many organisations only have a perimeter firewall.",
      },

      // ── Reading 3 ──
      {
        type: "reading",
        id: "fw-r3",
        heading: "Firewall Investigation Methodology and Rule Analysis",
        content:
          "A bank vault has a sophisticated alarm system. Every time someone touches the vault door, it logs the event. But the vault door is touched hundreds of times a day legitimately. The security guard's job is not to review every single log line — that is impossible. Their job is to find the patterns that indicate someone is testing the lock, probing for weaknesses, or has managed to open it when they shouldn't have.\n\nFirewall analysis is the same discipline. In a medium-sized enterprise, firewalls generate millions of log events per day. The SOC analyst needs efficient methods to find signal in all that noise.\n\n**Starting an investigation: what triggered the alert?**\n\nMost firewall investigations start with a SIEM alert, not raw log browsing. The alert tells you something anomalous was detected. Common starting points:\n- Threat intelligence match: a connection to/from a known malicious IP or domain\n- Volume anomaly: unusual spike in bytes transferred from a normally quiet machine\n- Policy violation: traffic on a port that should never appear (e.g., internal machine connecting to external on port 4444)\n- IDS/IPS signature: the NGFW's built-in intrusion detection fired on content inside a packet\n\n**Pivot: from alert to investigation**\n\nOnce you have a suspicious source IP (srcip), you pivot:\n\n1. **What else has this IP done?** Search all firewall logs for this srcip over the last 24 hours. What other destinations did it contact? What ports? Were any blocked?\n\n2. **What machine is this?** Look up the srcip in your DHCP logs or asset inventory to find the hostname and who owns the machine.\n\n3. **Has this destination IP (dstip) been contacted by others?** If one machine contacts a suspicious external IP, check whether other machines also contacted the same IP. If 20 machines all connect to 185.220.101.47:443 at regular intervals, you likely have a widespread malware infection.\n\n4. **What does threat intelligence say about the external IP?** Check VirusTotal, AbuseIPDB, and your SIEM's built-in threat feeds. If it is categorised as \"Malware C2\", the investigation becomes a confirmed incident.\n\n5. **What application/service?** If you have App-ID or proxy integration, determine the actual application. Is port 443 traffic actually HTTPS (benign-looking) or is it a known C2 framework tool like Cobalt Strike or Metasploit HTTPS listener?\n\n**Rule hit analysis**\n\nFirewall policies contain dozens or hundreds of rules. Rules are evaluated top-to-bottom, and the first matching rule wins. Monitoring rule hit counts reveals:\n- **High-hit deny rules**: which traffic is being blocked most often? High hits on an inbound-deny rule from diverse external IPs may indicate scanning activity against your perimeter.\n- **Permissive rules with unexpected traffic**: a rule that was created for a specific application but is now seeing traffic on unexpected ports — someone may be using it as a bypass.\n- **Shadow rules**: rules that never match (zero hits) may be duplicates or outdated. Rules that used to have hits but suddenly stopped may indicate a service has moved.\n\n**Containment actions via firewall**\n\nWhen you confirm malicious activity, your firewall is a key containment tool:\n- **Block specific external IP**: add a deny rule for the malicious destination IP (C2 server). This may interrupt active malware but does not remove it from the endpoint.\n- **Block source IP**: if you identify an attacking external IP (scanning, brute force), block it inbound.\n- **Quarantine segment**: if a machine is confirmed compromised, work with network operations to move it to an isolated VLAN that has no access to the internal network (only access to the SOC's analysis systems).\n- **Emergency rule**: add a temporary \"log and alert\" rule above existing rules to capture all traffic from a suspicious internal IP in high resolution while you investigate.",
      },

      // ── Question 1 ──
      {
        type: "question",
        id: "fw-q1",
        question:
          "Your firewall logs show the following over a 90-second window from source IP 10.30.0.45: connection attempts to 10.30.0.1 on ports 22, 80, 135, 139, 443, 445, 1433, 3389, 3306, 5432, 8080, 8443 — all denied by the firewall. What does this pattern most likely indicate?",
        options: [
          "A user testing multiple web services from their workstation — normal IT activity",
          "Internal port scanning from 10.30.0.45, likely a compromised internal host performing lateral movement reconnaissance",
          "A firewall misconfiguration causing legitimate traffic to be denied on multiple ports",
          "Normal Windows networking activity (SMB, RPC, and Active Directory communications)",
        ],
        answer: 1,
        explanation:
          "This is a textbook port scan signature: one source IP (10.30.0.45, an internal machine), one destination IP (10.30.0.1), scanning across 12 well-known service ports (SSH, HTTP, RPC, NetBIOS, HTTPS, SMB, MSSQL, RDP, MySQL, PostgreSQL, HTTP-Alt, HTTPS-Alt) within 90 seconds — all denied. No legitimate user application generates this pattern. This strongly indicates 10.30.0.45 is compromised and is performing internal reconnaissance to identify services on 10.30.0.1. It could also be a security scanner run by IT, but that should be pre-authorised and logged in the change management system. The fact that all connections are denied from the same source in such a short window is the key signature.",
        xp: 20,
      },

      // ── Question 2 ──
      {
        type: "question",
        id: "fw-q2",
        question:
          "Firewall logs show that internal host 10.50.0.122 makes an outbound connection to 45.83.91.202:443 every 300 seconds (exactly 5 minutes) for the past 6 hours. Each connection transfers approximately 450 bytes out and 200 bytes in, then closes. What does this pattern indicate?",
        options: [
          "Normal HTTPS web browsing to a content delivery network",
          "A scheduled Windows Update check",
          "C2 beaconing — malware on 10.50.0.122 is regularly checking in with a command and control server at regular intervals with small, consistent payloads",
          "A network printer polling for print jobs",
        ],
        answer: 2,
        explanation:
          "The defining characteristics of C2 beaconing are all present: (1) **Extreme regularity** — exactly every 300 seconds is a programmed interval, not human browsing behaviour. (2) **Consistent tiny payload** — 450 bytes out and 200 bytes in is too small for meaningful web content but consistent with a malware heartbeat. (3) **Long duration** — 6 hours of continuous beaconing. (4) **Single external IP** — legitimate browsing hits many different IPs. Real HTTPS web browsing has irregular timing, variable payload sizes, and multiple destinations. Windows Update contacts Microsoft-owned IP ranges on a specific schedule, not every 5 minutes. This is a high-confidence C2 beacon detection.",
        xp: 20,
      },

      // ── Question 3 ──
      {
        type: "question",
        id: "fw-q3",
        question:
          "In a FortiGate firewall log, you see: action=block, srcip=10.40.22.55, dstip=185.220.101.47, dstport=443, proto=TCP, sentbyte=0, rcvdbyte=0. The firewall blocked this connection. What does sentbyte=0 and rcvdbyte=0 tell you about this specific event?",
        options: [
          "The connection was fully established before being blocked, so no data is logged",
          "The firewall blocked the connection attempt before any data was exchanged — the TCP handshake never completed",
          "The log entry is corrupted and the byte values are missing",
          "The firewall only blocks ICMP traffic; TCP is always allowed",
        ],
        answer: 1,
        explanation:
          "When sentbyte=0 and rcvdbyte=0, it means the firewall denied the connection attempt before any data was actually transferred. The firewall matched the connection attributes (source IP, destination IP, port, protocol) against its deny rules and dropped or rejected the SYN packet before a TCP handshake could complete. This is the ideal outcome — the malware on 10.40.22.55 tried to reach its C2 server at 185.220.101.47:443 but the firewall prevented the connection from establishing. No data left your network. The next step is to investigate and remediate 10.40.22.55 (the infected internal host), even though the C2 communication was blocked.",
        xp: 20,
      },

      // ── Log Analysis ──
      {
        type: "log_analysis",
        id: "fw-la1",
        heading: "Analysing a Blocked Outbound C2 Connection",
        context:
          "Your SIEM has raised a 'Threat Intel Match — Known C2 Infrastructure' alert. A FortiGate firewall has blocked an outbound connection from an internal workstation to a destination IP that appears on multiple threat intelligence feeds as a known Cobalt Strike C2 server. The log event below was generated by the FortiGate and forwarded to your SIEM. Analyse the log to understand what happened and identify the key indicators.",
        event: {
          id: "evt-fw-c2-block-001",
          ts: "2026-06-24T14:33:08.000Z",
          source: "firewall",
          event_type: "net_blocked",
          hostname: "fortigate-core-01.contoso.com",
          severity: "critical",
          vendor: "Wazuh",
          raw: {
            "data.type": "traffic",
            "data.subtype": "forward",
            "data.logid": "0000000013",
            "data.level": "warning",
            "data.vd": "root",
            "data.action": "block",
            "data.logdesc": "Connection blocked by policy",
            "data.srcip": "10.10.22.87",
            "data.srcport": 54291,
            "data.srcmac": "00:1A:2B:3C:4D:5E",
            "data.srcintf": "internal-vlan22",
            "data.dstip": "185.220.101.47",
            "data.dstport": 443,
            "data.dstintf": "wan1",
            "data.proto": 6,
            "data.rule_uid": "pol-block-c2-threatintel-001",
            "data.rule_name": "Block_Outbound_ThreatIntel_C2",
            "data.sentbyte": 0,
            "data.rcvdbyte": 0,
            "data.duration": 0,
            "data.srccountry": "Reserved",
            "data.dstcountry": "Netherlands",
            "data.msg": "Connection to known C2 server blocked by threat intelligence policy",
            "data.eventtime": 1750775588,
            "threat_intel.ip": "185.220.101.47",
            "threat_intel.tags": ["cobalt-strike", "c2", "malware-distribution"],
            "threat_intel.confidence": "high",
            "threat_intel.sources": ["emerging-threats", "abuseipdb", "virustotal"],
            "asset.hostname": "WKSTN-ACCT-087",
            "asset.owner": "jennifer.walsh@contoso.com",
            "asset.department": "Accounting",
            "rule.name": "FW_Block_ThreatIntel_C2_Outbound",
            "rule.level": 15,
            "rule.description": "Outbound connection to known C2/malware IP blocked",
            "rule.pci_dss": ["10.6.1", "11.4"],
            "rule.nist_800_53": ["SI-3", "SI-4"],
          },
        },
        questions: [
          {
            question:
              "The firewall blocked this connection. Does this mean the threat is resolved and no further action is needed?",
            options: [
              "Yes — the firewall blocked the C2 connection, so the attacker has no access and the incident is closed",
              "No — the firewall blocked the C2 communication, but the malware is still present and active on WKSTN-ACCT-087 (jennifer.walsh's machine). The malware will likely retry. The endpoint must be isolated and remediated.",
              "No — the firewall rule should be removed so security researchers can track the malware's behaviour",
              "Yes — a block action means the packet was destroyed and no further malware activity is possible",
            ],
            answer: 1,
            explanation:
              "A firewall block stops network communication, not malware execution. The Cobalt Strike or other malware payload is still installed and running on WKSTN-ACCT-087 (jennifer.walsh's accounting workstation). It will continue to retry the C2 connection at regular intervals. The firewall will block each attempt, but: (1) The malware may have already established persistence (registry, scheduled tasks, services). (2) The attacker may change their C2 IP to one not yet on the threat feed. (3) The malware may have already exfiltrated data before this specific block event. Immediate actions required: isolate WKSTN-ACCT-087 from the network, engage EDR to identify the malware, and investigate what activities occurred on this machine before the C2 block alert.",
            xp: 25,
          },
          {
            question:
              "What is the destination IP that the malware tried to contact?",
            options: [
              "10.10.22.87",
              "185.220.101.47",
              "fortigate-core-01.contoso.com",
              "54291",
            ],
            answer: 1,
            explanation:
              "The destination IP (data.dstip) is 185.220.101.47. This is the external C2 server that the malware on the internal workstation (10.10.22.87, hostname WKSTN-ACCT-087) attempted to connect to on port 443 (HTTPS). The threat intelligence fields confirm this IP is tagged as 'cobalt-strike', 'c2', and 'malware-distribution' with high confidence across three threat intelligence sources. The source IP 10.10.22.87 is the internal infected machine, and 54291 is the ephemeral source port used by the malware process.",
            xp: 25,
          },
        ],
      },

      // ── Analyst Choice ──
      {
        type: "analyst_choice" as const,
        id: "fw-ac1",
        heading: "Verdict: C2 Beacon or Legitimate Software Update?",
        scenario: "2:07 AM. FortiGate NGFW triggers an alert: workstation WKSTN-SALES-032 is making outbound connections to 91.195.240.117 every 4 minutes on port 443. The connections last 2-3 seconds each. Business hours ended 6 hours ago. The asset belongs to sales rep m.kim@contoso.com. The destination IP appears on no URL reputation blocklists. What is your verdict?",
        event: {
          id: "evt-fw-ac-001",
          ts: "2026-06-25T02:07:12.000Z",
          source: "firewall" as const,
          vendor: "FortiGate",
          event_type: "net_connection" as const,
          severity: "high" as const,
          hostname: "WKSTN-SALES-032",
          user_email: "m.kim@contoso.com",
          description: "Highly regular outbound HTTPS beacon after hours — possible C2 heartbeat",
          mitre_technique: "T1071.001",
          mitre_tactic: "Command and Control",
          raw: {
            "data.type": "traffic",
            "data.subtype": "forward",
            "data.action": "accept",
            "data.srcip": "10.10.4.32",
            "data.srcport": 49821,
            "data.dstip": "91.195.240.117",
            "data.dstport": 443,
            "data.proto": "6",
            "data.app": "SSL",
            "data.sentbyte": 812,
            "data.rcvdbyte": 312,
            "data.duration": 2,
            "data.srccountry": "Reserved",
            "data.dstcountry": "Netherlands",
            "data.logdesc": "Connection accepted",
            "data.vd": "root",
            "beacon.interval_seconds": 240,
            "beacon.jitter_percent": 5,
            "beacon.connection_count_last_hour": 15,
            "beacon.first_seen": "2026-06-24T20:03:00Z",
            "threat_intel.ip": "91.195.240.117",
            "threat_intel.verdict": "not_listed",
            "threat_intel.asn": "AS49453 Global Layer B.V.",
            "rule.name": "Outbound_Beacon_Pattern_After_Hours",
            "rule.level": 11,
          },
        },
        correct_verdict: "true_positive",
        explanation: "This is a true positive C2 beacon. The key indicators: (1) Highly regular 4-minute interval with very low jitter (5%) — human and legitimate software do NOT create such precise intervals. Legitimate update checks happen once a day or once a week. (2) After-hours timing — the workstation's user went home at 8 PM; no legitimate software needs to check in 15 times per hour after business hours. (3) Tiny payload size (812 bytes sent, 312 received) — too small for any meaningful data transfer, consistent with a C2 heartbeat 'are you there?' ping. (4) The destination IP is a VPS on a bulletproof hosting provider in the Netherlands. The fact that it is not on a blocklist is not reassuring — C2 infrastructure is freshly deployed and rotated specifically to evade blocklists.",
        fp_trap: "The destination IP has no reputation hits on VirusTotal or other blocklist services. Many analysts close beacon alerts when the IP is 'clean'. But C2 infrastructure is constantly rotated precisely to stay off blocklists. The combination of precise interval, tiny payload size, and after-hours timing is a stronger signal than any reputation database.",
        xp: 30,
      },

      // ── Flag ──
      {
        type: "flag",
        id: "fw-flag1",
        prompt:
          "Examine the firewall log above. What is the destination IP address that was blocked by the FortiGate firewall? Enter the exact IP address as it appears in the data.dstip field.",
        answer: "185.220.101.47",
        hint: "Look for the data.dstip field in the raw log. This is the external IP address the malware tried to reach (the C2 server), which the firewall successfully blocked.",
        xp: 35,
      },
    ],
  },

  // ─────────────────────────────────────────────
  // ROOM 4 — DNS Investigation
  // ─────────────────────────────────────────────
  {
    id: "dns-investigation",
    title: "DNS Investigation",
    description:
      "Uncover the hidden intelligence in DNS logs — detect DGA domains, DNS exfiltration tunnels, fast flux C2, typosquatting, and analyse Sysmon Event ID 22 to identify malicious processes calling home.",
    difficulty: "intermediate",
    category: "Threat Detection",
    estimatedMinutes: 40,
    xp: 175,
    icon: "🌐",
    prerequisites: ["networking-protocols", "siem-fundamentals"],
    tasks: [
      // ── Reading 1 ──
      {
        type: "reading",
        id: "dns-r1",
        heading: "DNS: The Phone Book That Logs Every Call",
        content:
          "Imagine a phone book where every time someone looks up a number, the operator writes down: who made the call, what name they looked up, what number they found, and what time it was. Now imagine that every single device on your network — every laptop, server, printer, phone, and smart thermostat — has to make a call to this operator before connecting to anything on the internet.\n\nThat is DNS (Domain Name System), and it is possibly the most underutilised source of threat intelligence in many SOC environments. DNS translates human-readable names (www.google.com) into IP addresses that computers understand (142.250.185.46). Before your browser can load any website, your computer must first ask a DNS resolver \"what is the IP address for this domain?\" Every single network process that reaches out to the internet generates at least one DNS query.\n\n**Why DNS is investigative gold**\n\nMalware, when it runs on a machine, almost always needs to communicate with the attacker's infrastructure. To do that, it needs to resolve a domain name to an IP address. This DNS query happens even if the subsequent connection is encrypted. Even if the firewall blocks the final connection, the DNS query may still be logged.\n\nThis means DNS logs are a window into the intent of every process on your network, before encryption and before the actual connection.\n\n**Core DNS log fields**\n\n- **Query Name (QNAME)** — the domain being looked up. This is the most important field. What domain is being queried?\n- **Query Type (QTYPE)** — A (IPv4 address), AAAA (IPv6), MX (mail server), TXT (text records), CNAME (alias). Attackers sometimes abuse TXT records for DNS tunnelling.\n- **Response (RDATA)** — what IP address (or other record) was returned\n- **Response Code (RCODE)** — NOERROR (found), NXDOMAIN (domain does not exist), SERVFAIL (error), REFUSED (server refused query)\n- **Client IP** — which internal machine made the query\n- **Timestamp** — when the query was made\n- **DNS Resolver** — which DNS server answered the query (your internal resolver vs a public one — direct queries to 8.8.8.8 bypassing your corporate resolver is a red flag)\n\n**Sysmon Event ID 22 — DNS query logging on Windows**\n\nMicrosoft Sysinternals Sysmon, when deployed on Windows endpoints, generates **Event ID 22** for every DNS query made by every process. This is incredibly powerful because it links:\n- **The DNS query** (what domain was queried)\n- **The process making the query** (which program on the computer initiated it)\n- **The result** (what IP was returned, or NXDOMAIN)\n\nThis answers the question \"which process is calling home to this domain?\" — something network-level DNS logs cannot answer (they show the machine's IP, not the specific process). Sysmon Event 22 key fields:\n- `winlog.event_data.Image` — full path to the executable making the DNS query (e.g., C:\\Windows\\System32\\svchost.exe or C:\\Users\\alice\\AppData\\Roaming\\Update.exe)\n- `winlog.event_data.QueryName` — the domain being queried\n- `winlog.event_data.QueryResults` — the IP returned, or \"\" for NXDOMAIN\n- `winlog.event_data.ProcessId` — process ID\n- `event.code` = \"22\" — the Sysmon event ID",
      },

      // ── Reading 2 ──
      {
        type: "reading",
        id: "dns-r2",
        heading: "DNS Attack Techniques: DGA, Tunnelling, Fast Flux, and Typosquatting",
        content:
          "A city has thousands of streets. If a criminal uses a specific safe house, the police can watch that address. But what if the criminal has a way to generate a new safe house address every day from a secret algorithm? The police would never be able to pre-block all possible addresses. This is exactly what Domain Generation Algorithms do for malware.\n\n**Domain Generation Algorithms (DGA)**\n\nDGA is a technique used by sophisticated malware to generate hundreds or thousands of random-looking domain names algorithmically. The malware uses the current date and a secret seed value to calculate which domain names to try. Only the attacker knows the same algorithm and registers the \"winning\" domain for that day. All the other generated domains are unregistered and will return NXDOMAIN.\n\nDGA domains look like this:\n- xk3m9qa7vb2cn4wp.com\n- 4t8jhd2msq0vbne9.net\n- r7p1a3x5m2bk0nwq.org\n\nCharacteristics of DGA traffic in DNS logs:\n- **High NXDOMAIN volume**: the infected machine queries many non-existent domains (all the wrong DGA outputs for the day) before finding the one that resolves. An NXDOMAIN storm (many failed DNS queries in quick succession) is a classic DGA indicator.\n- **Algorithmically random-looking domains**: high entropy names with unusual letter distributions\n- **Short TTL**: attacker registers domains with very short time-to-live values so the C2 IP can change rapidly\n- **All queries from the same process**: Sysmon Event 22 will show the malware process making all these queries\n\n**DNS Tunnelling / DNS Exfiltration**\n\nDNS is almost never blocked by firewalls — every network needs DNS to function. Clever attackers exploit this by encoding data inside DNS queries themselves. Instead of making a normal query, the malware encodes stolen data as subdomains:\n\n`V2luZG93c1Bhc3N3b3Jk.attacker-c2.com` (Base64 encoded stolen data as a subdomain)\n\nThe attacker's DNS server receives these queries, decodes the subdomain, and reassembles the stolen data. This works even when all outbound TCP connections are blocked — it only needs UDP port 53 (DNS).\n\nDNS tunnelling signatures:\n- **Unusually long subdomain labels** — legitimate domains rarely have subdomains longer than 20-30 characters. Exfiltration subdomains may be 50-100+ characters.\n- **High query volume to same root domain** — many queries all going to randomstring1.attacker.com, randomstring2.attacker.com, etc.\n- **High entropy subdomains** — base64/hex encoded data looks random with very high character entropy\n- **Unusual query types** — TXT and NULL record queries are used in some DNS tunnelling tools (iodine, dnscat2)\n\n**Fast Flux**\n\nFast flux is a technique where the IP address behind a malicious domain changes extremely rapidly — sometimes every few minutes. Legitimate websites might update their DNS records a few times a year. A fast flux domain might change A records every 60-300 seconds and use dozens or hundreds of different IP addresses (often botnet machines acting as proxies).\n\nFast flux makes it very hard to block C2 by IP address — by the time you add a block rule, the IP has already changed. Indicators:\n- Very low TTL values (60 seconds or less) in DNS responses\n- Many different IPs returned for the same domain over time\n- IPs are distributed across many countries and different ISPs\n- No stable hosting relationship for the domain\n\n**Typosquatting**\n\nTyposquatting is registering domain names that look almost identical to legitimate trusted domains, relying on users mistyping or not noticing small differences:\n- micros0ft.com (zero instead of letter o)\n- paypa1.com (number 1 instead of letter l)\n- amazon-support.com (hyphenated with generic keyword)\n- gooogle.com (extra letter)\n- arnazon.com (rn looks like m at small font sizes)\n\nIn phishing campaigns, users receive links to these typosquatted domains and believe they are visiting the real site. In SOC investigations, DNS logs showing queries to typosquatted versions of your own company domain or trusted partners are a sign of phishing infrastructure targeting your users.\n\n**DNS Sinkholes**\n\nA DNS sinkhole is a security control where known malicious domains are redirected to a safe IP address (often 0.0.0.0 or a security team-controlled server) instead of returning the real malicious IP. When your DNS resolver has a sinkhole list (often from threat intelligence feeds), any malware trying to contact a known C2 domain gets redirected to the sinkhole IP — the connection fails harmlessly. More importantly, the sinkhole logs which internal machines queried the bad domain, creating a list of potentially infected hosts for the SOC to investigate.",
      },

      // ── Reading 3 ──
      {
        type: "reading",
        id: "dns-r3",
        heading: "DNS Investigation Workflow: From NXDOMAIN Storm to Confirmed Malware",
        content:
          "You receive an alert: \"NXDOMAIN Storm Detected — workstation WKSTN-DEV-044 queried 487 non-existent domains in the past 5 minutes.\" How do you investigate this efficiently and reach a verdict?\n\n**Step 1: Characterise the storm**\n\nCollect all the NXDOMAIN queries from the alerting machine in the time window:\n- How many unique domains were queried?\n- What is the structure of the domain names? (Random characters? Specific TLDs? Common length?)\n- What time interval separates queries? (Rapid-fire = DGA; slower, data-encoded = tunnelling)\n- Are any domains on threat intelligence feeds?\n\nIf the domains look like random strings (xj4k9m2n.com, p8a3c7f1.net, q2r6b4z0.org), this is a strong DGA indicator. If the domains all share the same base domain with long encoded subdomains (abc123def456.exfil.attacker.com), this looks more like DNS tunnelling.\n\n**Step 2: Identify the responsible process using Sysmon**\n\nNetwork-level DNS logs tell you the machine's IP but not the specific process. Pivot to Sysmon Event 22 logs for the same machine at the same timestamps:\n- Filter: `event.code: \"22\" AND winlog.computer_name: \"WKSTN-DEV-044\"`\n- Look at `winlog.event_data.Image` — which executable is generating the DNS queries?\n\nRed flags for the Image field:\n- Unexpected location: C:\\Users\\[username]\\AppData\\Roaming\\ or C:\\Temp\\ instead of C:\\Windows\\ or C:\\Program Files\\\n- Masquerading as a legitimate process but in the wrong location: C:\\Users\\bob\\svchost.exe (svchost.exe should only live in C:\\Windows\\System32\\)\n- Unknown executable name with suspicious characteristics\n\n**Step 3: Correlate with other telemetry**\n\nDNS investigation does not happen in isolation. Pivot to:\n- **EDR/Sysmon process creation logs** (Event ID 1): how was the suspicious process launched? What is its parent process? What command line was used?\n- **Firewall logs**: did any connection attempts follow the successful DNS resolution (if any domains resolved)? Did the firewall block them?\n- **AV/EDR**: has the endpoint security solution already flagged this process or file?\n\n**Step 4: Domain analysis**\n\nFor any domains that resolved (NOERROR), investigate the domain:\n- Check VirusTotal for the domain name\n- Check domain registration date (WHOIS): newly registered domains (hours or days old) are more suspicious than established domains\n- Check domain reputation on URLScan.io — what does the website show?\n- Look up the IP addresses the domain resolves to — are they on threat feeds?\n\n**Step 5: Scope the infection**\n\nIf one machine has DGA activity, how many others do?\n- Search your DNS logs for queries to the same DGA domains from other machines\n- Search for the same binary hash (from EDR) across your fleet\n- Check if the malware is a known family — if so, look for its known persistence mechanisms, other malware it drops, and known C2 infrastructure\n\n**Step 6: Contain and eradicate**\n\nFor confirmed DGA malware:\n1. Isolate the affected workstation(s) immediately\n2. Add the successfully-resolved malicious domains and IPs to your DNS sinkhole and firewall blocklist\n3. Run full forensic acquisition of the infected system\n4. Search for the malware binary hash across all endpoints using EDR\n5. Identify initial infection vector (check email for phishing, check web proxy for drive-by download, check USB activity)\n6. Eradicate: remove persistence mechanisms, remove malware binary, patch the vulnerability that allowed infection\n7. Recover: restore from clean backup or reimage the machine\n\n**Key metrics for DNS monitoring**\n\nA mature DNS monitoring programme tracks:\n- NXDOMAIN rate per host (baseline and alerts on spikes)\n- Domains per host per hour (baseline and alert on spikes)\n- Queries to newly registered domains (less than 30 days old)\n- Queries matching threat intelligence feeds (immediate high-priority alert)\n- Direct queries to external DNS resolvers bypassing your corporate resolver (8.8.8.8, 1.1.1.1 from workstations is suspicious — malware does this to bypass your DNS monitoring and sinkholes)",
      },

      // ── Question 1 ──
      {
        type: "question",
        id: "dns-q1",
        question:
          "Your DNS monitoring detects that workstation 10.20.30.44 queried 312 domains in 4 minutes, 309 of which returned NXDOMAIN. The queried domains look like: q7xk2j9m.com, v4p8a3b1.net, r6m0n2k5.org. What is the most likely explanation?",
        options: [
          "The user is browsing many websites simultaneously — normal during research",
          "DGA (Domain Generation Algorithm) malware infection — the malware is cycling through algorithmically generated domains to find its active C2 server, with almost all generated domains returning NXDOMAIN since only one is registered at a time",
          "The DNS server is malfunctioning and returning NXDOMAIN for legitimate domains",
          "The user is running a penetration testing tool with their manager's permission",
        ],
        answer: 1,
        explanation:
          "This is a textbook DGA pattern: (1) High volume of DNS queries in a short time — 312 queries in 4 minutes is ~78 queries/minute. Normal web browsing generates far fewer. (2) Overwhelming NXDOMAIN rate — 309/312 (99%) non-existent domains. Normal browsing returns a very high resolution success rate. (3) Domain structure — q7xk2j9m.com, v4p8a3b1.net, r6m0n2k5.org all exhibit high entropy, no meaningful words, and short random-character format. This is algorithmically generated, not human-chosen names. The machine is infected with DGA malware cycling through generated domain names looking for the one currently registered by the attacker.",
        xp: 20,
      },

      // ── Question 2 ──
      {
        type: "question",
        id: "dns-q2",
        question:
          "Sysmon Event ID 22 shows process C:\\Users\\frank\\AppData\\Roaming\\RuntimeBroker.exe making hundreds of DNS queries. RuntimeBroker.exe is a legitimate Windows process, but it normally lives in C:\\Windows\\System32\\. What technique does this most likely represent?",
        options: [
          "A Windows update that moved RuntimeBroker.exe to a new location",
          "Process masquerading (also called process name spoofing) — malware copied a legitimate Windows process name but placed itself in an unusual location to avoid detection",
          "This is completely normal — Windows processes can exist in any directory",
          "The user manually moved the file for performance reasons",
        ],
        answer: 1,
        explanation:
          "Process masquerading is a common malware evasion technique. Malware authors name their executables identically to well-known Windows system processes (RuntimeBroker.exe, svchost.exe, lsass.exe, explorer.exe) to blend in with lists of running processes. However, legitimate Windows system processes live exclusively in specific directories (C:\\Windows\\System32\\, C:\\Windows\\SysWOW64\\). Finding RuntimeBroker.exe in C:\\Users\\frank\\AppData\\Roaming\\ is a definitive indicator that this is malware impersonating a legitimate process name — it is not a legitimate Windows binary.",
        xp: 20,
      },

      // ── Question 3 ──
      {
        type: "question",
        id: "dns-q3",
        question:
          "During a DNS investigation you notice that the domain c2.attacker-infra.net resolves to a different IP address every 90 seconds, and the IP addresses belong to residential ISPs in many different countries. What technique does this describe?",
        options: [
          "CDN (Content Delivery Network) load balancing — normal for large websites",
          "Fast Flux — rapidly changing DNS records using many compromised machines (a botnet) as proxies, making the C2 infrastructure very difficult to block by IP address",
          "DNS round-robin — a standard technique for distributing load across servers",
          "DNSSEC failure causing inconsistent resolution results",
        ],
        answer: 1,
        explanation:
          "Fast flux has two defining characteristics: (1) Very rapid IP changes — legitimate CDNs change IPs too, but not every 90 seconds. (2) IPs belonging to residential ISPs in many countries — these are not datacenter IPs hosting servers; they are compromised home computers (botnet nodes) acting as traffic relay proxies. Standard CDN load balancing uses dedicated datacenter IPs that remain stable for hours or days. DNS round-robin changes infrequently. Fast flux is specifically an evasion technique designed to make IP-based blocking ineffective — by the time a security team adds a block rule for the current IP, the attacker has already moved to a different compromised node.",
        xp: 20,
      },

      // ── Log Analysis ──
      {
        type: "log_analysis",
        id: "dns-la1",
        heading: "Sysmon Event 22 — DGA DNS Storm Investigation",
        context:
          "Your SIEM has triggered a 'DGA Behaviour Detected' alert for workstation WKSTN-HR-033. The alert is based on a correlation of Sysmon Event ID 22 logs showing 200+ NXDOMAIN queries in under 3 minutes, all from the same process. The log below is a representative Sysmon Event 22 entry showing one of the suspicious DNS queries. Examine the process path, query name, and query result carefully.",
        event: {
          id: "evt-dns-dga-001",
          ts: "2026-06-24T11:22:17.438Z",
          source: "dns",
          event_type: "dns_query",
          hostname: "WKSTN-HR-033",
          severity: "critical",
          vendor: "Windows Security",
          raw: {
            "event.code": "22",
            "event.module": "sysmon",
            "event.provider": "Microsoft-Windows-Sysmon",
            "winlog.computer_name": "WKSTN-HR-033",
            "winlog.event_data.Image":
              "C:\\Users\\sarah.okafor\\AppData\\Local\\Temp\\WindowsUpdate\\svchost.exe",
            "winlog.event_data.ProcessId": "7412",
            "winlog.event_data.ProcessGuid": "{4d832f91-b2a1-4c77-0000-001027c86201}",
            "winlog.event_data.QueryName": "a7xk9m2j4q8b3n1r.cc",
            "winlog.event_data.QueryType": "A",
            "winlog.event_data.QueryResults": "::ffff:0.0.0.0",
            "winlog.event_data.QueryStatus": "NXDOMAIN",
            "winlog.event_data.User": "CONTOSO\\sarah.okafor",
            "winlog.event_data.UtcTime": "2026-06-24 11:22:17.438",
            "winlog.event_data.ParentImage":
              "C:\\Users\\sarah.okafor\\AppData\\Local\\Temp\\WinUpdate_Setup.exe",
            "winlog.event_data.ParentProcessId": "6104",
            "winlog.event_data.ParentCommandLine":
              "\"C:\\Users\\sarah.okafor\\AppData\\Local\\Temp\\WinUpdate_Setup.exe\"",
            "correlation.nxdomain_count_5min": 247,
            "correlation.unique_domains_5min": 247,
            "correlation.query_interval_avg_seconds": 1.2,
            "correlation.domains_sample": [
              "a7xk9m2j4q8b3n1r.cc",
              "p3m1q9z4k7x2b6n8.cc",
              "r8b2n4x7m1q3k9a5.cc",
              "v6z1k8m4x9b3n2r7.cc",
              "q4n7a2x1m8z3b6k9.cc",
            ],
            "asset.owner": "sarah.okafor@contoso.com",
            "asset.department": "Human Resources",
            "rule.name": "Sysmon_DGA_NXDOMAIN_Storm",
            "rule.level": 15,
          },
        },
        questions: [
          {
            question:
              "What is the suspicious process making the DNS queries, and why is its location a major red flag?",
            options: [
              "svchost.exe in C:\\Windows\\System32\\ — this is suspicious because svchost.exe should not make DNS queries",
              "C:\\Users\\sarah.okafor\\AppData\\Local\\Temp\\WindowsUpdate\\svchost.exe — it is masquerading as the legitimate svchost.exe (a Windows system process) but is located in a user's Temp directory, which is never a valid location for Windows system processes",
              "WinUpdate_Setup.exe — all Windows Update installers are suspicious",
              "The process location is not suspicious — Windows Update files are stored in user temp directories",
            ],
            answer: 1,
            explanation:
              "The path C:\\Users\\sarah.okafor\\AppData\\Local\\Temp\\WindowsUpdate\\svchost.exe is a textbook malware masquerade. svchost.exe (Service Host) is a critical legitimate Windows process — but it exclusively lives in C:\\Windows\\System32\\svchost.exe. Never in a user's Temp folder. The attacker named their malware 'svchost.exe' to blend in with process listings. The parent process WinUpdate_Setup.exe (also in Temp) is the dropper that likely arrived via phishing and spawned this DGA malware. The Temp directory is a classic malware staging area because it is always writable without admin rights.",
            xp: 25,
          },
          {
            question:
              "Looking at the domain samples in the correlation fields and the QueryName, what characteristics confirm this is DGA activity rather than normal DNS failures?",
            options: [
              "The domains use .cc TLD which is a country code for Cocos Islands — all .cc domains are malicious",
              "All 247 domains queried are unique, all returned NXDOMAIN, all have high-entropy random-looking names with consistent length and .cc TLD, and they are being queried at machine speed (~1.2 seconds apart) by a process masquerading as svchost.exe",
              "The query interval of 1.2 seconds is suspicious because humans type slower than that",
              "NXDOMAIN responses always indicate malware activity",
            ],
            answer: 1,
            explanation:
              "Multiple DGA indicators converge here: (1) 247 unique domains all returning NXDOMAIN — the malware is cycling through generated names looking for the one that resolves. (2) All domain names show the same structural pattern: random 16-character hex-like strings with a consistent .cc TLD, characteristic of a single generation algorithm using one seed. (3) Query rate of one every 1.2 seconds — automated machine-speed querying, not human browsing. (4) Generated by svchost.exe in a Temp directory — confirms a malicious process. (5) High entropy characters (a-z, 0-9 seemingly random) with no human-readable words. The combination of these factors is definitively DGA.",
            xp: 25,
          },
        ],
      },

      // ── Analyst Choice ──
      {
        type: "analyst_choice" as const,
        id: "dns-ac1",
        heading: "Verdict: DNS Tunneling or Legitimate CDN Traffic?",
        scenario: "Your DNS monitoring tool flags WKSTN-DEV-019 for generating 340 DNS queries in 10 minutes to subdomains of 'fastdelivery-cdn.com'. Subdomains look like: 'a7x3k1q.fastdelivery-cdn.com', 'b9p4r2m.fastdelivery-cdn.com'. The domain is 8 months old and resolves correctly to Cloudflare IPs. The subdomain labels are 7 random alphanumeric characters each. No malware was detected by EDR on this host. What is your verdict?",
        event: {
          id: "evt-dns-ac-001",
          ts: "2026-06-25T14:32:07.000Z",
          source: "dns" as const,
          vendor: "Microsoft Sysmon",
          event_type: "dns_query" as const,
          severity: "medium" as const,
          hostname: "WKSTN-DEV-019",
          user_email: "t.okonkwo@contoso.com",
          description: "High volume DNS queries to randomized subdomains — possible DGA or DNS tunneling",
          mitre_technique: "T1071.004",
          mitre_tactic: "Command and Control",
          raw: {
            "event.code": "22",
            "winlog.event_data.Image": "C:\\Users\\t.okonkwo\\AppData\\Roaming\\npm\\node.exe",
            "winlog.event_data.QueryName": "a7x3k1q.fastdelivery-cdn.com",
            "winlog.event_data.QueryStatus": "0",
            "winlog.event_data.QueryResults": "104.21.47.82",
            "winlog.provider_name": "Microsoft-Windows-Sysmon",
            "dns.queries_last_10min": 340,
            "dns.unique_subdomains_last_10min": 338,
            "dns.avg_subdomain_entropy": 3.84,
            "dns.resolver_ip": "8.8.8.8",
            "domain.fastdelivery-cdn.com.age_days": 243,
            "domain.fastdelivery-cdn.com.registrar": "Namecheap",
            "domain.fastdelivery-cdn.com.resolves_to": "Cloudflare IP range",
            "edr.host_verdict": "clean",
            "edr.last_scan": "2026-06-25T14:00:00Z",
            "rule.name": "DNS_High_Volume_Random_Subdomain",
            "rule.level": 8,
          },
        },
        correct_verdict: "escalate",
        explanation: "Escalation is correct — the evidence is genuinely ambiguous. Against malicious: 340 queries in 10 minutes with 338 unique subdomains is extremely high; random 7-character labels match DGA patterns; the process (node.exe from npm) is not typical CDN consumer behavior. For benign: the domain is 8 months old (DGA domains are usually fresh), it resolves to Cloudflare IPs (real CDN), and EDR shows no malware. CDNs like Fastly and Cloudflare do use randomized subdomain labels for load balancing. A Tier-2 analyst should: check what t.okonkwo was working on, review the actual DNS payload sizes (tunneling sends data in query strings — they will be long), and look at the full process tree for node.exe.",
        fp_trap: "CDNs legitimately use randomized subdomain prefixes for load balancing and cache partitioning. A random-looking subdomain label does NOT automatically mean DGA or tunneling. The domain age (8 months) and Cloudflare hosting are real evidence of legitimacy that cannot be dismissed. This is why escalation — not a TP verdict — is the correct call without further investigation.",
        xp: 30,
      },

      // ── Flag ──
      {
        type: "flag",
        id: "dns-flag1",
        prompt:
          "Examine the Sysmon Event 22 log above. What is the name of the suspicious process (the executable filename only, not the full path) that is generating the DGA DNS queries? Enter only the filename with its extension.",
        answer: "svchost.exe",
        hint: "Look at the winlog.event_data.Image field in the raw log. This shows the full path to the executable making the DNS queries. Extract just the filename (the last part after the final backslash).",
        xp: 35,
      },
    ],
  },
];

export default rooms;
