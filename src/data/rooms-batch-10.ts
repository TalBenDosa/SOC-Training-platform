
const rooms = [
  // ─────────────────────────────────────────────
  // ROOM 1 — Phishing Analysis
  // ─────────────────────────────────────────────
  {
    id: "phishing-analysis",
    title: "Phishing Analysis",
    description:
      "Learn to dissect malicious emails like a forensics expert: decode spoofed headers, failed authentication records, weaponised attachments, and Business Email Compromise patterns.",
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
          "Imagine receiving a letter in your mailbox. The envelope has a return address that says \"Internal Revenue Service, Washington DC\". But if you look at the postmark stamp on the envelope, you can see the letter was actually mailed from a post office in Romania. The text printed on the envelope (the \"From\" field) is just ink. Anyone can write anything there. The postmark stamp, however, is added by the postal system itself and is much harder to fake.\n\nEmail works exactly the same way. The **From:** field you see in your inbox is just text that the sender typed. It can say anything: absolutely anything. A criminal can make it say ceo@yourcompany.com with zero technical effort. What you need to examine are the **email headers**: the equivalent of postmarks and handling stamps added by every mail server that touched the message on its journey to you.\n\n**What headers reveal**\n\nEvery email carries a block of metadata called headers, hidden by default in most email clients. When you open headers (\"View Source\" or \"Show Original\" in Gmail), you see a log of every server the email passed through, timestamps, and authentication results.\n\n- **Return-Path:**, The envelope sender: the address where **bounce** messages (delivery failures) go. It is the domain SPF checks. On its own a mismatch with the From domain is a weak signal, because legitimate bulk mail sent through providers such as SendGrid or Mailchimp routinely uses the provider's bounce domain. A Return-Path like attacker@gmail-helpdesk.ru on a message claiming to be from ceo@bigbank.com is still worth noting alongside other evidence.\n\n- **Reply-To:**, Where **replies** go when the recipient clicks Reply. A Reply-To that points to an unrelated domain (From: ceo@bigbank.com, Reply-To: ceo.office@outlook-mail.example) is a much stronger red flag, and a classic BEC trick: the sender wants your answer to reach them, not the real person.\n\n- **Received:** headers. These are added by each mail server in **reverse order** (the bottom Received header was added first, the top one last). Each line shows: the sending server IP, the receiving server, and a timestamp. Reading them from the bottom up shows where the email came from. Be careful: the lowest lines are written by the sender's side, so they can be forged or show private addresses. The most trustworthy origin is the hop recorded by **your own** boundary mail server: the IP that handed the message to you.\n\n- **X-Originating-IP:**, Some webmail systems (Yahoo, older Hotmail) stamp the sender's actual IP address here. This is investigative gold, you can look it up in threat intelligence to see if it belongs to a known spam infrastructure or compromised host.\n\n- **Message-ID:**: A unique identifier assigned by the originating mail server. A message claiming to come from google.com but with a Message-ID like <random@sendinblue.fr> tells you the true sending platform.\n\n**SPF, DKIM, and DMARC: the three authentication shields**\n\nThink of these as three different security guards checking the letter before it gets to you.\n\n**SPF (Sender Policy Framework)**, The domain owner publishes a list in DNS saying \"only these IP addresses are allowed to send email for us\". When a receiving server gets a message claiming to be from bigbank.com, it looks up bigbank.com's SPF record and checks whether the sending IP is on the approved list. If not: **SPF FAIL**.\n\n**DKIM (DomainKeys Identified Mail)**, The sending server cryptographically signs the email with a private key. The receiving server looks up the public key in DNS and verifies the signature. If the email was altered in transit (or if a criminal is forging the domain), the DKIM signature will not match: **DKIM FAIL**. A valid DKIM signature is very hard to fake.\n\n**DMARC (Domain-based Message Authentication, Reporting & Conformance)**. DMARC ties the other two together. It requires that the domain in the From: header aligns with the SPF or DKIM domain, and tells receiving servers what to do (quarantine, reject, or do nothing) when neither SPF nor DKIM passes with alignment. When you see **DMARC FAIL**, it means the email claimed to be from a domain it had no right to send on behalf of.\n\nIn a phishing email that spoofs the real domain, you will commonly see all three failing. But watch for the opposite case: if the attacker registered a look-alike domain like bigbank-support.com and set up SPF, DKIM and DMARC for it, all three **pass**, because the From domain really is theirs. Authentication proves control of a domain, not that the domain belongs to the brand it imitates, so you still have to read the domain itself.\n\n**Practical workflow for header analysis**\n\nStep 1: Read the **Received:** headers bottom-up and find the first hop stamped by your own mail server, the IP it received the message from is the true external origin. Anything below that line is sender-controlled.\nStep 2: Extract the IP address from that header and look it up on VirusTotal, AbuseIPDB, or Shodan.\nStep 3: Check **Reply-To** and **Return-Path**, do they match the claimed From domain? (A Reply-To mismatch matters more.)\nStep 4: Read the **Authentication-Results** header, look for spf=fail, dkim=fail, dmarc=fail.\nStep 5: Check the **Message-ID** domain, does it match the From domain?\n\nA legitimate email from your bank will pass all three authentication checks, have a Return-Path matching the bank's domain or its email provider, and originate from an IP address owned by the bank or its email provider. A phishing email will almost always fail at least one of these tests.",
        checkpoint: {
          question: "A supplier invoice shows From: billing@northwind-supply.com and Return-Path: bounce-4471@em.mailprovider.example. Nothing else looks wrong yet. How should you weigh that Return-Path?",
          options: [
            "Weak on its own: it is the bounce address, and bulk-mail providers often use their own",
            "Strong BEC signal: your user's replies will be delivered to the mail provider's domain",
            "Proof of spoofing: SPF compares the Return-Path domain with the From domain",
            "Not useful: your own gateway writes Return-Path, so it shows nothing about the sender",
          ],
          answer: 0,
          explanation:
            "Return-Path is the envelope sender, where bounce messages go, and a provider bounce domain is normal for legitimate bulk mail, so on its own it is a weak signal. “Your user's replies will be delivered” describes Reply-To, not Return-Path. Reply-To is the stronger BEC signal. “SPF compares the Return-Path domain with the From domain” confuses SPF with DMARC: SPF checks whether the sending IP is allowed for the Return-Path domain; alignment with From is DMARC's job. “Your own gateway writes it” is wrong: the value comes from the sender's envelope, so it does reflect the sending side.",
        },
      },

      // ── Reading 2 ──
      {
        type: "reading",
        id: "phishing-r2",
        heading: "URLs, Attachments, and the Anatomy of a Phishing Kit",
        content:
          "Imagine a fake storefront that looks exactly like your favourite pharmacy: same logo, same colour scheme, same product photos. But the address above the door is slightly wrong: \"CVS-Pharmacy-Support.net\" instead of cvs.com. And the door leads to a back room where someone collects your credit card details. That is a phishing kit.\n\n**URL analysis: what to look for before you click**\n\nThe single most important rule in phishing analysis is: **never click a suspicious link from your normal workstation**. Instead, analysts examine URLs without visiting them.\n\n- **Hover, don't click**, In most email clients, hovering over a hyperlink reveals the actual destination URL in the status bar. The text shown (\"Click here to verify your account\") can say anything; the underlying href tells the truth.\n\n- **URL shorteners**. Links like bit.ly/xk3p9q hide the real destination. Analysts use services like CheckShortURL or URLScan.io to expand shortened URLs without visiting them. Attackers use shorteners specifically to hide malicious destinations.\n\n- **Homograph attacks**. Unicode allows characters that look identical to Latin letters. The Cyrillic letter \"а\" (U+0430) looks exactly like Latin \"a\" (U+0061). A URL like pаypal.com (with a Cyrillic а) looks perfect in an email but resolves to a completely different domain. Always check the raw ASCII or Punycode representation (pаypal.com becomes xn--pypal-4ve.com in Punycode).\n\n- **Subdomain tricks**: paypal.com.attacker.net is NOT paypal.com. The actual domain (the part before the last dot before the TLD) is attacker.net. Victims read from left to right and see \"paypal.com\" and stop.\n\n- **HTTPS does NOT mean safe**. Many people believe the padlock icon means a website is trustworthy. It only means the connection is encrypted. Criminals routinely obtain free TLS certificates (Let's Encrypt) for their phishing domains.\n\n**Analysing attachments without triggering them**\n\nAttachments are another major phishing delivery vector. Common weaponised attachment types:\n\n- **Macro-enabled Office documents (.docm, .xlsm)**. These contain embedded VBA macros that execute when the user clicks \"Enable Content\". Macros can download malware, execute PowerShell commands, and establish persistence. **Red flags:** document asks you to enable macros, document content is blurred or says \"enable editing to view\", document was received from an unexpected sender.\n\n- **Password-protected ZIPs**. Attackers package malware in a ZIP and provide the password in the email body. This bypasses automated email scanning because the scanner cannot open the ZIP without the password. The password is always in the email, \"please use password: Invoice2024 to open the attached file\".\n\n- **ISO and IMG files**. Disk image files can contain executables and, on Windows 10 before a recent patch, could bypass the Mark-of-the-Web (MOTW) security flag that warns users about downloaded files.\n\n- **PDF with embedded links**. PDFs containing links to credential harvesting pages. The PDF itself is clean but acts as a vehicle to get victims to click.\n\n**Business Email Compromise (BEC): the most expensive phishing variant**\n\nBEC does not always involve malware or malicious URLs. Instead, an attacker who has compromised or spoofed an executive's email account sends a convincing email to someone in finance: \"I need you to urgently wire $85,000 to our new vendor account. This is confidential, please process today.\"\n\nBEC characteristics to look for:\n- **Urgency and secrecy** (real executives rarely demand secret urgent wire transfers\n- **Reply-to mismatch**) the From field shows the CEO but Reply-To redirects to attacker@gmail.com\n- **Timing**. BEC attacks often happen on Fridays before holidays when the target executive is harder to reach for verbal confirmation\n- **Slightly wrong domain**. Ceo@company-corp.com vs ceo@company.com\n\n**Analysing the phishing kit itself**\n\nSometimes analysts obtain the actual phishing kit: the ZIP archive the attacker uploaded to a compromised server. These kits reveal: which legitimate site they are impersonating, how stolen credentials are exfiltrated (usually emailed to the attacker or posted to a Telegram bot), which IP addresses are whitelisted (attackers block known security company IPs from seeing the phishing page), and reused code that links kits to known threat actors.",
        checkpoint: {
          question: "A link in a reported email displays as paypal.com and the page shows a padlock. Your proxy logged the request as xn--pypal-4ve.com. Which technique explains what the user saw?",
          options: [
            "A URL shortener that redirected the click to a different domain",
            "A homograph: a look-alike Unicode letter inside the domain name",
            "A subdomain trick that places paypal.com left of the real domain",
            "A valid TLS certificate making a look-alike domain appear genuine",
          ],
          answer: 1,
          explanation:
            "The xn-- prefix is Punycode, the ASCII form of a domain that contains non-Latin characters. Here a Cyrillic letter that looks like “a”. That is a homograph. A shortener would log the shortener's own domain first, not a Punycode name. A subdomain trick would log something like paypal.com.attacker.net, with the brand on the left of a different registrable domain. The padlock is real but only means the connection is encrypted; a certificate cannot make one domain display as another.",
        },
      },

      // ── Reading 3 ──
      {
        type: "reading",
        id: "phishing-r3",
        heading: "Phishing Investigation Workflow: From Alert to Verdict",
        content:
          "Think of a bomb disposal technician. They do not grab a suspicious package and shake it. They follow a strict, safe procedure: assess from a distance, gather information, use tools remotely, then make a decision. Phishing analysis works the same way: a disciplined process keeps you from accidentally detonating the payload.\n\n**Step 1: Triage, is this actually a phishing attempt?**\n\nWhen a user reports a suspicious email, or your email gateway flags one, start by asking:\n- Did the user click anything or open any attachment? (If yes, this is now potentially an incident. Escalate)\n- Does the sender domain match the claimed organisation?\n- Is there urgency, threat, or unusual request language?\n- Does the email address a real need the user has, or is it unsolicited?\n\nNot every flagged email is malicious. Bulk marketing email, misconfigured legitimate systems, and aggressive spam filters all produce false positives.\n\n**Step 2: Safe header extraction**\n\nUse your email security gateway console (Proofpoint, Mimecast, Microsoft Defender for Office 365) to export the raw email headers **without delivering or opening the email yourself**. Copy the headers to a plain text editor.\n\nKey fields to extract and document:\n- Full Received chain (all hops)\n- Return-Path\n- Authentication-Results (SPF, DKIM, DMARC verdicts)\n- X-Originating-IP (if present)\n- Message-ID\n- Date and timezone\n\n**Step 3: Sender IP investigation**\n\nTake the originating IP (from the bottom Received header or X-Originating-IP) and check:\n- **VirusTotal**. Has this IP been flagged by security vendors?\n- **AbuseIPDB**. Has this IP been reported for abuse?\n- **Shodan**. What services is this IP running? Is it a mail server or a VPS that should not be sending email?\n- **Whois / ARIN/RIPE lookup**, who owns this IP? Is it registered to a known spam hosting provider?\n\n**Step 4: URL detonation (sandboxed)**\n\nIf the email contains URLs, submit them to:\n- **URLScan.io** (takes a screenshot and analysis of the page without you visiting it\n- **VirusTotal**) checks the URL against dozens of security vendors\n- **ANY.RUN or Hybrid Analysis**. Full dynamic sandbox if you need to see what the page does\n\nNever visit suspicious URLs in your corporate browser. Even visiting a page can sometimes trigger drive-by download exploits.\n\n**Step 5: Attachment analysis**\n\nIf there is an attachment:\n- Calculate the **SHA256 hash** of the file and check it on VirusTotal\n- Submit to a sandbox (ANY.RUN, Cuckoo, Joe Sandbox) for dynamic analysis\n- For Office documents: tools like **olevba** (part of oletools) extract and display VBA macro code without executing it\n- For PDFs: **pdfid** and **pdf-parser** extract embedded JavaScript and URLs\n\n**Step 6: Document and decide**\n\nAfter gathering evidence, make a verdict:\n- **Benign** (legitimate email, no action needed\n- **Spam**) bulk marketing, not targeted, report to gateway\n- **Phishing**. Credential harvesting attempt, block sender, block URLs, notify users, check if anyone clicked\n- **Spear phishing / BEC**. Targeted attack, escalate to incident response, notify management\n\n**Step 7: Containment actions**\n\nFor confirmed phishing:\n- Block the sender domain and IP in your email gateway\n- Block the malicious URLs in your web proxy\n- Search your email logs for other recipients of the same campaign (same Message-ID, same sender IP, same attachment hash)\n- If any user clicked: isolate their workstation, check EDR telemetry for signs of execution\n- Notify affected users and provide security awareness guidance\n\n**Key metrics to track**\n\nA mature SOC tracks: phishing volume by day/week, click-through rate (what percentage of users who received a phishing email actually clicked), time-to-detection, time-to-containment, and repeat reporter names (users who proactively report phishing deserve recognition).",
      },

      // ── Question 1 ──
      {
        type: "question",
        id: "phishing-q1",
        question:
          "An email arrives claiming to be from support@paypal.com. The Authentication-Results header shows: spf=fail, dkim=fail, dmarc=fail. What does this most likely indicate?",
        options: [
          "Genuine PayPal mail whose DKIM key was rotated, so the signature check broke",
          "Mail that spoofs paypal.com and did not come from PayPal's authorised servers",
          "Mail from a look-alike domain, which is why all three checks came back failed",
          "Genuine mail sent for PayPal by a marketing platform it uses for newsletters",
        ],
        answer: 1,
        explanation:
          "SPF fail means the sending IP is not in paypal.com's SPF record, DKIM fail means there is no valid paypal.com signature, and DMARC fail means neither check passed in alignment with the From domain. Together that is the signature of a spoofed paypal.com sender. A rotated DKIM key would not also make the sending IP unauthorised for SPF. A look-alike domain is the opposite case: the attacker owns it, so its own SPF, DKIM and DMARC usually pass. A marketing platform that PayPal really uses would be listed in its SPF record or sign with its DKIM key, so the mail would pass.",
        xp: 20,
      },

      // ── Question 2 ──
      {
        type: "question",
        id: "phishing-q2",
        question:
          "A user reports a suspicious email with an attachment named 'Invoice_Q4_2024.xlsm'. When they opened it, a bar appeared asking them to 'Enable Content'. What does this tell you, and what should the SOC analyst do first?",
        options: [
          "The macros have already run, since Office shows that bar once the code has executed",
          "It is macro-enabled; confirm whether they clicked Enable Content, then check EDR",
          "Hash the file on VirusTotal; if it shows 0 detections, close the report as benign",
          "Reimage the laptop now, then ask the user later whether they enabled the content",
        ],
        answer: 1,
        explanation:
          ".xlsm is a macro-enabled workbook, and the 'Enable Content' bar is the control that holds macros back until the user allows them. So the first question is whether the user clicked it; if so, check EDR for child processes of EXCEL.EXE such as powershell.exe, cmd.exe or wscript.exe. “The macros have already run” is backwards: the bar appears before execution. “0 detections, close it” trusts a signature lookup that a new or custom macro document easily passes. “Reimage now” is a containment step taken before you know whether anything executed, and it destroys the evidence you need to scope the incident.",
        xp: 20,
      },

      // ── Question 3 ──
      {
        type: "question",
        id: "phishing-q3",
        question:
          "An email that appears to come from the CEO asks finance for an urgent wire transfer. You open the headers. Which single header finding is the strongest Business Email Compromise (BEC) indicator?",
        options: [
          "Return-Path is a mail provider's bounce domain, not the company's",
          "The top Received line shows your own gateway accepting the message",
          "Reply-To is on an unrelated domain from the CEO's From address",
          "There is no X-Originating-IP header anywhere in the message",
        ],
        answer: 2,
        explanation:
          "BEC works by getting finance's answer to the attacker, and Reply-To decides where that answer goes, so a Reply-To on an unrelated domain is the strongest header signal. A provider bounce domain in Return-Path is common in legitimate bulk mail and is weak on its own. Your own gateway always appears in the top Received line; that is normal, not suspicious. X-Originating-IP is added only by some webmail systems, so its absence tells you nothing.",
        xp: 20,
      },

      // ── Log Analysis ──
      {
        type: "log_analysis",
        id: "phishing-la1",
        heading: "Analysing a Suspicious Email Gateway Alert",
        context:
          "Your organisation's email security gateway has flagged an inbound email and generated the following telemetry. The email claims to be from the CFO of a partner company. A junior analyst has escalated it to you for review. Examine the log carefully: pay close attention to the Received headers, authentication results, and attachment details.",
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
              "206fb7186eb4a4082cbf778e4efdd2975008b12d68e4d3e6dd35aede00cc51fa",
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
              "52.96.112.17: mail.contoso.com",
              "185.220.101.47: smtp.sendinblue-relay247.net",
              "10.44.22.8: the bottom-most Received line",
              "mailgw-01.contoso.com: the gateway that logged it",
            ],
            answer: 1,
            explanation:
              "Read Received headers bottom-up and find the first hop stamped by your own server. The bottom line (from [10.44.22.8]) was written by the sender's relay and shows a private, sender-controlled address, so it is not the internet origin even though it is the oldest. The first Contoso-stamped hop is mail.contoso.com receiving from smtp.sendinblue-relay247.net [185.220.101.47], so 185.220.101.47 is the true external origin; the SPF detail names the same IP. 52.96.112.17 is Contoso's own mail server passing the message inward, and mailgw-01.contoso.com is the last internal hop that recorded the event, not where it came from.",
            xp: 25,
          },
          {
            question:
              "Several findings in this log point to phishing. Which one, taken ALONE, would be the weakest reason to call the email malicious?",
            options: [
              "The attachment hash has 38/72 detections on VirusTotal",
              "Return-Path is on sendinblue-relay247.net, not globalpartners.com",
              "spf=fail for 185.220.101.47 and dmarc=fail for globalpartners.com",
              "Reply-To is a Gmail look-alike domain while From is globalpartners.com",
            ],
            answer: 1,
            explanation:
              "A Return-Path on a sending provider's bounce domain is normal for legitimate bulk mail, so on its own it proves little; here it only matters alongside the rest. 38 of 72 engines flagging the attachment is strong evidence the file is malicious. spf=fail plus dmarc=fail means the message claims globalpartners.com but was not sent with that domain's authorisation: a spoofing signal. A Reply-To on an unrelated look-alike domain redirects the victim's answer to the attacker, the classic BEC move. Together the four make this a confirmed phishing attempt.",
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
          description: "Email claiming a Microsoft account alert: SPF, DKIM and DMARC passed, attachment 0/72",
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
            "email.attachment.sha256": "9c04596adc5adf80b36fc690ecd8227e94925128cae19a934ec0c12aa66b3916",
            "email.attachment.vt_detections": "0/72",
            "email.embedded_url": "https://microsoft-account-security.org/verify?token=xK9pQ3mR7nT2",
            "email.url_category": "Uncategorized",
            "rule.name": "Email_Brand_Keyword_External_Sender",
            "rule.level": 7,
          },
        },
        correct_verdict: "true_positive",
        explanation: "This is a true positive phishing attempt. The key evidence: (1) The sending domain is 'microsoft-account-security.org', not microsoft.com. The SPF/DKIM/DMARC checks passing only verify the attacker's domain is correctly configured, not that it belongs to Microsoft. (2) The domain was registered just 3 days ago (June 21). Brand-new domains are a strong phishing indicator. (3) The embedded URL points to the same newly registered domain and is uncategorised, so the 'verify' link leads to a page Microsoft does not control. The 0/72 VirusTotal result is expected: the PDF is just a delivery vehicle for the link, not malware itself.",
        fp_trap: "All three authentication checks (SPF, DKIM, DMARC) passed, which looks reassuring. But these checks only validate that the sender legitimately controls the domain microsoft-account-security.org. They say nothing about whether that domain belongs to Microsoft. The PDF attachment being clean on VirusTotal is also misleading. It is a clean PDF that redirects to a phishing page, not a malicious file.",
        xp: 30,
      },

      // ── Flag ──
      {
        type: "flag",
        id: "phishing-flag1",
        prompt:
          "Go back to the 'Analysing a Suspicious Email Gateway Alert' log (the Urgent_Wire_Request_Q2.xlsm event, not the later verdict scenario). If alice.chen clicks Reply and answers the 'CFO', which domain would her answer actually be delivered to? Enter the domain only, without the user part before the @.",
        answer: "gmail-secure-mail.com",
        hint: "More than one header in that log names a domain other than globalpartners.com. Only one of those headers decides where replies go; the other is used for bounces.",
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
          "Think of a VPN (Virtual Private Network) like the secure entrance tunnel to a high-security office building. Employees park their cars in the public car park (the internet), walk through the secure tunnel, and emerge inside the building where all the company resources are. A guard station at the tunnel entrance logs every single person who enters: their name, what badge they used, what time they arrived, how long they stayed, and how many boxes they carried in and out.\n\nVPN logs are that guard station logbook. Every time an employee connects through your corporate VPN, a record is created. For SOC analysts, this data is invaluable because VPN is often the front door that attackers target, and the last layer of perimeter control standing between an attacker and your internal network.\n\n**What fields appear in VPN logs?**\n\n- **Username** (who authenticated (or who's credentials were used)\n- **Source IP / Client IP**) the public internet IP address the connection came from. This reveals the geographic location of the connecting device\n- **VPN Gateway**, which VPN concentrator was used (useful in large organisations with regional gateways)\n- **Authentication Method**. Password only, MFA, certificate, SAML/SSO\n- **Connection Start Time / End Time / Duration** (when did the session begin and end, how long did it last\n- **Bytes In / Bytes Out**) how much data flowed in each direction. Large bytes_out (from the user's perspective, meaning data leaving your network) can indicate data exfiltration\n- **Tunnel Type**. Full tunnel (all traffic goes through VPN) vs split tunnel (only corporate traffic goes through VPN, personal browsing bypasses it)\n- **Assigned Internal IP**, the IP address the VPN server assigned to the session inside the corporate network\n- **Authentication result** (success, failure, MFA denied, certificate invalid\n- **Disconnect Reason**) idle timeout, user disconnected, connection lost, admin terminated\n\n**Split tunnelling: the SOC analyst's blind spot**\n\nWhen split tunnelling is enabled, traffic to your corporate systems goes through the encrypted VPN tunnel, but everything else (Netflix, personal email, general web browsing) goes directly to the internet, bypassing all corporate security controls: the web proxy, the IDS/IPS, URL filtering, DLP. A user could be connected to VPN and simultaneously downloading malware via their split-tunnel personal traffic, and your security stack would have zero visibility.\n\nThis matters especially for endpoint security: if a remote worker's home machine gets infected, and they connect to VPN, that infected machine is now inside your network perimeter. Regardless of whether split tunnelling is enabled.\n\n**What normal VPN behaviour looks like**\n\nBaseline behaviour varies by organisation, but healthy patterns typically include:\n- Users connecting from consistent geographic locations (their home country)\n- Connection times matching working hours in the user's time zone\n- Reasonable session durations (hours, not weeks)\n- Bytes out consistent with normal work activity (documents, emails) not massive bulk data transfers\n- Consistent authentication methods (if Alice always uses MFA, a session where only password was used is anomalous)\n- Consistent device (certificate-based VPN can tie sessions to specific enrolled devices)",
        checkpoint: {
          question: "A remote laptop connects with a split-tunnel VPN profile. What visibility does the SOC lose compared with a full tunnel?",
          options: [
            "Corporate-bound traffic leaves the tunnel unencrypted on the home network",
            "Non-corporate traffic skips the corporate proxy, IDS/IPS, URL filter and DLP",
            "The gateway stops logging the session, so start and end times are lost",
            "Personal browsing is added to bytes_out, so transfer volumes are inflated",
          ],
          answer: 1,
          explanation:
            "Split tunnelling sends only corporate-bound traffic through the tunnel; everything else goes straight to the internet and never passes the proxy, IDS/IPS, URL filter or DLP. Corporate traffic is still encrypted inside the tunnel, so it is not exposed on the home network. The gateway still logs the session itself: username, times, assigned IP. And personal traffic does not inflate the session's byte counters; it bypasses the gateway, which is exactly why you cannot see it.",
        },
      },

      // ── Reading 2 ──
      {
        type: "reading",
        id: "vpn-r2",
        heading: "Impossible Travel, Brute Force, and Other VPN Attack Patterns",
        content:
          "Imagine you stamp your passport at customs in New York at 9:00 AM. Then at 9:45 AM the same morning, your passport is stamped in London. That is impossible, you cannot cross the Atlantic Ocean in 45 minutes. If someone is presenting your passport in London while you're still in New York, either your passport has been cloned, or someone stole it.\n\nThis exact logic is the foundation of one of the most powerful security detections in modern SOC work: **impossible travel**.\n\n**Impossible travel detection**\n\nImpossible travel occurs when the same user account authenticates from two locations that are geographically too far apart to be physically possible given the time between logins.\n\nThe calculation: distance between Location A and Location B ÷ time between logins = required travel speed. If required speed > maximum possible travel speed (approximately 1,000 km/h for commercial aviation), then it is impossible travel.\n\nFor example:\n- 09:12. User@company.com logs into VPN from Tel Aviv, Israel (IP: 212.143.x.x)\n- 09:41, user@company.com logs into VPN from Moscow, Russia (IP: 95.173.x.x)\n- Distance Tel Aviv → Moscow: approximately 2,760 km\n- Time elapsed: 29 minutes\n- Required speed: 2,760 km ÷ 0.48 hours = 5,750 km/h\n\nThis is physically impossible. The conclusion is one of: the account credentials were stolen and an attacker is using them from a different location; a shared account is being used by two different people simultaneously; or the user is using a VPN/proxy (the apparent location is not their real location).\n\n**VPN authentication brute force**\n\nBrute force against VPN endpoints is extremely common. Attackers use stolen username lists and either known passwords from data breaches (credential stuffing) or systematically try common passwords (password spraying).\n\nThree different credential attacks show up here, and you tell them apart by SHAPE (how the attempts are spread across accounts and passwords) not by how many source addresses are involved:\n- **Password guessing / classic brute force (T1110.001)**: many passwords against **one** account, usually fast and loud. In the logs: repeated auth_failure for the same username, high attempt count.\n- **Password spraying (T1110.003)**, **one** common password (e.g. Summer2024!) tried against **many** accounts, only once or twice each, so no single account ever reaches its lockout threshold. In the logs: many distinct usernames, very low attempt count per account.\n- **Credential stuffing (T1110.004)**, real username+password **pairs** leaked from someone else's breach, replayed against you. Attempts per account are low here too, but the giveaway is the success rate: stuffing produces actual successful logins, because some users reused that password.\n- A burst of failures followed immediately by a success. Compromise confirmed, whichever of the three it was.\n\nOne caution about source addresses, because this is exactly where the distinction usually gets mangled: spraying is often described as arriving from many distributed IPs, and it frequently does, but plenty of real sprays come from a single host, and plenty of stuffing runs are spread across a botnet to evade rate limiting. IP spread is useful supporting context, not the thing that defines which attack you are looking at. Classify on the account-and-password shape first.\n\n**Anomalous session behaviour post-authentication**\n\nOnce connected, what does the attacker do? Look for:\n- **Abnormally large bytes_out** (exfiltrating data through the VPN tunnel\n- **Connection at unusual hours**) 3:00 AM local time for a finance employee\n- **Connecting from a new country never seen before** for that user\n- **Persistent long-duration sessions**, an attacker might keep a VPN session alive for days\n- **Many rapid successive logins and logouts**. Automated probing\n\n**GlobalProtect and AnyConnect specifics**\n\nPalo Alto GlobalProtect logs appear in PAN-OS system logs and include: gateway, machine, user, public-ip, private-ip, protocol, auth-method, bytes-sent, bytes-received, duration, reason (for disconnect).\n\nCisco AnyConnect logs appear in ASA or FTD syslogs (message IDs: **113005** for AAA authentication rejected, **113004** for AAA authentication successful, and **113039** when an AnyConnect parent session starts) and include: username, group, IP address, protocol, bytes_in, bytes_out, duration, reason.\n\nBoth vendors export to SIEM via syslog, and modern SIEM platforms correlate VPN authentication events with other log sources (Office 365 sign-ins, EDR, badge access) to detect impossible travel even when an attacker uses a different authentication method on each platform.",
        checkpoint: {
          question: "Which VPN authentication pattern best fits credential stuffing rather than brute force or password spraying?",
          options: [
            "One username failing many times in a row, with a different password each try",
            "Few tries per account, a different password for each, and a few logins succeed",
            "Many usernames each tried once with the same password, and none of them succeed",
            "Failures arriving from hundreds of source IPs instead of from one single host",
          ],
          answer: 1,
          explanation:
            "Stuffing replays real leaked username+password pairs, so each account sees only a few attempts, the password differs per account, and the giveaway is that some logins succeed because users reused passwords. “One username failing many times” is classic brute force. “Same password across many usernames” is password spraying. “Hundreds of source IPs” describes how the traffic is distributed, not which attack it is: the reading warns that IP spread is supporting context, not the defining shape.",
        },
      },

      // ── Reading 3 ──
      {
        type: "reading",
        id: "vpn-r3",
        heading: "Building a VPN Monitoring Detection Strategy",
        content:
          "A good security operations centre does not just wait for VPN alerts to arrive. It builds a systematic monitoring strategy that defines what 'normal' looks like for each user and then automatically flags deviations. This approach is sometimes called **User and Entity Behaviour Analytics (UEBA)**.\n\nThink of it like a bank's fraud detection system for your debit card. The bank knows that you typically spend money in your home city, in amounts under a certain threshold, at certain types of merchants. When a transaction comes in from a foreign country at 3 AM for an unusual amount, the fraud system flags it, not because it has a specific rule that says 'this is fraud', but because it knows your baseline and this deviates significantly.\n\n**Building a VPN baseline per user**\n\nFor each VPN user, you want to establish:\n- **Typical source countries**. Alice always connects from Israel or occasionally from the US when travelling\n- **Typical connection hours**. Bob always connects between 07:00-19:00 UTC+2\n- **Typical session duration** (average 4-6 hours for knowledge workers\n- **Typical bytes transferred**) normal range for their role (developers transfer more than HR staff)\n- **Device fingerprint**. Specific certificate or device ID used\n\n**Key VPN detection rules to implement in your SIEM**\n\n1. **Impossible travel**, flag when the same account authenticates from two locations where the implied travel speed exceeds 800 km/h (allowing for some tolerance below speed of sound)\n\n2. **New country first seen**, alert when a user connects from a country they have never connected from before\n\n3. **VPN brute force**, alert on more than 5 authentication failures from the same IP targeting the same account within 10 minutes\n\n4. **Credential stuffing**, alert on more than 20 authentication failures across different accounts from the same IP within 5 minutes\n\n5. **Large data transfer post-VPN**, correlate VPN session data with file server and DLP logs; alert if a user downloads unusually large volumes after establishing a VPN connection\n\n6. **VPN success after multiple failures**. Alert when an authentication failure burst is followed by a success (probable compromise)\n\n7. **Non-working-hours connection from foreign country**. Alert when a user connects at 2 AM local time from a country other than their home country\n\n**Responding to a VPN compromise alert**\n\nWhen you suspect an account's VPN credentials have been compromised:\n\nStep 1: Immediately disable the account or terminate the suspicious VPN session\nStep 2: Force a password reset\nStep 3: Review what the attacker accessed during the session. What internal systems, files, and services were reached from the VPN-assigned internal IP\nStep 4: Check other authentication systems (Office 365, cloud console) for signs of the same stolen credentials being used\nStep 5: Check if the legitimate user's device shows any signs of info-stealing malware that may have exfiltrated the VPN credentials\nStep 6: Review the VPN gateway logs for other sessions from the same source IP, the attacker may have targeted other accounts from the same infrastructure\n\n**The impossible travel false positive problem**\n\nNot every impossible travel alert represents a compromise. Common benign explanations:\n- **Shared accounts** (service accounts, departmental logins) used by different people in different locations (not a good security practice, but it happens\n- **Legitimate use of personal VPN**) the user's traffic appears to come from a country where their VPN provider has servers, not their actual location\n- **IPv6 geolocation errors**. Geolocation databases are imperfect, especially for IPv6 addresses\n- **Rapid IP reassignment**. ISPs sometimes reassign IP blocks, causing geolocation to show a brief impossible jump\n\nWhen investigating impossible travel, always contact the user (through a verified channel, not email, the email might be compromised) to ask: \"Are you currently travelling? Did you log into the VPN from [Location]?\"",
      },

      // ── Question 1 ──
      {
        type: "question",
        id: "vpn-q1",
        question:
          "A user account shows the following VPN authentication events: 14:22 UTC, successful login from São Paulo, Brazil (IP: 177.84.x.x); 14:55 UTC, successful login from Tokyo, Japan (IP: 203.104.x.x). The distance between São Paulo and Tokyo is approximately 18,000 km. What is the correct assessment?",
        options: [
          "Benign: split tunnelling can make one device appear in different countries",
          "Impossible travel: about 32,700 km/h is needed, so suspect stolen credentials",
          "Benign: both logins succeeded, so the user completed authentication each time",
          "Benign: a personal VPN explains the jump, so no follow-up with the user is needed",
        ],
        answer: 1,
        explanation:
          "18,000 km ÷ (33/60) h ≈ 32,700 km/h, far beyond any aircraft, so this is impossible travel and the credentials should be treated as likely compromised until the user confirms otherwise. Split tunnelling decides which traffic uses the tunnel; it does not change the public IP the gateway records for the login. A successful login only proves someone had working credentials, not that it was the owner. A personal VPN is a real false-positive cause, but the reading's rule is to verify it with the user through a trusted channel, not to assume it and close the alert.",
        xp: 20,
      },

      // ── Question 2 ──
      {
        type: "question",
        id: "vpn-q2",
        question:
          "Your SIEM detects 47 VPN authentication failures from IP 91.195.240.33 targeting 47 different usernames over a 3-minute window, each attempt using the password 'Welcome1!'. What attack technique does this describe?",
        options: [
          "Brute force: many passwords tried against one account until one works",
          "Password spraying: one common password tried once across many accounts",
          "Credential stuffing: leaked username and password pairs replayed in bulk",
          "Confirmed compromise: a failure burst that one of the accounts did not survive",
        ],
        answer: 1,
        explanation:
          "One password ('Welcome1!') against 47 accounts, once each, is the spraying shape: no account gets enough failures to lock out. Brute force would show many failures against one username. Credential stuffing uses a different, leaked password for each account, not one shared password. And nothing here is a success. Compromise is confirmed only when a failure burst is followed by a successful login, which this log does not show.",
        xp: 20,
      },

      // ── Question 3 ──
      {
        type: "question",
        id: "vpn-q3",
        question:
          "A remote employee on a split-tunnel VPN session downloaded a malicious file from a public website. Where are you most likely to find evidence of that download?",
        options: [
          "In the corporate web proxy logs, because the user was connected to the VPN",
          "In endpoint telemetry (EDR) on the laptop; the proxy and IDS never saw it",
          "In the VPN gateway logs, which record each URL visited during a session",
          "In the HQ firewall logs, because the VPN client sends all traffic through HQ",
        ],
        answer: 1,
        explanation:
          "With split tunnelling, only corporate-bound traffic uses the tunnel; a download from a public site goes straight out of the home connection, so the corporate proxy, IDS/IPS and firewall never see it. What remains is the endpoint itself: EDR file, process and network events on the laptop. Being connected to the VPN does not route personal traffic through the proxy, VPN gateway logs record sessions and byte counts rather than URLs, and sending everything through HQ describes a full tunnel, not a split one.",
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
              "Impossible travel tells you one of the two sessions is probably not david.miller. Which session should you treat as the suspect one, and why?",
            options: [
              "Session 1 (Moscow): it authenticated with password only; Tel Aviv completed MFA",
              "Session 2 (Tel Aviv): it began later, so it is the login that intruded on the user",
              "Session 2 (Tel Aviv): it lasted 120 minutes, and long sessions point to an attacker",
              "Neither: both logins succeeded, so both must have been performed by the account owner",
            ],
            answer: 0,
            explanation:
              "Session 1 used password_only while Session 2 completed a TOTP code. An attacker holding a stolen password but not the second factor would produce exactly Session 1, and the Tel Aviv session fits the EMEA gateway the user normally uses. Which login came second says nothing about which is the intruder: the real user can log in after the attacker. Two hours is an ordinary working session; the reading's warning is about sessions held open for days. A successful login proves only that someone had working credentials. (Treat the byte counters with care: whether bytes_out means data sent to or from the client depends on the vendor's convention, so confirm that before calling it exfiltration.)",
            xp: 25,
          },
          {
            question:
              "After disabling the account, the response steps say to review the gateway for other accounts targeted from the same attacker infrastructure. Which address do you search for?",
            options: [
              "5.200.35.117",
              "91.108.4.22",
              "10.200.45.88",
              "10.200.45.91",
            ],
            answer: 1,
            explanation:
              "Other targeted accounts would show up as logins from the attacker's public client IP, and the suspect Moscow session came from 91.108.4.22. 5.200.35.117 is the client IP of the Tel Aviv session, which belongs to the real user. 10.200.45.88 and 10.200.45.91 are internal addresses the gateway assigned to the two sessions: they are what you pivot on to see what each session reached inside the network, not where the attacker connects from.",
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
          description: "VPN login from Thailand: user normally connects from London, no travel request filed",
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
        explanation: "Escalation to Tier 2 is the correct action. The evidence is ambiguous: MFA was successfully completed (which means the attacker either has the MFA token, or this IS the real user). Thailand is a common holiday destination. The user has a clean 4-year history. But no travel request was filed and this is a Monday morning login. Possibly the first workday of a vacation. Without contacting the user or their manager to confirm travel, you cannot make a TP/FP decision. A Tier-2 analyst should call the user directly, check badge access to the London office, and review what resources were accessed during the VPN session.",
        fp_trap: "MFA was successfully completed: many analysts close this as false positive because 'if the user approved MFA, it must be them'. But the log shows a TOTP code, and a TOTP code can still be stolen: a real-time phishing page can relay the six digits as the user types them, and a stolen TOTP seed generates valid codes on the attacker's device. More importantly, the right process is to verify, not assume. The absence of a travel request is a meaningful gap that requires confirmation.",
        xp: 30,
      },

      // ── Flag ──
      {
        type: "flag",
        id: "vpn-flag1",
        prompt:
          "Back in the 'Investigating a Suspicious VPN Login Sequence' log (david.miller@contoso.com, not the later j.petrov scenario): to learn which internal systems the attacker reached during the suspect session, you will search internal logs for that session's address inside the network. What is that address?",
        answer: "10.200.45.88",
        hint: "Each session has two addresses: the public one it connected from, and one the gateway handed out for use inside the network. You also need to pick the right session.",
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
      "Master the art of reading firewall logs. Identify port scans, C2 beacon patterns, and blocked outbound threats across FortiGate, Palo Alto, and Check Point NGFW telemetry.",
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
          "Imagine the firewall as the security guard at the entrance to a very large office building. Every person (packet) that wants to enter or leave must pass the guard's desk. The guard checks ID (source IP), checks the destination (destination IP and port), and compares them against a rulebook. If the rulebook says 'allow', the person is let through; if it says 'deny' or 'drop', they are turned away or quietly ignored. The guard writes down every single interaction in a logbook.\n\nFirewall logs are that logbook. And for a SOC analyst, it is one of the richest sources of network visibility you have.\n\n**Core firewall log fields**\n\nEvery firewall, regardless of vendor, captures some version of these fields:\n\n- **srcip (source IP)**, where the traffic originates. For outbound traffic, this is the internal machine's IP. For inbound, this is the internet IP attacking you.\n- **dstip (destination IP)**, where the traffic is going. For outbound, this is the internet server being contacted. For inbound, this is your server being targeted.\n- **srcport**: the source port (usually ephemeral, 1024-65535 for outbound connections)\n- **dstport / service**, the destination port. Port 80 = HTTP, 443 = HTTPS, 22 = SSH, 3389 = RDP, 3306 = MySQL. The port tells you what service or protocol is involved.\n- **proto / protocol** (TCP, UDP, or ICMP\n- **action**) allow, deny, drop, reject, reset. **Allow** = traffic was permitted. **Drop** = traffic was silently discarded (no response, useful against scanners). **Reject / Reset** = traffic was stopped and the sender was told so (a TCP reset or an ICMP unreachable). **Deny/Block** means different things per vendor: FortiGate's 'deny' drops silently by default, while Check Point uses 'Drop' for silent and 'Reject' for answered, always check which one your vendor means.\n- **bytes sent / bytes received**, payload size. Large bytes_sent in a normally-small-traffic session can indicate data exfiltration. Consistent tiny payloads at regular intervals can indicate C2 beaconing.\n- **duration** (how long the session lasted\n- **rule_name / rule_uid**) which specific firewall rule was triggered. Rule hit counts in dashboards show which rules are most active.\n- **policy_name**: the policy set that the rule belongs to\n\n**Stateful vs stateless inspection**\n\nA **stateless** firewall checks each packet individually against rules. It is fast but can be fooled by packet fragmentation and does not understand context.\n\nA **stateful** firewall tracks the **state** of network connections. It knows whether a packet is part of an established connection or a new one. For example: if your internal machine initiates a TCP connection to a web server, the firewall allows the response packets back in automatically because it knows those are part of an established session. This prevents attacks that try to inject malicious traffic disguised as return traffic.\n\nAll modern enterprise firewalls (FortiGate, Palo Alto, Check Point, Cisco FTD) are stateful. In fact, they are Next-Generation Firewalls (NGFW) that also do deep packet inspection, SSL decryption, application identification, and IPS/IDS integration.\n\n**Reading FortiGate logs**\n\nFortiGate uses a key-value format in syslogs. Important fields:\n- `logid`a numeric log identifier (e.g., 0000000013 = traffic forward)\n- `type=traffic` and `subtype=forward`standard traffic log\n- `action`accept, deny, drop, close, server-rst\n- `vd`virtual domain (VDOM) the traffic passed through\n- `sentbyte` / `rcvdbyte`bytes sent by source / received from destination\n- `srccountry` / `dstcountry`geographic lookup of source/destination IPs\n- `policyid`which policy number matched (maps to rule_name in the policy table)\n\n**Reading Palo Alto PAN-OS logs**\n\nPAN-OS uses CSV or syslog format with a defined field order:\n- `TRAFFIC` log type\n- `rule`the rule name that matched\n- `from`/`to`security zones (e.g., Trust → Untrust)\n- `app`application identified by App-ID (e.g., ssl, web-browsing, bittorent)\n- `bytes_sent`/`bytes_received`\n- `session_end_reason`tcp-fin, aged-out, policy-deny, threat\n\n**Reading Check Point logs**\n\nCheck Point uses SmartConsole log fields:\n- `rule_name`the matched rule\n- `inzone`/`outzone`traffic direction\n- `ProductFamily`which blade generated the log (Firewall, VPN, IPS, Application Control)\n- `Action`Accept, Drop, Reject, Encrypt",
        checkpoint: {
          question: "Two firewalls block the same probe to a closed port. One logs 'reject' and the scanner receives a TCP reset; the other logs 'drop' and the scanner receives nothing. What is the practical difference?",
          options: [
            "None: reject and drop are two vendor names for the same silent discard",
            "Drop gives no reply, so the scanner cannot even confirm the host exists",
            "Reject is used for inbound traffic, while drop is used for outbound",
            "Drop also bans the source IP, while reject blocks just that one packet",
          ],
          answer: 1,
          explanation:
            "A reject answers the sender (TCP reset or ICMP unreachable), which at least confirms something is there; a drop sends nothing, so the scanner just times out. They are not the same thing: the reset in the stem proves one firewall answered. Neither action is tied to traffic direction, and neither bans an address: a drop applies to the packets the rule matched, nothing more.",
        },
      },

      // ── Reading 2 ──
      {
        type: "reading",
        id: "fw-r2",
        heading: "Detecting Threats in Firewall Logs: Scans, Beacons, and Inbound Attacks",
        content:
          "A skilled attacker uses the internet the same way you do, making network connections to servers. The difference is what they're connecting to, what port they're using, and what data they send. Your firewall sees all of it. The challenge for the SOC analyst is finding the malicious needle in a haystack of millions of legitimate connections.\n\n**Port scanning signatures**\n\nBefore attacking a target, adversaries typically run reconnaissance. They scan the target's IP address on many ports to find which services are running. A port scan looks like this in firewall logs:\n\n- Many connection attempts from the **same source IP** to the **same destination IP** but on **many different destination ports** in a very short time\n- Most attempts result in **deny/drop/reject** actions (closed ports)\n- Traffic is typically **TCP SYN** packets (small payload, no full handshake)\n- Could be sequential (port 1, 2, 3... or 22, 23, 80, 443...) or random order\n\nA SIEM rule might trigger on: \"more than 50 distinct dstport values from the same srcip to the same dstip within 60 seconds\".\n\nImportant: internal-to-internal scanning (a machine inside your network scanning other internal machines) is often more alarming than external scanning, as it may indicate a compromised internal host doing lateral movement reconnaissance.\n\n**C2 beacon patterns, the ticking clock**\n\nOnce malware infects a machine, it calls home to the Command and Control (C2) server to receive instructions and report results. This \"calling home\" is called beaconing. Beacons have distinctive characteristics in firewall logs:\n\n- **Regularity**. Beacons happen at consistent time intervals. The malware is programmed to check in every 30 seconds, or every 5 minutes, or every hour. In firewall logs, you see connections to the same external IP at very regular intervals.\n- **Small, consistent payload**: the initial beacon is usually small (just a \"hello, here's my ID, any instructions?\"). Bytes values are consistently tiny unless data is being exfiltrated.\n- **Unusual ports**. C2 malware often uses port 443 (HTTPS) or port 80 (HTTP) to blend in with legitimate traffic. But some malware uses high ephemeral ports like 4444, 8080, or 8888.\n- **Long-lived pattern**: the connections may continue for days, weeks, or months\n- **Non-browser User-Agent** (if HTTP/S and you have proxy logs), the HTTP request doesn't look like a normal browser\n\nNext-generation firewalls with App-ID can sometimes detect that a connection using port 443 is not actually TLS/HTTPS. It's some other protocol tunnelled inside.\n\n**Inbound threats to watch for**\n\n- **RDP brute force**: many authentication failures from external IPs to your RDP servers (port 3389). If an attacker gets in via RDP, they have full graphical access to the desktop.\n- **SSH brute force**: similar pattern on port 22 from external IPs\n- **Web application attacks**: your WAF and firewall may both see large volumes of HTTP requests from the same IP, many resulting in 4xx/5xx error responses, probing for SQL injection or vulnerabilities\n- **SMB exploitation**: connections from external IPs trying port 445 (SMB), a firewall that allows inbound port 445 from the internet has a catastrophic misconfiguration (EternalBlue/WannaCry exploited this)\n\n**Distinguishing outbound vs inbound threats**\n\nA critical mental model: the direction of the threat matters.\n\n**Inbound**. External IP trying to reach your internal systems. You are the target. Your firewall's job is to block this.\n\n**Outbound**. Your internal IP connecting to an external system. Either a legitimate user/service, or a compromised internal host (malware) calling out to C2. Your firewall may allow port 80/443 outbound by default. This is the blind spot C2 malware exploits.\n\n**Lateral movement**: an internal IP scanning or connecting to other internal IPs. Your internal firewall segments (microsegmentation) should catch this, but many organisations only have a perimeter firewall.",
        checkpoint: {
          question: "Which pattern from a single internal host is most consistent with C2 beaconing?",
          options: [
            "One 3 GB upload to a foreign IP during a single ten-minute session",
            "A connection to one external IP every 60 s, each a few hundred bytes",
            "Attempts to dozens of different ports on one internal server in a minute",
            "Hundreds of short port-443 connections to many different IPs while browsing",
          ],
          answer: 1,
          explanation:
            "Beacons check in at a regular interval with small, consistent payloads to the same destination. A single 3 GB upload is a possible exfiltration, not a check-in pattern. Many ports on one server in a minute is a port scan. Many short connections to many different IPs is what ordinary web browsing looks like: the opposite of one fixed destination.",
        },
      },

      // ── Reading 3 ──
      {
        type: "reading",
        id: "fw-r3",
        heading: "Firewall Investigation Methodology and Rule Analysis",
        content:
          "A bank vault has a sophisticated alarm system. Every time someone touches the vault door, it logs the event. But the vault door is touched hundreds of times a day legitimately. The security guard's job is not to review every single log line: that is impossible. Their job is to find the patterns that indicate someone is testing the lock, probing for weaknesses, or has managed to open it when they shouldn't have.\n\nFirewall analysis is the same discipline. In a medium-sized enterprise, firewalls generate millions of log events per day. The SOC analyst needs efficient methods to find signal in all that noise.\n\n**Starting an investigation: what triggered the alert?**\n\nMost firewall investigations start with a SIEM alert, not raw log browsing. The alert tells you something anomalous was detected. Common starting points:\n- Threat intelligence match: a connection to/from a known malicious IP or domain\n- Volume anomaly: unusual spike in bytes transferred from a normally quiet machine\n- Policy violation: traffic on a port that should never appear (e.g., internal machine connecting to external on port 4444)\n- IDS/IPS signature: the NGFW's built-in intrusion detection fired on content inside a packet\n\n**Pivot: from alert to investigation**\n\nOnce you have a suspicious source IP (srcip), you pivot:\n\n1. **What else has this IP done?** Search all firewall logs for this srcip over the last 24 hours. What other destinations did it contact? What ports? Were any blocked?\n\n2. **What machine is this?** Look up the srcip in your DHCP logs or asset inventory to find the hostname and who owns the machine.\n\n3. **Has this destination IP (dstip) been contacted by others?** If one machine contacts a suspicious external IP, check whether other machines also contacted the same IP. If 20 machines all connect to 185.220.101.47:443 at regular intervals, you likely have a widespread malware infection.\n\n4. **What does threat intelligence say about the external IP?** Check VirusTotal, AbuseIPDB, and your SIEM's built-in threat feeds. If it is categorised as \"Malware C2\", the investigation becomes a confirmed incident.\n\n5. **What application/service?** If you have App-ID or proxy integration, determine the actual application. Is port 443 traffic actually HTTPS (benign-looking) or is it a known C2 framework tool like Cobalt Strike or Metasploit HTTPS listener?\n\n**Rule hit analysis**\n\nFirewall policies contain dozens or hundreds of rules. Rules are evaluated top-to-bottom, and the first matching rule wins. Monitoring rule hit counts reveals:\n- **High-hit deny rules**: which traffic is being blocked most often? High hits on an inbound-deny rule from diverse external IPs may indicate scanning activity against your perimeter.\n- **Permissive rules with unexpected traffic**: a rule that was created for a specific application but is now seeing traffic on unexpected ports. Someone may be using it as a bypass.\n- **Shadow rules**: rules that never match (zero hits) may be duplicates or outdated. Rules that used to have hits but suddenly stopped may indicate a service has moved.\n\n**Containment actions via firewall**\n\nWhen you confirm malicious activity, your firewall is a key containment tool:\n- **Block specific external IP**: add a deny rule for the malicious destination IP (C2 server). This may interrupt active malware but does not remove it from the endpoint.\n- **Block source IP**: if you identify an attacking external IP (scanning, brute force), block it inbound.\n- **Quarantine segment**: if a machine is confirmed compromised, work with network operations to move it to an isolated VLAN that has no access to the internal network (only access to the SOC's analysis systems).\n- **Emergency rule**: add a temporary \"log and alert\" rule above existing rules to capture all traffic from a suspicious internal IP in high resolution while you investigate.",
      },

      // ── Question 1 ──
      {
        type: "question",
        id: "fw-q1",
        question:
          "Your firewall logs show the following over a 90-second window from source IP 10.30.0.45: connection attempts to 10.30.0.1 on ports 22, 80, 135, 139, 443, 445, 1433, 3389, 3306, 5432, 8080, 8443. All denied by the firewall. What does this pattern most likely indicate?",
        options: [
          "An IT user checking several web services from a workstation, routine work",
          "An internal port scan from 10.30.0.45, possibly a compromised host's recon",
          "A firewall misconfiguration wrongly denying legitimate application traffic",
          "Normal Windows domain traffic (SMB, RPC and AD) between client and server",
        ],
        answer: 1,
        explanation:
          "One internal source, one destination, 12 unrelated service ports (SSH, HTTP, RPC, NetBIOS, HTTPS, SMB, MSSQL, RDP, MySQL, PostgreSQL, HTTP-Alt, HTTPS-Alt) in 90 seconds, all denied: that is the port-scan shape, and internal-to-internal scanning is a lateral-movement warning sign (unless it is an authorised IT scanner, which change management should show). Someone checking web services would touch a few web ports, not databases, RDP and SMB together. A misconfiguration denies the ports a real application uses, repeatedly, not a sweep of one-off attempts across every service. Windows domain traffic would use a handful of ports (135, 139, 445, 88, 389) and would mostly succeed, not be denied across MySQL and PostgreSQL too.",
        xp: 20,
      },

      // ── Question 2 ──
      {
        type: "question",
        id: "fw-q2",
        question:
          "Firewall logs show that internal host 10.50.0.122 makes an outbound connection to 45.83.91.202:443 every 300 seconds (exactly 5 minutes) for the past 6 hours. Each connection transfers approximately 450 bytes out and 200 bytes in, then closes. What does this pattern indicate?",
        options: [
          "Normal web browsing: it is encrypted HTTPS on port 443 like most traffic",
          "Data exfiltration: the connections have continued for six hours straight",
          "Beaconing: fixed five-minute check-ins with tiny payloads to one external IP",
          "An inbound probe: 45.83.91.202 keeps reaching the host every five minutes",
        ],
        answer: 2,
        explanation:
          "A fixed 300-second interval, ~450/200-byte payloads and one external destination over hours is the beacon shape, so treat it as possible C2 and identify the process behind it (some legitimate agents also poll on a timer, which is why you confirm before you conclude). Port 443 does not make traffic browsing: real browsing has irregular timing, varied sizes and many destinations. Six hours of 650-byte check-ins moves almost no data, so this is not exfiltration. And the internal host opens each connection outbound; the external IP is not reaching in.",
        xp: 20,
      },

      // ── Question 3 ──
      {
        type: "question",
        id: "fw-q3",
        question:
          "In a FortiGate firewall log, you see: action=deny, srcip=10.10.22.87, dstip=185.220.101.47, dstport=443, proto=6 (TCP), sentbyte=0, rcvdbyte=0, duration=0. What do the zero byte counters tell you about this specific event?",
        options: [
          "The session completed first; FortiGate does not count bytes on denied sessions",
          "The attempt was stopped before any data moved, so no session ever formed",
          "The syslog forwarder truncated the byte fields, so the real size is unknown",
          "The server answered with an empty response, so both counters stayed at zero",
        ],
        answer: 1,
        explanation:
          "Zero bytes in both directions with duration 0 means the policy matched the first packet (source, destination, port, protocol) and the TCP handshake never completed: no C2 data moved for this attempt. A completed session would show bytes, since counters are recorded for the traffic that actually passed. Truncation would leave the fields missing or malformed, not neatly zero in both directions alongside a zero duration. An “empty response” still needs a completed handshake, which carries bytes. The host 10.10.22.87 still needs investigating: the block stopped the connection, not whatever tried to make it.",
        xp: 20,
      },

      // ── Log Analysis ──
      {
        type: "log_analysis",
        id: "fw-la1",
        heading: "Analysing a Blocked Outbound C2 Connection",
        context:
          "Your SIEM has raised a 'Threat Intel Match: Known C2 Infrastructure' alert. A FortiGate firewall has blocked an outbound connection from an internal workstation to a destination IP that appears on multiple threat intelligence feeds as a known Cobalt Strike C2 server. The log event below was generated by the FortiGate and forwarded to your SIEM. Analyse the log to understand what happened and identify the key indicators.",
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
            "data.action": "deny",
            "data.logdesc": "Connection denied by policy",
            "data.srcip": "10.10.22.87",
            "data.srcport": 54291,
            "data.srcmac": "00:1A:2B:3C:4D:5E",
            "data.srcintf": "internal-vlan22",
            "data.dstip": "185.220.101.47",
            "data.dstport": 443,
            "data.dstintf": "wan1",
            "data.proto": 6,
            "data.policyid": 41,
            "data.policyname": "Block_Outbound_ThreatIntel_C2",
            "data.sentbyte": 0,
            "data.rcvdbyte": 0,
            "data.duration": 0,
            "data.srccountry": "Reserved",
            "data.dstcountry": "Netherlands",
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
              "Yes: the deny cut the attacker off, so the alert can be closed as contained",
              "No: whatever made the call is likely still running; investigate and isolate the host",
              "No: add the IP to the proxy blocklist as well, then watch for further attempts",
              "Yes: a denied first call means the payload failed and will not try again",
            ],
            answer: 1,
            explanation:
              "A firewall deny stops one network connection, not the code that made it. Whatever on 10.10.22.87 tried to reach a known Cobalt Strike server is most likely still installed and will retry, may already have persistence, may switch to a C2 address that is not on any feed, and may have done other things before this alert. So the host must be isolated and investigated with EDR. Closing as “contained” and “the payload failed and will not try again” both mistake a blocked connection for a removed infection. Adding the IP to the proxy blocklist is a reasonable extra control, but on its own it leaves an infected endpoint in service.",
            xp: 25,
          },
          {
            question:
              "Following the pivot steps, which search best tells you whether this is one infected machine or a wider infection?",
            options: [
              "Search all firewall logs for other traffic using source port 54291",
              "Search all firewall logs for other internal hosts contacting 185.220.101.47",
              "Search all firewall logs for every outbound connection to port 443",
              "Search DHCP logs for 185.220.101.47 to find the employee who owns it",
            ],
            answer: 1,
            explanation:
              "If other internal hosts also contacted the C2 address 185.220.101.47, the infection is wider than one workstation. That is the reading's “has this destination been contacted by others?” pivot. Source port 54291 is an ephemeral port chosen for this one connection; other traffic using it is coincidence, not related activity. Every outbound connection to 443 is most of your web traffic and tells you nothing. DHCP maps your own internal addresses to machines; 185.220.101.47 is an external server, so it will never be in your DHCP logs.",
            xp: 25,
          },
        ],
      },

      // ── Analyst Choice ──
      {
        type: "analyst_choice" as const,
        id: "fw-ac1",
        heading: "Verdict: C2 Beacon or Legitimate Software Update?",
        scenario: "2:07 AM. A FortiGate alert shows workstation WKSTN-SALES-032 making outbound connections to 91.195.240.117 on port 443. Searching the last six hours you find the first one at 20:03: two hours after m.kim@contoso.com logged off, and roughly one every 4 minutes since, each lasting 2-3 seconds. The destination does not belong to any vendor or service in the asset's software inventory, and it appears on no reputation blocklist. What is your verdict?",
        event: {
          id: "evt-fw-ac-001",
          ts: "2026-06-25T02:07:12.000Z",
          source: "firewall" as const,
          vendor: "FortiGate",
          event_type: "net_connection" as const,
          severity: "high" as const,
          hostname: "WKSTN-SALES-032",
          user_email: "m.kim@contoso.com",
          description: "Repeated outbound HTTPS connections from a sales workstation outside business hours",
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
            "threat_intel.ip": "91.195.240.117",
            "threat_intel.verdict": "not_listed",
            "threat_intel.asn": "AS49453 Global Layer B.V.",
            "rule.name": "FortiGate_Outbound_Repeated_Connection",
            "rule.level": 11,
          },
        },
        correct_verdict: "true_positive",
        explanation: "This is a true positive C2 beacon. Timers alone do not prove malice (EDR, MDM, chat and sync clients also poll every few minutes around the clock) so the verdict rests on the combination: (1) the behaviour is new, starting at 20:03 after the user had left, rather than a long-standing pattern; (2) a steady ~4-minute interval with tiny payloads (812 bytes sent, 312 received) is a check-in, not a user doing work; (3) the destination sits on a hosting provider's network (AS49453 Global Layer B.V.) and matches no software installed on the machine, so no legitimate agent explains it; (4) 'not_listed' is not reassuring, because fresh C2 infrastructure is often not on any list yet. Next step: identify the process making the connections on WKSTN-SALES-032 with EDR.",
        fp_trap: "The destination IP has no reputation hits on VirusTotal or other blocklist services. Many analysts close beacon alerts when the IP is 'clean'. But C2 infrastructure is constantly rotated precisely to stay off blocklists. The combination of precise interval, tiny payload size, and after-hours timing is a stronger signal than any reputation database.",
        xp: 30,
      },

      // ── Flag ──
      {
        type: "flag",
        id: "fw-flag1",
        prompt:
          "Go back to the 'Analysing a Blocked Outbound C2 Connection' log (the FortiGate event with data.action = deny, not the later verdict scenario). You have decided to isolate the machine that tried to reach the C2 server. What is that machine's hostname?",
        answer: "WKSTN-ACCT-087",
        hint: "Start from the address that opened the connection, then find what the SIEM's enrichment says that address is. The firewall's own name is not the answer.",
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
      "Uncover the hidden intelligence in DNS logs. Detect DGA domains, DNS exfiltration tunnels, fast flux C2, typosquatting, and analyse Sysmon Event ID 22 to identify malicious processes calling home.",
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
          "Imagine a phone book where every time someone looks up a number, the operator writes down: who made the call, what name they looked up, what number they found, and what time it was. Now imagine that every single device on your network (every laptop, server, printer, phone, and smart thermostat) has to make a call to this operator before connecting to anything on the internet.\n\nThat is DNS (Domain Name System), and it is possibly the most underutilised source of threat intelligence in many SOC environments. DNS translates human-readable names (www.google.com) into IP addresses that computers understand (142.250.185.46). Before your browser can load any website, your computer must first ask a DNS resolver \"what is the IP address for this domain?\" Every single network process that reaches out to the internet generates at least one DNS query.\n\n**Why DNS is investigative gold**\n\nMalware, when it runs on a machine, almost always needs to communicate with the attacker's infrastructure. To do that, it needs to resolve a domain name to an IP address. This DNS query happens even if the subsequent connection is encrypted. Even if the firewall blocks the final connection, the DNS query may still be logged.\n\nThis means DNS logs are a window into the intent of every process on your network, before encryption and before the actual connection.\n\n**Core DNS log fields**\n\n- **Query Name (QNAME)**: the domain being looked up. This is the most important field. What domain is being queried?\n- **Query Type (QTYPE)**, which kind of record is being asked for. The common ones every analyst should recognise: **A** (maps a name to an IPv4 address), **AAAA** (maps a name to an IPv6 address), **CNAME** (an alias pointing one name at another name), **MX** (the mail server responsible for a domain), **NS** (which name servers are authoritative for a domain), **PTR** (a reverse lookup. Turns an IP address back into a hostname, which analysts use constantly when pivoting from a suspicious IP to identify what it claims to be), **SOA** (Start of Authority: administrative metadata for a DNS zone), and **TXT** (free-form text records, e.g. the SPF and DKIM records used for email authentication). Attackers abuse **TXT** and **NULL** records to smuggle data out via DNS tunnelling, while sudden **NS** or **PTR** anomalies can betray DNS hijacking or fast-flux C2 infrastructure.\n- **Response (RDATA)** (what IP address (or other record) was returned\n- **Response Code (RCODE)**) NOERROR (found), NXDOMAIN (domain does not exist), SERVFAIL (error), REFUSED (server refused query)\n- **Client IP** (which internal machine made the query\n- **Timestamp**) when the query was made\n- **DNS Resolver** (which DNS server answered the query (your internal resolver vs a public one) direct queries to 8.8.8.8 bypassing your corporate resolver is a red flag)\n\n**Sysmon Event ID 22. DNS query logging on Windows**\n\nMicrosoft Sysinternals Sysmon, when deployed on Windows endpoints, generates **Event ID 22** for every DNS query made by every process. This is incredibly powerful because it links:\n- **The DNS query** (what domain was queried)\n- **The process making the query** (which program on the computer initiated it)\n- **The result** (what IP was returned, or NXDOMAIN)\n\nThis answers the question \"which process is calling home to this domain?\", something network-level DNS logs cannot answer (they show the machine's IP, not the specific process). Sysmon Event 22 key fields:\n- `winlog.event_data.Image`full path to the executable making the DNS query (e.g., C:\\Windows\\System32\\svchost.exe or C:\\Users\\alice\\AppData\\Roaming\\Update.exe)\n- `winlog.event_data.QueryName`the domain being queried\n- `winlog.event_data.QueryResults`the IP returned, or \"\" for NXDOMAIN\n- `winlog.event_data.ProcessId`process ID\n- `event.code` = \"22\": the Sysmon event ID",
        checkpoint: {
          question: "Your corporate resolver logged a query from 10.20.30.44 for a suspicious domain. Which question can Sysmon Event ID 22 on that host answer that the resolver log cannot?",
          options: [
            "Which IP address the suspicious domain resolved to",
            "Which program on the host made the DNS query",
            "Which internal machine sent the query to the resolver",
            "Which DNS server answered the query for the host",
          ],
          answer: 1,
          explanation:
            "The resolver sees queries arriving from a machine's IP, so it cannot tell which process asked. Sysmon Event 22 runs on the endpoint and records the Image: the executable that made the query. The resolved IP (RDATA), the client IP and the answering resolver are all fields the network-level DNS log already has.",
        },
      },

      // ── Reading 2 ──
      {
        type: "reading",
        id: "dns-r2",
        heading: "DNS Attack Techniques: DGA, Tunnelling, Fast Flux, and Typosquatting",
        content:
          "A city has thousands of streets. If a criminal uses a specific safe house, the police can watch that address. But what if the criminal has a way to generate a new safe house address every day from a secret algorithm? The police would never be able to pre-block all possible addresses. This is exactly what Domain Generation Algorithms do for malware.\n\n**Domain Generation Algorithms (DGA)**\n\nDGA is a technique used by sophisticated malware to generate hundreds or thousands of random-looking domain names algorithmically. The malware uses the current date and a secret seed value to calculate which domain names to try. Only the attacker knows the same algorithm and registers the \"winning\" domain for that day. All the other generated domains are unregistered and will return NXDOMAIN.\n\nDGA domains look like this:\n- xk3m9qa7vb2cn4wp.com\n- 4t8jhd2msq0vbne9.net\n- r7p1a3x5m2bk0nwq.org\n\nCharacteristics of DGA traffic in DNS logs:\n- **High NXDOMAIN volume**: the infected machine queries many non-existent domains (all the wrong DGA outputs for the day) before finding the one that resolves. An NXDOMAIN storm (many failed DNS queries in quick succession) is a classic DGA indicator.\n- **Algorithmically random-looking domains**: high entropy names with unusual letter distributions\n- **Short TTL**: attacker registers domains with very short time-to-live values so the C2 IP can change rapidly\n- **All queries from the same process**: Sysmon Event 22 will show the malware process making all these queries\n\n**DNS Tunnelling / DNS Exfiltration**\n\nDNS is almost never blocked by firewalls. Every network needs DNS to function. Clever attackers exploit this by encoding data inside DNS queries themselves. Instead of making a normal query, the malware encodes stolen data as subdomains:\n\n`V2luZG93c1Bhc3N3b3Jk.attacker-c2.com` (Base64 encoded stolen data as a subdomain)\n\nThe attacker's DNS server receives these queries, decodes the subdomain, and reassembles the stolen data. This works even when all outbound TCP connections are blocked. It only needs UDP port 53 (DNS).\n\nDNS tunnelling signatures:\n- **Unusually long subdomain labels**. Legitimate domains rarely have subdomains longer than 20-30 characters. Exfiltration subdomains may be 50-100+ characters.\n- **High query volume to same root domain**. Many queries all going to randomstring1.attacker.com, randomstring2.attacker.com, etc.\n- **High entropy subdomains**. Base64/hex encoded data looks random with very high character entropy\n- **Unusual query types**. TXT and NULL record queries are used in some DNS tunnelling tools (iodine, dnscat2)\n\n**Fast Flux**\n\nFast flux is a technique where the IP address behind a malicious domain changes extremely rapidly, sometimes every few minutes. Legitimate websites might update their DNS records a few times a year. A fast flux domain might change A records every 60-300 seconds and use dozens or hundreds of different IP addresses (often botnet machines acting as proxies).\n\nFast flux makes it very hard to block C2 by IP address, by the time you add a block rule, the IP has already changed. Indicators:\n- Very low TTL values (60 seconds or less) in DNS responses\n- Many different IPs returned for the same domain over time\n- IPs are distributed across many countries and different ISPs\n- No stable hosting relationship for the domain\n\n**Typosquatting**\n\nTyposquatting is registering domain names that look almost identical to legitimate trusted domains, relying on users mistyping or not noticing small differences:\n- micros0ft.com (zero instead of letter o)\n- paypa1.com (number 1 instead of letter l)\n- amazon-support.com (hyphenated with generic keyword)\n- gooogle.com (extra letter)\n- arnazon.com (rn looks like m at small font sizes)\n\nIn phishing campaigns, users receive links to these typosquatted domains and believe they are visiting the real site. In SOC investigations, DNS logs showing queries to typosquatted versions of your own company domain or trusted partners are a sign of phishing infrastructure targeting your users.\n\n**DNS Sinkholes**\n\nA DNS sinkhole is a security control where known malicious domains are redirected to a safe IP address (often 0.0.0.0 or a security team-controlled server) instead of returning the real malicious IP. When your DNS resolver has a sinkhole list (often from threat intelligence feeds), any malware trying to contact a known C2 domain gets redirected to the sinkhole IP: the connection fails harmlessly. More importantly, the sinkhole logs which internal machines queried the bad domain, creating a list of potentially infected hosts for the SOC to investigate.",
        checkpoint: {
          question: "Which DNS pattern from one host fits a DGA infection rather than DNS tunnelling, fast flux or typosquatting?",
          options: [
            "Many queries carrying long encoded subdomains under one registered domain",
            "Bursts of NXDOMAIN for many random-looking domains until one finally resolves",
            "One domain whose A record changes every minute to IPs in many countries",
            "Lookups of a domain that is one letter off from your company's real domain",
          ],
          answer: 1,
          explanation:
            "DGA malware generates many domains, most unregistered, so it produces an NXDOMAIN storm until it hits the one the attacker registered. Long encoded subdomains under a single domain are the tunnelling signature. One domain rotating through IPs in many countries is fast flux. A domain one letter off from a real one is typosquatting, usually phishing infrastructure.",
        },
      },

      // ── Reading 3 ──
      {
        type: "reading",
        id: "dns-r3",
        heading: "DNS Investigation Workflow: From NXDOMAIN Storm to Confirmed Malware",
        content:
          "You receive an alert: \"NXDOMAIN Storm Detected, workstation WKSTN-DEV-044 queried 487 non-existent domains in the past 5 minutes.\" How do you investigate this efficiently and reach a verdict?\n\n**Step 1: Characterise the storm**\n\nCollect all the NXDOMAIN queries from the alerting machine in the time window:\n- How many unique domains were queried?\n- What is the structure of the domain names? (Random characters? Specific TLDs? Common length?)\n- What time interval separates queries? (Rapid-fire = DGA; slower, data-encoded = tunnelling)\n- Are any domains on threat intelligence feeds?\n\nIf the domains look like random strings (xj4k9m2n.com, p8a3c7f1.net, q2r6b4z0.org), this is a strong DGA indicator. If the domains all share the same base domain with long encoded subdomains (abc123def456.exfil.attacker.com), this looks more like DNS tunnelling.\n\n**Step 2: Identify the responsible process using Sysmon**\n\nNetwork-level DNS logs tell you the machine's IP but not the specific process. Pivot to Sysmon Event 22 logs for the same machine at the same timestamps:\n- Filter: `event.code: \"22\" AND winlog.computer_name: \"WKSTN-DEV-044\"`\n- Look at `winlog.event_data.Image`which executable is generating the DNS queries?\n\nRed flags for the Image field:\n- Unexpected location: C:\\Users\\[username]\\AppData\\Roaming\\ or C:\\Temp\\ instead of C:\\Windows\\ or C:\\Program Files\\\n- Masquerading as a legitimate process but in the wrong location: C:\\Users\\bob\\svchost.exe (svchost.exe should only live in C:\\Windows\\System32\\)\n- Unknown executable name with suspicious characteristics\n\n**Step 3: Correlate with other telemetry**\n\nDNS investigation does not happen in isolation. Pivot to:\n- **EDR/Sysmon process creation logs** (Event ID 1): how was the suspicious process launched? What is its parent process? What command line was used?\n- **Firewall logs**: did any connection attempts follow the successful DNS resolution (if any domains resolved)? Did the firewall block them?\n- **AV/EDR**: has the endpoint security solution already flagged this process or file?\n\n**Step 4: Domain analysis**\n\nFor any domains that resolved (NOERROR), investigate the domain:\n- Check VirusTotal for the domain name\n- Check domain registration date (WHOIS): newly registered domains (hours or days old) are more suspicious than established domains\n- Check domain reputation on URLScan.io. What does the website show?\n- Look up the IP addresses the domain resolves to. Are they on threat feeds?\n\n**Step 5: Scope the infection**\n\nIf one machine has DGA activity, how many others do?\n- Search your DNS logs for queries to the same DGA domains from other machines\n- Search for the same binary hash (from EDR) across your fleet\n- Check if the malware is a known family, if so, look for its known persistence mechanisms, other malware it drops, and known C2 infrastructure\n\n**Step 6: Contain and eradicate**\n\nFor confirmed DGA malware:\n1. Isolate the affected workstation(s) immediately\n2. Add the successfully-resolved malicious domains and IPs to your DNS sinkhole and firewall blocklist\n3. Run full forensic acquisition of the infected system\n4. Search for the malware binary hash across all endpoints using EDR\n5. Identify initial infection vector (check email for phishing, check web proxy for drive-by download, check USB activity)\n6. Eradicate: remove persistence mechanisms, remove malware binary, patch the vulnerability that allowed infection\n7. Recover: restore from clean backup or reimage the machine\n\n**Key metrics for DNS monitoring**\n\nA mature DNS monitoring programme tracks:\n- NXDOMAIN rate per host (baseline and alerts on spikes)\n- Domains per host per hour (baseline and alert on spikes)\n- Queries to newly registered domains (less than 30 days old)\n- Queries matching threat intelligence feeds (immediate high-priority alert)\n- Direct queries to external DNS resolvers bypassing your corporate resolver (8.8.8.8, 1.1.1.1 from workstations is suspicious. Malware does this to bypass your DNS monitoring and sinkholes)",
      },

      // ── Question 1 ──
      {
        type: "question",
        id: "dns-q1",
        question:
          "Your DNS monitoring detects that workstation 10.20.30.44 queried 312 domains in 4 minutes, 309 of which returned NXDOMAIN. The queried domains look like: q7xk2j9m.com, v4p8a3b1.net, r6m0n2k5.org. What is the most likely explanation?",
        options: [
          "The user is browsing many sites at once; browsers routinely open dozens of tabs and generate hundreds of background lookups",
          "DGA malware cycling through generated domains to find its C2 server, with almost all of them returning NXDOMAIN",
          "The DNS server is malfunctioning and wrongly returning NXDOMAIN for legitimate domains after a cache corruption",
          "An authorised penetration test using subdomain enumeration, which produces this NXDOMAIN volume and random naming",
        ],
        answer: 1,
        explanation:
          "This is a textbook DGA pattern: (1) High volume of DNS queries in a short time, 312 queries in 4 minutes is ~78 queries/minute. Normal web browsing generates far fewer. (2) Overwhelming NXDOMAIN rate: 309/312 (99%) non-existent domains. Normal browsing returns a very high resolution success rate. (3) Domain structure: q7xk2j9m.com, v4p8a3b1.net, r6m0n2k5.org all exhibit high entropy, no meaningful words, and short random-character format. This is algorithmically generated, not human-chosen names. The machine is infected with DGA malware cycling through generated domain names looking for the one currently registered by the attacker.",
        xp: 20,
      },

      // ── Question 2 ──
      {
        type: "question",
        id: "dns-q2",
        question:
          "Sysmon Event ID 22 shows process C:\\Users\\frank\\AppData\\Roaming\\RuntimeBroker.exe making hundreds of DNS queries. RuntimeBroker.exe is a legitimate Windows process, but it normally lives in C:\\Windows\\System32\\. What technique does this most likely represent?",
        options: [
          "A per-user app in AppData that ships its own helper with the same name",
          "Masquerading: malware using a Windows process name from a wrong folder",
          "A Windows servicing change that relocated the binary into the profile",
          "DLL side-loading: a bad DLL loaded by the genuine RuntimeBroker.exe",
        ],
        answer: 1,
        explanation:
          "A Windows system binary name running from a user's AppData folder is the masquerading red flag the workflow teaches: the name is chosen to blend into process lists, and the location gives it away. Per-user apps do install into AppData, but they use their own names, not the name of a core Windows process. Windows servicing replaces system binaries inside C:\\Windows, it does not move them into a user profile. DLL side-loading would show the genuine RuntimeBroker.exe in System32 loading an odd DLL. Here the executable itself is in the wrong place.",
        xp: 20,
      },

      // ── Question 3 ──
      {
        type: "question",
        id: "dns-q3",
        question:
          "During a DNS investigation you notice that the domain c2.attacker-infra.net resolves to a different IP address every 90 seconds, and the IP addresses belong to residential ISPs in many different countries. What technique does this describe?",
        options: [
          "CDN load balancing: large sites rotate their edge-server IPs frequently, so this is expected",
          "Fast Flux: rapidly changing DNS records across botnet proxies, making the C2 hard to block by IP address",
          "DNS round-robin: a normal load-spreading technique that cycles through a fixed pool of server IPs",
          "DNSSEC failure: a broken validation chain returns a different random IP on almost every query",
        ],
        answer: 1,
        explanation:
          "Fast flux has two defining characteristics: (1) Very rapid IP changes, legitimate CDNs change IPs too, but not every 90 seconds. (2) IPs belonging to residential ISPs in many countries. These are not datacenter IPs hosting servers; they are compromised home computers (botnet nodes) acting as traffic relay proxies. Standard CDN load balancing uses dedicated datacenter IPs that remain stable for hours or days. DNS round-robin changes infrequently. Fast flux is specifically an evasion technique designed to make IP-based blocking ineffective, by the time a security team adds a block rule for the current IP, the attacker has already moved to a different compromised node.",
        xp: 20,
      },

      // ── Log Analysis ──
      {
        type: "log_analysis",
        id: "dns-la1",
        heading: "Sysmon Event 22: DGA DNS Storm Investigation",
        context:
          "Your SIEM has triggered a 'DGA Behaviour Detected' alert for workstation WKSTN-HR-033. The alert is based on a correlation of Sysmon Event ID 22 logs showing 200+ NXDOMAIN queries in under 3 minutes, all from the same process. The log below is a representative Sysmon Event 22 entry showing one of the suspicious DNS queries. Examine the process path, query name, and query result carefully (Sysmon records a non-existent domain as QueryStatus 9003 with empty QueryResults).",
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
            "winlog.event_data.QueryResults": "",
            "winlog.event_data.QueryStatus": "9003",
            "winlog.event_data.User": "CONTOSO\\sarah.okafor",
            "winlog.event_data.UtcTime": "2026-06-24 11:22:17.438",
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
              "svchost.exe in System32: it is odd for a service host to make this many DNS queries",
              "svchost.exe in the user's Temp folder: a system process name in a place it never runs from",
              "svchost.exe in Temp, but fine: the folder is named WindowsUpdate, so it is patch staging",
              "No process can be named: Sysmon Event 22 records the query but not the program",
            ],
            answer: 1,
            explanation:
              "The Image field is C:\\Users\\sarah.okafor\\AppData\\Local\\Temp\\WindowsUpdate\\svchost.exe. The real svchost.exe runs from C:\\Windows\\System32, never from a user's Temp folder, so this is a masquerade: the name blends into process lists and the path gives it away. Reading it as the System32 copy ignores the path actually logged. A folder called WindowsUpdate is just a name the attacker chose. Windows does not stage system binaries in a user's Temp directory. And naming the process is exactly what Event 22 adds over network DNS logs: the Image field.",
            xp: 25,
          },
          {
            question:
              "You now know which process is generating the storm. Which pivot best shows how that process got onto WKSTN-HR-033?",
            options: [
              "Resolver logs for the same .cc names queried by other hosts",
              "Sysmon Event ID 1 for ProcessId 7412: its parent and command line",
              "WHOIS on a7xk9m2j4q8b3n1r.cc to find out when it was registered",
              "Firewall logs for connections to the IP this query resolved to",
            ],
            answer: 1,
            explanation:
              "Event 22 records the query and the Image, but not who launched the process. Sysmon Event ID 1 (process creation) for the same ProcessId shows the parent and command line, which leads back to the dropper and the infection vector. Searching other hosts for the same names is the scoping step: valuable, but it answers “how far”, not “how it got here”. WHOIS on this name is a dead end: QueryStatus 9003 with empty QueryResults means it does not exist, so it is not registered. For the same reason there is no resolved IP to look for in the firewall logs.",
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
          description: "High volume DNS queries to randomized subdomains. Possible DGA or DNS tunneling",
          mitre_technique: "T1071.004",
          mitre_tactic: "Command and Control",
          raw: {
            "event.code": "22",
            "winlog.event_data.Image": "C:\\Users\\t.okonkwo\\AppData\\Roaming\\npm\\node.exe",
            "winlog.event_data.QueryName": "a7x3k1q.fastdelivery-cdn.com",
            "winlog.event_data.QueryStatus": "0",
            "winlog.event_data.QueryResults": "104.21.47.82",
            "winlog.provider_name": "Microsoft-Windows-Sysmon",
          },
        },
        correct_verdict: "escalate",
        explanation: "Escalation is correct: the evidence does not settle it either way. It is not the DGA pattern this room teaches: the names are subdomains of one domain that resolves (QueryStatus 0, an IP returned), not many unregistered domains failing with NXDOMAIN. It is also a weak fit for tunnelling, whose labels are long and encoded, while these are only 7 characters. Against benign: 340 queries in 10 minutes to one domain is high volume, and the process is a node.exe under the user's npm folder whose purpose you do not know, a developer tool, or a package doing something it should not. For benign: the domain is 8 months old and resolves to Cloudflare, and EDR flags nothing. A Tier-2 analyst should ask t.okonkwo what the project does, look at node.exe's command line and parent (Sysmon Event ID 1), compare the volume with other developers' machines, and check the query types and label lengths across all 340 queries.",
        fp_trap: "Random-looking labels are not proof of DGA or tunnelling, and an 8-month-old domain on Cloudflare is real evidence on the benign side. But Cloudflare also fronts attacker domains, and “EDR found no malware” only covers known-bad code. With an unexplained process generating heavy, unusual DNS, neither closing as benign nor declaring a true positive is supported yet. That gap is what escalation is for.",
        xp: 30,
      },

      // ── Flag ──
      {
        type: "flag",
        id: "dns-flag1",
        prompt:
          "Back in the Sysmon Event 22 log for WKSTN-HR-033: using the SIEM's 5-minute correlation counts, how many of the unique domains the process queried in that window actually resolved? This tells you whether the malware has found its C2 yet. Enter a number.",
        answer: "0",
        hint: "Compare the count of unique domains with the count of failed (non-existent) lookups for the same window.",
        xp: 35,
      },
    ],
  },
];

export default rooms;
