// Malicious email header scenarios for analyst training
// Each scenario is a realistic attack — analyst must identify IOCs before reveal.

export interface HeaderIOC {
  field: string;
  value: string;
  explanation: string;
  severity: "medium" | "high" | "critical";
}

export interface HeaderScenario {
  id: string;
  title: string;
  attackType: "BEC" | "Phishing" | "Spoofing" | "Malware" | "Impersonation" | "Credential Harvest";
  difficulty: "Easy" | "Medium" | "Hard";
  narrative: string; // short briefing shown BEFORE reveal
  // Parsed display fields
  from: string;
  to: string;
  subject: string;
  replyTo?: string;
  returnPath?: string;
  messageId: string;
  date: string;
  spf: string;
  dkim: string;
  dmarc: string;
  xMailer?: string;
  xOriginatingIp?: string;
  contentType?: string;
  receivedChain: string[];
  authResultsRaw: string;
  // Answer
  iocs: HeaderIOC[];
  rawHeader: string;
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

function raw(scenario: Omit<HeaderScenario, "rawHeader">): HeaderScenario {
  const lines: string[] = [];

  // Build received chain (newest first — standard email order)
  [...scenario.receivedChain].reverse().forEach((hop, i) => {
    lines.push(`Received: ${hop}`);
    if (i < scenario.receivedChain.length - 1) lines.push(`       ; ${scenario.date}`);
  });

  lines.push(`Message-ID: ${scenario.messageId}`);
  lines.push(`Date: ${scenario.date}`);
  lines.push(`From: ${scenario.from}`);
  lines.push(`To: ${scenario.to}`);
  lines.push(`Subject: ${scenario.subject}`);
  if (scenario.replyTo) lines.push(`Reply-To: ${scenario.replyTo}`);
  if (scenario.returnPath) lines.push(`Return-Path: <${scenario.returnPath}>`);
  if (scenario.xMailer) lines.push(`X-Mailer: ${scenario.xMailer}`);
  if (scenario.xOriginatingIp) lines.push(`X-Originating-IP: ${scenario.xOriginatingIp}`);
  if (scenario.contentType) lines.push(`Content-Type: ${scenario.contentType}`);
  lines.push(`MIME-Version: 1.0`);
  lines.push(`Authentication-Results: mx.nexacorp.com;`);
  lines.push(`       spf=${scenario.spf} smtp.mailfrom=${scenario.from.match(/<(.+)>/)?.[1] ?? ""};`);
  lines.push(`       dkim=${scenario.dkim};`);
  lines.push(`       dmarc=${scenario.dmarc}`);
  lines.push(`X-Microsoft-Antispam: BCL:0;`);
  lines.push(`X-Forefront-Antispam-Report: ${Math.random().toString(36).slice(2, 10).toUpperCase()}`);

  return { ...scenario, rawHeader: lines.join("\r\n") };
}

// ─── Scenarios ────────────────────────────────────────────────────────────────

const scenarios: HeaderScenario[] = [

  // ── 1. CEO Impersonation (BEC) ─────────────────────────────────────────────
  raw({
    id: "bec-ceo-impersonation",
    title: "CEO Wire Transfer Request",
    attackType: "BEC",
    difficulty: "Easy",
    narrative: "An email from 'the CEO' arrived requesting an urgent wire transfer. The CFO almost approved it.",
    from: "David Cohen <d.cohen@nexac0rp.com>",
    to: "Sarah Miller <s.miller@nexacorp.com>",
    subject: "URGENT: Wire Transfer Needed — Confidential",
    replyTo: "david.cohen.ceo@gmail.com",
    returnPath: "bounce@nexac0rp.com",
    messageId: "<C7B2F1E3.4A2D@nexac0rp.com>",
    date: "Mon, 16 Jun 2026 01:47:22 +0300",
    spf: "fail",
    dkim: "none",
    dmarc: "fail",
    xMailer: "Swaks v20201014.0",
    xOriginatingIp: "185.220.101.33",
    contentType: "text/html; charset=UTF-8",
    receivedChain: [
      "from mail.nexac0rp.com (185.220.101.33) by mx.nexacorp.com with SMTP id q4si2837492pjb.1",
      "from [185.220.101.33] (unknown) by mail.nexac0rp.com with SMTP id a1b2c3d4",
    ],
    authResultsRaw: "mx.nexacorp.com; spf=fail smtp.mailfrom=nexac0rp.com; dkim=none; dmarc=fail header.from=nexac0rp.com",
    iocs: [
      {
        field: "From domain",
        value: "nexac0rp.com",
        explanation: "Typosquatted domain — zero (0) instead of letter 'o' in 'nexacorp'. Classic BEC trick to fool a quick glance.",
        severity: "critical",
      },
      {
        field: "Reply-To",
        value: "david.cohen.ceo@gmail.com",
        explanation: "Reply-To redirects responses to a free Gmail account the attacker controls — replies never reach the real CEO.",
        severity: "critical",
      },
      {
        field: "SPF",
        value: "fail",
        explanation: "nexac0rp.com is not an authorized sender for NexaCorp mail — the domain is attacker-controlled.",
        severity: "high",
      },
      {
        field: "X-Mailer",
        value: "Swaks v20201014.0",
        explanation: "Swaks is a CLI SMTP testing tool used by attackers to send spoofed email — NOT a corporate mail client.",
        severity: "high",
      },
      {
        field: "X-Originating-IP",
        value: "185.220.101.33",
        explanation: "This IP is a known Tor exit node / bulletproof hosting address (AS204428). Legitimate CEO laptops don't originate from here.",
        severity: "critical",
      },
      {
        field: "Send time",
        value: "01:47 AM",
        explanation: "Sent at 01:47 AM local time. Executives sending urgent financial requests at 2 AM should always raise suspicion.",
        severity: "medium",
      },
    ],
  }),

  // ── 2. Microsoft Phishing ──────────────────────────────────────────────────
  raw({
    id: "microsoft-phish",
    title: "Fake Microsoft Security Alert",
    attackType: "Credential Harvest",
    difficulty: "Easy",
    narrative: "User received an email warning their account will be disabled within 24 hours and must 'verify' via a link.",
    from: "Microsoft Security <security-noreply@microsoft-account-alerts.net>",
    to: "j.chen@nexacorp.com",
    subject: "ACTION REQUIRED: Unusual sign-in detected on your account",
    replyTo: "no-reply@microsoft-account-alerts.net",
    returnPath: "bounces@microsoft-account-alerts.net",
    messageId: "<20260616.security.8472@microsoft-account-alerts.net>",
    date: "Mon, 16 Jun 2026 09:22:14 +0000",
    spf: "pass",
    dkim: "pass",
    dmarc: "pass",
    xMailer: "PHPMailer 6.6.4 (https://github.com/PHPMailer/PHPMailer)",
    xOriginatingIp: "185.220.101.47",
    contentType: "text/html; charset=UTF-8",
    receivedChain: [
      "from mail.microsoft-account-alerts.net (185.220.101.47) by mx.nexacorp.com with ESMTPS id p17si7291043pjm.5",
      "from [185.220.101.47] (helo=mail.microsoft-account-alerts.net) by mail.microsoft-account-alerts.net with SMTP",
    ],
    authResultsRaw: "mx.nexacorp.com; spf=pass smtp.mailfrom=microsoft-account-alerts.net; dkim=pass header.d=microsoft-account-alerts.net; dmarc=pass header.from=microsoft-account-alerts.net",
    iocs: [
      {
        field: "Sender domain",
        value: "microsoft-account-alerts.net",
        explanation: "Legitimate Microsoft emails come from @microsoft.com or @accountprotection.microsoft.com — never from a .net vanity domain. Domain was registered 3 days ago.",
        severity: "critical",
      },
      {
        field: "X-Mailer",
        value: "PHPMailer 6.6.4",
        explanation: "Microsoft's mail infrastructure doesn't use PHPMailer — this is an open-source library used by attackers to mass-send phishing campaigns.",
        severity: "high",
      },
      {
        field: "X-Originating-IP",
        value: "185.220.101.47",
        explanation: "Known Tor exit node / bulletproof hosting. Microsoft's servers originate from Microsoft Azure IP ranges (40.x, 52.x, 104.x).",
        severity: "critical",
      },
      {
        field: "SPF/DKIM/DMARC: pass",
        value: "all pass — but on wrong domain",
        explanation: "ALL three pass — because the attacker set them up on their own fake domain. Pass on a lookalike domain is NOT the same as passing for microsoft.com. Always check the DOMAIN, not just the result.",
        severity: "high",
      },
    ],
  }),

  // ── 3. Compromised Vendor Account ─────────────────────────────────────────
  raw({
    id: "vendor-compromise",
    title: "Invoice from Compromised Vendor",
    attackType: "BEC",
    difficulty: "Hard",
    narrative: "An invoice for $142,500 arrived from a legitimate long-term vendor. Everything looks real — SPF pass, DKIM pass. But something is wrong.",
    from: "Sarah Thompson <s.thompson@global-logistics-intl.com>",
    to: "ap@nexacorp.com",
    subject: "Invoice #INV-2026-0847 — Payment Due June 25",
    returnPath: "s.thompson@global-logistics-intl.com",
    messageId: "<YQBPR01MB8374F92A0D3BBF7C1E2A9BA4D9C72@YQBPR01MB8374.CANPRD01.PROD.OUTLOOK.COM>",
    date: "Sun, 15 Jun 2026 23:11:34 +0000",
    spf: "pass",
    dkim: "pass",
    dmarc: "pass",
    xMailer: "Microsoft Outlook 16.0.17531.20004",
    xOriginatingIp: "102.133.221.18",
    contentType: "multipart/mixed; boundary=\"_002_YQBPR01MB8374\"",
    receivedChain: [
      "from YQBPR01MB8374.CANPRD01.PROD.OUTLOOK.COM (102.133.221.18) by mx.nexacorp.com with HTTPS",
      "from AM8P193CA0048.EURPRD193.PROD.OUTLOOK.COM by YQBPR01MB8374.CANPRD01.PROD.OUTLOOK.COM",
      "from [41.216.183.22] (41.216.183.22) by AM8P193CA0048 via Frontend Transport",
    ],
    authResultsRaw: "mx.nexacorp.com; spf=pass smtp.mailfrom=global-logistics-intl.com; dkim=pass header.d=global-logistics-intl.com; dmarc=pass header.from=global-logistics-intl.com",
    iocs: [
      {
        field: "X-Originating-IP",
        value: "102.133.221.18 / 41.216.183.22",
        explanation: "The session originated from 41.216.183.22 — a Nigerian IP (AS37705). Sarah Thompson is based in Vancouver. This geolocation is impossible travel.",
        severity: "critical",
      },
      {
        field: "Received hop #3",
        value: "[41.216.183.22]",
        explanation: "The innermost Received header shows the actual client IP: 41.216.183.22 (Lagos, Nigeria). The legitimate vendor account was likely compromised — attacker logged in via OWA from Nigeria and sent this invoice.",
        severity: "critical",
      },
      {
        field: "Send time",
        value: "Sunday 23:11 UTC",
        explanation: "Invoice sent at 11 PM on a Sunday night from what should be a Vancouver-based accountant (UTC-7 = 4 PM Sunday — plausible) — but combined with the Nigerian IP, confirms account takeover.",
        severity: "medium",
      },
      {
        field: "Payment instructions changed",
        value: "Invoice #INV-2026-0847",
        explanation: "BEC playbook: attacker compromises vendor email, sends real-looking invoice but with updated bank account details. Always call the vendor to confirm payment instructions on invoices above threshold.",
        severity: "high",
      },
    ],
  }),

  // ── 4. Internal HR Impersonation ──────────────────────────────────────────
  raw({
    id: "hr-internal-spoof",
    title: "Fake IT / HR Internal Communication",
    attackType: "Impersonation",
    difficulty: "Medium",
    narrative: "An email from 'NexaCorp IT Helpdesk' asked employees to re-enter their credentials for a system upgrade. 12 users clicked the link.",
    from: "NexaCorp IT Helpdesk <helpdesk@nexacorp.com.helpdesk-support.io>",
    to: "all-staff@nexacorp.com",
    subject: "IMPORTANT: Microsoft 365 Credential Re-Verification Required",
    replyTo: "it-helpdesk@protonmail.com",
    returnPath: "noreply@helpdesk-support.io",
    messageId: "<helpdesk.20260616.092241@helpdesk-support.io>",
    date: "Mon, 16 Jun 2026 09:22:41 +0300",
    spf: "pass",
    dkim: "none",
    dmarc: "fail",
    xMailer: "PHPMailer 6.5.3",
    xOriginatingIp: "91.108.56.112",
    contentType: "text/html; charset=utf-8",
    receivedChain: [
      "from mail.helpdesk-support.io (91.108.56.112) by mx.nexacorp.com with SMTP id k3si4928173pja.2",
      "from [91.108.56.112] by mail.helpdesk-support.io with SMTP",
    ],
    authResultsRaw: "mx.nexacorp.com; spf=pass smtp.mailfrom=helpdesk-support.io; dkim=none; dmarc=fail header.from=helpdesk-support.io",
    iocs: [
      {
        field: "From address",
        value: "helpdesk@nexacorp.com.helpdesk-support.io",
        explanation: "Subdomain trick: the domain is helpdesk-support.io — 'nexacorp.com' is just a SUBDOMAIN prefix. The actual registrant domain is helpdesk-support.io, controlled by the attacker.",
        severity: "critical",
      },
      {
        field: "Reply-To",
        value: "it-helpdesk@protonmail.com",
        explanation: "Real internal IT will never ask you to reply to ProtonMail. Replies would go to the attacker.",
        severity: "critical",
      },
      {
        field: "DMARC",
        value: "fail",
        explanation: "DMARC fails because the From header domain (helpdesk-support.io) doesn't align with nexacorp.com's DMARC policy. The subdomain trick fools users visually but not authentication.",
        severity: "high",
      },
      {
        field: "X-Originating-IP",
        value: "91.108.56.112",
        explanation: "91.108.4.x and 91.108.56.x are Telegram datacenter IPs in the Netherlands. Legitimate NexaCorp IT sends from Microsoft 365 infrastructure.",
        severity: "high",
      },
      {
        field: "X-Mailer",
        value: "PHPMailer 6.5.3",
        explanation: "NexaCorp IT uses Microsoft 365 — which shows 'Microsoft Outlook' or no X-Mailer at all. PHPMailer indicates a script, not a corporate client.",
        severity: "medium",
      },
    ],
  }),

  // ── 5. Malware via Trusted Sender (Supply Chain) ───────────────────────────
  raw({
    id: "supply-chain-malware",
    title: "Malware Dropper from Trusted Partner",
    attackType: "Malware",
    difficulty: "Hard",
    narrative: "A macro-enabled Word document arrived from a regular business partner. AV didn't flag it. The email headers are the only warning sign.",
    from: "James Wilson <j.wilson@meridian-consulting.co.uk>",
    to: "m.johnson@nexacorp.com",
    subject: "Q2 2026 Project Proposal — Action Required",
    returnPath: "j.wilson@meridian-consulting.co.uk",
    messageId: "<AM6PR08MB7234B9B4F129F3B8C1D0B7F1E9C82@AM6PR08MB7234.eurprd08.prod.exchangelabs.com>",
    date: "Fri, 13 Jun 2026 14:33:19 +0000",
    spf: "pass",
    dkim: "pass",
    dmarc: "pass",
    xOriginatingIp: "223.5.5.5",
    xMailer: "Microsoft Outlook 16.0.17531.20000",
    contentType: "multipart/mixed; boundary=\"_003_AM6PR08MB7234\"",
    receivedChain: [
      "from AM6PR08MB7234.eurprd08.prod.exchangelabs.com by mx.nexacorp.com with HTTPS",
      "from HE1PR08MB2413.eurprd08.prod.exchangelabs.com by AM6PR08MB7234",
      "from [223.5.5.5] by HE1PR08MB2413 via Frontend Transport",
    ],
    authResultsRaw: "mx.nexacorp.com; spf=pass smtp.mailfrom=meridian-consulting.co.uk; dkim=pass header.d=meridian-consulting.co.uk; dmarc=pass header.from=meridian-consulting.co.uk",
    iocs: [
      {
        field: "X-Originating-IP",
        value: "223.5.5.5",
        explanation: "This IP belongs to Alibaba Cloud DNS (China). James Wilson is a UK consultant — he should be originating from British or EU IP space, not Chinese cloud infrastructure. His account was almost certainly compromised.",
        severity: "critical",
      },
      {
        field: "Received chain — innermost hop",
        value: "[223.5.5.5] via Frontend Transport",
        explanation: "The actual client IP that authenticated to Exchange Online is 223.5.5.5 (China). All three auth checks pass because the attacker has valid credentials for j.wilson's account.",
        severity: "critical",
      },
      {
        field: "SPF/DKIM/DMARC: all pass",
        value: "Account takeover scenario",
        explanation: "When an attacker steals credentials and logs in legitimately, ALL email auth checks pass — because the email IS sent from the real server. Headers alone cannot detect ATO; you need UEBA/impossible travel correlation.",
        severity: "high",
      },
      {
        field: "Attachment type",
        value: "macro-enabled document (.docm)",
        explanation: "Q2 proposals should be PDFs. A .docm file from a partner requesting macro-enabling is a classic initial access vector (T1566.001). The header gives no warning about the attachment's malicious content.",
        severity: "high",
      },
    ],
  }),

  // ── 6. Lookalike Domain — PayPal Phish ────────────────────────────────────
  raw({
    id: "paypal-lookalike",
    title: "PayPal Account Alert — Homoglyph Attack",
    attackType: "Phishing",
    difficulty: "Easy",
    narrative: "User received what looked like a PayPal security alert. The sender address looked right — until you look carefully.",
    from: "PayPal Security <security@paypa1.com>",
    to: "a.kim@nexacorp.com",
    subject: "We've limited your account — Immediate action required",
    replyTo: "paypal-security@gmail.com",
    returnPath: "bounce@paypa1.com",
    messageId: "<sec.paypa1.20260616.1139.cc8f3b2@paypa1.com>",
    date: "Mon, 16 Jun 2026 11:39:04 +0000",
    spf: "fail",
    dkim: "none",
    dmarc: "fail",
    xMailer: "Swaks v20201014.0",
    xOriginatingIp: "45.142.212.100",
    contentType: "text/html; charset=UTF-8",
    receivedChain: [
      "from smtp.paypa1.com (45.142.212.100) by mx.nexacorp.com with SMTP id r7si1094732pjb.3",
      "from [45.142.212.100] by smtp.paypa1.com with SMTP",
    ],
    authResultsRaw: "mx.nexacorp.com; spf=fail smtp.mailfrom=paypa1.com; dkim=none; dmarc=fail header.from=paypa1.com",
    iocs: [
      {
        field: "From domain",
        value: "paypa1.com (digit 1 not letter l)",
        explanation: "Homoglyph attack — 'paypa1.com' uses the digit '1' instead of the letter 'l'. Visually identical in many fonts. The legitimate domain is paypal.com.",
        severity: "critical",
      },
      {
        field: "Reply-To",
        value: "paypal-security@gmail.com",
        explanation: "PayPal does not use Gmail for customer communications. Replies from concerned users go directly to the attacker's inbox.",
        severity: "critical",
      },
      {
        field: "SPF",
        value: "fail",
        explanation: "paypa1.com has no authorized mail servers, or the attacker's IP is not in the SPF record. PayPal's real SPF record is comprehensive and always passes.",
        severity: "high",
      },
      {
        field: "X-Mailer",
        value: "Swaks v20201014.0",
        explanation: "PayPal uses enterprise-grade bulk mail infrastructure — not Swaks, a CLI tool typically used by pentesters and attackers.",
        severity: "medium",
      },
    ],
  }),

  // ── 7. Internal Password Reset Spoof ──────────────────────────────────────
  raw({
    id: "it-password-reset-spoof",
    title: "Spoofed IT Password Reset Email",
    attackType: "Spoofing",
    difficulty: "Medium",
    narrative: "An email arrived that appeared to come from the internal IT ticketing system, asking the user to reset their Active Directory password via a link.",
    from: "IT Helpdesk <noreply@nexacorp.com>",
    to: "l.nguyen@nexacorp.com",
    subject: "Password expiry notice — Reset required within 24 hours",
    replyTo: "noreply@nexacoorp.com",
    returnPath: "noreply@nexacoorp.com",
    messageId: "<helpdesk.noreply.20260616@nexacoorp.com>",
    date: "Mon, 16 Jun 2026 06:14:53 +0300",
    spf: "fail",
    dkim: "none",
    dmarc: "fail",
    xMailer: "PHPMailer 6.5.3",
    xOriginatingIp: "194.165.16.68",
    contentType: "text/html; charset=utf-8",
    receivedChain: [
      "from mail.nexacoorp.com (194.165.16.68) by mx.nexacorp.com with SMTP id g9si3748291pjc.1",
      "from [194.165.16.68] by mail.nexacoorp.com with SMTP",
    ],
    authResultsRaw: "mx.nexacorp.com; spf=fail smtp.mailfrom=nexacoorp.com; dkim=none; dmarc=fail header.from=nexacoorp.com",
    iocs: [
      {
        field: "From vs Return-Path mismatch",
        value: "From: nexacorp.com / Return-Path: nexacoorp.com",
        explanation: "The visible From address shows 'nexacorp.com' (legitimate) but Return-Path reveals 'nexacoorp.com' (double 'o' — attacker's domain). This is header spoofing — the From is faked, the Return-Path leaks the truth.",
        severity: "critical",
      },
      {
        field: "Reply-To",
        value: "noreply@nexacoorp.com",
        explanation: "Reply-To uses 'nexacoorp.com' (extra 'o'). The From header shows the legitimate domain, but Reply-To reveals where responses actually go.",
        severity: "critical",
      },
      {
        field: "SPF",
        value: "fail — smtp.mailfrom=nexacoorp.com",
        explanation: "SPF checks the Return-Path domain, not the From header. nexacoorp.com fails SPF because it's attacker-controlled. The legitimate nexacorp.com SPF would pass.",
        severity: "high",
      },
      {
        field: "X-Originating-IP",
        value: "194.165.16.68",
        explanation: "This IP is in AS198610 (Beget LLC, Russia). NexaCorp's IT ticketing system sends from Microsoft 365 or on-premise Exchange, not Russian hosting.",
        severity: "high",
      },
      {
        field: "Send time",
        value: "06:14 AM",
        explanation: "Automated IT systems send password expiry notices during business hours. A 6 AM notice is not typical for this environment.",
        severity: "medium",
      },
    ],
  }),

  // ── 8. Google Calendar Phish ───────────────────────────────────────────────
  raw({
    id: "google-calendar-phish",
    title: "Fake Google Calendar Invite",
    attackType: "Credential Harvest",
    difficulty: "Medium",
    narrative: "A meeting invite from 'Google Calendar' arrived. The attachment contained a link to a Google-lookalike login page that harvested credentials.",
    from: "Google Calendar <calendar-noreply@google-calendar-alerts.com>",
    to: "a.miller@nexacorp.com",
    subject: "Invitation: Q2 Business Review — Rescheduled to Mon Jun 17",
    replyTo: "calendar-donotreply@google-alerts.net",
    returnPath: "calendar-noreply@google-calendar-alerts.com",
    messageId: "<calendar.invite.20260616.143022@google-calendar-alerts.com>",
    date: "Mon, 16 Jun 2026 14:30:22 +0000",
    spf: "pass",
    dkim: "pass",
    dmarc: "pass",
    xMailer: "Swaks v20201014.0",
    xOriginatingIp: "62.210.205.122",
    contentType: "text/calendar; charset=UTF-8; method=REQUEST",
    receivedChain: [
      "from mail.google-calendar-alerts.com (62.210.205.122) by mx.nexacorp.com with ESMTPS",
      "from [62.210.205.122] by mail.google-calendar-alerts.com with SMTP",
    ],
    authResultsRaw: "mx.nexacorp.com; spf=pass smtp.mailfrom=google-calendar-alerts.com; dkim=pass header.d=google-calendar-alerts.com; dmarc=pass header.from=google-calendar-alerts.com",
    iocs: [
      {
        field: "Sender domain",
        value: "google-calendar-alerts.com",
        explanation: "Google Calendar notifications come from calendar-notification@google.com or google.com infrastructure. 'google-calendar-alerts.com' is an attacker-registered domain — Google does NOT use it.",
        severity: "critical",
      },
      {
        field: "Reply-To domain mismatch",
        value: "google-alerts.net vs google-calendar-alerts.com",
        explanation: "Even within the attacker's own domains, Reply-To uses a different domain (google-alerts.net) than the From (google-calendar-alerts.com). Fragmented infrastructure often betrays phishing kits.",
        severity: "high",
      },
      {
        field: "X-Mailer",
        value: "Swaks v20201014.0",
        explanation: "Google's mail infrastructure doesn't expose X-Mailer headers. Swaks is a manual/scripted SMTP tool — not Google's production mail pipeline.",
        severity: "high",
      },
      {
        field: "X-Originating-IP",
        value: "62.210.205.122",
        explanation: "This IP is in Paris, France (Iliad / Free SAS AS12876). Google sends calendar notifications from 209.85.x.x (Google LLC) IP ranges, not French hosting.",
        severity: "critical",
      },
      {
        field: "SPF/DKIM/DMARC: all pass",
        value: "on wrong domain",
        explanation: "Auth passes because attacker fully controls google-calendar-alerts.com. This is a reminder: PASS only means the sending domain is who it claims to be — it doesn't mean the domain is trustworthy.",
        severity: "medium",
      },
    ],
  }),

];

export const MALICIOUS_HEADER_SCENARIOS = scenarios;

export function pickRandomHeaderScenario(): HeaderScenario {
  return scenarios[Math.floor(Math.random() * scenarios.length)];
}
