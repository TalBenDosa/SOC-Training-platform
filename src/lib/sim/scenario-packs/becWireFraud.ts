/**
 * Scenario pack: "The CFO Who Never Called — a BEC Wire-Fraud Impersonation"
 *
 * INTERMEDIATE tier. A cloud-email case with NO malware, NO compromised internal
 * mailbox, and NO host to walk. An Accounts-Payable specialist receives an urgent
 * wire-transfer request that presents as the CFO. The tell is not a takeover — it
 * is IMPERSONATION. A follow-up message arrives from a LOOKALIKE, newly-registered
 * domain (nexacorp-finance.com, versus the real corporate nexacorp.com): the
 * display name reads as the CFO while the actual sender sits on the lookalike
 * domain, the envelope (P1) and header (P2) senders disagree, and the message
 * fails SPF, DKIM and DMARC. It is reinforced out-of-band by a phone call using a
 * DEEPFAKE voice clone of the CFO, captured as a Finance fraud report in the
 * service desk.
 *
 * The teaching spine is a single discrimination the student must make and defend:
 *   • This is EXTERNAL EXECUTIVE IMPERSONATION, not an account takeover. The proof
 *     is in the email authentication (fail/none) + the lookalike/newly-registered
 *     sender domain + the fact that the GENUINE CFO account shows only routine
 *     sign-ins and no new mailbox rules — his real mailbox was never touched.
 *   • The urgency and the deepfake phone call are SOCIAL PRESSURE, not
 *     corroboration. Verification has to run through a known-good channel, never
 *     the contact details the request itself supplies.
 *
 * A BENIGN CONTROL is included and is the pedagogical crux: the day before, the
 * REAL CFO sent Accounts Payable a genuine payment email — the same "urgent
 * finance email" shape, opposite verdict. It authenticates cleanly (SPF/DKIM/DMARC
 * pass), originates from the real nexacorp.com domain, and follows the standing
 * approval workflow. The discriminator is email authentication + real domain +
 * process — not the fact that a finance email is urgent.
 *
 * Covers T1656 (Impersonation — the display-name/domain spoof of the CFO, and the
 * deepfake voice call), T1566.002 (Spearphishing Link — the payment-portal link in
 * the message) and T1583.001 (Acquire Infrastructure: Domains — the attacker's
 * lookalike, newly-registered sending domain).
 *
 * SOURCES (all fields registry-valid for their declared vendor): Microsoft Defender
 * for Office 365 (the inbound wire-request email — sender, lookalike domain,
 * SPF/DKIM/DMARC results, display-name spoof, P1/P2 mismatch, impersonation
 * verdict, and the domain-reputation lookup), the Microsoft 365 Unified Audit Log
 * (the delivered message record and the genuine CFO account's routine activity),
 * and ServiceNow ITSM (the Finance fraud report capturing the deepfake phone call).
 * This pack fits the Microsoft 365 company profiles (nexacorp, medcore, globallogis).
 *
 * NOTE: register in scenarios.ts with difficulty "intermediate". The
 * ScenarioBundle itself carries no difficulty field.
 */

import type { ScenarioBundle, TelemetryEvent, IOC, ScenarioQuestion } from "@/lib/sim/types";
import { makeSha256 } from "@/lib/sim/iocs";

export function buildBecWireFraudScenario(
  scenarioId = "bec-wire-fraud-2026",
): ScenarioBundle {
  const B = new Date("2026-08-31T07:30:00Z").getTime();
  const T = (ms: number) => new Date(B + ms).toISOString();
  const MIN = 60_000;
  const HOUR = 3_600_000;

  // One incident — the whole case is a single BEC wire-fraud investigation.
  const INCIDENT = "inc:becwf:1";

  // The finance employee who is targeted, and her normal working context.
  const victim = {
    email: "p.nair@nexacorp.com",
    name: "Priya Nair",
    sam: "p.nair",
    title: "Accounts Payable Specialist",
    corpIp: "72.14.201.90", // her New York corporate egress
  };

  // The real CFO the attacker impersonates. His genuine account is on nexacorp.com.
  const cfo = {
    email: "david.okonkwo@nexacorp.com",
    name: "David Okonkwo",
    title: "Chief Financial Officer",
    corpIp: "72.14.201.61", // his usual New York corporate egress
  };

  // The attacker infrastructure: a lookalike, newly-registered domain, a sender
  // address on it, and a hosting-ASN egress used to send the mail.
  const lookalikeDomain = "nexacorp-finance.com";      // vs the real nexacorp.com
  const impostorFrom = `david.okonkwo@${lookalikeDomain}`; // header (P2) From
  const impostorEnvelope = `bounce-svc@mail.${lookalikeDomain}`; // envelope (P1)
  const senderIp = "102.89.44.19";                     // West-Africa hosting egress
  const senderAsn = 29465;
  const senderAsnOrg = "MTN-NIGERIA-Plc";
  const paymentLink = `https://${lookalikeDomain}/secure/beneficiary-update`;

  // The attachment carried by the fraudulent mail — its hash is the data IOC.
  const attachmentName = "Updated_Beneficiary_Wire_Instructions.pdf";
  const attachmentHash = makeSha256("nexacorp_bec_updated_beneficiary_wire_instructions_pdf_2026");

  // The spoofed number the deepfake call came from (kept in report text, not a field).
  const spoofedCallerNumber = "+1 (212) 555-0173";

  // The service desk that logged the fraud report.
  const serviceDesk = "servicedesk@nexacorp.com";
  const fraudTicket = "INC0091745";

  const events: TelemetryEvent[] = [
    // ─────────────────────────────────────────────────────────────────────
    // 0. BENIGN CONTROL — the REAL CFO's genuine payment email the day before.
    //    Same "urgent finance email" shape, opposite verdict: it authenticates
    //    cleanly (SPF/DKIM/DMARC pass), comes from the real nexacorp.com domain,
    //    and rides the standing approval workflow. This is what a legitimate
    //    executive finance request looks like.
    // ─────────────────────────────────────────────────────────────────────
    {
      id: "evt_becwf_00_benign_cfo_email",
      ts: T(-26 * HOUR),
      source: "email_gateway",
      vendor: "Microsoft Defender for Office 365",
      event_type: "email_received",
      user_email: victim.email,
      user_title: victim.title,
      src_ip: cfo.corpIp,
      severity: "informational",
      expected_verdict: "fp",
      fp_explanation:
        "Benign. The real CFO sent this the day before — the same urgent-payment shape, but everything the fraud lacks is present: SPF, DKIM and DMARC all pass, the sender is the genuine david.okonkwo@nexacorp.com on the corporate domain, and the mail references the standing approval workflow (a PO and a second approver). The signal is never that a finance email is urgent; it is email authentication, the real domain, and the process.",
      description:
        "The previous afternoon the CFO david.okonkwo@nexacorp.com emailed Accounts Payable to approve a scheduled vendor payment, referencing the purchase order and a second approver. It authenticated cleanly and came from the corporate domain.",
      raw: {
        "email.from.display_name": cfo.name,
        "email.from.address": cfo.email,
        "email.sender.address": cfo.email,
        "email.to.address": victim.email,
        "email.subject": "Approved: vendor payment PO-2026-4471 for Thursday run",
        "email.direction": "inbound",
        "email.message_id": "<b81f24c7-3a90-4d51-9e02-6f1a7c2b4419@nexacorp.com>",
        "email.spf": "pass",
        "email.dkim": "pass",
        "email.dmarc": "pass",
        "email.auth.compauth": "pass",
        "data.office365.Directionality": "Inbound",
        "data.office365.DeliveryAction": "Delivered",
        "data.office365.DeliveryLocation": "Inbox",
        "data.office365.ThreatType": "None",
        "data.office365.PhishConfidenceLevel": "None",
        "data.office365.SenderIp": cfo.corpIp,
        "data.office365.Sender": cfo.email,
        "data.office365.MailboxOwnerUPN": victim.email,
        "data.office365.ResultStatus": "Succeeded",
        "source.ip": cfo.corpIp,
      },
    },

    // ─────────────────────────────────────────────────────────────────────
    // 1. THE IMPERSONATION EMAIL — the crux. An urgent wire request that reads
    //    as the CFO but fails SPF/DKIM/DMARC, carries a display-name spoof, and
    //    has the envelope (P1) and header (P2) senders on a lookalike domain.
    //    Defender's impersonation protection raises the alert that opens the
    //    case. Impersonation (T1656). is_detection + non_edr.
    // ─────────────────────────────────────────────────────────────────────
    {
      id: "evt_becwf_01_impersonation_email",
      ts: T(0),
      source: "email_gateway",
      vendor: "Microsoft Defender for Office 365",
      event_type: "email_received",
      user_email: victim.email,
      user_title: victim.title,
      src_ip: senderIp,
      geo: { country: "Nigeria", city: "Lagos" },
      severity: "high",
      mitre_technique: "T1656",
      mitre_tactic: "Defense Evasion",
      incident_id: INCIDENT,
      is_detection: true,   // Defender impersonation protection — opens the case
      edr_scope: "non_edr", // email / identity control-plane, no host process to walk
      description:
        "An urgent wire-transfer request to p.nair reads from \"David Okonkwo\" but the actual sender is david.okonkwo@nexacorp-finance.com; the envelope and header senders disagree, SPF/DKIM/DMARC come back fail/none, and Defender's anti-phish flagged executive impersonation. It carries a link and a wire-instructions PDF.",
      network: { url: paymentLink, domain: lookalikeDomain, method: "GET" },
      raw: {
        // Envelope (P1) vs header (P2) — both on the lookalike domain, display name spoofs the CFO
        "email.from.display_name": cfo.name,
        "email.from.address": impostorFrom,          // header (P2) From
        "email.sender.address": impostorEnvelope,    // envelope (P1) MAIL FROM
        "email.to.address": victim.email,
        "email.subject": "URGENT: Wire Transfer Needed Today",
        "email.direction": "inbound",
        "email.message_id": "<9a3f71c0-6e24-4b8d-ae15-0c7f2d914b83@mail.nexacorp-finance.com>",
        "email.reply_to.address": impostorFrom,
        "email.url": paymentLink,
        "email.url_domain": lookalikeDomain,
        "email.attachment.name": attachmentName,
        "email.attachment.sha256": attachmentHash,
        "email.spf": "fail",
        "email.dkim": "none",
        "email.dmarc": "fail",
        "email.auth.compauth": "fail",
        // Defender for Office 365 verdict fields
        "data.office365.Directionality": "Inbound",
        "data.office365.DeliveryAction": "Delivered",
        "data.office365.DeliveryLocation": "Inbox",
        "data.office365.ThreatType": "Phish",
        "data.office365.ThreatName": "Spoof/Impersonation",
        "data.office365.DetectionMethod": "Impersonation domain",
        "data.office365.PhishConfidenceLevel": "High",
        "data.office365.SpamConfidenceLevel": "6",
        "data.office365.PolicyName": "Anti-phishing — Executive Impersonation Protection",
        "data.office365.Sender": impostorFrom,
        "data.office365.SenderIp": senderIp,
        "data.office365.NetworkMessageId": "d5b8f1a2-7c94-4e63-b0a1-2f6c8e37a941",
        "data.office365.InternetMessageId": "<9a3f71c0-6e24-4b8d-ae15-0c7f2d914b83@mail.nexacorp-finance.com>",
        "data.office365.MailboxOwnerUPN": victim.email,
        "data.office365.Url": paymentLink,
        "data.office365.UrlDomain": lookalikeDomain,
        "data.office365.AttachmentName": attachmentName,
        "data.office365.AttachmentSha256": attachmentHash,
        "alert.name": "User impersonation — protected executive",
        "alert.severity": "High",
        "alert.id": "MDO-2026-0831-7742",
        "source.ip": senderIp,
        "asn.number": senderAsn,
        "asn.organization.name": senderAsnOrg,
      },
    },

    // ─────────────────────────────────────────────────────────────────────
    // 2. THE DELIVERED-MESSAGE AUDIT — the M365 Unified Audit record of the mail
    //    reaching the inbox, carrying the payment-portal link the lure relies on.
    //    Spearphishing Link (T1566.002).
    // ─────────────────────────────────────────────────────────────────────
    {
      id: "evt_becwf_02_message_audit",
      ts: T(1 * MIN),
      source: "o365",
      vendor: "Microsoft 365 Unified Audit Log",
      event_type: "email_received",
      user_email: victim.email,
      src_ip: senderIp,
      severity: "medium",
      mitre_technique: "T1566.002",
      mitre_tactic: "Initial Access",
      incident_id: INCIDENT,
      description:
        "The Unified Audit Log recorded the wire-request message delivered to p.nair's mailbox from 102.89.44.19, with a button linking to nexacorp-finance.com/secure/beneficiary-update — the click target the wire lure depends on.",
      network: { url: paymentLink, domain: lookalikeDomain, method: "GET" },
      raw: {
        "data.office365.Operation": "TIMailData",
        "data.office365.Workload": "ThreatIntelligence",
        "data.office365.RecordType": "28",
        "data.office365.UserId": victim.email,
        "data.office365.UserType": "Regular",
        "data.office365.ClientIP": senderIp,
        "data.office365.Sender": impostorFrom,
        "data.office365.Recipients": victim.email,
        "data.office365.Subject": "URGENT: Wire Transfer Needed Today",
        "data.office365.Directionality": "Inbound",
        "data.office365.NetworkMessageId": "d5b8f1a2-7c94-4e63-b0a1-2f6c8e37a941",
        "data.office365.InternetMessageId": "<9a3f71c0-6e24-4b8d-ae15-0c7f2d914b83@mail.nexacorp-finance.com>",
        "data.office365.Url": paymentLink,
        "data.office365.UrlDomain": lookalikeDomain,
        "data.office365.UrlPath": "/secure/beneficiary-update",
        "data.office365.AttachmentName": attachmentName,
        "data.office365.AttachmentCount": "1",
        "data.office365.DeliveryAction": "Delivered",
        "data.office365.ResultStatus": "Succeeded",
        "source.ip": senderIp,
      },
    },

    // ─────────────────────────────────────────────────────────────────────
    // 3. THE LOOKALIKE-DOMAIN LOOKUP — Defender's URL/domain reputation returns
    //    the sender domain as newly registered (registered days earlier) and not
    //    the corporate domain. Attacker-registered infrastructure (T1583.001).
    // ─────────────────────────────────────────────────────────────────────
    {
      id: "evt_becwf_03_domain_reputation",
      ts: T(6 * MIN),
      source: "email_gateway",
      vendor: "Microsoft Defender for Office 365",
      event_type: "threat_intel_match",
      user_email: victim.email,
      severity: "medium",
      mitre_technique: "T1583.001",
      mitre_tactic: "Resource Development",
      incident_id: INCIDENT,
      description:
        "A domain-reputation lookup on nexacorp-finance.com returns a registration date eight days earlier, a privacy-shielded registrant, and no mail history — a young lookalike of the corporate nexacorp.com, not an owned domain.",
      network: { domain: lookalikeDomain, method: "GET" },
      raw: {
        "data.office365.Url": paymentLink,
        "data.office365.UrlDomain": lookalikeDomain,
        "data.office365.ThreatType": "Phish",
        "data.office365.DetectionMethod": "URL reputation",
        "data.office365.SenderIp": senderIp,
        "threat.name": "Lookalike sender domain",
        "threat.category": "phishing",
        "threat.id": "TI-DOMAIN-2026-0831-0091",
        "threat.url": paymentLink,
        "source.ip": senderIp,
        "asn.number": senderAsn,
        "asn.organization.name": senderAsnOrg,
      },
    },

    // ─────────────────────────────────────────────────────────────────────
    // 4. THE GENUINE CFO ACCOUNT — IS FINE. A Unified Audit review of the real
    //    david.okonkwo@nexacorp.com account over the window shows only routine
    //    sign-ins from his usual corporate address and no new mailbox rules.
    //    This is the discriminator: the CFO's real mailbox was never accessed,
    //    so this is external impersonation, not an account takeover. Benign context.
    // ─────────────────────────────────────────────────────────────────────
    {
      id: "evt_becwf_04_cfo_account_normal",
      ts: T(9 * MIN),
      source: "o365",
      vendor: "Microsoft 365 Unified Audit Log",
      event_type: "auth_success",
      user_email: cfo.email,
      user_title: cfo.title,
      src_ip: cfo.corpIp,
      geo: { country: "United States", city: "New York" },
      severity: "informational",
      description:
        "A Unified Audit review of the genuine CFO account david.okonkwo@nexacorp.com shows its recent sign-ins all from his usual New York corporate address with MFA satisfied, and no New-InboxRule or forwarding change in the window — his real mailbox was not accessed.",
      raw: {
        "data.office365.Operation": "UserLoggedIn",
        "data.office365.Workload": "AzureActiveDirectory",
        "data.office365.RecordType": "15",
        "data.office365.UserId": cfo.email,
        "data.office365.UserType": "Regular",
        "data.office365.ClientIP": cfo.corpIp,
        "data.office365.AuthenticationRequirement": "multiFactorAuthentication",
        "data.office365.ResultStatus": "Success",
        "data.office365.UserAgent":
          "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36",
        "GeoLocation.country_name": "United States",
        "GeoLocation.city_name": "New York",
        "source.ip": cfo.corpIp,
      },
    },

    // ─────────────────────────────────────────────────────────────────────
    // 5. THE DEEPFAKE PHONE CALL — a Finance fraud report in the service desk:
    //    a caller whose voice matched the CFO phoned Accounts Payable to chase
    //    the same wire, from a spoofed number, and no callback to a listed number
    //    was made. Out-of-band impersonation reinforcement (T1656).
    // ─────────────────────────────────────────────────────────────────────
    {
      id: "evt_becwf_05_fraud_report",
      ts: T(22 * MIN),
      source: "soar",
      vendor: "ServiceNow ITSM",
      event_type: "policy_modification",
      user_email: victim.email,
      severity: "high",
      mitre_technique: "T1656",
      mitre_tactic: "Defense Evasion",
      incident_id: INCIDENT,
      description:
        `Finance filed ticket ${fraudTicket}: p.nair reports a phone call from someone whose voice matched the CFO, pressing her to release the wire "before the bank cut-off". The number was not the CFO's directory number and no callback to a listed number was made.`,
      raw: {
        "servicenow.table": "incident",
        "servicenow.number": fraudTicket,
        "servicenow.short_description": "Wire request plus phone call from 'CFO' — possible payment fraud",
        "servicenow.description":
          `Accounts Payable (${victim.sam}) reports an urgent email and a follow-up phone call, both presenting as CFO David Okonkwo, pressing to release a wire today. The caller's voice sounded like the CFO and urged bypassing the normal approval, citing a bank cut-off. Call came from ${spoofedCallerNumber}, which does not match the CFO's number in the directory. Payment has been held pending verification.`,
        "servicenow.category": "Security",
        "servicenow.subcategory": "Fraud / Social Engineering",
        "servicenow.contact_type": "Phone",
        "servicenow.priority": "1 - Critical",
        "servicenow.urgency": "1 - High",
        "servicenow.impact": "2 - Medium",
        "servicenow.state": "In Progress",
        "servicenow.caller_id": victim.email,
        "servicenow.opened_by": serviceDesk,
        "servicenow.assignment_group": "Security Operations",
        "servicenow.u_identity_verification": "Caller claimed to be CFO by phone; no callback to the directory-listed number was made",
        "servicenow.u_verification_result": "Not verified",
        "servicenow.work_notes": "Payment held. Escalated to SOC to review the sending domain and the mailbox alert.",
        "servicenow.opened_at": "2026-08-31 07:52:00",
        "servicenow.sys_created_on": "2026-08-31 07:52:00",
      },
    },
  ];

  const iocs: IOC[] = [
    {
      type: "domain",
      value: lookalikeDomain, // nexacorp-finance.com — the lookalike, newly-registered sender domain
      first_seen: T(0),
      last_seen: T(22 * MIN),
      reputation: "malicious",
      tags: ["lookalike-domain", "newly-registered", "sender-domain"],
    },
    {
      type: "email",
      value: impostorFrom, // david.okonkwo@nexacorp-finance.com — the spoofed sender address
      first_seen: T(0),
      last_seen: T(22 * MIN),
      reputation: "malicious",
      tags: ["spoofed-sender", "executive-impersonation"],
    },
    {
      type: "ip",
      value: senderIp, // 102.89.44.19 — the hosting-ASN egress the mail was sent from
      first_seen: T(0),
      last_seen: T(6 * MIN),
      reputation: "malicious",
      tags: ["sending-ip", "hosting-asn"],
    },
    {
      type: "sha256",
      value: attachmentHash, // the "wire instructions" PDF attached to the fraudulent mail
      first_seen: T(0),
      last_seen: T(1 * MIN),
      reputation: "suspicious",
      tags: ["email-attachment", "wire-instructions"],
    },
  ];

  const questions: ScenarioQuestion[] = [
    {
      id: "q1",
      prompt:
        "The message presents as the CFO, but the evidence points to external impersonation rather than a takeover of the CFO's real mailbox. Which finding establishes that distinction?",
      hint: "Look at where the sender domain sits, at the SPF/DKIM/DMARC results, and at what the Unified Audit review of the genuine CFO account (evt_becwf_04) actually shows.",
      kind: "single",
      options: [
        { value: "auth_and_clean_account", label: "The mail fails authentication and rides the lookalike nexacorp-finance.com domain, while a Unified Audit review of the real CFO account shows only routine sign-ins and no new mailbox rules — his mailbox was never entered" },
        { value: "forwarding_rule_found", label: "A hidden forwarding rule was discovered on the CFO's real mailbox, proving his internal account was hijacked and used to originate the request from inside the tenant that day" },
        { value: "foreign_vpn_login", label: "The CFO's own account signed in from a foreign VPN minutes before the mail, showing the attacker was operating the executive's mailbox directly the whole time" },
        { value: "password_spray_first", label: "A run of failed logins against the CFO account appears just before the mail, indicating his password was brute-forced and then used to send it" },
      ],
      answer: "auth_and_clean_account",
      xp: 65,
      explanation:
        "A takeover means the attacker is operating the real internal mailbox; impersonation means they are only pretending to be the person from outside. Two things here settle it. First, the sending side is external and fraudulent: the mail fails SPF, DKIM and DMARC, and its sender is on nexacorp-finance.com — a lookalike of the real corporate nexacorp.com — not the CFO's genuine domain. Second, evt_becwf_04 is the discriminator: the Unified Audit review of the genuine david.okonkwo@nexacorp.com account shows only routine sign-ins from his usual corporate address and no New-InboxRule, so his real mailbox was never accessed. (b), (c) and (d) all describe a compromised-account story — a forwarding rule, a foreign sign-in, a password attack — and none of those appear anywhere in the timeline. That absence is exactly what tells you this is impersonation.",
    },
    {
      id: "q2",
      prompt:
        "The From line reads as the CFO by name. Which combination of message fields exposes the sender as spoofed rather than genuine?",
      hint: "Compare email.from.display_name against email.from.address, the envelope (email.sender.address) against the header From, and the SPF/DKIM/DMARC results.",
      kind: "single",
      options: [
        { value: "display_envelope_auth", label: "The display name shows the CFO while the real From address sits on a lookalike domain, the envelope (P1) and header (P2) senders disagree, and SPF, DKIM and DMARC all resolve to fail or none" },
        { value: "subject_urgency", label: "The subject line uses the word URGENT and demands same-day action, and an urgent tone on a payment email is on its own what marks a message as spoofed" },
        { value: "attachment_present", label: "The message carries a PDF attachment, and any finance email that arrives with an attachment instead of a link is by that fact a spoof" },
        { value: "geo_of_sender", label: "The sending IP geolocates outside the country, and a finance email whose source IP is abroad is definitively a spoofed sender" },
      ],
      answer: "display_envelope_auth",
      xp: 55,
      explanation:
        "The spoof lives in the header and authentication fields read together, not in the tone. The display name is set to \"David Okonkwo\" to catch the eye, but the actual From address is david.okonkwo@nexacorp-finance.com — a lookalike domain — and the envelope (P1) sender bounce-svc@mail.nexacorp-finance.com does not match the header (P2) From, a classic mismatch. On top of that the message fails SPF and DMARC and has no valid DKIM signature, so nothing cryptographically ties it to the domain it claims. (b), (c) and (d) each over-read a single circumstantial detail: urgency, an attachment, and a foreign IP are all common in fraud but are individually true of plenty of legitimate mail, and none of them is an authentication result. The verdict comes from the display-vs-address gap plus the P1/P2 mismatch plus the failed authentication.",
    },
    {
      id: "q3",
      prompt:
        "A day earlier the real CFO sent Accounts Payable a genuine payment email (evt_becwf_00, the control). Read against today's message, what actually separates the legitimate request from the fraudulent one?",
      hint: "Both are urgent finance emails from 'the CFO'. Compare the authentication results, the sending domain, and whether the standing approval process is followed.",
      kind: "single",
      options: [
        { value: "auth_domain_process", label: "The genuine one passes authentication, comes from the real nexacorp.com domain and cites the standing approval workflow; the fraudulent one fails authentication, uses a lookalike domain and leans on urgency to skip that workflow" },
        { value: "control_no_attachment", label: "The legitimate email carried no attachment at all, so the presence of any attached file is the single feature that separates the real request from the fraud" },
        { value: "control_after_hours", label: "The genuine message was sent after business hours and the fraud during the day, so the send time alone cleanly tells the two apart" },
        { value: "control_to_group", label: "Only the fraudulent one was addressed to a shared distribution list rather than a named person, which is what distinguishes it from the real request" },
      ],
      answer: "auth_domain_process",
      xp: 60,
      explanation:
        "This is the whole reason the control exists: both messages are urgent finance requests presenting as the CFO, so urgency and the CFO's name cannot be the signal. The real email (evt_becwf_00) passes SPF, DKIM and DMARC, originates from david.okonkwo@nexacorp.com on the corporate domain, and references the purchase order and a second approver — it runs through the standing process. Today's message fails authentication, sits on the lookalike nexacorp-finance.com domain, and pushes to release funds immediately, outside that process. (b), (c) and (d) invent differences the logs do not support and that would not generalise — attachments, send time, and recipient shape are not what makes a payment request trustworthy. Authentication, the real domain, and the process are.",
    },
    {
      id: "q4",
      prompt:
        "Finance also logged a phone call (evt_becwf_05) from someone whose voice matched the CFO, chasing the same payment. How should that call weigh in the verdict?",
      kind: "single",
      options: [
        { value: "second_channel_verify", label: "It is a second social-engineering channel — a voice clone reinforcing the email, not corroboration; verification has to use a number taken from the internal directory, never the one that placed the call" },
        { value: "voice_confirms", label: "Because the caller's voice clearly matched the CFO, the call independently confirms the request is genuine and the wire can proceed once the caller is happy" },
        { value: "voice_cannot_fake", label: "A live human voice cannot be convincingly faked, so a matching voice on the phone authenticates the payment where the email could not" },
        { value: "unrelated_close", label: "The call is a separate matter from the email alert and should be closed on its own without affecting the wire decision" },
      ],
      answer: "second_channel_verify",
      xp: 60,
      explanation:
        "Modern BEC increasingly pairs the email with an out-of-band call, and a convincing voice clone of an executive is now cheap to produce — so a matching voice is not proof of anything. The call in evt_becwf_05 is a second impersonation channel applying pressure (\"before the bank cut-off\"), and the report itself notes the number did not match the CFO's directory entry and that no callback was made. The correct move is to verify through a channel the request did not supply: call the CFO on the number listed in the internal directory, or confirm in person. (b) and (c) are exactly the trap the deepfake exploits — treating a familiar voice as authentication. (d) is wrong because the call and the email are the same fraud reinforcing itself, and the call is a reason to hold the payment, not to close a ticket.",
    },
    {
      id: "q5",
      prompt:
        "You are closing the ticket. What is the correct classification and immediate response?",
      kind: "single",
      options: [
        { value: "malicious_hold_verify_block", label: "Malicious — a fraudulent wire attempt: hold the payment, confirm the request with the CFO over a known-good channel, block the lookalike domain and sender, and brief Finance; the CFO's own account needs no reset, having never been accessed" },
        { value: "benign_release", label: "Benign — an urgent but real CFO request; release the payment once someone calls the number the caller gave back to confirm the beneficiary details are correct" },
        { value: "reset_cfo_password", label: "Treat it as an account compromise: reset the CFO's password and force MFA re-registration, which removes the attacker's access and stops the fraudulent wire at its source" },
        { value: "spam_low_priority", label: "Log it as low-priority spam, let the mail filter learn the new sender, and take no further action since the message was only a phishing email" },
      ],
      answer: "malicious_hold_verify_block",
      xp: 65,
      explanation:
        "The verdict is a malicious payment-fraud attempt, and the response follows from what the evidence is and is not. Because this is impersonation, the immediate priority is the money: hold the wire, and confirm the request directly with the CFO through a channel the attacker did not supply. Then contain the infrastructure — block the lookalike domain and the spoofed sender, submit them to the mail filter, and check whether anyone else received the lure — and brief Finance so the next urgent request is met with a callback. (b) walks straight into the fraud by trusting the attacker's own number. (c) misdirects effort: the CFO's account was never compromised (evt_becwf_04), so resetting his password fixes nothing and delays the payment hold. (d) badly under-rates an active, targeted wire-fraud attempt with a live phone component. Classify as BEC wire fraud and escalate.",
    },
  ];

  return {
    scenario_id: scenarioId,
    title: "The CFO Who Never Called — a BEC Wire-Fraud Impersonation",
    threat_actor: "Business email compromise operator (external executive impersonation, no host or mailbox foothold)",
    attack_kind: "bec_wire_fraud",
    briefing:
      "Microsoft Defender for Office 365 flagged an urgent wire-transfer email to Accounts Payable that appears to come from the CFO, and Finance filed a report about a phone call chasing the same payment. No money has moved yet. Determine whether this request is genuine before any transfer is approved, and explain what the evidence shows.",
    narrative: `This is an email-fraud case with no malware, no compromised internal mailbox, and no host to walk. At 07:30 an urgent message reached Priya Nair, an Accounts Payable specialist, pressing her to send a wire "today". The From line read "David Okonkwo" — the CFO — but the actual sender was david.okonkwo@nexacorp-finance.com. That domain is a lookalike of the real corporate nexacorp.com, registered only eight days earlier, and the message failed SPF, DKIM and DMARC: nothing tied it to the domain it claimed. The envelope sender and the header From disagreed, and Microsoft Defender for Office 365's anti-phishing raised an executive-impersonation alert — the ticket you picked up. The mail carried a "beneficiary update" PDF and a link to nexacorp-finance.com/secure/beneficiary-update.

The decisive check was on the genuine account. A Unified Audit review of the real david.okonkwo@nexacorp.com mailbox showed only routine sign-ins from his usual New York corporate address and no new inbox rules — his account was never touched. This was never a takeover; it was someone outside the company wearing the CFO's name.

Twenty minutes later Finance filed a fraud report: Nair had taken a phone call from a number that was not the CFO's, from a voice that sounded exactly like him, urging her to release the wire before a "bank cut-off". The voice was a deepfake clone — a second impersonation channel, not corroboration. A convincing voice is now cheap to synthesise, which is precisely why it cannot authenticate a payment.

The instructive comparison is the CFO's genuine payment email the day before: the same urgent-finance shape, but it passed SPF, DKIM and DMARC, came from the real nexacorp.com domain, and referenced the purchase order and a second approver — it ran through the standing approval process. Same shape, opposite verdict. The signal is never that a finance email is urgent; it is email authentication, the real domain, and the process. The right response holds the payment, verifies with the CFO on a number from the internal directory, and blocks the lookalike domain and sender — while leaving the un-compromised CFO account alone.`,
    learning_objectives: [
      "Identify a business email compromise (BEC) wire-fraud attempt from email-authentication failure (SPF/DKIM/DMARC), a display-name spoof, and an envelope-vs-header (P1/P2) sender mismatch",
      "Recognise a lookalike, newly-registered sender domain (nexacorp-finance.com against the real nexacorp.com) as attacker-registered infrastructure, and treat the sender address and domain as IOCs",
      "Distinguish external executive impersonation from a genuine internal mailbox takeover by checking whether the real executive's account shows any anomalous sign-ins or new mailbox rules",
      "Weigh a deepfake voice-clone phone call as out-of-band social pressure, and verify through a known-good, independently-sourced channel rather than the contact details the request supplies",
      "Reach and act on a malicious verdict: hold the wire, verify out-of-band, block the sender and lookalike domain, and brief Finance — without misdirecting response toward a password reset the un-compromised executive account does not need",
    ],
    alerts: [],
    events,
    iocs,
    killchain: [
      { ts: T(-26 * HOUR), phase: "Context", action: `Benign control — the real CFO (${cfo.email}) sends a genuine payment email that passes SPF/DKIM/DMARC` },
      { ts: T(0), phase: "Defense Evasion", action: `Impersonation email to ${victim.sam} — display-name spoof of the CFO from lookalike ${lookalikeDomain}, auth fail/none (T1656)` },
      { ts: T(1 * MIN), phase: "Initial Access", action: `Message delivered to the inbox with a link to ${lookalikeDomain}/secure/beneficiary-update (T1566.002)` },
      { ts: T(6 * MIN), phase: "Resource Development", action: `Domain lookup — ${lookalikeDomain} registered eight days earlier, a lookalike of ${cfo.email.split("@")[1]} (T1583.001)` },
      { ts: T(9 * MIN), phase: "Investigation", action: `Genuine CFO account reviewed — routine sign-ins only, no new inbox rules; the real mailbox was never accessed` },
      { ts: T(22 * MIN), phase: "Defense Evasion", action: `Deepfake voice-clone phone call chases the same wire from a spoofed number — out-of-band reinforcement (T1656)` },
    ],
    questions,
  };
}
