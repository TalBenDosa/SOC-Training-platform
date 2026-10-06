import type { TelemetryEvent } from "@/lib/sim/types";

// ── Event 1: USB bulk-copy DLP alert (Endpoint DLP) ─────────────────────────
const dlpUsbEvent: TelemetryEvent = {
  id: "evt-dlp-usb-001",
  ts: "2024-08-14T16:44:10.000Z",
  source: "dlp",
  vendor: "Microsoft Purview",
  event_type: "dlp_alert",
  severity: "high",
  user_email: "s.colb@nexacorp.com",
  hostname: "WS-HR-1142",
  description:
    "Endpoint DLP flagged a bulk copy of files containing U.S. Social Security Numbers to a removable USB drive",
  raw: {
    "data.office365.Operation": "DlpRuleMatch",
    "data.office365.Workload": "Endpoint",
    "data.office365.PolicyDetails.PolicyName": "PII - U.S. SSN",
    "data.office365.PolicyDetails.PolicyId": "b7e14a2c-9f31-4d88-8e2a-1c3f4a5b6d7e",
    "data.office365.PolicyDetails.Rules.RuleName": "SSN Bulk Copy to Removable Media",
    "data.office365.PolicyDetails.Rules.Actions": "BlockAccess,GenerateAlert",
    "data.office365.SensitiveInfoType.Name": "U.S. Social Security Number",
    "data.office365.SensitiveInfoType.Count": "312",
    "data.office365.SensitiveInfoType.Confidence": "92",
    "data.office365.ExfiltrationEventType": "RemovableMediaCopy",
    "data.office365.FileName": "Employee_Master_Records_2024.xlsx",
    "data.office365.FilePath": "C:\\Users\\s.colb\\Documents\\HR\\Employee_Master_Records_2024.xlsx",
    "data.office365.SourceFileSize": "4718592",
    "data.office365.DeviceName": "WS-HR-1142",
    "data.office365.UserId": "s.colb@nexacorp.com",
    "data.office365.RemovableMedia.DeviceId": "USBSTOR\\DiskSanDisk_Ultra_USB_3.0",
    "data.office365.RemovableMedia.SerialNumber": "4C531001551122117402",
    "data.office365.RemovableMedia.VolumeLabel": "SANDISK32",
    "data.office365.ActionTaken": "Blocked",
    "action_result": "blocked",
  },
};

// ── Event 2: Email-to-personal-account DLP block (Exchange/O365 DLP) ────────
const dlpEmailEvent: TelemetryEvent = {
  id: "evt-dlp-email-001",
  ts: "2024-08-16T09:12:03.000Z",
  source: "dlp",
  vendor: "Microsoft Purview",
  event_type: "dlp_block",
  severity: "high",
  user_email: "m.reyes@nexacorp.com",
  hostname: "N/A",
  description:
    "Outbound email to a personal Gmail address was blocked after DLP detected an attachment with credit card numbers",
  raw: {
    "data.office365.Operation": "DlpRuleMatch",
    "data.office365.Workload": "Exchange",
    "data.office365.PolicyDetails.PolicyName": "PCI - Credit Card Number - External Send Block",
    "data.office365.PolicyDetails.PolicyId": "e2a9c714-6b58-4a19-9d02-7f8e1b3c4d5f",
    "data.office365.PolicyDetails.Rules.RuleName": "Block CC Numbers to Non-Corp Domain",
    "data.office365.PolicyDetails.Rules.Actions": "BlockAccess,NotifySender",
    "data.office365.SensitiveInfoType.Name": "Credit Card Number",
    "data.office365.SensitiveInfoType.Count": "47",
    "data.office365.SensitiveInfoType.Confidence": "85",
    "data.office365.SensitiveInfoType.DetectedValues": "****-****-****-4927,****-****-****-1183",
    "data.office365.ExchangeMetaData.From": "m.reyes@nexacorp.com",
    "data.office365.ExchangeMetaData.To": "m.reyes.personal@gmail.com",
    "data.office365.ExchangeMetaData.Subject": "Q3 Chargeback Report - backup copy",
    "data.office365.ExchangeMetaData.Attachment": "Q3_Chargebacks_RAW.xlsx",
    "data.office365.ExchangeMetaData.AttachmentSize": "1148392",
    "data.office365.ExchangeMetaData.MessageId": "<a1b2c3d4-e5f6-7890@nexacorp.com>",
    "data.office365.ExchangeMetaData.Direction": "Outbound",
    "data.office365.ActionTaken": "Blocked",
    "data.office365.JustificationText": "",
    "data.office365.Override": "false",
    "action_result": "blocked",
  },
};

// ── Event 3 (analyst_choice): order-ID false-positive email ────────────────
const dlpFpEvent: TelemetryEvent = {
  id: "evt-dlp-fp-001",
  ts: "2024-08-19T13:27:55.000Z",
  source: "dlp",
  vendor: "Microsoft Purview",
  event_type: "dlp_alert",
  severity: "medium",
  user_email: "k.nassar@nexacorp.com",
  hostname: "N/A",
  description:
    "DLP flagged an email to a business partner domain containing 16-digit number sequences matching the credit-card pattern",
  raw: {
    "data.office365.Operation": "DlpRuleMatch",
    "data.office365.Workload": "Exchange",
    "data.office365.PolicyDetails.PolicyName": "PCI - Credit Card Number - External Send Audit",
    "data.office365.PolicyDetails.Rules.RuleName": "Audit Possible CC Numbers",
    "data.office365.PolicyDetails.Rules.Actions": "GenerateAlert",
    "data.office365.SensitiveInfoType.Name": "Credit Card Number",
    "data.office365.SensitiveInfoType.Count": "18",
    "data.office365.SensitiveInfoType.Confidence": "62",
    "data.office365.SensitiveInfoType.DetectedValues": "4102-8837-2201-0044,4102-8837-2201-0051",
    "data.office365.ExchangeMetaData.From": "k.nassar@nexacorp.com",
    "data.office365.ExchangeMetaData.To": "procurement@logisticspartner-co.com",
    "data.office365.ExchangeMetaData.Subject": "Open Purchase Orders - August Reconciliation",
    "data.office365.ExchangeMetaData.Attachment": "PO_Reconciliation_Aug2024.csv",
    "data.office365.ExchangeMetaData.Direction": "Outbound",
    "data.office365.ActionTaken": "Allowed - Alert Only",
    "data.office365.JustificationText": "",
    "action_result": "allowed",
  },
};

// ── Event 4 (analyst_choice): departing-employee cloud upload ──────────────
const dlpDepartingEvent: TelemetryEvent = {
  id: "evt-dlp-departing-001",
  ts: "2024-08-21T22:41:17.000Z",
  source: "dlp",
  vendor: "Microsoft Purview",
  event_type: "dlp_alert",
  severity: "critical",
  user_email: "d.farrow@nexacorp.com",
  hostname: "WS-SALES-0387",
  description:
    "Endpoint DLP detected a bulk upload of customer database exports to a personal Dropbox account outside business hours, two days before the user's resignation effective date",
  raw: {
    "data.office365.Operation": "DlpRuleMatch",
    "data.office365.Workload": "Endpoint",
    "data.office365.PolicyDetails.PolicyName": "Customer Data - Cloud Upload Block",
    "data.office365.PolicyDetails.Rules.RuleName": "Bulk Upload to Unsanctioned Cloud App",
    "data.office365.PolicyDetails.Rules.Actions": "GenerateAlert",
    "data.office365.SensitiveInfoType.Name": "Customer Record (Composite: Name+Email+Phone)",
    "data.office365.SensitiveInfoType.Count": "8420",
    "data.office365.SensitiveInfoType.Confidence": "88",
    "data.office365.ExfiltrationEventType": "CloudUpload",
    "data.office365.FileName": "CRM_Full_Export_Aug2024.csv",
    "data.office365.FilePath": "C:\\Users\\d.farrow\\Downloads\\CRM_Full_Export_Aug2024.csv",
    "data.office365.SourceFileSize": "22548992",
    "data.office365.DeviceName": "WS-SALES-0387",
    "data.office365.UserId": "d.farrow@nexacorp.com",
    "data.office365.CloudApp.Name": "Dropbox",
    "data.office365.CloudApp.Category": "Unsanctioned",
    "data.office365.CloudApp.UploadUrl": "https://www.dropbox.com/upload",
    "data.office365.ActionTaken": "Allowed - Alert Only",
    "data.office365.EventTimeLocal": "22:41:17",
    "action_result": "allowed",
  },
};

// ── Room: DLP Fundamentals for SOC Analysts ─────────────────────────────────
const dlpRoom = {
  id: "dlp-fundamentals",
  title: "Data Loss Prevention (DLP) for SOC Analysts",
  description:
    "Learn how Data Loss Prevention works from the SOC analyst's chair: the three DLP channels (endpoint, network, cloud/email), the sensitive-data types DLP is built to catch, how policies and classifiers score confidence, the actions DLP can take, and how to read and triage a real DLP alert. Work through Microsoft Purview / O365 DLP examples covering USB exfiltration, blocked outbound email, a classic false positive, and a genuine insider-threat escalation.",
  difficulty: "intermediate" as const,
  category: "Data Security",
  estimatedMinutes: 65,
  xp: 340,
  icon: "🔐",
  prerequisites: ["log-management"],
  tasks: [
    // ── Reading 1 ──────────────────────────────────────────────────────────
    {
      type: "reading" as const,
      id: "dlp-r1",
      heading: "What Is DLP, and Why It Matters",
      content:
        "Think about walking through airport security. There is a scanner at the gate whose entire job is to look inside your bag and flag anything that should not be leaving the secure area — a knife, a liquid over 100ml, an undeclared item. The scanner does not care who you are or whether you are a frequent flyer with a spotless record. It looks at the contents, compares them against a set of rules, and either lets the bag through, flags it for a manual check, or stops it outright.\n\n" +
        "Data Loss Prevention (DLP) is the airport bag scanner for your organization's data. Its job is to look inside outbound traffic — files copied to a USB drive, emails leaving the company, documents uploaded to a cloud service, text pasted into a browser — and decide whether that content contains something that should not be leaving in that way, to that destination, by that person. Just like the airport scanner, DLP does not primarily judge intent. It judges content. A well-meaning employee attaching the wrong spreadsheet to an email triggers the exact same technical detection as a malicious insider stealing a customer database. The content pattern is what matters to the tool; distinguishing intent is the analyst's job downstream.\n\n" +
        "Why does this matter to a SOC? Because data is the actual target of almost every attack an organization defends against. Ransomware crews steal data before they encrypt it, for double-extortion leverage. Nation-state actors exfiltrate intellectual property. Insiders — whether malicious, negligent, or simply careless — move sensitive files to the wrong place every single day. Firewalls, EDR, and identity tools protect the perimeter and the endpoint, but none of them look inside the content of a file and ask 'does this contain 300 social security numbers?' That is DLP's unique job, and it is often the last line of defense between a sensitive file and the outside world.\n\n" +
        "DLP is also a compliance requirement, not just a security nice-to-have. Regulations like PCI-DSS (credit card data), HIPAA (health records), and GDPR (EU personal data) either explicitly require or strongly imply that organizations must have controls preventing regulated data from leaving in an uncontrolled way. A DLP incident, therefore, is not only a potential security event — it can also be a reportable compliance event, which is why DLP alerts often carry more organizational weight than a typical EDR alert of the same technical severity.\n\n" +
        "One important mental model to carry forward through this room: DLP is a content-inspection control, not a behavior-inspection control. It answers 'what is in this data and where is it going?' — not 'is this user acting suspiciously?' UEBA and insider-threat platforms answer the behavior question. The best SOC investigations combine both: DLP tells you what left, and behavioral context tells you whether that departure was normal.",
      codeExample:
        "THE AIRPORT SCANNER ANALOGY\n" +
        "=============================\n\n" +
        "AIRPORT SECURITY                       DATA LOSS PREVENTION\n" +
        "-----------------                       ----------------------\n" +
        "Bag enters the scanner            -->   File/email/upload leaves a monitored channel\n" +
        "X-ray looks at CONTENTS            -->   Classifier looks at CONTENT (regex, keywords,\n" +
        "                                          fingerprints) inside the file or message\n" +
        "Compares against banned-item list  -->   Compares against sensitive-info-type patterns\n" +
        "                                          (SSN, credit card, PHI, source code, secrets)\n" +
        "Item flagged                       -->   DLP policy match\n" +
        "  - Allowed through                -->     - Audit (log only)\n" +
        "  - Manual bag check                -->     - Warn / require justification\n" +
        "  - Confiscated                     -->     - Block\n" +
        "  - Escorted to security office     -->     - Escalate to SOC / insider-threat team\n\n" +
        "KEY INSIGHT: the scanner does not know or care WHO you are or WHY you packed the\n" +
        "item. It flags based on CONTENT. Determining intent (forgot it was in there vs.\n" +
        "smuggling it deliberately) is a human decision made AFTER the flag — exactly like\n" +
        "a SOC analyst's job after a DLP alert fires.",
      checkpoint: {
        question: "During a DLP case the shift lead asks: 'Is s.colb behaving differently from her normal week?' Which tool is built to answer that, and what does DLP add instead?",
        options: [
          "UEBA answers it; DLP adds what the data contained and where it was going",
          "DLP answers it, because each policy match compares the user with her baseline",
          "DLP answers it, because Block actions are reserved for users acting unusually",
          "EDR answers it; DLP adds which malware signature matched the copied file",
        ],
        answer: 0,
        explanation: "The reading draws the line clearly: DLP is a content-inspection control that answers 'what is in this data and where is it going?', while UEBA and insider-threat platforms answer the behavior question. A DLP policy match does not compare the user with any baseline — the same match fires for a careful employee and for a thief. Block is chosen by the policy for the content and destination, not by how unusual the user is. EDR watches processes and malware, and DLP does not match malware signatures.",
      },
    },
    // ── Reading 2 ──────────────────────────────────────────────────────────
    {
      type: "reading" as const,
      id: "dlp-r2",
      heading: "The Three DLP Channels: Endpoint, Network, Cloud/Email",
      content:
        "DLP is not a single sensor — it is a family of enforcement points deployed across three distinct channels, because sensitive data can leave an organization through three very different paths. Understanding which channel generated an alert tells you immediately what kind of investigation you are about to do.\n\n" +
        "Endpoint DLP runs as an agent on the laptop or desktop itself (in Microsoft Purview this is the Endpoint DLP client baked into the standard Microsoft 365 endpoint agent; other vendors include Symantec DLP Endpoint, Forcepoint, and Digital Guardian). Endpoint DLP is unique because it can see activity that never touches the network at all: copying a file to a USB drive, printing a document, pasting sensitive text into an unauthorized application, taking a screenshot of a screen showing customer records, or dragging a file into a personal cloud-sync folder on disk. Because it lives directly on the device, endpoint DLP is the only channel that can catch 'air-gapped' exfiltration methods like USB copy or printing — no other DLP layer sees those actions.\n\n" +
        "Network DLP inspects traffic as it crosses the network boundary — historically via a dedicated network appliance or proxy inline with outbound traffic, inspecting FTP transfers, unencrypted web uploads, and generic network protocols for sensitive content signatures. Network DLP has become less dominant as more traffic moved to encrypted HTTPS and to cloud SaaS apps the network appliance cannot decrypt without a TLS-inspecting proxy in the path. It is still relevant for legacy protocols (FTP, SMTP relays outside of Exchange Online) and can be paired with a web proxy/CASB doing SSL inspection to give it visibility into HTTPS uploads.\n\n" +
        "Cloud / Email DLP is where most modern enterprise DLP activity actually lives today, because most exfiltration now happens through SaaS applications the organization already controls: Exchange Online (email), SharePoint and OneDrive (file sharing and sync), Microsoft Teams (chat and file share), and third-party SaaS connected via a CASB (Cloud Access Security Broker) like Microsoft Defender for Cloud Apps. Because these are the organization's own managed cloud services, DLP can inspect content natively — no decryption or inline interception required. Microsoft Purview DLP (the primary example used throughout this room) enforces policies across Exchange, SharePoint, OneDrive, Teams, and the Endpoint client all from a single policy engine, which is why its logs use one unified schema (data.office365.* fields) regardless of which of these workloads generated the event.\n\n" +
        "A practical takeaway for triage: the Workload field in a Purview DLP log (Endpoint, Exchange, SharePoint, Teams) immediately tells you the channel, and the channel narrows your investigation. An Endpoint / RemovableMediaCopy event means physical media — check the USB device serial and ask whether this user has a legitimate reason to move data offline. An Exchange event means email — check the recipient domain first, since internal-to-internal email matching a DLP policy is a very different risk than external send. A SharePoint or Teams event usually means an external share link was created — check who the share was granted to and whether the link is anonymous/anyone-with-the-link.",
      codeExample:
        "THE THREE DLP CHANNELS\n" +
        "========================\n\n" +
        "CHANNEL              WHAT IT SEES                          EXAMPLE EXFIL METHODS\n" +
        "--------              -------------                          ----------------------\n" +
        "Endpoint DLP          Local device activity, before          USB copy, printing,\n" +
        "(agent on the         anything touches the network           clipboard paste, screenshot,\n" +
        " laptop/desktop)                                             local sync-folder drag\n\n" +
        "Network DLP           Traffic crossing the network           FTP upload, unencrypted\n" +
        "(inline appliance     boundary (legacy protocols, or         web upload, SMTP relay\n" +
        " or proxy)            HTTPS if paired with SSL inspection)   outside managed email\n\n" +
        "Cloud / Email DLP     Content inside the organization's      Email to external domain,\n" +
        "(native SaaS          own managed SaaS platforms             SharePoint/OneDrive external\n" +
        " integration)         (Exchange, SharePoint, Teams,          share link, Teams file share,\n" +
        "                      third-party via CASB)                 CASB-monitored SaaS upload\n\n" +
        "MICROSOFT PURVIEW: ONE POLICY ENGINE, ONE SCHEMA\n" +
        "==================================================\n" +
        "  data.office365.Workload = \"Endpoint\"     -> USB / print / clipboard / screenshot\n" +
        "  data.office365.Workload = \"Exchange\"     -> outbound / inbound email\n" +
        "  data.office365.Workload = \"SharePoint\"   -> file share / external link created\n" +
        "  data.office365.Workload = \"OneDrive\"     -> personal cloud sync / share\n" +
        "  data.office365.Workload = \"Teams\"        -> chat message / file share in Teams\n\n" +
        "  Same field, same policy engine, different Workload value -> tells you the channel\n" +
        "  in one glance, before you read a single other field.",
    },
    // ── Reading 3 ──────────────────────────────────────────────────────────
    {
      type: "reading" as const,
      id: "dlp-r3",
      heading: "Sensitive Data Types: What DLP Is Built to Catch",
      content:
        "DLP policies are only as good as the sensitive-data types they are configured to detect. Every major DLP platform ships with a library of built-in classifiers for the most commonly regulated data categories, and understanding these categories helps you interpret an alert's actual business risk the moment you see which SensitiveInfoType matched.\n\n" +
        "PII (Personally Identifiable Information) is the broadest category: names, addresses, dates of birth, national ID numbers, U.S. Social Security Numbers, passport numbers, driver's license numbers. PII is regulated in nearly every jurisdiction (GDPR in the EU, various U.S. state privacy laws, PIPEDA in Canada) and is the single most common DLP match category in most organizations simply because HR, sales, and support teams handle it constantly as part of normal business.\n\n" +
        "PCI data refers specifically to payment card information regulated under the PCI-DSS standard: primary account numbers (16-digit credit card numbers), CVV codes, and cardholder names in combination with the card number. PCI matches carry heavy compliance weight — a confirmed PCI data leak can trigger mandatory breach notification and card-network fines, which is why PCI policies are very commonly configured to Block rather than merely Audit.\n\n" +
        "PHI (Protected Health Information) covers medical records, diagnosis codes, patient names linked to treatment information, insurance IDs, and prescription data, regulated under HIPAA in the U.S. and equivalent health-privacy laws elsewhere. PHI classifiers often look for a combination of a patient identifier plus a medical term or diagnosis code, since a diagnosis code alone or a name alone is not enough to constitute PHI — DLP engines increasingly require this kind of 'compound evidence' to raise confidence.\n\n" +
        "Source code and intellectual property is a category that is harder to detect with simple pattern matching, because code does not have a fixed format like a credit card number. Detection typically relies on file extension (.py, .java, .cpp, .sql), keyword density (import, function, class, proprietary code comments), or — most reliably — document fingerprinting, where the organization registers specific documents (design documents, templates, or with some vendors actual source files) as a fingerprint baseline and DLP flags any file that substantially reuses that registered content.\n\n" +
        "Secrets and credentials — API keys, private keys, database connection strings, cloud access tokens, passwords in plaintext — are an increasingly important DLP category because a leaked secret can be immediately weaponized by anyone who finds it, unlike a leaked PII record which usually requires further exploitation. Detection uses regex patterns matched to the specific format of well-known key types (AWS access keys begin with AKIA, private key files contain a distinctive -----BEGIN PRIVATE KEY----- header, etc.) combined with file names like .env, .pem, id_rsa, or config files known to store credentials.\n\n" +
        "A SOC analyst reading an alert should always ask: which category matched, and what does that category imply about downstream risk if this data actually left? A PCI match implies regulatory reporting obligations. A secrets match implies an immediate need to rotate the exposed credential regardless of intent. A source-code match implies competitive/IP risk that may need legal involvement. The SensitiveInfoType field is therefore one of the highest-value fields in any DLP alert.",
      codeExample:
        "SENSITIVE DATA TYPE REFERENCE\n" +
        "================================\n\n" +
        "CATEGORY          EXAMPLES                              TYPICAL REGULATION\n" +
        "---------          --------                              -------------------\n" +
        "PII                SSN, passport #, DOB, home address    GDPR, state privacy laws\n" +
        "PCI                Credit card PAN, CVV, cardholder name PCI-DSS\n" +
        "PHI                Diagnosis codes, patient + treatment  HIPAA\n" +
        "Source Code / IP   .py/.java/.sql files, design docs     Internal IP policy\n" +
        "Secrets            API keys (AKIA...), private keys,     Internal security policy\n" +
        "                   .env / .pem / connection strings\n\n" +
        "WHY THE CATEGORY MATTERS TO YOUR INVESTIGATION\n" +
        "=================================================\n" +
        "  PCI match      -> compliance reporting risk, often auto-BLOCK policy\n" +
        "  PHI match      -> HIPAA breach-notification risk if confirmed\n" +
        "  Secrets match  -> rotate the credential immediately, regardless of intent\n" +
        "  Source code    -> competitive/IP risk, may need legal + engineering leadership\n" +
        "  PII (general)  -> most common, usually lower urgency unless volume is large",
      checkpoint: {
        question: "A Secrets match fires on a .env file a developer uploaded to a personal cloud folder; it contains an AWS access key (the kind that begins AKIA). The developer says it was an accident. Per the reading, what is the immediate priority?",
        options: [
          "Rotate the exposed key now, whatever the developer's intent turns out to be",
          "Confirm intent with HR first, since an accident needs no technical action",
          "Check the confidence score; below 85, a single key match needs no action",
          "Coach the developer and close, because the upload was clearly accidental",
        ],
        answer: 0,
        explanation: "The reading is explicit: a secrets match means rotating the exposed credential regardless of intent, because anyone who finds a leaked key can use it immediately. Intent still matters for how the developer is treated, but it does not make the key safe again. Keys have a fixed, recognisable format (AWS access keys begin AKIA), so a match is rarely a coincidence, and a lower score is no reason to leave a real key active. Coaching comes after rotation, not instead of it.",
      },
    },
    // ── Reading 4 ──────────────────────────────────────────────────────────
    {
      type: "reading" as const,
      id: "dlp-r4",
      heading: "How DLP Classifiers Work: Regex, Keywords, Fingerprinting, and Confidence",
      content:
        "Every DLP alert is the output of a content classifier making a probabilistic judgment, and understanding the mechanics behind that judgment is essential for triage — because the classification method directly determines how much you should trust a single alert.\n\n" +
        "The simplest and oldest method is regex (regular expression) pattern matching. A credit card number classifier looks for a 16-digit sequence matching known card issuer prefixes (4 for Visa, 5 for Mastercard) and validates the number against the Luhn checksum algorithm — the same math used by payment processors to catch typos. A U.S. SSN classifier looks for the XXX-XX-XXXX format. Regex is fast and reliable for data with a truly fixed structure, but it is also the source of most false positives: any 16-digit number that happens to pass the Luhn check (an order ID, an invoice number, a tracking number) can trigger a credit-card match even though it has nothing to do with payment data.\n\n" +
        "Keyword and proximity matching adds context around a regex match to raise or lower confidence. A 9-digit number alone might be a phone extension, a case number, or an SSN. If that number appears near the words 'Social Security', 'SSN', or 'Employee ID' within a defined proximity window, confidence increases significantly. This is why compound sensitive-info-types (like PHI, which typically requires a patient identifier AND a medical term) are more reliable than single-pattern types.\n\n" +
        "Two related but DIFFERENT methods recognize the organization's own content instead of guessing at a pattern. Document fingerprinting builds a hash-based signature from a registered document — in Microsoft Purview, typically a standard form or template such as a blank patent application or HR intake form — and flags outgoing files that reuse that document's text, even after someone fills the form in. Exact Data Match (EDM) works on structured data instead: the organization uploads a table of real sensitive values (for example, the actual customer database), DLP stores only hashes of each row's values, and an outgoing file matches when it contains those exact values (e.g. a real customer's account number together with that same customer's name). Both are precise but operationally expensive to set up. EDM is what lets DLP say 'this file contains OUR customer records' rather than merely 'this file contains something that looks like a customer record'; fingerprinting is what lets it say 'this is one of OUR standard forms.'\n\n" +
        "Machine learning / trainable classifiers are the newest method, used by Microsoft Purview's trainable classifiers and similar features in other platforms. Instead of a human writing a regex, the classifier is trained on hundreds of sample documents that are confirmed sensitive and hundreds that are confirmed not sensitive (e.g., 'resumes' or 'source code' as a document type), and it learns to recognize the pattern statistically. This helps with data types that have no fixed structure at all, like legal contracts or financial statements.\n\n" +
        "Whichever method is used, the classifier outputs a confidence score (commonly expressed 0-100 in Purview logs via SensitiveInfoType.Confidence), and most organizations configure policies with a minimum confidence threshold and often a minimum match COUNT before an action fires — for example, 'block only if confidence is 85 or higher AND at least 10 instances are found in the same document', which filters out the single stray number that happens to match a pattern by coincidence. As a SOC analyst, always check both the confidence score and the match count together: a single low-confidence match is a strong false-positive candidate, while a high-confidence match with hundreds of instances (like the 312-SSN USB event you will analyze shortly) is a strong true-positive candidate.",
      codeExample:
        "DLP CLASSIFIER CONFIDENCE MODEL\n" +
        "==================================\n\n" +
        "METHOD                  HOW IT WORKS                        RELIABILITY\n" +
        "-------                  -------------                        -------------\n" +
        "Regex pattern            Fixed format match (e.g. 16 digits   Fast, but prone to\n" +
        "                         + Luhn checksum)                     false positives\n\n" +
        "Keyword proximity        Regex match + nearby context words   Raises confidence,\n" +
        "                         ('SSN', 'Social Security')           reduces false positives\n\n" +
        "Document fingerprinting  Hash signature of a registered       High confidence for that\n" +
        "                         document / standard form (template)  form, setup per template\n\n" +
        "Exact Data Match (EDM)   Hashed rows of a real structured     Very high confidence,\n" +
        "                         dataset (e.g. customer table)        operationally heavy to set up\n\n" +
        "Trainable classifier /   Statistical model trained on real    Good for unstructured\n" +
        "ML                       sensitive vs. non-sensitive samples  data types (contracts, code)\n\n" +
        "READING THE CONFIDENCE + COUNT TOGETHER\n" +
        "==========================================\n" +
        "  Confidence: 92   Count: 312    -->  Strong true-positive signal\n" +
        "  Confidence: 62   Count: 18     -->  Investigate — could be an\n" +
        "                                      order-ID / non-PCI numeric pattern\n" +
        "  Confidence: 55   Count: 1      -->  Likely false positive, low priority\n" +
        "  Confidence: 95   Count: 1      -->  High-confidence single match, e.g. a\n" +
        "                                      fingerprinted secret — still worth checking\n\n" +
        "Policy example: \"Block if Confidence >= 85 AND Count >= 10\" -- this threshold\n" +
        "logic is exactly why the same SensitiveInfoType can be Audit-only in one policy\n" +
        "and auto-Block in another.",
    },
    // ── Question 1 ────────────────────────────────────────────────────────
    {
      type: "question" as const,
      id: "dlp-q1",
      question:
        "Which DLP channel is the ONLY one capable of detecting a user copying a sensitive file directly to a USB thumb drive?",
      options: [
        "Network DLP, because a USB-attached drive is just another egress path covered by its inspection of outbound traffic",
        "Cloud/Email DLP, because Purview connectors log file-copy activity from any device signed in to the tenant",
        "Endpoint DLP, because its on-device agent sees local file activity that never touches the network or a cloud workload",
        "Network and Endpoint DLP together, because the endpoint agent relays USB events through the gateway for inspection",
      ],
      answer: 2,
      explanation:
        "USB copy is a local, on-device action — the file never crosses the network boundary and never touches a cloud/SaaS workload. Only Endpoint DLP, running as an agent directly on the laptop or desktop, can see this activity (along with printing, clipboard paste, and screenshots). Network DLP and Cloud/Email DLP have no visibility into purely local, offline activity.",
      xp: 20,
    },
    // ── Reading 5 (policies, actions, alert anatomy) ─────────────────────────
    {
      type: "reading" as const,
      id: "dlp-r5",
      heading: "DLP Actions: Audit, Warn/Justify, Block, and Encrypt",
      content:
        "Once a DLP policy matches content, the platform must decide what to actually DO about it. Every major DLP platform offers a small set of standard enforcement actions, and understanding the escalation ladder between them is essential for interpreting how seriously an organization treats a given policy — and for knowing what response options are even available to you as an analyst.\n\n" +
        "Audit (log only) is the lightest action. The policy match is recorded, an alert may be generated for the SOC/compliance team to review, but the user's action is NOT interrupted — the email sends, the file uploads, the USB copy completes. Audit mode is commonly used when a policy is first deployed (to observe real-world match volume and tune confidence thresholds before enforcing) or for lower-risk data categories where the organization wants visibility without disrupting business workflows. The order-ID false-positive example later in this room used exactly this action: 'Allowed - Alert Only.'\n\n" +
        "Warn / Justify sits in the middle. The user's action is paused with a pop-up (in Outlook, a policy tip appears before the email sends) informing them that the content appears to match a sensitive-data policy. The user can then choose to cancel the action, or override it — often required to type a business justification ('This is an approved vendor data share, ticket #4471') before the system allows the action to proceed. This creates a paper trail: the JustificationText field in Purview logs captures exactly what the user typed, which is gold for an investigator trying to distinguish a well-meaning override from a suspicious one.\n\n" +
        "Block is the hardest technical control: the action is stopped outright. The email bounces back to the sender with a non-delivery notice referencing the policy. The USB copy operation fails with a Windows access-denied style error. The cloud upload is rejected. Block is reserved for the highest-risk combinations — a common real-world default is to Block PCI or PHI data leaving to an external/non-corporate domain, while only Auditing or Warning on lower-risk PII patterns internally.\n\n" +
        "Encrypt is a distinct fourth action available on some channels (particularly email): rather than blocking the message outright, the DLP policy automatically applies Microsoft Purview Message Encryption (or an equivalent) to the outbound email, allowing the business communication to proceed but ensuring only the intended, authenticated recipient can open it. This is common for legitimate regulated data that MUST be sent externally as part of business (e.g., sending a signed contract with PII to a partner) — the policy adds protection instead of stopping the workflow.\n\n" +
        "For a SOC analyst, the action taken (visible in the ActionTaken field) is one of the fastest signals for triage priority. A Blocked event means the data did NOT leave — your investigation is about intent and policy tuning, not about active data loss. An Allowed - Alert Only event on a high-value data type means the data DID leave and your investigation is now about consequence, not prevention. This single distinction should shape how urgently you escalate.",
      codeExample:
        "DLP ACTION ESCALATION LADDER\n" +
        "===============================\n\n" +
        "  AUDIT              WARN / JUSTIFY         BLOCK              ENCRYPT\n" +
        "  ----------         ----------------       ----------         ---------\n" +
        "  Log only,          User sees policy       Action is          Message is\n" +
        "  action proceeds    tip, may override      stopped entirely   auto-protected,\n" +
        "  unimpeded          with justification      (email bounces,    action proceeds\n" +
        "                     text captured           USB write fails)   with protection\n\n" +
        "  Used for:          Used for:               Used for:          Used for:\n" +
        "  - New policies     - Medium-risk data      - PCI/PHI to       - Legit regulated\n" +
        "    being tuned        needing a paper          external           data that MUST\n" +
        "  - Low-risk           trail                    domain             go out (signed\n" +
        "    PII patterns     - Internal PII          - Secrets/keys       contracts, etc.)\n" +
        "                       moves                   detected\n\n" +
        "TRIAGE SIGNAL FROM ActionTaken FIELD:\n" +
        "  \"Blocked\"               -> data did NOT leave. Investigate INTENT / tune policy.\n" +
        "  \"Allowed - Alert Only\"  -> data DID leave. Investigate CONSEQUENCE, escalate faster.\n" +
        "  \"Allowed - Overridden\"  -> user saw the warning and chose to proceed anyway.\n" +
        "                             Check JustificationText immediately.",
      checkpoint: {
        question: "A DLP event shows ActionTaken = 'Allowed - Overridden'. What happened, and which field should you read first?",
        options: [
          "The user saw a policy tip and chose to proceed — read JustificationText",
          "The policy was in audit mode, so no tip was shown — read the Confidence score",
          "An admin released the blocked message afterwards — read the PolicyId",
          "The transfer was blocked, then retried successfully — read the device serial",
        ],
        answer: 0,
        explanation: "'Allowed - Overridden' is the Warn/Justify outcome: the user was paused by a policy tip, chose to override it, and usually had to type a business reason that Purview stores in JustificationText — the first thing to read. Audit mode never shows the user anything and is logged as 'Allowed - Alert Only'. An admin releasing a message is a separate workflow, and a block followed by a retry would appear as a Blocked event plus a separate later event.",
      },
    },
    // ── Reading 6 (investigation + insider overlap) ──────────────────────────
    {
      type: "reading" as const,
      id: "dlp-r6",
      heading: "Investigating a DLP Alert: Malicious, Well-Meaning, or False Positive?",
      content:
        "A DLP alert tells you WHAT matched and WHERE it was headed. It does not tell you WHY. Every DLP investigation is ultimately an exercise in reconstructing intent from indirect evidence, and every alert falls into one of three buckets: malicious exfiltration, a well-meaning employee doing their job clumsily, or a false positive where the classifier matched content that is not actually sensitive.\n\n" +
        "Start with the content match itself. Check the SensitiveInfoType, the Confidence score, and the Count. A low-confidence, single-instance match on a common numeric pattern (an order ID, a tracking number, an internal ticket number) is the classic false-positive shape — this is exactly the order-ID example you will analyze later in this room. A high-confidence match with a large count of a genuinely regulated data type (hundreds of real SSNs, a full customer table) is much more likely to be a genuine sensitive-data event, regardless of intent.\n\n" +
        "Next, check the destination. Internal-to-internal movement (an email between two corporate addresses, a file share to a colleague in the same tenant) is inherently lower risk than movement to an external domain, a personal webmail address, or an unsanctioned cloud app (a personal Dropbox or Gmail account is a much stronger signal than a known business-partner domain). The recipient domain is often the single fastest way to separate 'routine business process' from 'exfiltration.'\n\n" +
        "Then check the user context: role, department, and normal behavior baseline. Does this user's job function plausibly explain handling this data type? An HR employee handling employee SSNs is expected; a warehouse-logistics employee handling SSNs is not. Is the volume and timing consistent with normal work (business hours, typical file sizes for this role) or anomalous (bulk export at 10 PM, far larger than the person's usual file sizes)? This is exactly where DLP overlaps with insider-threat and UEBA tooling — a single DLP event in isolation is rarely enough to prove malicious intent, but a DLP event correlated with HR context (a resignation on file, a performance improvement plan, a recent role change) or behavioral anomalies (off-hours access, unusual data volume, first-time destination) meaningfully raises the suspicion level.\n\n" +
        "Finally, check for a justification or a ticket. If the user was prompted and typed a business justification, read it — a specific, verifiable justification ('Sending signed NDA to vendor per ticket #4471') is reassuring; a vague or absent justification is not. Check whether IT or the business unit has any record of an approved data-sharing agreement with the destination.\n\n" +
        "Putting this together, the standard DLP triage flow is: (1) assess the content match quality, (2) assess the destination risk, (3) assess the user/behavioral context, (4) check for justification/authorization, (5) render a verdict — false positive, well-meaning employee (educate/coach), or malicious/high-risk (escalate to insider-threat team, HR, and/or legal, and consider containment such as account/device isolation). The insider-threat overlap is real and important: DLP is frequently the FIRST signal that surfaces an insider-threat case, but DLP alone almost never proves malicious intent — it takes the combination of content, destination, and behavioral/HR context to get there.",
      codeExample:
        "DLP TRIAGE DECISION FRAMEWORK\n" +
        "================================\n\n" +
        "STEP 1: CONTENT MATCH QUALITY\n" +
        "  Confidence + Count high, genuine regulated type  --> raises suspicion\n" +
        "  Confidence low, count 1, generic numeric pattern  --> false-positive candidate\n\n" +
        "STEP 2: DESTINATION RISK\n" +
        "  Internal <-> Internal                              --> lower risk\n" +
        "  External but known business-partner domain         --> moderate, verify relationship\n" +
        "  Personal webmail / unsanctioned cloud app           --> high risk\n\n" +
        "STEP 3: USER / BEHAVIORAL CONTEXT\n" +
        "  Role plausibly explains handling this data          --> lower risk\n" +
        "  Off-hours, unusual volume, first-time destination   --> higher risk\n" +
        "  HR flags present (resignation, PIP, role change)    --> higher risk\n" +
        "  --> THIS is where DLP overlaps with UEBA / insider-threat tooling\n\n" +
        "STEP 4: JUSTIFICATION / AUTHORIZATION\n" +
        "  Specific, verifiable justification + ticket         --> reassuring\n" +
        "  Vague, absent, or contradicted by HR/IT records      --> escalate\n\n" +
        "STEP 5: VERDICT\n" +
        "  False Positive        -> tune policy, close, no user action needed\n" +
        "  Well-Meaning Employee -> coach/educate, document, close\n" +
        "  Malicious / High-Risk -> escalate to insider-threat team, HR, legal;\n" +
        "                           consider account/device containment",
    },
    // ── Question 2 ────────────────────────────────────────────────────────
    {
      type: "question" as const,
      id: "dlp-q2",
      question:
        "A DLP alert shows SensitiveInfoType.Name = \"Credit Card Number\", Confidence = 58, Count = 1, for an internal email between two corporate employees. What is the MOST LIKELY explanation, and what should you check first?",
      options: [
        "A malicious insider staging card data — the match itself indicates intent, so escalate to the insider-threat team before reviewing the document",
        "Likely a false positive — one low-confidence match in internal mail fits a coincidental number such as an order ID; check the detected value and document context first",
        "A confirmed PCI exposure — any card-type match requires regulator notification and legal review regardless of confidence, so open a breach case before triage",
        "Low risk by design — internal-to-internal mail is outside DLP scope, so close the alert and tune the policy to exclude internal recipients",
      ],
      answer: 1,
      explanation:
        "Low confidence (58) plus a single match (Count=1) plus an internal-to-internal destination is the textbook false-positive shape: a numeric pattern that coincidentally passed a Luhn-style check without actually being a real card number (an order ID, invoice number, or tracking number are common culprits). The correct next step is to check the actual DetectedValues and surrounding text, not to assume malicious intent or to assume compliance impact — both extremes skip the verification step that separates a real PCI event from noise.",
      xp: 25,
    },
    // ── Log Analysis 1: USB bulk copy ────────────────────────────────────
    {
      type: "log_analysis" as const,
      id: "dlp-la1",
      heading: "Endpoint DLP: Investigating a USB Bulk-Copy Alert",
      context:
        "You are triaging a high-severity DLP alert in Microsoft Purview. An HR employee's workstation (WS-HR-1142) generated an Endpoint DLP block when a large file was copied to a USB drive. Read the raw event carefully and answer the questions about what this event tells you.",
      event: dlpUsbEvent,
      questions: [
        {
          question:
            "The event shows SensitiveInfoType.Count = 312 and SensitiveInfoType.Confidence = 92, for SensitiveInfoType.Name = \"U.S. Social Security Number\". How should you interpret this combination?",
          options: [
            "A strong true-positive signal — the file very likely holds a real bulk set of SSNs",
            "A false-positive signal — 312 near-identical hits usually means one ID column repeating",
            "The count is what matters — confidence reflects the policy's threshold, not each match",
            "The confidence is what matters — a high count simply reflects the file's large size",
          ],
          answer: 0,
          explanation:
            "High confidence (92) means the classifier is very sure each individual match is a genuine SSN (likely reinforced by keyword proximity like 'Employee ID' or 'SSN' column headers). A high count (312) means this is not an isolated coincidence — it strongly suggests a genuine bulk dataset of real employee records, consistent with the file name Employee_Master_Records_2024.xlsx. Together, these are the classic shape of a true positive on a genuinely sensitive bulk-data file. A repeating ID column would normally score low confidence, not 92. Confidence is the classifier's certainty about each match, not a policy setting, and a large file with no SSNs would still count zero matches — read the two fields together, as the reading's confidence-plus-count table does.",
          xp: 25,
        },
        {
          question:
            "The field data.office365.ActionTaken shows \"Blocked\" and data.office365.RemovableMedia.SerialNumber is populated with a specific USB device serial number. What does this tell you about both the outcome AND your next investigative step?",
          options: [
            "Close as coached — Blocked means no data left, so there is nothing more to check",
            "The copy failed, but the attempt still needs a why, and the serial identifies the drive",
            "Treat it as active data loss — Blocked means the alert fired, not that the copy stopped",
            "Reset the user's password first — a blocked bulk copy implies a compromised account",
          ],
          answer: 1,
          explanation:
            "Blocked confirms the data did not successfully leave via this attempt — that lowers urgency around active data loss, but it does NOT close the investigation. A blocked attempt to bulk-copy 312 SSNs off an HR workstation still warrants understanding intent: was this an authorized data migration, a mistaken habit, or a deliberate attempt that will simply be retried through another channel? The USB serial number is valuable for correlating whether this same device has been used before, and for asset/device-control follow-up (e.g., is USB write access appropriately restricted for this role going forward). Closing on 'Blocked' alone skips the intent question. Blocked does mean the write failed, so this is not active data loss. And nothing here suggests a compromised account — the copy ran on s.colb's own workstation from her own profile — so a password reset is not the first move.",
          xp: 25,
        },
        {
          question:
            "Given that this is an HR employee (s.colb@nexacorp.com) on an HR workstation, moving a file literally named Employee_Master_Records_2024.xlsx, what should be your FIRST triage step before assuming malicious intent?",
          options: [
            "Escalate to the insider-threat team now, since bulk PII moved by anyone is a red flag",
            "Check for an approved HR task — a migration ticket or manager sign-off — for this copy",
            "Close it as expected activity, since HR staff handle employee master records daily",
            "Isolate WS-HR-1142 first, then work out whether the copy was legitimate or not",
          ],
          answer: 1,
          explanation:
            "Role context matters here: an HR employee handling the employee master file is plausible as normal work, so the first step is to check internal records — an approved HR migration, backup or vendor transfer, ideally with a ticket or manager sign-off — before concluding anything. Escalating straight to the insider-threat team skips that cheap check and treats a likely job task as a threat. Closing it because she works in HR assumes the answer; HR staff can misuse data too. Isolating the workstation is containment for a confirmed threat, and this copy was already blocked.",
          xp: 20,
        },
      ],
    },
    // ── Log Analysis 2: email to personal Gmail blocked ──────────────────
    {
      type: "log_analysis" as const,
      id: "dlp-la2",
      heading: "Exchange DLP: Investigating a Blocked Email to a Personal Account",
      context:
        "A DLP alert fires showing an outbound email from a finance employee was blocked before it left the organization. Review the event and determine what the fields reveal about the risk and the appropriate next step.",
      event: dlpEmailEvent,
      questions: [
        {
          question:
            "The recipient field shows data.office365.ExchangeMetaData.To = \"m.reyes.personal@gmail.com\" while the sender is \"m.reyes@nexacorp.com\". Why is this specific detail significant to your investigation?",
          options: [
            "Little — once the email is Blocked, the recipient address adds nothing to triage",
            "It looks like the sender's own personal account: company data moved to personal storage",
            "It suggests a reply-to phishing trick, so check the sender's mailbox rules first",
            "It points to account compromise — attackers often send data to lookalike addresses",
          ],
          answer: 1,
          explanation:
            "The naming pattern 'm.reyes.personal@gmail.com' strongly suggests this is the sender's own personal email account, not a third-party recipient. This is one of the most common DLP scenarios in real SOC work: employees moving files to personal accounts for convenience ('I want to work on this at home this weekend') without malicious intent, but which still constitutes an unauthorized data transfer outside company control and a genuine policy violation worth documenting and coaching, even when it is not theft. The destination still matters after a block, because it shows what the user was trying to do. Nothing in the event points to phishing or a mailbox rule — the message was composed and sent by m.reyes — and an address built on the sender's own name fits self-forwarding far better than an attacker's drop box.",
          xp: 25,
        },
        {
          question:
            "The subject line reads \"Q3 Chargeback Report - backup copy\" and the attachment contains 47 credit card number matches at 85% confidence. What does the phrase 'backup copy' in the subject line suggest about likely intent, and how should that shape (not replace) your investigation?",
          options: [
            "It settles the case as benign, so close the alert without any further steps",
            "It hints at a benign motive, but verify there is no pattern and coach the user",
            "It is irrelevant, because the attachment content and destination are what count",
            "It is a known evasion phrase, so treat the email as confirmed exfiltration",
          ],
          answer: 1,
          explanation:
            "Self-authored context clues like an honest subject line ('backup copy') are meaningful evidence that shifts probability toward benign intent, but they are not proof and should not end the investigation on their own. The correct approach is to weigh this alongside other signals (is this a one-time event or a pattern? does the employee have a history of similar attempts? what does company policy say about handling PCI data?) and to use it as a coaching opportunity — the block already prevented the actual data loss, so the remaining work is about policy compliance and education, not incident containment. Calling the subject line irrelevant throws away the user's own stated reason, and there is no basis for treating the word 'backup' as an evasion keyword.",
          xp: 20,
        },
      ],
    },
    // ── Analyst Choice 1: order-ID false positive ─────────────────────────
    {
      type: "analyst_choice" as const,
      id: "dlp-ac1",
      heading: "Verdict: PCI Data Leak or False Positive?",
      scenario:
        "k.nassar@nexacorp.com, a procurement coordinator, sent a purchase-order reconciliation spreadsheet to procurement@logisticspartner-co.com — a known, existing business partner the company has worked with for three years. Microsoft Purview's DLP flagged the email as a possible Credit Card Number match: 18 instances at 62% confidence, all appearing in a column of 16-digit numbers. The action taken was 'Allowed - Alert Only' since the policy is currently in audit mode for this rule. What is your verdict?",
      event: dlpFpEvent,
      correct_verdict: "false_positive",
      explanation:
        "This is a textbook false positive. Three signals converge: (1) confidence is only 62%, well below the high-confidence range (85+) typically required for genuine PCI matches; (2) the recipient is a long-standing, known business partner receiving a purchase-order reconciliation document, which is exactly the kind of file that legitimately contains 16-digit numeric identifiers (PO numbers, invoice numbers) that can coincidentally pass a Luhn-style checksum; (3) the sample DetectedValues (4102-8837-2201-0044, 4102-8837-2201-0051) share the same 12-digit prefix and differ only in a small sequential suffix — the shape of consecutive PO or invoice numbers, not of unrelated customers' card numbers. (Note that audit mode itself is not evidence either way: it is an admin deployment choice, not a judgement by the classifier.) The correct action is to review the actual DetectedValues, confirm they are PO/invoice numbers rather than real card numbers, and consider tuning the classifier or the confidence threshold to reduce this kind of noise for procurement workflows.",
      fp_trap:
        "It is tempting to treat any 'Credit Card Number' match as automatically serious because PCI carries heavy compliance weight. But the confidence score (62, well below a typical 85+ block threshold), the sequential, PO-like DetectedValues, and the legitimate business relationship with the recipient all point to a coincidental numeric pattern — not real cardholder data. Escalating every PCI-labeled alert without checking confidence and context wastes analyst time and trains the business to ignore DLP alerts as noise.",
      xp: 30,
    },
    // ── Analyst Choice 2: departing employee cloud upload ─────────────────
    {
      type: "analyst_choice" as const,
      id: "dlp-ac2",
      heading: "Verdict: Routine Cloud Backup or Insider Threat Exfiltration?",
      scenario:
        "d.farrow@nexacorp.com, a sales account manager, uploaded a file named CRM_Full_Export_Aug2024.csv containing 8,420 customer records (name, email, phone) to a personal Dropbox account at 10:41 PM — well outside business hours. The DLP policy is currently in audit mode ('Allowed - Alert Only'), so the upload succeeded. The DLP event itself carries no HR data, so you looked the user up separately in the HR system: it shows this employee resigned and is in their notice period, with a termination date of 2024-08-23 — two days after this event. What is your verdict?",
      event: dlpDepartingEvent,
      correct_verdict: "escalate",
      explanation:
        "This should be escalated immediately to the insider-threat team, HR, and legal. Every risk signal is pointing the same direction: a large-volume export of the FULL customer database (not a routine subset), sent to an unsanctioned personal cloud app (not an approved business tool), at 10:41 PM outside business hours (atypical timing), by an employee who is two days from their last day (a classic insider-threat window — departing employees account for a large share of real-world data-theft cases). No single signal alone would necessarily justify escalation, but the combination of content (full customer DB), destination (personal Dropbox), timing (off-hours), and HR context (imminent departure) together crosses the threshold from 'worth reviewing' to 'escalate now.' Recommended immediate actions include preserving evidence, considering temporary restriction of this user's cloud-upload and USB permissions, and looping in HR/legal before the termination date to determine next steps (which may include early offboarding).",
      fp_trap:
        "A tempting false-comfort argument is 'the policy only alerted, it didn't block, so this must be low-priority, and sales reps regularly export customer data as part of their job.' That reasoning misses that Audit mode simply means the DATA ALREADY LEFT — an audit-only policy provides zero prevention, so 'it wasn't blocked' should never be read as 'it wasn't serious.' The combination of full-database volume, personal-cloud destination, off-hours timing, and imminent resignation is exactly the pattern real insider-threat programs are built to catch — treating it as routine because the user's job title involves customer data would be a serious triage failure.",
      xp: 35,
    },
    // ── Question 3 ────────────────────────────────────────────────────────
    {
      type: "question" as const,
      id: "dlp-q3",
      question:
        "Why is a DLP alert alone often insufficient to prove malicious insider intent, and what additional context typically closes that gap?",
      options: [
        "DLP lacks destination data, while EDR telemetry reconstructs content and destination, so insider cases should rest on EDR alerts rather than DLP",
        "DLP shows WHAT matched and WHERE it went, not WHY; closing the gap takes behavioral context (timing, volume vs. baseline, new destination) plus HR context (role, resignation status)",
        "A 'Blocked' DLP action is complete evidence, since a blocked transfer confirms the user deliberately attempted to move protected content out of the tenant",
        "The confidence score settles intent: a score above 85 shows the user knew the data was sensitive, whatever the timing, volume or HR context",
      ],
      answer: 1,
      explanation:
        "DLP is a content-inspection control — it is excellent at telling you what sensitive data was involved and where it was going, but it has no visibility into intent. The gap between 'content matched a policy' and 'this was malicious' is closed by layering in behavioral context (is this normal for this user? unusual timing or volume?) and organizational/HR context (does this role plausibly explain the activity? is there a resignation, PIP, or other red flag on file?). This is precisely why DLP and insider-threat/UEBA programs are designed to work together rather than in isolation. EDR does not reconstruct content the way DLP does, a Blocked action shows an attempt but not why it was made, and a high confidence score only means the classifier is sure about the content — it says nothing about what the user knew or intended.",
      xp: 25,
    },
    // ── Matching ──────────────────────────────────────────────────────────
    {
      type: "matching" as const,
      id: "dlp-m1",
      heading: "Match Each DLP Channel or Classifier Concept to Its Description",
      instructions:
        "Three of these are DLP channels and two are classifier concepts. Match each one on the left to its description on the right.",
      pairs: [
        {
          id: "endpoint",
          left: "Endpoint DLP",
          right: "Sees USB copies, printing, clipboard paste and screenshots — actions that never reach the network",
        },
        {
          id: "network",
          left: "Network DLP",
          right: "Inline appliance or proxy at the boundary; needs TLS inspection to see HTTPS uploads, so it mostly covers legacy protocols such as FTP",
        },
        {
          id: "cloud",
          left: "Cloud / Email DLP",
          right: "Inspects content natively inside Exchange, SharePoint, OneDrive and Teams, and other SaaS through a CASB",
        },
        {
          id: "confidence",
          left: "Confidence score",
          right: "A 0-100 value saying how sure the classifier is that a match really is the data type it claims",
        },
        {
          id: "fingerprint",
          left: "Document fingerprinting",
          right: "Recognises files that reuse the text of a registered template or standard form, even once it has been filled in",
        },
      ],
      explanation:
        "Recognizing which channel (Endpoint / Network / Cloud) generated an alert immediately tells you what kind of investigation is coming, while understanding classifier mechanics (confidence score, fingerprinting) tells you how much to trust the alert's content match before you even look at destination or user context.",
      xp: 30,
    },
    // ── Ordering ──────────────────────────────────────────────────────────
    {
      type: "ordering" as const,
      id: "dlp-o1",
      heading: "Order the Steps to Investigate a DLP Incident",
      instructions:
        "A thorough DLP investigation follows the five-step triage flow from the investigation reading, moving from the raw content match to a final verdict. Arrange the steps in order, from first to last.",
      items: [
        { id: "content", text: "Assess the content match quality — SensitiveInfoType, confidence score and match count" },
        { id: "destination", text: "Assess the destination risk — internal, known business partner, or personal webmail / unsanctioned cloud app" },
        { id: "user", text: "Assess user and behavioral context — role, timing and volume against normal, and HR red flags such as a resignation" },
        { id: "justification", text: "Check for a justification or approval — the user's stated business reason and any matching ticket or manager sign-off" },
        { id: "verdict", text: "Render a verdict — false positive, well-meaning employee (coach), or malicious/high-risk (escalate to insider-threat, HR, legal)" },
      ],
      correct_order: ["content", "destination", "user", "justification", "verdict"],
      explanation:
        "This is the reading's five-step flow. Content quality comes first because it tells you whether there is a real match worth pursuing. Destination risk then separates routine business flows from personal or unsanctioned destinations. User and behavioral context — including HR red flags — is where DLP meets insider-threat work. Justification and approval are the last check, because a specific, verifiable reason can resolve what otherwise looks suspicious, while its absence raises concern going into the verdict. (ActionTaken — Blocked versus Allowed - Alert Only — sets how urgently you work through these steps rather than being a step of its own.)",
      xp: 30,
    },
    // ── Flag ──────────────────────────────────────────────────────────────
    {
      type: "flag" as const,
      id: "dlp-f1",
      event: dlpUsbEvent, // show the USB bulk-copy log this flag reads (not the nearest one)
      prompt:
        "Look at the USB bulk-copy DLP event analyzed earlier in this room. The asset team needs to find the exact physical drive used in the blocked copy. Which value should you give them? Enter it exactly as shown.",
      answer: "4C531001551122117402",
      hint: "A volume label can be renamed by anyone, and a device ID names only the make and model.",
      xp: 30,
    },
  ],
};

export default [dlpRoom];
