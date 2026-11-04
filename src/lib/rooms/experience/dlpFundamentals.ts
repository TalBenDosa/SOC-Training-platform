import type { RoomExperience } from "./types";

// "Operation Sealed Brief" for the "dlp-fundamentals" room.
// Script: docs/campaign/29-dlp-fundamentals.md.
// Station task ids must match the room's task order exactly (see getRoomExperience).
//
// Ashby & Rowe (fictional law firm), not the graded tasks' NexaCorp. Lab data
// differs from the graded tasks: the channel sort never includes a USB copy
// (q1); the classifier console tests other numbers than q2's internal email
// and never decides a verdict; the trace follows print and an external
// sharing link, never la1's USB copy (or its serial, f1), la2's email to
// Gmail, ac1's purchase orders or ac2's Dropbox upload; and nothing orders
// the triage steps (o1) or matches channels to descriptions (m1).
export const DLP_FUNDAMENTALS: RoomExperience = {
  roomId: "dlp-fundamentals",
  codename: "Operation Sealed Brief",
  theme: "dlp",
  handler: { name: "Daniel Okoye", role: "Insider Risk Lead, Ashby & Rowe" },
  briefing: [
    "Ashby & Rowe. 600 lawyers, 40,000 client matters, and privileged documents that must never leave the firm.",
    "Data loss prevention watches every copy, print, share and send. It sees what moved and where. It never sees why.",
    "Daniel Okoye runs insider risk. Every week his queue fills with matches: most are mistakes, a few are not.",
    "Learn what DLP can see, how sure it is, what it can do, and how to tell a slip from a theft.",
  ],
  mission: "Place every exfiltration path on the right DLP channel, test text against Purview's classifiers and read their confidence, choose the right enforcement action for each policy, and trace a match through activity, history and HR context to a verdict.",
  estimate: "~50 min",
  look: { primary: "#fbbf24", secondary: "#818cf8", warn: "#f43f5e" },
  scene: "sealedbrief",
  layout: "stage",
  stations: [
    {
      id: "channels",
      label: "Where DLP Watches",
      topic: "What DLP is · endpoint, network and cloud/email channels",
      tagline: "Put every way out on the channel that sees it",
      building: "control",
      taskIds: ["dlp-r1", "dlp-r2", "dlp-q1"],
    },
    {
      id: "classify",
      label: "How Sure Is It?",
      topic: "PII, PCI, PHI and IP · regex, Luhn, keywords, fingerprints · confidence",
      tagline: "Test text against the classifiers yourself",
      building: "lab",
      taskIds: ["dlp-r3", "dlp-r4", "dlp-q2"],
    },
    {
      id: "actions",
      label: "Audit, Warn, Block",
      topic: "Audit, warn and justify, block, encrypt · when each fits",
      tagline: "Choose the action for each policy",
      building: "vault",
      taskIds: ["dlp-r5"],
    },
    {
      id: "trace",
      label: "Reading the Alert",
      topic: "Content, destination, user, justification · the triage flow",
      tagline: "Follow one match to a verdict",
      building: "office",
      taskIds: ["dlp-r6", "dlp-la1", "dlp-f1", "dlp-la2"],
    },
    {
      id: "verdict",
      label: "Slip or Theft?",
      topic: "False positives, well-meaning users and insiders",
      tagline: "Call the hard ones",
      building: "ticket",
      taskIds: ["dlp-ac1", "dlp-ac2", "dlp-q3", "dlp-m1", "dlp-o1"],
      boss: true,
    },
  ],
  personas: {
    "dlp-q1": { name: "Daniel Okoye", role: "Insider Risk Lead", line: "Someone copied a file to a USB stick. Which channel could even see it?" },
    "dlp-q2": { name: "Daniel Okoye", role: "Insider Risk Lead", line: "One card number, confidence 58, internal email. What's your first move?" },
    "dlp-q3": { name: "Daniel Okoye", role: "Insider Risk Lead", line: "Why can't a DLP alert alone prove intent?" },
    "dlp-ac1": { name: "Daniel Okoye", role: "Insider Risk Lead", line: "Eighteen 'card numbers' in a procurement spreadsheet. Real?" },
    "dlp-ac2": { name: "Daniel Okoye", role: "Insider Risk Lead", line: "8,420 customer records to a personal Dropbox at 22:41. Your call." },
  },
  briefings: {
    // ── Readings 1-2: what DLP is, and its channels ──
    "dlp-r2": [
      {
        kind: "sort",
        title: "Who Sees It?",
        prompt: "Ways a client file could leave Ashby & Rowe this week. Which DLP channel is placed to see each one?",
        buckets: [
          { id: "endpoint", label: "Endpoint DLP (agent on the laptop)" },
          { id: "network", label: "Network DLP (at the boundary)" },
          { id: "cloud", label: "Cloud / email DLP (inside the service)" },
        ],
        items: [
          { id: "print", text: "A trainee prints a 90-page privileged brief at home", bucket: "endpoint", why: "Printing never touches the network gateway or a cloud service. Only the laptop's agent sees it." },
          { id: "paste", text: "A paralegal pastes a client's medical report into a public AI chatbot in the browser", bucket: "endpoint", why: "Endpoint DLP can watch clipboard paste into unsanctioned sites and apps." },
          { id: "ftp", text: "A legacy scanner uploads files over plain FTP to an outside print vendor", bucket: "network", why: "Unencrypted traffic crossing the boundary: exactly what a network DLP appliance can read." },
          { id: "share", text: "A partner creates an 'Anyone with the link' share on a SharePoint matter folder", bucket: "cloud", why: "The share happens inside Microsoft 365; Purview sees it natively." },
          { id: "teams", text: "A client's passport scan is posted in a Teams chat with a guest user", bucket: "cloud", why: "Teams messages and files are inspected inside the service." },
          { id: "mail", text: "An associate emails a settlement draft to opposing counsel's firm", bucket: "cloud", why: "Exchange DLP inspects the message and attachments before they leave." },
        ],
      },
    ],
    // ── Readings 3-4: what counts as sensitive, and how sure DLP is ──
    "dlp-r4": [
      {
        kind: "terminal",
        title: "Test the Classifier",
        prompt: "Exchange Online can tell you exactly how its classifiers read a piece of text. Test four snippets from Ashby & Rowe documents and read the confidence.",
        shell: "powershell",
        host: "PS C:\\> ",
        commands: [
          { match: "test-dataclassification\\s+.*4532981044715563.*(visa|card|expir).*", help: "Test-DataClassification -TextToClassify \"Visa card 4532981044715563 expires 09/28\"   a valid card number with card words around it",
            output: "ClassificationName : Credit Card Number\nConfidence         : 85\nCount              : 1\nMatchedValues      : 4532981044715563" },
          { match: "test-dataclassification\\s+.*4532981044715563.*", help: "Test-DataClassification -TextToClassify \"Ref 4532981044715563\"   the same number, no card words",
            output: "ClassificationName : Credit Card Number\nConfidence         : 65\nCount              : 1\nMatchedValues      : 4532981044715563" },
          { match: "test-dataclassification\\s+.*4532981044715560.*", help: "Test-DataClassification -TextToClassify \"Visa card 4532981044715560\"   one digit different",
            output: "(no sensitive information types detected)" },
          { match: "test-dataclassification\\s+.*(\\d{3}-\\d{2}-\\d{4}).*", help: "Test-DataClassification -TextToClassify \"Employee SSN 078-05-1120\"   a US Social Security number pattern",
            output: "(no sensitive information types detected)\nNote: 078-05-1120 is a well-known invalid SSN; the classifier rejects it." },
        ],
        objectives: [
          { id: "hi", task: "With card words next to it, what confidence does the valid number get?", hint: "Test-DataClassification -TextToClassify \"Visa card 4532981044715563 expires 09/28\"", answer: ["85"], why: "High confidence: the number passes the Luhn checksum AND supporting keywords ('Visa', 'expires') are nearby." },
          { id: "lo", task: "The same number with no card words: what confidence?", hint: "Test-DataClassification -TextToClassify \"Ref 4532981044715563\"", answer: ["65"], why: "Only the pattern and checksum match: medium confidence. Most false positives live down here." },
          { id: "luhn", task: "Change the last digit to 0. Does it still match? (yes/no)", hint: "Test-DataClassification -TextToClassify \"Visa card 4532981044715560\"", answer: ["no"], why: "It fails the Luhn checksum, so it can't be a real card number. Random 16-digit strings fail about nine times in ten." },
        ],
      },
    ],
    // ── Reading 5: actions ──
    "dlp-r5": [
      {
        kind: "sort",
        title: "Pick the Action",
        prompt: "Five Ashby & Rowe policies. Choose the enforcement action each one should use.",
        buckets: [
          { id: "audit", label: "Audit only (log, don't interrupt)" },
          { id: "warn", label: "Warn and allow a justification" },
          { id: "block", label: "Block" },
          { id: "encrypt", label: "Encrypt and send" },
        ],
        items: [
          { id: "new", text: "A brand-new 'privileged document' classifier, deployed last week, match rate unknown", bucket: "audit", why: "Watch real match volume and tune before you interrupt anyone." },
          { id: "client", text: "Lawyers emailing case documents to clients' own addresses, which they do every day", bucket: "encrypt", why: "The send is legitimate; the risk is in transit. Encrypt it and let the work go on." },
          { id: "personal", text: "Client matter files uploaded to personal cloud storage", bucket: "block", why: "No business reason exists; stop it outright." },
          { id: "external", text: "Sharing a matter folder with an external party for the first time", bucket: "warn", why: "Often legitimate (co-counsel, experts). Ask the user to confirm and record why." },
          { id: "phi", text: "Medical records from personal-injury cases sent outside the firm unencrypted", bucket: "block", why: "Health data in clear text to the outside: a regulatory breach if it goes." },
        ],
      },
    ],
    // ── Reading 6: investigating ──
    "dlp-r6": [
      {
        kind: "trace",
        title: "Follow the Match",
        prompt: "A DLP alert on j.whitcombe, a senior associate. Work it from content to verdict.",
        lead: "Purview raised 'Privileged matter shared externally' on j.whitcombe at 18:52 on Friday.",
        steps: [
          {
            id: "content", source: "Purview Activity explorer · j.whitcombe · Friday",
            ask: "Which activity matched the privileged-document classifier with high confidence?",
            columns: ["time", "activity", "file", "classifier", "confidence"],
            rows: [["16:10", "FilePrinted", "Expert_Invoice_0412.pdf", "(none)", "-"], ["18:52", "SharingInvitationCreated", "Halbrook_Merger_Strategy.docx", "Privileged Legal Advice", "92"], ["18:55", "FileAccessed", "Halbrook_Merger_Strategy.docx", "Privileged Legal Advice", "92"]],
            answer: 1,
            why: "A sharing invitation on a privileged strategy memo, at high confidence. The content match is real.",
            learned: "18:52: privileged merger strategy shared (confidence 92)",
          },
          {
            id: "dest", source: "SharePoint audit · sharing details",
            ask: "Who did it go to?",
            columns: ["file", "shared with", "domain type", "link type"],
            rows: [["Halbrook_Merger_Strategy.docx", "counsel@vellmann-partners.example", "external: known co-counsel", "Specific people, view only"]],
            answer: 0,
            why: "Co-counsel on the same deal, view-only, named recipient. A business partner, not a personal account.",
            learned: "Destination: named co-counsel on the matter, view-only link",
          },
          {
            id: "ok", source: "Matter system · Halbrook merger · team and approvals",
            ask: "Is there an approval that covers it?",
            columns: ["record", "detail"],
            rows: [["Engagement letter", "Vellmann Partners retained as co-counsel, 2026-09-14"], ["Matter team", "j.whitcombe: lead associate"], ["Justification at share", "Sending revised strategy to co-counsel per partner instruction"]],
            answer: 0,
            why: "Retained co-counsel, the right person, and a justification typed at the warning. A well-meaning, authorised share: close it and record why.",
            learned: "Verdict: authorised share to retained co-counsel; close with justification",
          },
        ],
      },
    ],
    // Drill before the graded USB event: a Purview SharePoint record, field by field.
    "dlp-la1": [
      {
        kind: "anatomy",
        title: "Anatomy of a DlpRuleMatch",
        prompt: "Before the graded endpoint event: a cloud DLP match from the same audit log, field by field.",
        source: "Microsoft Purview · Unified Audit Log · DlpRuleMatch · SharePoint",
        fields: [
          { key: "Operation", value: "DlpRuleMatch", label: "What", note: "A policy rule matched. Same operation whatever the channel." },
          { key: "Workload", value: "SharePoint", label: "Channel", note: "Endpoint, Exchange, SharePoint, OneDrive or MicrosoftTeams: tells you where to look next." },
          { key: "PolicyDetails.PolicyName", value: "Client Privilege - External Share" },
          { key: "PolicyDetails.Rules.Actions", value: "NotifyUser,GenerateAlert", label: "What it did", note: "Notify and alert: the share went through. Block would read BlockAccess." },
          { key: "SensitiveInfoType.Name", value: "Privileged Legal Advice (trainable classifier)", label: "Matched" },
          { key: "SensitiveInfoType.Confidence", value: "92", label: "How sure" },
          { key: "SensitiveInfoType.Count", value: "1", label: "How many", note: "One document. A bulk count is a different shape of risk." },
          { key: "SharePointMetaData.FileName", value: "Halbrook_Merger_Strategy.docx" },
          { key: "UserId", value: "j.whitcombe@ashbyrowe.example", label: "Who" },
          { key: "JustificationText", value: "Sending revised strategy to co-counsel per partner instruction", label: "Why (user's own words)", note: "Present only when the policy asked for it." },
        ],
        summary: "Channel, policy, action, match, confidence, count, user, justification. Read the graded endpoint record field by field the same way.",
      },
    ],
    // Drill before the verdicts: a justification override, field by field.
    "dlp-ac1": [
      {
        kind: "worksheet",
        title: "Three Overrides",
        prompt: "Warn-and-justify policies let users override with a reason. Read three overrides from this week and judge the reasons.",
        caption: "Purview · DLP policy overrides · Ashby & Rowe",
        columns: ["user", "what", "destination", "justification"],
        rows: [
          ["r.tan", "Expert report (PHI)", "medical-expert@clinic.example", "Expert witness on Patel v. Corlis needs the records by Monday"],
          ["l.okafor", "Settlement terms, Halbrook matter", "deals@hartwell-capital.example", "ok"],
          ["m.ferreira", "Court filing draft", "filings@court-efile.example", "e-filing deadline 17:00"],
        ],
        questions: [
          { id: "odd", q: "Which override needs a follow-up?", hint: "Which reason explains nothing?", answer: ["l.okafor", "okafor"], why: "'ok' is not a reason, and Hartwell Capital isn't on the matter team. A justification box only helps if someone reads what was typed." },
          { id: "who", q: "What would you check first for that override?", hint: "Is the recipient on the matter?", answer: ["matter team", "engagement", "the matter system", "whether hartwell is on the matter", "the recipient", "approval"], why: "The matter record: is Hartwell Capital a party, an adviser, or nobody? That decides slip versus leak." },
        ],
      },
    ],
  },
};
