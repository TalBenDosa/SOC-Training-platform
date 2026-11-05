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
        kind: "defuse",
        title: "Stop the Leak at the Right Sensor",
        prompt: "Client files are heading out of Ashby & Rowe four different ways this Friday. For each, cut the one control that sits where DLP can actually see and stop it.",
        device: "Exfil gauge · Friday 17:40",
        seconds: 90,
        rounds: [
          {
            id: "print",
            state: "A trainee has opened a 90-page privileged brief and sent it to the printer at her home. The firm VPN is off and nothing is uploaded anywhere.",
            wires: [
              { id: "proxy", label: "Block the print vendor's domain at the web gateway" },
              { id: "endpoint", label: "Endpoint DLP print restriction on the laptop agent" },
              { id: "mailrule", label: "Exchange mail flow rule for attachments" },
            ],
            cut: "endpoint",
            hint: "Where does the print job travel, and what is on that path?",
            why: "A local print never crosses the gateway or enters a cloud service, so only the agent on the laptop sees the print action. The gateway and Exchange are watching paths this job never takes.",
          },
          {
            id: "scanner",
            state: "A legacy scanner pushes matter files over plain FTP, port 21, to an outside print vendor. The scanner has no agent and cannot be given one.",
            wires: [
              { id: "agent", label: "Roll out the endpoint DLP agent to the scanner" },
              { id: "network", label: "Network DLP inspecting traffic leaving the boundary" },
              { id: "spo", label: "A Purview policy on the SharePoint matter library" },
            ],
            cut: "network",
            hint: "No agent, and the traffic is not encrypted.",
            why: "Unencrypted FTP crossing the boundary is readable on the wire, which is what network DLP is for. The scanner cannot run an agent, and the files never touch SharePoint.",
          },
          {
            id: "link",
            state: "A partner has just made an Anyone-with-the-link share on the Corlis matter folder in SharePoint. No file has left the tenant yet.",
            wires: [
              { id: "spo", label: "Purview DLP policy on SharePoint sharing" },
              { id: "endpoint", label: "Endpoint DLP rule on file copy to removable media" },
              { id: "ftp", label: "Network DLP signature for FTP uploads" },
            ],
            cut: "spo",
            hint: "The action happens inside a service, before any download.",
            why: "The sharing event lives inside Microsoft 365, so the cloud-side policy sees and can block it at creation. The other two controls watch the laptop and the wire, and nothing is on either.",
          },
          {
            id: "paste",
            state: "A paralegal is pasting a client's medical report into a public AI chatbot in the browser. The page is HTTPS and the gateway cannot decrypt it.",
            wires: [
              { id: "gw", label: "Network DLP at the gateway reading the HTTPS body" },
              { id: "clip", label: "Endpoint DLP paste control for unsanctioned sites" },
              { id: "exo", label: "Exchange DLP policy for outbound mail" },
            ],
            cut: "clip",
            hint: "What can see the clipboard before the data is encrypted?",
            why: "The agent sees the paste in the browser before the data is encrypted. The gateway only sees encrypted bytes it cannot read, and there is no mail involved for Exchange to inspect.",
          },
        ],
        lesson: "Each DLP channel sees a different place: the laptop agent sees print and paste, network DLP sees unencrypted traffic leaving, and cloud DLP sees actions inside the service. Pick the control that sits on the path the data takes.",
      },
    ],
    // ── Readings 3-4: what counts as sensitive, and how sure DLP is ──
    "dlp-r4": [
      {
        kind: "codebreak",
        title: "Name That Detector",
        prompt: "Daniel is tuning Ashby & Rowe's classifiers and describes each one by what it does. Name the term he means.",
        tries: 6,
        rounds: [
          { id: "luhn", clue: "The checksum a 16-digit string must pass before it can count as a real card number. Named for an IBM engineer.", answer: "LUHN", why: "A random 16-digit string fails the Luhn check about nine times in ten, which removes most order numbers and reference codes that merely look like cards." },
          { id: "keyword", clue: "Words like Visa or expires found close to a matched number. They lift confidence without changing the pattern itself.", answer: "KEYWORD", why: "Supporting evidence near a match moves it from the medium band to the high band. The same number with nothing around it stays medium." },
          { id: "phi", clue: "Three letters for patient diagnoses, treatment records and insurer IDs, the class behind the medical reports in personal-injury files.", answer: "PHI", why: "Protected health information. It is a data class, not a pattern: it is usually found by keywords and dictionaries rather than a single regex." },
          { id: "edm", clue: "Three letters. Matches against a hashed copy of your real client table, so only genuine client records trigger it.", answer: "EDM", why: "Exact Data Match hashes the real records and compares, which is why it has far fewer false positives than a generic pattern." },
        ],
        lesson: "A classifier is evidence, not a verdict: pattern, checksum, nearby keywords and exact-match lists each move the confidence, and the confidence decides what the policy does.",
      },
    ],
    // ── Reading 5: actions ──
    "dlp-r5": [
      {
        kind: "reactor",
        title: "Policy Reactors",
        prompt: "Five Ashby & Rowe policies ride the belt. Route each into the enforcement reactor it should use before it reaches the end.",
        reactors: [
          { id: "audit", label: "AUDIT", sub: "log it, don't interrupt" },
          { id: "warn", label: "WARN", sub: "ask for a justification" },
          { id: "block", label: "BLOCK", sub: "stop it outright" },
          { id: "encrypt", label: "ENCRYPT", sub: "let it go, protected" },
        ],
        items: [
          { id: "new", text: "A brand-new 'privileged document' classifier, deployed last week, match rate unknown", reactor: "audit", why: "Watch real match volume and tune before you interrupt anyone." },
          { id: "client", text: "Lawyers emailing case documents to clients' own addresses, which they do every day", reactor: "encrypt", why: "The send is legitimate; the risk is in transit. Encrypt it and let the work go on." },
          { id: "personal", text: "Client matter files uploaded to personal cloud storage", reactor: "block", why: "No business reason exists; stop it outright." },
          { id: "external", text: "Sharing a matter folder with an external party for the first time", reactor: "warn", why: "Often legitimate (co-counsel, experts). Ask the user to confirm and record why." },
          { id: "phi", text: "Medical records from personal-injury cases sent outside the firm unencrypted", reactor: "block", why: "Health data in clear text to the outside: a regulatory breach if it goes." },
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
