import type { RoomExperience } from "./types";

// "Operation Second Look" for the "analyst-mindset" room.
// Script: docs/campaign/18-analyst-mindset.md.
// Station task ids must match the room's task order exactly (see getRoomExperience).
//
// Halcyon Insurance (fictional). Lab data differs from the graded tasks: the
// disconfirming-evidence sort and the prediction trace follow a service
// account, not q2's newly registered domain; the six-question sheet is an RDP
// logon, not la1's 03:12 finance logon; the baseline searches are about a
// marketing user, not la2's IT script or ac1's backup job; the bias notes are
// other scenarios than m1's and never the pre-labelled queue of q1; and the
// fact/assumption notes never use q3's svchost statements or order the triage
// steps (o1).
export const ANALYST_MINDSET: RoomExperience = {
  roomId: "analyst-mindset",
  codename: "Operation Second Look",
  theme: "mind",
  handler: { name: "Lena Sorensen", role: "SOC Shift Lead, Halcyon Insurance" },
  briefing: [
    "Halcyon Insurance. A SOC of nine, four hundred alerts a night, and one rule on Lena Sorensen's whiteboard: take a second look.",
    "Tools can be learned in an afternoon. The habit of asking 'does that actually make sense?' takes practice.",
    "Lena will make you form competing stories, predict what each one leaves behind, check it against what's normal, and catch your own brain cutting corners.",
    "Same alerts as everyone else. Different thinking.",
  ],
  mission: "Practise the analyst's habits: test theories with evidence that could disprove them, chain 'so what?' into checkable predictions, run the six questions, measure normal with SIEM searches, catch biases in real case notes, and separate fact from assumption before you close.",
  estimate: "~55 min",
  look: { primary: "#c084fc", secondary: "#2dd4bf", warn: "#f43f5e" },
  scene: "mindlab",
  layout: "stage",
  story: {
    intro: { title: "Take a Second Look", src: "https://wrxhxtdllbctsawvewue.supabase.co/storage/v1/object/public/lesson-videos/operation/analyst-mindset/secondlook-intro-348b1486.mp4", poster: "https://wrxhxtdllbctsawvewue.supabase.co/storage/v1/object/public/lesson-videos/operation/analyst-mindset/secondlook-intro-d98b2eaa.jpg" },
    afterStation: {
      theory: { title: "Predict, Then Check", src: "https://wrxhxtdllbctsawvewue.supabase.co/storage/v1/object/public/lesson-videos/operation/analyst-mindset/secondlook-ch2-eb833fde.mp4", poster: "https://wrxhxtdllbctsawvewue.supabase.co/storage/v1/object/public/lesson-videos/operation/analyst-mindset/secondlook-ch2-587c2de0.jpg" },
      normal: { title: "Normal for Whom?", src: "https://wrxhxtdllbctsawvewue.supabase.co/storage/v1/object/public/lesson-videos/operation/analyst-mindset/secondlook-ch3-85036ff1.mp4", poster: "https://wrxhxtdllbctsawvewue.supabase.co/storage/v1/object/public/lesson-videos/operation/analyst-mindset/secondlook-ch3-ff168667.jpg" },
      close: { title: "What Did You Actually Verify?", src: "https://wrxhxtdllbctsawvewue.supabase.co/storage/v1/object/public/lesson-videos/operation/analyst-mindset/secondlook-finale-05b65315.mp4", poster: "https://wrxhxtdllbctsawvewue.supabase.co/storage/v1/object/public/lesson-videos/operation/analyst-mindset/secondlook-finale-0c0d3ca2.jpg" },
    },
  },
  stations: [
    {
      id: "theory",
      label: "Two Stories",
      topic: "Thinking like a detective · competing hypotheses · the 'so what?' chain",
      tagline: "Test a theory by looking for what would kill it",
      building: "lab",
      taskIds: ["mind-r1", "mind-r2", "mind-q2"],
    },
    {
      id: "six",
      label: "Six Questions",
      topic: "Who, what, where, when, why (innocent first), is it normal, blast radius",
      tagline: "Run one alert through all six",
      building: "archive",
      taskIds: ["mind-r3", "mind-la1"],
    },
    {
      id: "normal",
      label: "Know Normal",
      topic: "Baselines · entity-specific normal · first-time-seen",
      tagline: "Measure normal with SIEM searches before you judge",
      building: "control",
      taskIds: ["mind-r4", "mind-la2", "mind-flag1", "mind-ac1"],
    },
    {
      id: "bias",
      label: "Your Own Brain",
      topic: "Confirmation, fatigue, anchoring, tunnel vision, availability, authority",
      tagline: "Catch the bias in real case notes",
      building: "office",
      taskIds: ["mind-r5", "mind-q1", "mind-m1"],
    },
    {
      id: "close",
      label: "Fact or Assumption",
      topic: "Labelling statements · silent assumptions · when to dig and when to close",
      tagline: "Clean up a case note before it goes on record",
      building: "ticket",
      taskIds: ["mind-r6", "mind-q3", "mind-o1"],
      boss: true,
    },
  ],
  personas: {
    "mind-q1": { name: "Lena Sorensen", role: "SOC Shift Lead", line: "Half the queue arrives pre-labelled 'likely benign'. How do you keep that from steering you?" },
    "mind-q2": { name: "Lena Sorensen", role: "SOC Shift Lead", line: "New domain, registered yesterday. You've said 'so what'. Now what?" },
    "mind-q3": { name: "Lena Sorensen", role: "SOC Shift Lead", line: "Two lines in a case note. Which one is a fact?" },
    "mind-ac1": { name: "Lena Sorensen", role: "SOC Shift Lead", line: "Encoded PowerShell, HR laptop, 22:47. It looks terrible. Is it?" },
  },
  briefings: {
    // ── Reading 1: thinking like an analyst ──
    "mind-r1": [
      {
        kind: "sort",
        title: "Does It Test the Theory?",
        prompt: "Theory: 'svc_reports, a reporting service account, was stolen and is being used by an attacker.' For each piece of evidence, does it support the theory, disprove it, or not test it at all?",
        buckets: [
          { id: "sup", label: "Supports the theory" },
          { id: "dis", label: "Could disprove it" },
          { id: "none", label: "Doesn't test it" },
        ],
        items: [
          { id: "a", text: "svc_reports logged on interactively (type 10, RDP) to an accounting PC", bucket: "sup", why: "Service accounts run jobs; they don't open desktops. This fits an attacker using the password." },
          { id: "b", text: "A change ticket says IT used svc_reports by hand last night to rerun a failed report", bucket: "dis", why: "A verified, innocent reason. If it checks out (time, host, who did it), the theory falls." },
          { id: "c", text: "The alert's severity is High", bucket: "none", why: "A label someone else assigned. It doesn't tell you what happened." },
          { id: "d", text: "svc_reports' password was last changed 4 years ago", bucket: "none", why: "It makes theft easier, but it's true whether or not it was stolen. It doesn't test this event." },
          { id: "e", text: "The RDP session came from 10.40.2.18, an IT admin's jump host it has used before", bucket: "dis", why: "The kind of check that could kill the attacker theory: a known source with history." },
          { id: "f", text: "Right after logon, the account ran nltest /domain_trusts", bucket: "sup", why: "Domain discovery is what an intruder does first, not what a reporting job does." },
        ],
      },
    ],
    // ── Reading 2: hypotheses and the 'so what?' chain ──
    "mind-r2": [
      {
        kind: "trace",
        title: "So What, Then What?",
        prompt: "Follow the theory forward. At each step, say what you'd expect to see if svc_reports is in an attacker's hands, then check for it.",
        lead: "02:41: svc_reports opened an RDP session on ACC-PC-22. Hypothesis A: stolen and misused. Hypothesis B: an admin using it by hand.",
        steps: [
          {
            id: "src", source: "Windows Security 4624 · ACC-PC-22",
            ask: "So what? If an admin did this, it should come from an IT host. Where did the logon come from?",
            columns: ["time", "account", "LogonType", "IpAddress"],
            rows: [["02:41:07", "svc_reports", "10", "10.40.9.77"], ["01:00:02", "svc_reports", "5", "-"], ["08:12:44", "a.wong", "2", "127.0.0.1"]],
            answer: 0,
            why: "Type 10 from 10.40.9.77. The 01:00 type 5 is the normal service start. Next: is 10.40.9.77 an IT host?",
            learned: "RDP logon as svc_reports from 10.40.9.77 at 02:41",
          },
          {
            id: "asset", source: "Asset inventory",
            ask: "What is 10.40.9.77?",
            columns: ["IP", "hostname", "owner", "role"],
            rows: [["10.40.2.18", "IT-JUMP-01", "IT Operations", "admin jump host"], ["10.40.9.77", "MKT-LT-0315", "j.ferreira (Marketing)", "laptop"], ["10.40.9.80", "MKT-LT-0318", "Marketing", "laptop"]],
            answer: 1,
            why: "A marketing laptop, not an IT host. Hypothesis B just got weaker. Prediction for A: that laptop shows signs of compromise.",
            learned: "Source is MKT-LT-0315, a marketing laptop: not IT",
          },
          {
            id: "edr", source: "EDR · process events · MKT-LT-0315 · 02:00-02:45",
            ask: "If A is true, the laptop should show an attacker at work. Is there?",
            columns: ["time", "process", "command line"],
            rows: [["02:12:30", "msedge.exe", "(browser)"], ["02:36:51", "rundll32.exe", "rundll32.exe C:\\ProgramData\\cache\\c.dll,Run"], ["02:40:58", "mstsc.exe", "mstsc /v:ACC-PC-22"]],
            answer: 1,
            why: "A DLL from ProgramData run at 02:36, then RDP to the accounting PC four minutes later. The prediction came true.",
            learned: "MKT-LT-0315 ran an unknown DLL at 02:36, then RDP'd out: Hypothesis A holds",
          },
        ],
      },
    ],
    // ── Reading 3: the six questions ──
    "mind-r3": [
      {
        kind: "worksheet",
        title: "One Alert, Six Questions",
        prompt: "Run this alert through the framework. Everything you need is in the table.",
        caption: "Alert: 'RDP logon by svc_backup to FIN-LT-0007' · Sunday 01:58",
        columns: ["source", "what it says"],
        rows: [
          ["Directory", "svc_backup: service account, member of Backup Operators"],
          ["CMDB", "FIN-LT-0007: CFO's laptop"],
          ["SIEM, last 30 days", "svc_backup interactive logons anywhere: 0"],
          ["Change calendar", "no work scheduled this weekend"],
          ["Directory", "Backup Operators can read every file on 61 servers"],
        ],
        questions: [
          { id: "who", q: "WHO: human, or service account?", hint: "Directory row 1.", answer: ["service", "service account"], why: "A service account behaving like a human (an interactive desktop session) is the first red flag." },
          { id: "where", q: "WHERE: whose machine is it?", hint: "CMDB.", answer: ["CFO", "the CFO's", "CFO's laptop"], why: "The most targeted laptop in the company. Location raises the stakes." },
          { id: "normal", q: "IS IT NORMAL: how many interactive logons did svc_backup make in 30 days?", hint: "SIEM row.", answer: ["0", "zero", "none"], why: "First time ever. Attackers, by definition, do things that weren't happening before." },
          { id: "why", q: "WHY: is there an innocent explanation on record? (yes/no)", hint: "Change calendar.", answer: ["no"], why: "You looked for the benign reason first and found none. That absence is information." },
          { id: "radius", q: "BLAST RADIUS: on how many servers can this account read every file?", hint: "Last directory row.", answer: ["61"], why: "If it's stolen, it reaches 61 servers. Move now and notify." },
        ],
      },
    ],
    // ── Reading 4: baselines ──
    "mind-r4": [
      {
        kind: "deduce",
        title: "Whose Normal Is It?",
        prompt: "Tuesday 14:00. One rule fired on six accounts: a sign-in from abroad plus more than 1 GB downloaded from the shared drive. Five are normal for the person behind them. One is not. Lena hands you the baselines one clue at a time. Strike out the innocent ones and accuse.",
        nameColumn: "Account",
        columns: ["Signed in from", "Downloaded today", "Department"],
        suspects: [
          { id: "ralmeida", name: "r.almeida", cells: ["Brazil", "2.9 GB", "Analytics"] },
          { id: "msilva", name: "m.silva", cells: ["Brazil", "1.4 GB", "Sales"] },
          { id: "dokafor", name: "d.okafor", cells: ["United Kingdom", "4.2 GB", "Finance"] },
          { id: "tnovak", name: "t.novak", cells: ["Portugal", "1.8 GB", "Marketing"] },
          { id: "kito", name: "k.ito", cells: ["Brazil", "3.1 GB", "Marketing"] },
          { id: "phaddad", name: "p.haddad", cells: ["United Kingdom", "3.0 GB", "Finance"] },
        ],
        clues: [
          "Directory: r.almeida and m.silva are based in the Sao Paulo office, so Brazil is where they work every day.",
          "Travel system: t.novak is at an approved partner conference in Lisbon this week.",
          "SIEM, 30 days: d.okafor pulls between 3 and 5 GB from the shared drive every week for the finance model.",
          "SIEM, 30 days: p.haddad downloads 2 to 4 GB every Tuesday, always from a United Kingdom address.",
        ],
        culprit: "kito",
        why: "k.ito is the only account whose own normal was broken twice. In 30 days k.ito signed in from Brazil exactly once, today, against 418 sign-ins from the United Kingdom, and usually downloads about 45 MB a day, so 3.1 GB is roughly 70 times normal. No travel is booked, and HR shows k.ito working from the London office. r.almeida had the biggest foreign sign-in and a 2.9 GB download, which look scary but are ordinary for that person. Generic normal ('people travel, analysts pull data') would have closed this: entity-specific normal says escalate.",
      },
    ],
    // ── Reading 5: biases ──
    "mind-r5": [
      {
        kind: "duel",
        title: "Brain Against Habit",
        prompt: "3 a.m. at Halcyon, and your own brain is the opponent. Each round it plays a bias taken from real case notes. Play the habit that beats that exact bias. Each habit can be used once.",
        attacker: "A tired brain",
        moves: [
          { id: "m1", move: "Authority", detail: "'Ticket says Tier 2 already cleared this host in March, so closing.'", counter: "reverify", hint: "The earlier verdict is real. The question is whether it covers tonight.", why: "An earlier senior verdict replaced looking at today's evidence. The habit is to treat it as context and re-check today's data. Asking what the senior would say just moves the authority around." },
          { id: "m2", move: "Alert fatigue", detail: "'Same as the last 80 DLP hits from this rule. Closed.' It was a different file type.", counter: "sample", hint: "Eighty alike teaches the eye to stop reading.", why: "Eighty in a row trained the brain to stop looking at the 81st. Fully opening a sample and comparing its varying fields to the last one breaks the autopilot. Closing faster only feeds it." },
          { id: "m3", move: "Availability", detail: "'We had a Qakbot case Monday, so this beacon is Qakbot.'", counter: "alts", hint: "What you saw most recently is not what is most likely.", why: "A fresh case feels likely because it is fresh. Writing three other explanations and what each predicts forces the evidence to choose. Going with the group's guess is availability shared by five people." },
          { id: "m4", move: "Tunnel vision", detail: "'Reset the user's password, case closed.' Nobody checked what else the account touched.", counter: "radius", hint: "The reset was a good action. What did it leave unasked?", why: "The analyst found one thing and stopped. Asking what else the account reached, and on how many hosts, is the blast-radius question that was never asked." },
          { id: "m5", move: "Anchoring", detail: "'Vendor title says Possible Scanner, and the traffic does look scanner-ish.'", counter: "readraw", hint: "The title was written before you looked at anything.", why: "The title set the frame before the evidence was read. Reading the raw fields first, then the title, lets the log decide. Closing the ticket to clear the queue removes the chance to be corrected." },
          { id: "m6", move: "Confirmation", detail: "'It is the VPN glitch again. The three lines that do not fit are probably noise.'", counter: "disprove", hint: "The three lines are doing the one job your theory cannot.", why: "Evidence that contradicts the theory was waved away instead of tested. Writing what would disprove the theory and looking for it turns the odd lines into the test. Asking a teammate to agree only adds a second vote for the same story." },
        ],
        cards: [
          { id: "reverify", name: "Re-check today's evidence, cite the old verdict as context", effect: "Past decisions inform, they do not decide." },
          { id: "sample", name: "Open one in ten fully and compare it with the last", effect: "Breaks the autopilot on repetitive alerts." },
          { id: "alts", name: "Write three other explanations and what each predicts", effect: "Makes the evidence choose between stories." },
          { id: "radius", name: "Ask what else the account touched and where", effect: "Sizes the incident before closing." },
          { id: "readraw", name: "Read the raw fields before the title", effect: "Forms your own view first." },
          { id: "disprove", name: "Name what would kill the theory and look for it", effect: "Treats odd lines as the test." },
          { id: "speed", name: "Close faster to clear the queue", effect: "Cuts the time spent per alert." },
          { id: "vote", name: "Go with what the room thinks", effect: "Picks the answer most people agree on." },
        ],
        lesson: "A bias is a shortcut your brain takes when it is tired. Each one has a habit that beats it: re-check today's data, sample the repeats, list alternatives, size the blast radius, read raw before the title, and look for what would disprove you.",
      },
    ],
    // ── Reading 6: fact, assumption, and when to stop ──
    "mind-r6": [
      {
        kind: "sort",
        title: "Fact or Assumption?",
        prompt: "A draft case note for the svc_reports incident. Label every sentence before it goes on record.",
        buckets: [
          { id: "fact", label: "Fact: observed in a log or system" },
          { id: "assume", label: "Assumption or unverified claim" },
        ],
        items: [
          { id: "a", text: "4624 shows svc_reports, LogonType 10, from 10.40.9.77 at 02:41:07.", bucket: "fact", why: "Straight from the log. Anyone can check it." },
          { id: "b", text: "j.ferreira probably opened a phishing attachment.", bucket: "assume", why: "'Probably' and no email or click evidence yet. Write it as a lead, not a finding." },
          { id: "c", text: "j.ferreira says they were asleep at 02:30.", bucket: "assume", why: "A claim, unverified. True or not, it can't carry the conclusion." },
          { id: "d", text: "EDR shows rundll32 loading C:\\ProgramData\\cache\\c.dll at 02:36:51.", bucket: "fact", why: "Recorded telemetry." },
          { id: "e", text: "The attacker didn't reach any other system.", bucket: "assume", why: "Unless you searched every other host for svc_reports and found nothing, this is hope. Say what you checked." },
          { id: "f", text: "No svc_reports logons on any other host since 01:00, per a SIEM search across all Windows hosts.", bucket: "fact", why: "Now the blast-radius claim is a fact, because the search that supports it is named." },
        ],
      },
      {
        kind: "worksheet",
        title: "Dig or Close?",
        prompt: "Two cases at the end of a shift. For each, decide whether you can close or must keep digging.",
        caption: "End-of-shift review · Halcyon SOC",
        columns: ["case", "what's verified", "what's open", "cost if wrong"],
        rows: [
          ["A: odd DNS query from KIOSK-LOBBY-2", "domain is a known ad network; kiosk has no logons; 1 query", "nothing answerable", "a lobby kiosk"],
          ["B: odd DNS query from DA account's admin PC", "domain is 2 days old", "beacon pattern not checked; other hosts not checked", "the whole domain"],
        ],
        questions: [
          { id: "a", q: "Case A: close or dig?", hint: "Every answerable question is answered, and the stakes are low.", answer: ["close"], why: "Verified, documented, low cost if wrong. Closing here is good judgement, not laziness." },
          { id: "b", q: "Case B: close or dig?", hint: "Open questions you can answer, and the highest stakes.", answer: ["dig", "keep digging", "dig deeper"], why: "Same kind of signal, completely different cost of being wrong. Depth should scale with stakes." },
        ],
      },
    ],
  },
};
