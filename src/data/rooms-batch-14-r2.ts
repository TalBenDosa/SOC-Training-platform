/**
 * Learning Rooms — Batch 14 (Room 2)
 *
 * "The Analyst Mindset: How to Think and Ask the Right Questions"
 *
 * This room is deliberately COGNITIVE, not mechanical. It does not repeat the
 * six-phase investigation lifecycle taught in "investigation-methodology"
 * (Trigger -> Scope -> Collect -> Analyze -> Conclude -> Document). Instead it
 * teaches the thinking that happens INSIDE the "Analyze" phase and before it:
 * how to form a hypothesis, what questions to ask of an alert, how to spot
 * your own biases, and how to know when you have enough evidence to stop.
 */

import type { TelemetryEvent } from "@/lib/sim/types";

// ── Log analysis event 1: the ambiguous 3AM logon ──────────────────────────
const midnightLogonEvent: TelemetryEvent = {
  id: "evt-mind-la1-001",
  ts: "2024-08-14T03:12:03.000Z",
  source: "ad",
  vendor: "Windows Security",
  event_type: "auth_success",
  severity: "medium",
  hostname: "WS-FIN-2041",
  user_email: "r.patel@nexacorp.com",
  src_ip: "10.10.20.55",
  description: "Successful interactive logon for r.patel at 03:12 AM on a finance workstation",
  raw: {
    "event.code": "4624",
    "winlog.event_data.TargetUserName": "r.patel",
    "winlog.event_data.LogonType": "2",
    "winlog.event_data.AuthenticationPackageName": "Negotiate",
    "winlog.event_data.IpAddress": "10.10.20.55",
    "winlog.event_data.WorkstationName": "WS-FIN-2041",
    "winlog.event_data.ProcessName": "C:\\Windows\\System32\\winlogon.exe",
    "data.context":
      "r.patel is a financial analyst. Badge system shows r.patel badged into the building at 03:05 AM using their own badge. Calendar shows a note: 'quarter close - late night'.",
  },
};

// ── Log analysis event 2: the ambiguous PowerShell execution ───────────────
const powershellDownloadEvent: TelemetryEvent = {
  id: "evt-mind-la2-001",
  ts: "2024-11-02T14:26:41.000Z",
  source: "edr",
  vendor: "CrowdStrike Falcon",
  event_type: "process_create",
  severity: "medium",
  hostname: "WS-IT-0912",
  user_email: "d.okafor@nexacorp.com",
  src_ip: "10.10.8.19",
  description: "PowerShell process launched by IT admin account with a script download command",
  raw: {
    "event.module": "crowdstrike",
    "event.dataset": "crowdstrike.falcon",
    "crowdstrike.event.EventType": "ProcessRollup2",
    "crowdstrike.event.FileName": "powershell.exe",
    "crowdstrike.event.CommandLine":
      "powershell.exe -NoProfile -ExecutionPolicy Bypass -Command \"Invoke-WebRequest -Uri https://raw.githubusercontent.com/nexacorp-it/deploy-scripts/main/patch-agent.ps1 -OutFile C:\\Temp\\patch-agent.ps1; C:\\Temp\\patch-agent.ps1\"",
    "crowdstrike.event.ParentImageFileName": "cmd.exe",
    "crowdstrike.event.ParentProcessId": "6210",
    "crowdstrike.event.UserName": "CORP\\d.okafor",
    "crowdstrike.event.HostName": "WS-IT-0912",
    "data.context":
      "d.okafor is a Tier 2 IT support technician. The GitHub repo 'nexacorp-it/deploy-scripts' is the company's own internal automation repository, referenced in three change-tickets this month.",
  },
};

// ── Analyst-choice event: alert LOOKS scary but is benign (jump-to-conclusions trap) ──
const analystChoiceEvent: TelemetryEvent = {
  id: "evt-mind-ac1-001",
  ts: "2024-09-05T22:47:12.000Z",
  source: "edr",
  vendor: "CrowdStrike Falcon",
  event_type: "process_create",
  severity: "high",
  hostname: "WS-HR-1188",
  user_email: "m.chen@nexacorp.com",
  src_ip: "10.10.11.44",
  description: "PowerShell launched with an encoded command by an HR employee outside business hours",
  mitre_technique: "T1059.001",
  mitre_tactic: "Execution",
  raw: {
    "event.module": "crowdstrike",
    "event.dataset": "crowdstrike.falcon",
    "crowdstrike.event.EventType": "ProcessRollup2",
    "crowdstrike.event.FileName": "powershell.exe",
    "crowdstrike.event.CommandLine":
      "powershell.exe -enc VwByAGkAdABlAC0ASABvAHMAdAAgACIAQgBhAGMAawB1AHAAIABjAG8AbQBwAGwAZQB0AGUAIgA=",
    "crowdstrike.event.ParentImageFileName": "BackupAgentService.exe",
    "crowdstrike.event.ParentProcessId": "1204",
    "crowdstrike.event.ParentImagePath": "C:\\Program Files\\Veeam\\Backup\\BackupAgentService.exe",
    "crowdstrike.event.UserName": "CORP\\SYSTEM",
    "crowdstrike.event.HostName": "WS-HR-1188",
    "crowdstrike.event.FileSigned": "true",
    "data.decoded_command": "Write-Host \"Backup complete\"",
    "data.context":
      "The parent process is the signed Veeam backup agent service, running as SYSTEM, and this workstation is scheduled for a nightly 22:45 backup job per the IT change calendar.",
  },
};

// ── Room definition ──────────────────────────────────────────────────────
const analystMindsetRoom = {
  id: "analyst-mindset",
  title: "The Analyst Mindset: How to Think and Ask the Right Questions",
  description:
    "Learn to think like a SOC analyst, not just operate like one. This room is not about clicking through a workflow — it is about the mental habits that separate an analyst who spots real threats from one who rubber-stamps alerts. You will practice forming hypotheses, asking the right questions of every alert, building a baseline of 'normal', catching your own cognitive biases in the act, and knowing when to keep digging versus when to close a case with confidence.",
  difficulty: "beginner" as const,
  category: "SOC Operations",
  estimatedMinutes: 55,
  xp: 370,
  icon: "🧠",
  prerequisites: ["soc-structure"],
  tasks: [
    // ── Reading 1: What it means to "think like an analyst" ──────────────
    {
      type: "reading" as const,
      id: "mind-r1",
      heading: "What Does It Mean to \"Think Like an Analyst\"?",
      content:
        "Imagine two people looking at the exact same pile of evidence. The first person sees a list of facts and moves on. The second person sees a list of facts and starts asking questions: *Why is this here? What does this normally look like? What would I expect to find if my theory is correct — and did I find it?* The second person is thinking like an analyst. The facts did not change. The thinking did.\n\n" +
        "This room is not about the mechanical steps of an investigation — you already learned that workflow (trigger, scope, collect, analyze, conclude, document) in the Investigation Methodology room. This room is about what happens INSIDE your head during that 'analyze' step, and honestly, during every step. It is about the questions you ask, the assumptions you refuse to make, and the discipline it takes to change your mind when the evidence tells you to.\n\n" +
        "**The Detective Analogy**\n\n" +
        "A good detective does not look at a crime scene and immediately announce a suspect. A good detective looks at the evidence and asks: *what story does this evidence tell, and what OTHER stories could also explain it?* They form a working theory, then they deliberately go looking for evidence that would prove that theory WRONG — not just evidence that confirms it. If the theory survives that stress test, it graduates from 'guess' to 'conclusion.'\n\n" +
        "**The ER Doctor Analogy**\n\n" +
        "An emergency room doctor does not treat every patient with a headache the same way. A doctor asks a structured set of questions — when did it start, how severe, any other symptoms, any relevant history — before forming a differential diagnosis: a ranked list of possible explanations, from most likely and most dangerous down to least likely. Only then do they order the right test to rule possibilities in or out. A SOC analyst does the same thing with an alert: form a ranked list of what this COULD be, then look for the specific piece of evidence that would confirm or kill each possibility.\n\n" +
        "**Why This Matters More Than Tool Knowledge**\n\n" +
        "You can teach almost anyone which button to click in a SIEM in an afternoon. You cannot teach curiosity and discipline in an afternoon — those take practice. The analysts who become genuinely excellent are not the ones who memorized the most field names. They are the ones who developed the habit of asking 'wait, does that actually make sense?' every single time something crosses their screen. That habit is what this room is trying to build in you.\n\n" +
        "**The Core Shift**\n\n" +
        "A beginner looks at an alert and asks: *'Is this bad?'* — a yes/no question that invites a guess. An analyst looks at the same alert and asks: *'What would have to be true for this to be normal, and what would have to be true for this to be an attack — and which of those things can I actually check?'* That reframe, from a guess to a checkable question, is the entire subject of this room.",
      codeExample:
        "BEGINNER QUESTION            ANALYST QUESTION\n" +
        "==================            ==================\n" +
        "\"Is this bad?\"           -->  \"What would make this normal, and what\n" +
        "                               would make this an attack? Which of\n" +
        "                               those can I check right now?\"\n\n" +
        "\"This looks scary.\"      -->  \"WHY does it look scary? Which specific\n" +
        "                               field triggered that reaction in me?\"\n\n" +
        "\"I've seen this before,\" -->  \"Was that PREVIOUS case actually the\n" +
        "\"it's fine.\"                  same, or am I pattern-matching too\n" +
        "                               fast on a surface similarity?\"\n\n" +
        "\"The user says it was\"  -->  \"Can I verify that independently, or\n" +
        "\"them.\"                       am I just trusting a claim?\"",
    },

    // ── Reading 2: Forming a hypothesis + the "so what?" chain ────────────
    {
      type: "reading" as const,
      id: "mind-r2",
      heading: "Forming a Hypothesis and the \"So What?\" Chain",
      content:
        "The single most useful habit you can build as a new analyst is this: before you touch a second data source, state out loud (or type into your notes) what you THINK is happening. This is your hypothesis. It does not need to be correct. It needs to exist, because a hypothesis gives your investigation direction. Without one, you are just staring at logs hoping something jumps out.\n\n" +
        "**Where a Hypothesis Comes From**\n\n" +
        "A hypothesis is your best guess at an explanation, built from the first few facts in front of you. If you see a PowerShell process with an encoded command, your hypothesis might be: 'this could be a malicious script trying to hide its command from casual inspection — OR it could be a legitimate internal automation tool that happens to encode its commands for reasons unrelated to evasion.' Notice that is not one hypothesis — it is two competing hypotheses. That is normal and healthy. Good analysts usually start with at least two: 'attack' and 'benign explanation.'\n\n" +
        "**The \"So What?\" Chain**\n\n" +
        "Once you have a hypothesis, the next skill is chaining it forward. For every fact you learn, ask 'so what does that mean, and what would I expect to see NEXT if my hypothesis is true?' This is called the 'so what?' chain, and it is what separates someone reading a log from someone actually reasoning about it.\n\n" +
        "Example chain: 'This host made a DNS query to a domain registered yesterday.' So what? 'Newly registered domains are disproportionately used for phishing and C2 infrastructure — attackers register them right before a campaign.' So what does that mean I should check next? 'If this is C2, I would expect to see repeated, regular connections to that domain afterward — a beacon pattern. Let me check the connection history for that host and that domain.' You just turned one fact into a specific, checkable next step — instead of guessing.\n\n" +
        "**\"What Would I Expect to See Next?\" Is the Engine**\n\n" +
        "This question is the engine that drives an investigation forward without you getting lost. Every time you learn something, ask: if my current theory is correct, what OTHER evidence should exist somewhere in my environment? Then go look for it. If you find it, your theory gets stronger. If you look and it is NOT there, that is just as valuable — it means your theory might be wrong, or incomplete, and you need to adjust it.\n\n" +
        "**A Worked Example**\n\n" +
        "Alert: a workstation made an outbound connection to an IP address on port 4444. Hypothesis: 'this could be a reverse shell — 4444 is a classic Metasploit default port.' So what would I expect to see next if that is true? 'I would expect a suspicious parent process that spawned the connection, likely something that should not be making network connections at all, like cmd.exe, powershell.exe, or a browser exploited via a malicious document. I'd also expect this to be a NEW destination for this host — not one it talks to regularly.' You check the process tree: sure enough, a Word document spawned cmd.exe, which spawned the connection. Your hypothesis just gained real support because the evidence you PREDICTED you'd find, you actually found.\n\n" +
        "Contrast that with: you check the process tree and find the connection came from a legitimate backup agent that has used port 4444 for three years, to the same IP, every night. Your hypothesis just failed the test — and that is a GOOD outcome, because it stopped you from escalating a false positive.",
      codeExample:
        "THE 'SO WHAT?' CHAIN — WORKED EXAMPLE\n" +
        "========================================\n\n" +
        "FACT: Outbound connection to 91.x.x.x:4444\n" +
        "   |\n" +
        "   v  \"So what?\"\n" +
        "MEANING: Port 4444 is a common reverse-shell / C2 default port\n" +
        "   |\n" +
        "   v  \"What would I expect to see next if this is really C2?\"\n" +
        "PREDICTION: A suspicious parent process (not a normal user action)\n" +
        "            AND this destination should be NEW for this host\n" +
        "   |\n" +
        "   v  Go check the process tree + connection history\n" +
        "RESULT A: WINWORD.EXE -> cmd.exe -> connection  (prediction CONFIRMED)\n" +
        "          --> hypothesis strengthens, escalate\n\n" +
        "RESULT B: BackupAgent.exe -> same IP every night for 3 years\n" +
        "          (prediction FAILED)\n" +
        "          --> hypothesis weakens, likely benign, document and close",
    },

    // ── Reading 3: The question framework for every alert ────────────────
    {
      type: "reading" as const,
      id: "mind-r3",
      heading: "The Question Framework: What to Ask of Every Single Alert",
      content:
        "Regardless of source — a firewall block, a failed login, a DLP alert, an EDR detection — there is a small set of questions that applies to almost every alert you will ever see. Memorize these. They will not always be answerable immediately, but asking them is what keeps your thinking structured instead of scattered.\n\n" +
        "**WHO** — Who is the user or account involved? Is it a real named human, a service account, or a shared/generic account? Does this account normally do the thing the alert describes? A service account behaving like a human (interactive logon, browsing, opening documents) is far more suspicious than a human behaving like a human.\n\n" +
        "**WHAT** — What actually happened, in plain language, stripped of jargon? If you cannot explain the event to a non-technical manager in one sentence, you do not understand it well enough yet. What process, what file, what action, what protocol?\n\n" +
        "**WHERE** — Where did this happen? Which host, which network segment, which geographic location? Is this host a high-value asset (domain controller, finance server) or a low-value one (spare kiosk machine)? Location changes the urgency dramatically.\n\n" +
        "**WHEN** — When did this happen, relative to normal patterns? Business hours or 3 AM? Weekday or weekend? Right before or after a known change window, holiday, or mass layoff? Timing alone does not prove anything, but it is a powerful multiplier on suspicion.\n\n" +
        "**WHY** — Why would this legitimately happen? Force yourself to generate the innocent explanation FIRST, before you generate the attack explanation. This single habit — actively searching for the benign reason before you search for the malicious one — is the best anti-bias practice you can build. If you can think of no plausible innocent reason at all, that itself is meaningful information.\n\n" +
        "**IS THIS NORMAL FOR THIS ENTITY?** — Not 'is this normal in general' but 'is this normal for THIS specific user, THIS specific host, THIS specific application?' A remote PowerShell session might be completely routine for an IT admin's workstation and wildly abnormal for the CFO's laptop. Generic normality is a trap; you need entity-specific normality, which is exactly what a baseline gives you (next reading).\n\n" +
        "**WHAT IS THE BLAST RADIUS?** — If this turns out to be a real attack, what is the worst-case scope? One workstation, or a domain admin account that touches everything? A guest Wi-Fi laptop, or a server holding customer payment data? You do not need to know the full scope to ask this question — asking it early tells you how urgently to move and who to notify if things escalate.\n\n" +
        "Run every alert through this list, even briefly, even mentally. Most of the time you will answer three or four of the six questions in ten seconds and immediately know whether this is routine. The value of the framework is in the harder 10% of cases, where forcing yourself through all six questions stops you from missing something a rushed glance would skip.",
      codeExample:
        "THE SIX-QUESTION ALERT FRAMEWORK\n" +
        "==================================\n" +
        "  1. WHO      -- real user? service account? does this fit their role?\n" +
        "  2. WHAT     -- can I explain this event in one plain sentence?\n" +
        "  3. WHERE    -- which host/segment? high-value asset or low-value?\n" +
        "  4. WHEN     -- normal hours? tied to a known change window?\n" +
        "  5. WHY      -- what is the INNOCENT explanation? (ask this first!)\n" +
        "  6. BLAST RADIUS -- if this is real, how bad could it get, and who\n" +
        "                     needs to know if it escalates?\n\n" +
        "RULE OF THUMB:\n" +
        "  If you can't answer WHY (innocent explanation) AND the WHO/WHERE/WHEN\n" +
        "  all look abnormal together -- that convergence of multiple abnormal\n" +
        "  answers is what should raise your suspicion, not any single field\n" +
        "  alone.",
    },

    // ── Reading 4: Baselining "normal" ────────────────────────────────────
    {
      type: "reading" as const,
      id: "mind-r4",
      heading: "You Cannot Spot Abnormal Until You Know Normal",
      content:
        "Here is a fact that trips up almost every new analyst: an event is never suspicious in a vacuum. 'PowerShell ran with an encoded command' is not inherently an attack — some legitimate enterprise tools do exactly that. 'A login happened at 3 AM' is not inherently an attack — some employees legitimately work odd hours, and some legitimate scheduled jobs run overnight. Suspicion is not a property of the event. Suspicion is a property of the GAP between the event and what is normal for that specific entity.\n\n" +
        "**What a Baseline Actually Is**\n\n" +
        "A baseline is your working mental (or documented) model of what normal looks like for a user, a host, an application, or a network segment. Building one does not require fancy UEBA tooling, though that helps at scale. It requires asking questions like: does this user normally log in from this location? Does this server normally make outbound connections at all? Does this application normally spawn a command shell? Does this account normally touch this file share?\n\n" +
        "**Sources for Building a Baseline on the Fly**\n\n" +
        "You will not always have a perfect historical baseline available, but you can usually approximate one quickly: check the user's job title and department (does the ROLE make this activity plausible?), check the asset's function (is this a workstation, a server, a kiosk?), check recent history for this specific user or host in the SIEM (search their last 30 days — is this a first-time occurrence or a daily routine?), and check any change-management or ticketing system (was this activity pre-approved?).\n\n" +
        "**First-Time-Seen Is a Powerful Signal**\n\n" +
        "One of the single most useful questions in all of SOC analysis is simply: 'has this specific combination happened before?' A host connecting to a new external IP for the first time ever. A user accessing a file share they have never touched. An admin account logging in from a country it has never logged in from. None of these facts alone proves an attack — but 'first time ever' dramatically raises the value of investigating further, because attackers, by definition, are doing something that was not happening before they arrived.\n\n" +
        "**The Trap of Assuming Generic Normal**\n\n" +
        "The most common baselining mistake is substituting generic assumptions ('everyone logs in from home sometimes,' 'IT people run scripts all the time') for entity-specific facts. Generic assumptions are exactly the gap attackers exploit, because they know analysts often reach for the easy generic explanation instead of doing the ten extra seconds of work to check whether it is true for THIS user, THIS host, right now.",
      codeExample:
        "QUICK BASELINE CHECKLIST (do this before judging 'normal vs abnormal')\n" +
        "==========================================================\n" +
        "  [ ] What is this user's actual job role? Does the activity fit it?\n" +
        "  [ ] What is this asset's function? (workstation / server / kiosk)\n" +
        "  [ ] Search the SIEM: has THIS user/host done THIS before? (30-90 days)\n" +
        "  [ ] Is there a change ticket, maintenance window, or business\n" +
        "      justification on file?\n" +
        "  [ ] Is this the FIRST TIME this specific combination has occurred?\n" +
        "      (new destination, new tool, new login location, new file share)\n\n" +
        "  Generic normal (\"lots of people do this\") is NOT the same as\n" +
        "  entity-specific normal (\"THIS person/host does this regularly\").\n" +
        "  Always check the specific case before trusting the generic one.",
    },

    // ── Reading 5: Cognitive biases that trip analysts ────────────────────
    {
      type: "reading" as const,
      id: "mind-r5",
      heading: "Cognitive Biases That Quietly Sabotage Analysts",
      content:
        "Your brain has shortcuts built in to help you make fast decisions with limited information. Those shortcuts are extremely useful in daily life and extremely dangerous in a SOC, because attackers benefit every time your shortcuts lead you to the wrong conclusion. Knowing these biases by name is the first step to catching them in yourself.\n\n" +
        "**Confirmation Bias** — Once you form a hypothesis, you unconsciously start noticing evidence that supports it and glossing over evidence that contradicts it. If you decide early that 'this is probably just IT doing maintenance,' you will read every subsequent log line through that lens, even ones that do not actually fit. The fix: deliberately look for the piece of evidence that would PROVE you wrong, not just more evidence that confirms you right.\n\n" +
        "**Alert Fatigue** — After triaging your two-hundredth false positive of the shift, your brain starts pattern-matching alert #201 to 'probably also nothing' before you have actually looked at it. This is not laziness — it is a real neurological response to repetitive low-stakes decisions. The fix: build in a hard rule that every alert, no matter how routine-looking, gets at least the six-question framework applied, even if it takes fifteen seconds. Routine checks catch the rare real attack hiding inside a flood of noise.\n\n" +
        "**Anchoring** — The first piece of information you see disproportionately shapes everything after it. If the alert title says 'Likely False Positive — Known Scanner IP,' you will subconsciously interpret every subsequent fact as supporting that label, even when a fact is genuinely ambiguous. The fix: try to look at the raw evidence BEFORE reading any pre-existing severity label, verdict, or analyst note, when practical — or at least consciously ask 'would I read this fact the same way if the label said the opposite?'\n\n" +
        "**Tunnel Vision** — Once you lock onto one theory, you stop looking for alternative explanations or additional scope. You find the compromised laptop and stop there, without asking 'did this attacker touch anything ELSE?' The fix: before closing any confirmed incident, explicitly ask 'what ELSE would I expect to see if this is bigger than what I've found so far?' — the blast-radius question from the framework — even after you already have an answer that feels satisfying.\n\n" +
        "**Availability Bias** — You judge how likely something is by how easily an example comes to mind. If your team just dealt with a ransomware incident last week, you will over-weight ransomware as an explanation for an unrelated alert this week, simply because it is fresh in memory. The fix: consciously generate a full list of possible explanations rather than going with the first (most memorable) one.\n\n" +
        "**Authority Bias** — If a senior analyst, a manager, or even the ticket's previous handler already labeled something 'benign,' you are less likely to question it, even if you notice something odd. The fix: treat previous verdicts as a helpful data point, not a substitute for your own look at the evidence — especially if new information has appeared since that verdict was made.\n\n" +
        "None of these biases make you a bad analyst — they make you human. The goal is not to eliminate them (you cannot) but to recognize the moment they are steering you, and to build habits — like actively searching for disconfirming evidence — that counteract them.",
    },

    // ── Reading 6: Fact vs assumption, and when to stop digging ──────────
    {
      type: "reading" as const,
      id: "mind-r6",
      heading: "Separating Fact From Assumption — and Knowing When to Stop",
      content:
        "Every investigation note you will ever write contains a mix of two very different kinds of statements: facts and assumptions. A fact is something you directly observed in a log, a screen, or a system — it is verifiable and someone else could independently confirm it by looking at the same data. An assumption is something you are inferring, guessing, or taking on someone's word without independent verification. Both have a place in an investigation, but only if you know which is which.\n\n" +
        "**Learn to Label Your Own Statements**\n\n" +
        "'The workstation made a DNS query to a domain registered yesterday' — that is a fact, pulled directly from a log. 'The user probably clicked a phishing link' — that is an assumption, unless you have actually confirmed a click event, a browser history entry, or the user's own account of what they did. Both statements might end up in your case notes, but they should never be written in a way that makes the reader think both are equally certain. Good analysts get in the habit of phrasing things precisely: 'the log shows X' versus 'this suggests X' versus 'the user reported X, unverified.'\n\n" +
        "**The Danger of Silent Assumptions**\n\n" +
        "The most dangerous assumptions are the ones you do not even notice you are making. 'The user said it was them logging in from that new country, so it's fine' quietly assumes the user's account was not already compromised and being used to explain away the very evidence that would reveal the compromise. 'MFA was approved, so it must be legitimate' quietly assumes MFA cannot be bypassed or that the user did not approve a push notification by mistake (MFA fatigue). Whenever you catch yourself about to close a case, go back through your reasoning and ask: 'which of these statements did I actually verify, and which am I just trusting?'\n\n" +
        "**When to Keep Digging**\n\n" +
        "Keep investigating when: you have an unanswered question from the six-question framework that you CAN answer with available data but have not checked yet; a fact you found does not fit your current hypothesis at all (do not paper over it — that is confirmation bias in action); the blast-radius question is still open (you know one host is affected but have not checked whether the attacker moved laterally); or a claim from the user or another team is unverified and verification is possible.\n\n" +
        "**When to Stop and Close**\n\n" +
        "Stop when: every question in the framework has either been answered by verified fact or is genuinely unanswerable with reasonably available data (and you have documented that gap honestly, rather than guessing to fill it); the evidence you predicted you would find (from your 'so what?' chain) either appeared or clearly did not, giving you a real answer either way; you have checked for related activity (blast radius) and found none; and your conclusion could be independently reproduced by another analyst reading only your documented facts — not your gut feeling.\n\n" +
        "**A Useful Gut-Check**\n\n" +
        "Before closing any case, ask yourself one final question: 'if I am wrong about this, what would that cost, and did I do enough work to justify that risk?' Closing a low-value kiosk machine's odd DNS query after a five-minute check is reasonable. Closing a domain administrator's odd DNS query after the same five-minute check is not — the cost of being wrong is completely different, and your depth of digging should scale with that cost, not just with how busy your queue is.",
      codeExample:
        "FACT vs ASSUMPTION -- LABEL EVERY STATEMENT\n" +
        "=============================================\n" +
        "  FACT       : \"the log shows...\"      (directly observed, verifiable)\n" +
        "  ASSUMPTION  : \"this suggests...\"       (your inference)\n" +
        "  UNVERIFIED  : \"the user reported...\"   (someone's claim, not checked)\n\n" +
        "KEEP DIGGING IF:\n" +
        "  - an answerable framework question is still open\n" +
        "  - a fact contradicts your current hypothesis\n" +
        "  - blast radius is unconfirmed\n" +
        "  - a claim is unverified and verification is possible\n\n" +
        "OK TO CLOSE IF:\n" +
        "  - framework questions are answered by fact, or the gap is documented\n" +
        "  - your predicted evidence was checked (found OR clearly absent)\n" +
        "  - blast radius was checked, nothing further found\n" +
        "  - another analyst could reach your conclusion from your notes alone\n\n" +
        "GUT-CHECK: \"If I'm wrong, what does that cost -- and did my digging\n" +
        "            match that cost?\"",
    },

    // ── Question 1 ──────────────────────────────────────────────────────
    {
      type: "question" as const,
      id: "mind-q1",
      question:
        "An analyst sees an alert titled 'Likely benign — known IT scanning tool' before looking at any raw evidence, and finds themselves agreeing with that label almost immediately without really checking the details. Which bias is most directly at play?",
      options: [
        "Availability bias — recent memorable incidents are distorting the judgment",
        "Anchoring — the pre-existing label is disproportionately shaping how the analyst reads everything that follows",
        "Alert fatigue — too many alerts triaged in a row",
        "Tunnel vision — locking onto one theory and ignoring alternative scope",
      ],
      answer: 1,
      explanation:
        "This is a textbook example of anchoring: the first piece of information (a pre-written label) shapes the interpretation of everything the analyst looks at afterward, even before they have evaluated the raw evidence themselves. The fix is to look at raw evidence first when possible, or consciously ask 'would I interpret this fact the same way if the label said the opposite?'",
      xp: 30,
    },

    // ── Question 2 ──────────────────────────────────────────────────────
    {
      type: "question" as const,
      id: "mind-q2",
      question:
        "You are applying the 'so what?' chain to an alert about a host connecting to a domain registered yesterday. What is the correct NEXT step after concluding 'newly registered domains are often used for phishing/C2'?",
      options: [
        "Immediately escalate the case as a confirmed compromise without further checks",
        "Close the alert, since domain age alone rarely proves anything conclusively",
        "Ask what evidence you would expect to find if this really is C2 (e.g. a repeating beacon pattern) and go check specifically for that",
        "Ask the end user whether they visited the domain on purpose and accept their answer as the final word",
      ],
      answer: 2,
      explanation:
        "The 'so what?' chain works by turning each fact into a specific, checkable prediction. After identifying why the fact matters (domain age correlates with malicious use), the next step is to predict what OTHER evidence should exist if your hypothesis is correct (a beacon pattern, repeated regular connections) and then go verify whether that predicted evidence actually exists. This turns a vague suspicion into a testable, evidence-based conclusion — rather than jumping to escalation or closure, or relying solely on an unverified user claim.",
      xp: 30,
    },

    // ── Question 3 ──────────────────────────────────────────────────────
    {
      type: "question" as const,
      id: "mind-q3",
      question:
        "Two facts about an alert: (1) 'the process was svchost.exe' and (2) 'the user probably launched it by accident.' How should these two statements be treated in your investigation notes?",
      options: [
        "Both should be written with equal confidence, since they both appeared during the same investigation",
        "Statement 1 is a verifiable fact from the log; statement 2 is an assumption/inference and should be clearly labeled as such unless independently confirmed",
        "Statement 2 is more important because it explains motive, so it should be listed first and treated as the primary conclusion",
        "Neither statement matters until the case is escalated to Tier 3",
      ],
      answer: 1,
      explanation:
        "Separating fact from assumption is a core analyst discipline. 'The process was svchost.exe' is something directly observable in the log — a fact. 'The user probably launched it by accident' is an inference about intent that has not been verified (e.g. by asking the user, or by other corroborating evidence) — it should be phrased as a hypothesis or unverified claim, not stated as established truth. Blurring this distinction in case notes misleads anyone who reads them later.",
      xp: 25,
    },

    // ── Log analysis 1: the 3AM logon ─────────────────────────────────────
    {
      type: "log_analysis" as const,
      id: "mind-la1",
      heading: "Practice the Framework — A 3 AM Logon on a Finance Workstation",
      context:
        "You are a Tier 1 analyst and this alert just landed in your queue: a successful interactive logon on a finance workstation at 03:12 AM. Your first instinct might be alarm — but instead of reacting, walk through the six-question framework deliberately. Read the event, including the context note, and answer the questions below by reasoning through WHO, WHEN, WHY, and what is/is not verified.",
      event: midnightLogonEvent,
      questions: [
        {
          question:
            "Which piece of information in this event is a FACT, and which is closer to an ASSUMPTION you should still verify independently before fully trusting it?",
          options: [
            "The logon time (03:12 AM) is an assumption; the badge swipe is a fact",
            "The logon event itself (event.code 4624, LogonType 2) is a fact pulled directly from the log; the badge system record and calendar note are additional facts from OTHER systems that corroborate the story, but should still be cross-checked for tampering or coincidence rather than accepted purely at face value",
            "Everything in the raw log and the context note should be treated as equally certain, since it all came from company systems",
            "None of this can be trusted without asking the user directly first",
          ],
          answer: 1,
          explanation:
            "The AD logon event (event.code 4624, LogonType 2 = interactive) is a directly observed fact from the authentication log. The badge swipe and calendar note are ALSO facts (from other systems), but they are corroborating evidence from separate sources, which is exactly what you want — independent confirmation, not just one system's word. A disciplined analyst still asks 'could any of these be spoofed or coincidental?' rather than assuming multiple systems agreeing means it's automatically closed — but here, badge + calendar + AD logon aligning is strong, multi-source support for the benign explanation.",
          xp: 35,
        },
        {
          question:
            "Applying the 'WHY' question from the framework (find the innocent explanation FIRST) — what is the most plausible benign explanation here, and what would make you suspicious enough to keep digging despite it?",
          options: [
            "There is no plausible benign explanation for a 3 AM logon, so this should always be escalated as an attack regardless of context",
            "The benign explanation is quarter-close overtime, supported by the calendar note and badge swipe; you would still dig further if, for example, the badge system showed no matching swipe, or if this user had never logged in this late before in their history",
            "Since LogonType is 2 (interactive) rather than 3 (network), this can never be an attack, so no further checking is needed",
            "The workstation name (WS-FIN-2041) alone proves this is authorized financial activity",
          ],
          answer: 1,
          explanation:
            "This event demonstrates 'first-time-seen' style baselining and the WHY-first habit: the benign explanation (late-night quarter-close work) fits, and it is independently corroborated by the badge system (physical presence, same person) and a calendar note. A good analyst would still keep digging if any of those corroborating facts were missing or contradictory — e.g., no matching badge swipe, or this being the user's first-ever late night login with no supporting business reason. LogonType alone does not prove intent, and the workstation name alone is not proof of authorization — it is the CONVERGENCE of multiple independent, verifiable facts that builds real confidence.",
          xp: 35,
        },
      ],
    },

    // ── Log analysis 2: the PowerShell download ────────────────────────────
    {
      type: "log_analysis" as const,
      id: "mind-la2",
      heading: "Practice the Framework — PowerShell Downloading and Running a Script",
      context:
        "An IT support technician's workstation launched PowerShell with a command that downloads a script from GitHub and immediately executes it. On the surface, 'download a script from the internet and run it' is a pattern security training tells you to fear. Walk through the framework before reacting.",
      event: powershellDownloadEvent,
      questions: [
        {
          question:
            "Using the 'blast radius' and 'is this normal for this entity' questions together, what is the single most important fact that changes how you should read this alert?",
          options: [
            "The process name is powershell.exe, which is inherently suspicious regardless of context",
            "The script is hosted on the company's OWN internal GitHub organization (nexacorp-it/deploy-scripts), and the user is a Tier 2 IT technician whose job role plausibly includes running deployment scripts — this is entity-specific normal, not generic 'PowerShell is always scary'",
            "The parent process is cmd.exe, which always indicates malware staging",
            "-ExecutionPolicy Bypass always means an attack, with no legitimate use case"
          ],
          answer: 1,
          explanation:
            "This event is designed to test whether you fall for surface-level pattern matching ('PowerShell + download + execute = attack') versus doing the actual WHO/WHERE/WHY check. The repository belongs to the company's own IT organization, referenced in real change tickets, and the user's job role (Tier 2 IT support) plausibly includes exactly this kind of activity. -ExecutionPolicy Bypass and downloading-then-running a script ARE genuinely used in attacks too — which is why you still verify (check the repo owner, check the ticket references, check the user's role) rather than dismissing OR escalating on pattern alone.",
          xp: 35,
        },
        {
          question:
            "Even though the context here looks benign, what specific follow-up check would still be reasonable before fully closing this alert, consistent with 'keep digging until questions are actually answered' rather than just accepting the surface story?",
          options: [
            "None — the GitHub org name alone is sufficient proof, no further check needed",
            "Verify that the referenced change tickets are real, currently open/approved, and actually correspond to this specific script and time window — rather than just trusting that a plausible-sounding org name means the activity was authorized",
            "Escalate automatically regardless of findings, because PowerShell was involved",
            "Ask the technician for a verbal confirmation and treat that as sufficient proof on its own"
          ],
          answer: 1,
          explanation:
            "A disciplined analyst distinguishes between a PLAUSIBLE story and a VERIFIED one. The org name looking legitimate is a good sign but is not, by itself, proof against something like a compromised internal GitHub account or an insider threat. Cross-checking the actual change tickets (an independent system) for a match to this specific script and time window is the kind of low-cost verification that turns 'this looks fine' into 'this IS fine, and I can show my work.' A verbal claim from the technician alone is an unverified assumption, not confirmation.",
          xp: 35,
        },
      ],
    },

    // ── Analyst choice: don't jump to conclusions trap ─────────────────────
    {
      type: "analyst_choice" as const,
      id: "mind-ac1",
      heading: "Verdict: Scary-Looking Alert — True Positive or False Positive?",
      scenario:
        "22:47 at night. An EDR alert fires as HIGH severity: powershell.exe launched with a Base64-encoded command (-enc) on an HR employee's workstation, outside business hours. Encoded PowerShell commands are a well-known technique attackers use to hide malicious commands from casual log review. Before you react to the severity label, walk through WHO launched it, WHAT the decoded command actually says, and WHETHER the timing fits any known schedule. What is your verdict?",
      event: analystChoiceEvent,
      correct_verdict: "false_positive" as const,
      explanation:
        "This is a false positive, and the trap is the surface pattern: 'PowerShell + Base64-encoded command + after hours' is a combination security training teaches you to fear, and the HIGH severity label reinforces that instinct. But walking through the framework changes the picture completely. WHO: the parent process is not a user shell at all — it is BackupAgentService.exe, a signed Veeam backup service, running as SYSTEM (not an interactive human account). WHAT: the context note shows the decoded command is simply Write-Host \"Backup complete\" — a completely benign status message, not an attack payload. WHEN: 22:45 matches the documented nightly backup schedule on the IT change calendar. Many legitimate enterprise tools Base64-encode PowerShell commands for reasons unrelated to evasion (safely passing special characters, multi-line scripts, or internal tooling conventions) — encoding itself is not proof of malicious intent, only a reason to look closer at WHO ran it and WHAT it actually says.",
      fp_trap:
        "The HIGH severity label and the well-known 'Base64-encoded PowerShell' attacker technique both push you toward an immediate escalation instinct. This is exactly the anchoring and pattern-matching trap the room warns about: the correct response is not to trust the scary-looking surface pattern, but to actually decode the command, check the true parent process, and check whether the timing matches a documented schedule — all of which are quick, verifiable checks that flip the verdict from 'attack' to 'signed backup software doing exactly what it is scheduled to do.'",
      xp: 35,
    },

    // ── Matching: bias to example ──────────────────────────────────────
    {
      type: "matching" as const,
      id: "mind-m1",
      heading: "Match Each Cognitive Bias to the Scenario That Illustrates It",
      instructions:
        "Analysts fall into predictable mental traps. Match each cognitive bias on the left to the SOC scenario on the right that best illustrates it in action.",
      pairs: [
        {
          id: "confirmation",
          left: "Confirmation bias",
          right: "An analyst decides early that an alert is 'probably just a scanner' and then reads every subsequent log line in a way that supports that idea, without ever looking for evidence that would contradict it",
        },
        {
          id: "fatigue",
          left: "Alert fatigue",
          right: "After closing 150 similar low-priority alerts in a shift, the analyst spends only two seconds glancing at alert #151 before marking it benign — even though it is subtly different from the rest",
        },
        {
          id: "anchoring",
          left: "Anchoring",
          right: "The alert arrives pre-labeled 'Likely False Positive' by the SIEM's auto-triage rule, and the analyst's read of the raw evidence is subconsciously shaped by that label before they've even looked at it",
        },
        {
          id: "tunnel",
          left: "Tunnel vision",
          right: "An analyst finds one compromised laptop, fixes it, and closes the case — without ever checking whether the attacker used those same credentials to touch any other system",
        },
        {
          id: "availability",
          left: "Availability bias",
          right: "Because the team handled a ransomware outbreak last week, an unrelated alert this week gets over-weighted toward 'this is probably ransomware too', simply because ransomware is fresh in everyone's mind",
        },
        {
          id: "authority",
          left: "Authority bias",
          right: "A junior analyst notices something odd in a case, but since a senior analyst already labeled it 'benign' last week, they don't raise the concern or re-check it themselves",
        },
      ],
      explanation:
        "Recognizing these biases by NAME is what makes them catchable in the moment. Confirmation bias and anchoring both distort how you READ evidence; alert fatigue and availability bias distort how much ATTENTION and WEIGHT you give an alert; tunnel vision distorts how far you look for SCOPE; and authority bias distorts whether you trust your OWN observations over someone else's prior verdict. The counter-habit for nearly all of them is the same: actively look for the piece of evidence that would prove your current belief wrong, rather than only looking for evidence that confirms it.",
      xp: 40,
    },

    // ── Ordering: mental triage steps ────────────────────────────────────
    {
      type: "ordering" as const,
      id: "mind-o1",
      heading: "Order the Mental Steps of Triaging an Ambiguous Alert",
      instructions:
        "When an alert lands that is not immediately obvious as benign or malicious, there is a natural mental order to work through it. Arrange these steps from the first thing you should do to the last.",
      items: [
        {
          id: "react",
          text: "Notice your gut reaction to the alert (e.g. 'this looks scary' or 'this looks routine') and consciously set it aside rather than acting on it immediately",
        },
        {
          id: "framework",
          text: "Run the alert through the six-question framework: who, what, where, when, why (innocent explanation first), and blast radius",
        },
        {
          id: "hypothesis",
          text: "Form at least two competing hypotheses — one benign explanation and one attack explanation",
        },
        {
          id: "predict",
          text: "For your leading hypothesis, ask 'what would I expect to see next if this is true?' and identify a specific, checkable prediction",
        },
        {
          id: "verify",
          text: "Go check whether that predicted evidence actually exists, treating the result honestly whether it supports or contradicts your hypothesis",
        },
        {
          id: "decide",
          text: "Decide whether open questions remain that are answerable (keep digging) or whether the case is sufficiently supported by verified fact (document and close)",
        },
      ],
      correct_order: ["react", "framework", "hypothesis", "predict", "verify", "decide"],
      explanation:
        "The mental sequence starts with catching your own instinct so it doesn't drive premature conclusions, then structures your thinking with the six-question framework, then turns that structured understanding into competing testable hypotheses, then makes a specific prediction from your leading hypothesis, then actually verifies that prediction against real evidence, and only then decides whether to keep digging or close. Skipping straight from 'gut reaction' to 'decide' is exactly how false positives get escalated and real attacks get dismissed.",
      xp: 40,
    },

    // ── Flag ──────────────────────────────────────────────────────────────
    {
      type: "flag" as const,
      id: "mind-flag1",
      prompt:
        "Look back at the PowerShell download log analysis event above (the IT technician running patch-agent.ps1). The 'data.context' field explains what made this activity verifiable rather than just plausible-sounding. Enter the exact GitHub organization name (the part before the slash) referenced in the process.command_line field that ties this activity to the company's own infrastructure.",
      answer: "nexacorp-it",
      hint: "Look at the URL in process.command_line — it follows the pattern github.com/ORGANIZATION/repository-name. The organization name comes right after 'raw.githubusercontent.com/'.",
      xp: 30,
    },
  ],
};

export default [analystMindsetRoom];
