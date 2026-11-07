import type { RoomExperience } from "./types";

// "Operation Chain of Command" for the "escalation-procedures" room.
// Script: docs/campaign/84-escalation-procedures.md.
// Station task ids must match the room's task order exactly (see getRoomExperience).
//
// Task order changed so each reading sits with the tasks it teaches:
// esc-read-1, esc-q1 | esc-read-2, esc-q2 | esc-read-3, esc-q3, esc-log-1 | esc-ac1
// (room order was esc-read-1, esc-read-2, esc-read-3, esc-q1, esc-q2, esc-q3, esc-log-1, esc-ac1).
// esc-q1 sits after reading 1 because that reading says Tier 1 closes clear false positives with
// documentation and works from playbooks. The room has no flag task.
//
// Ashdown Rail Freight (fictional), not the graded tasks' MSSP and FINANCE VLAN records.
// Signature: Wake Them or Wait? At 03:00 the learner decides who gets woken, with what message.
// A `queue` of night alerts where over-escalating burns the on-call and under-escalating loses
// an hour, then a real `chat` with the on-call lead where the learner gives a usable escalation:
// what, who, impact, what was done, what is needed.
// Game mix: chat + duel + tune. Other labs: anatomy, sort, sequence, queue, hotspot, match,
// worksheet, reactor.
// Lab data differs from the graded tasks: the incident is a credential dump by a stolen
// contractor account on one train-planning server, never ransomware, Maze, 12 hosts, a FINANCE
// VLAN or SRV-DC-01 (log-1, ac1); the known pattern is wagon telematics gateways re-authenticating
// at crew change, never a mistyped password or a VPN (q1); the bridge is a Duty Controller, a
// system owner and the on-call lead deciding on a departure, never 40 servers (q2); the clean
// neighbour is a signalling gateway, never a domain controller (log-1 q2); the page gaps are 8,
// 53, 7 and 82 minutes, never 09:14 to 09:45 (log-1 q1); the half-done cases are accounts, mail
// rules and remote sessions, never EDR isolating hosts (ac1). The day shift starts at 06:00, not
// 07:00. The Tier 2 isolation fact (read-1 checkpoint) appears only as a row on the on-call card.
//
// How chat grades: a typed message against regexes, case-insensitive, first hit wins. So failure
// rules come first and fire on every goal, then each goal's winning rule, partial rules that have
// Renata ask for the missing part, and a catch-all that coaches. `said()` keeps a rule from firing
// on its own negation: "this can't wait until 06:00" must pass where "this can wait until 06:00"
// must not. No lookbehind: it breaks new RegExp on older Safari. Curly apostrophes from phone
// keyboards are why every contraction is written with `.?`.
// memory: true, so winning rules read everything said toward the goal and every other rule reads
// only the last message. So a claim that should not count must not match the winning rule at all,
// because it stays in the pool: hedged clauses and "the trains are fine" are gated inside the
// pattern, and their coaching rules sit after the win. Failure rules run first. In the `whole`
// goal the partials ask for the part after the one just given (what, impact, done, need), so a
// learner answering one part at a time is led round to a win.

/** Words that negate what follows. */
const NEG = "\\b(?:can.?t|cannot|can not|won.?t|wouldn.?t|shouldn.?t|should not|mustn.?t|must not|don.?t|do not|doesn.?t|does not|didn.?t|did not|isn.?t|is not|aren.?t|are not|wasn.?t|was not|not|no(?!\\s+doubt)|never|unable|haven.?t|have not|hasn.?t|has not)\\b";
/** The same, plus words that leave the rest of a clause open. */
const NOT = `${NEG}|\\b(?:unsure|whether|if)\\b`;
/** Matches `phrase` only when nothing earlier in its own clause negates it. */
const said = (phrase: string, also = "") => `(?:^|[.!?;,:]\\s*|\\b(?:but|and|because|since|so)\\s+)(?:(?!${NOT}${also})[^.!?;,:])*(?:${phrase})`;
/** "Every hour we wait" and "by the time we wait" argue against waiting, they don't agree to it. */
const COSTING = "|\\b(?:while|by the time|every (?:hour|minute|moment)|each (?:hour|minute)|the (?:longer|more)|too (?:long|late))\\b|\\bcan.?t afford to\\b";
/** A guess: a clause carrying one of these doesn't count as a finding. */
const HEDGE = "\\b(?:maybe|might|perhaps|possibly|probably|not sure|i think|i guess|hunch|could be|may be|bad feeling|seems?|looks? like)\\b";
/** `a` and `b` in either order in one sentence, with no negation between them. */
const near = (a: string, b: string) => `(?:${a})(?:(?!${NEG})[^.!?]){0,70}(?:${b})|(?:${b})(?:(?!${NEG})[^.!?]){0,70}(?:${a})`;
/** All of these in the one message. */
const has = (...parts: string[]) => `^${parts.map(p => `(?=.*${p})`).join("")}`;
/** All of `parts`, and not `missing`. */
const lacks = (missing: string, ...parts: string[]) => `${has(...parts)}(?!.*${missing})`;

// Failure rules: what a tired analyst really says at 03:00.
const CULPRIT = "russia|china|chinese|north korea|\\biran|nation.?state|state.?sponsored|organi[sz]ed crime|crime gang|\\bapt\\b|a competitor|\\brival|\\binsider";
const SELF_ISOLATE = "\\b(?:i|we)(?:.ve| have| had)?\\s+(?:already\\s+|just\\s+)?(?:isolated|unplugged|cut (?:it|that|the server|ash-plan-02) off|pulled (?:it|that|the server|ash-plan-02|the plug)|took (?:it|that|the server|ash-plan-02) (?:off|down)|shut (?:it|that|the server|ash-plan-02) (?:off|down))";
const OVERCLAIM = "(?:whole|entire) (?:network|company|domain|estate|railway)[^.!?;,]{0,20}(?:compromised|hacked|infected|down|gone)|(?:everything|every (?:server|system|train)|all (?:the |our )?(?:servers|systems|trains))[^.!?;,]{0,20}(?:compromised|hacked|infected|down|gone)|we.?(?:ve| have) been hacked|stop (?:all|every)(?: the)? trains?";
const COMFORT = "under control|\\b(?:it|this|that|we|everything)(?:.?s| is| are|.re) (?:all |now )?(?:contained|fine|safe|handled|sorted|ok(?:ay)?)\\b(?!\\s+to\\b)|all good|nothing to worry";
const DOWNPLAY = "probably nothing|nothing serious|\\bcan (?:probably |likely |maybe |easily )?wait\\b|\\bcould (?:probably |likely |maybe )?wait\\b|wait (?:until|till|for) (?:the )?(?:morning|day|06)|not urgent|no rush|false alarm";

// The five parts of a usable escalation.
const WRONG = "dump|lsass|(?:credential|password)s?[^.!?]{0,30}(?:stolen|stole\\b|theft|taken|copied|harvest|exposed|compromis)|(?:steal|stole\\b|stolen|theft|harvest|copied|compromis)[^.!?]{0,30}(?:credential|password)|\\bhash(?:es)?\\b|comsvcs|stolen|stole\\b|attacker|intruder|intrusion|malicious|compromis|hack|breach|malware|unauthori[sz]ed";
const WHERE = "(?:ash-?\\s?plan-?\\s?0?2|plan(?:ning)? server|planning|halloran|contractor)";
const TRAINS = "\\b0?4[:.]?40(?:\\s?[ap]m)?|four.?forty|\\btrains?|departures?|timetable|schedule|tonight.?s plan|\\boperations|freight";
/** The trains named as at risk. "The trains are running fine" names them and says the opposite. */
const TRAINS_FINE = "\\s+(?:are|is|will be|should be|look|seem)\\s+(?:all\\s+|still\\s+)?(?:fine|ok|okay|unaffected|on time|running (?:fine|ok|okay|normally|as normal|on time))";
const AT_RISK = `(?:${TRAINS})\\b(?!${TRAINS_FINE})`;
const REACH = "\\badmins?\\b|administrator|credential|password|\\bhash(?:es)?\\b|lateral|spread|move (?:on|sideways|around|across)|next (?:server|host|system|hop)|other (?:servers|hosts|systems|machines)|privilege";
const STOPPED = "disabl|deactivat|suspend|revok|locked (?:out |down )?(?:the |that |his |her |their )?(?:account|user|contractor|login|d\\.?\\s?halloran|halloran)|(?:account|login|user|contractor|halloran)[^.!?;,]{0,30}\\b(?:locked|blocked|killed|kicked|shut off|turned off|switched off)|blocked (?:the |that )?(?:account|login|user|contractor|d\\.?\\s?halloran|halloran)|kill(?:ed)? (?:the |that |his |their )?(?:session|account)";
const TICKET = "ticket|inc-?\\s?5127";
const CUT_OFF = "isolat|off the network|disconnect|quarantin|cut(?:ting)? [^.!?]{0,30}off|tak(?:e|ing) [^.!?]{0,30}(?:off|offline)|pull(?:ing)? [^.!?]{0,30}off|containment|contain (?:it|that|the server|ash-plan-02)";
const ASK = "need|want|requir|approv|authori[sz]|sign.?off|permission|can you|could you|would you|will you|please|ok to|okay to|go.?ahead|your (?:call|decision|ok|okay|say)|recommend|request|asking|should we|suggest|propose|allow|let.?s|decision|decide";
const NEED_IT = `${said(near(ASK, CUT_OFF))}|(?:can.?t|cannot|can not|don.?t have|do not have|lack|not allowed to|not authori[sz]ed to)[^.!?]{0,40}(?:isolat|authority|approv|permission)|(?:beyond|above|outside) (?:my|our|tier 1)[^.!?]{0,20}(?:authority|permission)`;
// Who sits on the bridge, and which part of the decision each one holds.
const INES = "\\bines\\b|carvalho|duty controller|\\bcontroller\\b";
const OWNER = "\\bowner\\b";
const RENATA = "\\byou\\b|\\byours?\\b|renata|volkova|on.?call|tier 2";
const RENATA_DECIDES = said(near(RENATA, `${CUT_OFF}|approv|sign.?off`));
const INES_DECIDES = said(near(INES, `${TRAINS}|delay|hold`));
const OWNER_DECIDES = said(near(OWNER, "cop(?:y|ied|ying)|export|back.?up|sav(?:e|ing)|snapshot|extract|\\bplan\\b|restore"));

const ALL_WHAT = said(WRONG, `|${HEDGE}`);
const ALL_IMPACT = said(AT_RISK);
const ALL_DONE = said(STOPPED);
const ALL_NEED = `(?:${NEED_IT})`;

export const ESCALATION_PROCEDURES: RoomExperience = {
  roomId: "escalation-procedures",
  codename: "Operation Chain of Command",
  theme: "chainofcommand",
  handler: { name: "Renata Volkova", role: "SOC Shift Lead, Ashdown Rail Freight" },
  briefing: [
    "Ashdown Rail Freight. Container trains by night, three terminals, and one analyst on the SOC desk from 22:00 to 06:00.",
    "The first train leaves Thornley Gate at 04:40, and everything it carries was planned on one server.",
    "Renata Volkova holds the on-call pager and keeps one rule: a wasted page costs sleep, a held page costs an hour, and neither is free.",
    "Tonight the desk is yours. Learn who can do what, then decide who gets woken, and with what message.",
  ],
  mission: "Learn whose desk each job lands on, close a known pattern properly, set the night pager, work the night queue, wake Renata with a message that can be acted on, see who gets called next, read the record back, then give the verdict on the graded case.",
  estimate: "~45 min",
  look: { primary: "#f7b267", secondary: "#7bdff2", warn: "#f25f5c" },
  scene: "facilitychainofcommand",
  layout: "facility",
  stations: [
    {
      id: "page",
      label: "The Page",
      topic: "The SOC tier structure · who holds which authority · closing a false positive yourself",
      tagline: "Whose desk does this land on?",
      building: "control",
      taskIds: ["esc-read-1", "esc-q1"],
    },
    {
      id: "call",
      label: "The Call",
      topic: "When to escalate · when not to · what a good escalation says · escalation bridges",
      tagline: "Wake them or wait?",
      building: "office",
      taskIds: ["esc-read-2", "esc-q2"],
    },
    {
      id: "handover",
      label: "The Handover",
      topic: "External parties · 24/7 contacts and runbooks · after you escalate · reading an escalation record",
      tagline: "The page is sent. Now what?",
      building: "archive",
      taskIds: ["esc-read-3", "esc-q3", "esc-log-1"],
    },
    {
      id: "verdict",
      label: "Night Verdict",
      topic: "Weighing what has stopped against what hasn't",
      tagline: "One analyst. One decision.",
      building: "ticket",
      taskIds: ["esc-ac1"],
      boss: true,
    },
  ],
  personas: {
    "esc-q1": { name: "Renata Volkova", role: "SOC Shift Lead", line: "One small alert on your screen. What happens to it?" },
    "esc-q2": { name: "Renata Volkova", role: "SOC Shift Lead", line: "Several teams, one incident. What gets set up?" },
    "esc-q3": { name: "Renata Volkova", role: "SOC Shift Lead", line: "It's gone up to Tier 2. What does your next hour look like?" },
    "esc-log-1": { name: "Renata Volkova", role: "SOC Shift Lead", line: "Read the whole record, times included." },
    "esc-ac1": { name: "Renata Volkova", role: "SOC Shift Lead", line: "Your shift, your decision. What's the verdict?" },
  },
  briefings: {
    // ── Reading 1: the tiers and what Tier 1 finishes alone ──
    "esc-read-1": [
      {
        kind: "anatomy",
        title: "Read the On-Call Card",
        prompt: "22:00, your first night alone on the desk. Before going home, Renata hands you the on-call card and says everything else tonight follows from it. Scan every line: each desk has its own work and its own limits.",
        source: "Ashdown SOC · on-call card · night shift",
        fields: [
          { key: "why_tiers", value: "match the work to the skill", label: "Why there are tiers", note: "Like a hospital: a triage nurse first, general doctors for most patients, specialists for the rare cases. If every alert went straight to the most experienced people, they'd spend their days closing false alarms." },
          { key: "tier1.work", value: "the SIEM alert queue", label: "Your desk", note: "Watch the queue, review each alert, and label it true positive, false positive or benign. Look up IOCs (indicators of compromise, such as a hash or an address) in threat intelligence, check whether the system is sensitive, and open a ticket for anything confirmed or suspected." },
          { key: "tier1.limits", value: "playbooks, no high-impact actions", label: "What your desk can't do", note: "A playbook is a step-by-step guide for one type of alert. Tier 1 follows them and closes clear false positives with notes, but doesn't take high-impact actions or call law enforcement." },
          { key: "tier2.work", value: "deep investigation", label: "The next desk up", note: "In-depth forensics on compromised systems, static and dynamic malware analysis, tying activity together across systems to find the scope, talking to system owners and IT, and writing containment and remediation plans." },
          { key: "tier2.authority", value: "approves host isolation", label: "Authority held by Tier 2", note: "Who can cut an endpoint off the network." },
          { key: "tier3.work", value: "threat hunting and forensics", label: "The specialists", note: "Lead major incidents, reverse engineer advanced malware, hunt for threats no alert raised, research attribution (which actor is this?) and build new detections." },
          { key: "tier3.outside", value: "external parties, executives", label: "Who talks outside", note: "Law enforcement, regulators, outside incident response firms and the executive team during a major incident." },
          { key: "on_call.tonight", value: "Renata Volkova, Tier 2 lead", label: "Who you can wake", note: "One analyst on the desk from 22:00 to 06:00, one person on the pager." },
        ],
        summary: "Three desks, each matched to a level of skill and authority. Your job isn't to solve everything: it's to finish what's yours and hand up what isn't, quickly and cleanly.",
      },
      {
        kind: "sort",
        title: "Which Desk Does It Land On?",
        prompt: "Renata tests the card before leaving. Put each job on the desk that does it. Nearby jobs are easy to mix up, so read what each one really asks for.",
        buckets: [
          { id: "t1", label: "Tier 1: triage" },
          { id: "t2", label: "Tier 2: deep investigation" },
          { id: "t3", label: "Tier 3: specialists" },
        ],
        items: [
          { id: "a", text: "Check a file hash in threat intelligence and see whether the host is sensitive", bucket: "t1", why: "A lookup and a context check are the first steps of triage." },
          { id: "b", text: "Sort tonight's SIEM alerts into true positive, false positive or benign", bucket: "t1", why: "Watching the queue and labelling alerts is what the first desk is for." },
          { id: "c", text: "Open a ticket for activity that looks malicious", bucket: "t1", why: "Tier 1 opens the ticket for confirmed or suspected activity, so the case exists before it moves up." },
          { id: "d", text: "Run a sample in a sandbox to see what it does", bucket: "t2", why: "Static and dynamic malware analysis sits with Tier 2. Tier 3 is for advanced reverse engineering." },
          { id: "e", text: "Tie one account's activity together across three terminals' servers", bucket: "t2", why: "Correlating across systems to find the scope is Tier 2's work." },
          { id: "f", text: "Agree a containment plan with the system's owner", bucket: "t2", why: "Tier 2 talks to system owners and writes the containment and remediation plans." },
          { id: "g", text: "Take apart a custom loader nobody has seen before", bucket: "t3", why: "Advanced reverse engineering is specialist work. A sandbox run is the desk below." },
          { id: "h", text: "Hunt for intruders no alert has raised", bucket: "t3", why: "Tier 3 hunts proactively. No alert means nothing arrived in the queue." },
          { id: "i", text: "Work out which threat actor runs a campaign", bucket: "t3", why: "Attribution research belongs to the specialists." },
          { id: "j", text: "Brief the executive team during a major incident", bucket: "t3", why: "Tier 3 leads major incidents and handles executive communication." },
        ],
      },
      {
        kind: "sequence",
        title: "Finish a Case at Your Own Desk",
        prompt: "22:06. A burst of device re-authentications from the wagon telematics gateways lands in your queue, right at crew change. It looks loud. Put the steps in the order that finishes this at your own desk.",
        primer: {
          title: "Finishing a case at your own desk",
          points: [
            "A **false positive** is an alert that fired on harmless activity. Most of a night's queue is benign or false.",
            "Playbooks list **known patterns**: this rule, this source, this time window, with the reason it happens.",
            "If every condition of the pattern holds, the case is yours to finish. If one doesn't, it isn't the known pattern.",
            "The note is part of the work. The next person must be able to see why it was closed.",
          ],
          example: {
            label: "A warehouse firm's backup alert",
            lines: [
              "Rule: large outbound copy from BK-01 at 01:00.",
              "Playbook entry BK-3: source BK-01, destination the off-site vault, between 01:00 and 02:00.",
              "All three hold, so the analyst notes `Matched BK-3: source, destination, window` and closes it.",
              "Next week the same rule shows an unknown destination. One condition fails, so it stays open.",
            ],
          },
        },
        items: [
          { id: "note", text: "Write in the ticket which entry matched and what you checked" },
          { id: "read", text: "Read the alert: which rule, which source, what time" },
          { id: "close", text: "Close it, with that reason on the record" },
          { id: "entry", text: "Open the playbook entry for this rule" },
          { id: "check", text: "Check each condition of the pattern against this alert: gateways only, crew-change window, rail network range" },
        ],
        order: ["read", "entry", "check", "note", "close"],
        doneNote: "Four minutes, and nobody lost any sleep. The alert was loud, but the playbook explained it and every condition held, so it never needed to leave your desk.",
      },
    ],
    // ── Reading 2: when to escalate, the night queue and the call ──
    "esc-read-2": [
      {
        kind: "tune",
        title: "Set the Night Pager",
        prompt: "The old pager rule woke Renata for nearly everything, and pages started getting read slowly. Here are last quarter's twelve worst nights. Set the two dials so the pager goes off for the six that needed someone awake, and stays quiet on the rest. Any one dial tripping fires the pager. The results call those six attacks and any other page a false alarm.",
        primer: {
          title: "What justifies an escalation",
          points: [
            "**Triggers:** confirmed malicious activity (clear evidence, not a hunch), more than one system involved, a step beyond your authority, skills or tools you don't have.",
            "**More triggers:** likely legal or regulatory trouble (personal data, extortion, an insider), and **sensitive systems**: domain controllers, which answer logons for the whole domain, plus finance systems and executives' devices.",
            "**Time limit:** a playbook gives you a fixed time, usually 30 to 60 minutes. Past it with no conclusion, you escalate anyway.",
            "**Not triggers:** a false positive you can prove, activity with a known harmless explanation, a case your playbook covers, or doubt before you've done the playbook's steps.",
            "**Both errors cost.** Under-escalation leaves an incident without the people it needs. Over-escalation floods Tier 2 and teaches them to read your pages slowly.",
          ],
          example: {
            label: "Counting triggers at a warehouse firm",
            lines: [
              "A stolen login reaches a stock server, then a second one, and blocking it needs the network team.",
              "Confirmed: yes. Two systems: yes. Beyond your authority: yes. That's 3.",
              "A stock-count script trips a rule, and a change record explains it. That's 0: note it and close.",
            ],
          },
        },
        eventColumn: "Night case",
        mode: "any",
        dials: [
          { id: "triggers", label: "Escalation triggers the case meets, at least", short: "Triggers", min: 1, max: 5, step: 1, start: 1 },
          { id: "stuck", label: "Minutes worked with no conclusion, at least", short: "Stuck", unit: "min", min: 15, max: 90, step: 5, start: 30 },
        ],
        events: [
          { id: "b1", label: "A depot account reaches a second server and a block is needed", bad: true, values: { triggers: 3, stuck: 20 } },
          { id: "b2", label: "A credential tool confirmed on a directory server", bad: true, values: { triggers: 3, stuck: 15 } },
          { id: "b3", label: "A customer list copied to an outside share", bad: true, values: { triggers: 4, stuck: 25 } },
          { id: "b4", label: "A finance mailbox rule forwarding invoices outside", bad: true, values: { triggers: 3, stuck: 30 } },
          { id: "b5", label: "A laptop calling an unknown host, every check inconclusive", bad: true, values: { triggers: 1, stuck: 55 } },
          { id: "b6", label: "A service nobody can explain on the rostering server", bad: true, values: { triggers: 1, stuck: 50 } },
          { id: "g1", label: "A patch job restarts 60 servers under a change ticket", bad: false, values: { triggers: 0, stuck: 10 } },
          { id: "g2", label: "The vulnerability scanner sweeps every subnet in its window", bad: false, values: { triggers: 0, stuck: 5 } },
          { id: "g3", label: "Adware on a yard kiosk, and the playbook removes it", bad: false, values: { triggers: 1, stuck: 12 } },
          { id: "g4", label: "A new admin script, explained by its change ticket at minute 40", bad: false, values: { triggers: 1, stuck: 40 } },
          { id: "g5", label: "Malware quarantined on a sales laptop before it ran", bad: false, values: { triggers: 2, stuck: 18 } },
          { id: "g6", label: "A lure reported by 30 staff, every copy purged, no clicks", bad: false, values: { triggers: 2, stuck: 22 } },
        ],
        goal: { catch: 6, maxFalse: 0 },
        lesson: "How loud an alert is, or how many machines a ticketed job touches, tells you little: the patch job touched 60 servers and needed nobody. Count the triggers that are really met, and keep a time limit for the cases that won't resolve. The limit needs care too: too short wakes someone for a case you'd have solved, too long leaves a real one sitting.",
      },
      {
        kind: "queue",
        title: "Wake Them or Wait?",
        prompt: "Tonight, 23:00 to 03:00. Six alerts, one pager. Every page you send spends Renata's sleep and the weight of the next page. Every page you hold gives an intruder hours nobody is watching. Severity is only the rule's opinion, so read the fields, then choose what happens to each alert.",
        console: "SOAR · Night queue · Ashdown SOC",
        primer: {
          title: "Four ways out of an alert",
          points: [
            "**Close with a note:** you can show it's harmless.",
            "**Keep working:** steps are left on the playbook, so the case isn't ready to judge. Being unsure doesn't change that.",
            "**Day Tier 2 queue:** it needs Tier 2, but nothing gets worse by morning. Escalating doesn't always mean waking someone.",
            "**Wake the on-call:** triggers are met and the next step can't wait for the day shift.",
            "Ashdown's playbook time limit is 45 minutes. `on_call.pages_tonight` and `day_shift_in` are what each choice costs.",
          ],
          example: {
            label: "Three alerts from a bus company's night",
            lines: [
              "Timetable export, change ticket on file, source and window match: close with a note.",
              "Odd logon, step 1 of 6 done, 5 minutes in: keep working.",
              "Stolen token used on the payroll server, and revoking it needs Tier 2: wake the on-call.",
            ],
          },
        },
        actions: [
          { id: "close", label: "Close with a note", tone: "close" },
          { id: "work", label: "Keep working the playbook", tone: "contain" },
          { id: "day", label: "Send to the day Tier 2 queue", tone: "contain" },
          { id: "wake", label: "Wake the on-call", tone: "escalate" },
        ],
        alerts: [
          {
            id: "archive",
            time: "23:12",
            severity: "Critical",
            rule: "Mass file rename on a server",
            entity: "ASH-ARCH-01",
            fields: [
              { k: "account", v: "svc_archive" },
              { k: "files_touched", v: "48,210" },
              { k: "change_ticket", v: "CHG-20418, 23:00 to 23:45" },
              { k: "playbook.entry", v: "KP-07 nightly archive: host, account, window" },
              { k: "on_call.pages_tonight", v: "0" },
              { k: "day_shift_in", v: "6 h 48 min" },
            ],
            context: "Rated Critical, and a mass rename is how some very bad nights begin.",
            answer: "close",
            why: "Host, account, window and change ticket all match the playbook entry. A page here would spend Renata's sleep on a ticketed job, and Critical was only the rule's opinion. Close it and write down what matched.",
          },
          {
            id: "roster",
            time: "00:35",
            severity: "High",
            rule: "Repeating outbound connections",
            entity: "ASH-ROSTER-01",
            fields: [
              { k: "asset", v: "Crew rostering server, staff personal data" },
              { k: "destination", v: "198.51.100.40:8443, every 300 s since 23:38" },
              { k: "playbook.steps_done", v: "6 of 6" },
              { k: "minutes_on_case", v: "55" },
              { k: "conclusion", v: "None. Signed process, purpose unknown" },
              { k: "on_call.pages_tonight", v: "0" },
              { k: "day_shift_in", v: "5 h 25 min" },
            ],
            context: "You've done every step and still can't say what it is. It hasn't got worse, and it would be easy to keep looking.",
            answer: "wake",
            why: "Past the time limit with no conclusion, on a system holding personal data. Renata traced it in twelve minutes to a vendor's new licence check and went back to bed. It was still the right page, because you're judged on what you knew at 00:35, and five hours of an unexplained connection is the cost of not asking.",
          },
          {
            id: "encoded",
            time: "01:21",
            severity: "Medium",
            rule: "Encoded PowerShell command",
            entity: "KY-OFFICE-07",
            fields: [
              { k: "asset", v: "Yard office PC, Kestrel Yard" },
              { k: "command", v: "powershell.exe -enc (212 characters)" },
              { k: "playbook.steps_done", v: "1 of 5" },
              { k: "minutes_on_case", v: "6" },
              { k: "next_step", v: "Decode the command" },
              { k: "on_call.pages_tonight", v: "1" },
              { k: "day_shift_in", v: "4 h 39 min" },
            ],
            context: "Something about it feels wrong. Renata has only just got back to sleep, but asking would be quicker than decoding it.",
            answer: "work",
            why: "You're 6 minutes in with 4 steps to go. Tier 2 would ask what the command decodes to, and you can find that out yourself. It decoded to the yard's printer-mapping script. A page now would have cost Renata a second wake-up for a question you hadn't asked yet.",
          },
          {
            id: "macro",
            time: "01:48",
            severity: "Medium",
            rule: "Macro document quarantined",
            entity: "SALES-LT-31",
            fields: [
              { k: "file", v: "Tariff_Q4.xlsm" },
              { k: "verdict", v: "Malicious" },
              { k: "macro_ran", v: "false" },
              { k: "other_hosts_with_file", v: "0" },
              { k: "playbook.steps_done", v: "5 of 5" },
              { k: "sandbox.access", v: "Tier 2 only" },
              { k: "on_call.pages_tonight", v: "1" },
              { k: "day_shift_in", v: "4 h 12 min" },
            ],
            context: "Confirmed bad, and you can't finish it yourself. But it never ran, and it's sitting in quarantine.",
            answer: "day",
            why: "You need Tier 2's sandbox, so it does go up. But nothing ran, one laptop, and nothing gets worse by 06:00. Hand it to the day queue with your notes. Waking Renata would have bought nothing the morning doesn't.",
          },
          {
            id: "signin",
            time: "02:20",
            severity: "Low",
            rule: "Contractor sign-in outside rota",
            entity: "d.halloran",
            fields: [
              { k: "gateway", v: "RA-GW-01" },
              { k: "source_ip", v: "203.0.113.77" },
              { k: "rota.status", v: "Not on shift tonight" },
              { k: "playbook.steps_done", v: "0 of 4" },
              { k: "minutes_on_case", v: "3" },
              { k: "on_call.pages_tonight", v: "1" },
              { k: "day_shift_in", v: "3 h 40 min" },
            ],
            context: "One sign-in, rated Low. It could be a contractor working late. You don't know yet.",
            answer: "work",
            why: "Three minutes in with no steps done. The Low doesn't let you close it, and nothing yet justifies a page. What did the session touch? That's the playbook's next question, so go and answer it.",
          },
          {
            id: "lsass",
            time: "02:52",
            severity: "Medium",
            rule: "Suspicious access to LSASS memory",
            entity: "ASH-PLAN-02",
            fields: [
              { k: "account", v: "d.halloran" },
              { k: "command", v: "rundll32.exe comsvcs.dll, MiniDump 712 C:\\Windows\\Temp\\d.dmp full" },
              { k: "asset", v: "Train-planning server, builds the 04:40 departures" },
              { k: "logged_on", v: "p.marek (planning admin)" },
              { k: "isolation", v: "Needs Tier 2 approval" },
              { k: "on_call.pages_tonight", v: "1" },
              { k: "day_shift_in", v: "3 h 08 min" },
            ],
            context: "Rated Medium. You've already woken Renata once tonight, for a licence check. The day shift is only three hours away.",
            answer: "wake",
            why: "LSASS is the Windows process holding the credentials of logged-on users, and that command writes its memory to a file. Confirmed malicious, a sensitive system, and a next step you can't approve. Your earlier page isn't a debt you repay by waiting, and each hour held here is an hour with an admin's credentials loose and nobody able to act.",
          },
        ],
      },
      {
        kind: "chat",
        title: "Wake Renata With a Usable Message",
        prompt: "03:00. The alert from 02:52 is real, and only Tier 2 can approve what comes next. Renata picks up on the second ring, half asleep. Type your own messages, or tap one to see how it lands. Your notes are in each goal.",
        primer: {
          title: "A page someone can act on half asleep",
          points: [
            "Five parts: **what** happened, **who** or which system, the **impact**, what you've **done**, and what you **need**.",
            "The ticket carries the rest: incident ID and title, timeline, IOCs, and your recommended next steps.",
            "Say what's confirmed. A guess at 03:00 gets repeated as fact at 04:00.",
            "End with one clear ask, and one thing the person can say yes or no to.",
          ],
          example: {
            label: "A page from a grain co-op's SOC",
            lines: [
              "**What:** INC-2210, a forged supplier-payment rule confirmed in a mailbox.",
              "**Who:** j.kerr, accounts payable.",
              "**Impact:** Friday's payment run pays out at 09:00.",
              "**Done:** rule saved to the ticket, sessions revoked at 01:40.",
              "**Need:** your approval to hold the payment run.",
            ],
          },
        },
        bot: "Renata Volkova",
        botRole: "SOC Shift Lead, on call",
        memory: true,
        greeting: "Volkova. That's twice tonight, and it's three in the morning. What have you got?",
        fallback: "You're breaking up, or I'm still asleep. What's happened, and what do you need from me?",
        rules: [
          { match: said(CULPRIT), reply: "Who did it is a guess, and a guess at this hour gets repeated as fact. Give me what EDR actually showed." },
          { match: said(SELF_ISOLATE), reply: "You did what? That call isn't Tier 1's. Either that's not what happened, or we have a second problem. Tell me what you actually did." },
          { match: said(OVERCLAIM), reply: "Is that confirmed? You have evidence of one server and one account. Say that, and let's not stop a railway on a feeling." },
          { match: said(COMFORT), reply: "If it's handled, why am I awake? Tell me what's still open." },
          { match: said(DOWNPLAY, COSTING), reply: "Then why did you wake me? If it can wait, it belongs in the day queue. If it can't, tell me why." },

          { match: has(ALL_WHAT, WHERE), goal: "what", wins: true, reply: "All right, I'm awake. So why can't this wait for the day shift at 06:00?" },
          { match: HEDGE, goal: "what", reply: "Is that confirmed? If it is, say so. If it isn't, work it before you wake me." },
          { match: ALL_WHAT, goal: "what", reply: "Bad, yes. On which machine, and whose account?" },
          { match: WHERE, goal: "what", reply: "What about it? What actually happened there?" },
          { match: ".", goal: "what", reply: "That's a feeling, and I can't act on a feeling. What happened, and where? Read it to me off the alert." },

          { match: has(ALL_IMPACT, said(REACH)), goal: "impact", wins: true, reply: "That's why I'm up, then. What have you done so far, and what do you want from me?" },
          { match: `(?:${TRAINS})\\b${TRAINS_FINE}`, goal: "impact", reply: "For now, yes. What happens to them if this goes on? And what's in that dump?" },
          { match: ALL_IMPACT, goal: "impact", reply: "The trains, fine. What about the dump itself? Who was logged on to that server?" },
          { match: said(REACH), goal: "impact", reply: "Understood. And what does that server do for Ashdown tonight? What's the business about to feel?" },
          { match: ".", goal: "impact", reply: "Everyone's alert is urgent at 03:00. Tell me what gets hurt, and when." },

          { match: has(ALL_DONE, ALL_NEED), goal: "ask", wins: true, reply: "Good. Clear enough to say yes to. You'll have an answer in five minutes." },
          { match: said(STOPPED), goal: "ask", reply: "Good, that's stopped one door. Now what do you need from me? Name the action." },
          { match: ALL_NEED, goal: "ask", reply: "I can do that. First, what's already been done, so I don't repeat it? What have you shut off?" },
          { match: TICKET, goal: "ask", reply: "A ticket stops nothing. What have you actually shut off, and what do you need from me?" },
          { match: ".", goal: "ask", reply: "I can't say yes to that. What have you done, and what's the one decision you want from me?" },

          { match: has(ALL_WHAT, WHERE, ALL_IMPACT, ALL_DONE, ALL_NEED), goal: "whole", wins: true, reply: "That'll do. Ines can act on that half asleep. Send it. I'm opening an escalation bridge now, because this decision is split between several people and they need to hear each other." },
          { match: lacks(ALL_IMPACT, ALL_WHAT, WHERE, ALL_DONE, ALL_NEED), goal: "whole", reply: "Nearly. Ines runs trains, so what does this do to the 04:40?" },
          { match: lacks(ALL_DONE, ALL_WHAT, WHERE, ALL_IMPACT, ALL_NEED), goal: "whole", reply: "Nearly. What has already been shut off? Ines will ask." },
          { match: lacks(ALL_NEED, ALL_WHAT, WHERE, ALL_IMPACT, ALL_DONE), goal: "whole", reply: "Nearly. So what's the ask? Say what you need decided." },
          { match: lacks(ALL_WHAT, WHERE, ALL_IMPACT, ALL_DONE, ALL_NEED), goal: "whole", reply: "Nearly. What actually happened on that server? Ines has no alert to look at." },
          { match: ALL_NEED, goal: "whole", reply: "Good ask, but Ines has only just woken up. Start from what happened, and where." },
          { match: said(STOPPED), goal: "whole", reply: "Good. Now the ask: what do you need decided?" },
          { match: ALL_IMPACT, goal: "whole", reply: "That's what Ines cares about. Now, what has already been done about it?" },
          { match: has(ALL_WHAT, WHERE), goal: "whole", reply: "Clear. Now the impact: what does it do to the 04:40?" },
          { match: WHERE, goal: "whole", reply: "And what happened there?" },
          { match: ALL_WHAT, goal: "whole", reply: "On which machine, and whose account?" },
          { match: ".", goal: "whole", reply: "Ines wakes up to that on a pager with no context. What happened, where, what it does to the 04:40, what's been done, and what you need. Go." },
          { match: has(RENATA_DECIDES, INES_DECIDES, OWNER_DECIDES), goal: "bridge", wins: true, reply: "That's the call. Three people, three decisions, nobody talking over anybody. And you stay on it: you saw this first." },
          { match: lacks(OWNER_DECIDES, RENATA_DECIDES, INES_DECIDES), goal: "bridge", reply: "Right so far. And the planning system's owner? What do we need from them?" },
          { match: lacks(RENATA_DECIDES, INES_DECIDES, OWNER_DECIDES), goal: "bridge", reply: "Right so far. And what's on me?" },
          { match: lacks(INES_DECIDES, RENATA_DECIDES, OWNER_DECIDES), goal: "bridge", reply: "Right so far. And what does Ines decide?" },
          { match: INES_DECIDES, goal: "bridge", reply: "Yes, that one's Ines's. And the planning system's owner?" },
          { match: OWNER_DECIDES, goal: "bridge", reply: "Yes, the owner can tell us that. And what's on me?" },
          { match: RENATA_DECIDES, goal: "bridge", reply: "That one's mine. And Ines?" },
          { match: has(INES, OWNER), goal: "bridge", reply: "Right people. Now, what does each one decide?" },
          { match: "\\beveryone\\b|\\beverybody\\b|\\ball of\\b|\\bwhole\\b|\\bboard\\b|\\blegal\\b", goal: "bridge", reply: "A call with twenty people decides nothing. Who holds a piece of this decision, and what is it?" },
          { match: ".", goal: "bridge", reply: "The bridge is open. Who has to be on it, and what does each one decide?" },
        ],
        goals: [
          { id: "what", task: "Say what happened and where. Your notes: INC-5127, the contractor account d.halloran dumped LSASS memory on ASH-PLAN-02, confirmed by EDR at 02:52.", tries: ["Hey, sorry, I've got a weird alert. Can you take a look?", "I think it's a nation-state crew going after the railway.", "INC-5127: the contractor account d.halloran dumped LSASS memory on ASH-PLAN-02, confirmed by EDR at 02:52."], why: "An incident number, what happened, where and whose account. Renata can find it and picture it before sitting up." },
          { id: "impact", task: "Renata asks why it can't wait. Say what's at risk. Your notes: planning admin p.marek was logged on, so those credentials may be in the dump. The 04:40 departures are built on that server.", tries: ["It's a bad one, trust me.", "Honestly, it can probably wait until the day shift.", "A planning admin was logged on, so those credentials may be in the dump, and the 04:40 departures are built on that server."], why: "Impact is what gets hurt and when. An alert title can't tell Renata that, and it's what turns a technical finding into a reason to be awake." },
          { id: "ask", task: "Say what you've done and exactly what you need. Your notes: ticket open, d.halloran disabled at 02:55, the server is still on the network, and only Tier 2 can approve cutting it off.", tries: ["What do you want me to do?", "I've isolated the server already, so we're fine.", "Ticket's open and d.halloran was disabled at 02:55. The server is still on the network, and I need your approval to isolate it."], why: "What's done stops Renata repeating it. One named ask gives Renata something to say yes or no to, and a request is yours to make even when the decision isn't." },
          { id: "whole", task: "Renata says Ines Carvalho, the Duty Controller, needs paging too, and that pager takes one message. Type the whole escalation for Renata to check: what, who, impact, done, needed. The two below show what not to send, so write this one yourself.", tries: ["Security issue on a planning server, please call the SOC.", "URGENT!!! We've been hacked, the whole network is compromised, stop all trains!"], why: "Five parts, one message, nothing guessed. It works at any hour for anyone, including someone who runs trains and has never heard of LSASS." },
          { id: "bridge", task: "The bridge is open. Cutting off ASH-PLAN-02 stops the 04:40 plan, and the decision is due by 04:00. Say who must be on it and what each one decides. Your notes: Renata decides on isolation, Ines decides what happens to the 04:40, and the planning system's owner says whether the plan can be copied off first.", tries: ["Everyone in IT, to be safe.", "Just you and me. We can tell the others afterwards.", "You decide on isolating, Ines decides on the 04:40, and the owner says whether the plan can be copied off first."], why: "A bridge works when each person on it knows which decision is theirs. Too few and a decision has no owner. Too many and nobody makes it." },
        ],
        doneNote: "What, who, impact, done, needed. That's a page Renata could act on half asleep, and it cost one wake-up, spent well. A vague page would have cost the same sleep and a second call. Held until 06:00, it would have cost three hours.",
      },
    ],
    // ── Reading 3: who else gets called, and staying on the case ──
    "esc-read-3": [
      {
        kind: "duel",
        title: "Who Gets Called Next?",
        prompt: "Wednesday, 09:10. The review shows the intruder copied the consignee list off ASH-PLAN-02 before it was cut off, and it reaches the German subsidiary. You won't make these calls yourself, but Renata expects you to recognise them so you can flag them. For each problem, play the party it needs.",
        attacker: "The morning after",
        primer: {
          title: "Who sits outside the company",
          points: [
            "Tier 1 doesn't make these calls. You tell your manager one may be needed, so you need to recognise each one.",
            "**CISA** (Cybersecurity and Infrastructure Security Agency): the US national cyber agency. Critical infrastructure sectors, such as energy, healthcare and transportation, are expected to report significant incidents.",
            "**FBI and law enforcement:** for crime, such as extortion or fraud. **National CERT** (Computer Emergency Response Team): each country has one, useful for attribution, blocking and legal steps across borders.",
            "**Regulators** have deadlines: GDPR's is 72 hours, and each one differs.",
            "**Cyber insurer:** must hear promptly, or a claim can fail, and may send its own firm. **External IR firm:** specialists for when the forensic work outgrows the team.",
          ],
          example: {
            label: "A dental chain's bad week",
            lines: [
              "Patient records in Spain copied: a regulator, with a deadline.",
              "A forged payment order for a real invoice: law enforcement, because it's fraud.",
              "Both are the same incident. Each problem has its own party.",
            ],
          },
        },
        moves: [
          { id: "m1", move: "An email: pay by Friday or the consignee list gets published", detail: "A demand, a deadline and stolen data. Someone is committing a crime against Ashdown.", counter: "police", hint: "What is extortion, before it's anything else?", why: "Extortion is a crime, so law enforcement comes in, and from then on evidence has to be handled so it can stand up later." },
          { id: "m2", move: "The stolen list includes EU customers of the German subsidiary", detail: "Personal data of people in the EU, and the hours are already counting.", counter: "reg", hint: "Which law gives you 72 hours?", why: "GDPR gives 72 hours to notify the supervisory authority. Regulators each set their own timeline, so Legal needs to know now, not on Friday." },
          { id: "m3", move: "Rail freight is transportation, and this is a significant incident", detail: "A federal agency expects to hear from operators in critical infrastructure sectors.", counter: "cisa", hint: "Which agency do critical infrastructure operators report to?", why: "Transportation is a critical infrastructure sector, and CISA expects significant incidents reported. It can also offer technical help and threat intelligence." },
          { id: "m4", move: "The list was sent to a server in a third country", detail: "Nobody at Ashdown has standing there, and the host won't answer a stranger.", counter: "cert", hint: "Who has standing in another country's networks?", why: "A national CERT works across borders and can help with blocking and the legal process in another jurisdiction." },
          { id: "m5", move: "The policy says notify promptly", detail: "The clause is in the small print, and a 24/7 hotline is on the contact sheet.", counter: "ins", hint: "Who pays for all this, if they're told in time?", why: "Late notice can invalidate the claim, and many carriers send their own IR firm. Make that call early." },
          { id: "m6", move: "All three terminals need imaging, and the team is three people", detail: "The forensic work has outgrown the team, and the board wants answers this week.", counter: "ir", hint: "Who do you bring in when the job is bigger than the team?", why: "A retained external IR firm supplies forensic capacity for large investigations. The contract is there so nobody has to find one in a crisis." },
        ],
        cards: [
          { id: "reg", name: "Data protection regulator", effect: "Receives breach notifications, on a deadline." },
          { id: "day", name: "Day Tier 2 queue", effect: "For cases that can wait until morning." },
          { id: "police", name: "Law enforcement", effect: "Investigates crime. Changes how evidence is kept." },
          { id: "ins", name: "Cyber insurer", effect: "Covers the loss if told in time." },
          { id: "cisa", name: "CISA", effect: "US national cyber agency." },
          { id: "report", name: "Weekly report", effect: "For things nobody needs to hear today." },
          { id: "ir", name: "External IR firm", effect: "Forensic capacity on retainer." },
          { id: "cert", name: "National CERT", effect: "A country's response team, works across borders." },
        ],
        lesson: "One incident can need many outside parties, each for its own reason and on its own clock. You don't make these calls on a night shift, but noticing one is needed and telling your manager is part of the job.",
      },
      {
        kind: "hotspot",
        title: "What's Wrong With This Contact Sheet?",
        prompt: "Renata pulls up the 24/7 escalation contact sheet and asks one question: what if I hadn't picked up? Tap every line that would have let you down at 03:00. Lines that are fine will say so.",
        artifact: "Ashdown SOC · 24/7 escalation contacts · printed 16 September",
        finish: "A contact sheet is only as good as its last test, and every gap on it shows up at the worst possible hour. Test it every quarter, with backups for every role, and make sure a runbook sits with each scenario so a new analyst can follow it under pressure.",
        parts: [
          { id: "test", text: "Last full test of all numbers: 11 February", flag: true, note: "That's seven months ago. Contacts should be tested quarterly, because a number that died in April only shows up when nobody answers.", style: "subject" },
          { id: "t2", text: "Tier 2 on-call: weekly rota, pager 555-0142", flag: false, note: "Fine. A rota behind one pager number stays right when the name changes.", style: "body" },
          { id: "backup", text: "Tier 2 backup: none listed", flag: true, note: "If the on-call doesn't pick up, you have nobody. The rotation needs a backup contact.", style: "body" },
          { id: "mgr", text: "SOC Manager: desk line, 08:00 to 18:00", flag: true, note: "The SOC Manager must be reachable 24/7. A desk line in office hours is no use at night.", style: "body" },
          { id: "legal", text: "Legal counsel: Sable & Hart LLP, front desk, weekdays", flag: true, note: "Legal needs an after-hours emergency contact. Deadlines don't stop for the weekend.", style: "body" },
          { id: "ins", text: "Cyber insurer: incident hotline 555-0163, 24/7", flag: false, note: "Fine. A round-the-clock hotline, which is what a carrier should give you.", style: "body" },
          { id: "ir", text: "External IR firm: retainer AR-2291, duty desk 555-0187, 24/7", flag: false, note: "Fine. The retainer reference and a duty desk are what you'll need to hand over.", style: "body" },
          { id: "cust", text: "Key customer security contacts: shared list, reviewed 2 September", flag: false, note: "Fine. Reviewed this month.", style: "body" },
        ],
      },
      {
        kind: "match",
        title: "After the Page",
        prompt: "The case has gone up, but your part in it hasn't ended. Renata walks through what happened after 03:00. Match each moment to what you did, because you'd seen things no one else had.",
        primer: {
          title: "A case is handed up, not handed off",
          points: [
            "After you escalate, you still hold context nobody else has: what the alert looked like, what you checked, and what seemed odd.",
            "The next desk will come back to you.",
            "Watching how Tier 2 works a case is one of the best ways to learn the job.",
            "Hand over your notes. The incident belongs to the whole team until it's closed.",
          ],
        },
        pairs: [
          { id: "p1", left: "03:40: Renata asks why the contractor's sign-in caught your eye", right: "You answer from your notes within a minute", why: "You saw it first, and only you know what you looked at. A slow answer here slows the whole bridge." },
          { id: "p2", left: "04:15: a new alert names a second account from the same contractor firm", right: "You link it to INC-5127 and tell Renata straight away", why: "A related alert isn't a new case. You're the one who can recognise it as part of this one." },
          { id: "p3", left: "04:50: Renata finds a copy of the dump had been moved to a folder you hadn't checked", right: "You ask how it was found, and add that check to your own routine", why: "That's the learning a page buys. The case shows you what Tier 2 looks at that you didn't." },
          { id: "p4", left: "06:00: your shift ends with the case still open", right: "You leave your notes in the ticket and say how to reach you", why: "The notes pass to the day shift and the case stays with the team, so a question at 09:00 still finds you." },
        ],
      },
    ],
    // ── Log analysis: read an escalation back ──
    "esc-log-1": [
      {
        kind: "anatomy",
        title: "Read an Escalation Record Field by Field",
        prompt: "Renata opens your own escalation from last night in the SOAR platform. It's the record a reviewer reads, so learn how to read one. Scan every field: a record shows when it was sent as well as what it says.",
        source: "SOAR · escalation record · INC-5127",
        fields: [
          { key: "escalation.incident_id", value: "INC-5127", label: "Find it fast", note: "The first thing Tier 2 needs." },
          { key: "escalation.from_tier", value: "1", label: "Who sent it", note: "With escalation.to_tier: 2 and escalation.analyst, it shows the route it took." },
          { key: "escalation.severity", value: "P1", label: "How fast it must move", note: "The priority as judged at the time of escalation." },
          { key: "escalation.reason", value: "Confirmed LSASS dump on ASH-PLAN-02. Isolation needs Tier 2.", label: "Why it went up", note: "Exactly what requires Tier 2. A reason that names the missing authority tells the reader what to do first." },
          { key: "escalation.timestamp", value: "2026-09-16T03:00:00.000Z", label: "When it went up", note: "Hold this against every time in the actions list. A record's age isn't when it was written: it's the gap between the first moment a trigger was met and this stamp." },
          { key: "escalation.affected_hosts_count", value: "1", label: "Scope as known", note: "One number, and it should match the notes." },
          { key: "escalation.iocs", value: "comsvcs.dll MiniDump, 203.0.113.77", label: "What to search for", note: "The IOCs Tier 2 can pivot on straight away." },
          { key: "escalation.actions_taken_by_tier1", value: "02:52 evidence confirmed; 02:55 d.halloran disabled; 02:58 ticket opened; 03:00 on-call paged", label: "The real timeline", note: "Confirmed at 02:52, paged at 03:00: 8 minutes. Those are the minutes in which nobody with the authority to act knew about it." },
          { key: "escalation.analyst_notes", value: "ASH-GW-SIG: no activity seen", label: "What hasn't been touched", note: "The gateway links the planning network to the signalling network. A line like this tells Tier 2 what's next on the intruder's path, and how much time is left to get in the way." },
        ],
        summary: "Read a record twice: once for what it says, once for what its times say. A complete record sent late still cost the time it sat, and a note about what isn't hit yet tells the reader how long they have.",
      },
      {
        kind: "worksheet",
        title: "How Long Did Each Page Sit?",
        prompt: "Renata keeps a table of this quarter's escalations for the shift review. The team's target from confirmed to paged is 10 minutes. Work out what each delay cost.",
        caption: "Ashdown SOC · escalation review · this quarter",
        columns: ["Case", "Confirmed", "Paged", "Hosts when confirmed", "Hosts when paged"],
        rows: [
          ["INC-4871", "01:06", "01:14", "1", "1"],
          ["INC-4902", "23:48", "00:41", "1", "5"],
          ["INC-5015", "04:05", "04:12", "2", "2"],
          ["INC-5066", "02:10", "03:32", "2", "2"],
          ["INC-5127", "02:52", "03:00", "1", "1"],
        ],
        questions: [
          { id: "gap", q: "How many minutes passed between confirmed and paged on INC-4902?", hint: "It crosses midnight: 12 minutes to 00:00, then the rest.", answer: ["53", "53 minutes", "53 min"], why: "12 minutes to midnight and 41 after it. That page sat for 53 minutes after the evidence was in." },
          { id: "hosts", q: "How many more hosts did the intruder reach while INC-4902 sat?", hint: "Compare the two host columns on that row.", answer: ["4", "four"], why: "From 1 host to 5. That's the price of the gap: the analyst was writing a fuller summary while the intruder kept working." },
          { id: "missed", q: "How many of the five cases missed the 10-minute target?", hint: "Work out the gap on every row.", answer: ["2", "two"], why: "INC-4902 at 53 minutes and INC-5066 at 82. The other three took 8, 7 and 8. INC-5066 lost no hosts, but that was luck: the record shows nobody could have acted in those 82 minutes." },
        ],
      },
    ],
    // ── Boss warm-up: partly handled is not handled ──
    "esc-ac1": [
      {
        kind: "reactor",
        title: "Finished, or Only Half Done?",
        prompt: "Before the final case, Renata reads out how last quarter's automated responses left things. Automation is good at making a night look calmer than it is. Route each one before it reaches the end of the belt.",
        primer: {
          title: "An automatic action is a step, not an outcome",
          points: [
            "When a tool has acted, the question isn't what it did. It's what's left.",
            "Ask three things. Has everything affected been stopped? Has it stopped moving? Can you finish the rest with your own authority?",
            "All three yes: record it and carry on.",
            "Any no, with the next person who can act hours away: the rest needs someone awake, and your page says what is left to do.",
          ],
          example: {
            label: "A water company's night",
            lines: [
              "Auto-block stopped 1 of 2 remote sessions at 01:10.",
              "Everything stopped? No. Still moving? The second session is active. Can you finish? The block needs the network team.",
              "So the page goes out, and it says what is left to do: the second session.",
            ],
          },
        },
        reactors: [
          { id: "done", label: "Finished", sub: "Record it, nobody wakes" },
          { id: "open", label: "Half done", sub: "Someone has to act now" },
        ],
        items: [
          { id: "i1", text: "SOAR disabled 3 of 5 stolen depot accounts. The other 2 are on a protected list, and one signed in 4 minutes ago.", reactor: "open", why: "Three of five sounds like progress, but two accounts are live and one is in use, and protected accounts are beyond what your desk can touch." },
          { id: "i2", text: "The mail gateway purged all 62 copies of a lure. Message trace shows no clicks.", reactor: "done", why: "Every copy gone, nobody clicked, and the trace proves it. Nothing is left to do tonight." },
          { id: "i3", text: "Auto-block stopped the first source address. The same session came back from a new address 6 minutes later.", reactor: "open", why: "It's still moving: the block changed the address, not the intruder." },
          { id: "i4", text: "A forced reset ran on a stolen mailbox account. Its rule forwarding invoices outside is still switched on.", reactor: "open", why: "A password reset doesn't remove a mailbox rule. The account looks fixed while the mail keeps leaving." },
          { id: "i5", text: "EDR removed a coin miner from one kiosk. No other host has seen the hash, and the playbook is complete.", reactor: "done", why: "One host, confirmed clean, no spread, and the playbook covers it." },
          { id: "i6", text: "The firewall blocked a scanner, which turned out to be Ashdown's own vendor. The change ticket matches.", reactor: "done", why: "Harmless and explained. The block is the only thing to undo, and that can happen in the morning." },
          { id: "i7", text: "A remote session was cut, and the quiet since looks good. The dropped tool is still scheduled to start at 04:00.", reactor: "open", why: "Quiet isn't finished. The next step is already booked, and someone needs to remove it before 04:00." },
        ],
      },
    ],
  },
};
