# Room & quiz authoring spec

Written after a coverage audit of the platform. Every rule exists because the
audit found the opposite in shipped content.

## The gap this content closes

The platform has 66 rooms and 23 scenarios, and **42 of the 82 ATT&CK techniques
a student is asked to handle in the scenarios are never taught in any room**.
Students practise Kerberoasting, AS-REP roasting, Golden Ticket and DCSync with
no room that teaches Kerberos. That is the gap to close: teach what is practised.

Room categories with no quiz at all: Foundations, Endpoint Security, Identity,
Log Analysis, SIEM, Incident Response, Forensics, Data Security.

## Quiz contract

```ts
// src/lib/quizzes/data.ts
export interface QuizQuestion {
  id: string; question: string; options: string[];
  answer: number;        // 0-based index into options
  explanation: string; xp: number;
}
export interface Quiz {
  slug: string; title: string; description: string;
  difficulty: "Beginner" | "Intermediate" | "Advanced";
  category: string; icon: string;   // emoji
  estimatedMinutes: number; questions: QuizQuestion[];
}
```

Rules:
- **10–12 questions**, `xp` 10 (recall) / 15 (applied) / 20 (analysis).
- **All four options must be similar length.** An audit found correct answers
  running 2–3× longer than every distractor, which lets a student score without
  reading. Count your characters.
- Distractors must be **plausible and wrong for a stateable reason** — a real
  confusion a junior analyst has, not filler. "T1486 ransomware" dropped into an
  identity question is filler.
- The `explanation` must say **why each wrong option is wrong**, not restate the
  right one. This is the only teaching moment after the answer is revealed.
- No deprecated ATT&CK IDs anywhere, including distractors: T1076, T1086, T1064,
  T1035, T1117 are all retired.
- At least **3 questions per quiz must be applied** — give a log line, a command,
  a field value or a short situation and ask what it means or what to do next.
  Pure definition recall for 12 questions is a flashcard, not an assessment.
- Facts must be checkable: real Event IDs, real field names, real CVSS ranges,
  real port numbers, real ATT&CK IDs. If you are unsure, use fewer specifics.

## Room contract

```ts
// src/data/rooms.ts — RoomTask union
ReadingTask       { type:"reading", id, heading, content, codeExample?, diagram?, diagramCaption? }
QuestionTask      { type:"question", id, question, options[], answer, explanation, xp }
LogAnalysisTask   { type:"log_analysis", id, heading, context, event: TelemetryEvent, questions[] }
FlagTask          { type:"flag", id, prompt, answer, hint?, xp }
AnalystChoiceTask { type:"analyst_choice", id, heading, scenario, event, correct_verdict, explanation, fp_trap?, xp }
MatchingTask      { type:"matching", id, heading, instructions, pairs[{id,left,right}], explanation, xp }
OrderingTask      { type:"ordering", id, heading, instructions, items[{id,text}], correct_order[], explanation, xp }
QueryFillTask     { type:"query_fill", id, heading, language:"kql"|"spl", context, template, blanks[], explanation, xp }

Room { id, title, description, difficulty, category, estimatedMinutes, xp, icon, prerequisites[], tasks[] }
```

Rules:
- **10–16 tasks.** Open with `reading`, then alternate teaching and practice.
  Never more than two `reading` tasks in a row.
- Use **at least four different task types** per room. A room of reading +
  question only is a slideshow.
- `xp` on the Room must equal the EXACT sum of its task xp — no added base. The
  app awards xp per task (`TaskPlayer` grants `task.xp`) and there is no
  completion bonus, so the room card's number is only honest if it equals what
  a student can actually earn. (An earlier version of this spec said "+50 base"
  — that was wrong, sourced from a different subsystem, and produced rooms that
  overstated their own XP. Verify against `RoomClient.tsx` if in doubt, not this
  file's memory of it.)
- `prerequisites` must reference **real room ids** that exist. Check first.
- Every room must contain **at least one `log_analysis` or `analyst_choice`**
  task built on a realistic `TelemetryEvent`, because reading a log is the job.
- `content` uses `\n\n` between paragraphs. Define every acronym on first use.
- Use `diagram` (Mermaid source) for anything structural — a protocol exchange,
  a ticket flow, a trust relationship. Prose explains those badly.

### Log rules inside rooms — these are the ones that get violated

A `TelemetryEvent.raw` block is a claim that the named product emits those
fields. It must contain **observations, never conclusions**:
- No field that states the finding: `pass_the_hash: true`, `hash_mismatch: true`,
  `is_malicious: true`, `threat.category: "PossibleDNSTunnel"`.
- No `*.Description` sub-field on `winlog.event_data.*` — that key does not
  exist in the Windows schema, and every instance found was a hint in disguise.
- No derived analytics: `baseline.*`, `*_per_minute`, `time_since_*`,
  `ml.score`, `deviation_factor`. If the question asks the student to compute
  it, it must not already be in the log.
- Real field names for the named vendor. Windows → `winlog.event_data.*` +
  `event.code`; Sysmon → `winlog.provider_name: "Microsoft-Windows-Sysmon"`;
  MDE → `DeviceProcessEvents` columns; CrowdStrike → `crowdstrike.*`.
- Facts: RID 500 is the built-in Administrator. NTLM network logon is
  `LogonProcessName: "NtLmSsp"`. LogonType 2 = console, 3 = network, 5 =
  service, 10 = RDP. 4768 = TGT, 4769 = TGS, 4625 = failed logon, 1102 = log
  cleared. Kerberoasting is a **4769** for an SPN account with RC4 `0x17`
  (T1558.003); AS-REP roasting is pre-auth disabled, `PreAuthType: 0`
  (T1558.004). They are different attacks.
- A process cannot do what its integrity level forbids: opening `lsass.exe` with
  `PROCESS_ALL_ACCESS` needs SeDebugPrivilege, so `integrity: "medium"` cannot
  do it. Show the escalation or start elevated.

### Pedagogy

- The student should be able to **derive** the answer from what the task shows.
  Do not put the answer in the log and then ask for it.
- Include false positives. A room where every artefact is malicious teaches
  students to escalate everything, which is the failure mode real SOCs have.
  Use `analyst_choice` with `correct_verdict: "false_positive"` and an
  `fp_trap` explaining what makes it look bad.
- Tone is encouraging and concrete. Explain the *why*, not just the *what*.
