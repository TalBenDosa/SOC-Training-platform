# Log Realism Standard (one bar for every surface)

Owner decision (Tal, 2026-11-09): log realism must be UNIFORM across the whole platform, not only in
Team Training. Every log a learner can see, on any page, meets the same bar. The rules below were
first enforced for Team Training after the Sdema exercise (2026-11-08, branch fix/sdema-logs). They
now apply everywhere.

## Surfaces in scope

| Surface | Where the logs come from |
|---|---|
| Live Feed (Dashboard) | `src/app/(app)/dashboard/` attackStories, benignEvents, core-stories/*, ai-stories/*, liveEventEnrich, useLiveEvents; `src/lib/sim/companyProfiles*.ts`, `src/lib/sim/emitters/*`; rendered through `src/lib/logs/native/*` |
| Scenarios page | `src/lib/sim/scenarios.ts`, `src/lib/sim/scenario-packs/*`, `src/lib/sim/scenarioEvents.ts`, `src/lib/scenarios/*` |
| Team Training | `src/lib/team/*` (already done on fix/sdema-logs; keep green) |
| XDR console | `src/lib/sentinel/*` (tables, workspace, evidence, baseline, fallback) |
| EDR console | `src/lib/edr/*` (fromLiveStory, rtr, staticLab, iocIntel) |
| Forensic workbench | `src/lib/forensics/*` |
| Learning rooms and lessons | `src/data/rooms-batch-*.ts`, `src/lib/rooms/experience/*`, lesson files with log examples |

## The rules

Each rule has an ID. Gates and reports cite the ID.

### R1 Native fields only
Every field in a raw block exists in the named vendor's real schema, with the vendor's real value
format (enums, casing, time format, id shape). Checked by `npm run validate:logs` (field registry)
and `src/lib/logs/native/validate.ts` (native schemas). No invented fields such as
`maintenance.*`, `query_count_last_hour`, `s1.*` that the product does not emit.

Vendor enum strings are kept verbatim, even when MITRE ATT&CK renamed the tactic behind them. A
product field prints what the product prints: Defender `AlertInfo.Category` and Graph alert
`category` stay `DefenseEvasion` (the value in Microsoft's own Graph `alerts_v2` example), Sentinel
`SecurityAlert.Tactics` stays `DefenseEvasion`, and a GuardDuty finding type stays
`DefenseEvasion:IAMUser/AnomalousBehavior`. Our own tagging (the row's `mitre_tactic`, lesson text,
rubric answers) uses v19 names and IDs (R10). Explain the gap in teaching text; never rewrite the
vendor string.

### R2 Same shape for attack and benign
For one source and one event type, attack rows and benign or decoy rows carry the same set of
real fields. The field count may differ by at most 30%. A learner must never be able to tell
malicious from benign by how many fields a row has, by which fields are present, or by an
`event_type` used only for decoys.

### R3 One identity, one id
- One user has one UPN, one SAM name, one SID, one object id, everywhere they appear.
- User names follow the company's own convention (`u.petrov`, not `upetrov`, if the company uses
  `first-initial.last`).
- One host has one IP and one FQDN form across all rows of a story. A DC has one IP.
- Hosts and users come from the company's own asset pool. Nothing from one company appears in
  another (iron rule: no cross-environment mixing).
- Non-human principals (service accounts, anonymous chat users, `SYSTEM`, apps) are never
  re-homed into a named employee. One rule: `src/lib/sim/nonHuman.ts`.

### R4 Time is coherent
- Every timestamp inside a raw block agrees with the row's own time (same instant, the vendor's
  format and zone).
- A story is re-timed with one monotone map: order is kept, and gaps keep their proportion.
- A correlation alert, incident or ticket comes after the events it describes, never before.
- One record has one creation time (no ticket with three `opened_at`).
- Times written in text (descriptions, ticket notes) match the re-timed raw times.

### R5 Addresses
- Attacker infrastructure uses documentation ranges: 192.0.2.0/24, 198.51.100.0/24,
  203.0.113.0/24. Exception kept by owner decision: 185.220.101.45.
- Internal hosts use RFC 1918 ranges consistent with the company's subnets.
- A company's own public egress (office, VPN) uses a documentation range too, one per company.
- No real third-party public IPs unless they belong to a well-known service and are used for that
  service (for example a Microsoft or Google range on a sign-in row).
- NAT and published services are coherent: the firewall's `natdst` or equivalent matches the
  internal server that the story names.

### R6 Process truth
One process has one pid for its life. A child's parent pid and parent image match the parent's
own row. Command lines, hashes and image paths stay the same for one process on every row and
every console (Live Feed, EDR, XDR, forensic workbench).

### R7 A story can be proven from its evidence
- Every alert carries or links its evidence (the rows behind it, in the same tenant and window).
- A brute-force or spray has enough rows to prove it (for example 10 to 20 failures over 8 to 12
  accounts within 2 to 3 minutes for a spray), with full 4625 or sign-in fields and real
  status codes.
- A twist or follow-up happens only after the attacker reached what it needs.
- A benign look-alike carries the evidence that disproves it (device and MFA details on a travel
  sign-in, normal volume on a backup or upload).

### R8 Realistic volume and severity
- Ordinary noise is at least twice the attack rows in any feed a learner triages.
- Severity does not reveal the answer: high-severity benign alerts exist, and low-severity attack
  rows exist.
- Repeated benign rows are drawn fresh, not copied (no identical "Payroll Summary" mail three
  times).
- Tickets are a minority of the feed (about 8% or less).

### R9 No answer leaks
Raw fields never state the verdict (`is_malicious`, `attack_stage`, `expected_verdict`,
`maintenance_window: true` on the attacked host, labels such as "attacker" in a user name).
Existing check: `src/lib/logs/native/answerLeak.test.ts`.

### R10 Content rules
No em dashes in any visible text. MITRE ATT&CK v19 IDs and tactic names in our own tags and text
(a vendor's own enum value inside a raw field stays verbatim, see R1). Fictional people and
companies. The vendor named on a row is the vendor whose format the row uses.

## How it is enforced

- `src/lib/logs/realism/` holds one checker per rule and one collector per surface.
- `src/lib/logs/realism/realism.gate.test.ts` runs every checker over every surface and fails on
  any violation that is not in the reviewed baseline. The baseline may only shrink.
- `npm run validate:logs` keeps enforcing R1 at the field level.
- New content must pass the gate before merge.
