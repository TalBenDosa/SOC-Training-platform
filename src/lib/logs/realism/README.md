# Log realism gate

Enforces docs/LOG-REALISM-STANDARD.md (rules R1 to R9) the same way on every surface a learner sees.

```
npm run realism:gate       # fail on any violation not in realism-baseline.json
npm run realism:baseline   # rewrite the baseline from today's violations (shrink-only)
npm run realism:report     # write realism-report.md: per-surface x per-rule table + examples
```

`realism:baseline` refuses to add a key that is not already in the baseline. An owner-approved reset
is `node src/lib/logs/realism/cli.mjs baseline --grow`. The gate prints how many baselined
violations are fixed, so the baseline can be shrunk after a fix lands.

A baseline key is `surface|rule|rowId|detail`. Row ids are stable (event ids, story ids, scenario
slugs, room and task ids, fixed seeds); details carry no counts or times, so fixing one problem
removes one key and nothing else moves. XDR background rows have no id of their own and are keyed
per table.

## Files

| File | What |
|---|---|
| `types.ts` | `LogRow` (one rendered row), `Violation`, `Collected` |
| `collect.ts` | runs every collector once |
| `collectors/live.ts` | Live Feed for the 5 built-in companies |
| `collectors/scenarios.ts` | every built-in scenario (SCENARIOS, packs included) |
| `collectors/team.ts` | Team Training feed, XDR workspace, forensic workbench |
| `collectors/edr.ts` | EDR console cases from the Live Feed and the scenarios, RTR `ps`, Static Lab |
| `collectors/rooms.ts` | room task logs and room lab rows |
| `checkers/r1.ts` ... `r9.ts` | one checker per rule |
| `realism.gate.test.ts` | the gate (also the baseline / report writer, by `REALISM_MODE`) |
| `report.ts` | baseline file, table and report |
| `cli.mjs` | `realism:baseline` / `realism:report` |

## Collectors: what each surface really shows

All collectors are deterministic (seeded random, fixed shift start 2026-11-09T08:00Z).

- **live**: the noise pool as page.tsx builds it (company sources only, no real attack,
  normalizeHostIps, fitsStack, applyStack) and every story storiesForCompany deals the company
  (easy, medium, hard; solo), instantiated with a seeded random, kept when storyHonoursLocks.
  Each row is re-timed like useLiveEvents (phases of 2-3 rows 2-4 minutes apart, phaseTimes,
  withRebasedTime with the local story clock), enriched (enrichEvent), its SIEM mirror added
  (siemMirror) and rendered with nativeView under the company's own products. Rows with no native
  module are collected as the legacy raw block the feed then shows. One feed per story (noise ticks
  every 90 s, 1-2 rows) is recorded for R8. The company's own products only: chosen stacks are
  covered by src/lib/logs/native/stack.stories.test.ts.
- **scenario**: each SCENARIOS bundle with the page's withholding (conclusion raw keys dropped,
  incident ids), rendered with nativeStoryRenderer(bundle.events) as ScenarioClient does.
- **team**: buildTeamTimeline(company, "medium", `realism-<company>`) with a 5-seat roster, feed
  channel, each row re-timed to T0 + due offset (as the workbench and forensic review do) and
  rendered with nativeView. The bonus channel is not collected.
- **xdr**: buildWorkspace over the team events with the baseline on: every table row (event rows and
  background rows) plus every alert with the events behind it.
- **forensic**: buildEvidenceView (memory and triage) for every attacked endpoint host of each team
  session, captured one minute after the host's last row, no RTR kill, no isolation.
- **edr**: buildInvestigationFromStory over each live story's injected rows, and
  buildInvestigationsFromScenario over each scenario's client events: RTR `ps` (hostProcesses),
  process network connections, Static Lab strings / FLOSS / capa of each non-benign image.
- **room**: the `event` of every log_analysis, analyst_choice and flag task (the raw block the
  player prints), and the lab parts that show log rows (hunt tables, trace steps, queue alerts,
  worksheets, pcap packet lists, portal tables and log grids, terminal output) of rooms whose
  experience passes getRoomExperience.

## Checkers and their blind spots

**R1 Native fields only.** Calls the two existing R1 checks, nothing re-implemented:
validateNative on every rendered native record (live, scenario, team), and
scripts/validate-log-fields.mjs on authored raw blocks, run with its own baseline hidden so all
current violations count (its baseline still governs `npm run validate:logs`). Authored-block
violations are attributed by file: src/data -> room, scenario files -> scenario, the rest -> live.
Blind spots: lab rows (free-form tables), XDR rows (covered by src/lib/sentinel/workspace.test.ts
column checks), and raw blocks whose vendor the registry does not know (the script lists them).

**R2 Same shape.** Per (surface, source, event type) with at least 2 attack and 2 benign rows of
known truth: median field count differs by more than 30%, or a field is on 80% or more of one
side and on none of the other (3 or more rows on that other side). Legacy raw rows are grouped by
source, vendor and event code. Blind spots: rows with unknown truth (room log_analysis, lab rows,
EDR), an `event_type` used only by decoys (not mechanical: many benign-only types are legitimate),
and value tells (a field present on both sides whose value differs).

**R3 One identity.** Scope: one company (live, team, xdr), one scenario, one room, one EDR case.
Account <-> SID and UPN <-> object id are read as pairs inside one record object (XSid beside
XName, userId beside userPrincipalName, AccountObjectId beside AccountUpn, Okta id beside
alternateId); host <-> IP from a record's own host and own-address fields (ComputerName /
LocalAddressIP4, DeviceName / LocalIP, agentComputerName / agentIpV4, Computer / ComputerIP,
host.name / host.ip). Naming convention: a company address written two ways for one roster person
(`jchen` and `j.chen`, or `john.chen` beside `j.chen`). Iron rule: a row of one company naming
another company's domain, realm, host, roster person or office address (tokens owned by one
company only, 5+ characters, word-bounded). Blind spots: hosts and users outside the company
pools (stories bring their own servers by design), a company whose convention is not
initial.last, people not on the roster, tenant renames in Team (sessions are collected without a
tenant).

**R4 Time.** (a) a native record's own time equals the row time within 1 s; (b) for rows shown as a
raw block, the primary time field (Timestamp, TimeGenerated, @timestamp, UtcTime, CreationTime,
createdDateTime, eventTime ...) equals the row time within 2 s; XDR TimeGenerated lies between the
event time and one hour after; (c) no time in a record is more than 2 minutes after the row
(expiry, validity, schedule, due, SLA, end and similar fields excepted; a number is a time only
under a time-like key); (d) a story's rows authored in time order are shown in that order
(baseline rows skipped; team rows matched to their authored story event); (e) an XDR alert is not
before the last event behind it, a SIEM mirror not before its detection; (f) one ServiceNow number,
one opened_at. Blind spots: "gaps keep their proportion" (the Live Feed re-times per phase, so
proportions are not kept by design; not flagged), times written in prose (descriptions, ticket
notes), EDR and forensic HH:MM:SS columns, text-format records' secondary times.

**R5 Addresses.** Every public IPv4 shown (a whole-value address, an address in a URL, or in a
field whose name says address) must be a documentation address, 185.220.101.45, or inside a
well-known service range (Microsoft, Google, AWS, Cloudflare, Akamai, Zscaler, Fastly, Apple,
GitHub, public resolvers). One violation per address per scope. Each company's office egress
(COMPANY_ASSETS.office.ip) must be a documentation address. OIDs (2.5.x.x, 1.3.6.x) and version
fields are not addresses. Blind spots: whether a service-range address is used for that service;
internal subnets per company; NAT coherence (natdst vs the story's server).

**R6 Process truth.** (a) Story rows with a process (live, team, scenario; endpoint sources), per
story and host, by the pid the native record prints (canonicalPids; a scenario prints its authored
pid): one pid is one image name, one path, one hash and one command line (a command line that is
only the image name is ignored, paths of the image normalised); a parent pid that is another row's
process names that image; nothing is its own parent. Noise-pool rows are skipped (pid reuse hours
apart is real). (b) EDR console: one pid per process in `ps`; a single-instance process (lsass,
services, wininit, smss, explorer per user) once; a case process and the feed rows of the same
image and command line on the same host share a pid. (c) Forensic: a pid is one image and has one
parent across pslist and pstree. Blind spots: processes that live only in a raw block (an MDE
InitiatingProcessId with no process object), pid reuse inside a story, the XDR tables.

**R7 Provable story.** XDR alerts link the events behind them. A story tagged T1110.003 shows at
least 10 failed sign-ins over at least 8 accounts within 10 minutes of feed time; T1110 / .001 /
.004 at least 10 failures (failures: auth, SSH, VPN, DB, MFA-denied rows, HTTP 401/403). Not
mechanical: "a twist happens only after the attacker reached what it needs" and "a benign
look-alike carries the evidence that disproves it".

**R8 Volume and severity.** On the feeds a learner triages: noise is at least twice the attack rows
(live: over each story's shift window with the hook's tick and phase constants; team: the whole
session); per company some benign row is high or critical and some attack row is low; no 3 or more
identical benign rows (times, GUIDs and long ids aside) in a noise pool or session; tickets
(ServiceNow) at most about 8% (flagged above 10%). Blind spots: the live feed's deck reshuffle with
user rotation on long shifts, org-authored companies.

**R9 No answer leaks.** Verdict keys in a record (is_malicious, attack_stage, expected_verdict,
ground_truth, is_attack, fp_explanation, correct_verdict, it_verify_result, is_baseline ...),
`malicious: true`, a maintenance flag set to true, verdict words (attacker, hacker, evil,
malicious, pwned, backdoor) in an identity value, and the authored conclusion (first 40 characters
of an attack row's description) copied into a native record. Blind spots: verdict wording in
free-text vendor fields (a product's own detection name legitimately says "malicious"), severity
as a tell (R8 covers it coarsely), room log_analysis rows (the description is shown by design).
