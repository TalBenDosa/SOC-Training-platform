# Game labs: writing brief

Tal, 2026-11-05: the CMD lab is good, but it is in almost every room, so every room feels the same and
learners stop moving on. Every room gets original, topic-driven game missions with real challenge. No two
rooms play alike.

## The rule

- Typing commands stays only where the command line IS the skill: `linux-fundamentals`,
  `linux-log-analysis`, `windows-fundamentals`, `powershell-for-soc-analyst`. One `terminal` lab at most.
  Every other room has none.
- Every room uses its own mix of at least two game kinds. See the table below. The mix must stay unique
  (`labIntegrity.test.ts` enforces all of this).

## The game kinds

Exact fields and comments: `src/lib/rooms/experience/types.ts` (`BriefingLab`). Copy the shapes exactly.

| kind | what the learner does | what makes it hard |
|---|---|---|
| `intercept` | items drop toward what they guard; block or allow | clock tightens, 3 lives |
| `duel` | attacker plays a move; play the one card that stops it | played cards are gone, 3 lives |
| `deduce` | strike suspects out as clues arrive, then accuse | 2 accusations, fewer clues is better |
| `tune` | set numeric dials, deploy, see what it caught | results only on deploy, 3 deploys |
| `pathway` | walk a real route hop by hop on a map | wrong hop costs a life and says why |
| `defuse` | read a state, cut the one right wire | global clock, wrong cut is -10s |
| `outbreak` | isolate one host a turn while the infection moves link by link | network drawn fresh each run; use the fields only |
| `codebreak` | guess a term, port or ID from a clue | letter feedback, limited tries |
| `rush` | rapid two-way calls for a target | 60s, streak multiplier |
| `spotdiff` | known-good beside suspect, tap tampered lines | false accusations cost lives |

## What to do in each room

1. Read the room's experience file, and the room's tasks with `grep` in `src/data/rooms-batch-*.ts`.
2. Remove every `terminal` lab, except one in the four console rooms.
3. Put the room's assigned game kinds in. Each new lab replaces a removed one in the SAME task slot. If the
   room has fewer `terminal` labs than assigned games, the remaining games replace the most generic `sort`
   or `worksheet` labs in the room.
4. A room's labs must still teach everything the removed lab taught. Move every `why` point into the new
   lab. A reading's labs must cover what that reading teaches, because the game replaces the reading.

## Quality bar

Tal: gamification is there to illustrate and to teach. The game is the way in, never the goal. Ask of
every lab: what does a learner who LOSES walk away knowing? If the answer is nothing, it is decoration.

- **The game must BE the topic.** A duel in a firewall room plays firewall moves. If you could swap the
  words and reuse the game in another room, rewrite it.
- **Real challenge.** Wrong options are the mistakes real analysts make, and look right at first glance.
  Never make the right answer the longest or the most detailed. Avoid "obviously evil" items: a legitimate
  tool used badly, a benign thing that looks scary, a near-match that differs by one field.
- **Use the room's story.** Its company, mentor and incident (see `briefing`, `handler`). The `prompt` puts
  the learner in a moment of that story in one or two sentences, in the mentor's world.
- **Practice data differs from the graded tasks.** Never reuse a graded task's values, and never reveal a
  graded answer. Labs are practice; the graded task comes after.
- **Teach on every outcome.** Each `why`, `hint` and `lesson` says the reason, with the concrete field,
  value or behaviour. One or two sentences. `hint` nudges without giving the card away.
- Data is realistic, never real: no real people, domains are `.example`, IPs are RFC 1918 or 203.0.113.x,
  198.51.100.x. Native field names for each log source. MITRE ATT&CK v19 (Stealth TA0005, Defense
  Impairment TA0112). Do not use a technique ID unless the room teaches it.
- All text in English. No em dashes. ASCII apostrophes inside double-quoted strings.
- Do not name the platform. No `howTo` unless the default steps truly do not fit.

## Sizes

`intercept` 10 items, 4+ of each side, `seconds` 10 to 12. `duel` 5 moves, 7 cards. `deduce` 5 or 6 suspects,
3 or 4 clues; clue 1 alone must not solve it. `tune` 10 to 12 events, 1 or 2 dials, goal needs thought:
the obvious round number should NOT pass; `start` must fail the goal. `pathway` 8 to 10 nodes spread across
the map (x, y 10 to 90, no two within 14 of each other), route of 4 to 6 hops, a `traps` entry for every
tempting wrong neighbour, a `notes` entry for every route node. `defuse` 4 rounds, 3 wires each, `seconds`
75 to 100. `outbreak` 6 by 5, `crown` at most 9 characters, `via` the room's real spread path: use it only as assigned. `codebreak` 3 or 4 rounds, answers 3 to
8 letters or digits, no spaces. `rush` 14 cards, target 10, `seconds` 60, statements short enough to read
in 4 seconds. `spotdiff` 10 to 14 lines, 3 changes, 1 or 2 decoys; every line not listed is identical in
both copies.

## Assignments

| room | games | idea |
|---|---|---|
| intro-cybersecurity | rush, duel | threat or not blitz; attacker vs CIA defences |
| soc-structure | pathway, defuse | route a ticket through the tiers; a shift crisis |
| cyber-kill-chain | duel, pathway | break each stage; walk the chain |
| mitre-attack | codebreak, duel | tactic and technique IDs; technique vs mitigation |
| networking-fundamentals | pathway, codebreak, rush | packet across subnets; OSI and ports |
| networking-protocols | codebreak, intercept | well-known ports; packets at the edge |
| firewall-network-security | intercept, pathway | first-match allow or deny; through the zones |
| windows-fundamentals | spotdiff, deduce | real vs fake process list; who ran it |
| active-directory | pathway, deduce, spotdiff | path to the crown jewels; who roasted; GPO baseline |
| windows-event-logs | codebreak, deduce | event IDs; who logged on |
| linux-fundamentals | spotdiff, rush | /etc/passwd and cron baseline; permissions blitz |
| linux-log-analysis | deduce, rush | who got in; auth.log line calls |
| log-management | tune, pathway | retention and volume budget; a log's pipeline |
| siem-fundamentals | tune, intercept | correlation threshold; events through the rule |
| wazuh-fundamentals | tune, spotdiff | rule level; FIM baseline |
| sentinel-fundamentals | tune, deduce | analytics rule threshold; incident entities |
| detection-rules-tuning | tune, rush | precision vs recall; TP or FP calls |
| log-sources-integration | pathway, spotdiff | agent to indexer; parser before and after |
| microsoft-365-security | spotdiff, intercept | inbox rules before and after; consent grants |
| endpoint-security-fundamentals | outbreak, duel | contain the spread; EDR vs technique |
| crowdstrike-falcon | outbreak, deduce | contain with network isolation; which host is patient zero |
| sentinelone | outbreak, spotdiff | rollback scope; storyline before and after |
| malware-analysis-fundamentals | spotdiff, defuse | clean vs sample strings; detonation steps |
| alert-triage | rush, defuse | close or escalate; night-shift queue |
| digital-forensics-basics | deduce, defuse | artifact logic; order of volatility |
| email-security | intercept, rush | SPF, DKIM, DMARC at the gateway; true or false |
| phishing-analysis | intercept, deduce | mails at the gateway; which sender forged it |
| vpn-monitoring | tune, defuse | impossible-travel speed; session response |
| firewall-log-analysis | intercept, defuse | drops vs allows; scan in progress |
| dns-investigation | tune, codebreak | subdomain entropy and length; record types |
| protocols-masterclass | codebreak, rush | header flags and status codes; protocol facts |
| firewall-masterclass | duel, intercept | evasion vs firewall generation; L7 calls |
| av-vs-edr-masterclass | duel, tune | evasion vs control; behaviour score |
| analyst-mindset | deduce, duel | hypothesis logic; cognitive bias vs habit |
| dlp-fundamentals | defuse, codebreak | exfil stop; data classes and labels |
| windows-privilege-escalation | pathway, rush | the climb from user to SYSTEM; true or false |
| persistence-mechanisms | spotdiff, duel | autoruns baseline; persistence vs removal |
| vulnerability-management | tune, outbreak | CVSS and EPSS cut-off; patch before spread |
| encoding-encryption-hashing | codebreak, spotdiff, defuse | decode tokens; hash compare; pick the primitive |
| timestamps-and-timelines | deduce, rush, defuse | clock skew whodunit; UTC offsets; timeline rebuild |
| log-entry-anatomy | codebreak, spotdiff, rush | field names; forged log line; field meanings |
| identity-basics | duel, intercept, tune | attack vs auth control; sign-ins; lockout threshold |
| malware-types | deduce, outbreak | name the family from behaviour; worm spread |
| security-products-behaviour | pathway, deduce | which product sees each hop; which log proves it |
| web-application-security | pathway, codebreak | request through the stack; status codes |
| risk-fundamentals | duel, defuse | threat vs control; prioritise under pressure |
| powershell-for-soc-analyst | codebreak, spotdiff | decode a flag; clean vs obfuscated script |
| commodity-initial-access | outbreak, defuse | the loader spreads; stop the chain |
| macos-security-fundamentals | spotdiff, deduce, rush, intercept | LaunchAgents; which plist; TCC calls; notarisation gate |
