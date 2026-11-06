# Room build brief

How to turn one Learning Room into an Operation room. Read this, then read the room, then build. Exact field shapes live in `src/lib/rooms/experience/types.ts` (`BriefingLab`); game kinds are explained in `docs/campaign/GAME-LABS-BRIEF.md`. A finished example: `src/lib/rooms/experience/defenderXdr.ts` with `docs/campaign/58-defender-xdr.md`.

## What a room is

- One fictional company, one mentor, one incident that runs through the whole room. Every station moves that story on.
- 3 to 5 stations. A station is a contiguous run of task ids. The last is the boss (`boss: true`), holding the hardest graded task.
- Every reading (and any non-reading task that needs a warm-up) has labs in `briefings`, keyed by task id. The learner may read only the labs, because the reading text is folded away. So the labs must teach everything the graded tasks need.

## The rules (Tal's, all binding)

1. **The game is the way in, never the goal.** Ask of every lab: what does a learner who LOSES walk away knowing? Wrong moves say why. A game with cyber words on it and nothing to learn is a failure.
2. **A lab never copies a graded answer.** It teaches the idea on another example, and the graded task makes the learner apply it. No graded scenario, value pair, hostname or option wording in a lab. Never add a block of facts to a `prompt`: put a fact in a row, a clue, a card or a `why`. If a graded task is pure recall of one fact, a lab may show that fact in passing, as data in a row with its label, but must not ask it.
3. **Every fact a graded task needs is reachable through the labs.** Go through the graded tasks one by one and name the lab line that teaches each idea. Write that list as the "separation" section of the campaign doc, and state what differs from the graded task.
4. **Every room differs from every other room,** in design and in challenge. Use the `Signature` you are given. Use at least 2 arcade kinds, and the set of arcade kinds in the room must not match any other room (`labIntegrity.test.ts` enforces this). No `terminal` lab: typing commands is reserved for four rooms.
5. **Realistic, not real.** Native formats and real field names for every log, console and tool. `.example` domains, RFC 1918, 203.0.113.x, 198.51.100.x. No real company, no real person, no logo or product name in console chrome. Real product names are fine in teaching text.
6. **Professional level.** Write for working analysts. Concrete values, real tool behaviour, real pitfalls. MITRE ATT&CK v19 (Stealth TA0005, Defense Impairment TA0112). If you are not certain of a technical fact, check it or leave it out.
7. **Clear.** Every station and lab title says what it teaches. Each lab's prompt says what to do. Beginners may read it, so name an acronym the first time you use it.
8. **Text:** English. No em dashes or en dashes. The mentor gets no he or she in any text: use the name or "they". No content counts in marketing-style lines.
9. **Do not change a reading's `content` or `heading`:** it would disable its recorded narration. Do not change graded tasks, answers or flags. If a graded task is wrong, report it, do not fix it.

## What to write

1. `src/lib/rooms/experience/<camelRoomId>.ts` exporting `export const <UPPER_SNAKE_ROOM_ID>: RoomExperience`. Header comment: codename, company, signature, game mix, and how lab data differs from the graded tasks. Fields: `roomId`, `codename`, `theme`, `handler`, `briefing` (4 short lines), `mission`, `estimate`, `look` (3 colours, not the same as the previous rooms), `scene`, `layout: "facility"`, `stations`, `personas` (one neutral line per graded task, never hinting at the answer), `briefings`.
2. `docs/campaign/<NN>-<room-id>.md`, in Hebrew, same headings as `58-defender-xdr.md`, including the separation list and the film table of 4 films: intro, two chapters, finale. Films tell backstory and never show lab answers.

Station `taskIds` must be the room's real ids. Keep the room's task order if it already groups well. If it does not, choose a new order, write it in the file's header comment and in your reply. **Do not edit `src/data/*`, `index.ts`, `types.ts`, `OperationView.tsx`, `rooms.tsx` or any shared file, and do not run the reorder script.** The integrator does that. You may run `npx tsx scripts/print-room.ts <room-id>` (from the worktree) and `npx tsc --noEmit -p .`. Save time: read the room, read only the lab shapes you use, and do not read the other rooms.

## Common failures

- `duel`: each move's counter must be a different card, and there must be more cards than moves. `rush`: 12 to 16 cards, target at least 60%. `intercept`: 8 to 12 items, 3+ of each side. `deduce`: `cells` length equals `columns` length. `tune`: goals must be reachable, and the winning settings must not be the starting ones. `pathway`: every route hop must be an edge. `spotdiff`: both copies equal length, only listed lines differ. `codebreak`: answers 3 to 10 letters or digits. `trace`: vary the answer row. `hunt`: exactly one right line per rung; wrong lines must really return something different; check by hand that the final query returns `expect` rows. `portal`: at least 6 steps, every target reachable.
- `chat`: set `memory: true` so follow-ups can add up to a win. Test free text with `said()`-style negation; `locks` takes `finish`; `spotdiff` takes `winTitle`.
- `hotspot` default finish text assumes a phishing lure: set `finish` otherwise. `spotdiff` default text says tampered and known-good: set `hud`, `sameLine` and `howTo` if it compares anything else.
- `portal` traps fire at every step, not only the step they were written for. Word each one so it stays true at any moment, or leave it out. Do not trap something the learner should be free to look at.
- Consoles must only show states the real product can show. Evidence verdicts are Malicious, Suspicious, No threats found. Live Response commands are `connections`, `processes`, `getfile`, not netstat.
- Joins must be right on a real fleet: PIDs repeat across devices, so a process join includes the device. FolderPath includes the file name.
- Keep hostnames, counts and roles consistent across all labs of a room. A host said to have no agent cannot have telemetry two stations later.
- Check each game's own promise. If a game says a product only reports what it sees, every move must be something that product can really see.
- Teach the decisive signal of the boss task in a lab of its own, on another example, not in a passing clause.
- A clue that points straight at the answer, or a `tune` that wins by leaving the dials alone.
- A lab named after the graded answer.
- Persona lines that give the verdict away.

## Your reply

Under 15 lines: the file paths; the task order (only if changed); the theme and scene ids; the facility config for your room (hall or campus, as assigned), as a code block; anything wrong you found in the graded tasks. No summary of what you wrote.
