# Review: Operation Quiet Wire (room `tunneling-c2-channels`)

Reviewed 2026-11-03. Scope: `src/data/rooms-batch-17-r6.ts` (room content, log events and answer keys), `src/lib/rooms/experience/tunnelingC2.ts` (stations, briefing, labs, personas), `src/lib/rooms/experience/types.ts`, `src/lib/rooms/grading.ts`, `src/data/rooms.ts` task types, and the operation components under `src/components/operation/`. Line numbers are against the file state at review time; where a fix moved a block, the finding says so. Technical claims were checked against MITRE ATT&CK, the relevant RFCs, OpenSSH, IANA, FoxIO (JA3/JA4), Zeek/RITA and vendor docs (sources at the end). Findings I then fixed are marked **[fixed]**; the fix is described inline.

## 1. Summary verdict

**Accuracy: strong to begin with, with a handful of real errors and several precision gaps.** The core teaching was better than most training material: the -L/-R/-D directions are right, the outbound-vs-inbound asymmetry is correctly the spine of the room, the beaconing math (interval, symmetric jitter band, delta clustering, beacon score) is correct and the worked example checks out, and the dual-use "context decides, not the tool" thesis is exactly right. The errors were in the details: a misstated Linux ping payload, "4444 is not a registered service" (it is, for obsolete krb524), a vague Chisel fingerprint, and JA3 presented as the current TLS pivot when browser extension randomization has made JA4 the right choice since 2023. The room also cited no MITRE technique IDs at all for a room whose entire subject is ATT&CK's Command and Control tactic.

**Pedagogy: the single biggest problem was structure, not content.** The room presented **six readings in a row** (r1 through r6) before the first graded task, then a block of questions, logs and exercises. That is a wall of theory with no practice between, the exact anti-pattern the gamified-rooms concept is meant to fix. Nothing was assessed that was never taught, and the one near-miss (the beacon observation-window idea, which `tunnel-o1` leans on) has been shored up. Difficulty curve was otherwise reasonable.

**Mission realism: a good exercise set, not yet a hunt.** The tasks covered spot-the-beacon, confirm-the-channel and triage well, but the room **stopped at the verdict**. A real C2 hunt continues: scope the other hosts, contain in a safe order, eradicate, and document. None of that was graded. Two new tasks and a reorder close that gap.

## 2. Accuracy findings

Severity: **High** = wrong or self-contradicting; **Medium** = imprecise or dated in a way an experienced analyst would catch; **Low** = polish.

### High

**A1. Linux ping payload described wrong. [fixed]**
Original r3 content and codeExample: "a standard Linux/Unix ping sends a recognizable, incrementing 48- or 56-byte pattern". The Linux `ping` default data size is **56 bytes**, and the first **8 bytes are a timestamp** that changes every packet; only the remaining 48 bytes are the incrementing `0x10...0x37` filler. Teaching it as a wholly fixed pattern would make an analyst misread a normal Linux ping (whose leading bytes legitimately change) as anomalous.
**Fix:** rewrote both the prose and the codeExample to "56 bytes: 8-byte timestamp, then the incrementing bytes 0x08, 0x09, 0x0a ... 0x37", and added to the detection text that only those timestamp bytes change in a real Linux ping.

**A2. "Port 4444 has no standard registered service." [fixed]**
Original r2 content and codeExample. IANA **does** register 4444/tcp and 4444/udp (to `krb524`, an obsolete Kerberos 5-to-4 ticket translator; `nv-video` is also noted on it). The true teaching point is not that 4444 is unregistered but that nothing in a modern enterprise uses it, so an outbound connection to it has no business explanation.
**Fix:** reworded to "4444 is Metasploit's default LPORT; its IANA entry (krb524) is obsolete, so nothing modern uses it", and softened the two MCQ distractors that called 4444 "unregistered" to "an unusual port".

### Medium

**A3. No MITRE ATT&CK technique IDs anywhere. [fixed]**
The room's subject is the Command and Control tactic, yet it named no technique. The prompt explicitly asks for T1071/T1572/T1090/T1095/T1568/T1573 to be verified and used.
**Fix:** wove the correct IDs into the readings and the new closing report, each where it is taught: Protocol Tunneling **T1572** (SSH/Chisel/ngrok tunnels), Proxy **T1090** with **.001** Internal Proxy (SOCKS through a victim) and **.003** Multi-hop Proxy (SOCKS chaining), Web Protocols **T1071.001** and DNS **T1071.004** (HTTP(S)/DNS C2), Encrypted Channel **T1573** (TLS wrap), Non-Application Layer Protocol **T1095** (ICMP/raw TCP shells), Non-Standard Port **T1571** (SSH on 443, shell on 4444), Dynamic Resolution **T1568** (DGA/fast flux). All are live in ATT&CK and in this platform's v19 library except T1095 and T1090.001, which are cited only in prose (not in a structured `mitre` field), so the MITRE-drawer consistency test is unaffected; see A11.

**A4. Chisel fingerprint too vague ("a specific banner/handshake behavior"). [fixed]**
Chisel's recognizable default is concrete: the client opens a **WebSocket upgrade** whose `Sec-WebSocket-Protocol` header carries the protocol version string (`chisel-v3` in the current `jpillora/chisel`), with an SSH session multiplexed inside the WebSocket (confirmed against the upstream `server_handler.go` and `share/version.go`).
**Fix:** replaced the vague phrase with that description, kept the "operators customize it, so behavior beats static signatures" point.

**A5. JA3 presented as the current TLS pivot. [fixed]**
Original r6 Step 4 and codeExample said only "JA3/JA3S". Since early 2023 Chrome (and others) **randomize TLS ClientHello extension order on every connection**, so a browser's JA3 changes constantly and is no longer a stable pivot. FoxIO's **JA4/JA4S sorts the values before hashing** and stays stable, which is why it is the better fingerprint to pivot and scope on today.
**Fix:** rewrote Step 4 to explain JA3's instability and lead with JA4/JA4S; updated the codeExample line to "JA4/JA4S (JA3 is unstable for browsers)".

**A6. SSH -D and -R precision gaps. [fixed]**
Three true but omitted points an advanced learner should have: (1) OpenSSH's `-D` SOCKS proxy relays **TCP only**, not UDP, even though SOCKS5 defines UDP; (2) `-R` with a **single port** (`-R 1080 host`) is reverse dynamic forwarding (a SOCKS proxy on the remote side), added in **OpenSSH 7.6**; (3) by default `-R` binds the remote listener to loopback unless the server sets `GatewayPorts` (immaterial when the attacker owns the server, worth stating so the learner is not surprised by a lab box that refuses a remote bind).
**Fix:** added all three to r1/r2 as short clauses, and noted the Windows OpenSSH client (shipped since Windows 10 1809) so the -L/-R/-D syntax is not treated as plink-only.

### Low

**A7. "Living-off-the-Land" used loosely for ngrok/Chisel/plink. [fixed]**
Strictly, LOLBins are tools the OS already ships (e.g. `ssh.exe`, `netsh interface portproxy`); ngrok/Chisel/plink are third-party binaries the attacker brings. Detection logic is the same, but the label was imprecise.
**Fix:** retitled r5 "Dual-Use Tunneling Tools", added one sentence drawing the distinction and giving `netsh interface portproxy` as a genuine built-in example, and the matching lab includes it.

**A8. Several run-on sentences and a mispunctuated heading. [fixed]**
r6 Step 6 read as sentence fragments ("Given how genuinely dual-use... Is exactly the failure mode"); the heading used a comma for a colon. la2 Q3 explanation and the m1 explanation had comma splices.
**Fix:** repaired punctuation throughout the readings edited. No em dashes introduced (the only `—` in the file is the pre-existing header comment).

**A9. la2 Q2 explanation named SQLi as the likely vector. [fixed]**
"via SQL injection leading to command execution, or a malicious extended stored procedure" is plausible but imprecise: if the beacon is attributed to `sqlservr.exe` **itself** (not a child process), the likely mechanism is code loaded **into** the engine (a malicious CLR assembly or extended-stored-procedure DLL), whereas `xp_cmdshell` would surface as a child process such as `cmd.exe`.
**Fix:** reworded to distinguish in-engine execution from a spawned child process.

### Notes, not changed

**A10. ngrok abuse has two distinct fingerprints (agent side vs. endpoint side).** The r5 ngrok paragraph describes the agent-side tunnel (`ngrok.exe` making outbound TLS to ngrok's cloud; by default the agent connects to `connect.ngrok-agent.com` on 443, and the free tier's public hostnames sit under `*.ngrok-free.app`/`*.ngrok-free.dev`). It does not separately treat the visitor side (traffic arriving at the public ngrok URL). The existing text is accurate for the SOC-telemetry case the room cares about (outbound from an internal host), so this is left as a possible future depth addition, not an error.

**A11. T1095 and T1090.001 are not in the platform's v19 MITRE library (`src/lib/mitre/attack.ts`).** They are cited only in reading prose, and `attack.v19.test.ts` only scans structured `mitre`/`threat.technique.id` fields, so no test breaks and no drawer misfires. If these are ever moved into a structured field on an event, add library entries first.

## 3. Pedagogy findings

**P1. Six readings before any practice. [fixed by reorder]**
Original task order was r1,r2,r3,r4,r5,r6, then all questions/logs/exercises. Learners met 6 dense readings (SSH forwarding, SOCKS/shells, ICMP/DNS, beaconing math, dual-use tools, the playbook) before doing anything. **Fix:** interleaved so each group of readings is immediately practised:
- r1, r2 → **q1** (the -R danger)
- r3, r4 → **q2** (the jitter band)
- r5 → **q3**, then **m1** (mechanisms across r1-r5)
- r6 → **la1** (plink), **f1** (the outer port)
- **la2**, **o1**, **qf1**, **ac1** (the DB beacon case)
- **o2**, **wr1** (contain and close)
The flag's `logTask` is pinned to `tunnel-la1` so the reorder does not mis-resolve its log.

**P2. One assessed idea was under-taught. [fixed]**
`tunnel-o1` requires the learner to know that a beacon hunt needs a **multi-hour window** (and that destination rarity filters busy update/telemetry services). r4 taught clustering but not the window length explicitly.
**Fix:** added an "observation window must outlast the sleep" paragraph to r4, and a note that real tools (RITA over Zeek) use robust statistics (skew, median absolute deviation) rather than a raw standard deviation.

**P3. Difficulty curve is sound.** Checkpoints are ungraded and unlimited-retry (teaching); q1-q3 are single-concept applications; la1/la2 apply to raw logs; m1/o1/qf1 synthesise; the new boss (o2 + wr1) requires sequencing a response and writing it up. No cliff, no anticlimactic boss.

## 4. Mission realism findings

**M1. The room stopped at the verdict.** Measured against a real C2 hunt (spot the beacon → confirm the channel → scope the other hosts → contain safely → eradicate → document), the original room did the first two or three well and nothing after. **Fix:** two new graded tasks, using existing task types only:

- **`tunnel-o2`** (`ordering`, 35 XP) — "Contain the SRV-DB07 Channel". The learner sequences preserve → scope → contain → eradicate → watch → document on the confirmed beacon. Teaches that evidence preservation precedes reimaging, that scoping precedes cutting the channel (or the operator moves to a new implant), and that blocking the destination alone is not containment.
- **`tunnel-wr1`** (`written_report`, 50 XP) — "Close the Case". The learner writes the closing summary for all three findings (SRV-APP12 plink, SRV-DB07 beacon, WKS-DEV27 benign true positive), cites the real indicators, maps the ATT&CK techniques and gives a verdict. Graded by the existing `written_report` rubric (depth by word count, evidence by citing the case's own indicators, fabrication penalty).

**M2. XP and estimate updated.** New graded-XP sum = 495 (was 410): q1 25, q2 30, q3 25, la1 80, la2 85, ac1 30, m1 40, o1 35, qf1 35, f1 25, **o2 35**, **wr1 50**. `estimatedMinutes` raised 70 → 85. No new log event was added (both new tasks reuse the case's existing evidence), so `validate-log-fields.mjs` still passes.

**M3. The experience ties the tasks into a route.** `tunnelingC2.ts` renders the room as a NETWORK scene of relay nodes: six hops from "Hop 1: The Beacon" (how the link is built) through "The Carrier", "The Disguise", "First Evidence" and "The Pivot" to the boss "C2 Core" (cut it, close it). Station task ids are contiguous and match room order exactly. Every reading has 2-4 briefing labs mixing the five kinds; all use a separate fictional network (Harbor Logistics), different hosts, ports, intervals and tools, and RFC 5737 documentation IPs, so no lab leaks a graded answer, and each lab agrees with the current reading text.

## 5. Checks run

- `npx tsc --noEmit -p .` — clean.
- `npx eslint` on both edited files — clean (one pre-existing `import/no-anonymous-default-export` warning on the batch file's `export default [tunnelingRoom]`, present before this work).
- `npx vitest run src/lib/rooms` — 59/59 pass (includes the all-rooms flag-log resolution regression and the ATT&CK v19 consistency tests).
- `npx tsx scripts/validate-content.mjs` — only the expected "roomsMeta stale (regenerate)" message for this room; no content defects. (roomsMeta.ts is owned elsewhere and was not touched.)
- `node scripts/validate-log-fields.mjs` — PASS, no new field violations.
- Grading of both new tasks proved with a temporary vitest file calling `gradeTask(task, submission, room)` (full-credit, partial and fail cases for `tunnel-o2`; strong-report, empty and fabricated-IOC cases for `tunnel-wr1`), then deleted.

## Sources

- MITRE ATT&CK: Application Layer Protocol **T1071** (.001 Web Protocols, .004 DNS), Protocol Tunneling **T1572**, Proxy **T1090** (.001 Internal Proxy, .003 Multi-hop Proxy), Non-Application Layer Protocol **T1095**, Dynamic Resolution **T1568**, Encrypted Channel **T1573**, Non-Standard Port **T1571**.
- RFC 792 (ICMP echo), RFC 1918/5737 (private and documentation IP ranges), RFC 1928 (SOCKS5, UDP associate), RFC 1035 (DNS message/label limits), RFC 6455 (WebSocket, `Sec-WebSocket-Protocol`).
- OpenSSH `ssh(1)` man page (-L/-R/-D semantics, loopback bind and `GatewayPorts`, TCP-only dynamic proxy) and the OpenSSH 7.6 release notes (reverse dynamic `-R [port]`); Microsoft docs on the Windows OpenSSH client shipping since Windows 10 1809.
- IANA Service Name and Transport Protocol Port Number Registry (4444 → krb524 / nv-video).
- `jpillora/chisel` upstream `share/version.go` (`ProtocolVersion = "chisel-v3"`) and `server/server_handler.go` (the `Upgrade: websocket` + `Sec-WebSocket-Protocol` version check).
- FoxIO JA4+ specification and JA3/JA4 explainers (Chrome TLS extension-order randomization from early 2023; JA4 sorts ciphers and extensions before hashing).
- ngrok documentation (agent connects outbound over 443 to `connect.ngrok-agent.com`; free-tier public hostnames under `ngrok-free.app` / `ngrok-free.dev`).
- RITA / Zeek beaconing documentation (inter-arrival deltas; robust dispersion via skew and median absolute deviation; multi-hour observation windows).
