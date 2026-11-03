# Review: Operation High Tower (room `active-directory`)

Reviewed 2026-11-03. Scope: `src/data/rooms-batch-03.ts` (the `active-directory` room object only), `src/lib/rooms/experience/activeDirectory.ts`, `src/lib/rooms/experience/types.ts`, `src/lib/rooms/grading.ts`, `src/components/operation/mechanics/*` and `briefing/Labs.tsx`. Technical claims checked against Microsoft Learn (Event 4768/4769/4624/4662 reference pages, the SecurityEvent table reference, the group-management audit pages) and MITRE ATT&CK. Fixes described here were applied in the same pass; line numbers are post-fix unless marked "was".

## 1. Summary verdict

**Accuracy: strong core, with one field-role error, one schema mismatch and several outdated or imprecise claims, all now fixed.** The room already handled the single most-confused point correctly: on Event 4769, `ServiceName` is the roast target and `TargetUserName` is the requester (la1 Q1 and its inline comment). That is better than most AD training. The problems were (a) the Kerberos authentication `method`/`logon_type` on the la1 and ac1 events did not match the raw `AuthenticationPackageName`; (b) RC4 was presented as flatly "highly suspicious" with no mention of legacy-AES-less accounts or that AES tickets are also crackable, and with no reference to Microsoft's ongoing RC4-as-default removal on DCs; (c) DCSync was attributed to a single right (`DS-Replication-Get-Changes`) and "DC-level access", when it needs both replication rights on the domain object and does not require logging on to the DC; (d) several reading passages had broken punctuation left over from em-dash removal, including a mangled DC-function bullet list in r1 that fused "KDC" and "SYSVOL" into one unreadable line.

**Pedagogy: well scaffolded, but two taught-not-assessed gaps and a weak boss, now closed.** Five readings build cleanly from "what is AD" to the quiet attacks. The gaps: the room taught 4769 field roles and RC4 but never made the student *scope* a lead in the SIEM (the real next step), and it taught the verdict taxonomy only implicitly. The boss floor was `la2 + flag2 + ac1`, three items the student had largely already met. A scoping `query_fill` and a closing `written_report` now add the two missing real steps and give the boss genuine synthesis.

**Mission realism: good bones, now a real investigation.** After the fixes the room reads as a single climb: learn the building, learn how it proves identity, learn what to watch, then work three correlated-feeling cases (an RC4 roast, an NTLM relay, an off-hours DC logon) and hand them over at end of shift. That is close to how a night-shift analyst actually meets AD activity.

## 2. Accuracy findings

Severity: **High** = wrong or contradicts a graded answer; **Medium** = outdated/misleading/unrealistic; **Low** = wording/polish.

### High

**A1. la1 and ac1 normalized `authentication` block did not match the raw event.** (`:173` and `:467`, was)
la1 carried `authentication.method: "Kerberos"` with `logon_type: 3`. A 4769 service-ticket request is not a logon and has no LogonType; carrying `logon_type: 3` on it is wrong and could teach a student to expect a logon type on every Kerberos event. ac1 carried `authentication.method: "NTLM"` while its raw `AuthenticationPackageName` is `Negotiate` (correct for an RDP/interactive logon, which negotiates to Kerberos).
**Fixed:** removed `logon_type` from the la1 auth block; changed ac1 `method` to `Negotiate` to agree with the raw field. (`:173`, `:467`)

**A2. DCSync described imprecisely (reading and q5).** (r2 DCSync paragraph; r3 DCSync bullet; q5 `:259`)
The r2 text said an attacker "with specific permissions (DS-Replication-Get-Changes)" can "impersonate a Domain Controller" and that this "requires DC-level access". Per MITRE T1003.006 and Microsoft's replication model, DCSync needs **both** `DS-Replication-Get-Changes` **and** `DS-Replication-Get-Changes-All` on the domain object, and the whole point is that it does **not** require logging on to the DC. It also dropped the dependency that Event 4662 only appears with Directory Service Access auditing and a SACL on the domain object.
**Fixed:** r2 and r3 now name both rights, state no DC logon is needed, add the MITRE id (T1003.006) and the 4662 auditing dependency. q5 was already correct (both GUIDs, "not a Domain Controller"); left intact and now matches the reading.

**A3. RC4 taught as a flat red flag.** (r2 Kerberoasting indicator; r3 Kerberoasting detection)
"RC4 ticket requests are highly suspicious" with no caveats is wrong often enough to mis-train. Microsoft's own 4768 guidance treats non-AES encryption types as the thing to monitor, but a legacy account that never received AES keys will legitimately get RC4, and an attacker can request AES tickets too (slower to crack, still crackable).
**Fixed:** r2 and r3 now say RC4 stands out *for an account that supports AES*, note Microsoft's removal of RC4 as a Kerberos default on DCs, and state the two caveats; they stress that the pattern (one requester, many service accounts, minutes apart) matters as much as the value. This aligns with q3, whose key already explains that 0x12 AES is the normal value.

### Medium

**A4. r1 Domain Controller function list was corrupted.** (`:48`, was)
Em-dash cleanup had fused the bullets into `"Runs the Kerberos Key Distribution Center (KDC) (the authentication engine - Hosts the SYSVOL share) where Group Policy settings are stored"`, with unbalanced parentheses and two functions merged.
**Fixed:** rewrote the list as five clean bullets and corrected "Authorises access" to the more accurate "supplies the identity and group memberships that servers use to decide access" (the file server enforces its own ACL; the DC does not authorise each file open).

**A5. "access is revoked everywhere instantly" overstated.** (`:48`, was)
Disabling an AD account refuses *new* authentication, but already-issued Kerberos tickets remain valid until expiry (up to ~10h). This matters directly: it is why the room's own containment guidance says to end sessions, not just disable.
**Fixed:** r1 now states the ticket-lifetime caveat and ties it to containment.

**A6. GPO application cadence and DC-outage claim imprecise.** (`:48`, was)
"Every time a user logs in or a computer starts up" omitted background refresh (~90 min). "If the Domain Controller goes down" ignored that enterprises run several DCs and that cached logons still work on known machines.
**Fixed:** r1 now says "startup or logon, and again in the background roughly every 90 minutes", and "if every Domain Controller goes down ... apart from cached logons".

**A7. LDAP filter example was not a valid filter.** (r2, was)
`(objectClass=user)(sAMAccountName=j.smith)` is two filters with no operator. RFC 4515 filters are prefix-form.
**Fixed:** `(&(objectClass=user)(sAMAccountName=j.smith))` with a one-line explanation of `&`.

**A8. Golden Ticket detection could be sharper.** (r3)
Added the high-value detection that a 4769 service ticket with no preceding 4768 TGT for that account is a forged-TGT tell, alongside the existing "unusual lifetimes / nonexistent accounts". Removed the now-defunct "Microsoft ATA" (end-of-life) and kept MDI.

**A9. Pass-the-Hash detection thin.** (r3)
Added the matching 4776 (NTLM credential validation on the DC) and the "admin account suddenly using NTLM where it normally uses Kerberos" signal, which is the realistic PtH tell rather than volume alone.

### Low

**A10. Step headers used mixed punctuation** ("Step 1, AS-REQ" vs "Step 3. TGS-REQ"). Normalised to "Step N: NAME" across r2.

**A11. Event-ID monitoring list** (r3) now distinguishes 4728 (global group, e.g. Domain Admins), 4732 (local/domain-local, e.g. built-in Administrators on DCs) and 4756 (universal, e.g. Enterprise Admins), per the Microsoft group-management audit pages, where it previously lumped 4728/4732 together. Also clarified that 4672 fires for SYSTEM and service logons too, so it must be filtered by account.

**A12. SPN not defined.** r2 introduced Kerberoasting without ever saying what an SPN is. Added a one-sentence SPN definition with a concrete example (`MSSQLSvc/...`).

## 3. "Answer given away" findings

**B1. la1 event description pre-stated the verdict.** (`:170`, was)
The event `description` read "Kerberos Service Ticket request with RC4 encryption: possible Kerberoasting", and `severity: "high"`, naming the technique the student is asked to identify, and the context said "with an older encryption type".
**Fixed:** description is now the neutral "A Kerberos service ticket was requested"; context no longer editorialises the encryption type (the student must read TicketEncryptionType themselves). `mitre_technique`/`mitre_tactic` are retained on the event object but are not rendered by the Evidence Board mechanic (verified in `EvidenceBoard.tsx`, which shows only `context` and the flattened `raw`), so they do not leak to the student.

**B2. la2 event description pre-stated the relay conclusion.** (`:376`, was)
It read "...authenticated ... via NTLM, but the claimed WorkstationName does not match the source IP", which is exactly la2 Q1's answer. The two enrichment findings were also embedded as `raw` fields with verdict-laden names (`asset.cmdb_lookup_...`, `asset.dhcp_lease_...`) that both failed the native-schema gate and handed over the reasoning.
**Fixed:** description is now "An account was successfully logged on (network logon, NTLM)". The enrichment is moved into the `context` (where la1 already puts its narrative) as two neutral lookup results, and the raw block now carries only genuine 4624 NTLM fields (`LogonProcessName: NtLmSsp`, `LmPackageName`, `KeyLength`), which also clears the two baselined field violations for this room.

## 4. Mission / gamification changes

The room was a correct quiz in a tower costume: stations mapped to task *types*. Two real investigation steps were missing entirely, so I added them with existing task types (no component or type changes).

**New task ad-qf1 (query_fill, 30 XP)** — "Scope the Roast". After the RC4 lead in la1/flag1, the student writes the Sentinel `SecurityEvent` KQL that counts how many distinct service accounts the suspect host asked for in 24h (`dcount(ServiceName) by TargetUserName, IpAddress`), extracting `TicketEncryptionType` from `EventData` because it has no column. Accepts the `::ffff:` IPv4-mapped form via `endswith`. This is the "one event is a lead, not a case" step the room taught (r3) but never practised.

**New task ad-wr1 (written_report, 50 XP)** — "Write the Shift Handover". The boss deliverable: one note covering all three cases (roast, relay, authorised DC logon), each with technique, real indicators, verdict and next action, ending with a priority. Its `referenceIocs` are all values already visible in the room's events; grading proven with a temporary vitest (strong answer passes, empty fails), then deleted.

**Reading additions to support them (no assessed-but-untaught gaps):** r3 gained a "Read a 4769 Field by Field" block, a "Scoping in the SIEM" block (SecurityEvent table, EventID/TargetUserName/ServiceName/IpAddress columns, `extract()` for EventData-only fields, `endswith` for `::ffff:`, `dcount`), and a "Context Before Verdict" block defining true positive / benign true positive / false positive / escalate. These teach exactly what qf1, wr1 and ac1 assess.

**XP / time:** graded XP sum is now 505 (was 425): q1 20 + q4 20 + q2 25 + q3 30 + la1 (30+35) + flag1 40 + qf1 30 + q7 30 + la2 (35+35) + flag2 35 + q5 30 + q6 30 + ac1 30 + wr1 50. `xp` updated to 505 and `estimatedMinutes` to 65.

**Station regrouping (experience):** five floors, each contiguous and covering every task once, in room order: Ground Floor (r1,q1,q4) → Mezzanine/Ticket Office (r2,q2,q3) → Monitoring Floor/Evidence Room (r3,la1,flag1,qf1) → The Quiet Floor (r4,q7,r5,la2,flag2) → The Crown/boss (q5,q6,ac1,wr1). Flag `logTask` refs added (`ad-flag1`→`ad-la1`, `ad-flag2`→`ad-la2`) so the flags pin the right log after regrouping; room task order was left unchanged, so no other flag refs needed touching.

## 5. Open items / notes for the caller

- **roomsMeta is stale** (`roomsMeta/active-directory 17 vs 19`): expected, since two graded tasks were added. I did not edit `roomsMeta.ts` (out of scope per instructions); it must be regenerated before release.
- **No type changes needed.** The five briefing-lab kinds and existing task types covered everything; the tower scene already exists. Nothing in the feature set was missing.
- The two other content-gate errors (`tunneling-c2-channels`, `ransomware-full-lifecycle`) are other agents' rooms, same stale-roomsMeta class, not touched here.

### Sources
Microsoft Learn: Event 4768 reference (PreAuthType table 0/2/15/16/138, TicketEncryptionType 0x11/0x12/0x17, `::ffff:` client-address form, failures move to 4771); SecurityEvent table column reference (EventID, TargetUserName, ServiceName, IpAddress, WorkstationName, AuthenticationPackageName as columns; other EventData via extract); Audit Security Group Management (4728 global / 4732 local / 4756 universal). MITRE ATT&CK: T1558.003 (Kerberoasting), T1003.006 (DCSync), T1557.001 (LLMNR/NBT-NS poisoning), T1021.001 (RDP). Microsoft KB 5073381 / CVE-2026-20833 (RC4 Kerberos hardening phases on DCs).
