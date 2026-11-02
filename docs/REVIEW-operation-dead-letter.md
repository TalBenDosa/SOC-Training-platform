# Review: Operation Dead Letter (room `phishing-analysis`)

Reviewed 2026-11-03. Scope: `src/data/rooms-batch-10.ts` lines 6-265 (room content and answer keys), `src/lib/rooms/experience/phishingAnalysis.ts` (stations, briefing, labs), `src/lib/rooms/experience/types.ts`, `src/components/operation/OperationView.tsx`, `src/components/operation/mechanics/*.tsx`, `src/components/operation/briefing/IntelBriefing.tsx` and `Labs.tsx`, `src/lib/rooms/grading.ts`, plus `RoomClient.tsx` (replay credit). No source files were changed.

## 1. Summary verdict

**Accuracy: mostly sound, with three errors that need fixing.** The core header and authentication teaching in reading 1 is better than most training material: it gets Return-Path vs Reply-To right, knows that SPF checks the envelope domain, and covers the look-alike-domain case where every check passes. The problem is the evidence built on that teaching. Both the graded log (la1) and the first lab show SPF failing against the **From** domain while the Return-Path is a different domain, which is technically impossible and contradicts the reading. Reading 3 tells the learner to take the origin IP "from the bottom Received header", which is the exact distractor la1 Q1 marks wrong. The attachment section also describes the 2019 threat landscape. It says nothing about Microsoft blocking internet macros by default (2022), and it leaves out QR-code phishing, adversary-in-the-middle (AiTM) MFA-bypass kits, HTML smuggling and abuse of legitimate SaaS.

**Pedagogy: good scaffolding at the start, flat at the end.** The labs are well designed and never leak a graded answer. They use the fictional Northwind domain and RFC 5737 IP addresses, which the graded tasks do not. Difficulty peaks at the Evidence Lab (station 3). Station 4 is easy, and the boss vault (station 5) is the easiest station of all: the answer sits in a field shown on the same screen. "Reply-To decides where replies go" is assessed four times (r1 checkpoint, q3, la1 Q2 option D, flag). Several things that decide the graded verdict were never taught: newly registered domains, URL category, softfail/none results and MITRE mapping.

**Gamification and realism: a well-made quiz in costume, not yet a mission.** The stations map to task types (questions, log, verdict, flag), not to the steps of a real triage. The learner never scopes the campaign (who else received it), never decides a containment action, never checks whether anyone clicked or entered credentials, and never writes a ticket note or replies to the reporter. In practice these are most of the work on a reported phish. Each one can become a station with the existing mechanics plus one new "action board" mechanic.

## 2. Accuracy findings

Severity: **High** = teaches something wrong or contradicts a graded answer; **Medium** = outdated, misleading or unrealistic in a way an experienced analyst would notice; **Low** = wording, nuance or polish. "Check" = not fully verified; confirm before changing.

### High

**A1. la1 SPF result checks the wrong domain (graded evidence contradicts the reading).**
`rooms-batch-10.ts:147` `"email.return_path": "bounce@sendinblue-relay247.net"` together with `:155-156` `spf: "fail"`, `spf_detail: "185.220.101.47 is not permitted to send for globalpartners.com"`.
SPF evaluates the MAIL FROM (Return-Path) domain, and the HELO identity, not the From: header domain (RFC 7208 sections 1.1 and 2.4). The room teaches this correctly at `:24` ("It is the domain SPF checks") and in the r1 checkpoint explanation at `:35`. With MAIL FROM at sendinblue-relay247.net, SPF would be evaluated for sendinblue-relay247.net and would almost certainly **pass**, because the attacker controls that domain. DMARC then fails because neither the SPF-authenticated domain nor any DKIM `d=` domain aligns with globalpartners.com (RFC 7489 section 3.1). The la1 Q1 explanation (`:186`) even cites "the SPF detail names the same IP" as corroboration.
**Correct version:** `spf: "pass"`, `spf_detail: "smtp.mailfrom=sendinblue-relay247.net: 185.220.101.47 is permitted"`, `dkim: "none"` (or `pass` with `d=sendinblue-relay247.net`), `dmarc: "fail"`, `dmarc_detail: "header.from=globalpartners.com not aligned with SPF or DKIM domain"`. Reword la1 Q2 option C (`:195`) to "dmarc=fail for globalpartners.com: no SPF or DKIM domain aligns with the From domain", and update its explanation (`:200`). This turns a factual error into the best alignment lesson in the room.

**A2. Lab 1 shows the same impossible SPF result.**
`phishingAnalysis.ts:81` Return-Path `<bounce-7731@em.bulkmailer.example>`, `:85` sending relay `relay7.bulkmailer.example`, and `:91-92` `spf=fail ... SPF failed ... nothing passed in alignment with northwind-bank.com`.
A bulk mailer's own relay sending with its own bounce domain passes SPF for bulkmailer.example. The lab's tag line "the domain SPF checks" (`:81`) is correct, and the lab then contradicts it three lines later.
**Correct version:** `Authentication-Results: mx1.yourco.com; spf=pass smtp.mailfrom=em.bulkmailer.example; dkim=none; dmarc=fail header.from=northwind-bank.com`, with the note "SPF passed, but for the bulk mailer's domain, not the From domain. Nothing aligned with northwind-bank.com, so DMARC fails." The lab's "Spoofed From" simulate scenario (`:125-129`) is correct, because there From and envelope are both northwind-bank.com.

**A3. Reading 3 tells the learner to use the bottom Received header as the origin.**
`rooms-batch-10.ts:66` "Take the originating IP (from the bottom Received header or X-Originating-IP)".
This contradicts reading 1 (`:24` "the lowest lines are written by the sender's side, so they can be forged... The most trustworthy origin is the hop recorded by your own boundary mail server"), the lab at `phishingAnalysis.ts:87-88`, and la1 Q1, whose distractor C (`:181`) is "10.44.22.8: the bottom-most Received line". A learner who reads r3 most recently is taught the wrong answer to a graded question.
**Correct version:** "Take the IP that your own boundary server recorded in its Received line (the first hop stamped by your side, reading bottom-up). X-Originating-IP, when present, is the webmail client's IP and is sender-supplied."

**A4. "A phishing email will almost always fail at least one of these tests."** (`:24`, last sentence)
This is false in 2026, and it contradicts the paragraph above it and the whole of ac1. Most credential phishing now comes from look-alike or newly registered domains with full SPF/DKIM/DMARC, from compromised legitimate mailboxes (vendor email compromise, thread hijacking), or from abused legitimate services (SharePoint/OneDrive shares, DocuSign, Google Forms, Dropbox notifications), and all of these pass authentication. Gmail/Yahoo bulk-sender rules (Feb 2024) and Outlook.com rules (May 2025) have pushed attackers to authenticate properly.
**Correct version:** "Failing authentication strongly suggests spoofing of the exact domain. Passing authentication proves only that the sender controls the domain it used: look-alike domains, compromised real accounts and abused cloud services all pass, so always judge the domain, the request and the link as well."

### Medium

**A5. Macro section is outdated (no Mark-of-the-Web block).** `:45` (".docm, .xlsm ... execute when the user clicks Enable Content") and q2 (`:92`, `:101`).
Since 2022, Office on Windows blocks VBA macros in files carrying Mark of the Web by default. The user gets a red "SECURITY RISK: Microsoft has blocked macros" banner with no Enable Content button (Microsoft announcement Feb 2022; [Netskope summary](https://www.netskope.com/blog/microsoft-office-vba-blocked-by-default-in-files-from-the-internet), [TechTarget](https://www.techtarget.com/searchsecurity/news/252513141/Microsoft-disables-VBA-macros-by-default)). A yellow Enable Content bar on an emailed .xlsm in 2026 means MOTW was missing: the file came out of a container that drops MOTW, sat in a Trusted Location, or the tenant overrides the policy. That fact is itself an investigative lead.
**Fix:** add one paragraph on MOTW and the red banner. Keep q2 but add to the stem "your tenant still allows macros from the internet (legacy exception)", or rewrite it around the red-banner case ("The user says a red banner appeared and they used File > Properties > Unblock...").

**A6. The 2026 phishing landscape is missing.** r2 (`:45`) covers macros, password ZIPs, ISO and PDF links only. A 2026 SOC analyst most often sees:
- QR-code phishing ("quishing"). ATT&CK names it under T1566.002 and T1598.003 ([MITRE T1598.003](https://attack.mitre.org/techniques/T1598/003/)).
- AiTM reverse-proxy kits (Tycoon 2FA, EvilProxy, Evilginx-based) that steal the session cookie and bypass MFA. This changes containment: a password reset alone is not enough, and sessions must be revoked.
- HTML/SVG attachments doing HTML smuggling (T1027.006), and links to legitimate file-share services.
- Callback phishing (TOAD) and fake CAPTCHA "ClickFix" pages that make the user paste a command into Win+R.

**Fix:** a short "what you will actually see in 2026" block in r2, and one lab item each.

**A7. "When you see DMARC FAIL, it means the email claimed to be from a domain it had no right to send on behalf of."** (`:24`)
Overstated. Legitimate mail fails DMARC through forwarding, mailing lists (which break DKIM and change the SPF path), and third-party senders the domain owner forgot to authorise. r3 itself lists "misconfigured legitimate systems" as a false-positive source (`:66`). ARC (RFC 8617) exists precisely for the forwarding case.
**Fix:** "DMARC fail means the message could not prove it came from the From domain. With a strict policy that is usually spoofing, but forwarding, mailing lists and misconfigured vendors also fail."

**A8. DKIM on spoofed mail is usually `none`, not `fail`; DKIM pass is for the `d=` domain.** `:24` "if a criminal is forging the domain, the DKIM signature will not match: DKIM FAIL".
A spoofer normally adds no signature for the spoofed domain (`dkim=none`) or signs with their own domain (`dkim=pass header.d=attacker.example`). `fail` mostly means a signature broke in transit, often benign (footers added by gateways, mailing lists). RFC 6376 section 6.1 and RFC 8601 result values. The lab already uses `dkim=none` correctly (`phishingAnalysis.ts:91`).
**Fix:** teach the result values pass / fail / none / softfail / neutral / temperror for SPF and DKIM, and that a DKIM pass must be read together with its `d=` domain. Also mention the Microsoft `compauth` result, which M365 analysts read first.

**A9. Log vendors and field names are not native (breaks the platform's own native-schema rule).**
- la1 (`:137-141`): vendor `"Microsoft 365 Unified Audit Log"` with `Operation: "MessageReceived"`, `ClientIP` set to the sending relay, and `SourceFileName` used for an email attachment. The Unified Audit Log does not record inbound message delivery with headers. ClientIP there is the IP of the user or client performing an action. SourceFileName is a SharePoint/OneDrive field. The hostname `mailgw-01.contoso.com` (an on-prem gateway) also conflicts with an M365 cloud source.
- ac1 (`:216`, `:225`): vendor `"Microsoft Defender for Office 365"` with `data.office365.Operation: "EmailReceived"` and `AuthenticationResults.*`.

**Fix:** model la1 on the Defender XDR `EmailEvents` + `EmailAttachmentInfo` + `EmailUrlInfo` tables. EmailEvents has `NetworkMessageId`, `InternetMessageId`, `SenderFromAddress`, `SenderMailFromAddress` (the Return-Path), `SenderIPv4` (the last relay that connected to Exchange Online), `RecipientEmailAddress`, `Subject`, `AuthenticationDetails` (SPF/DKIM/DMARC/CompAuth), `DeliveryAction`, `DeliveryLocation` and `ThreatTypes` ([EmailEvents reference](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-emailevents-table)). **Check** exact column names with `EmailEvents | getschema`. Show the Received chain and Reply-To as a separate "raw message headers" artifact, which is how analysts really get them (Explorer > email entity > download / Message header analyzer).

**A10. la1 `rule.description` hands over the analysis.** `:169-171` `rule.name: "BEC_Attachment_Phishing_High_Confidence"`, `rule.description: "...failed all authentication checks and has Reply-To mismatch"`.
The rule text states the verdict and names the Reply-To mismatch that la1 Q2 and the flag test, which breaks the platform's "no hints in raw logs" rule. **Fix:** a neutral rule such as `rule.name: "Inbound_External_MacroAttachment"`, `rule.description: "Inbound external mail with macro-enabled Office attachment"`.

**A11. Delivered mail that failed DMARC with p=reject.** la1 `:159-160` (`dmarc: "fail"`, `dmarc_policy: "reject"`, yet delivered to alice.chen) and q1 (paypal.com publishes p=reject).
Since August 2023 Exchange Online honours sender DMARC policy by default. Admins can choose reject, quarantine or junk ([Practical365](https://practical365.com/dmarc-policy-change-august-2023/)). **Check** the default action for p=reject in current anti-phishing policies. A real analyst would ask "why was this delivered?" **Fix:** either set `dmarc_policy: "none"` for globalpartners.com, which also teaches that a partner without an enforcing DMARC policy is spoofable, or keep reject and add `DeliveryAction: "Delivered"` with an override reason (for example a transport rule allow-listing the partner). That is a realistic and teachable misconfiguration.

**A12. Containment after a click omits credential handling; "isolate first" is wrong for a credential link.** r3 `:66` ("If any user clicked: isolate their workstation, check EDR") and lab `phishingAnalysis.ts:252` ("Isolate the clicker's workstation... Contain first, then confirm").
For a credential-harvesting link the key question is whether credentials (or an MFA approval) were submitted. Check proxy logs for a POST to the domain, and Entra sign-in logs for a sign-in from a new IP or ASN soon after the click. If yes: reset the password, **revoke sessions and refresh tokens** (needed against AiTM), review newly registered MFA methods, mailbox inbox and forwarding rules (T1564.008), and OAuth consent grants. Isolation fits when a file was downloaded or executed. CISA phishing guidance and Microsoft's [phishing investigation playbook](https://learn.microsoft.com/en-us/security/operations/incident-response-playbook-phishing) both centre on credential and session actions.
**Fix:** split the lab item into "Clicked + downloaded file → isolate + EDR" and "Clicked + entered password → reset, revoke sessions, check MFA and inbox rules", and add the same to the r3 text.

**A13. Message-ID treated as a reliable sender indicator.** `:24` ("tells you the true sending platform"; Step 5 "does it match the From domain?") and lab `:89-90`.
Message-ID is generated by the originating client or MSA and is fully sender-controlled (RFC 5322 section 3.6.4). Like Return-Path, an ESP Message-ID is normal for legitimate bulk mail. The reading applies the "weak on its own" caveat to Return-Path but not to Message-ID. **Fix:** add the same caveat.

**A14. Phishing-kit sentence is self-contradictory.** `:45` "which IP addresses are whitelisted (attackers block known security company IPs...)". Kits carry **blocklists** (often `.htaccess` or PHP lists of security-vendor IPs, crawler user agents and ASNs). **Fix:** "which IP addresses and user agents are blocked (kits hide the page from known security-vendor and crawler IPs)".

**A15. Public sandbox submission risks.** r3 Step 4/5 (`:66`) recommends URLScan.io and VirusTotal without warning that public scans and uploads are visible to others. A URL with a victim token (like ac1's `verify?token=xK9pQ3mR7nT2`) or an internal document can leak data and tip off the attacker. **Fix:** "Search by hash first; submit URLs as private or unlisted scans; never upload documents that may contain company data to a public service."

**A16. Real third-party IP used as fake infrastructure.** `185.220.101.47` (la1 `:141,151,168`; ac1 `:236`) sits in 185.220.101.0/24, a widely known Tor exit relay range. Tor exits generally do not relay SMTP, and the same IP appears in two unrelated campaigns without comment. The labs correctly use RFC 5737 ranges (`phishingAnalysis.ts:7-8`). **Fix:** use 198.51.100.x or 203.0.113.x in graded tasks too. If the reuse across la1 and ac1 is intentional, make it a pivot question ("the same IP appears in the earlier case: what does that tell you?").

### Low

**A17. Broken punctuation from em-dash removal.** `:45` "(real executives rarely demand secret urgent wire transfers\n- **Reply-to mismatch**) the From field..."; `:66` "**URLScan.io** (takes a screenshot ... without you visiting it\n- **VirusTotal**) checks..." and "**Benign** (legitimate email, no action needed\n- **Spam**) bulk marketing"; `:24` "**Return-Path:**, The envelope sender", "**Reply-To:**, Where", "**SPF (Sender Policy Framework)**, The domain owner"; `:45` "Ceo@company-corp.com". **Fix:** use a colon after each bold label and close the parentheses on the same bullet.

**A18. "The actual domain (the part before the last dot before the TLD)"** (`:45`). This is confusing and wrong for multi-label public suffixes (`attacker.co.uk`). **Fix:** "the registrable domain: the label just left of the public suffix (.com, .co.uk), plus that suffix".

**A19. ISO/MOTW "on Windows 10 before a recent patch"** (`:45`). The fix shipped in the November 2022 updates (CVE-2022-41091, exploited in the wild, CISA KEV) and applied to Windows 11 as well ([BleepingComputer](https://www.bleepingcomputer.com/news/microsoft/microsoft-fixes-motw-zero-day-used-to-drop-malware-via-iso-files/), [Help Net Security](https://www.helpnetsecurity.com/2022/11/08/cve-2022-41091-november-2022-patch-tuesday/)). **Fix:** "Before the November 2022 Windows updates (CVE-2022-41091), files inside a mounted ISO did not inherit Mark of the Web." Attackers have since moved to other containers and to LNK/HTML.

**A20. ac1 MITRE mapping (check).** `:222` `T1566.001` (Spearphishing Attachment). The PDF is clean and the attack is a credential-harvest link. ATT&CK lists "PDF attachments containing links to credential-harvesting sites" (Dragonfly) under **T1598.003 Phishing for Information: Spearphishing Link** ([MITRE](https://attack.mitre.org/techniques/T1598/003/)). Either is defensible, but the room never teaches either mapping. Pick one and explain it in the ac1 explanation.

**A21. Small realism details.** Sendinblue rebranded as Brevo in 2023. Cuckoo Sandbox (`:66`) is unmaintained (CAPE is the maintained fork). "The password is always in the email" (`:45`) is overstated: sometimes it is in a second email or inside an image. Searching by Message-ID (`:66`) finds copies of one message, but campaigns usually have a unique Message-ID per recipient, so sender, subject, URL and attachment hash are better pivots. In la1 the X-Originating-IP (`:168`) equals the relay IP. It should be the webmail client IP, not the ESP relay.

**A22. r1 checkpoint explanation.** `:35` "'Your own gateway writes it' is wrong". Strictly, the final delivery MTA on the receiving side inserts the Return-Path header (RFC 5321 section 4.4); its *value* comes from the sender's MAIL FROM. The option is still wrong because it says "shows nothing about the sender". **Fix:** "Your side writes the header, but the address in it is the sender's MAIL FROM, so it does reflect the sending side."

## 3. Pedagogy findings

**P1. Difficulty curve peaks in the middle and drops at the boss.**

| Station | What the learner does | Cognitive level | Penalty | Real difficulty |
|---|---|---|---|---|
| 1 Archive | 3 readings, 10 labs, 2 checkpoints | Understand | None; checkpoint unlimited retries | Easy (correct for teaching) |
| 2 Sorting Plant | 3 MCQs | Recall | Shield per miss, 2 tries | Easy: q2 and q3 have one nuanced option and three obvious wrong ones |
| 3 Evidence Lab | 2 MCQs on a raw log | Apply | Shield per miss, single try | Medium: the hardest station |
| 4 Triage Office | 1 verdict | Apply/Evaluate | Shield per miss + 120 s clock | Easy-medium: the r1 "look-alike" lab is the same pattern |
| 5 Vault (boss) | Type one domain | Recall | Shield per wrong code | Easiest: the `email.reply_to` field is shown in the vault's evidence panel (`VaultKeypad.tsx:50-64`) and the question is the fourth Reply-To check |

A boss should require synthesis: several fields combined into one decision, or a value that has to be derived. See R4.

**P2. One concept is over-assessed and others are never assessed.** Reply-To is tested in the r1 checkpoint (`:26`), q3 (`:110`), la1 Q2 option D (`:196`) and the flag (`:259`). "Return-Path is weak alone" is tested in the r1 checkpoint and again in la1 Q2. Taught but never assessed: homographs/punycode (only the ungraded r2 checkpoint), subdomain tricks, URL shorteners, password ZIPs, ISO, the tool-selection lab, verdict categories, campaign scoping, the post-click response. r3, the workflow reading, has no checkpoint and no graded task covers its steps 3 to 7.

**P3. Assessed but not taught.**
- ac1's explanation rests on "registered just 3 days ago... Brand-new domains are a strong phishing indicator" (`:249`) and `email.url_category: "Uncategorized"` (`:243`). Neither domain age nor URL categorisation appears in r1 to r3. Add two sentences to r2 (newly registered domains, WHOIS creation date, proxy categories) and one lab item.
- ac1 offers four verdicts (true positive, false positive, escalate, informational; `TriageDesk.tsx:13-18`), but the room never says when to escalate rather than close as a true positive. r3's verdicts are benign / spam / phishing / BEC, a different taxonomy. Align them: say in r3 that "phishing (contained by SOC)" maps to True positive and "BEC / clicked + credentials" maps to Escalate.

**P4. Recall questions where transfer questions would fit.** q3 restates the r1 Reply-To paragraph almost word for word. q1 is the "spoof" scenario from the r1 simulate lab. Make station 2 questions require applying the idea to a new artifact: for example, show three Authentication-Results lines (pass/pass/fail with `header.d=` differing from `header.from`; softfail; none) and ask which one proves spoofing of the exact domain.

**P5. Sequence lab forces one order where the real order is flexible.** `phishingAnalysis.ts:197-209` requires IP, then URL, then attachment, then decide, then contain. Steps 3 to 5 have no fixed order. Containment, especially purge, usually starts as soon as one indicator is confirmed malicious, in parallel with deeper analysis. The lab also has no "scope: who else received it" step. The penalty is only a nudge, but it teaches a rigid waterfall. **Fix:** make steps 3 to 5 one "Gather evidence (any order)" group, add "Scope the campaign", and put "Contain" before the final verdict write-up.

**P6. Checkpoint and labs can be brute-forced.** Reading checkpoints allow unlimited retries with no cost (`IntelBriefing.tsx:44-61`), and sort/match labs accept unlimited guesses. That is acceptable for teaching, but since Intel tokens are earned per reading regardless of how many guesses it took, tokens reward completion rather than understanding. Consider awarding the token only when the checkpoint is right on the first try, or a half token otherwise.

**P7. Replay after a reveal restores full credit.** When a learner misses a question twice, the answer is revealed (`grading.ts:81-87`). A breach restarts the station (`OperationView.tsx:182-191`), and replaying a cleared station reopens its tasks (`:158`). `RoomClient.tsx:344-351` keeps the best-of XP and credit, so the learner can re-answer the revealed question for full XP and full pass credit. The 65% mastery gate can therefore be passed by failing, reading the reveal and replaying. This is a platform-wide design choice ("Revisit missed" behaves the same way), but Operation Mode makes it a one-click loop. **Fix:** on a replay of a task whose answer was revealed, award stars but cap XP and pass credit at the half-credit level, or serve a variant item.

## 4. Gamification and realism findings

**G1. Penalties that punish careful reading.**
- **Triage clock** (`TriageDesk.tsx:11, 36-44`): 120 s starts on mount and covers reading the persona line, the scenario, and an evidence panel of about 25 raw fields (`:97-109`). A careful novice who checks every field and cross-references the readings can easily exceed 120 s and lose a shield for thoroughness, before answering anything. With overtime plus two wrong tries the station breaches, even though the clock never auto-submits. **Fix:** start the clock on the learner's first verdict-button hover or after an "I've read the ticket" click; or scale it to field count (for example 60 s + 6 s per field); or make overtime cost a star rather than a shield; and pause while the tab is hidden.
- **Vault format errors** (`VaultKeypad.tsx:34`; `grading.ts:111-113`): every wrong code costs a shield. "@gmail-secure-mail.com", the full address "robert.harrington.cfo@gmail-secure-mail.com", or a trailing dot all fail, although each shows the right finding. **Fix:** add `FLAG_ALIASES["phishing-analysis:phishing-flag1"]` that strips a leading "@", a user part and a trailing dot, or normalise in the grader; and do not charge a shield for a "format" miss (answer contains the right domain).
- **Sorting Plant breach maths:** three shields across three two-try questions means one question missed twice plus one first-try slip breaches the station and replays all three questions, including the ones answered right. **Fix:** restart from the failed task, or give 4 shields for 3-question stations.

**G2. The stations are task types, not investigation steps.** Archive, Sorting Plant, Evidence Lab, Triage Office and Vault correspond to reading, question, log_analysis, analyst_choice and flag. The two cases (la1, the Harrington CFO wire email; ac1, the R. Thomas Microsoft notice) are unrelated, and the narrative ("Every station you clear brings us closer to the sender", `phishingAnalysis.ts:18`) is never paid off: no station gets closer to the sender. The flag prompt even breaks the fiction: "(the Urgent_Wire_Request_Q2.xlsm event, not the later verdict scenario)" (`:259`).

**G3. Comparison with a real reported-phish triage.**

| Real step | In the room? | Gap |
|---|---|---|
| 1. User report arrives (Report button / phish mailbox), ticket opened | Partly: persona line in ac1 only | The la1 case has no reporter; no ticket, no SLA |
| 2. Header and authentication analysis | Yes (r1, q1, q3, la1) | Good, after fixing A1 to A3 |
| 3. URL / attachment reputation and detonation | Taught (r2, r3), assessed only as given values (`vt_detections`, `url_category`) | The learner never chooses a tool or reads a sandbox result |
| 4. Scope: message trace, who else received it, who clicked | Taught in one r3 bullet and one lab item | Never practised |
| 5. Containment: purge, block sender/domain/URL, reset and revoke if clicked | Taught in r3 and the "Someone clicked" lab | Never decided or scored |
| 6. Clicked-user follow-up: sign-in logs, MFA, inbox rules | Missing | Missing |
| 7. Verdict, ticket notes, feedback to reporter, BEC finance actions | Verdict only (ac1) | No notes, no user reply, no wire-recall step |

**G4. Suggested new mission steps.** Each uses data the room already has or a small addition, and each fits the existing mechanics or one new one.

1. **"The Reporter" (new opening station, Triage Desk variant).** Alice Chen reports the Harrington email through the Report button: "This looks like Robert, but he never asks me for wires. I opened the spreadsheet, nothing happened." The learner sees the user-reported message entry. They decide (a) the priority and (b) the first question to ask Alice, choosing from: "Did you click Enable Content or type a password?", "Forward it to me as an attachment", "Delete it", "Reply to Robert to check". Scoring: the right first question gets full points; "reply to Robert" (the attacker's Reply-To) costs a shield and the explanation links back to Reply-To. This gives the flag concept a real-world consequence instead of a fourth recall test.
2. **"Message Trace" (new station, Evidence Board with a results table).** Show a 10-row message-trace or `EmailEvents` result for sender domain gmail-secure-mail.com / sendinblue-relay247.net / attachment SHA256: 6 recipients, 4 delivered to inbox, 1 junk, 1 quarantined; then an `UrlClickEvents` / proxy row showing one user clicked. Questions: "How many mailboxes still hold the message?", "Which pivot found the recipient the subject search missed (the subject was varied)?", "Who needs follow-up?" One pivot can be a typed value scored like the flag: the SHA256 prefix or the count.
3. **"Containment Board" (new mechanic: action board).** The learner gets about 10 action cards and a budget of moves: "Soft-delete from all mailboxes (Explorer > Take action)", "Block sender domain in Tenant Allow/Block List", "Block sendinblue-relay247.net IP" (trap: shared ESP infrastructure), "Block URL at proxy", "Reset Alice's password", "Revoke Alice's sessions", "Isolate Alice's laptop", "Email all staff with the link", "Call the real Robert Harrington on a known number", "Notify finance to hold any wire to the new account". Scoring: required actions (purge, block, out-of-band verify, finance hold) score points; harmful ones (email the link to all staff, block the shared ESP IP) cost a shield; unnecessary but harmless ones (isolating when nothing executed) cost a star, not a shield. The learner learns proportional response. Order matters lightly: purge before user notification earns a bonus.
4. **"Did it run?" (Evidence Board on EDR).** Using the existing EDR console style: Alice's process tree after opening the .xlsm. Variant A shows EXCEL.EXE spawning nothing (MOTW block worked: red banner). Variant B shows EXCEL.EXE spawning powershell.exe with `-enc`. The learner decides: close the endpoint branch, or isolate and escalate. This is q2 played on real evidence instead of described.
5. **"The Clicker" (for ac1, Triage Desk plus sign-in log).** After the true-positive verdict, R. Thomas admits he clicked the link and "signed in, then it said session expired". Show the Entra sign-in log: his normal sign-in, then a successful sign-in 4 minutes later from a hosting-provider ASN with the same session or a new device. The learner chooses: reset only / reset + revoke sessions / reset + revoke + check MFA methods and inbox rules. Only the last is correct. This teaches AiTM (A6, A12).
6. **"Close the ticket" (new boss: case-note builder, replaces or follows the vault).** The learner assembles the ticket from pinned Evidence Board items, the existing case board pins (`EvidenceBoard.tsx:95-125`, currently ungraded), plus a verdict, scope count and actions taken, and picks the reporter-feedback message. Score with the existing `written_report` grader (`grading.ts:202-270`, IOC citation + fabrication check): it must cite the Reply-To domain, the origin IP, the attachment SHA256 and the number of recipients. This is a true synthesis boss and uses the case board, which today does nothing.

**G5. Small immersion fixes.**
- Have the briefing promise something the mission delivers: "Every station you clear brings us closer to the sender" should become "...closer to closing this campaign". Better, add a final reveal that ties la1 and ac1 to the same actor through the shared IP (A16).
- Remove the meta-text from the flag prompt (`:259`). Phrase it in-world: "Alice is about to hit Reply. Where would her answer land?"
- The ac1 persona says "Do I need to do anything?" but the scenario text is a SIEM alert. Pick one framing; the user-report framing is more realistic and sets up mission step 5.
- Star rating is purely shields left. Consider one star for "used no hint" or "under the clock" so the clock rewards speed instead of only punishing slowness.

## 5. Prioritised recommendations

| # | Change | Type | Effort |
|---|---|---|---|
| 1 | Fix la1 SPF/DMARC values so SPF is evaluated for the Return-Path domain and DMARC fails on alignment; reword la1 Q2 option C and explanation (A1) | content fix | S |
| 2 | Fix the r1 inspect-lab Authentication-Results to `spf=pass smtp.mailfrom=em.bulkmailer.example ... dmarc=fail header.from=northwind-bank.com` (A2) | content fix | S |
| 3 | Fix r3 Step 3 "bottom Received header" to "the hop your boundary server recorded" (A3) | content fix | S |
| 4 | Replace "A phishing email will almost always fail at least one of these tests" (A4); soften the DMARC-fail and DKIM-fail statements (A7, A8) | content fix | S |
| 5 | Neutralise la1 `rule.name` / `rule.description` (A10); move la1 and ac1 to native Defender `EmailEvents` fields plus a separate raw-header artifact (A9); replace the Tor-range IP (A16); resolve delivered-despite-p=reject (A11) | content fix | M |
| 6 | Add the MOTW macro block, QR phishing, AiTM, HTML smuggling, SaaS abuse and ClickFix to r2; update q2's premise (A5, A6) | content fix | M |
| 7 | Rewrite post-click containment: credentials entered means reset + revoke sessions + MFA/inbox-rule review; isolate only on execution (A12); add the public-sandbox warning (A15) | content fix | S |
| 8 | Triage clock: start after "ticket read" and scale with field count, overtime costs a star not a shield; vault: accept "@domain", full address and trailing dot without a shield penalty (G1) | mechanic change | S |
| 9 | Teach domain age and URL category before ac1 asks about them; align the r3 verdict taxonomy with the four Triage Desk verdicts (P3) | content fix | S |
| 10 | Add "Message Trace" scoping station (G4.2) | new mission step | M |
| 11 | Add "Containment Board" action-card mechanic with required / harmful / unnecessary scoring (G4.3) | mechanic change + new mission step | L |
| 12 | Replace the boss vault with "Close the ticket", built from case-board pins and graded by the `written_report` grader (G4.6), or make the flag a derived value (for example the recipient count from the trace) | new mission step | M |
| 13 | Add "The Clicker" sign-in-log follow-up to ac1 (G4.5) and "Did it run?" EDR process tree after q2 (G4.4) | new mission step | M |
| 14 | Add "The Reporter" opening step that ties Reply-To to a real consequence and drops one of the four Reply-To checks (G4.1, P2) | new mission step | M |
| 15 | Cap XP and pass credit on replays of a revealed task, or serve a variant (P7); award the Intel token for a first-try checkpoint (P6) | mechanic change | M |
| 16 | Relax the r3 sequence lab: evidence steps in any order, add "Scope", containment can precede the write-up (P5) | content fix | S |
| 17 | Clean up punctuation artifacts, the registrable-domain definition, the ISO patch date, the phishing-kit blocklist wording, the Message-ID caveat, the ac1 MITRE mapping and the r1 checkpoint wording (A13, A14, A17 to A22) | content fix | S |

## Sources

- RFC 5321 (SMTP, section 4.4 trace and Return-Path), RFC 5322 (section 3.6.4 Message-ID), RFC 7208 (SPF, sections 1.1 and 2.4), RFC 6376 (DKIM), RFC 7489 (DMARC, section 3.1 alignment), RFC 8601 (Authentication-Results), RFC 8617 (ARC), RFC 5737 (documentation IP ranges)
- MITRE ATT&CK T1566 / T1566.001 / T1566.002, [T1598.003 Spearphishing Link](https://attack.mitre.org/techniques/T1598/003/), T1564.008, T1027.006
- Microsoft: VBA macros blocked by default in files from the internet (Feb 2022), summarised by [Netskope](https://www.netskope.com/blog/microsoft-office-vba-blocked-by-default-in-files-from-the-internet) and [TechTarget](https://www.techtarget.com/searchsecurity/news/252513141/Microsoft-disables-VBA-macros-by-default)
- CVE-2022-41091 ISO MOTW fix: [BleepingComputer](https://www.bleepingcomputer.com/news/microsoft/microsoft-fixes-motw-zero-day-used-to-drop-malware-via-iso-files/), [Help Net Security](https://www.helpnetsecurity.com/2022/11/08/cve-2022-41091-november-2022-patch-tuesday/)
- Exchange Online honours DMARC policy from August 2023: [Practical365](https://practical365.com/dmarc-policy-change-august-2023/)
- Defender XDR [EmailEvents table](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-emailevents-table); Microsoft [phishing investigation playbook](https://learn.microsoft.com/en-us/security/operations/incident-response-playbook-phishing)
