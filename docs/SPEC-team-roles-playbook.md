# אפיון — Team-SOC · ספר-תפקידים (Per-Role Playbook)

> **מטרה במשפט:** לכל אחד משבעת התפקידים בחדר-האירוע — מה רואים על המסך, איך חוקרים, למי מדווחים, ואיך נמדדת ההצלחה — ברמת-פירוט שממנה מפתח בונה מסכים.
> **תאריך:** 2026-09-14
> **סטטוס:** אפיון בלבד — אין שינויי-קוד.
> **ממקד ומרחיב את** §3 (תפקידים), §6 (ניקוד) ו-§13 (דרישות טל) של `SPEC-team-soc-multiplayer.md`. מסמך זה **צולל פנימה** — הוא לא מחליף ולא סותר את המאסטר; היכן שהמאסטר מגדיר role-ID, event-type, שדה או רובריקה — משתמשים בו verbatim.
> **מקורות-הצלבה:** `SPEC-team-soc-multiplayer.md` · `SPEC-edr-console.md` · `nice-framework-mapping.md` · הקוד החי: `src/app/(app)/team/[id]/page.tsx` (לובי + קונסולות-תפקיד כפי שנבנו), `src/app/(app)/dashboard/EventFeed.tsx` + `IncidentReportModal.tsx` (תחושת-היחיד).

---

## 0. איך לקרוא את המסמך הזה

### 0.1 מוסכמות

- **עברית להסבר; אנגלית/verbatim** לכל מונח-טכני, role-ID, event-type, שם-שדה ומזהה-קוד.
- **מה שכבר קיים** מסומן `✅ built` (רץ ב-`team/[id]/page.tsx` היום), **מה שהמאסטר מגדיר אך טרם נבנה** מסומן `🔜 spec`, ו**מה שהוא שלב-עתידי** מסומן `⏳ later phase`. אין להציג פיצ'ר עתידי כאילו קיים.
- כל **מסך** מתואר גם ב-ASCII wireframe בסגנון §7.2 של המאסטר, אבל ספציפי-לתפקיד.
- כל **פעולה** נלכדת כ-event ב-`session_events` דרך `apply_session_action(session_id, expected_seq, idempotency_key, action)` (המאסטר §8.2). זו האמת היחידה שממנה נגזרים מצב-חי, ניקוד ו-AAR.

### 0.2 מזהי-התפקידים (verbatim מ-`ROLE_LABEL` בקוד + §13.4)

| role-ID | תווית (`ROLE_LABEL`) | נבנה? |
|---|---|---|
| `t1` | Tier-1 Triage | ✅ קונסולה חיה (`T1Console`) |
| `t2` | Tier-2 Investigator | ✅ קונסולה חיה (`T2Console`) |
| `t3` | Tier-3 / Threat Hunter | ✅ משתמש כרגע ב-`T2Console` (משותף עם T2); קונסולת-hunt ייעודית `🔜 spec` |
| `lead` | Incident Lead | ✅ קונסולה חיה (`LeadConsole`) |
| `de` | Detection Engineer | 🔜 spec (אין קונסולה בקוד עדיין) |
| `ti` | Threat Intel | 🔜 spec |
| `mgr` | SOC Manager | 🔜 spec |

> בקוד היום `me.role === "t2" || me.role === "t3"` מרנדרים **אותה** `T2Console`. במסמך זה אני מפריד ביניהם לוגית (T2 = חקירת-הסלמה + EDR; T3 = ציד-עומק + scope סופי) ומסמן את פיצול-הקונסולה כ-`🔜 spec`.

### 0.3 מילון ה-event-types שהתפקידים פולטים (מ-§8.4 + הקוד)

`feed.event` · `event.opened {event_id, dwell_ms}` · `disposition.set {event_id, verdict}` · `escalation.requested/acknowledged/accepted/bounced/resolved` · `containment.requested/approved/denied/executed` · `case.created/updated/status_changed` · `evidence.pinned` · `note.added` · `decision.logged` · `sitrep.sent` · `intel.published` · `rule.published/tuned` · `message.sent` · `ticket.answered` · `hint.used` · `report.submitted/graded` · `passdown.signed` · `grade.assigned/overridden`.
**חדשים שמסמך זה מציע** (מסומנים 🔜): `scope.set/scope.confirmed` · `hunt.started/hunt.finding` · `filter.applied` · `pivot.used` · `edr.opened`.

### 0.4 שלד-המסך המשותף (מסגרת שכל תפקיד יושב בתוכה)

זהו §7.2 של המאסטר, כפי שהקוד ממש אותו ב-phase RUNNING: פיד משותף בשמאל (`SharedFeed` — "Live SIEM feed"), פאנל-תפקיד + `ActivityLog` בימין, שורת-סטטוס עליונה (`online · logs · you: <role>`).

```
┌───────────────────────────────────────────────────────────────────────────┐
│ Live team exercise · NexaCorp · easy      ● Radio  N online · K logs · you: <role> │
├──────────────────────────────────────────┬────────────────────────────────┤
│ LEFT  (grid 1fr)                          │ RIGHT (grid 360px)             │
│ ┌──────────────────────────────────────┐ │ ┌────────────────────────────┐ │
│ │ Live SIEM feed        (SharedFeed)    │ │ │ <ROLE CONSOLE>             │ │
│ │  ▸ ● [Vendor] description  host  [sev] │ │ │  role-gated panel         │ │
│ │  ▾ ● [Vendor] description  host  [TP]  │ │ ├────────────────────────────┤ │
│ │     source/type/MITRE + raw <pre>      │ │ │ Team activity (ActivityLog)│ │
│ └──────────────────────────────────────┘ │ └────────────────────────────┘ │
└──────────────────────────────────────────┴────────────────────────────────┘
```

> כל תפקיד למטה מחליף את `<ROLE CONSOLE>` בפאנל שלו. הפיד עצמו זהה לכולם — ההבדל הוא בפאנל-התפקיד ובפעולות מוגבלות-התפקיד (§3.7 של המאסטר).

---

## 1. Tier-1 Triage Analyst (`t1`)

### 1.1 מה רואים על המסך

הפאנל הימני = `T1Console` (`✅ built`) מעל `ActivityLog`. הפיד המשותף בשמאל.

```
RIGHT PANEL — Tier-1 triage
┌────────────────────────────────────────────┐
│ 🛡 Tier-1 triage                            │
│ Pick a log ▼  [ #142 Encoded PowerShell … ] │  ← <select> מכל feed.event
│ [ true positive ] [ false positive ] [ benign ]  ← disposition.set
│ ───────────────────────────────────────────│
│ ESCALATE TO TIER-2                          │
│ What did you see? (one line) ______________ │  ← form.what   (חובה)
│ Why suspicious? name indicator/technique    │  ← form.why    (≥10 תווים בקוד;
│  ________________________________________   │     §5.2 דורש ≥20 מילים 🔜)
│ [ impact: host ▼ ]   [ conf: med ▼ ]        │  ← impact enum · confidence
│ [ ↗ Escalate ]                              │  ← escalation.requested
└────────────────────────────────────────────┘
```

- **role-gated:** T1 **לא** רואה כפתורי isolate/kill/block/approve. יש לו רק disposition + escalate + (🔜) מענה ל-help-desk ticket. תואם למטריצת §3.7.
- **shared:** הפיד, ה-`ActivityLog`, ומצב-התיק (`🔜 spec` — פאנל Shared Case מ-§5.1 עדיין לא בקוד).
- **מה חסר מול המאסטר (`🔜`):** תור-triage ממוין לפי `ruleLevel`/SLA (היום זה `<select>` שטוח), ערוץ help-desk (`ticket.answered`), טיימר-SLA לאירועי high/critical בשורת-הסטטוס התחתונה (§7.2 bottom bar). ה-`SharedFeed` כבר נותן sev-dot ותג-vendor, אז התור קיים חלקית.

### 1.2 איך מבצעים חקירה — דוגמה: PuTTY-trojan chain

התרחיש (מעוגן ב-injects של המאסטר — Kerberoasting #8, exfil ל-mega.nz #14): מייל-פישינג → המשתמש מריץ `putty.exe` טרוג'ני מ-`C:\Users\jdoe\Downloads` (לא-חתום, path אנומלי) → beacon ל-C2 → PowerShell encoded → Kerberoasting → exfil.

זרימת-T1 טובה, צעד-אחר-צעד על ה-UI הקיים:
1. אירוע high נכנס לפיד — `▸ ● [EDR] putty.exe spawned by WINWORD.EXE  FIN-WS-07  [high]`. T1 לוחץ על השורה → זה פולט `event.opened {event_id}` (הקוד עושה זאת ב-`onOpen`).
2. קורא את ה-raw block (`<pre>`): `process.parent_name=WINWORD.EXE`, `process.path=…\Downloads\putty.exe`, `signed=false`, `process.cmdline` עם `-enc`. שלושת ה-red-flags: parent אנומלי, path אנומלי, לא-חתום (בדיוק ה"methodology" של §SocMethodologyBanner: Source→Actors→Behavior→Pattern→Classify).
3. פותח את `mitre_technique` בפיד → קורא "What to look for". מסמן disposition = **true_positive** (`disposition.set`).
4. ממלא את טופס-ההסלמה: `what` = "Trojanized PuTTY on FIN-WS-07, parent WINWORD, unsigned, encoded PowerShell"; `why` = מזכיר את **המנגנון** (parent=WINWORD, path=Downloads, `-enc`, unsigned) — לא "נראה חשוד"; `impact` = host; `confidence` = high. לוחץ **Escalate** → `escalation.requested`.
5. **מצוין:** T1 גם סוגר את ה-FP-decoys סביבו עם נימוק (למשל PsExec לגיטימי של IT — מזוהה דרך ה-IT-verify widget מ-`DetailPanel`), ולא מסלים "ליתר-ביטחון".

- **חקירה חלשה:** מסלים בלי לפתוח את ה-raw (dwell נמוך, `why` ריק/"looks suspicious"); או closure-rate 95%+ (מסלים-חסר); או מתעלם מה-help-desk ticket.
- **כלים בהישג-יד:** הפיד + raw + MITRE slideout + (בקונסולת-היחיד) ThreatIntelDrawer ל-hash/ip/domain. T1 **לא** נכנס ל-EDR (`/edr`) — זו קרקע של T2/T3.

### 1.3 למי מדווחים / מוסרים

- **out:** `escalation.requested {event_id, what, why, impact, confidence, requested_action:"investigate"}` → יעד **T2** (בצוות-6 יכול להיות T2 ספציפי; בצוות-3 → T2/T3).
- **in:** `escalation.acknowledged` חוזר מ-T2 → T1 יודע שמישהו תפס (היום ה-`ActivityLog` מציג "acknowledged an escalation"). בשלב מאוחר, פידבק `escalation.resolved {outcome}` סוגר את הלולאה ("ההסלמה הזו הייתה נכונה כי…").
- **הסלמה שלמה מכילה:** raw+enrichment+נימוק-מנגנון+impact+confidence (נספח א׳ של המאסטר). ה-UI כבר אוכף את שדות-החובה (כפתור Escalate disabled עד ש-`what` מלא ו-`why≥10`).
- **"waiting for you":** T1 → תור-ה-Escalations של T2 (`T2Console` header "Escalations for you (N)"). זה ה-UI שמייצר את התלות-ההדדית.
- הזרימה המלאה מצוירת פעם-אחת ב-§8.1.

### 1.4 איך נמדדת הצלחה — כרטיס T1 (סולם 0/4/8/12)

מרחיב את נספח ד׳ של המאסטר; כל קריטריון קשור ל-event שממנו הוא נגזר.

| # | קריטריון | 12 | 8 | 4 | 0 | נגזר מ-event |
|---|---|---|---|---|---|---|
| 1 | דיוק-disposition | ≥90% מול ground-truth | 75–89% | 50–74% | <50% | `disposition.set.verdict` vs answer-key |
| 2 | דיוק-הסלמה | ≥80% אושרו + 0 אבודות | 60–79% | 40–59% או הסלמה-אבודה | <40% | `escalation.requested` → `.accepted`/`.bounced` |
| 3 | שלמות-כרטיס | כל שדות-חובה + ≥2 ראיות + מנגנון ב-`why` | חסר שדה אחד | רק "נראה חשוד" | ריק | payload של `escalation.requested` |
| 4 | time-to-triage (high/crit) | ≤5′ | ≤10′ | ≤15′ | >15′ | Δ(`feed.event`→`event.opened`/`disposition.set`) |
| 5 | help-desk tickets בזמן (🔜) | כולם בזמן + vishing נדחה | איחור אחד | אישר vishing | התעלם | `ticket.answered` |

- **מצוין:** "escalate signals, not doubts" — כרטיס עם raw+enrichment+מנגנון+confidence מכויל; סוגר FP עם הסבר; לא מסלים מפחד.
- **חלש:** closure 95%+ (מסלים-חסר) או הסלמה >30% (מפחד); כרטיסים ריקים; מתעלם מפניות-משתמשים; שוכח ראיות.
- **NICE:** PR-CDA-001 Cyber Defense Analyst (T0020, T0023, T0155, T0164).

---

## 2. Tier-2 Investigator (`t2`)

### 2.1 מה רואים על המסך

הפאנל הימני = `T2Console` (`✅ built`): תור-הסלמות-נכנסות עם ack → request-containment.

```
RIGHT PANEL — Tier-2 investigator
┌────────────────────────────────────────────┐
│ 🚨 Escalations for you (3)                   │
│ ┌────────────────────────────────────────┐  │
│ │ Trojanized PuTTY on FIN-WS-07…          │  │  ← what
│ │ parent WINWORD, unsigned, encoded PS    │  │  ← why
│ │ from Dana · impact host · conf 0.9      │  │  ← actor · impact · confidence
│ │ [ ✓ Acknowledge ]                       │  │  ← escalation.acknowledged
│ │ (after ack) [ 🛡 Request containment ]  │  │  ← containment.requested
│ └────────────────────────────────────────┘  │
└────────────────────────────────────────────┘
   + (🔜 spec) EDR launcher · timeline builder · case status · report
```

- **role-gated:** T2 **כן** יכול `containment.requested` (מבקש, לא מבצע — האישור של Lead), ואחרי אישור — isolate/kill ב-EDR. לא מאשר containment בעצמו, לא כותב detection-rule.
- **מה קיים היום:** ack + request-containment. **מה חסר (`🔜 spec` מ-§3.2):** כפתור "Investigate in EDR" (פותח `/edr` על ה-host, טעון עם עץ-התהליכים של התקיפה — `SPEC-edr-console.md §3`), בונה-ציר-זמן (drag events → timeline), חיפוש/pivot בפיד (`eventSearch` predicates), עדכון סטטוס-תיק (`case.status_changed`), וכותב-דוח (ה-grader הקיים `/api/dashboard/incident-report`).

### 2.2 איך מבצעים חקירה — המשך ה-PuTTY-trojan

1. הסלמה נכנסת → T2 לוחץ **Acknowledge** תוך דקות (`escalation.acknowledged`; ה-SLA-clock של 5′ מ-§5.2 מתחיל ברגע `escalation.requested`).
2. **Investigate in EDR** (`🔜`) → `/edr` נפתח על FIN-WS-07 עם עץ-התהליכים: `WINWORD.EXE → putty.exe(unsigned) → powershell.exe(-enc) → cmd`. T2 קורא node-אחר-node: cmdline, path, signer, SHA256. לוחץ **hash lookup** (Phase-1 חי) → verdict זדוני.
3. **בונה scope:** מפווט על ה-hash/IP בפיד (`pivot.used` 🔜) → מוצא beacon ל-C2 מ-host שני, ו-`4769 RC4 burst` (Kerberoasting) → scope = {hosts:2, users:1, techniques:[T1566, T1059.001, T1558.003]}. פולט `scope.set` (🔜).
4. מבקש הכלה: **Request containment** → `containment.requested {event_id, target:"FIN-WS-07", reason}` — עם נימוק-impact ("C2 active, blast radius = user offline; server לא-הפקה").
5. אחרי `containment.approved` מה-Lead → מבצע isolate ב-EDR → `containment.executed` → ה-beacon בפיד נעצר (state משותף, `SPEC-edr-console.md §3.2`).
6. כותב **דוח-אירוע** (guided 4 שדות כמו `IncidentReportModal`: what / IOCs / action / impact) → `report.submitted` → grader → `report.graded`.

- **מצוין:** מאשר-קבלה מהר; בונה ציר-זמן **לפני** שמבקש הכלה; מבקש אישור עם נימוק-impact; מחזיר פידבק ל-T1.
- **חלש:** reimage/isolate רפלקסיבי; שוכח לאשר קבלה (T1 "תלוי באוויר"); מפקיע את תפקיד ה-Lead; ציר-זמן רק מה-EDR בלי הפיד.

### 2.3 למי מדווחים / מוסרים

- **in:** `escalation.requested` מ-T1 (התור ב-header). **out-למעלה:** `containment.requested` → **Lead**; `escalation.requested {to_role:"t3"}` (elevation) → **T3** לחקירת-עומק; `escalation.requested {to_role:"ti"}` → **TI** לבקשת-intel; בקשת-כלל → **DE**.
- **out-למטה:** `escalation.resolved {outcome:"confirmed"/"fp"}` → **T1** (פידבק).
- **hand-off שלם:** case עם timeline + scope + evidence pins + recommended containment + report. ה-Lead צריך רק "האם לאשר את ההכלה".
- **"waiting for you":** T2 → תור-האישורים של Lead (`LeadConsole` "Containment approvals (N)").

### 2.4 איך נמדדת הצלחה — כרטיס T2 (0/4/8/12)

| # | קריטריון | 12 | 8 | 4 | 0 | נגזר מ-event |
|---|---|---|---|---|---|---|
| 1 | ack-latency | ≤2′ | ≤5′ | ≤10′ | >SLA / אבוד | Δ(`escalation.requested`→`.acknowledged`) |
| 2 | דיוק ציר-הזמן | כל שלבי ה-chain בסדר נכון | חוסר שלב אחד | סדר שגוי | לא נבנה | `case.updated.timeline` vs ground-truth |
| 3 | שלמות-scoping | כל hosts/users/techniques שזוהו | ≥70% | 40–69% | <40% | `scope.set` (🔜) vs answer-key |
| 4 | המלצת-הכלה | נכונה + מנומקת + בזמן | נכונה, נימוק חלש | נכונה אך מאוחרת | host תמים / רפלקסיבי | `containment.requested.reason` + target-correctness |
| 5 | דוח-אירוע | grader ≥80 | 60–79 | 40–59 | <40 / לא הוגש | `report.graded.score` |

- **NICE:** PR-CIR-001 Cyber Defense Incident Responder (T0041, T0047, T0161, T0163, T0175).
- `reopen-count` (`case.status_changed` חזרה ל-Investigating) הוא מדד-איכות רוחבי — נספר לרעה.

---

## 3. Tier-3 / Threat Hunter (`t3`)

### 3.1 מה רואים על המסך

היום `t3` מרנדר את **אותה** `T2Console` (`me.role === "t2" || me.role === "t3"`). האפיון: קונסולת-T3 ייעודית (`🔜 spec`) = EDR מלא + hunt-board + scope-confirm.

```
RIGHT PANEL — Tier-3 / Threat Hunter   (🔜 spec — today shares T2Console)
┌────────────────────────────────────────────┐
│ 🧭 Hunt board                                │
│ Hypothesis: "putty C2 has a second beacon"  │  ← hunt.started {hypothesis}
│  evidence: [ EVT-8A… ] [ EVT-3F… ] + pin    │  ← evidence.pinned
│  finding:  [ + add finding ]                 │  ← hunt.finding
│ ───────────────────────────────────────────│
│ 📐 Scope review (from T2)                    │
│  T2 scope: hosts:2 users:1 tech:[T1558.003] │
│  [ ✓ Confirm scope ] [ ✎ Amend & return ]   │  ← scope.confirmed / bounce → T2
│ ───────────────────────────────────────────│
│ [ Open full EDR ]  process tree · RTR-lite  │  ← edr.opened  (SPEC-edr-console)
└────────────────────────────────────────────┘
```

- **role-gated:** T3 מקבל את **קונסולת-ה-EDR המלאה** (process tree, RTR-lite, hash — `SPEC-edr-console.md`), חיפוש/pivot חופשי על **כל** הפיד, ו-hunt-board (hypothesis→evidence→finding). מאשר/דוחה את ה-scope של T2. isolate/kill רק אחרי אישור Lead. מנחה את T2.
- **shared:** אותו פיד ותיק. ההבדל מ-T2: T2 רץ על ההסלמה הספציפית; T3 עושה hypothesis-driven hunting מעבר לה (SANS 2025: ציד = השערה, לא סריקה).

### 3.2 איך מבצעים חקירה — דוגמה: Azure-AD Global-Admin escalation

תרחיש: AiTM token-theft → `Add member to role: Global Administrator` מ-IP חדש (impossible travel) → OAuth-consent לאפליקציה זדונית → mail-forwarding rule. שדות אמיתיים (מזיכרון Azure AD): `_source.data.office365.Operation="Add member to role"`, `AzureActiveDirectoryEventType`, `ActorIpAddress`, `ModifiedProperties`, `_source.GeoLocation.country_name`.

1. T2 העלה elevation ("role change חשוד"). T3 מנסח **hypothesis** ב-hunt-board: "משתמש שהתווסף ל-Global-Admin ביצע persistence נוסף" → `hunt.started`.
2. pivot על ה-actor: מחפש בפיד `Operation:"Add-MailboxPermission"`, `Set-Mailbox …ForwardingSmtpAddress`, ו-`Consent to application`. מוצא forwarding-rule + OAuth-grant → `hunt.finding` לכל אחד, `evidence.pinned`.
3. מוודא impossible-travel: `ActorIpAddress` + `GeoLocation.country_name` מול login-history → מאשר account-takeover.
4. קובע scope סופי: {identities:1 (global-admin), apps:1 (OAuth), persistence:[forwarding, role]} → `scope.confirmed` (או **Amend & return** ל-T2 עם נימוק).
5. ממליץ ל-Lead: revoke sessions + remove role + revoke OAuth-consent + kill forwarding-rule — כחבילה.

- **מצוין:** השערה ממוקדת, ציד שמניב ממצא חדש (persistence שלא היה בהסלמה המקורית), ייחוס-טכניקה מדויק (T1098, T1114.003, T1528), הנחיה ברורה ל-T2.
- **חלש:** "סורק הכל" בלי השערה; מאשר scope בלי לבדוק; מפספס את ה-persistence השני; ציד בלי finding מתועד.

### 3.3 למי מדווחים / מוסרים

- **in:** elevation מ-T2 (`escalation.requested {to_role:"t3"}`); בקשות-hunt מ-Lead.
- **out:** `scope.confirmed` → מזין את החלטת-ה-Lead; `containment.requested` (חבילת-eradication) → **Lead**; `escalation.requested {to_role:"ti"}` → **TI** לייחוס-actor; בקשת-כלל → **DE** (לתפוס את הטכניקה שנחשפה בציד).
- **out-למטה:** הנחיה ל-T2 (מה לחקור הלאה) — `note.added` על התיק / `message.sent`.

### 3.4 איך נמדדת הצלחה — כרטיס T3 (0/4/8/12)

| # | קריטריון | 12 | 8 | 4 | 0 | נגזר מ-event |
|---|---|---|---|---|---|---|
| 1 | דיוק-scope סופי | כל הישויות המושפעות | ≥80% | 50–79% | <50% | `scope.confirmed` vs answer-key |
| 2 | hunt-yield | ≥1 ממצא/persistence חדש מעבר להסלמה | ממצא חלקי | חזר על הידוע | 0 findings | `hunt.finding` count + novelty |
| 3 | זמן מהשערה-למסקנה | ≤10′ | ≤20′ | ≤30′ | לא הגיע | Δ(`hunt.started`→`scope.confirmed`) |
| 4 | דיוק-ייחוס-טכניקה | כל ה-techniques נכון | חוסר אחד | ייחוס גס | שגוי | `hunt.finding.technique` vs MITRE ground-truth |
| 5 | איכות ההנחיה ל-T2 | הנחיה ממוקדת + מנומקת | כללית | מועטה | אין / השתלט | `note.added`/`message.sent` to T2 |

- **NICE:** PR-CDA-001 + AN-TWA-001 (חלקי). מבוסס SANS 2025 hunting.

---

## 4. Incident Lead (`lead`)

### 4.1 מה רואים על המסך

הפאנל = `LeadConsole` (`✅ built`): תור-בקשות-הכלה עם Approve/Deny.

```
RIGHT PANEL — Incident Lead
┌────────────────────────────────────────────┐
│ 🛡 Containment approvals (2)                 │
│ ┌────────────────────────────────────────┐  │
│ │ Contain FIN-WS-07                       │  │  ← target
│ │ C2 active; user offline · by Rani       │  │  ← reason · requester
│ │ [ ✓ Approve ]   [ Deny ]                │  │  ← containment.approved / .denied
│ └────────────────────────────────────────┘  │
└────────────────────────────────────────────┘
   + (🔜 spec) Situation Board · Decision Log · cadence timer · SITREP · Mgmt channel
```

- **role-gated חשוב:** ל-Lead **אין** raw-log מלא (§3.7 שורה "פתיחת raw-log מלא: Lead ❌"). הוא רואה סיכומים שהצוות מייצר, לא לוגים גולמיים — כי תפקידו לתאם, לא לחקור.
- **מה חסר מול המאסטר (`🔜 spec`):** Situation Board (כל התיקים + סטטוס + owner + SLA); Decision Log (`decision.logged` עם נימוק+זמן); טיימר-cadence ("next update by HH:MM"); תבנית SITREP (4 שאלות, נספח ב׳ → `sitrep.sent`); ערוץ-הנהלה (`message.sent {channel:"mgmt"}` מול AI-CISO). היום קיים רק ה-approval-queue.

### 4.2 איך מבצעים חקירה (ליתר-דיוק: איך מתאמנים ומחליטים)

ה-Lead **לא חוקר** — הוא מנהל את האירוע. על ה-PuTTY-chain:
1. פותח את הסשן ב-`team.organized` (מסמן מי-Lead ומחלק תפקידים; המאסטר §5.8 — milestone חובה לפני שהקמפיין מתחיל).
2. בקשת-הכלה נכנסת מ-T2 (`Contain FIN-WS-07`). ה-Lead **חייב לשאול "מה ה-impact"** לפני שמאשר: האם FIN-WS-07 הוא שרת-הפקה? (inject אפשרי: CISO "יש דמו ללקוח בעוד 20 דק׳", נספח ג׳ #4/#12).
3. מחליט → **Approve** (`containment.approved`) ומתעד `decision.logged {decision:"isolate FIN-WS-07", reason:"C2 active, blast radius contained, not prod"}` (🔜).
4. שולח SITREP #1 (4 שאלות: מה/מי · האם הצליח · מי ולמה · איך ממשיכים + "next update 14:40") → `sitrep.sent`.
5. מסרב ל-CEO בנימוס ("Do you wish to take command?") — inject #13.

- **מצוין:** "This is X, I'm the incident lead", מחלק תפקידים, מאשר תוך דקות **עם נימוק**, עדכון-הנהלה כל 20–30 דק׳.
- **חלש:** "צולל" ל-raw ומפסיק לתאם; מאשר בלי לשאול impact; שוכח עדכון-הנהלה עד ש-inject-ה-CEO מגיע; לא מתעד החלטות.

### 4.3 למי מדווחים / מוסרים

- **in:** `containment.requested` מ-T2/T3; `intel.published` מ-TI; `escalation.requested {to_role:"lead"}` (elevation) מ-T2/T3.
- **out-פנימה:** `containment.approved/denied` → T2/T3; assign owner + set severity (`case.updated`).
- **out-החוצה:** `sitrep.sent` (הנהלה) · escalation חיצונית (legal/HR/LE) · "hand over command" → Mgr אם נותק (inject #17).
- **"waiting for you":** ה-Lead הוא ה-single-source-of-truth — כולם ממתינים להחלטות שלו; הוא ממתין ל-scope/impact מ-T2/T3.

### 4.4 איך נמדדת הצלחה — כרטיס Lead (0/4/8/12)

| # | קריטריון | 12 | 8 | 4 | 0 | נגזר מ-event |
|---|---|---|---|---|---|---|
| 1 | `team.organized` | ≤5′ מתחילת הסשן | ≤8′ | ≤12′ | לא סומן | `team.organized` timestamp |
| 2 | time-to-approval + נכונות | ≤3′ + החלטה נכונה | ≤7′ נכונה | מאוחר או נימוק חלש | אישר host תמים / דחה נכונה | Δ(`containment.requested`→`.approved`) + correctness |
| 3 | יומן-החלטות | כל DECISION עם נימוק+זמן | חוסר נימוק אחד | החלטות בודדות | לא תיעד | `decision.logged` completeness |
| 4 | cadence + SITREP | עדכון כל 20–30′ + 4 שאלות | פספוס-cadence אחד | SITREP חלקי | לא עדכן עד inject | `sitrep.sent` intervals |
| 5 | עמידה בלחץ-הנהלה | טיפל בכל injects הנהלה נכון | פספוס אחד | תגובה חלשה | נכנע ל-CEO/הדליף | inject-response events |

- **NICE:** PR-CIR-001 (מנהיגות) + OV-MGT-001 (חלקי); ENISA "incident manager".

---

## 5. Detection Engineer (`de`)  🔜 spec — אין קונסולה בקוד עדיין

### 5.1 מה רואים על המסך

```
RIGHT PANEL — Detection Engineer   (🔜 spec)
┌────────────────────────────────────────────┐
│ ⚙ Rule editor                               │
│  predicate: process.name="putty.exe" AND    │  ← שפת eventSearch predicates
│             signed=false AND path~"Downloads"│     (→ KQL/SPL-lite ⏳ later)
│  [ ▶ Backtest on session ]                   │  ← מריץ על אירועי-הסשן
│  → catches 3 TP · 0 FP                        │  ← backtest result
│  [ Publish rule ]  → SIEM-CUSTOM-014         │  ← rule.published
│ ───────────────────────────────────────────│
│ 🗺 ATT&CK coverage (this session)            │
│  T1566 ✅  T1059.001 ✅  T1558.003 ✗ gap     │
│ 📥 Requests from T2/T3                        │
│  "need rule for T1021.001 from FIN-WS-07"    │
└────────────────────────────────────────────┘
```

- **role-gated:** DE כותב/מכוונן כללים; `publish rule` מייצר alert חדש בפיד לכולם ("SIEM-CUSTOM-xxx"). לא מאשר containment, לא מבצע triage.
- מבוסס §3.4: שפת-הסינון הקיימת (`eventSearch` predicates / filters) → בעתיד KQL/SPL-lite (`⏳ later`, REALISM #13). backtest = הרצה על אירועי-הסשן; מפת-coverage ATT&CK; תור-בקשות מ-T2/T3.

### 5.2 איך מבצעים חקירה — סגירת פער תוך כדי האירוע

על ה-PuTTY-chain: T2/T3 חשפו Kerberoasting (`4769 RC4 burst`). DE כותב predicate צר (`event.id=4769 AND ticket_encryption=0x17 AND count>N per host`), עושה **backtest** על הסשן (תופס 2 TP, 0 FP), ו-**publish** → `rule.published {rule_id:"SIEM-CUSTOM-014"}` → alert חדש מופיע לכל הצוות אם הטכניקה חוזרת. **מצוין:** כלל צר שתופס את השלב-**הבא** לפני שקורה, ומוסבר לצוות. **חלש:** כלל על IP בודד ("alert inflation", NCSC) או כלל שמציף את T1.

### 5.3 למי מדווחים / מוסרים

- **in:** בקשות-כלל מ-T2/T3 (תור-בקשות); coverage-gap שה-Lead ביקש.
- **out:** `rule.published`/`rule.tuned` (לכל הפיד); דיווח `coverage-gap` → **Lead** (`note.added`/`message.sent`); suppress FP-pattern (מנומק).

### 5.4 איך נמדדת הצלחה — כרטיס DE (0/4/8/12)

| # | קריטריון | 12 | 8 | 4 | 0 | נגזר מ-event |
|---|---|---|---|---|---|---|
| 1 | verifiable rule | נתפס ב-backtest + בפועל | נתפס ב-backtest בלבד | לא נתפס | לא פורסם | `rule.published` + backtest result |
| 2 | FP-rate של הכלל | 0 FP על הפיד | 1–2 FP | 3–5 FP | מציף | alerts שהכלל הצית vs ground-truth |
| 3 | time-to-publish | ≤5′ מבקשה | ≤10′ | ≤20′ | >20′ | Δ(request→`rule.published`) |
| 4 | coverage-delta ATT&CK | סגר ≥2 techniques | סגר 1 | ניסה | 0 | coverage map before/after |
| 5 | תיעוד | כלל מוסבר + מה תופס | הסבר חלקי | שם בלבד | ריק | `rule.published.payload.doc` |

- **NICE:** PR-CDA-001 + AN-TWA-001 (חלקי); Rapid7 detection-engineering lifecycle.

---

## 6. Threat-Intel Analyst (`ti`)  🔜 spec

### 6.1 מה רואים על המסך

```
RIGHT PANEL — Threat Intel   (🔜 spec — builds on existing ThreatIntelDrawer)
┌────────────────────────────────────────────┐
│ 🔎 Intel repository (this campaign)          │
│  vendor advisory: "APT-sim uses trojanized   │  ← נגזר מה-story (חלקי,
│   PuTTY → Kerberoasting → mega.nz exfil"     │     עם 1 IOC שגוי — inject #10)
│ ✍ Intel note                                 │
│  actor/campaign: ______  confidence: [med▼]  │
│  relevance: ______  recommended action: ____ │
│  next expected technique: T1048 (exfil)      │  ← ניבוי שלב-הבא
│  [ Publish note ]  → intel.published          │
│ 📥 Requests from T2/T3/Lead                    │
└────────────────────────────────────────────┘
```

- **role-gated:** TI מפרסם intel notes (מופיע ל-T1/T2/Lead); מציע IOCs לחסימה (**ה-Lead מאשר**); לא מבצע containment. מבוסס §3.5 + ה-`ThreatIntelDrawer` הקיים (hash/ip/domain lookup).

### 6.2 איך מבצעים חקירה

הופך IOCs להקשר: על ה-PuTTY-chain — מזהה שה-hash+C2 תואמים ל"קמפיין" מוכר, קובע actor/technique עם **confidence מפורש**, ומנבא את השלב-הבא (`T1048` exfil ל-mega.nz — מקדים את inject #14). **מצוין:** note קצר עם confidence מפורש, **לפני** שהשלב-הבא קורה. **חלש:** "Wall of IOCs" בלי המלצה; ייחוס בלי confidence; מאמץ את ה-IOC השגוי מה-advisory בלי אימות.

### 6.3 למי מדווחים / מוסרים

- **in:** בקשות-intel מ-T2/T3/Lead; advisory מה-repository (inject).
- **out:** `intel.published {actor, campaign, confidence, next_technique, recommended_action}` → T1/T2/Lead; הצעת-IOCs-לחסימה → **Lead** (מאשר); תיוג actor/campaign על התיק (`case.updated`).

### 6.4 איך נמדדת הצלחה — כרטיס TI (0/4/8/12)

| # | קריטריון | 12 | 8 | 4 | 0 | נגזר מ-event |
|---|---|---|---|---|---|---|
| 1 | actionable-rate | ≥80% מה-notes הובילו לפעולה | 60–79% | 40–59% | <40% | `intel.published` → פעולה עוקבת |
| 2 | time-to-action | note לפני שהשלב קרה | ≤5′ אחרי | מאוחר | לא רלוונטי | Δ(note→פעולה/שלב) |
| 3 | דיוק-ייחוס | actor+technique נכון | technique בלבד | גס | שגוי | `intel.published` vs ground-truth |
| 4 | ניבוי שלב-הבא | ניבא נכון לפני שקרה | ניבא באיחור | ניבוי גס | לא ניבא | `next_technique` vs מה שקרה בפועל |
| 5 | IOC-precision | 0 IOCs שגויים מוצעים | 1 שגוי | 2–3 | הציף שגויים | proposed-IOC vs answer-key |

- **NICE:** AN-TWA-001 Threat/Warning Analyst; NIST RS.CO.

---

## 7. SOC Manager / Shift Lead (`mgr`)  🔜 spec — המדריך יכול לשחק

### 7.1 מה רואים על המסך

```
RIGHT PANEL — SOC Manager / Shift Lead   (🔜 spec)
┌────────────────────────────────────────────┐
│ 📊 Load board                                │
│  T1 Dana: 6 open · 1 SLA breach ⚠           │  ← alerts/analyst, SLA breaches
│  T2 Rani: 2 cases · ok                       │
│  open cases: 3 · reopened: 1                 │
│ [ Re-assign ] [ Change priority ]            │  ← case.updated
│ [ Open 2nd T1 (AI-assist) ]                  │  ← inject-driven
│ ───────────────────────────────────────────│
│ 📋 Passdown log (MITRE App. D)               │  ← format B (§5.7)
│  on-duty · open cases {id,sev,last,next}     │
│  [ Sign passdown ]  → passdown.signed         │
│ 💬 Mgmt channel                              │
└────────────────────────────────────────────┘
```

- **role-gated:** Mgr מנהל עומס/SLA/עדיפויות; חותם passdown; elevation להנהלה; מאשר containment **רק** אם ה-Lead נותק (inject #17, §3.7 הערה \*). אין לו raw-log מלא (כמו Lead).

### 7.2 איך מבצעים חקירה (ניהול-משמרת)

לא חוקר — מאזן עומס. על תרחיש עם second-incident (inject #3, password-spray על VPN): Mgr מזהה ש-T1 עמוס → re-assign / פותח T1 שני; מוודא שאין SLA-breach על ה-critical; מכין passdown לפורמט B (inject #20). **מצוין:** passdown שמאפשר לצוות-הבא להמשיך בלי לשאול. **חלש:** מתעלם מ-SLA-breaches; passdown חסר "next step + deadline".

### 7.3 למי מדווחים / מוסרים

- **in:** מצב-עומס מכל התפקידים; elevation מ-Lead.
- **out:** re-assign/priority (`case.updated`); `passdown.signed` → צוות-משמרת-הבא (פורמט B); elevation → הנהלה; (אם Lead נותק) `containment.approved`.

### 7.4 איך נמדדת הצלחה — כרטיס Mgr (0/4/8/12)

| # | קריטריון | 12 | 8 | 4 | 0 | נגזר מ-event |
|---|---|---|---|---|---|---|
| 1 | SLA-adherence | 0 breaches | 1 breach | 2–3 | >3 | SLA timers vs `event.opened`/`disposition.set` |
| 2 | איזון-עומס | פער-עומס נמוך בין analysts | פער בינוני | פער גבוה | analyst אחד קורס | alerts/analyst distribution |
| 3 | passdown | כל השדות (App. D) + next+deadline | חוסר שדה | חלקי | לא חתם | `passdown.signed.payload` |
| 4 | reopen-rate | 0 | 1 | 2 | >2 | `case.status_changed` reopens |
| 5 | elevation נכונה | בזמן + מוצדק | מוצדק אך מאוחר | מיותר | פספס נדרש | elevation events |

- **NICE:** OV-MGT-001 (חלקי) + MITRE "SOC leadership".

---

## 8. The incident as a relay — אירוע אחד דרך כל התפקידים

### 8.1 זרימת-ההסלמה המלאה (מצוירת פעם-אחת)

```mermaid
sequenceDiagram
    autonumber
    participant F as Live Feed (server)
    participant T1 as T1 Triage
    participant T2 as T2 Investigator
    participant T3 as T3 / Hunter
    participant L as Incident Lead
    participant DE as Detection Eng
    participant TI as Threat Intel
    participant M as SOC Manager
    participant X as Mgmt / external (AI SimCell)
    F->>T1: feed.event (high) — putty.exe by WINWORD on FIN-WS-07
    T1->>T1: event.opened + disposition.set (true_positive)
    T1->>T2: escalation.requested {evidence, why=mechanism, impact, confidence}
    T2->>T1: escalation.acknowledged (SLA clock)
    T2->>T2: edr.opened + scope.set {hosts:2, T1558.003}
    T2->>T3: escalation.requested {to_role:t3} (elevation, deep hunt)
    T3->>T3: hunt.started → hunt.finding (2nd persistence) → scope.confirmed
    T3->>TI: escalation.requested {to_role:ti} (attribution)
    TI->>L: intel.published {actor, confidence, next_technique}
    T2->>L: containment.requested {isolate FIN-WS-07, impact}
    X->>L: inject: CISO "demo in 20m — don't isolate?"
    L->>L: decision.logged (approve; reason: C2 active, not prod)
    L->>T2: containment.approved
    T2->>F: containment.executed → beacon stops (shared state)
    T3->>DE: request rule for exposed technique
    DE->>F: rule.published (SIEM-CUSTOM-014)
    L->>X: sitrep.sent (4 questions, next update 14:40)
    M->>M: load balance + passdown.signed (format B)
    T2->>T1: escalation.resolved {outcome: confirmed} (feedback)
```

### 8.2 ציר-הזמן של האירוע (טבלת relay — מי · מה רואה · מה פולט · איך הצוות מתקדם)

| t (offset) | תפקיד | מה רואה | פעולה (event) | ה-hand-off ל־ |
|---|---|---|---|---|
| 00:02 | T1 | feed.event high על FIN-WS-07 | `event.opened` → `disposition.set(TP)` | — |
| 00:04 | T1 | raw: parent=WINWORD, unsigned, `-enc` | `escalation.requested` | T2 (תור "Escalations for you") |
| 00:05 | T2 | הסלמה בתור | `escalation.acknowledged` | T1 (ActivityLog: "acknowledged") |
| 00:09 | T2 | עץ-תהליכים ב-EDR | `edr.opened` → `scope.set` | T3 (elevation) |
| 00:14 | T3 | scope של T2 + pivot | `hunt.started`→`hunt.finding`→`scope.confirmed` | TI + Lead |
| 00:16 | TI | IOCs + advisory | `intel.published {next: T1048}` | Lead (Situation Board) |
| 00:18 | T2 | scope מאושר | `containment.requested` | Lead (תור "Containment approvals") |
| 00:19 | Lead | inject CISO "demo" | `decision.logged`→`containment.approved` | T2 |
| 00:20 | T2 | אישור | `containment.executed` → beacon עוצר | הפיד (כולם רואים) |
| 00:22 | DE | טכניקה שנחשפה | `rule.published` | הפיד (alert חדש) |
| 00:24 | Lead | תמונת-מצב | `sitrep.sent` | הנהלה (Mgmt channel) |
| 00:30 | Mgr | עומס + סוף-משמרת | `passdown.signed` | צוות-הבא (format B) |
| 00:32 | T2 | סגירה | `escalation.resolved` → `report.submitted` | T1 (feedback) + grader |

### 8.3 איך ציון-הצוות מצטבר (מ-§6.2, כולם מ-`session_events`)

| רכיב | משקל | מה בטבלה למעלה מזין אותו |
|---|---|---|
| Detection & Containment outcome | 30 | עומק-kill-chain בעת `containment.executed` (00:20, לפני exfil) + MTTC |
| Escalation & handoff quality | 20 | שלמות `escalation.requested` (00:04) + ack-latency (00:04→00:05) + 0 אבודות |
| Coordination & communication | 15 | `team.organized` ≤5′ + `decision.logged` מנומק (00:19) + cadence |
| Reports & documentation | 20 | `report.graded` (00:32) + `sitrep.sent` (00:24) + `passdown.signed` (00:30) |
| Timeliness & SLA | 15 | time-to-triage (00:02) + time-to-approval (00:18→00:19) |

> ציון-הצוות אחד ומשותף; כל תפקיד מקבל בנוסף כרטיס-אישי-פרטי (§1.4–§7.4). **אין ניקוד חי** במהלך האימון — נחשף רק בדו"ח-הסיום (§13.12 של המאסטר).

---

## 9. Per-role success at a glance

| role | מסך ראשי | פעולת-מפתח (event) | מדווח ל־ | 3 קריטריונים מובילים | תנאי-ניצחון |
|---|---|---|---|---|---|
| **T1** Triage | `T1Console` — תור + disposition + טופס-הסלמה | `escalation.requested` | T2 | דיוק-disposition · דיוק-הסלמה · שלמות-כרטיס | הסלמה שלמה ומדויקת שאושרה, FP נסגרו עם נימוק |
| **T2** Investigator | `T2Console` + EDR (🔜) + timeline | `containment.requested` | Lead (+ פידבק ל-T1) | ack-latency · scoping · המלצת-הכלה | scope נכון + הכלת ה-host הנכון בזמן |
| **T3** Hunter | Hunt-board + EDR מלא (🔜) | `scope.confirmed` / `hunt.finding` | Lead / TI / DE | scope סופי · hunt-yield · ייחוס | חשף persistence נוסף וקבע scope מלא |
| **Lead** | Situation Board + Decision Log (🔜) | `containment.approved` + `decision.logged` | הנהלה | `team.organized` · time-to-approval · יומן+cadence | תיאם, אישר נכון עם נימוק, עדכן בזמן |
| **DE** | Rule editor + backtest (🔜) | `rule.published` | Lead / T2·T3 | verifiable rule · FP-rate · coverage-delta | כלל צר שתופס את השלב-הבא, 0 FP |
| **TI** | Intel repo + note editor (🔜) | `intel.published` | Lead / T1·T2 | actionable-rate · ניבוי · IOC-precision | note עם confidence שהוביל לפעולה, לפני השלב-הבא |
| **Mgr** | Load board + Passdown (🔜) | `passdown.signed` | הנהלה / צוות-הבא | SLA-adherence · איזון-עומס · passdown | 0 SLA-breaches + passdown שממשיך בלי שאלות |

---

## 10. שאלות פתוחות לטל

1. **פיצול T2/T3 בקוד:** היום `t3` חולק את `T2Console`. לבנות קונסולת-T3 ייעודית (hunt-board + EDR מלא + scope-confirm) כבר ב-MVP, או להשאיר משותף עד שלב-2? (המלצה: להשאיר משותף ל-MVP; לפצל ב-שלב-2 יחד עם DE/TI/Mgr.)
2. **סולם-ניקוד:** מסמך זה משתמש ב-4 עמודות (0/4/8/12) לקריאוּת; המאסטר (נספח ד׳) משתמש ב-5 (0/4/6/8/12). לאחד לסולם אחד לפני שבונים את מסך-הרובריקה בלובי?
3. **Shared Case panel:** ה-`SharedFeed`/`T1Console`/`T2Console`/`LeadConsole` קיימים, אבל פאנל-התיק-המשותף (§5.1: status/owner/scope/evidence/timeline/notes) עדיין `🔜`. האם זה חלק מ-Phase 0.4 או Phase 1?
4. **event.opened dwell:** הקוד פולט `event.opened {event_id}` בלבד; המדידה (time-to-triage, thoroughness) דורשת `dwell_ms`. להוסיף עכשיו?
5. **DE rule language:** predicate-ל-`eventSearch` ל-MVP, או להמתין ל-KQL/SPL-lite (⏳)? (המלצה: predicate ל-MVP — כבר קיים ב-`eventSearch`.)
6. **מי מנקד "הנחיה ל-T2"** (קריטריון T3 #5) — האם ניתן לגזור אוטומטית מ-`note.added`/`message.sent`, או שזה קריטריון שדורש דירוג-מדריך (`observer.rated`)?
