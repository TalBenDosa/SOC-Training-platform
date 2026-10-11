# סקירת ריאליזם — Team-SOC Multiplayer (staging)

**שיטה:** קריאת קוד בפועל (לא רק ספק), השוואה ל-4 מקורות-אמת: `docs/SPEC-team-soc-multiplayer.md` (המחקר העצמאי שהניע את הבנייה: MITRE Ten Strategies, NIST SP 800-61r3/800-84, ENISA Incident Management Guide, PagerDuty/incident.io IR docs, Henshel et al. 2016, Granåsen & Andersson 2016, Locked Shields/Frontiers 2022), `docs/SPEC-team-roles-playbook.md`, `docs/SPEC-team-ux-ui.md`, ומול תפעול SOC אמיתי מוכר (triage queue → escalation → containment-approval → hunt, SITREP/decision-log, SIEM/EDR/SOAR).

קבצים שנסקרו: `src/app/(app)/team/[id]/page.tsx` (1935 שורות — הליבה כולה), `src/app/(app)/team/page.tsx`, `src/lib/team/buildTimeline.ts`, `supabase/migrations/0049_team_sessions.sql` / `0050` / `0051_team_session_rpc.sql` / `0053_team_roles_real_feed.sql` / `0056_team_continuous_feed.sql`, `src/app/api/team/sessions/[id]/start/route.ts`, ורשימת `src/lib/sim/scenario-packs/*` (49 חבילות).

---

## 1. ציון ריאליזם כולל לכל ממד (1–5)

| ממד | ציון | הסבר |
|---|:-:|---|
| **תפעול (Operations)** | **4/5** | מחזור-חיים מלא ונאמן: תור→disposition→הסלמה מובנית→ack→scope→בקשת-הכלה→אישור→ביצוע→ציד. State machine אמיתי, claim-lock נגד עבודה-כפולה, roster+presence. **אבל**: ה-RBAC האמיתי (מי מותר לו לעשות מה) אוכף בשרת רק על כ-9 מתוך ~25 סוגי-פעולה — שאר הפעולות (כולל `containment.executed`, `staff.inject`, `rule.published`, `case.status_set`) עוברות תחת ברירת-מחדל פתוחה. זה סותר את עקרון-העיצוב המוצהר של הספק עצמו ("תפקיד = הגבלה, לא רק תצוגה", §1.4 עיקרון 1). |
| **כלים (Tooling)** | **4/5** | EventFeed/EDR/DE-backtest הם **אותם רכיבי single-player** בדיוק — לא סימולציה-לייט. "Investigate in EDR" בונה מהפיד האמיתי ומחזיר `null` בכנות כשאין טלמטריית-endpoint (לא פותח קונסולה ריקה). T2 פותח את ה-log המלא (לא רק את מילות T1). DE עושה back-test חי בשפת-predicate אמיתית. חסר: מושג SOAR/playbook מפורש (אך שרשרת בקשה→אישור→ביצוע ממלאת את התפקיד הפדגוגי בלי לבנות UI מיותר), אין ספריית saved-search חוצת-סשן. |
| **IR-Comms** | **3.5/5** | טופס-ההסלמה של T1 הוא הכי-נאמן במוצר (Summary/Observations עם שער-איכות של ≥12 מילים/≥1 IOC — "Escalate signals, not doubts"). Decision-log ו-SITREP (4 שאלות MITIRE) קיימים ומדויקים מבנית, **אבל** ללא שער-איכות מקביל (סף של 5 תווים בלבד ל-decision) וללא cadence/טיימר "next update by" — בדיוק ההפך מהעיקרון של הספק עצמו ש-T1 מקבל את השער הכי קשה וה-Lead/Mgr הכי רך, כשבפועל ההיפך אמור להיות נכון (יומן-ההחלטות הוא מה שמבקר-IR אמיתי בודק ראשון). |
| **נוף-איומים (Threatscape)** | **4.5/5** | משתמש **באותו מנוע** של single-player: 49 scenario-packs מבוססי-ATT&CK אמיתי, pool רעש-רקע ספציפי-לחברה, ורענון-רעש רציף כל 10s (`replenish_feed`, migration 0056) שלעולם לא ממחזר אירועי-תקיפה — מדמה נאמנה את "90% המשעמם". חיסרון יחיד משמעותי: **סיפור-תקיפה אחד בלבד לסשן**, בלי second-incident/decoy ובלי הסתגלות-יריב (branch on containment) — לצוות של 4–6 זה עשוי לא לספק מספיק "עומק" ל-T3/DE/TI בו-זמנית. |

**ציון-על משוקלל: 4/5** — התשתית התפעולית והתוכן עצמם ברמה גבוהה מאוד ונאמנים למחקר שהניע אותם; הפער העיקרי הוא **אכיפה** (RBAC בשרת, שערי-איכות ל-Lead) ו-**עומק-דביר** (AAR guided replay, סיפור-תקיפה יחיד) ולא בארכיטקטורה.

---

## 2. מפת ריאליזם מאוחדת

| ממד | פער | חומרה | מאמץ | מקור |
|---|---|:-:|:-:|---|
| תפעול | RBAC בשרת חלקי — `containment.executed`, `staff.inject`, `rule.published`, `intel.published`, `case.status_set`/`case.assigned`, `scope.set`/`scope.confirmed`, `sitrep.sent` נופלים ל-else פתוח | **גבוהה** | נמוך (SQL בלבד) | `supabase/migrations/0056...sql` L14-31 מול `docs/SPEC-team-soc-multiplayer.md` §1.4 עיקרון 1, §3.7 |
| תפעול | אין תור-triage ממוין (SLA/severity) ל-T1 — עובד מול dropdown על פיד גולמי | בינונית | בינוני (UI מעל דאטה קיים) | `T1Console` ב-page.tsx L683 מול SPEC §3.1 "לעולם לא פיד לא-מסונן" |
| תפעול/IR | אין טיימר-SLA/ack חי גלוי לשחקן (רק מחושב post-hoc ב-AAR) | בינונית | בינוני | `computeReport` L1600 מול SPEC §5.3 "SLA timers · cadence" |
| תפעול | אין Format-B (מסירת-משמרת בין שני צוותים) — `handover.noted` נכתב אך אין צד-קולט | נמוכה (מוצהר Phase-2) | גבוה | SPEC §2.2 פורמט B |
| IR-Comms | Decision-log/SITREP ללא שער-איכות (סף 5 תווים) לעומת שער T1 (12 מילים+IOC) | **גבוהה** | נמוך | `DecisionLog`/`SitrepConsole` L1063-1128 מול SPEC §5.2 |
| IR-Comms | אין cadence אכוף ("next update by HH:MM") — רק ספירת-SITREPs גולמית ברובריקה | בינונית | בינוני | SPEC §5.3; רובריקה ב-L1465 |
| IR-Comms | אין AI SimCell (CISO/עיתונאי/vishing) — inject ידני בלבד מהמדריך | נמוכה (מוצהר Phase-2) | גבוה (LLM) | `InstructorPanel` L1130 מול SPEC §5.5 |
| כלים | אין SOAR/playbook מפורש (אך השרשרת request→approve→execute ממלאת תפקיד דומה) | נמוכה | — | — |
| כלים | EDR handoff דרך localStorage+טאב חדש — לא משותף-realtime בין חברי-צוות | נמוכה | בינוני | `openEdr` L338 |
| Threatscape | סיפור-תקיפה יחיד לסשן — אין second-incident/decoy, אין הסתגלות-יריב | **גבוהה** לצוות גדול | בינוני-גבוה | `buildTeamTimeline.ts` L48 מול SPEC §4.1 שלב 2, §5.4 |
| Threatscape/AAR | AAR הוא metrics-dashboard בלבד — אין replay דו-מסלולי, אין "מי-ידע-מה-מתי", אין AI Narrator/hot-wash מונחה | **גבוהה** | בינוני (הדאטה כבר קיים ב-`events`) | `TeamReport` L1646 מול SPEC §6.6, §7.4 (Tannenbaum & Cerasoli: debrief ≈ מחצית הלמידה) |
| הכל | ~35% מתאי-הרובריקה הם `TODO`/null (FP-rate של DE, actionable-rate של TI, "incident report" של T2 שיכול לעשות שימוש-חוזר ב-grader הקיים) | בינונית | בינוני (יש תבנית מוכחת) | `roleRubric` L1438-1491 |

---

## 3. Top-10 פערים (השפעה-על-ריאליזם ÷ מאמץ — ממוינים)

1. **RBAC בשרת לא שלם** — `session_action_allowed` צריך לגדר את כל 25 סוגי-הפעולה, לא רק 9. זו לא רק "באג ריאליזם" — זו פירצת-הגנה: תלמיד T1 יכול טכנית (למשל דרך console) לבצע `containment.executed` או `staff.inject` בלי הרשאה. תיקון = הרחבת ה-CASE statement בקובץ SQL אחד. **מאמץ הכי נמוך, השפעה הכי גבוהה במפה כולה.**
2. **AAR ללא replay מונחה** — הדאטה (event log מלא, ground-truth, timestamps) כבר קיים ב-`computeReport`; חסר רק שכבת-תצוגה של ציר דו-מסלולי + "מי ידע מה מתי" + 3 רגעי-מפתח. המחקר (Tannenbaum & Cerasoli, מצוטט בספק עצמו) קובע שזה **מחצית מהערך הפדגוגי** של כל התרגיל.
3. **שער-איכות ל-Decision-log/SITREP** — היום T1 עובד תחת המשמעת הכי קשה במוצר (12 מילים, IOC חובה) בעוד Lead/Mgr — התפקיד שהכי נבדק ב-IR אמיתי — עובד תחת סף של 5 תווים. הפיכת חוסר-הסימטריה הזו קלה (אותו דפוס UI שכבר קיים ב-T1Console).
4. **סיפור-תקיפה יחיד לסשן** — לצוות 4-6 עם T3/DE/TI ייעודיים, אירוע ליניארי אחד עלול להשאיר תפקידים "מחכים". אין צורך ב-AI מסתגל (Phase 2 המלא) — even סיפור-משני דטרמיניסטי שני (decoy) שכבר קיים כ-scenario-pack, שנבחר ומוזרק בתזמון קבוע, ייתן ל-Lead תרגול קונקרטי ב"ניהול שני אירועים במקביל" (Parallelism — SPEC §6.4).
5. **אין תור-triage ממוין ל-T1** — הבדל אמיתי בין "לעבוד תור מדורג-לפי-SLA" (SOC אמיתי) לבין "לבחור log מ-dropdown על פיד גולמי". תיקון UI-בלבד מעל `enrichEvent`/`ruleLevel` הקיימים.
6. **אין SLA/cadence timer חי** — הלחץ-הזמן שמניע "אם לוקח יותר מכמה דקות מסלימים" (MITRE) לא מורגש בזמן-אמת, רק נמדד בדיעבד. Countdown-badge על כל הסלמה פתוחה, ו-"next SITREP by" ל-Lead — מאמץ בינוני, השפעה גבוהה על תחושת-הלחץ האותנטית.
7. **תאי-רובריקה חסרים (~35%)** — בפרט "Incident report" של T2 יכול לעשות שימוש-חוזר מיידי בדפוס ה-grader הדטרמיניסטי הקיים מ-single-player (`incident-report/route.ts`, המוזכר בספק כתבנית מפורשת) — הרחבה זולה יחסית עם השפעה על שלמות-הניקוד.
8. **EDR handoff לא-משותף (localStorage+טאב)** — T2/T3 שניהם יכולים לחקור אותו host אך לא רואים את הפעולות אחד של השני בזמן-אמת בקונסולת ה-EDR (בניגוד לפיד המשותף האמיתי). מאמץ בינוני (broadcast של פעולות EDR), השפעה נמוכה-בינונית.
9. **Format B (מסירת-משמרת בין צוותים)** — מוצהר Phase-2 בספק עצמו; `handover.noted` כבר נכתב היום בלי צד-קולט אמיתי. השאירו כפי שהוא — לא P0.
10. **AI SimCell (CISO/עיתונאי/vishing) חסר** — יש תחליף אנושי סביר (Instructor inject-composer), אבל מטיל עומס-הפעלה כבד על מדריך שמריץ 4 חדרים. Phase-2 מוצהר; ADD רק אחרי 1-7.

---

## 4. Roadmap מתועדף

### P0 — לתקן/לחזק לפני ריצה רשמית (מאמץ נמוך, השפעה גבוהה)
- **STRENGTHEN — RBAC בשרת מלא.** הרחיבו את `session_action_allowed` (מיגרציה חדשה על בסיס 0056) כך שכל סוג-פעולה בעל בעל-הרשאה מוגדר בטבלת §3.7 של הספק יקבל תנאי מפורש: `containment.executed`→t2/t3, `staff.inject`→instructor בלבד, `rule.published`→de, `intel.published`→ti, `case.status_set`/`case.assigned`→t2/t3/lead/mgr (assign: lead/mgr בלבד), `scope.set`→t2, `scope.confirmed`→t3, `sitrep.sent`→lead/mgr, `handover.noted`→mgr. קובץ: `supabase/migrations/0056_team_continuous_feed.sql` (הוסיפו מיגרציה חדשה, אל תערכו קיימת).
- **STRENGTHEN — שער-איכות ל-Decision-log/SITREP.** להעלות את הסף (rationale חובה + ≥8 מילים לדוגמה) בקובץ `page.tsx` ב-`DecisionLog`/`SitrepConsole` (L1063-1128), באותו דפוס בדיוק כמו `gate`/`canEscalate` שכבר קיים ב-`T1Console`.

### P1 — משנה את מה שהתלמיד מתאמן עליו (מאמץ בינוני, השפעה גבוהה)
- **ADD — AAR מונחה עם replay.** מסך "ended" חדש שמציג ציר-זמן דו-מסלולי (תקיפה↑/תגובה↓) מתוך `events` הקיים, עם קליק-לפרט "מי ראה זאת ומתי" ו-3 רגעי-מפתח (ההסלמה הראשונה, החלטת-ההכלה, ה-inject הקשה ביותר). כל הדאטה כבר מחושב ב-`computeReport`; זו בעיקר עבודת-רינדור. קובץ: `TeamReport` ב-`page.tsx` (L1646).
- **ADD — SLA/cadence חי.** Countdown-badge על כל הסלמה `requested` ללא `acknowledged`, ו-"next SITREP by HH:MM" ל-Lead/Mgr עם נאדג' אם עבר. משתמש בזמנים שכבר נשמרים (`occurred_at`).
- **STRENGTHEN — תור-triage ממוין ל-T1.** מיון ברירת-מחדל לפי `ruleLevel`/גיל בתוך `T1Console`, לא רק dropdown — משתמש ב-`enrichEvent`/`ruleLevel` הקיימים ב-`useLiveEvents.ts`.
- **ADD — סיפור-משני (second incident) קבוע-בזמן.** בחירה דטרמיניסטית של scenario-pack שני (decoy או אמיתי) שמוזרק ~אמצע-הסשן ב-`buildTeamTimeline.ts` — לא דורש AI-adversary מסתגל, רק עוד `pickStoryForCompany` שני עם offset קבוע.
- **STRENGTHEN — חיבור ה-grader הקיים ל-T2 "incident report".** שימוש-חוזר בדפוס `incident-report/route.ts` (rubric דטרמיניסטי + AI-prose + anti-injection) על סיכום-T2, כדי לסגור את תא-הרובריקה "Incident report" שהיום `TODO`.

### P2 — נחמד-להיות, לא דחוף (תואם להצהרת-Phase-2 של הספק עצמו)
- **ADD — AI SimCell (CISO/עיתונאי/vishing personas)** — משדרג את ה-inject הידני הקיים; מצריך שכבת-LLM חדשה.
- **ADD — Format B (מסירת-משמרת בין שני צוותים)** — `handover.noted` כבר קיים; דורש מנגנון-סשן-ממשיך.
- **STRENGTHEN — שיתוף-EDR בזמן-אמת** בין T2/T3 (broadcast של פעולות RTR/process-tree, לא רק localStorage).
- **REMOVE/לא לגעת** — שום דבר לא מומלץ להסרה: אין "קישוט" מיותר בקוד שנסקר; כל מנגנון קיים משרת למידה בפועל (גם ה-INTEL_REPO עם ה-decoy IOC וגם ה-claim-lock על alerts).

---

## 5. מה כבר חזק — לשמר בלי לגעת

- **פיד אחד משותף בזמן-אמת לכל הצוות** (Broadcast-from-Database + DB-reconcile safety-net) — זה בדיוק מה שאף מתחרה (TryHackMe SOC Sim, RangeForce) לא נותן, ומדויק להפליא ל"war-room אחד" של SOC אמיתי.
- **טופס-הסלמה עם שער-איכות אמיתי** (סיכום + תצפיות ≥12 מילים + ≥1 IOC + חומרה) שמתעד את ה-log המלא כ-snapshot — כך ש-T2 תמיד חוקר את האירוע האמיתי, לא רק את הפרשנות של T1. זה ליבת-הריאליזם התפעולי-מספר-1 של המוצר, מיושם היטב.
- **State machine מלא ומגודר-תפקיד להסלמה ולהכלה** (`requested→acknowledged→bounced/resolved`, `requested→approved/denied→executed`) עם dedup לוגי (`alert.claimed`/`released`) נגד עבודה-כפולה — נדיר לראות ברמה הזו בכלי-אימון.
- **שימוש-חוזר מלא במנועי single-player** (EventFeed, EDR console, scenario-packs, benign-noise pool) — אין "גרסת-Lite" מיוחדת ל-team mode; זה מבטיח שהריאליזם של הפלטפורמה החד-שחקנית (שכבר גבוה) עובר במלואו לצוות.
- **רענון-רעש רציף שלעולם לא חוזר על אירוע-תקיפה** (`replenish_feed`, כל 10s) — פותר אלגנטית את בעיית "המשמרת מסתיימת בשקט" ומדמה את ה"90% המשעמם" שהמחקר של הספק מצטט (Vectra/Microsoft-Omdia).
- **רובריקת 0/4/8/12 גלויה עם `n/a` כן ולא ניקוד-סמוי** — עונה ישירות לתלונה התיעודית של 42% מהמשתתפים ב-Locked Shields על שקיפות-ניקוד.
- **TI console עם IOC-דקוי מכוון** — לימוד מובנה של "וודא לפני שאתה מעביר הלאה", לא רק "wall of IOCs".
