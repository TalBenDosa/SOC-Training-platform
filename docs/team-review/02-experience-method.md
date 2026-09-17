# ביקורת חוויה + שיטת-הרצה — Team-SOC Multiplayer (staging)

> **מה זה:** התבוננות-מהצד על **איך התרגיל הצוותי מתנהל היום** ואיך לשפר את **שיטת-ההרצה** — כמדריך וכמתאמן — במהלך run-through דמה של צוות מלא. **דו"ח בלבד; לא נגעתי בקוד.**
> **תאריך:** 2026-09-16
> **היקף:** `src/app/(app)/team/[id]/page.tsx` · `src/app/(app)/team/page.tsx` · `src/app/api/team/sessions/**` · `src/lib/team/buildTimeline.ts` · מיגרציות 0049–0060 · הספקים `SPEC-team-*.md`.
> **מתודה:** מעקב-קוד מקצה-לקצה (lobby→feed→relay→report) + הרצת שערי-בריאות. **לא** ביקורת נאמנות-שדה של לוגים (זה תחום `soc-livefeed-playthrough-auditor`).

---

## 0. שערי-בריאות (הרצתי בפועל)

| שער | תוצאה |
|---|---|
| `node node_modules/typescript/bin/tsc --noEmit` | ✅ 0 שגיאות |
| `npx vitest run` | ✅ 157/157 עברו (14 קבצים) |

שום דבר שבור טכנית. הבעיות למטה הן **חווייתיות ושיטתיות**, לא באגים שמפילים בילד. (נקודה אחת חשודה — G-חדש #12 — עלולה להפיל פעולה בזמן-ריצה בקונפיגורציית-משתמש מסוימת.)

---

## 1. תמונת-מצב — מה הצוות באמת חווה היום

מתאמן נכנס ל-`/team/<id>` → לובי עם roster + presence + ready-check מהמם (3-2-1 countdown) → המדריך לוחץ Start → **פיד חי משותף זהה-לכולם** (pg_cron מקדם timeline דטרמיניסטי, benign מתחדש בלי-סוף, ההתקפה מוזרקת פעם-אחת ב-30%–100% של הפיד) → **relay מנוקד**: T1 מתייג + מסלים 🚩 עם snapshot-לוג-מלא → T2/T3 מאשרים-קבלה, חוקרים (pivot / Investigate-in-EDR), קובעים scope, מבקשים הכלה → SOC Manager מאשר + מתעד החלטה + SITREP → T2 מבצע isolation → T3 מאשר scope → Shared Case נסגר → End-Exercise → **דו"ח per-role + team** (רובריקה 0/4/8/12, MTTA/MTTC, CSV).

**מה שמרשים כבר עכשיו (לא לגעת):**
- **Onboarding סולו מצוין** — `RoleGuideModal` פעם-אחת/תפקיד (mission · steps · hand-off · measured · "how the team works together") + directive-banner גלוי-תמיד (`roleDirective`). מתאמן מבין מה לעשות **בלי מדריך חי**.
- **הפיד המשותף + reconcile** — Broadcast-from-DB + poll-safety-net כל 6s. אף לוג לא אובד; קצב ריאלי (5–9s, צפוף יותר ב-hard). הצוות באמת רואה אותו אירוע באותה שנייה.
- **role-gating בשרת** — `session_action_allowed` אוכף role×phase; הגיבור פיזית לא יכול לעשות הכל. זו ליבת התלות-ההדדית והיא תקינה.
- **hand-offs עם אישור דו-כיווני** — T1 רואה sent→ack→bounced→resolved; containment עובר request→approve→execute. מנגנון ה-bounce מלמד feedback-loop אמיתי.
- **soft-claim ל-T1** — שני T1 לא עובדים על אותה התראה (🔒, TTL 5 דק', "Take over").
- **דו"ח נגזר-מיומן** — רובריקה per-role + team-metrics + CSV, הכל מ-`session_events` append-only. אמין וניתן-לשחזור.

---

## 2. ממצאים מדורגים (השפעה-על-הלמידה ↓)

### 🔴 F1 — אירוע-יחיד סקריפטי אחד לא מעסיק צוות מלא; רוב התפקידים במתנה
**איפה:** `buildTimeline.ts` — סטורי-התקפה **אחד** לכל סשן; אין decoy/parallel incident. `page.tsx` — כל ה-relay מתנקז לאירוע-אחד.
**מה קורה בפועל:** עם 2×T1, 2×T2, T3, Manager — כולם מתכנסים על **אירוע-אחד**. ה-benign הוא רק רעש+FP (`expected_verdict!=tp`), אין התקפה-שנייה אמיתית. אחרי ש-T1 הראשון תפס והסלים — לשאר ה-T1 אין "אות" נוסף לצוד; T2 השני יושב; Manager מקבל עבודה רק כשמגיעה בקשת-הכלה (מאוחר בשרשרת). **דד-טיים מובנה ל-T3 ול-Manager בתחילת הסשן, ול-T1/T2 עודפים לכל האורך.**
**המלצה:** להוסיף **incident שני** לכל סשן — לפחות decoy אחד (password-spray/VPN, phishing שני) שרץ במקביל, ורצוי אחד decoy + אחד real. זה מה שמעסיק multi-T1/T2, מכריח תיעדוף (Manager!), ומייצר עבודה-לכל-תפקיד מהדקה הראשונה. הכי משתלם: להזריק סטורי-benign-אך-חשוד שני מ-`attackStories` עם verdict=fp כ"מתיחה", ובהמשך סטורי-real שני שמצריך תיק שני ב-Shared Case (המכניקה כבר תומכת ב-scope/case; חסר רק multi-case).

---

### 🔴 F2 — בלי מדריך פעיל אין tempo, injects, לחץ-זמן או curveballs
**איפה:** `InstructorPanel` — inject ידני בלבד (announcement/ticket/mgmt_pressure). אין MSEL, אין injects אוטומטיים/מתוזמנים, אין personas. `SlaBar`+cadence-timer+idle-nudge **הוסרו** (G-12/G-18, לבקשת Tal, "העמיסו").
**מה קורה בפועל:** אם המדריך לא יושב ומקליד injects — **קורים אפס injects**. אין management-pressure, אין vishing-ticket, אין resource-removal, אין "second incident", אין guiding-inject כשצוות תקוע. גם אין **שום טיימר** על המסך (בניגוד ל-dashboard היחיד עם 30 דק'), אין אורך-משמרת מוגדר, ואין קצב-לחץ. התרגיל "רץ" אבל שטוח — הדופק היחיד הוא זרימת-הפיד.
**מה זה עושה למתאמן:** SOC אמיתי נמדד על התנהגות-תחת-לחץ. בלי לחץ-זמן ובלי curveballs, המתאמנים מבצעים relay רגוע — לא מתאמנים על ההחלטות שבאמת נשברות בצוות (הסלמת-יתר מפחד, מנהל שמתערב, החמצה תחת עומס).
**המלצה:**
1. **MSEL מינימלי אוטומטי** — 3–5 injects מתוזמנים לכל סטורי (`at_time`/`on_milestone`) שנטענים ב-`buildTimeline` יחד עם הפיד: management-pressure ב-t+8', vishing-ticket ב-t+12', "EDR של host X מפסיק לדווח" (resource-removal), ו-**guiding-inject אוטומטי** אם לא הייתה `escalation.requested` על attack-event עד t+N (החזרת idle-nudge, אך **ברמת-הצוות** ולא כ-clutter אישי).
2. **טיימר-משמרת רך** — מד-התקדמות שקט (לא countdown לחיץ) שנותן תחושת-זמן בלי להעמיס. אפשר בשורת-הסטטוס העליונה בלבד.
3. להחזיר SLA-clock **רק על high/critical פתוחים**, כתג-אחד בשורת-הסטטוס (לא bar נפרד) — כך פותרים את תלונת-ה-clutter של Tal אך משמרים את הלחץ.

---

### 🔴 F3 — הסלמות/הכלות **לא מנותבות**; multi-T2 = עבודה כפולה, T3 לא מקבל עבודה ייעודית
**איפה:** `page.tsx` — `escalations = events.filter(type==="escalation.requested")`; **כל** T2 ו-T3 רואים את **כל** ההסלמות ("Escalations for you (N)"). אין `to_role`, אין claim על הסלמה (רק על alert של T1). ה-elevation ל-T3 שמתואר בספק (`escalation.requested{to_role:t3}`) **לא ממומש**.
**מה קורה בפועל:** שני T2 יכולים לאשר-קבלה ולבקש-הכלה על **אותה** הסלמה (idempotency הוא per-user, לא per-escalation) → ack כפול, containment כפול. T3 לא מקבל "elevation" — הוא רק חולק את inbox ה-T2 + hunt-console; הערך הייחודי שלו (ציד-עומק) תלוי לגמרי ביוזמה עצמית, שום דבר לא **מוסר לו** עבודה. Manager מקבל עבודה רק בסוף.
**המלצה:**
- **claim על הסלמה** (כמו soft-claim של T1) — כש-T2 מאשר-קבלה, ההסלמה מסומנת "בטיפול ע"י X"; שאר ה-T2 רואים 🔒.
- **elevation מפורש ל-T3** — כפתור "Escalate to Tier-3 (deep hunt)" ב-`T2Console` שפולט `escalation.requested{to_role:t3}`, ותור נפרד "Elevations for you" ב-T3. כך יש relay אמיתי T2→T3 ולא שני תפקידים על אותו inbox.
- **routing ל-Manager מוקדם** — Manager צריך משימה מהדקה הראשונה: תור-triage-oversight ("N התראות high פתוחות ללא disposition · SLA") שמעסיק אותו בתיעדוף לפני שמגיעות בקשות-הכלה.

---

### 🟠 F4 — הדיבריף הוא scorecard, לא AAR מונחה (חצי-מהלמידה חסר)
**איפה:** `TeamReport` — מטריקות + רובריקה + CSV. **אין** את `§6.6 Hot-wash` של הספק: אין ציר-דו-מסלולי (תקיפה↑/תגובה↓), אין replay, אין "who-knew-what-when", אין 3-רגעי-מפתח, אין שאלות-פתוחות למדריך, אין sustain/improve, אין override-ניקוד, אין improvement-items שנשמרים.
**למה זה חשוב:** המחקר בספק עצמו (§1.2, Tannenbaum & Cerasoli) קובע ש-debrief **מונחה** משפר ביצועי-צוות ב-~25% (team-level d=1.20) — וזה פי-3 מ-debrief לא-מונחה. דו"ח-מספרים לבד לא מייצר את השיחה. מתאמן יוצא עם ציון, לא עם הבנה **מה קרה ולמה**.
**עוד פער-מדידה:** קריטריונים רבים ברובריקה מחזירים `n/a` (timeline accuracy, incident report, team organised, management pressure, SLA, FP-rate, time-to-publish, elevation) → Manager למשל מנוקד בפועל רק על workload/passdown/reopen. תפקידים נראים "לא-נמדדים".
**המלצה:**
1. **מסך hot-wash** אחרי End — ציר-דו-מסלולי מ-`session_events` (feed.event = תקיפה; escalation/containment/decision = תגובה) עם 3-רגעי-מפתח נגזרים-אוטומטית (ההסלמה-הראשונה, ההחלטה-על-הכלה, ה-inject-הקשה) + שאלה-פתוחה לכל אחד. זה בר-מימוש מהיומן הקיים בלבד.
2. **improvement-items עם owner-תפקיד** שנשמרים לסשן הבא (מזין פורמט "סבב-תפקידים").
3. לסגור לפחות את קריטריוני-ה-`n/a` שה-events שלהם כבר קיימים (team.organized ניתן לגזור מ-first case.assigned/decision; SLA מ-feed→disposition שכבר נמדד).

---

### 🟠 F5 — Coordination קבור: war-room מקופל, אין ערוץ-הנהלה, "מי מוביל" משתמע
**איפה:** `WarRoom` = tab שלישי בתוך accordion "Team context" **מקופל כברירת-מחדל**. אין Mgmt-channel נפרד. `team.organized` (מי המוביל) לא נלכד כ-milestone (רובריקה: n/a).
**מה קורה בפועל:** תקשורת טבעית לא קורית כי הערוץ חבוי — הצוות ימשיך לתאם ב-Zoom/כיתה חיצוני, וה-AAR מפספס את "who-knew-what-when". אין רגע-פתיחה של "This is X, I'm the incident lead" — הבעלות על האירוע משתמעת מהרשאות, לא מוצהרת.
**המלצה:**
- לחשוף war-room כפאנל-קבוע (לא accordion) לפחות ל-Manager/T3, או pin לתחתית — הוא נדרש ל-15% מציון-ה-Coordination.
- **ritual פתיחה** בלובי: הצוות מסמן "מי ה-Incident Commander" → פולט milestone (`team.organized`) → מזין רובריקה + נותן בעלות מפורשת.
- ערוץ-הנהלה קצר ל-Manager (יעד ל-mgmt-pressure injects).

---

### 🟠 F6 — כשל-שקט: אף אחד לא מסלים את ההתקפה = אין שום סימן עד הדו"ח
**איפה:** הפיד מתנגן לפי לוח-זמנים ללא תלות בפעולות-הצוות; אין consequence-model, אין guiding-inject אוטומטי (הוסר), אין "attack succeeded" mid-exercise.
**מה קורה בפועל:** צוות שמפספס את ההתקפה מקבל פידבק רק ב-End ("detected: No"). אין לולאת-תיקון תוך-כדי. בלי מדריך פעיל שמבחין — הזדמנות-הלמידה הגדולה ביותר (ההחמצה) עוברת בשקט.
**המלצה:** guiding-inject אוטומטי ברמת-הצוות (F2.1) פותר גם את זה: אם אין `escalation.requested` על attack-event עד t+N, מוזרק inject ("User reports files encrypting on FIN-WS-07") שמכריח את הצוות חזרה למסלול — וגם נספר לרעה קטנה ברובריקה (green-team-assist).

---

### 🟠 F7 — ניתוק תפקיד single-seat עוצר את ה-relay; אין reassign
**איפה:** T3 ו-Manager הם single-seat (`SINGLE_SEAT` ב-`team/page.tsx`). אין reassign-role מהמדריך בזמן-ריצה, אין AI-backfill.
**מה קורה בפועל:** אם Manager מתנתק — אין מי לאשר הכלה, ה-relay נעצר (יש back-compat ל-`lead` אבל הוא לא ניתן-להקצאה ב-UI). T1 מתנתק → אף אחד לא מסלים. presence מציג ניתוק, ה-poll משחזר events בחזרה, אבל **תפקיד-חסר לא מתמלא**.
**המלצה:**
- **reassign-role מהמדריך** בזמן-ריצה (הכי חשוב ל-single-seat).
- fallback: אם Manager offline > N דק', לאפשר ל-T3 לאשר הכלה (ה-inject "Lead נותק" של הספק) — הגייט כבר מתיר lead/mgr; צריך רק hand-over-command ב-UI.

---

### 🟡 F8 — לובי בלי briefing/objectives; המתאמן מתחיל "קר"
**איפה:** `team/page.tsx`/`[id]` לובי = company + difficulty + roster בלבד. ה-ROE הוא משפט-אחד על כרטיס-ה-ready. אין objectives, אין תיאור-פורמט, אין "מה נחשב הצלחה".
**מה קורה בפועל:** בלי מדריך שמסביר, הצוות לא יודע מה סוג-האירוע הצפוי, כמה זמן, ומה המטרה. (חלק מזה מכוון — no-answer-leakage — אבל objectives≠spoilers.)
**המלצה:** כרטיס-briefing בלובי: משך-משוער, פורמט (משמרת-צוות), 3 objectives ברמת-תהליך ("keep the queue clean · escalate with evidence · contain the right host"), והרובריקה הגלויה (שקיפות-ניקוד — הספק §6.1: 42% מתלונות Locked Shields = ניקוד-סמוי).

---

### 🟡 F9 — drift בין הספקים לקוד; ופער-הרשאה חשוד ב-staff.inject
**איפה:**
- **doc-drift:** הבילד צומצם ל-{t1,t2,t3,mgr} (`team/page.tsx`), אבל הספקים עדיין מתארים בהרחבה 7 תפקידים כולל Lead/DE/TI. הקונסולות DE/TI/Lead קיימות בקוד (back-compat) אך **לא ניתנות-להקצאה** ב-UI → לעולם לא בשימוש בסשן חדש. מבלבל לקורא-הספק.
- **🟡 חשוד (דורש החלטה):** `staff.inject` מגודר בשרת ל-`p_role = 'instructor'` **בדיוק** (0059), אבל `InstructorPanel` מרונדר ל-`me.is_staff || me.role === "instructor"`. platform-admin/org_admin שה-member-role שלו אינו literally "instructor" יראה את ה-composer אבל יקבל `action_not_allowed` בשליחה. יוצר-הסשן מתווסף כ-instructor, אז ב-happy-path זה עובד — אבל super-admin שמצטרף לסשן של אחר ייתקל בזה.
**המלצה:** ליישר את הספקים ל-role-set הנוכחי (או להחזיר Lead/DE/TI כניתנים-להקצאה); ולהחליט אם `staff.inject` צריך להתיר גם `is_session_staff` ולא רק role='instructor'.

---

## 3. איך להריץ את התרגיל טוב יותר (שינויי שיטה/פורמט)

הבעיה השורשית: **המכניקה מצוינת, השיטה סטטית.** היום זה relay-יחיד רגוע שדורש מדריך-סופר-פעיל כדי להרגיש חי. ארבעה שינויי-פורמט הופכים אותו לתרגיל-צוות אמיתי:

1. **מ"אירוע-אחד" ל"משמרת עם ≥2 אירועים במקביל."** decoy + real, בזמנים שונים. זה לבדו פותר דד-טיים, מכריח תיעדוף (Manager), ונותן עבודה לכל T1/T2 עודף. **השינוי בעל ההשפעה הגבוהה ביותר.**

2. **MSEL אוטומטי מובנה בכל סטורי.** 3–5 injects מתוזמנים + guiding-inject-לצוות-תקוע. הופך "מדריך חייב להקליד" ל"התרגיל מריץ את עצמו, המדריך מכוונן." זה מה שמאפשר run-through **בלי facilitator** — שזו מטרת-העל.

3. **relay מנותב-תפקיד.** claim-על-הסלמה + elevation-מפורש-ל-T3 + oversight-queue-ל-Manager. כל תפקיד מקבל עבודה **שנמסרת אליו**, לא inbox משותף שגורם לעבודה-כפולה.

4. **דיבריף = שיחה, לא מספרים.** מסך hot-wash מונחה (ציר-דו-מסלולי + 3-רגעים + שאלות-פתוחות + improvement-items) — פי-3 למידה לפי המחקר של הספק עצמו.

**פורמטים עתידיים שהמכניקה כבר כמעט תומכת בהם:**
- **מסירת-משמרת (פורמט B):** ה-passdown המובנה כבר קיים — חסר רק צוות-שני-מקבל. רץ 2×40 דק' על אותו seed.
- **צוות-מול-צוות (פורמט C):** אותו seed לכמה חדרים, השוואה ב-AAR — deterministic-timeline כבר מאפשר זאת.
- **סבב-תפקידים (פורמט D):** improvement-items-נשמרים (F4.2) + מדידת-דלתא בין-סשנים.

---

## 4. Roadmap מתועדף (quick wins → structural)

### P0 — Quick wins (השפעה גבוהה, מאמץ נמוך; בעיקר UI/timeline על מכניקה קיימת)
- **claim על הסלמה** (F3) — לשכפל את soft-claim של T1 להסלמות; מונע עבודה-כפולה של multi-T2. **S**
- **war-room גלוי** (F5) — להוציא מ-accordion לפאנל-קבוע/pinned. **S**
- **briefing + רובריקה-גלויה בלובי** (F8) — כרטיס objectives + טבלת-ניקוד. **S**
- **ritual "מי מוביל" בלובי** → `team.organized` milestone (F5) — סוגר גם קריטריון-רובריקה n/a. **S**
- **החלטה על באג-ההרשאה** `staff.inject` (F9) — להתיר `is_session_staff`. **S**
- **טיימר-משמרת רך + SLA-tag על high פתוחים** בשורת-הסטטוס (F2.2/2.3) — מחזיר לחץ בלי clutter. **S–M**

### P1 — Core method (השינויים שהופכים אותו לתרגיל-צוות אמיתי)
- **incident שני (decoy + real) לכל סשן** (F1) — multi-case ב-Shared Case + הזרקת סטורי-שני ב-`buildTimeline`. **M–L**
- **MSEL אוטומטי + guiding-inject-לצוות-תקוע** (F2/F6) — injects מתוזמנים ב-timeline; contingency-inject אם אין הסלמה עד t+N. **M**
- **elevation מפורש ל-T3 + oversight-queue ל-Manager** (F3) — relay מנותב אמיתי; מסיר דד-טיים. **M**
- **מסך hot-wash מונחה** (F4) — ציר-דו-מסלולי + 3-רגעים + improvement-items, הכל מהיומן. **M–L**
- **reassign-role + hand-over-command בזמן-ריצה** (F7) — עמידות לניתוקים. **M**

### P2 — Structural (פורמטים חדשים + עומק)
- **פורמט B (מסירת-משמרת)** — צוות-שני-מקבל-passdown; ה-passdown כבר מובנה. **L**
- **פורמט C (צוות-מול-צוות)** + leaderboard opt-in — deterministic-seed כבר תומך. **L**
- **AI SimCell/personas** (help-desk/CISO/עיתונאי) — curveballs חיים במקום inject-טקסט. **L**
- **פורמט D (סבב-תפקידים)** + מדידת-דלתא-בין-סשנים — למידה-לאורך-זמן. **L**
- **facilitator console מלא** — MSEL-timeline, pressure-dials, "stuck team" heuristic, SA-board, multi-room. **L**

---

## 5. עובד טוב — לא לגעת
- הפיד המשותף + reconcile (Broadcast-from-DB + poll 6s) — G-19, יציב.
- role-gating בשרת (`session_action_allowed`) — G-20, ליבת-האבטחה תקינה.
- לובי + ready-check מגובב (presence + N/N + countdown) — G-21, ממומש יפה.
- onboarding סולו (`RoleGuideModal` + directive-banner) — מתאמן לא תקוע ב"מה עכשיו".
- דו"ח נגזר-מיומן + CSV + רובריקה 0/4/8/12 — בסיס-הערכה אמין וניתן-לשחזור.
- soft-claim T1, escalation state-machine (ack/bounce/resolve), scope set→confirm, containment request→approve→execute — ה-relay-core בנוי היטב; חסרים לו רק ניתוב, אירוע-שני, לחץ ודיבריף.
