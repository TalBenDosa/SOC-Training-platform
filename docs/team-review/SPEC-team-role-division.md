# אפיון — חלוקת תפקידים וחלוקת עבודה ב-Team-SOC

**תאריך:** 2026-09-23
**מטרת המסמך:** אפיון מלא של **חלוקת התפקידים** ו**חלוקת העבודה** באימון הצוותי — במיוחד:
מה קורה כשיש **יותר מאנליסט Tier-1 אחד**, או **יותר מאנליסט Tier-2 אחד**? איך העבודה
מתחלקת ביניהם, מי עובד על מה, ואיך נמנעת עבודה כפולה.
**סטטוס:** תיאור המצב הקיים בקוד (grounded ב-`src/app/(app)/team/[id]/page.tsx`) + פערים
והמלצות בסוף. staging-only.

---

## 0. תקציר מנהלים (TL;DR)

מודל חלוקת-העבודה בפיצר הוא **"משיכה עם מניעת-התנגשות"** (pull-based self-dispatch with
collision-avoidance), לא **"דחיפה/הקצאה"** (push/assignment). כלומר:

- **אין דיספצ'ר שמחלק התראות לאנליסטים ספציפיים.** אין "התראות 1–10 לאנליסט א'".
- כל האנליסטים באותו טיר רואים **תור/inbox משותף** אחד (מקור-אמת משותף).
- כל אנליסט **מושך** את הפריט הבא (בד"כ מראש התור) ומתחיל לעבוד עליו.
- **מנגנון נעילה רך** מונע ששני אנליסטים יעבדו על אותו פריט: ב-Tier-1 זה soft-claim
  (`alert.claimed`), ב-Tier-2 זה "מי שאישר ראשון תפס" (first-`escalation.acknowledged`).
- כשאנליסט אחר רואה פריט "תפוס", מוצג לו מי מחזיק בו + כפתור **Take over** (השתלטות).

זה מודל ריאליסטי ל-SOC אמיתי (analyst pulls from the queue), אבל כרגע הוא **פסיבי** —
המערכת מונעת התנגשות אבל לא **מאזנת עומסים באופן פעיל** (ראו §7).

---

## 1. מודל המושבים (Seats) לפי תפקיד

| תפקיד | קוד | מספר מושבים | תפקיד עיקרי | Console |
|---|---|---|---|---|
| **Tier-1** | `t1` | **מרובה (N)** | טריאז' של תור ההתראות, הסלמה של האמיתיים עם ראיות | `T1Console` |
| **Tier-2** | `t2` | **מרובה (N)** | לקיחת הסלמות מה-inbox, חקירה לעומק, בקשת containment + כתיבת דוח | `T2Console` |
| **Tier-3** | `t3` | **יחיד (1)** | ציד מתקדם (hunting), אישור scope, ייעוץ ל-T2 | `HuntConsole` + inbox משני |
| **SOC Manager** | `mgr` | **יחיד (1)** | תיאום, אישור/דחיית containment, הקצאת owner לתיק, SITREP, סגירה | `MgrConsole`/`LeadConsole` |
| instructor / observer | — | יחיד/מרובה | בעל-הסשן / צופה (לא נספר לכיסוי) | `InstructorPanel` |

תאימות-לאחור: `lead`≈`mgr`, `de`≈`t2`, `ti` (threat-intel) קיימים כשאריות.

**למה T1 ו-T2 מרובים, ו-T3/Manager יחידים?** כי חלוקת-העבודה רלוונטית רק היכן שיש
**נפח מקבילי**: הרבה התראות גולמיות (עבודת T1) והרבה תיקים בחקירה (עבודת T2). Tier-3
והמנהל הם **נקודות התכנסות** (convergence) — יש דבר אחד מכל אחד כדי לשמור על החלטה
אחידה ו-span-of-control נקי.

**זרימת-העל** (מתוך `OVERALL_FLOW`, `page.tsx:48`):
> Tier-1 מטרייג' את תור ההתראות ומסלים את האמיתיים עם ראיות → Tier-2 מאשר, חוקר לעומק
> ומבקש containment → Tier-3 צד עמוק יותר ומאשר scope → SOC Manager מאשר containment,
> מתעד החלטות ו-SITREP ומוביל לסגירה. **כולם עובדים על Shared Case אחד.**

---

## 2. הלב: איך העבודה מתחלקת (העיקרון)

חלוקת-העבודה בנויה על **שלוש שכבות**:

1. **תור/Inbox משותף** — כל האנליסטים באותו טיר רואים את אותה רשימה, ממוינת לפי
   דחיפות. זה ה-shared mental model: כולם רואים מה יש לעשות.
2. **משיכה עצמית (self-dispatch)** — אנליסט בוחר פריט (בד"כ מהראש) ומתחיל. אין הקצאה
   מלמעלה.
3. **מניעת-התנגשות (collision-avoidance)** — ברגע שאנליסט לקח פריט, השאר רואים שהוא
   תפוס וע"י מי, כך שלא נעשית עבודה כפולה. תמיד יש דרך **להשתלט** (Take over) אם צריך.

ההבדל בין הטירים הוא **במימוש הנעילה**:
- **Tier-1:** נעילה רכה על **התראה** (`alert.claimed` / `alert.released`).
- **Tier-2:** נעילה מרומזת דרך **אישור** (`escalation.acknowledged` = תפיסה).

---

## 3. חלוקת עבודה כשיש כמה Tier-1 (הפירוט)

### 3.1 מה כולם רואים
- **תור התראות משותף (B6)** — `queue`, `page.tsx:1081`. מכיל את כל ההתראות ב-severity
  `high`/`critical` שעדיין לא קיבלו disposition, ממוין לפי **severity × ותק** (`score =
  rank × (1 + mins/5)`), הכי דחוף למעלה, עם תג SLA. **התור זהה לכל ה-T1** — אין תור אישי.
- **הפיד המשותף המלא** — לבחירת כל לוג (`options`, `page.tsx:1107`), לא רק ה-highs.

### 3.2 איך נמנעת עבודה כפולה — soft-claim
- כש-T1 פותח דוח על התראה, המערכת **תופסת אותה אוטומטית** (`reportOpen && sel &&
  !selClaim → act("alert.claimed")`, `page.tsx:1153`) — "כדי ששני Tier-1 לא יעבדו על
  אותו לוג".
- T1 אחר שבוחר את אותה התראה רואה: **"🔒 claimed by [שם]"** + כפתור **Take over**
  (`page.tsx:1241`). הפיד עצמו מציג תג "claimed by other" (`rowStatus`, `page.tsx:554`).
- **תפיסה חיה ~5 דקות** (`CLAIM_TTL = 5*60*1000`, `page.tsx:1090`). אחרי-כן היא פגה
  אוטומטית — כדי שאנליסט שנטש/יצא לא ינעל התראה לנצח.
- **שחרור התפיסה** קורה ב-3 דרכים:
  1. **disposition** (סיווג ההתראה) — משחרר מיד (`page.tsx:1103`).
  2. **סגירה כ-FP/Benign** ב-Tier-1 — "release any soft claim so a teammate can reuse
     the row" (`page.tsx:1159`).
  3. **הסלמה** — אחרי escalate מבוצע `alert.released` כדי "למסור את התפיסה" הלאה
     (`page.tsx:1177`).
- **Release ידני** — כפתור "Release" זמין כשאתה המחזיק (`page.tsx:1245`).

### 3.3 התוצאה בפועל (תרחיש 3× Tier-1)
1. שלושה T1 רואים תור זהה של, נניח, 12 התראות high/critical.
2. דנה פותחת #1 → #1 ננעל לה (🔒). יוסי רואה #1 נעול, מדלג ל-#2. רון לוקח #3.
3. הם עובדים במקביל **בלי לתאם ידנית** — הנעילה הרכה עושה את התיאום.
4. דנה מסלימה את #1 → התפיסה משתחררת, #1 עובר ל-inbox של Tier-2, והתור של T1 מתקצר.
5. אם דנה נתקעת/יצאה, אחרי 5 דק' #1 נפתחת שוב לכל T1, או שיוסי לוחץ **Take over** מיד.

> **מה זה כן / מה זה לא:** זהו מודל **פול קואופרטיבי** — כל אחד מושך מהראש, נמנעות
> התנגשויות. זה **לא** מודל שמקצה לכל T1 מכסה או פרטישן קבוע, ו**לא** מאזן פעיל
> (אם דנה איטית ויוסי פנוי — המערכת לא תעביר לו את #1 יזומה; הוא צריך לבחור להשתלט).

---

## 4. חלוקת עבודה כשיש כמה Tier-2 (הפירוט)

### 4.1 מה כולם רואים
- **Inbox הסלמות משותף אחד** — "Escalations for you (N)" (`page.tsx:1433`). מכיל את כל
  מה ש-Tier-1 הסלים (`escalations`, `page.tsx:493`). **אין inbox אישי לכל T2.**
- **מיון לפי עדיפות** (`prioritized`, `page.tsx:1419`): תיקים פתוחים קודם, ואז ציון
  `severity × זמן-המתנה × confidence × (contain? 1.5)` (`prioKey`, `page.tsx:1409`).

### 4.2 איך נמנעת עבודה כפולה — first-acknowledge-claims
- **אישור = תפיסה.** ה-`ackedBy` map רושם מי **אישר ראשון** כל הסלמה (`page.tsx:500`),
  "כדי ש-Tier-2 שני יראה שהתיק כבר בעבודה ולא יטפל בו כפול".
- T2 שני שמסתכל על תיק שכבר אושר ע"י אחר רואה אינדיקציה **"being worked by [שם]"**
  (`page.tsx:1490` — `claimer && claimer !== meId`).
- **התיקים שלי** = `myCases` (`page.tsx:1423`): הסלמות שה-T2 הזה **אישר ולא סגר**. רק
  עליהן הוא יכול לכתוב דוח (`report.submitted`), לבקש containment, ולסגור. כלומר, אחרי
  שאתה מאשר תיק — הוא **שלך** לאורך מחזור-החיים שלו.

### 4.3 התוצאה בפועל (תרחיש 2× Tier-2)
1. שני T2 רואים inbox זהה עם 5 הסלמות ממוינות.
2. מאיה מאשרת (ack) את ההסלמה הדחופה ביותר → היא הופכת ל"תיק של מאיה"; עידו רואה עליה
   "being worked by מאיה" ומדלג להסלמה הבאה.
3. כל אחד חוקר את התיקים שאישר, כותב דוח, מבקש containment מהמנהל, מסלים ל-T3 אם צריך.
4. אין השתלטות אוטומטית — אם מאיה עמוסה ב-3 תיקים ועידו פנוי, **החלוקה תלויה בהם**
   (עידו יאשר את הבאים בתור), לא במערכת שתאזן.

> **הבדל עדין מ-Tier-1:** ב-T1 התפיסה **רכה וזמנית** (5 דק', משוחררת בסיווג) כי
> ההתראה מהירה. ב-T2 התפיסה **מחזיקה לאורך התיק** (עד resolve) כי חקירה היא עבודה
> ארוכה שאתה "הבעלים" שלה. שני דגמים שונים לשני אורכי-עבודה שונים — וזו החלטת-עיצוב
> נכונה.

---

## 5. Tier-3 והמנהל — נקודות התכנסות (לא חלוקה)

- **Tier-3 (יחיד):** מקבל **תור elevations נפרד** (`elevation.requested`, `page.tsx:507`)
  — "כדי ש-T3 יקבל עבודה שנמסרת אליו, לא רק inbox משותף". ה-inbox הרגיל משני ומקופל
  אצלו כברירת-מחדל (`inboxOpen = role!=="t3"`, `page.tsx:1401`) כי **הציד הוא הפעולה
  הדומיננטית** שלו. אין כאן "חלוקה" — יש מושב אחד.
- **SOC Manager (יחיד):** נקודת-ההחלטה. מאשר/דוחה containment, **מקצה owner לתיק**
  (`case.assigned`, `page.tsx:930`), מתעד SITREP ומוביל לסגירה. הוא ה**כן**-דיספצ'ר
  היחיד במערכת: הקצאת owner ל-Shared Case היא הפעולה ה"דוחפת" היחידה. span-of-control:
  מנהל אחד מרכז את כל האנליסטים (ראו §7 לגבי מגבלת 3–7 של NIMS).

---

## 6. טבלת סיכום — מודל החלוקה לפי טיר

| היבט | Tier-1 (מרובה) | Tier-2 (מרובה) | Tier-3 (יחיד) | Manager (יחיד) |
|---|---|---|---|---|
| מה משותף לכולם | תור התראות + פיד | inbox הסלמות | — | Shared Case |
| יחידת-העבודה | התראה (alert) | תיק/הסלמה (case) | elevation / hunt | ההחלטה + התיק |
| מנגנון תפיסה | soft-claim (`alert.claimed`) | first-ack (`escalation.acknowledged`) | תור נפרד | מקצה owner |
| משך התפיסה | ~5 דק' / עד disposition | עד resolve (התיק שלך) | — | — |
| השתלטות | "Take over" (`:1241`) | ack ע"י אחר (נדיר) | — | reassign |
| שחרור | disposition / FP / escalate / ידני | resolve | — | — |
| מודל | pull + collision-avoidance | pull + ownership | convergence | dispatch נקודתי |

---

## 7. מעבר לחלוקה פעילה — **מיושם** (2026-09-23)

חלוקת-העבודה הייתה **תקינה וריאליסטית אך פסיבית** (מונעת-התנגשות, לא מאזנת-עומסים).
חמשת השיפורים הבאים הפכו אותה ל**"איזון-עומסים פעיל"** — קשורים ישירות למחקר ב-
[`RESEARCH-2026-09-23-team-training-design.md`](RESEARCH-2026-09-23-team-training-design.md)
(Salas: *mutual performance monitoring* + *backup behaviour*). **כולם יושמו** (staging-only;
תוכנית מלאה: `~/.claude/plans/hazy-juggling-acorn.md`). מיפוי מלא של הקוד בנספח §8.

1. **[High] ✅ ניטור-הדדי פעיל למנהל.** ה-`SituationBoard` כבר לא רק **מציג** עומס — נוסף
   כרטיס **"Rebalance load"** שמזהה אנליסטים עמוסים (≥`OVERLOAD_CASES`=3 תיקים פתוחים,
   כולל עומס-`claim` של T1) ומאפשר למנהל ללחוץ **Nudge**. הניטור הפך מתצוגה לפעולה.
2. **[High] ✅ קרדיט-צוותי על איזון-עומסים (backup behaviour).** נוסף תא רובריקה
   **"Backup & load-balancing"** ל-T1 ול-T2: T1 מזוכה על *Take-over* של התראה מעמית; T2
   מזוכה על לקיחת תיק כשעמית **מאותו טיר** עמוס. **null כשאפס → לא מעניש** throughput נמוך
   של מי שגיבה. למנהל: תא **"Load balancing"** שמודד *כיסוי אפיזודות-עומס בנדנודים* (לא
   ספירה גולמית → אין תמריץ לספאם).
3. **[Medium] ✅ "Take next" (assisted pull).** כפתור ב-T1 (מושך את ההתראה הדחופה ביותר
   שלא נתפסה → פותח דוח שתופס אוטומטית) וב-T2 (**"Take next case"** → מאשר את התיק הפתוח
   הדחוף ביותר). מונע ששניים יקפצו על אותו פריט ומקטין פריטים-יתומים.
4. **[Medium] ✅ span-of-control למנהל.** אזהרה ב-Situation Board כשמנהל מתאם >`MAX_SPAN`=7
   אנליסטים מחוברים (NIMS/ICS 3–7). מטריקת "Online" עוברת ל-tone אזהרה.
5. **[Low] ✅ מדד "פריט יתום".** תג **⚠ unclaimed** על התראת high/critical שעברה SLA, לא
   נתפסה ולא הוסלמה — ממוינת לראש התור. משלים את ה-`guidingNudgeMins` הכללי (`:520`) ברמת
   הפריט הבודד.

**אירוע/מיגרציה חדשים:** `coordination.nudge` (mgr/lead, running) נוסף ל-
`session_action_allowed` במיגרציה `0068_team_coordination_nudge.sql` (הוחל ל-staging; הגייט
אומת). כל השאר client-only מעל אירועים קיימים.

**סטטוס אימות:** שערים ירוקים (tsc · vitest 157/157 · validate:content/feed/logs · build ·
rooms-meta ללא drift) + בדיקת-גייט של המיגרציה. ה-playthrough החי של 2× T1 טרם הורץ (auth
של staging תקוע ב-sandbox) — לבדיקה מומלצת ב-dev עם שני דמו-פלייארים.

**מה לשמר כמו שהוא:** מודל ה-pull + soft-claim + first-ack הוא נכון וריאליסטי; ה-TTL
של 5 דק' מונע נעילות-יתומות; ה-Shared Case כמקור-אמת יחיד; והפרדת T3/Manager למושבים
יחידים ששומרת על החלטה אחידה.

---

## 8. נספח — הפניות קוד (`src/app/(app)/team/[id]/page.tsx`)

> מס' השורות **מקורב** (יישום §7 מ-2026-09-23 הזיז שורות) — חפש לפי שם-הסמל.

**מנגנוני החלוקה הקיימים (§2–§5):**

| מנגנון | סמל / עוגן |
|---|---|
| זרימת-העל | `OVERALL_FLOW` |
| תור התראות T1 | `const queue = feed…` |
| soft-claim | `CLAIM_TTL`, `claims`, `claimerOf` |
| auto-claim בפתיחת דוח | effect עם `reportOpen && sel && !selClaim` |
| release ב-FP / escalate | `alert.released` (ב-`disp`/`escalate`) |
| UI "🔒 claimed by / Take over" | `selClaim` block ב-`T1Console` |
| first-ack claims T2 | `ackedBy` |
| תור elevations ל-T3 | `elevations`, `elevation.requested` |
| inbox ממוין של T2 | `prioritized`, `prioKey` |
| התיקים שאישרתי | `myCases` |
| "being worked by [name]" | `ackedBy.get(eid)` render |
| הקצאת owner ע"י המנהל | `case.assigned` |

**מנגנוני החלוקה הפעילה (§7, מיושם):**

| שיפור | סמל / עוגן |
|---|---|
| ניטור-הדדי + Nudge (מנהל) | `SituationBoard` → `overloaded`, `nudge()`, כרטיס "Rebalance load" |
| באנר Nudge לצוות | `activeNudge` (רכיב האב) → באנר במסך running |
| ספי עומס | `OVERLOAD_CASES = 3`, `MAX_SPAN = 7` |
| עומס-T1 ב-loadByUser | פסקת "Tier-1 open-work load" ב-`team` useMemo |
| קרדיט גיבוי (חישוב) | פסקת "Work-division / backup metrics" ב-`computeReport` (`takeoverByUser`, `backupAckByUser`, `loadBalanceRate`) |
| תאי רובריקה חדשים | `roleRubric`: "Backup & load-balancing" (t1/t2), "Load balancing" (mgr) |
| שדות RubricCtx | `backupCount`, `loadBalanceRate` |
| "Take next" (T1) | `takeNext()`, `queueDisplay` |
| "Take next case" (T2) | `nextUnacked`, `takeNextCase()` |
| span-of-control | `spanWarn` (Situation Board) |
| תג "⚠ unclaimed" | `isOrphan()`, `queueDisplay` (orphan-first) |
| מיגרציה + gate | `supabase/migrations/0068_team_coordination_nudge.sql` (`coordination.nudge`) |

*Cross-ref: `RESEARCH-2026-09-23-team-training-design.md` (Part 2 & Part 6),
`AGENT-PLAYTEST-2026-09-19-team.md`, `MASTER-SYNTHESIS.md`.*
