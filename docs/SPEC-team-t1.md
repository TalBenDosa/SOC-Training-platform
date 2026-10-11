# אפיון מקיף — Tier‑1 Analyst (אימון צוותי)

> אפיון-מוצר מלא לתפקיד אנליסט Tier‑1 בחדר-האימון הצוותי של HACK THE SOC.
> נכתב לפי ראיון-אפיון עם Tal (2026‑09‑15). מתאר את מסך-העבודה, מחזור-חיי
> ההתראה, הסיווג, דו״ח-ההסלמה, שער-האיכות, המסירה ל-Tier‑2, והמדידה — עם מיפוי
> ל-`session_events` ולפערים מול הבילד הקיים. משלים את `docs/SPEC-team-ux-ui.md`
> (המסמך הרוחבי) ואת `docs/SPEC-team-roles-playbook.md`. סולם-ניקוד: 0/4/8/12.

---

> **סטטוס מימוש (2026-09-15): T1-1…T1-8 מומשו במלואם** ואומתו חי (מיגרציה 0060 על staging;
> tsc + 157/157). כולל: פיד גולמי, Claim/Assign (`alert.claimed`/`released`), סיווג רביעי
> **Suspicious**→low-confidence, דו״ח מובנה (Summary·Observations·IOCs·Assessment·Recommended·Severity),
> שדה IOCs (+IOC מהלוג + טקסט + זיהוי-סוג), שער-איכות קשיח (checklist חי), מצב Escalated + מעקב-סטטוס.
> **הערה:** סרגל-SLA (G-12) ובאנר-nudge (G-18) הוסרו מהתצוגה לבקשת Tal (העמיסו על המסך).

## 0. תמצית ההחלטות (from the elicitation)

| תחום | ההחלטה |
|---|---|
| מודל-המסך | **פיד SIEM גולמי מלא** (לא alert-queue) |
| חלוקת-עבודה בין 2×T1 | **Claim/Assign** — נעילה רכה של התראה לאנליסט |
| אפשרויות-סיווג | **TP · FP · Benign · Suspicious — needs more info** |
| מחזור-חיים | **New → Dispositioned → Escalated** (claim = בעלות רכה, לא state) |
| טיפול ב-Suspicious | **מוסלם ל-T2 כ-lead בביטחון-נמוך** |
| דו״ח-ההסלמה | מובנה: **Summary · Observations · IOCs · Assessment · Recommended action · Severity** |
| צירוף-ראיות | **אירוע-טריגר אחד + שדה IOCs** (לחיצה-להוספה מהלוג + טקסט חופשי) |
| שער-איכות | **קשיח** — חובה: אינדיקטור + נימוק משמעותי + חומרה |
| מסירה ל-T2 | האירוע עובר ל-**Escalated** + **מעקב-סטטוס** (ack/bounced/resolved) על מסך ה-T1 |
| מדד-כותרת | **דיוק-סיווג מול ground‑truth** |

---

## 1. המשימה (mission)

T1 הוא **קו-החזית**: מסנן את זרם-ההתראות, קובע לכל אחת סיווג, ומעביר את האמיתיות
הלאה ל-Tier‑2 — **מגובות בדו״ח**. הוא **לא חוקר לעומק** (זה תפקיד T2/T3). המדד
המרכזי שלו: **דיוק-סיווג** — להבדיל תקיפה-אמיתית מרעש, ולהסלים אותות ולא ספקות.

מספר אנליסטים חולקים את אותו תור במקביל (בהרכב הנוכחי: 2×T1).

---

## 2. מה T1 רואה על המסך (screen)

עמודה-שמאלית = **הפיד הגולמי המלא** (רכיב `EventFeed` הזהה לדשבורד היחיד):

```
┌───────────────────────────────────────────────────────────┐
│ [directive banner] Triage the feed — set a disposition …  │  ← §5.8 ux-ui
│ [SLA bar] sh+crit clocks · N breached                     │  ← G-12
├───────────────────────────────────────────────────────────┤
│ Filters: [All][High][Med][Low]  [source ▾]  [search…]     │  ← G-04
│ ┌ Time  Agent      Source   Description        Lvl  Rule ┐ │
│ │ 12:03 WS-FIN-11  EDR      chrome.exe wrote…   8   HTS…  │ │  ← claimable rows
│ │  ▸ (expand → raw log + MITRE + pivot chips)            │ │
│ └───────────────────────────────────────────────────────┘ │
└───────────────────────────────────────────────────────────┘
        עמודה-ימנית = קונסולת Tier‑1 triage (§4)
```

**מרכיבים (קיימים היום ✅):** directive banner · SLA bar · פילטרים (severity/source/
search) + click-to-pivot · שורות מתרחבות עם raw + MITRE · טלמטריית click/dwell
(`event.opened`).

**חדש לתפקיד (🔧):** מחווני-**claim** על שורות שכבר נלקחו ע״י אנליסט אחר (§3).

### 2.1 Claim / Assign — חלוקת-עבודה בין 2×T1 (🔧 חדש)

כדי ששני אנליסטים לא יטפלו באותה התראה:
- כל שורת-פיד מקבלת פעולת **"Take"** (או קליק על אינדיקטור-בעלות). לחיצה → נעילה-רכה.
- שורה שנלקחה ע״י אחר מסומנת: `🔒 claimed by <name>` (עמומה מעט, אך עדיין נגישה
  לצפייה). לחיצה על שורה נעולה מציגה "מטופל ע״י X — לקחת בכל זאת?" (override מכוון).
- הנעילה היא **רכה** (ownership hint), לא state נפרד במחזור-החיים (§ההחלטה של Tal).
  פוקעת אוטומטית אם האנליסט מסווג/מסלים, מבטל, או מתנתק (timeout).
- Event חדש: `alert.claimed` / `alert.released` (payload `{event_id}`), gate: t1,
  running. מצב-הבעלות = פרוקציה מעל היומן (אחרון קובע), בדיוק כמו שאר ה-Shared Case.

---

## 3. מחזור-חיי ההתראה (lifecycle)

```
        ┌─────────┐   claim (רך)   ┌─────────────┐  TP/Suspicious   ┌────────────┐
  feed →│   NEW   │ ─────────────▶ │ DISPOSITIONED│ ───────────────▶│  ESCALATED │→ (T2)
        └─────────┘                └─────────────┘                  └────────────┘
                                     │ FP / Benign
                                     ▼
                                   CLOSED (נסגר ב-T1, נשאר ביומן)
```

- **NEW** — כל אירוע-feed שטרם סווג.
- **DISPOSITIONED** — T1 קבע TP / FP / Benign / Suspicious.
- **ESCALATED** — אירוע שהוסלם ל-T2 (TP או Suspicious). מסומן על מסך ה-T1 עם
  סטטוס-מעקב (§6).
- claim הוא **בעלות רכה** על-גבי NEW, לא state נפרד (החלטת Tal).

---

## 4. סיווג (disposition)

ארבע אפשרויות על כל התראה:

| סיווג | משמעות | מה קורה |
|---|---|---|
| **True Positive** | תקיפה/פעילות-זדונית אמיתית | חובה **להסלים** ל-T2 (עם דו״ח מלא, §5) |
| **False Positive** | התראת-שווא | נסגר ב-T1 (נשאר ביומן, לא מוסלם) |
| **Benign** | פעילות לגיטימית | נסגר ב-T1 |
| **Suspicious — needs more info** (🔧 חדש) | חשוד, לא ודאי | **מוסלם ל-T2 כ-lead בביטחון-נמוך** (`confidence` נמוך + תגית `low_confidence`) |

- Event: `disposition.set` (קיים) — payload `{event_id, verdict}` עם verdict מורחב:
  `true_positive | false_positive | benign | suspicious`.
- **אין** דרישת פתק-triage על FP/Benign (החלטת Tal: "כל מה שעובר ל-T2 מגובה בדו״ח")
  — הכתיבה מרוכזת בהסלמה בלבד.

---

## 5. דו״ח-ההסלמה (escalation report) — הלב של התפקיד

**כלל-הזהב (Tal): כל מה שעובר ל-Tier‑2 מגובה בדו״ח מובנה.** ההסלמה = הדו״ח.

### 5.1 מבנה הדו״ח (🔧 מורחב מהקיים)

| # | שדה | תיאור | חובה? |
|---|---|---|---|
| 1 | **Summary** | שורה אחת: מה קרה + על מי (`what` הקיים) | ✔ |
| 2 | **Observations** | מה נצפה — התהליך/הרצף/הראיה (`why` המורחב) | ✔ |
| 3 | **IOCs** | אינדיקטורים (§5.2) — לפחות אחד | ✔ (שער-איכות) |
| 4 | **Assessment** | הערכת-האנליסט: מה זה כנראה + confidence | ✔ |
| 5 | **Recommended action** | contain / investigate / monitor / escalate-to-mgr (`requested_action`) | ✔ |
| 6 | **Severity** | low / medium / high / critical (🔧 שדה חדש) | ✔ (שער-איכות) |

- `impact` + `confidence` הקיימים נשמרים (impact נכנס תחת Assessment; confidence נגזר
  מ-Suspicious=low). ה-`entity`/`hostname` האמיתיים כבר מצורפים אוטומטית (תוקן ב-nit #2/#3).
- Event: `escalation.requested` (קיים) — payload מורחב:
  `{event_id, summary, observations, iocs[], assessment, requested_action, severity, entity, hostname, confidence}`.
  (מיפוי-לאחור: `what`=summary, `why`=observations, נשמרים לתאימות.)

### 5.2 שדה ה-IOCs (🔧 חדש) — לחיצה-להוספה + טקסט חופשי

- בפאנל ה-raw של השורה הנבחרת, כל ערך-מפתח (host / user / IP / hash / domain) מקבל
  כפתור **"+ IOC"** — לחיצה מוסיפה אותו לרשימת-ה-IOCs של הדו״ח (מהיר ומדויק, בלי הקלדה).
- בנוסף, שדה-טקסט חופשי להוספת IOC ידני (אחד לשורה).
- כל IOC מקבל **זיהוי-סוג אוטומטי** (IP / domain / sha256 / email / host) לתצוגה ולניקוד-דיוק.
- מבנה: `iocs: [{ type, value, source: "picked"|"manual" }]`.

### 5.3 שער-איכות (quality gate) — קשיח (🔧)

לחצן **Escalate** נעול עד שמתקיימים **כל** התנאים:
1. **אינדיקטור אחד לפחות** ב-IOCs.
2. **נימוק משמעותי** — Observations ≥ 20 מילים (או סף שיוגדר; היום why ≥ 10 תווים).
3. **Severity** נבחר.
4. **Recommended action** נבחר.
- כל עוד חסר — הכפתור מציג tooltip "מה חסר להסלמה" (checklist חי).
- זה מלמד את הכלל המקצועי: **"escalate signals, not doubts"**.

---

## 6. מסירה ל-Tier‑2 ומעקב (hand-off & tracking)

אחרי **Escalate**:
- האירוע עובר ל-**ESCALATED** על מסך ה-T1 — מסומן בבירור (לא נעלם מהתור).
- T1 רואה **מעקב-סטטוס חי** של ההסלמה שלו:
  - `sent` → `acknowledged` (T2 לקח) → אחד מ: `bounced` (הוחזר עם סיבה) / `resolved` (נסגר).
- **bounced** → מופיע באזור "Bounced back to you" (קיים ✅) עם הסיבה; T1 מתקן ומסלים מחדש.
- זהו **טיקט עקיב** — סוגר את לולאת-המשוב T1↔T2 (המקור: `escalation.acknowledged` /
  `escalation.bounced` / `escalation.resolved`, כולם קיימים ✅).

---

## 7. מדידה (success metrics)

**מדד-הכותרת (החלטת Tal): דיוק-סיווג מול ground‑truth.**
- `disposition_accuracy` = אחוז ה-dispositions שתאמו את ה-`expected_verdict` של האירוע
  (TP-אמיתי→true_positive; benign/fp→false_positive|benign). זהו הקריטריון הדומיננטי בכרטיס.

קריטריונים משניים (נשמרים ברובריקה, משקל נמוך יותר — §3.f ב-ux-ui):
- Escalation precision (כמה הסלמות אושרו מול הוחזרו).
- Card/report completeness (כל השדות + IOC + severity).
- Time-to-triage (High/Critical).
- Help-desk tickets (אם הופעלו injects).

סולם 0/4/8/12 לכל קריטריון; קריטריון ללא-מדידה = `not yet measured` (מחוץ ל-%).

---

## 8. פערים מול הבילד הקיים (build tasks)

| # | פריט | קיים? | מה נדרש |
|---|---|---|---|
| T1-1 | פיד גולמי + פילטרים + pivot + dwell | ✅ | — |
| T1-2 | סיווג TP/FP/Benign | ✅ | להוסיף **Suspicious** (verdict רביעי) → מסלים low-confidence |
| T1-3 | **Claim/Assign** (נעילה רכה + מחוונים) | ❌ | `alert.claimed`/`alert.released` + UI-בעלות בשורות |
| T1-4 | דו״ח מובנה (Summary/Observations/IOCs/Assessment/Action/Severity) | 🔧 חלקי | להרחיב את טופס-ההסלמה + payload; היום what/why/impact/conf/req_action |
| T1-5 | **שדה IOCs** (click-to-add + free text + typing) | ❌ | כפתורי "+IOC" ב-DetailPanel + שדה + `iocs[]` בסכמה |
| T1-6 | **שער-איכות קשיח** (IOC + נימוק + severity) | 🔧 | היום why≥10 תווים בלבד; להוסיף checklist-חי + severity |
| T1-7 | מצב **Escalated** + מעקב-סטטוס על מסך T1 | 🔧 חלקי | היום "bounced back" בלבד; להוסיף תצוגת sent/ack/resolved להסלמות-שלי |
| T1-8 | מדד-כותרת = disposition accuracy | ✅ | כבר ברובריקה; להדגיש ככותרת-הכרטיס |

**מיגרציית DB צפויה (0060):** gate ל-`alert.claimed` / `alert.released` (t1, running).
(שאר השינויים הם payload/UI — `disposition.set` ו-`escalation.requested` כבר מגודרים.)

---

## 9. סדר-בנייה מומלץ

1. **T1-2** (Suspicious verdict → low-confidence escalation) — קטן, ערך-מיידי.
2. **T1-4 + T1-5 + T1-6** (הדו״ח המובנה + IOCs + שער-איכות) — הליבה שביקש Tal.
3. **T1-7** (Escalated + מעקב-סטטוס) — סוגר את לולאת-המסירה.
4. **T1-3** (Claim/Assign) — דורש מיגרציה 0060; מונע כפילות בהרכב 2×T1.
5. **T1-8** — התאמת כותרת-הרובריקה.

---

## 10. שאלות פתוחות להמשך

- סף "נימוק משמעותי" המדויק לשער-האיכות — 20 מילים? או N תווים? (כרגע: 20 מילים לניקוד-מלא).
- timeout לפקיעת claim אוטומטי (למשל 5 דק׳ ללא פעולה)?
- האם "override" של claim (לקיחה בכפייה) דורש אישור/נרשם ביומן?
- האם Suspicious→T2 צריך תור נפרד אצל T2, או משתלב בתור-ההסלמות הרגיל עם תגית low-confidence?
