# מפת ריאליזם — עד כמה הפלטפורמה דומה ל-SOC אמיתי, ומה לשפר

> סינתזה של פליטת סוכני הריאליזם (operations · tooling · ir-comms · threatscape). כל טענה מגובה בקוד. עודכן 2026-08-11.

## התובנה המרכזית
**מנוע הטלמטריה והתוכן כבר קרובים מאוד למציאות** — נאמנות הלוגים (raw בפורמט vendor-מדויק), מנוע ה-Threat-Intel drawer, מנוע הרעש/FP, ותזמון התקיפות הם ברמה מקצועית. **פער הריאליזם כמעט כולו במעטפת שסביב זה:**
1. **מעטפת זרימת-העבודה** (queue → case → escalate → handover) — חסרה.
2. **עומק אינטראקציה** (pivot בקליק, process-tree, הרצת שאילתה, playbook בזרימה) — רדוד.
3. **תיקוני נכונות/עדכניות בתוכן** — hashes מזויפים, נוף 2025 חסר, הפרות SPEC ישנות.

הרוב המכריע של ה-quick wins **מנצל קומפוננטות ונתונים שכבר קיימים**.

## ציון ריאליזם לכל ממד (1–5)
| ממד | ציון | למה |
|---|---|---|
| **תפעול יומיומי** | ⚠️ 2.5 | טלמטריה מצוינת, אבל החוויה היא "ציד אירוע בודד" ולא משמרת מונחית-תור |
| **כלים וקונסולות** | 🟨 3.0 | נאמנות שדות + enrichment ברמה אמיתית; אין הרצת שאילתה / tree / pivot בקליק |
| **IR, תיעוד ותקשורת** | ⚠️ 2.5 | התאוריה מצוינת; התרגול בזרימה דק — אין כתיבת הסלמה, ה-rubric מתגמל אורך |
| **נוף איומים ונתונים** | 🟨 3.5 | ה-packs החדשים ברמה גבוהה; חובות: hashes מזויפים, נוף 2025 חסר, הפרות SPEC |

---

## Top-10 פערים (מדורגים לפי השפעה / מאמץ)

| # | פער | ממד | חומרה | מאמץ | כמה כבר קיים |
|---|---|---|---|---|---|
| 1 | **אין Case Workspace** — התלמיד לא "עובד תיק" (סטטוס, הערות, הצמדת אירועים). ה-`ActiveIncident` קיים ב-backend אך נסתר | תפעול+IR | 🔴 | בינוני | ~60% |
| 2 | **Hashes "מאומתים" מזויפים** — `malwareHashes.ts` מבטיח "VirusTotal live" אבל EMOTET/QAKBOT/AsyncRAT הם hex סינתטי → pivot ל-VT נשבר | איומים | 🔴 | **נמוך** | — |
| 3 | **אין הסלמה T1→T2** — לא כפעולה ולא ככתיבה מדורגת (ה-grader רק מתגמל את המילה "escalate") | תפעול+IR | 🔴 | בינוני | דפוס ה-grader קיים |
| 4 | **נוף 2025 חסר** — edge→ransomware (CitrixBleed 2 / SonicWall), ClickFix, Scattered-Spider vishing→MFA reset | איומים | 🔴 | בינוני-גבוה | תשתית packs קיימת |
| 5 | **אין תור התראות / triage lifecycle** — בוחרים חברה+קושי, לא מקבלים תור עם עדיפות/SLA | תפעול | 🟡 | גבוה | `ruleLevel` כבר מחושב |
| 6 | **ה-rubric מתגמל אורך-טקסט, לא מבנה/timeline** — `depth = words≥150 ? 25` | IR | 🟡 | **נמוך** | 2 graders קיימים |
| 7 | **Playbooks מחוץ לזרימה** — קיימים כדף ניווט, לא נגישים ברגע ה-triage | תפעול+כלים+IR | 🟡 | **נמוך** (UI) | תוכן+תיוג MITRE קיימים |
| 8 | **אין click-to-pivot** — הסינון ידני בד-רופדאון, לא לחיצה על ערך | כלים | 🟡 | **נמוך** (UI) | filter state קיים |
| 9 | **אין process-tree + containment** — שדות parent/child קיימים אך מוצגים שטוח; אין כפתור Isolate | כלים | 🟡 | בינוני | הנתונים קיימים |
| 10 | **scenarios ישנים מפרים את ה-SPEC** — `AccessCount:312` analytics-in-raw שה-SPEC עצמו אוסר | איומים | 🟡 | נמוך-בינוני | validate script קיים |

---

## Roadmap מתועדף

### P0 — השפעה-לריאליזם הכי גבוהה למאמץ (עשה קודם)
1. **תקן את ה-hashes המזויפים (#2)** — *נמוך.* החלף ל-SHA256 אמיתיים מ-MalwareBazaar (או הסר את ההבטחה "VirusTotal"), + בדיקת CI ש-64-hex ולא-סינתטי. **שובר את הכישור עצמו שמלמדים** (pivot ל-VT), ולכן ראשון.
2. **Case Workspace (#1)** — *בינוני, 60% קיים.* הפוך את `ActiveIncident` הנסתר לכרטיס תיק: סטטוס (New→Investigating→Contained→Closed TP/FP), הערות/scratchpad, "הוסף אירוע לתיק" (ה-event IDs כבר נאספים). זה לבדו הופך "ציד + חיבור" ל**"עבודת תיק"**, ומזין את #3/#5/handover בחינם. משתמש מחדש ב-`AttackChainBoard` כ-timeline של התיק.
3. **תקן את ה-rubric: מבנה במקום אורך (#6)** — *נמוך.* בשני ה-graders, החלף/הרחב את מדד ה-word-count בזיהוי **timeline** ו**המלצה/פעולה** ו**impact**. במצב המונחה כבר יש שדות What/IOCs/Action/Impact — הוסף שדה **Timeline**.

### P1 — חיזוק (מנצל תוכן/קומפוננטות קיימים)
4. **Playbook בזרימה (#7)** — *UI בלבד.* התאם `PLAYBOOKS[].tags` ל-MITRE של האירוע (כבר מחושב כ-`storyMitre`) והצג את הנוהל המתאים ב-detail panel / report modal. אפס תוכן חדש.
5. **Escalate to T2 + handoff מדורג (#3)** — *מנגנון קטן.* פעולה על התיק שדורשת handoff מובנה (מה/למה/ראיות) לפני קבלה; דרג עם checks של ה-incident-report grader הקיים.
6. **click-to-pivot (#8)** — *UI בלבד.* חבר לחיצה על ערך שדה ב-detail ל-`setUserFilter/setHostFilter/setIpFilter` הקיימים.
7. **חשוף MTTA + הוסף MTTR** — *UI קטן.* `avgCatchMs` הוא כבר MTTA — קרא לו כך והוצא מה-"+more"; אחרי #2 (Contained→Closed) — מדוד MTTR. הוסף עמודות ל-CSV של המורה.
8. **נוף 2025 — 3 packs חדשים (#4)** — *תוכן.* Edge→ransomware (CitrixBleed 2 / SonicWall→Akira/DragonForce) · ClickFix paste-and-run · Help-desk vishing→MFA reset. + קדם 3-4 packs קיימים (AiTM, OAuth, ESXi) ל-rotation של ה-live feed. מקורות: CISA AA24-109A, AA23-320A.
9. **retrofit הפרות SPEC (#10)** — *נמוך-בינוני.* הוצא `*Count`/`bytes`/`duration` מ-`raw` ב-scenarios הישנים; הרחב את `validate-scenarios.mjs` לתפוס מפתחות אסורים ב-raw.

### P2 — עומק והרחבה (מנגנון גדול יותר)
10. **מצב Queue (#5)** — *מנגנון גדול.* תצוגת תור שממיינת לפי `ruleLevel`, עם disposition per-item ו-SLA. פותר גם את מתח ה-"אין verdict per row" — לתייג benign זו המיומנות האמיתית.
11. **process-tree + Isolate (#9)** — בנה `ProcessTree` מהשדות הקיימים + כפתור containment מדומה.
12. **enrichment בתוך room tasks** — עגן את ה-`ThreatIntelDrawer` גם ב-227 משימות ה-`log_analysis`.
13. **הרצת שאילתה אמיתית** — evaluator מינימלי של KQL/SPL מעל מערך האירועים החי (הרחבת ה-filter predicates).
14. **freshness cadence** — `last_reviewed` + `intel_source` per scenario; checklist רבעוני מול CISA KEV; דוח scenarios מעופשים (>12 חודשים).
15. **מצבי realism/hard** — הורד צפיפות signal והעלה יחס FP לכיוון פרופורציות SOC אמיתיות; ציון tone/audience ל-report.

---

## מה כבר חזק — לשמר (אל תבנה מחדש)
- **נאמנות שדות** (`rawLogFormat.ts`) — raw בפורמט vendor-מדויק (FortiGate/PAN/Check Point/Cisco/Windows XML). הממד הכי חזק.
- **Threat-Intel drawer** — VT-style hash, AbuseIPDB-style IP, GeoIP, domain age. קרוב לקונסולה אמיתית.
- **מנוע רעש/FP** — ~385 templates benign, FP-decoys משכנעים, תזמון תקיפות מדורג.
- **ה-packs החדשים** — `aitmTokenTheft.ts` הוא רף איכות: שחזור AiTM 2024 עם schema נכון של Entra ו-benign traveler להבחנה.
- **grader עם fabrication-detection** — rubric דטרמיניסטי + זיהוי בדייה.
- **כלי QA** — `coverage-report.mjs`, `audit-scenarios.mjs`, `validate-scenarios.mjs`, `SPEC.md`.

## שורה תחתונה
כדי שהפלטפורמה "תרגיש כמו מקום עבודה" — **לא צריך לבנות מנוע חדש**, אלא לעטוף את המנוע המצוין הקיים ב**זרימת T1 אמיתית** (queue→case→escalate→handover), להוסיף **עומק אינטראקציה** (pivot/tree/playbook-בזרימה), ולתקן **חובות תוכן** (hashes, נוף 2025, SPEC). ה-P0 כולם quick wins מעל נתונים שכבר קיימים.
