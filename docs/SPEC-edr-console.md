# אפיון — קונסולת EDR ברמת Falcon, משולבת ב-SOC Dashboard

> אפיון מבוסס-מחקר לבניית ממשק EDR ריאליסטי לחקירת אירועים, משולב עם ה-Dashboard החי. מבוסס על CrowdStrike Falcon (Insight EDR + Workbench + RTR) ו-Microsoft Defender for Endpoint. עודכן 2026-08-11.
>
> מקורות: [Falcon Insight EDR data sheet](https://web-assets.claroty.com/crowdstrike-briefs-external/crowdstrike-falcon-insight-data-sheet.pdf) · [Falcon Insight XDR walkthrough](https://www.crowdstrike.com/tech-hub/endpoint-security/falcon-insight-xdr-walkthrough/) · [Falcon triage & RTR methodology (Medium/InfoSecDion)](https://medium.com/@InfoSecDion/falcon-triage-methodology-navigating-crowdstrikes-edr-for-incident-response-8f77470a22e5) · [Investigate with Falcon (InventiveHQ)](https://inventivehq.com/knowledge-base/crowdstrike/how-to-investigate-a-security-incident-using-crowdstrike-falcon).

## 1. מה מכיל EDR אמיתי (Falcon) — מחקר

| מודול ב-Falcon | מה זה עושה | ערך לאנליסט |
|---|---|---|
| **Endpoint Detections** | רשימת התראות מתועדפת: חומרה, tactic+technique (ATT&CK), host, תהליך מפעיל, pattern disposition | נקודת ההתחלה — מה לטפל קודם |
| **Detection / Execution Details** | **עץ תהליכים (ancestry)** מלא; לכל node: command line, image path, SHA256/MD5, signer, user, ה-IOA/IOC שהצית, חיבורי רשת, כתיבות קובץ, registry | ליבת החקירה — "מי הריץ את מי ולמה זה חשוד" |
| **Incident Workbench** | מאגד התראות קשורות ל-**incident** אחד עם score, timeline מלא של התקיפה, hosts/users מושפעים, ותצוגת graph | לראות את התמונה המלאה מקצה לקצה |
| **Threat Graph / Process Explorer** | pivot: תהליך → domains → files → hosts אחרים | לעקוב אחרי התפשטות |
| **Host Management** | פרטי host: hostname, OS, sensor version, last seen, groups, IP, סטטוס | הקשר על המכונה |
| **Network Containment (Isolate)** | מנתק את ה-host מהרשת (למעט תקשורת ה-sensor), הפיך | פעולת ההכלה המרכזית של T1 |
| **Real Time Response (RTR)** | shell מרוחק ל-endpoint: `ps`, `get <file>`, `kill <pid>`, `netstat`, `reg query`, `rm`, `runscript`; שכבות Read/Active/Admin | חקירה עמוקה + תגובה ידנית |
| **Detection disposition** | assign, status (New→In Progress→True/False Positive→Closed), comment | ניהול מחזור-חיים של ההתראה |
| **IOC management / Event Search** | ניהול indicators; חיפוש טלמטריה גולמית | ציד וחסימה |

**התובנה:** באנליסט אמיתי הזרימה היא: **Detection → Execution Details (עץ תהליכים) → Enrich (hash/IP/domain) → Decide (Isolate / RTR / disposition) → Document**. זה מה שנבנה.

## 2. מיפוי Falcon → מה לבנות בפלטפורמה (+ ערך למידה)

| # | יכולת Falcon | לבנות | ערך למידה | סטטוס |
|---|---|---|---|---|
| 1 | Detections list | תור התראות EDR (חומרה/technique/host) | תעדוף | 🔜 Phase 2 |
| 2 | Execution Details — עץ תהליכים | ✅ עץ ancestry אינטראקטיבי + detail per node | ליבת החקירה | ✅ v1 |
| 3 | node detail (cmdline/path/signer/hash) | ✅ פאנל פירוט + hash lookup אמיתי | "מה חשוד בתהליך" | ✅ v1 |
| 4 | חיבורי רשת/קבצים per process | טאב Network/Files בפאנל התהליך | לעקוב אחרי C2/drops | 🔜 Phase 2 |
| 5 | ATT&CK על ההתראה | ✅ detection badges (technique) | שפה משותפת | ✅ v1 |
| 6 | Network Containment | ✅ Isolate host (+ יחזור ל-Dashboard) | פעולת ההכלה | ✅ v1 (בסיסי) |
| 7 | **RTR shell** | RTR-lite: `ps`/`netstat`/`get`/`kill`/`reg query` מדומים | חקירה+תגובה ידנית | 🔜 Phase 2 |
| 8 | Detection disposition | סטטוס + comment + TP/FP | מחזור-חיים | 🔜 Phase 2 |
| 9 | Incident Workbench | timeline מאוחד + score + graph | תמונה מלאה | 🔜 Phase 3 |
| 10 | Host Management | כרטיס host מורחב | הקשר | ✅ v1 (בסיסי) |

## 3. אינטגרציה Dashboard ⇄ EDR (הלב של הבקשה)

ב-Falcon אמיתי ה-EDR וה-console הם **מוצר אחד** — התראה בקונסולה נפתחת ל-execution details. כך נחבר:

1. **מ-Dashboard ל-EDR:** על אירוע תהליך/endpoint חשוד ב-live feed → כפתור **"Investigate in EDR"** → נפתחת קונסולת ה-EDR עבור אותו host, טעונה מראש עם **עץ התהליכים של התקיפה החיה** (נגזר מ-`storyMitre`/ה-`ActiveIncident` שכבר קיים במנוע).
2. **מ-EDR ל-Dashboard:** **Isolate host** ב-EDR → ה-host מסומן "Contained" גם ב-Dashboard (סטטוס משותף), וה-beacon בפיד נעצר.
3. **התאמת ישויות:** ה-beacon/alert ב-Dashboard = התהליך הזדוני ב-EDR (אותו pid/hash/IP). כך התלמיד מבין ששני המסכים הם **אותה מציאות משתי זוויות** — בדיוק כמו SIEM+EDR אמיתיים.
4. **גשר טכני:** state משותף (ה-`ActiveIncident` מ-`useLiveEvents.ts` → מתורגם ל-`EdrInvestigation` ב-runtime); דגל isolation ב-context משותף.

## 4. מודל הנתונים (קיים ב-`src/lib/edr/investigations.ts`)
`EdrProcess` (pid/ppid/name/cmdline/user/path/signed/sha256/verdict/note) · `EdrDetection` (pid/technique/severity) · `EdrTimelineEvent` · `EdrInvestigation` (host/processes/detections/timeline/answer). **הרחבות Phase 2:** `network[]`/`files[]`/`registry[]` per process; `EdrDetection.ioa` (הסבר ה-Indicator of Attack); `rtrTranscript` (תסריט תגובות RTR מדומות).

## 5. תוכנית בנייה מדורגת

**✅ Phase 1 (נבנה — `/edr` live):** עץ תהליכים אינטראקטיבי · detail per node · hash lookup אמיתי · detection badges · Isolate · timeline · החלטה מדורגת (flag payload / resolve FP) · 2 חקירות (chain אמיתי + FP).

**🔜 Phase 2 — עומק Falcon (הבא):**
- **RTR-lite** — shell מדומה: `ps`, `netstat`, `get <file>`, `kill <pid>`, `reg query`, עם תגובות ריאליסטיות מה-investigation data. מלמד תגובה ידנית.
- **טאבים per-process** — Network (חיבורי C2), Files (drops), בפאנל התהליך.
- **Detection disposition** — סטטוס New→In Progress→TP/FP + comment.
- **Detections queue** — כמה התראות פתוחות, מתועדפות.
- הרחבת נתונים: network/files/registry + IOA explanations.

**🔜 Phase 3 — אינטגרציה + Workbench:**
- **"Investigate in EDR" מה-Dashboard** → EDR טעון עם התקיפה החיה.
- **Isolation משותף** Dashboard⇄EDR.
- **Incident Workbench** — timeline מאוחד + score + graph של התקיפה.
- עוד 4-6 חקירות מגוונות (ransomware, lateral movement, credential theft, Linux).

## 6. מטרות למידה + הערכה
- **מיומנות ליבה:** לקרוא עץ תהליכים ולזהות את ה-payload (signer/path/hash/parent אנומליים).
- **הבחנה:** FP מול TP (חקירת ה-PsExec מלמדת שכלי dual-use תלוי-הקשר).
- **תגובה:** מתי לבודד, ומה להריץ ב-RTR.
- **גשר תאוריה→פרקטיקה:** מחבר את חדר batch-28 (EDR theory) לתרגול חי.
- **הערכה:** ההחלטה המדורגת (payload/FP) + (Phase 2) איכות פקודות ה-RTR ו-disposition נכון.

## שורה תחתונה
Phase 1 כבר חי ב-`/edr`. Phase 2 (RTR + network/files + disposition) הופך אותו לחקירת-עומק אמיתית; Phase 3 מחבר אותו ל-Dashboard כך שהתלמיד חווה **SIEM+EDR כמוצר אחד** — בדיוק כמו במקום עבודה.
