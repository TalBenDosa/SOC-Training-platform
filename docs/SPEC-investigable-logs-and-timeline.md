# אפיון-יישום — לוגים ניתנים-לחקירה + ציר-זמן מדיד (נושא B)

**תאריך:** 18.08.2026 · **מטרה:** להפוך את מנגנון-הלוגים כך שיתמוך ב-**חקירה חוצת-לוגים (pivot)** + **שחזור-ציר-זמן מדיד** + **רעש חולק-ישויות** — הליבה של מודל-היעד (ניטור→טריאז'→חקירה→ציר-זמן→דו״ח).
**סטטוס:** אפיון-תכנון. לא קוד. בסיס-החלטה לפני בנייה.

---

## סקירה — 4 הרכיבים ותלותם
```
B2 (chain/parent tagging)  →  B3 (timeline grading)
        │                          ▲
        ▼                          │
B1 (entity model)  →  pivot  →  B4 (shared-entity noise)  →  אתגר-חקירה אמיתי
```
- **B2** נותן את מפתח-התשובות (רצף + סיבתיות). זול, ופותח את B3.
- **B3** מודד את התוצר-המרכזי (הציר שהתלמיד בונה).
- **B1** הופך את הלוגים ל-pivotable (חקירה חוצת-מקורות).
- **B4** גורם לחקירה להיות לא-טריוויאלית.

---

## B2 — תיוג-שרשרת + הורה-סיבתי

### שינוי מבני (backward-compatible — שדות אופציונליים)
ב-`src/lib/sim/types.ts`, ל-`TelemetryEvent`:
```ts
/** Which attack chain this event belongs to. Absent = benign noise. */
chain_id?: string;         // e.g. "aitm-token-theft-2026"
/** 1-based order of this step within its chain — the timeline ground truth. */
chain_step?: number;
/** Event id of the causal predecessor in the chain (for lead-following + link grading). */
parent_event?: string;
```

### היכן מוטבע
ב-`attackStories.ts` → `instantiateStory` (כבר עושה `events.map`): להטביע מהסדר-במערך —
```ts
events: s.events.map((e, i, arr) => ({
  ...e,
  chain_id: s.id ?? s.title,
  chain_step: i + 1,
  parent_event: i > 0 ? arr[i - 1].id : undefined,
}))
```
רעש benign: ללא `chain_id` (או `"benign"`).

### מה זה פותח
1. **ground-truth לציר-זמן** = אירועים ממוינים לפי `chain_step`.
2. **הובלת-חקירה** = "מה קרה אחרי X" דרך `parent_event`.
3. **לינק-אירועים אוטומטי** לבדיקה.

*מאמץ:* נמוך.

---

## B3 — בדיקת ציר-הזמן שהתלמיד בונה

### קלט
- `truth` = אירועי-התקיפה של הסשן, ממוינים לפי `chain_step`.
- `student` = רשימת event-ids מסודרת שהתלמיד הרכיב (התוצר המרכזי).

### נוסחאות-ציון (מודול טהור `src/lib/sim/timelineScore.ts`)
```
intersection = student ∩ truth   (לפי id)
completeness = |intersection| / |truth|           // תפס את אירועי-התקיפה?
precision    = |intersection| / |student|          // לא הכניס רעש?
order        = (# זוגות-סמוכים-אמיתיים בסדר-יחסי-נכון) / (|truth|-1)   // הסדר נכון?
score = 0.40*completeness + 0.40*order + 0.20*precision   // 0..1
```
- **causal bonus (אופציונלי):** אם התלמיד קישר parent→child, לתגמל התאמה ל-`parent_event`.
- **דיווח:** מה חסר (אירועי-truth שלא נכללו), מה מיותר (רעש שהוכנס), היכן הסדר שגוי.

*בונה-על:* דפוס ה-grader הקיים (`incident-report/route.ts`). *מאמץ:* נמוך.

---

## B1 — מודל-ישויות עקבי (תשתית-pivot)

### שינוי מבני
ב-`companyProfiles.ts`, לכל חברה **טבלת-ישויות קנונית**:
```ts
interface CompanyEntities {
  users:     { id: string; email: string; role: string }[];
  hosts:     { name: string; ip: string; role: string }[];   // מרחיב את asset-inventory שכבר אוכפים
  // אופציונלי: serviceAccounts, externalPeers ידועים
}
```

### הכלל (invariant)
כל ערך-**זהות-פנימית** באירוע (user_email / hostname / src_ip פנימי) חייב להתאים ל-`CompanyEntities` של החברה הפעילה.
- **חריגים לגיטימיים שכבר טיפלנו בהם:** לקוח-מרוחק ב-auth (src_ip=IP-הלקוח), NAT (`::ffff:`, IP-ציבורי), attacker externals. הצ'ק הקיים (`bindsHostIp`) כבר מבחין telemetry-מארח מ-auth — להרחיב אותו למודל-הישויות המלא.

### מה זה פותח
`pivot(value)` = "כל האירועים עם הישות הזו על-פני כל המקורות" — עובד רק אם הישויות עקביות. זו **תשתית-החקירה**.

*בונה-על:* הצ'ק `ASSET_INVENTORY` שבנינו. *מאמץ:* בינוני.

---

## B4 — רעש חולק-ישויות עם התקיפה

### הדרישה
כשמזריקים שרשרת על ישות E (host/user), לוודא ש-E מייצרת גם **אירועי-benign** בסשן (לפני/סביב התקיפה), ולכלול ~N אירועי-רעש שחולקים ישויות עם התקיפה.

### למה
היום רעש ותקיפה מנותקים → pivot תמיד "נקי" (כל מה שמצאת = תקיפה). במציאות, host-מותקף עשה גם דברים לגיטימיים. **זה מה שהופך חקירה לאתגר** — התלמיד חייב להבחין benign-מול-malicious על אותה ישות.

### יישום
- בבחירת-הסשן: לזהות את ישויות-התקיפה, ולהבטיח קיום אירועי-benign עליהן (מהמאגר או מיוצרים).
- להוסיף red-herrings: ~2-3 אירועי-benign שדומים-שטחית לשלב-תקיפה (אבל לגיטימיים) — עם `fp_explanation`.

*מאמץ:* בינוני.

---

## מדד-בונוס — איכות מסלול-החקירה (נגזר מ-B1+B2)
מעקב אחרי ה-pivots/חיפושים שהתלמיד הריץ, מול "המסלול-האידיאלי" (שרשרת `parent_event` מנקודת-הזרע):
- **overlap:** האם עקב אחרי החוט הנכון.
- **efficiency:** כמה pivots עד התמונה המלאה.
- **זמן-לשלב.**
> זה האות שמבדיל "ניחש נכון" מ"חקר נכון" — ומזין גם את שאלת-המחקר Q10.

---

## מיפוי לקבצים
| שינוי | קובץ |
|---|---|
| שדות chain_id/chain_step/parent_event | `src/lib/sim/types.ts` |
| הטבעת התיוג | `src/app/(app)/dashboard/attackStories.ts` (`instantiateStory`) |
| מודל-ישויות פר-חברה | `src/lib/sim/companyProfiles.ts` |
| אכיפת-ישויות (invariant) | הרחבת `scripts/validate-runtime-feed.mjs` (ASSET_INVENTORY) |
| ציון-ציר-זמן | חדש: `src/lib/sim/timelineScore.ts` |
| ממד-רצף בדו״ח | `src/app/api/dashboard/incident-report/route.ts` (או grade-route ייעודי) |
| רעש חולק-ישויות | לוגיקת-בחירת-סשן ב-`useLiveEvents.ts` |
| אינדקס-pivot (B5, צד-נתונים) | חדש: אינדקס בזיכרון מעל אירועי-הסשן |

## סדר-בנייה מומלץ (מדורג לפי תלות + ROI)
1. **B2** (שדות + הטבעה) — זול, פותח הכול. *~חצי יום.*
2. **B3** (`timelineScore` + דיווח) — מודל טהור, קל-לבדיקה. *~יום.*
3. **B1** (מודל-ישויות + הרחבת-הצ'ק) — תשתית-pivot. *~1-2 ימים.*
4. **B4** (רעש חולק-ישויות) — אתגר-החקירה. *~1-2 ימים.*
5. **B5** (אינדקס-pivot) — צד-הנתונים של כלי-החקירה (ה-UI נפרד). *~יום.*

> כל אחד ניתן-למסירה ובדיק בפני-עצמו. B2+B3 לבד כבר נותנים ground-truth + מדידה לציר-זמן — התוצר-המרכזי של המודל — עוד לפני שנוגעים ב-UI.

## מה מחוץ-לאפיון-הזה (בכוונה)
- **כלי-החקירה ב-UI** (pivot-click, timeline-builder, search box) — זה שכבת-הממשק; האפיון הזה מכין את **שכבת-הנתונים** שמאפשרת אותם. UI ייאפיין בנפרד.
- שינוי לוגים קיימים / גיוון (C) — לא כאן, לפי בקשתך.
