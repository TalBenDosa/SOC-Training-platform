# תסריט חדר 69: AI Attacks in the SOC, Part 2

**שם המבצע:** Operation Model Behaviour
**רמה:** בינוני
**העולם:** Quillfeather Legal (משרד עורכי דין בדוי): 140 עובדים, ועוזר AI פנימי בשם Quill שקורא תיקים במקום המתמחים.
**המנטור:** Anselm Okoro, AI Security Lead. (בטקסטים במעבדות אין לשון זכר או נקבה.)

## סיפור הרקע
ביום שישי הצד השני בתיק Ashgrove Mills v. Tarrant Freight הציע בדיוק את הסכום שמופיע בתזכיר חסוי אחד, מספר שמעולם לא יצא מהמשרד. איש לא שלח, הדפיס או העביר אותו. העד היחיד שנשאר הוא הלוג של העוזר עצמו, והמשימה של Anselm היא לקרוא אותו שורה אחרי שורה ולהחליט מה מותר ל-Quill לעשות כשיחזור לעבודה.

## המכניקה הייחודית של החדר
- **Read the Agent's Log:** שלוש מעבדות `trace` על לוגים של prompt, אחזור, קריאות כלי, פרוקסי, WAF ו-pgAudit. הלומד עוקב אחרי הזרקה עקיפה ממסמך שאוחזר ועד בקשה יוצאת, בדיוק כפי ש-SOC רואה אותה: מודל, prompt, מסמך, קריאת כלי, בקשה החוצה. שמות השדות לפי מוסכמות OpenTelemetry GenAI.
- **Replay It With One Change:** חימום לבוס. כל תיקון מוצע מורץ מול תוקף שמתאים את עצמו בשלוש דרכים, וכך רואים איזה תיקון מחזיק ואיזה רק סוגר דלת אחת.
- אין כאן `chat`: מעבדת הצ'אט שייכת לחדר 50.

## העולם התלת-ממדי
אולם קלפים (`facility`, ‏hall) עם ליבת `knot`: חדר הקריאה של המשרד, קלף אחד לכל תחנה.

## סדר המשימות
r7, m1 | r12, q8, r13, q9 | r14, q10 | r15, q11, r16, q12 | q7

## התחנות
| # | תחנה | משימות | המשחקים |
|---|---|---|---|
| 1 | The Assistant | r7, m1 | **Read the Agent's Log** (trace), **Ten Names, Ten Findings** (match) |
| 2 | The Tool Belt | r12, q8, r13, q9 | **Anatomy of a Tool Call** (anatomy), **Three Ways to Hand Over Too Much** (sort), **Follow the Payload** (trace), **Fix It Where It Lands** (duel) |
| 3 | The Meter | r14, q10 | **Set the Gateway Limits** (tune), **Five Faces of LLM10** (lineup) |
| 4 | The Guardrails | r15, q11, r16, q12 | **Which Verdict Was Fooled?** (deduce), **One Gate or Several?** (simulate), **Read the Whole Session** (trace), **Whose Rule Did It Beat?** (reactor) |
| 5 (בוס) | Model Behaviour | q7 | **Replay It With One Change** (simulate), ואז ההחלטה הנבחנת |

**הפרדה מהשאלות הנבחנות:**
- שאלת הביניים של r7 (למה ההזרקה הפכה לדליפה): השלב האחרון של Read the Agent's Log מלמד את הרעיון דרך כלי `fetch_url` ו-query string, לא דרך תיוג פניות ושליחת מייל.
- m1 (התאמת שם לתיאור): Ten Names, Ten Findings מתאים שם לממצא קונקרטי במשרד, כולל LLM07, LLM08, LLM09 שלא נבחנים, ולא לניסוח ההגדרה.
- q8 (שורש הבעיה): הפריט הראשון ב-Three Ways to Hand Over Too Much מלמד את ההבחנה "החשבון תואם בדיוק, העודף הוא הפונקציה" על תוסף יומן ו-`delete_event`, לא על הזמנות והחזרים.
- q9 (סיווג והיכן הפגם): Follow the Payload מראה פגם באפליקציה דרך SQL שהורכב מטקסט המודל, ו-Fix It Where It Lands מראה HTML דרך תג `<script>` בדיג'סט, לא תג תמונה עם `onerror` בקונסולת ניהול.
- q10 (Denial of Wallet והמענה): Set the Gateway Limits ו-Five Faces of LLM10 משתמשים במפתחות API מאומתים ובבאג חוזר, לא בצ'אטבוט ציבורי, סוף שבוע או טקסט מילוי המוני.
- q11 (טכניקה ולקח): Which Verdict Was Fooled? הוא קישור מייל עם אותיות דומות (homoglyph), לא מחרוזות שנוספו לקובץ, ו-One Gate or Several? מלמד שכלל לטריק אחד לא סוגר את החולשה ושאף מנוע לא יכול להיות שער יחיד.
- q12 (AML.T0054 ומדוע מסווג הודעות מפספס): Read the Whole Session הוא מסלול של תשעה תורים על גונב סיסמאות במסגרת עד מומחה, לא עשרה תורים על כופרה במסגרת קורס. Whose Rule Did It Beat? מלמד להבדיל בין T0051, T0054 ו-T0015. T0024.002 נלמד ב-Five Faces of LLM10.
- q7 (הבוס): Replay It With One Change מלמד את הסימן המכריע במעבדה נפרדת, על Quill וכלי fetch, לא על סוכן חדש ודוא"ל. הניסוחים שונים מהאפשרויות, והחסימה היא של דומיין אחד ולא של ערוץ הדוא"ל.

## סרטונים (כל אחד מסתיים בכרטיס NEXT MISSION עם הפעולה הראשונה, ולא חושף את תשובות התרגול שאחריו)
| סרטון | מתי | הפניה |
|---|---|---|
| Intro: "The Exact Figure" | כניסה | תחנה 1 |
| Chapter 2: "Saturday Morning" | אחרי The Assistant | תחנה 2 |
| Chapter 3: "The Invoice" | אחרי The Meter | תחנה 4 |
| Finale: "Model Behaviour" | אחרי הבוס | החדר הבא |
