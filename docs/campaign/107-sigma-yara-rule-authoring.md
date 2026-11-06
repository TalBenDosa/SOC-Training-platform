# תסריט חדר 107: Writing Detection Rules: Sigma & YARA Authoring

**שם המבצע:** Operation Rule and Sign
**רמה:** מתקדם
**העולם:** Pelham Instruments (חברה בדויה): 900 עובדים שבונים מאזניים מדויקים וציוד כיול למעבדות בבתי חולים ובאוניברסיטאות, וכל קושחה יוצאת חתומה במפתח אחד.
**המנטור:** Tatiana Ogunleye, Detection Content Author. (בטקסטים במעבדות אין לשון זכר או נקבה.)

## סיפור הרקע
ביום שני סוכן ה-EDR הוריד תוכנה קטנה ולא חתומה מ-PEL-BLD-03, שרת הבנייה שיושב ליד מפתח החתימה. חוק ה-YARA הראשון שנכתב עבורה התאים ל-412 קבצים רגילים ונמשך תוך שעה. Tatiana חותמת על כל חוק שמגיע לייצור, והקושחה נחתמת ביום שישי. הלומד מתחיל מדף ריק: קודם מיון של מה ששווה לבנות עליו, אחר כך חוק Sigma למנגנון ההורדה, חוק YARA למשפחת הדגימה, ובסוף קריאה של התראה חיה מול הלוגיקה של החוק שהפיק אותה.

## המכניקה הייחודית של החדר
**Write It Tight:** שלושה משחקים על טקסט החוק עצמו, לא על תוכנית זיהוי.
- **Worth Keeping or Burns in a Day** (`sort`): שורות מהדגימה בשלושה סלים: שווה לשמור, נשרף תוך יום, תואם גם לתוכנה תקינה. שני כיווני הכישלון של החדר מתורגלים על אותו מיון.
- **Write It Tight: Count and Ceiling** (`tune`): שתי חוגות, ספירת מחרוזת ותקרת גודל, מול שתי קבוצות בדיקה. יש צירוף מנצח אחד, והמספרים העגולים נכשלים.
- **From Goodware Match to Tight Rule** (`spotdiff`): חוק YARA שתואם תוכנה תקינה ליד גרסה הדוקה, עם שני שינויים שלא משנים דבר.

החוקים הם Sigma אמיתי (מודיפיירים, logsource) ו-YARA אמיתי (strings, condition, ‏wide, ‏ascii, ‏filesize, מודול pe). חדרים 73 ו-96 עוסקים ב-use cases ובתוכנית זיהוי, וכאן עובדים על הטקסט.

## העולם התלת-ממדי
אולם קלפים (`facility`, ‏hall) עם ליבת `matrix`: קלף לכל תחנה.

## סדר המשימות
r1, r2, q1 | r3, qf1, r4, qf2, ac1 | r5, r6, qf3, q2, m1, o1 | la1, f1

הסדר שונה מהסדר המקורי: m1 ו-o1 הועברו אחרי Reading 6. במקור m1 בוחנת אופרטורים של YARA לפני ש-Reading 5 מלמד אותם, ו-o1 מפנה ל-Readings 3 ו-6 לפני ש-Reading 6 נקרא. הקריאות נשארות בסדר 1 עד 6, ולכן כל הפניה מסוג "Reading N" נשארת נכונה. הדגל f1 מפנה ל-Reading 2 ו-Reading 3 בלבד, ואין בו מספר "Log Analysis N".

## התחנות
| # | תחנה | משימות | המשחקים |
|---|---|---|---|
| 1 | The Sample | r1, r2, q1 | **Worth Keeping or Burns in a Day** (sort), **Fix the Draft With the Right Modifier** (duel), **Does This Block Fire?** (worksheet) |
| 2 | The Sigma Rule | r3, qf1, r4, qf2, ac1 | **A Two-Tool Sigma Rule, Line by Line** (anatomy), **One Phrase or Separate Words?** (worksheet), **Name the Parts of a Rule Conversion** (codebreak), **Same Rule, Two SIEMs** (worksheet), **Four Hits From the New Rule** (queue) |
| 3 | The YARA Rule | r5, r6, qf3, q2, m1, o1 | **A YARA Rule, Line by Line** (anatomy), **Read the Scan Output** (worksheet), **Write It Tight: Count and Ceiling** (tune), **From Goodware Match to Tight Rule** (spotdiff), **From Hypothesis to Sign-Off** (sequence) |
| 4 (בוס) | The Sign-Off | la1, f1 | **Walk an Alert Back Through Its Rule** (trace), **Did the Sensor Stop It?** (sort) |

**הפרדה מהשאלות הנבחנות:**
- **שאלת הביניים של r1** (שני כיווני הכישלון): ה-primer של **Worth Keeping or Burns in a Day** מגדיר רחב מדי וצר מדי, והמיון מתרגל אותם. שונה: שורות מקובץ PE, ודוגמת ה-primer היא ערכת פישינג.
- **שאלת הביניים של r2** (רשימה מול `|all`): ה-primer של **Fix the Draft** מלמד OR מול AND. שונה: `reg save` ב-primer ו-`/transfer` במשחק, לעולם לא הדגלים הנבחנים.
- **q1** (מה הבלוק תואם): **Does This Block Fire?** מלמד ששורות בבלוק הן AND ושה-Image הוא הקובץ שרץ. שונה: bitsadmin על שש שורות, והמילה בשורת הפקודה מופיעה דרך python, לא דרך מעטפת cmd ולא PowerShell.
- **שאלת הביניים של r3** (למה שתי מילים ולא ביטוי): **One Phrase or Separate Words?** מלמד סדר שמשתנה. שונה: מתגים של bitsadmin, ודוגמת ה-primer היא `net localgroup`.
- **qf1** (השלמת הבלוק): **A Two-Tool Sigma Rule** מראה את `Image`, את `|all` ואת תנאי של בלוק יחיד. שונה: הורדות ב-bitsadmin ו-curl, בלוקים בשם `sel_*`, בלי vssadmin.
- **שאלת הביניים של r4** (מה משתנה בין SIEM ל-SIEM): **Name the Parts of a Rule Conversion** מלמד backend ו-pipeline, ו-**Same Rule, Two SIEMs** מראה את אותו חוק פעמיים. שונה: חוק ההורדה, והשאלה היא כמה שורות משתנות.
- **qf2** (OR ב-KQL והביטוי של wmic): טבלת **Same Rule, Two SIEMs** מראה שהמילה הבוליאנית עוברת כמו שהיא, והשאלה שם היא על `and`. הביטוי של wmic מופיע רק כשורת נתונים עם תווית בטבלה של **One Phrase or Separate Words?**, ליד שתי פקודות wmic אחרות, ולא נשאל.
- **ac1** (פסק דין על פגיעת חוק, חוק מבני מול מחרוזת קשיחה): **Four Hits From the New Rule** מלמד לקרוא הורה, חשבון והקשר. שונה: ארבע פגיעות של חוק הורדה, הורים מסוג dropper ו-WmiPrvSE, בלי Office ובלי PowerShell מקודד.
- **שאלת הביניים של r5** (פער בהקס): **A YARA Rule, Line by Line** מסביר `??` ו-`[2-6]`. שונה: בתים אחרים, בחוק של Kestrel.
- **שאלת הביניים של r6** (מחרוזת קשיחה): ה-config המוצפן ב-**Worth Keeping or Burns in a Day** מלמד למה שינוי של בית אחד מספיק. שונה: קובץ PE, לא מטען מוסתר של webshell.
- **qf3** (תנאי YARA): **A YARA Rule, Line by Line** מלמד `filesize <` ו-`1 of (...)`. שונה: קובץ PE בגודל 1MB, בלי PHP, בלי 150KB ובלי שמות המחרוזות הנבחנים.
- **q2** (אבחון וריפוי של חוק רחב): **Write It Tight: Count and Ceiling** ו-**From Goodware Match to Tight Rule** מלמדים תקרה ודרישה לכמה אותות. שונה: לואדר PE עם 412 התאמות, תנאי של ספירה, בלי PHP ובלי ספריות צד שלישי.
- **m1** (מודיפיירים ואופרטורים): **Fix the Draft** מכסה את צד ה-Sigma, ו-**A YARA Rule, Line by Line** עם **Read the Scan Output** מכסים את צד ה-YARA. שונה: `1 of sel_*`, `#loop > 3`, `@loop[1]`, וכל ההגדרות בניסוח אחר ועל דוגמה אחרת.
- **o1** (סדר הכיוונון): **From Hypothesis to Sign-Off** מלמד את הסדר על סיפור קונקרטי. שונה: שישה צעדים במקום שמונה, בניסוח של בוקר אחד של Tatiana.
- **la1** (התראה מול החוק שלה, ארבע שאלות): **Walk an Alert Back Through Its Rule** מלמד הערכה נפרדת של כל בלוק, רשימה כ-OR, פילטר מדויק וסיכון של דרישה נוספת. **Did the Sensor Stop It?** מלמד במעבדה משלו את האות המכריע: האם הפעולה הסתיימה. שונה: מפתח Run ב-Sysmon Event 13, לא גישה ל-LSASS, הכמעט-התאמה היא אותו שם קובץ בתיקייה אחרת, וערכי ה-disposition מנוסחים אחרת ולא כוללים את הערך הנבחן.
- **f1** (התנאי עם wildcard): ה-primer והקלף של **Fix the Draft** מלמדים את הצורה `1 of sel_*`. שונה: קידומת אחרת, כך שהלומד צריך להחיל את הצורה על הקידומת של החוק הנבחן.

## סרטונים (כל אחד מסתיים בכרטיס NEXT MISSION עם הפעולה הראשונה, ולא חושף את תשובות התרגול שאחריו)
| סרטון | מתי | הפניה |
|---|---|---|
| Intro: "412 Files" | כניסה | תחנה 1 |
| Chapter 2: "A Blank Page" | אחרי The Sample | תחנה 2 |
| Chapter 3: "The Bench" | אחרי The Sigma Rule | תחנה 3 |
| Finale: "Rule and Sign" | אחרי The Sign-Off | החדר הבא |
