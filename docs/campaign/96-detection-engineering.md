# תסריט חדר 96: Detection Engineering Fundamentals

**שם המבצע:** Operation Signal and Noise
**רמה:** מתקדם
**העולם:** Cadenza Music Group (קבוצת מוזיקה בדויה): שלושה לייבלים, זרוע הוצאה לאור, 620 עובדים, וקטלוג הקלטות מאסטר שהוא כל העסק.
**המנטור:** Lior Danso, Detection Lead. (בטקסטים במעבדות אין לשון זכר או נקבה.)

## סיפור הרקע
ב-SIEM של Cadenza יש 1,240 חוקי זיהוי, והדוח הרבעוני קורא לזה 81% כיסוי של ATT&CK. ביום שישי האחרון אלבום שטרם יצא הופיע בפורום הדלפות. הפורץ היה בפנים 19 ימים, ואף חוק לא ירה. ה-backlog עובר ל-Lior Danso יחד עם שאלה אחת מהדירקטוריון: כמה מהכיסוי הזה אמיתי?

## המכניקה הייחודית של החדר
**Coverage Is Not Quantity.** הלומד מנהל backlog של זיהויים, תוכנית שלמה ולא use case בודד כמו בחדר 73.
- **What Ever Fired?** (`hunt`, SPL): הלומד בונה שורה אחרי שורה שאילתה שמודדת אילו טכניקות ATT&CK מחזיקות חוק שירה אי פעם. 14 חוקים, שש טכניקות צבועות בירוק, שלוש שירו באמת. התוצאות מחושבות מהשורות.
- **Harder to Dodge** (`spotdiff`): אותו חוק לפני ואחרי שכתוב שעמיד לעקיפה. שינויים קוסמטיים עולים בחיים.
- **The Evasion Round** (`duel`): ה-red team משחק התחמקות, והלומד משחק את לוגיקת הזיהוי ששורדת אותה.

## העולם התלת-ממדי
אי קמפוס (`facility`) של החברה: ארבעה מבנים לפי התחנות. ה-Hub נושא את שם החברה.

## סדר המשימות
r1, q1 | r2, q3 | r3, r4, m1, q2 | la1, flag1, queryfill1

הסדר שונה: בחדר המקורי כל הקריאות באות ראשונות, כך שאי אפשר לחתוך אותו לתחנות. הקריאות נשארות בסדר 1 עד 4, ולכן כל הפניה ל-"Reading N" תקפה. q2 נשארת אחרי Reading 4, ו-queryfill1 אחרי Reading 2. flag1 נשארת אחרי la1 ומציינת את ההתראה בשם החוק, בלי מספור "Log Analysis N".

## התחנות
| # | תחנה | משימות | המשחקים |
|---|---|---|---|
| 1 | The Backlog | r1, q1 | **What Does a Noisy Rule Cost?** (worksheet), **What Can't the Vendor Pack Know?** (sort) |
| 2 | The Heatmap | r2, q3 | **Which Kind of Logic Is This?** (sort), **Anatomy of an Inventory Row** (anatomy), **What Ever Fired?** (hunt), **Walk the Intruder's Path** (worksheet) |
| 3 | The Rewrite | r3, r4, m1, q2 | **From Idea to Retirement** (sequence), **Anatomy of a Sigma Rule** (anatomy), **Harder to Dodge** (spotdiff), **The Evasion Round** (duel) |
| 4 (בוס) | First Fire | la1, flag1, queryfill1 | **How Far Did the Failures Spread?** (worksheet), **What Still Works?** (trace), **Why Did This Logon Fail?** (anatomy), **Counting Rows or Counting Things?** (worksheet) |

לכל מעבדה שדורשת ידע יש primer מקופל (`fold: true`), כי זה חדר מתקדם.

**הפרדה מהשאלות הנבחנות:**
- **שאלת הביניים של r1 (למה לא מספיקים חוקי ברירת מחדל):** נלמד ב-What Can't the Vendor Pack Know?. הדוגמאות הן שעות אולפן, שמות חשבונות ca_ וכספת המאסטרים, בלי PsExec של IT ובלי הניסוח של התשובה.
- **q1 (דיוק של 95% על 200 התראות):** נלמד ב-What Does a Noisy Rule Cost?: נוסחת הדיוק, הסכום על פני חוקים, והרף של 99% ב-primer. המספרים אחרים (92%, 90%, 70%, 98%, 99.5%), והדוגמה המחושבת היא סורק חבילות.
- **שאלת הביניים של r2 (יתרון Sigma):** נלמד בשורות sigma_source ו-compiled_to של Anatomy of an Inventory Row, בלי לפסול אף הסחה.
- **q3 (טכניקות עם אפס חוקים):** נלמד ב-Walk the Intruder's Path: שלב בלי חוק מתויג לא מעלה התראה, וההתראה הראשונה האפשרית מגיעה בשלב מאוחר יותר. הטכניקות הן T1133, T1003.001, T1021.002, T1039, T1560.001 ו-T1567.002, ולא T1566, T1078 או T1190.
- **שאלת הביניים של r4 (רשימה תחת שדה אחד):** נלמד בשורת CommandLine|contains ב-Anatomy of a Sigma Rule, על חוק schtasks ולא על PowerShell מקודד.
- **m1 (חלקי חוק Sigma):** נלמד ב-Anatomy of a Sigma Rule, על חוק schtasks ובניסוח שונה משל זוגות ההתאמה.
- **q2 (logsource של firewall):** נלמד בשורת logsource (השאילתה מחפשת רק שם) ובסיכום של אותה אנטומיה (אפס שורות, אפס התראות). המעבדה לא מעבירה חוק ל-firewall ולא מראה חוק ששינו לו logsource.
- **la1 שאלה 1 (פירוק T1110.003):** נלמד ב-Anatomy of an Inventory Row על T1021.002, מהטקטיקה דרך הטכניקה ועד תת-הטכניקה.
- **la1 שאלה 2 (פיזור הכשלונות):** נלמד ב-How Far Did the Failures Spread?. במעבדה 50, 1 ו-3 ניסיונות לחשבון, לא 2. ההתראה הנבחנת לא מופיעה.
- **la1 שאלה 3 (מה דחוף ביותר):** הסימן המכריע מקבל מעבדה משלו, What Still Works?: טוקן API שדלף, כתובת שנחסמה, אותו טוקן מכתובת חדשה, ורק ביטול הטוקן עוצר. אין בה ריסוס, חשבונות או בקר תחום, וה-primer לא מזכיר אף אחת מההסחות.
- **flag1 (קוד הסטטוס):** נלמד ב-Why Did This Logon Fail?. האירוע הוא משימת סריקה ישנה עם 0xC0000064. הקוד הנבחן מופיע רק כנתון בהערה של SubStatus, והמעבדה לא שואלת עליו.
- **queryfill1 (dc ו-src_ip):** נלמד ב-Counting Rows or Counting Things?: חשבון מול שיתופים ב-Event 5140, לא מקור מול חשבונות ב-4625. הפונקציה dc מופיעה ב-primer ובגיליון, אבל לא נדרשת הקלדה שלה. השאלה האחרונה מראה מה קורה כשהקיבוץ הוא לפי השרת שכתב את הלוג, על נתונים אחרים.

## סרטונים (כל אחד מסתיים בכרטיס NEXT MISSION עם הפעולה הראשונה, ולא חושף את תשובות התרגול שאחריו)
| סרטון | מתי | הפניה |
|---|---|---|
| Intro: "1,240 Rules" | כניסה | תחנה 1 |
| Chapter 2: "Nineteen Days" | אחרי The Backlog | תחנה 2 |
| Chapter 3: "Green Cells" | אחרי The Heatmap | תחנה 3 |
| Finale: "Signal" | אחרי First Fire | החדר הבא |

**הערות לסרטונים:** הסיפור בלבד: האלבום שדלף, הדוח הרבעוני, הפער בין מה שכתוב על הקיר לבין מה שקרה ב-19 הימים, והרגע שבו חוק סוף סוף יורה. בלי נוסחאות, בלי מספרי טכניקות, בלי פקודות SPL או שדות Sigma, ובלי סדר פעולות לבלימה.
