# תסריט חדר 71: Data Staging & Exfiltration Channels

**שם המבצע:** Operation Exit Route
**רמה:** בינוני
**העולם:** Ostrava Precision Bearings (יצרנית מיסבים בדויה): 640 עובדים, מפעל אחד, ושנים עשר ימים עד הגשת הצעה חתומה למכרז סרני רכבת.
**המנטור:** Helene Vaszary, Data Protection Analyst. (בטקסטים במעבדות אין לשון זכר או נקבה.)

## סיפור הרקע
ביום שני מצטט מהנדס מכירות של מתחרה סבולת שקיימת רק בתיקייה אחת, על שרת קבצים אחד. התיקייה RailAxle-G7 עדיין במקומה, שום דבר לא חסר, קונסולת ה-DLP שקטה, וחומת האש אישרה הכול. ל-Helene יש שם של תיקייה ואין לה הוכחה. צריך לעקוב אחרי הנתונים מה-share ועד היציאה, להוכיח את הגניבה במספרים, ולא להאשים את העבודה שעושה בדיוק את אותו דבר בכל לילה.

## המכניקה הייחודית של החדר
**Follow the Data.** תיקייה גנובה אחת עוברת דרך share, תיקיית staging, ארכיון וערוץ יציאה, וכל קפיצה היא טכניקת ATT&CK אמיתית עם הטלמטריה שלה. אחר כך המספרים מדברים: גודל הארכיון על הדיסק מול הבתים שיצאו על הקו. הלקח: הגדלים הם ההוכחה, אבל ההקשר הוא שמכריע.
- **Follow the Data (pathway):** הליכה קפיצה אחר קפיצה מ-OPB-FS02 ועד cloudlocker.example. בכל צומת נכון מופיעים הטכניקה, הטקטיקה והלוג. הטקטיקה משתנה רק בצעד שמוציא בתים מהמארח.
- **Do the Sizes Match? (trace):** הולכים אחורה מחומת האש: 1,409,882,640 בתים על הקו, ארכיון של 1,372,416,512 בתים, 2,068,912,640 בתים ב-staging, ו-812 רשומות 5145. ההפרש של 2.7% הוא תקורת TCP/IP ו-TLS. הורדה כמעט זהה בגודלה, קובץ STEP גדול ממה שיצא, ו-.msi קרוב בגודל שנכנס ולא יצא הם המלכודות.
- **Set the Line (tune):** כלל שסוכם לפי מארח ויעד בשעה, ומחובר להיסטוריה. המספר העגול 500 מפספס ריצה של 470 MB בחלקים קטנים. תעבורת DNS לעולם לא תדליק כלל בתים.
- **Same Shape, Different Context (spotdiff):** העבודה הלילית המאושרת מול שכפול של צוות האדום. הצורה זהה, ושורת הגודל היא דווקא הפיתיון.
- **On the Host or Off It? (rush):** בליץ של מהלכים: האם הנתונים כבר עזבו את המארח?

## העולם התלת-ממדי
אולם קלפים (`facility`, core מסוג `chain`): חמישה קלפים לפי התחנות, ושרשרת שמרחפת מעל הכן, כמו שרשרת הצעדים של הנתונים.

## סדר המשימות
r0, r1, r2, q1 | r3, q2, r4, f1 | r5, r6, q3, m1, o1 | r8, r7, la1 | ac1, q4

(סדר חדש: בחדר המקורי q3 בא אחרי תיק mega.nz, ו-o1 ו-f1 באים אחרי הבוס. q3 עבר לערוצים, o1 לסוף הערוצים כשכל השרשרת כבר נלמדה, f1 לארכיון, והבוס סוגר את החדר.)

## התחנות
| # | תחנה | משימות | המשחקים |
|---|---|---|---|
| 1 | The Share | r0, r1, r2, q1 | **Follow the Data** (pathway), **Anatomy of a Share Read** (anatomy), **Whose Read Doesn't Fit?** (worksheet), **Anatomy of a Staging Copy** (anatomy), **Routine Copy or Staging?** (sort) |
| 2 | The Archive | r3, q2, r4, f1 | **Anatomy of an Archive Command** (anatomy), **What Can a Content Scanner Still Read?** (match), **Four Signs on One File** (inspect), **Data Point or Case?** (sort) |
| 3 | The Exit | r5, r6, q3, m1, o1 | **Mount, Then Write** (worksheet), **Name the Channel** (sort), **Encoded Subdomains: Tunnel or Vendor?** (inspect), **Set the Line** (tune), **On the Host or Off It?** (rush) |
| 4 | Bytes Out | r8, r7, la1 | **Same Shape, Different Context** (spotdiff), **Who Can Confirm It?** (match), **Walk It Back** (sequence), **Do the Sizes Match?** (trace), **What a Firewall Session Can Say** (anatomy) |
| 5 (בוס) | Stolen or Scheduled | ac1, q4 | **Four Large Transfers** (queue), **What Would a Thief Also Do?** (sort), ואז ההחלטות הנבחנות |

**הפרדה מהשאלות הנבחנות:**

מה מלמד כל פריט נבחן, ובמה הוא שונה:
- **שאלת הביניים של r1 (5145 מול 5140, 5142, 4624):** שורת EventID ב-Anatomy of a Share Read מציגה את ההבדל כנתון, על לוג של Ostrava, בלי לשאול. RelativeTargetName ו-AccessMask מסבירים מה נמצא רק ב-5145. לא FS-LAW01 ולא ClientMatters$.
- **q1 (T1039 ואז T1074.001, שתיהן Collection):** צמתי eng ו-stage ב-Follow the Data ו-Anatomy of a Staging Copy. כאן פקודת Robocopy אחת קוראת את כל התיקייה ומורידה אותה ל-C:\Windows\Temp, 812 קריאות, בלי פער זמן. בשאלה יש 640 קבצים, העתקה ארבע דקות אחר כך, תת-קבוצה, ו-C:\ProgramData. שום מעבדה לא שואלת את הזוג.
- **שאלת הביניים של r3 (-hp מול -p):** שורת -hp ב-Anatomy of an Archive Command וזוגות ה-match. הדוגמה של Ostrava עם סיסמה משלה.
- **q2 (T1560.001 הוא Collection):** הערת הצומת archive בנתיב, וסיכום האנטומיה שאומר שהצפנה לא הופכת את זה ל-Stealth או ל-Exfiltration. שורת -v מסבירה שפיצול בדיסק הוא לא T1030. אין טענה של עמית, והניסוח שונה.
- **f1 (הסיסמה מהדוגמה המנוסחת בקריאה):** זכירה טהורה. הפקודה המלאה מופיעה פעם אחת כשורה עם תווית "Worked example in the reading" ב-Anatomy of an Archive Command, ואף מעבדה לא שואלת אותה. הסיסמה של Ostrava היא אחרת.
- **שאלת הביניים של r5 (למה USB עדיין רלוונטי):** שאלה 3 ב-Mount, Then Write על תא ה-CNC המנותק, בניסוח שונה, עם ה-why על air gap. שאלה 2 מסבירה שאין עקבה ברשת אבל יש טלמטריית נקודת קצה, ולכן המסיח הראשון נופל.
- **שאלת הביניים של r6 (Rclone):** פריט c1 ב-Name the Channel: כלי לגיטימי ברמת משתמש, ההקשר הוא הסימן, והוא מדבר עם API של אחסון.
- **q3 (T1048 דרך DNS):** מעבדות Name the Channel ו-Encoded Subdomains. ההבדל בין T1048 ל-T1041 ול-T1071.004 נלמד על מקרים אחרים: SMTP, FTP, C2 שרץ על DNS, TXT כל 60 שניות. המקרה של DNS הוא מארח של צוות האדום עם C2 ב-TLS על 8443, ללא חסימת USB וללא HTTPS. בדיקת ספק ו-CDN מול שורות הספק במעבדה.
- **m1 (התאמת טכניקה לטקטיקה):** זכירה. On the Host or Off It? שואל על מהלכים קונקרטיים ולא על מזהים, והמזהה מופיע רק ב-why. Follow the Data מציג את המיפוי כנתון. אף זוג לא מועתק.
- **o1 (סדר השרשרת):** הנתיב ב-Follow the Data עובר אותו סדר בניסוח אחר, בלי לבקש מיון.
- **שאלת הביניים של r8 (מה מאושר בשניות):** זוג ב-Who Can Confirm It?, על ניסוח של שאלות ולא של מסיחים.
- **la1 שאלה 1 (זוג שדות הכיוון):** שלב out ב-Do the Sizes Match? ו-What a Firewall Session Can Say. כל שדה מסביר מה הוא לא יודע: dstcountry, apprisk, duration, service. לא mega.nz ולא ערכי הבתים של השאלה.
- **la1 שאלה 2 (מה עוד לבדוק):** שלב context ב-trace וסיכום האנטומיה, על חשבון ויעד אחרים.
- **ac1 (ההכרעה):** מעבדה נפרדת, Four Large Transfers. ייצוא ERP לאתר DR של החברה, לא Veeam, לא Azure Blob ולא 02:00. ההבדל בין Benign True Positive ל-False Positive נלמד על שתי התראות מאותו כלל, עם misfire אמיתי של parser, וההחרגה הצרה מופיעה ב-why.
- **q4 (החלש והחזק):** מעבדה נפרדת, What Would a Thief Also Do? על ייצוא ה-ERP. מיון בין צורה להקשר, וכל why מסביר למה ההקשר נחשב ביחד ולא כל סעיף לבד.

## סרטונים (כל אחד מסתיים בכרטיס NEXT MISSION עם הפעולה הראשונה, ולא חושף את תשובות התרגול שאחריו)
| סרטון | מתי | הפניה |
|---|---|---|
| Intro: "The Quote" | כניסה | תחנה 1 |
| Chapter 2: "Nothing Is Missing" | אחרי The Archive | תחנה 3 |
| Chapter 3: "The Night Shift" | אחרי Bytes Out | תחנה 5 |
| Finale: "Exit Route" | אחרי Stolen or Scheduled | החדר הבא |
