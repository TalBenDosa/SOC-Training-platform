# תסריט חדר 90: Writing the Incident Report

**שם המבצע:** Operation Final Report
**רמה:** בינוני
**העולם:** Bellwether Schools Trust (רשת בתי ספר בדויה): 14 בתי ספר, צוות IT קטן, ותקרית שנסגרה ביום חמישי של חופשת אמצע הסמסטר.
**המנטור:** Priyanka Hale, IR Report Lead. (בטקסטים במעבדות אין לשון זכר או נקבה.)

## סיפור הרקע
הפורץ כבר בחוץ, ועכשיו יושב על השולחן הדוח. יו"ר הנאמנים, האחראי על הגנת המידע והמהנדס שבונה מחדש את הגישה מרחוק מבקשים את אותו דוח, וכל אחד מהם צריך ממנו דבר אחר. ל-Priyanka יש כבר רשימה ארוכה של חקירות טובות שנפלו בשלב הזה: עובדות נכונות, קורא לא נכון, ואין דרך לבדוק אותן. אחרי שהלומד עובר את דוח Bellwether, מחכה לו התיק של Solstice Actuarial, המבחן שכל כותב דוחות חדש עובר אצל Priyanka.

התקרית של Bellwether: סיסמה של קבלן חיצוני, gateway ישן שנשאר מחוץ לפריסת ה-MFA, ו-41 MB של פרטי קשר של הורים שיצאו מ-BW-MIS02. התקרית הזאת חוזרת בכל המעבדות, והמספרים בה זהים מתחנה לתחנה.

## המכניקה הייחודית של החדר
- **Write for Who Reads It:** אותה תקרית הופכת לתקציר מנהלים, ל-timeline טכני ולרשימת פעולות. כל פורמט נכתב עבור קורא אחר.
- **How Much Detail Does the Chair Get? / the Engineer Get?:** שתי מעבדות `tune` על אותן עובדות. ה-rule הוא עט אדום שמוחק שורות, והכיוון מתהפך: מה שהיו"ר צריך, המהנדס מוחק, ולהפך.
- **סימון טיוטות:** ארבע מעבדות `spotdiff` של טיוטה מול גרסה נקייה. הלומד מקיש על טענות בלי ראיות ועל האשמה של אדם, ולא על הבדלי ניסוח. שינוי מילים שלא משנה את העובדה הוא decoy שעולה בחיים.
- **What Earns the Marks:** הניקוד של ה-written_report נלמד במעבדה משלו, על גיליון ציונים של ארבע כתיבות תרגול.
- **ההבדל מחדר 63:** חדר 63 מכסה הערות אנליסט ותיעוד שוטף. כאן זה הדוח המלא.

## העולם התלת-ממדי
אי קמפוס (`facility`, Campus) של Bellwether Schools Trust עם Hub בשם INCIDENT REPORT HUB וחמישה מבנים לפי התחנות.

## סדר המשימות
r1, r2, q1, o1 | r3, m1, la1, f1, qf1 | r4, q2, ac1, q4 | r5, q3 | wr1

(הסדר שונה. הסדר המקורי: r1, r2, q1, o1, r3, m1, la1, q2, r4, ac1, r5, qf1, q3, f1, q4, wr1. במקור q2 בדקה defensibility לפני הקריאה שמלמדת אותה, ו-q4, f1 ו-qf1 ישבו אחרי r5 בלי קשר לנושא שלה. עכשיו f1 ו-qf1 צמודות ל-la1 שאת הרשומה שלה הן קוראות, ו-q2 ו-q4 יושבות אחרי r4. ל-f1 יש `event` משלה ואין בה נוסח "Log Analysis N", ולכן השינוי לא שובר אותה.)

## התחנות
| # | תחנה | משימות | המשחקים |
|---|---|---|---|
| 1 | The Reader | r1, r2, q1, o1 | **Translated, or Just Shorter?** (sort), **How Much Detail Does the Chair Get?** (tune), **Two Files, Six Revisions Later** (spotdiff), **A Finished Report, Section by Section** (anatomy), **Where Would You Turn?** (sort) |
| 2 | The Record | r3, m1, la1, f1, qf1 | **The IOC List Gate** (intercept), **Mark Up the Timeline** (spotdiff), **How Much Detail Does the Engineer Get?** (tune), **Read the Record Before You Quote It** (anatomy) |
| 3 | The Review | r4, q2, ac1, q4 | **Will This Claim Stand?** (intercept), **Which Decision Can Nobody Prove?** (worksheet), **Does It Go in the Report?** (queue) |
| 4 | The Gap | r5, q3 | **Mark Up the Root Cause** (spotdiff), **Which Gap Does It Close?** (sort) |
| 5 (בוס) | Final Report | wr1 | **What Earns the Marks** (worksheet), **Mark Up the Final Draft** (spotdiff) |

**הפרדה מהשאלות הנבחנות:**
- **שאלת הביניים של r1 (למה דוח אחד):** עובדת זיכרון. היא מודגמת ב-Two Files, Six Revisions Later על דוח תיבות הדואר של השנה שעברה, והמילה drift מופיעה רק בלקח. המעבדה לא שואלת אותה.
- **q1 (מה הבעיה בתקציר):** הרעיון, תרגום מול קיצור, נלמד ב-Translated, or Just Shorter? על משפטים של Bellwether. בדוגמת הפריימר יש דיסק גיבוי של מרפאת שיניים. שורה אחת במעבדה מכילה T1133, ולא נזכרים בה T1053.005, AP-SRV14 או svc-report. שם שרת נשאר ב-tune בשורה k4 שנשמרת, ולכן אף מעבדה לא מלמדת ששם שרת אסור בתקציר, וגם לא שהוא מותר, ושום מסיח של q1 לא נשלל ישירות.
- **o1 (סדר הסעיפים):** עובדת זיכרון. הסדר מופיע פעם אחת, בדרך אגב, כשורות עם תווית ב-A Finished Report, Section by Section על דוח אחר (תיבות דואר, 2025). אף מעבדה לא מבקשת לסדר סעיפים.
- **m1 (תוכן לסעיף):** נלמד ב-Where Would You Turn? על שאלות של אנשים ב-Bellwether, ובסיכום של Read the Record Before You Quote It. הניסוחים של m1 לא מופיעים.
- **la1, שאלה 1 (ערך ה-IOC של משימה מתוזמנת):** העיקרון, עמודה שמחזיקה בדיוק את הערך, נלמד בפריימר של Read the Record. שם המשימה ב-The IOC List Gate הוא PrintSpoolRefresh על BW-MIS02, שם אחר מזה של הנבחנת. המעבדות לא עוברות על AccountName, שורת פקודה או ReportId, ולכן המסיחים לא נשללים אחד אחד.
- **la1, שאלה 2 (hash עם אלגוריתם):** נלמד בפריימר של The IOC List Gate, ועל שורת InitiatingProcessSHA256 באנטומיה. ה-hash של המעבדות שונה מזה של הנבחנת.
- **la1, שאלה 3 (רשומת timeline):** נלמד ב-Mark Up the Timeline על התחברות ל-gateway והעברת קבצים, ובדוגמת הפריימר על מוזיאון. אין שם משימה מתוזמנת, ProgramData או SYSTEM.
- **f1 (TaskName):** הערך נקרא מהרשומה הנבחנת ולא מופיע באף מעבדה.
- **qf1 (host ו-ActionType):** צורת השאילתה נלמדת בפריימר של Read the Record על UsbDriveMounted ו-mus-db01.museum.example. שני הערכים של הנבחנת לא מופיעים.
- **q2 (החלטה לא מתועדת):** נלמד ב-Which Decision Can Nobody Prove? על השהיית התחברות לפורטל ההורים, לא על שרת מושבת. העבודה בזמן אמת נלמדת בפריימר של Will This Claim Stand?. אף שורה לא שוללת את המסיחים על זיכרון מדויק או על תיק משפטי.
- **שאלת הביניים של r4 (שש השאלות):** עובדת זיכרון. היא מופיעה כנקודה בפריימר של Will This Claim Stand? והמעבדה לא שואלת אותה.
- **ac1 (benign true positive):** נלמד ב-Does It Go in the Report? על גיבוי לילי, סריקת פגיעויות וכניסת feed שגויה, עם קרוב-לטעות אחד: טיקט שמקושר אבל לא מתאים. אין במעבדה התחברות של אדמין, ולא CHG-2291.
- **q4 (גבול החיפוש):** נלמד ב-Will This Claim Stand? בשורות c3, c4 ו-c5, על gateways, בתי ספר ו-30 יום של לוגים. שתי המילים של הנבחנת לא מופיעות כצמד.
- **שאלת הביניים של r5 (למה האשמה היא כישלון):** נלמד בפריימר של Mark Up the Root Cause ובשורה 3 במעבדה, בלי הביטוי של השאלה ובלי ההסבר שלה.
- **q3 (המלצות גנריות):** נלמד ב-Which Gap Does It Close? על תרבות אבטחה, feed מודיעיני והצפנת מחשבים ניידים. שתי ההמלצות של q3 לא מופיעות, ואין במעבדה המלצה גנרית שנוסף לה בעלים, כדי לא לשלול את המסיח.
- **wr1 (האות המכריע של הבוס):** הגרסה הכתובה נבדקת לפי אורך, מזהים אמיתיים מועתקים במדויק, ואף ערך ממוצא. זה נלמד במעבדה משלו, What Earns the Marks, על גיליון של ארבע כתיבות תרגול בלי ערכי התיק. דוגמת הפריימר היא תיבת דואר במרפאה. הניסוח של תקציר ושל סיבת שורש נלמד ב-Mark Up the Final Draft על Bellwether. הפריימר מזהיר שערכים ממעבדות החדר נחשבים ממוצאים, כי הבודק סורק רק את תוכן החדר המקורי. נקודה בפריימר מפנה ל-Field notes של Reading 1 (סטטוס והשפעה) ושל Reading 5 (הפער), ולרשומה של la1 (ה-hash), בלי להביא את הערכים עצמם.

## סרטונים (כל אחד מסתיים בכרטיס NEXT MISSION עם הפעולה הראשונה, ולא חושף את תשובות התרגול שאחריו)
| סרטון | מתי | הפניה |
|---|---|---|
| Intro: "Half Term" | כניסה | תחנה 1 |
| Chapter 2: "Three Readers" | אחרי The Reader | תחנה 2 |
| Chapter 3: "The Reviewer Calls" | אחרי The Review | תחנה 4 |
| Finale: "Signed Off" | אחרי Final Report | החדר הבא |
