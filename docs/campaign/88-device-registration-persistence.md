# תסריט חדר 88: Device Registration Abuse & MFA Persistence

**שם המבצע:** Operation Extra Device
**רמה:** בינוני
**העולם:** Stonehaven Credit Bureau (לשכת אשראי בדויה): 640 עובדים, ותיקי האשראי של 11 מיליון צרכנים מאחורי התחברות אחת.
**המנטור:** Adaeze Romero, Identity Analyst. (בטקסטים במעבדות אין לשון זכר או נקבה.)

## סיפור הרקע
ביום רביעי ה-IT איפס את הסיסמה של Gwen Tallis, ראשת צוות Disputes, אחרי דיווח על מייל פישינג, והטיקט נסגר עד הצהריים. ביום שישי בבוקר הסיסמה ההיא כבר לא עובדת, ואף אחד ב-Stonehaven לא החליף אותה. Adaeze פותחת את מרכז הניהול ומתחילה מהשאלה הפשוטה ביותר: מה החשבון הזה בעצם מחזיק? ברשימת המכשירים יש טלפון שאף אחד לא קנה.

## המכניקה הייחודית של החדר
- **The Phone Nobody Bought:** פורטל בסגנון Entra, 16 צעדים על רשימת המכשירים, Audit logs, רשימת שיטות האימות, Sign-in logs ו-Risky users. הלומד משווה את All devices מול מרשם הנכסים, קושר `Register device` ו-`User registered security info` להתחברות שקדמה להם, רואה Primary Refresh Token בהתחברות לתיקי האשראי, ומגלה ששני איפוסי סיסמה לא נגעו באף אחת משתי הרשימות.
- **הלקח של החדר:** איפוס סיסמה משנה סיסמה. הוא לא מסיר מכשיר רשום ולא מסיר שיטת אימות רשומה.
- **What Did It Touch?:** ריצת `rush` שבה כל קלף הוא פעולה אחת ואובייקט אחד: עדיין שם, או נעלם.
- **Six Registrations, One Intruder:** `deduce` על שישה רישומים אמיתיים מאותו שבוע. עמודת ה-roles לא עוזרת אף פעם, וזו הנקודה.

## העולם התלת-ממדי
אי קמפוס (`facility`, Campus) של Stonehaven עם Hub בשם IDENTITY OPERATIONS HUB וחמישה מבנים לפי התחנות, מפוזרים כך שאף מבנה לא מסתיר מבנה אחר ואף אחד לא עומד מול ה-Hub.

## סדר המשימות
r1, r2, q1, q1b | r3, m1 | r4, la1, o1 | r5, ac1, q3 | qf1, f1, q4

(הסדר המקורי נשמר.)

## התחנות
| # | תחנה | משימות | המשחקים |
|---|---|---|---|
| 1 | The Device List | r1, r2, q1, q1b | **Way In or Way Back?** (sort), **Read One Registration Record** (anatomy), **The Phone Nobody Bought** (portal), **Old List, New List** (worksheet) |
| 2 | The Reset | r3, m1 | **What Did It Touch?** (rush) |
| 3 | The Timing | r4, la1, o1 | **Six Registrations, One Intruder** (deduce), **Three Clean-ups That Went Wrong** (simulate) |
| 4 | Routine or Not | r5, ac1, q3 | **Close It With a Reason** (queue) |
| 5 (בוס) | Close the Case | qf1, f1, q4 | **Which Table Holds It?** (sort), **The Laptop That Outlived the Rotation** (trace) |

**הפרדה מהשאלות הנבחנות:**
- **בדיקת הביניים של r1 ‏(T1098.005):** ה-primer של Way In or Way Back מציג את T1098.005 כנתון עם התווית שלו, בלי לשאול עליו. הדוגמה היא T1098.004 על jump host. הטכניקות האחרות שמופיעות כאפשרויות בבדיקה לא מוזכרות בכלל.
- **q1 (השוואת oldValue ו-newValue):** הדוגמה ב-Old List, New List היא הוספת מספר קולי שלוקח את ה-Default. התרגול מלמד הסרה רק על r.naidoo עם TwoWayVoiceMobile, בלי OneWaySMS ובלי הזוג PhoneAppNotification מהשאלה. שורה נוספת של h.mbeki מלמדת ששם זהה פעמיים הוא שתי שיטות, על PhoneAppOTP, כהכנה לקריאת הרשומות ב-la1 וב-ac1.
- **q1b (שיטה מול מכשיר):** ה-primer של הפורטל מתאר שתי רשימות, ושני הצעדים בפורטל מראים רשומה מכל סוג על החשבון של Gwen. שום ניסוח של אפשרות לא מופיע.
- **בדיקת הביניים של r3 (הסיסמה דלפה שוב):** השורה "מפתח שלא פג" ב-primer של What Did It Touch? מלמדת את הרעיון, בלי דליפה ובלי תרחיש הסיסמה מהשאלה.
- **m1 (התאמת שדות):** Read One Registration Record מלמדת `initiatedBy.user.id`, `roles`, `targetResources[0].id`, `StrongAuthenticationMethod` ו-`correlationId` על הרשומה של n.brandt. הפורטל מלמד `Register device`, ו-primer הפורטל מלמד SSPR.
- **la1 (שלוש שאלות):** הקריאה הועברה ל-g.tallis מ-203.0.113.58 בריגה, 17 דקות אחרי ההתחברות (לא 9), והשיטה נוספת לצד שתיים קיימות (לא אחת). שאלה 3: הקלפים ב-rush מלמדים על מספר טלפון, כלל דואר ומכשיר, ולא מצמידים ביטול sessions או חסימת IP לשיטה, כדי לא לפסול את המסיחים אחד אחד.
- **o1 (סדר הטיפול):** Three Clean-ups That Went Wrong מציגה רק שלושה מקרים שבורים, ולא סדר נכון שלם. ה-primer נותן שלושה כללי תלות שלא לפי הסדר, והחזרה של המשתמש בסוף דרך ערוץ מאומת נלמדת על דוגמת הצינור הדולף, עם דייר שחוזר רק אחרי שבעל הבית מאמת מי הוא.
- **ac1 (פסק דין):** התור ב-Close It With a Reason עוסק בגל רענון של 38 חשבונות, במשתמש נעול שקיבל עזרה ובהתראה שגויה של כלל רחב מדי, לא בהחלפת טלפון עם שיחה ל-helpdesk. ה-primer מלמד benign true positive על כלל אחר עם CHG-3310.
- **q3 (roles ריק):** אף שורה לא טוענת שהשדה לא מכריע. ב-deduce חמישה מששת החשבונות מראים `[]`, והלומד רואה בעצמו שהעמודה לא עזרה.
- **qf1 (שאילתה):** `User registered security info` מופיע ברשומות, ו-`RiskLevelDuringSignIn` מופיע כשורת נתון בהתחברויות בפורטל, ושניהם לא נשאלים. Which Table Holds It? ממיינת עמודות אחרות, והדוגמה בנויה על `User deleted security info` ו-`AppDisplayName`.
- **f1 (הכתובת):** `initiatedBy.user.ipAddress` מוסבר בקריאת הרשומה של n.brandt, עם ערך אחר, והתרגול חוזר בפורטל.
- **q4 (מה נשאר אחרי הכול):** הסיגנל המכריע מקבל מעבדה משלו, The Laptop That Outlived the Rotation: לפטופ של קבלן שנרשם בינואר, עבר רוטציית סיסמאות במאי ועדיין עונה על בדיקת המכשיר ביוני. אין שם תוקף ואין Authenticator.

## סרטונים (כל אחד מסתיים בכרטיס NEXT MISSION עם הפעולה הראשונה, ולא חושף את תשובות התרגול שאחריו)
| סרטון | מתי | הפניה |
|---|---|---|
| Intro: "The Wednesday Password" | כניסה | תחנה 1 |
| Chapter 2: "Still Locked Out" | אחרי The Device List | תחנה 2 |
| Chapter 3: "A Long Queue" | אחרי The Timing | תחנה 4 |
| Finale: "Close the Case" | אחרי Close the Case | החדר הבא |
