# תסריט חדר 81: Ransomware: Full Attack Lifecycle

**שם המבצע:** Operation Cold Vault
**רמה:** מתקדם
**העולם:** Marchbank Cold Storage (חברת אחסון בקירור בדויה): תשעה מחסני קירור, 640 עובדים, ומערכת dispatch אחת שאומרת לכל מלגזה מה להוציא.
**המנטור:** Elodie Kamau, Incident Commander. (בטקסטים במעבדות אין לשון זכר או נקבה.)

## סיפור הרקע
יום שני, 05:52. על מסכי ה-dispatch מופיע מכתב כופר, המלגזות עוצרות, והפיקוד על האירוע עובר ל-Elodie Kamau. כולם רוצים להתחיל מהמכתב. אצל Elodie המכתב הוא רק נקודת הפתיחה להליכה אחורה: הוא העמוד האחרון של סיפור שהתחיל 26 ימים קודם, בכניסה אחת של חשבון קבלן מהקירור. בדרך היו ברוקר שמכר את הגישה, affiliate שעבד קרוב לשלושה שבועות, עובד BMS שהחשבון שלו הגיע בטעות ל-Domain Admins, ו-140 GB של חוזי לקוחות שיצאו שלושה ימים לפני שקובץ אחד הוצפן.

## המכניקה הייחודית של החדר
**Where Could You Have Stopped It?** אירוע אחד מושמע לאחור מהמכתב עד הדריסת רגל הראשונה, ובכל שלב הלומד מחפש את הנקודה האחרונה שבה מגן עוד יכול היה לשבור את השרשרת.
- **Walk It Back From the Note:** ‏`sequence` שפותח את החדר. שבע ראיות בלי תאריכים, מהמכתב אחורה, והשאלה היא תמיד "מה האירוע הזה היה צריך קודם?". ההליכה נגמרת בכניסה הראשונה, ומשם מתחילה התחנה הראשונה, The Foothold.
- **Walk It Back From the Cleared Log:** ‏`sequence` שני, על שרת אחד שה-Security log שלו נמחק. הוא מראה שכלי ההגנה נופלים לפני ההעברה הגדולה, והשחזור והראיות רק בשעות האחרונות.
- **The Encryption Run:** ‏`outbreak` על הריצה עצמה. הלומד מבודד מארח אחד בכל תור ומרגיש כמה מעט נשאר להציל בשלב הזה.
- **What Each Earlier Cut Would Have Saved:** ‏`defuse` שמחזיר את כל הסיפור לאחור, מיום ראשון בלילה ועד יום ‎-26. כל חיתוך מוקדם יותר קטן יותר ומציל יותר. המסר: המכתב הוא הקבלה, לא האירוע.

## העולם התלת-ממדי
אולם קלפים (`facility`, ‏hall) עם ליבה מסוג `chain`: שרשרת שמרחפת מעל הכן, וקלף לכל תחנה. האולם נושא את שם החברה.

## סדר המשימות
r1, r2, q1 | r3, r4, la1 | r5, q2, r6, o1 | r7, la2, ac1, m1 | r8, la3, q3, f1

**הסדר שונה מהחדר המקורי.** במקור m1 יושבת מיד אחרי q2, אבל שלושה מתשעת הזוגות שלה (shadow copies, ניקוי לוגים, exfiltration לענן) נלמדים רק ב-r6 וב-r7. לכן m1 עברה לסוף התחנה הרביעית. הקריאות נשארו בסדר 1 עד 8, ו-o1 ו-la2 נשארו מיד אחרי הקריאה שאומרת שהן באות אחריה.

## התחנות
| # | תחנה | משימות | המשחקים |
|---|---|---|---|
| 1 | The Foothold | r1, r2, q1 | **Walk It Back From the Note** (sequence), **What Does a Restore Undo?** (sort), **Three Businesses Behind One Note** (match), **Find the First Door** (deduce), **Right Door, Right Fix** (defuse) |
| 2 | The Master Key | r3, r4, la1 | **Signed by Microsoft, Run by the Crew** (match), **One Task, or a Fleet?** (worksheet), **Whose Token Reaches the Domain?** (deduce), **What Did They Just Take?** (defuse), **Anatomy of an LSASS Read** (anatomy) |
| 3 | The Cold Aisle | r5, q2, r6, o1 | **Three Tools, Three Traces** (sort), **Admin or Intruder?** (deduce), **Walk It Back From the Cleared Log** (sequence), **Retention Job or Last Warning?** (sort) |
| 4 | The Loading Dock | r7, la2, ac1, m1 | **Which Server Is Packing to Leave?** (deduce), **Anatomy of an Upload** (anatomy), **Inside a Live Transfer** (defuse), **Same Alert, Different Night** (sort), **The Case File, Line by Line** (worksheet) |
| 5 (בוס) | The Note | r8, la3, q3, f1 | **Why Nobody Can Just Get the Key** (match), **Anatomy of an Encryptor** (anatomy), **The Encryption Run** (outbreak), **What Each Earlier Cut Would Have Saved** (defuse), **Which Host Gets the Technician?** (deduce), **Facts for Those Who Decide** (defuse) |

**הפרדה מהשאלות הנבחנות:**
- **שאלת הביניים של r1** (מה נשאר בידי התוקף אחרי שחזור נקי): What Does a Restore Undo?, עם הפריימר על שני המנופים. שונה: הלומד ממיין נכסים של Marchbank, בלי שאלה על מקרה שחזור.
- **שאלת הביניים של r2** (למה התקני קצה): הטבלה של Find the First Door (עמודת הסוכן) והסיבוב edge ב-Right Door, Right Fix (פגיעות שפורסמה לפני שישה ימים, בלי סוכן), והלומד מסיק מהם. שונה: המעבדה מוצאת שהדלת הייתה RDP, ואין בה ניסוח של התכונות.
- **q1** (השערת וקטור כניסה): הרמזים של Find the First Door מסלקים דלתות לפי מה שהלוגים מראים, גם כשמשהו חסר, והדוגמה בפריימר מראה הרגל של השערה שנכתבת עכשיו. שונה: הכניסה ב-Marchbank היא RDP חשוף, הדוגמה מסתיימת ב-T1566, ומקרה ה-edge הוא שער העברת קבצים אצל חברה אחרת, לא VPN.
- **o1** (סדר תשעת השלבים): הסדר נבנה משני ה-sequence, מהפריימר של Signed by Microsoft (הרצה, עמידות, ואז סיור) ומהפריימר של Walk It Back From the Cleared Log (כלי הגנה לפני ההעברה, shadow copies ולוגים ממש לפני ה-Impact). שונה: אירועים קונקרטיים בלי שמות שלבים, שבעה ושישה ולא תשעה, ולאחור.
- **שאלת הביניים של r4** (DCSync): הפריימר של What Did They Just Take? מסביר replication ואת שתי ההרשאות, וסיבובים 1 עד 3 מבחינים בין LSASS, ‏DCSync והעתקת NTDS.dit. שונה: מקרה של f.nkosi ואירוע 4662, דוגמת המפתחות של מלון, ובלי נוסח האפשרויות.
- **la1 שאלה 1** (rundll32 ו-comsvcs): הסיכום של Anatomy of an LSASS Read נותן עובדה אחת לזכירה: הפונקציה MiniDump והפרמטרים שלה. שדה TargetProcessId מראה שה-PID נרשם באירוע. שונה: הרשומה היא Sysmon 10 של כלי בשם rtkhelper.exe, בלי פקודת comsvcs ובלי ערכים, והמסקנה נשארת ללומד.
- **la1 שאלה 2** (מסכה והרשאות): הערכים בשדה GrantedAccess ו-Whose Token Reaches the Domain?. שונה: המסכה 0x1410, הכלי רץ כ-SYSTEM, והחשבון הוא מהנדס BMS דרך Legacy-ServerOps, לא טכנאי helpdesk.
- **la1 שאלה 3** (מיקום הקובץ): הנתון בשדה SourceImage, וה-why של הטבלה ב-One Task, or a Fleet? על שם שמסווה פעולה. שונה: תיקייה של ספק אחר ושם אחר, והמעבדה לא מסבירה למה נבחר המיקום.
- **la1 שאלה 4** (התגובה): סיבובים 1 ו-2 של What Did They Just Take? והלקח שלו מלמדים שהשאלה היא מה יצא ולאן הוא מגיע, ו-Whose Token Reaches the Domain? מלמד שההגעה נקבעת בקבוצות. שונה: אין סיבוב תגובה על דאמפ. הסיבוב הרביעי עוסק באיפוס כפול של krbtgt.
- **שאלת הביניים של r5 ו-q2** (הדפוס ולא הכלי): Admin or Intruder? ו-Three Tools, Three Traces. ההשוואה בין f.nkosi ל-adm-l.varga נשארת ברמת השעה והטיקט. שונה: שירות בשם CHLRSVC על 11 מארחים, ולצידו אדמין כמעט זהה עם טיקט, לא PSEXESVC על שני שרתים.
- **m1** (התאמת טכניקות): The Case File, Line by Line מציג את המזהים כנתון בשורה ולא שואל עליהם. השאלות על ימים ושורות. התיאורים של Marchbank, לא של הזוגות.
- **שאלת הביניים של r7** (למה חלון ה-staging): Which Server Is Packing to Leave?: הנפחים ב-MB-ACC-03 נשארו בפנים, ו-MB-FS-01 הראה אותו אות יום לפני ש-140 GB יצאו. הלומד מסיק את ערך החלון. שונה: שרת ACC-03 ו-.rar, בלי מקרה של Finance.
- **la2 שאלה 1** (מיקום והפעלה): Anatomy of an Upload, שדות FilePath, ‏ParentBaseFileName ו-SHA256HashData. ההערות מתארות מה השדה מראה ולא שופטות. שונה: MEGAcmd ולא rclone.
- **la2 שאלה 2** (קריאת הפקודה): הפריימר של Anatomy of an Upload מגדיר את `--config`, ‏`-q`, ‏`--transfers` ו-`copy`. שונה: הגדרות בלבד, בלי דוגמת rclone, והדוגמה המעובדת היא עבודת azcopy.
- **la2 שאלה 3** (קשר לאירוע): הערך בשדה UserName, מול שורת ה-DCSync ב-The Case File. שונה: חשבון אחר אחרי DCSync, לא החשבון של הדאמפ.
- **la2 שאלה 4** (מה עושים עכשיו): Inside a Live Transfer מלמד למה תהליך רץ לא מושפע משינוי בחשבון ואיפה חסימה באמת עוצרת תעבורה. שונה: אין סיבובי טיקט בדיעבד או המתנה להצפנה, יש שאלות על נקודת הבקרה ועל דיווח של 9 מתוך 34 נפחים.
- **ac1** (benign true positive): Same Alert, Different Night, עם השדה הנסתר שמראה מה ה-config באמת אומר, והפריימר על שלושת ה-verdict. שונה: AzCopy ו-WinSCP, לא rclone ל-SharePoint, ועם רשומות CHG אחרות.
- **la3 שאלה 1** (התחזות): Anatomy of an Encryptor, שדות FileName ו-FilePath, והגדרת masquerading בפריימר. שונה: spoolsrv.exe מול spoolsv.exe, לא wuauclt, בלי הערות על SysWOW64 או על החשבון.
- **la3 שאלה 2** (הארגומנטים): שדה CommandLine מציין רק מה כל דגל, והפריימר מבחין בין מודל עסקי של כופר לבין wiper. שונה: דגלים אחרים ויעדים C:\ ו-D:\, והקישור בין רשימת ההחרגה לאתחול נשאר ללומד.
- **la3 שאלה 3** (האות המכריע של הבוס): מעבדה משלו, Which Host Gets the Technician?, על שישה מארחים עם מצבי חיישן שונים, וההשוואה בין השורות היא הלמידה. שונה: השאלה היא לאן לשלוח טכנאי, לא מה אומרת חסימה אחת. Marchbank, ובלי המספרים 61 ו-140.
- **q3** (מה עושים עכשיו): Facts for Those Who Decide מלמד מי הבעלים של כל שאלה: עיתונות, רגולטור, הודעות לעובדים ותשלום. הגדרת הבידוד בפריימר של The Encryption Run וה-sort על שחזור ב-r1 מאפשרים להסיק את השאר. שונה: אף סיבוב אינו מסיחי q3.
- **f1** (השם החדש של הקובץ): שדה FileRename ב-Anatomy of an Encryptor מראה שהסיומת נוספת אחרי השם המלא. שונה: pallet_plan.xlsx וסיומת אחרת.

## סרטונים (כל אחד מסתיים בכרטיס NEXT MISSION עם הפעולה הראשונה, ולא חושף את תשובות התרגול שאחריו)
| סרטון | מתי | הפניה |
|---|---|---|
| Intro: "05:52" | כניסה | תחנה 1 |
| Chapter 2: "The Listing" | אחרי The Foothold | תחנה 2 |
| Chapter 3: "The Quiet Week" | אחרי The Cold Aisle | תחנה 4 |
| Finale: "The Receipt" | אחרי The Note | החדר הבא |
