# תסריט חדר 95: Privileged Access Monitoring

**שם המבצע:** Operation Master Key
**רמה:** מתקדם (כל פריימר מקופל, `fold: true`)
**העולם:** Ironbridge Trust Bank (בנק בדוי): ספר חשבונות מרכזי אחד, וכספת שמנפיקה כל סיסמת אדמין בבניין.
**המנטור:** Wanjiru Castellan, PAM Security Lead. (בטקסטים במעבדות אין לשון זכר או נקבה.)

## סיפור הרקע
סגירת הרבעון ביום שישי, והמבקר של הרגולטור מבקש דבר אחד: לכל סשן אדמין על הספר המרכזי, ה-check-out שאישר אותו. ביום שלישי בלילה חיישן בשרת הדוחות ITB-RPT02 רושם רשומה חריגה, ו-Wanjiru Castellan כבר לא סומכים על הספירה. מכאן הסיפור הולך אחורה: קובץ KeePass ישן על share של IT, שנשמר עוד מלפני הכספת, הגיע למחשב סניף של j.vance. כ-30 שעות אחר כך מישהו ניסה להריץ פקודה מתוך SQL Server ונדחה. שני חשבונות שמעולם לא נכנסו לכספת הובילו לשרת הדוחות, ומשם יצא hash של חשבון מנוהל, adm-ledger01. הסיבוב של החשבון הזה הושהה בגלל עבודת batch של ספק, ולכן ה-hash המשיך לעבוד. בלילה ההוא נפתח סשן אדמין על ITB-LEDGER02 בלי שום check-out מאחוריו.

## המכניקה הייחודית של החדר
- **Who Used the Key?:** מעבדת `hunt` ב-KQL של חמישה שלבים עם טבלאות משלה (`SecurityEvent`, `SecurityEvent (4624)`, `PamSessions_CL`). הלומד מחבר 4672 ל-4624 של אותו סשן, ואז מעמיד את ההתחברויות מול הכספת ומוצא סשן אדמין אחד בלי check-out. מי שמחבר רק לפי החשבון מקבל "אין תוצאות" שנראה נקי, כי אותו חשבון נמשך באותו בוקר לשרת אחר.
- **Which Privileged Events Page Someone?:** מעבדת `tune` עם שני חוגות: כמה אישורים נמצאו (check-out, טיקט, חלון) ומה טווח ההגעה של היעד. המספר העגול 5 נכשל, והאירוע שלא מקפיץ אף אחד עדיין פותח טיקט.
- **Close, Contain or Verify?:** מעבדת `defuse` על ארבע התראות מהרבעון הקודם, כולן מותרות. היא מלמדת מתי הרשומה עצמה לא יכולה להכריע.
- **הגבול של החדר:** חדרים 34 ו-78 מכסים תקיפות AD ו-Kerberos. כאן נשארים על היום של החשבון המיוחס: מי משך את המפתח, ומה החשבון עשה אחר כך.

## העולם התלת-ממדי
אולם קלפים (`facility`, Hall) בשם Key Hall, עם `core: "matrix"` וארבעה קלפים לפי התחנות. סצנה `facilitymasterkey`, ערכת נושא `masterkey`.

## סדר המשימות
r1, r2, q3 | r3, q1, q2 | r4, la2, flag2 | r1b, la1, flag1, ac1

**הסדר שונה.** הסדר המקורי: r1, r1b, r2, r3, q1, q2, q3, la1, ac1, flag1, r4, la2, flag2. עכשיו q3 יושבת ליד קריאת הכספת, r4 ליד הלוג והדגל שלה, flag1 באה מיד אחרי la1 (ויש לה גם `logTask` קבוע), ו-ac1 סוגרת את החדר כבוס. r1b עברה אחרי r3 כי הטקסט שלה מתייחס ל-priv-r2 ול-Step 6 של priv-r3 כאילו כבר נקראו. אין בחדר דגל בנוסח "Log Analysis N".

## התחנות
| # | תחנה | משימות | המשחקים |
|---|---|---|---|
| 1 | The Vault | r1, r2, q3 | **Five Doors: How Far Each Kind of Account Reaches** (locks), **Read the Rights in One Admin Token** (inspect), **Read One Vault Check-Out** (anatomy), **Group Scope Picks the Event ID** (sort), **Route Each Question to the Record That Answers It** (reactor) |
| 2 | The Climb | r3, q1, q2 | **Put One Intruder's Climb in Order** (sequence), **Read One LSASS Handle** (anatomy) |
| 3 | The Unvaulted Key | r4, la2, flag2 | **Read One Refused xp_cmdshell Call** (anatomy), **Does This Parent Have a Reason?** (queue), **Time the Quiet Gap** (worksheet) |
| 4 (בוס) | Who Used the Key? | r1b, la1, flag1, ac1 | **Close, Contain or Verify?** (defuse), **Who Used the Key? Set Check-Outs Against Logons** (hunt), **Which Privileged Events Page Someone?** (tune), **Follow One Session From Its Rights to Its Approval** (trace) |

**הפרדה מהשאלות הנבחנות:**
- **שאלת הביניים של r1 (הזכות שקוראת זיכרון של תהליך אחר):** עובדת זיכרון. היא מופיעה בדרך אגב כשורה עם תווית ב-Read the Rights in One Admin Token, על adm-win03 ו-ITB-FS02. המעבדה לא שואלת אותה, ו-SeTcbPrivilege לא מופיעה בה.
- **שאלת הביניים של r3 (DCSync):** עובדת זיכרון. היא מופיעה כשורה עם הערה ב-Put One Intruder's Climb in Order. המעבדה שואלת על סדר הצעדים, לא על השיטה.
- **q1 (מה אומר 0x1FFFFF מ-PowerShell על LSASS):** נלמד ב-Read One LSASS Handle על rptcollect.exe עם 0x1010, ובדוגמת הפריימר על memsnap ודפדפן. אין במעבדה PowerShell, ואף שורה לא מזכירה את המסיחים על סריקה, ניהול סשנים או גיבוי.
- **q2 (איזה זוג אירועים לחבר):** ההיקף של הקבוצה נלמד ב-Group Scope Picks the Event ID על קבוצות אחרות, עם דוגמת פריימר על Account Operators, ו-4720 נלמד ב-Route Each Question. Domain Admins מופיעה רק כנתון בשורת היקפים בפריימר. שום מעבדה לא מחברת את 4720 לאירוע קבוצה.
- **q3 (המטרה של כספת PAM):** עובדת זיכרון. היא מופיעה כשדות ברשומה אחת ב-Read One Vault Check-Out, והמעבדה לא שואלת מה מטרת הכספת. ההערות מתארות שדות ולא פוסלות אף מסיח.
- **la1, שאלה 1 (איזו ראיה מראה שימוש בזכות):** מה כל רשומה מתעדת נלמד ב-Route Each Question ובפריימר Holding a right is not using it, על SeLoadDriverPrivilege ועל שרתים אחרים. הפריימר מתאר רשומות ולא עובר על ארבע האפשרויות.
- **la1, שאלה 2 (התרחיש המסוכן ביותר):** נלמד בנקודה בפריימר של Read One LSASS Handle: כמה LSASS מחזיק תלוי במכונה. אין במעבדות svc-backup, DC01 או 03:22.
- **la2, שאלה 1 (למה הורה-ילד מספיק):** נלמד ב-Does This Parent Have a Reason? על w3wp, spoolsv, tomcat, CcmExec, explorer וה-Task Scheduler, ובדוגמת הפריימר על dns.exe. מנוע מסד הנתונים לא מופיע שם כהורה.
- **la2, שאלה 2 (מה קרה בפער של שש שעות):** נלמד ב-Time the Quiet Gap על קובץ KeePass ופער של 30 שעות, ובדוגמת הפריימר על ZIP של HR. אין שם svc-mssql, 4769 או RC4.
- **flag2 (ההרשאה):** המעבדה מראה איפה לקרוא: השדה `sql.database_role` ברשומה שנדחתה, עם הערך db_datareader. הערך הנבחן לא מופיע באף מעבדה, והוא נקרא מהרשומה הנבחנת.
- **flag1 (הערך שקושר 4672 ל-4624):** השדות נלמדים בפריימר של ה-hunt, ומתורגלים בשלב הראשון של Follow One Session על 0x3C88E10. הערך הנבחן לא מופיע במעבדות.
- **שאלת הביניים של r1b ו-ac1 (permitted מול authorised):** האות המכריע של הבוס נלמד במעבדה משלו, Close, Contain or Verify?, על קבוצת Treasury, על שרת הניהול של ה-firewall, על שער התשלומים ועל שרת קבצים, בלי מסד נתונים, בלי טבלת לקוחות ובלי שאילתה גדולה. דוגמת הפריימר היא חדר ספרים נדירים בספרייה. הפריימר מגדיר את שתי השאלות ולא דן באף אפשרות של הנבחנת.

## סרטונים (כל אחד מסתיים בכרטיס NEXT MISSION עם הפעולה הראשונה, ולא חושף את תשובות התרגול שאחריו)
| סרטון | מתי | הפניה |
|---|---|---|
| Intro: "The Count" | כניסה | תחנה 1 |
| Chapter 2: "Signed Out" | אחרי The Vault | תחנה 2 |
| Chapter 3: "Report Server" | אחרי The Climb | תחנה 3 |
| Finale: "The Master Key" | אחרי Who Used the Key? | החדר הבא |
