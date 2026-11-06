# תסריט חדר 62: Authentication & Identity Monitoring

**שם המבצע:** Operation Who Goes There
**רמה:** בינוני
**העולם:** Silverpine Credit Union (איגוד אשראי בדוי): 310 עובדים, 12 סניפים, וחברים שסומכים על כך שמישהו שומר על הדלת.
**המנטור:** Tove Ramirez, Identity Security Lead. (בטקסטים במעבדות אין לשון זכר או נקבה.)

## סיפור הרקע
כל דפיקה בדלת של Silverpine נכתבת. Windows קורא לזה Security log, ו-Tove קוראים לזה ספר הכניסות. הבוקר הספר התמלא בכישלונות התחברות, כולם תחת אותו מזהה אירוע. אחד מהם הוא טלר שחזר מחופשה. האחרים לא. התפקיד של הלומד הוא לקרוא שורה אחת, אחר כך את התבנית שעל פני אלפי שורות, ולומר מי עומד בדלת.

## המכניקה הייחודית של החדר
**קוראים תבנית, לא שורה.** אותו מזהה אירוע אומר דברים שונים לגמרי לפי הצורה שלו לאורך זמן.
- **Same Error, Three Stories:** פורטל בסגנון Entra. שתי שורות כישלון זהות לחלוטין (50126) מתגלות, רק אחרי קיבוץ לפי מקור, כשלושה סיפורים: אדם ששכח סיסמה, spray ו-stuffing. משם הלומד ממשיך להצלחה, להוכחה שניתנה, למדיניות שלא חלה, לנסיעה הבלתי אפשרית, ללוג Windows המקורי, לקובץ השיתוף ולחסימת החשבון.
- **Tune the Failed-Logon Rule:** כוונון של שני ספים על שתים-עשרה פרצי 4625 בצורות אמיתיות: חשבונות שונים ממקור אחד ביום, וחשבונות שונים בשעה העמוסה ביותר. המספרים העגולים נכשלים: סף שעתי של 15 מפספס spray איטי של ניסיון כל 5 דקות, סף של 10 מקפיץ התראת שווא על probe ניטור, וסף יומי של 10 מקפיץ התראה על פקיעת סיסמאות בסניף.

## העולם התלת-ממדי
אי קמפוס (`facility`) של Silverpine: ארבעה מבנים לפי התחנות, ו-Hub שנושא את שם החברה. תצורת ה-`theme` היא `whogoes` וה-`scene` הוא `facilitywhogoes`.

## סדר המשימות
r1, q3 | r2, q1, q2 | r3, o1 | la1, flag1

הסדר השתנה מהסדר השמור (r1, r2, r3, q1, q2, q3, la1, o1, flag1), כי שם שלוש הקריאות יושבות ברצף בתחילת החדר ואין קיבוץ לתחנות.

## התחנות
| # | תחנה | משימות | המשחקים |
|---|---|---|---|
| 1 | The Logon Book | r1, q3 | **Anatomy of a Failed Logon** (anatomy), **Does the Logon Type Fit the Account?** (queue), **Kerberos or NTLM?** (sort), **Follow Borrowed Credentials** (trace) |
| 2 | Read the Shape | r2, q1, q2 | **Same Error, Three Stories** (portal), **How Fast Would They Have to Fly?** (worksheet), **Where a Forged Ticket Shows** (sort) |
| 3 | Set the Watch | r3, o1 | **Tune the Failed-Logon Rule** (tune), **Walk the Failed-Logon Alert** (defuse), **Rebuild the Attack from the Log** (sequence) |
| 4 (בוס) | Who Goes There? | la1, flag1 | החקירה הנבחנת |

**הפרדה מהשאלות הנבחנות:**
- **שאלת הביניים של r1 ‏(Type 5 ו-Domain Admin):** השורה "Review: LogonType 5" ב-queue מלמדת ש-Type 5 הוא Service על svc-backup, חשבון שירות שעושה את עבודתו. השורה "Review: LogonType 4" מלמדת את הכלל על Domain Admin, דרך Batch ועל adm.ruiz. בלי adm.kowalski ובלי שרת קבצים.
- **שאלת הביניים של r2 ‏(stuffing מול spray):** בפורטל, השלבים `spray` ו-`stuff` מלמדים את ההבדל על 203.0.113.62 ועל 198.51.100.34, ו-`why` של השלב `stuff` מסביר למה סיסמאות שנעשה בהן שימוש חוזר פשוט עובדות. אין נוסח תשובה משותף.
- **q1 ‏(80 אירועים, 75 חשבונות):** מקור ה-spray בפורטל הוא 41 חשבונות, ניסיון אחד לכל חשבון, 7 דקות, וללא 203.0.113.77. שאלת הפורטל היא "מי מנחש סיסמה אחת", והגרסה הנבחנת דורשת ליישם אותה על מספרים אחרים.
- **q2 ‏(לונדון וסידני):** ב-worksheet הזוגות יוצאים מ-Tacoma אל Frankfurt, Singapore ו-Denver, עם חישוב המהירות (שאלה `speed`) והחרגת יציאת VPN (שאלה `vpn`). ההבחנה מ-atypical location ומ-concurrent session נמצאת ב-`why` של `fly`. בפורטל הזוג הוא Tacoma ו-Sao Paulo.
- **q3 ‏(k.ito, svc-sql, SQL02):** ה-trace מלמד את הצמד 4648 במקור ו-4624 Type 3 ביעד על אדמין שמשתמש בחשבון השני של עצמו (p.lindqvist אל adm.lindqvist, SP-PAY01), ואז מקרה ישן בעמדת טלר. אין חשבון שירות ואין SQL.
- **la1 שאלה 1 ‏(0xC000006A):** שדה SubStatus באנטומיה מראה את הקודים כנתון, על רשומה עם 0xC0000064 (שם שהוקלד לא נכון). סיבוב d1 ב-defuse מיישם אותם על מקור אחר.
- **la1 שאלה 2 ‏(Type 3 ו-NTLM):** האנטומיה היא Type 10 עם Negotiate. הרעיון של נפילה ל-NTLM כשפונים לשרת לפי IP נלמד בפריט `c` ב-sort "Kerberos or NTLM?", על מכונת צילום שכותבת ל-\\10.20.4.12\Scans.
- **la1 שאלה 3 ‏(שלושה חשבונות שהתחברו):** השלב `block` בפורטל הוא חשבון אחד מריצת stuffing, וסיבוב d4 ב-defuse הוא חשבון אחד בשם אחר, ובשניהם הנוסח שונה. אין 62 אירועים, 58 חשבונות או CORP-AUTH-0101.
- **o1 (סדר שלבי ה-spray):** ה-sequence משתמש בקטעי לוג ממקרה סגור ובלי חותמות זמן, לא בשמות השלבים ולא בנוסח שלהם. הלומד מתרגם אירועים לשלבים.
- **flag1 ‏(כתובת המקור):** ההערה של השדה IpAddress באנטומיה מלמדת שזה השדה לחיפוש מכישלון להצלחה, על 10.30.8.44. סיבוב d2 מיישם אותו. הכתובת הנבחנת לא מופיעה בשום מעבדה.

**כיסוי הקריאות:** logon types בכל ה-queue; 4768, 4769, 4771 ו-NTLM ב-sort הראשון; 4648 ב-trace; 4740 בפורטל ובסיבוב d3; Golden Ticket וכל האינדיקטורים שלו, כולל klist, ב-sort "Where a Forged Ticket Shows"; שבעת שלבי החקירה בסיבובי ה-defuse; כוונון ספים ב-tune.

## סרטונים (כל אחד מסתיים בכרטיס NEXT MISSION עם הפעולה הראשונה, ולא חושף את תשובות התרגול שאחריו)
| סרטון | מתי | הפניה |
|---|---|---|
| Intro: "The Logon Book" | כניסה | תחנה 1 |
| Chapter 2: "Same Word, Every Line" | אחרי The Logon Book | תחנה 2 |
| Chapter 3: "The Rule Tove Wants" | אחרי Read the Shape | תחנה 3 |
| Finale: "Who Goes There" | אחרי הבוס | החדר הבא |
