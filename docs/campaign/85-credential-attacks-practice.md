# תסריט חדר 85: Credential Attacks in the Logs

**שם המבצע:** Operation Spray Paint
**רמה:** בינוני
**העולם:** Mariposa Hotels Group (רשת מלונות בדויה): 38 מלונות, 7,400 עובדים, דומיין אחד, וכל דלפק קבלה מתחבר לאותם שני domain controllers.
**המנטור:** Ewan Tshabalala, Detection Analyst. (בטקסטים במעבדות אין לשון זכר או נקבה.)

## סיפור הרקע
יום שישי, 07:10. קיר ה-failed logons ב-SOC של ליסבון אדום מקצה לקצה, שלושה ימים לפני שבעלי המלונות מגיעים לכנס השנתי. כותרות החוקים על הקיר אומרות דברים שונים, ו-Ewan לא מאמין להן. על הקיר יש כמה התקפות שונות, כל אחת דורשת תגובה אחרת, ואחת מהן אולי כבר הצליחה.

## המכניקה הייחודית של החדר
**Tell the Attacks Apart by Their Shape.**
- **From Failures to Breadth:** מעבדת `hunt` ב-KQL על `IdentityLogonEvents`, חמישה שלבים: מכשלונות גולמיים לשורה לכל מקור וחשבון, ומשם לכמה חשבונות שונים כל מקור נגע בהם. המקור עם הכי הרבה כשלונות נוגע בחשבון אחד, והסדר מתהפך מול העיניים.
- **Name the Shape From the Numbers:** מעבדת `sort`. ממצאים בלי תווית, רק מספרים: חשבונות, ניסיונות, מקורות, הצלחות. הלומד מסווג brute force, spray ו-stuffing, ושני קלפים נושאים כותרת חוק מטעה.
- **Prove a Success Followed:** מעבדת `hunt` שנייה, ארבעה שלבים, על אותה טבלה. ה-join הוא על חשבון יחד עם מקור, והשעון מוכיח שההצלחה באה אחרי הכשלונות. חדר 62 כבר מכסה tune של ספירה בחלון זז, ולכן כאן אין כיוונון בכלל, רק כתיבת השאילתה.
- **משחקי הארקייד:** hunt + intercept + spotdiff.

## העולם התלת-ממדי
אולם קלפים (`facility`, Hall) של Mariposa עם ליבת `matrix` וארבעה קלפים לפי התחנות.

## סדר המשימות
r1, r2, q1, m1 | la1, la2, f1, q2 | ac1, o1 | qf1

**הסדר שונה:** f1 עבר מאחרי qf1 אל מיד אחרי la2, כי הוא קורא את הרשומה של la2, וכך qf1 נשאר המשימה האחרונה של הבוס. הטקסט של f1 אומר "Log Analysis 2" וזה עדיין נכון: la1 ו-la2 שומרים על הסדר שלהם, ורק שתי המשימות האלה הן Log Analysis בחדר.

## התחנות
| # | תחנה | משימות | המשחקים |
|---|---|---|---|
| 1 | The Wall | r1, r2, q1, m1 | **Does It Touch a Sign-In at All?** (sort), **A Typo Beside a Script: What Actually Differs** (spotdiff), **Read the Outcome Code** (worksheet), **From Failures to Breadth** (hunt), **Name the Shape From the Numbers** (sort) |
| 2 | The Shape | la1, la2, f1, q2 | **Why Didn't It Lock?** (worksheet), **First Moves on a Deep Burst** (sequence), **Is the Cap an Accident?** (worksheet), **Prove a Success Followed** (hunt) |
| 3 | After the Burst | ac1, o1 | **Name the Verdict** (queue), **Explain It or Escalate It** (intercept), **After the Hit** (sequence) |
| 4 (בוס) | The Detection | qf1 | **Pick the Window and the Bar** (worksheet), ואז השאילתה הנבחנת |

**הפרדה מהשאלות הנבחנות:**
- **נקודת הביניים של r1 (למה dumping לא מופיע):** הפריימר של Does It Touch a Sign-In at All? מגדיר את ארבע הטכניקות על כספות חדר. הקלפים הם comsvcs MiniDump, reg save, ntds.dit ו-Sysmon 10, בלי שאלות על Kerberos, SPN או 4768.
- **q1 (מעבר ל-0xC0000234):** השורה מופיעה רק כנתון עם תווית בכרטיס הקודים של Read the Outcome Code. המעבדה שואלת על 0xC0000064 ועל 0xC0000071, ואין בה ריצה שמתחלפת לקוד נעילה.
- **m1 (התאמת טכניקה לחתימה):** Name the Shape From the Numbers מלמד מארבעה מספרים, בלי ניסוחי האפשרויות. dumping נלמד במעבדת r1 בנפרד.
- **la1, שאלה 1:** הצורה נלמדת ב-From Failures to Breadth, על conf.salonazul עם 14 כשלונות ב-26 דקות מפורט קיר, לא d.solano עם 47.
- **la1, שאלה 2 (למה לא ננעל):** Why Didn't It Lock? מלמד threshold, חלון איפוס ו-fine-grained policy על חמישה חשבונות אחרים. הפריימר לא מונה את ההסברים, הלומד מסיק אותם מהשורות.
- **la1, שאלה 3:** First Moves on a Deep Burst, על פורט בקומת הכנסים ולא על IP חיצוני, ובלי ניסוח האפשרויות.
- **la2, שאלה 1:** מקור אחד ו-9 חשבונות מ-PC בחדר ההדרכה, לא 142 חשבונות מ-IP חיצוני. סף הנעילה של Mariposa הוא 6 ולא 4.
- **la2, שאלה 2 (התקרה מכוונת):** Is the Cap an Accident? על שלושה ממצאי עבר, מדיניות 10 ו-6, תקרה 9 ו-5.
- **la2, שאלה 3:** Prove a Success Followed מחפש הצלחה בפועל, על f.marques. האפס בעמודת הנעילות נלמד כנתון בטבלה, בלי k.mensah ובלי המקור של החדר.
- **f1 (LogonType):** קריאה מהרשומה. הפריימר של ה-spotdiff מסביר את שדה LogonType, והמעבדה לא שואלת מה היה הערך ב-la2.
- **q2 (רוחב ולא נפח):** בשלב הרביעי של ההאנט הסדר מתהפך, ו-Name the Shape מראה את זה שוב, על מספרים שאינם 60 ו-8.
- **ac1 (benign true positive):** שלושת הפסקים נלמדים ב-Name the Verdict על סריקה מאושרת, שגיאת parser ו-red team. Explain It or Escalate It מלמד מקור, חלון ואישור על טלפון, שרת מנעולים וצומת סריקה אחד עם חשבון אחד, והרעיון של סיבה משותפת נלמד על מנעולי דלתות מאותה אצוות סוללות. אין במעבדות חשבון אחד שנכשל מכמה שרתים פנימיים, אין חשבון שירות אחרי החלפת סיסמה, ואין ניסוח מההסבר הנבחן.
- **o1 (שרשרת ה-spray):** After the Hit הוא השתלטות stuffing שנגמרת ב-payroll, לא spray שנגמר בשרת קבצים. אין בו אף פריט מהסדר הנבחן.
- **qf1 (הבוס):** האות המכריע, רוחב לכל מקור, נלמד במעבדה משלו, From Failures to Breadth, על `IdentityLogonEvents`, `ActionType` ו-`AccountName`, ובשתי שורות summarize. הטבלה הנבחנת, השדות שלה ו-dcount על השדה הנבחן לא מופיעים בהאנט. `dcount` מוצג בפריימר על דוגמת כרטיסי מפתח, 4625 ו-TargetUserName מוצגים כנתון בפריימרים. Pick the Window and the Bar עובד עם חלון של 3 שעות וסף 6 על spray של 37 חשבונות. מארחי ביקורת מאושרים לא נספרים בטבלה, ומארח הביקורת צריך כניסת allowlist.

## סרטונים (כל אחד מסתיים בכרטיס NEXT MISSION עם הפעולה הראשונה, ולא חושף את תשובות התרגול שאחריו)
| סרטון | מתי | הפניה |
|---|---|---|
| Intro: "The Wall Is Red" | כניסה | תחנה 1 |
| Chapter 2: "No Lockouts" | אחרי The Wall | תחנה 2 |
| Chapter 3: "Three Days to the Summit" | אחרי The Shape | תחנה 3 |
| Finale: "The Rule Stays On" | אחרי The Detection | החדר הבא |
