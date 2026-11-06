# תסריט חדר 78: Kerberos & Windows Authentication Deep Dive

**שם המבצע:** Operation Three Heads
**רמה:** מתקדם
**העולם:** Vale Regional Health (רשת בתי חולים בדויה): שלושה בתי חולים, 6,400 עובדים, דומיין Active Directory אחד, וכל מערכת במחלקות נשענת על כרטיס Kerberos.
**המנטור:** Astrid Okonjo, Identity Threat Analyst. (בטקסטים במעבדות אין לשון זכר או נקבה.)

## סיפור הרקע
השבוע צצה למכירה הסיסמה של פקידת מחלקה, ו-Astrid משכה את הלוגים של בקרי הדומיין. השם Kerberos בא מהכלב התלת-ראשי שבשער, וכאן הראשים הם הלקוח, ה-KDC והשירות, ולכל אחד מפתח משלו. מישהו עובד על שלושתם: שאילת כרטיסים לפיצוח, בקשה בלי הוכחת סיסמה, וכרטיס אמיתי שמשוחזר ממכונה אחרת. ובסוף, כשהכול נראה חשוד, מגיע כרטיס אחרון שבו צריך להחליט אם זה ראש רביעי.

## המכניקה הייחודית של החדר
- **Read the Ticket:** חדר 34 נותן שמות להתקפות על AD, והחדר הזה מחליט ביניהן לפי שדות. ב-`defuse` הלומד חותך את החוט הנכון בין Kerberoasting, AS-REP roasting ו-pass-the-ticket לפי השדות של אירוע אחד, ובכל סיבוב שדה ההצפנה לא מכריע.
- **The Ticket Ladder:** `hunt` ב-SPL על 4768 ו-4769, שורה אחרי שורה, עד שורה אחת: המבקש והכתובת. הלומד מגלה ש-count הוא לא מספר שירותים שונים, ש-23 עשרוני הוא 0x17, ושלא כל חשבון שירות מתחיל ב-svc_.
- **Escalate or Backlog?:** `intercept` שמלמד את האות המכריע של הבוס: ארבע שאלות על כרטיס RC4, פיזור, קצב, מקור ותיעוד.

## העולם התלת-ממדי
אי קמפוס (`facility`) של הרשת: חמישה מבנים לפי התחנות, בלי מבנה מאחורי מבנה ובלי מבנה מול ה-Hub המרכזי. ה-Hub נושא את שם הרשת.

## סדר המשימות
r1, r2, q1, o1 | r3, r4, q2 | r5, la1, f1, qf1 | r6, la2, q3, m1 | ac1

**הסדר שונה מהחדר המקורי.** במקור ac1, m1, o1, qf1 ו-f1 יושבות בסוף: סידור ההחלפה מגיע אחרי ההתקפות, ו-f1 ו-qf1 רחוקות מהלוג שהן מתייחסות אליו.

## התחנות
| # | תחנה | משימות | המשחקים |
|---|---|---|---|
| 1 | The Ticket Office | r1, r2, q1, o1 | **Five Messages, One Sign-In** (inspect), **Whose Key Locks It?** (sort), **Follow One Session Through the Logs** (trace) |
| 2 | The Cipher Field | r3, r4, q2 | **Anatomy of a 4769** (anatomy), **Who Can Be Downgraded?** (worksheet), **What Does the KDC Check?** (simulate) |
| 3 | Read the Ticket | r5, la1, f1, qf1 | **Read the Ticket** (defuse), **The Ticket Ladder** (hunt), **Which Password Goes First?** (sort) |
| 4 | No Paper Trail | r6, la2, q3, m1 | **The Missing Receipt** (trace), **Whose Secret Burns?** (match) |
| 5 (בוס) | The Last Ticket | ac1 | **Three Ways to Close an Alert** (sort), **Escalate or Backlog?** (intercept), ואז ההחלטה הנבחנת |

**הפרדה מהשאלות הנבחנות:**
- **q1** (אין 4768 או 4769 באף DC): Follow One Session מלמד שאירועי כרטיס נכתבים רק ב-DC שענה ושיש לחפש בכולם, ש-4624 ביעד אומר מה ה-package, שסשן NTLM משאיר 4776 בלי כרטיס. Five Messages מלמד שהשירות לא שואל את ה-KDC, ולכן אפשר לבנות כרטיס offline. שונה: סשן שמגיעים אליו לפי כתובת IP, עם 4776, ולא חיפוש ריק בכל ה-DC.
- **o1** (סדר ההחלפה): Five Messages מציג את ההודעות כנתון על כניסה של אחות, ולא שואל סדר. המעבדה לא מבקשת לסדר דבר.
- **q2** (אין בדיקת הרשאות ב-KDC): What Does the KDC Check? מראה פורטל שכר שמסרב ב-Service בזמן ש-4769 הצליח. שונה: שירות web וסבל, לא SQL ו-k.alvarez.
- **la1 שאלה 1** (פרץ של RC4 על שירותים רבים): Read the Ticket ו-The Ticket Ladder. שונה: בסיבוב ההגנה הפרץ ב-AES, וב-hunt הפרץ הוא חמישה שירותים, לא 59. What Does the KDC Check? מלמד שהכרטיס שהונפק הוא החומר הגנוב.
- **la1 שאלה 2** (של מי הסיסמה בסכנה): Anatomy of a 4769, שדה ServiceName. Whose Key Locks It? מלמד שהשירות מחזיק את המפתח. שונה: כרטיס תקין של אחות ב-0x12.
- **la1 שאלה 3** (התגובה): Which Password Goes First? מלמד שהסיכון הוא בחשבונות השירות ולא במבקש, ושמפתחות AES נוצרים רק בהחלפת סיסמה. What Does the KDC Check? מלמד שהפיצוח offline ולא משאיר עקבות, ו-Anatomy of a 4769 מלמד ש-IpAddress הוא המארח לבדיקה. שונה: שאלה אחרת, סדר החלפת הסיסמאות, ולא בחירת תגובה מתוך אפשרויות.
- **f1** (הכתובת של הלקוח): Anatomy of a 4769, שדה IpAddress, וסיכום ה-hunt. שונה: כתובות 10.30.x, לא טווח 10.55.
- **qf1** (KQL ל-Kerberoasting): The Ticket Ladder מלמד את הלוגיקה, ספירת שירותים שונים ועיבוי לפי מבקש, ב-SPL בלבד, עם הערה על dcount. השאילתה הנבחנת היא KQL ועם bin של זמן.
- **la2 שאלה 1** (PreAuthType 0 מול overpass): Read the Ticket, סיבוב ראשון, ו-The Missing Receipt, שלב ראשון, שמעמיד PreAuthType 2 עם 0x17 מול PreAuthType 0. שונה: בסיבוב ה-AS-REP ההצפנה AES, לא 0x17 כמו ב-la2 וב-q3.
- **la2 שאלה 2** (חשבון נשכח, אין צורך בפרטי גישה): הפריימר של Read the Ticket ו-Whose Secret Burns? (AD לא משבית חשבון כשהאפליקציה פרשה). שונה: svc_faxgw, שער פקס, לא כלי דוחות שפורק.
- **la2 שאלה 3** (התגובה): Whose Secret Burns?, זוג svc_faxgw. שונה: הנוסח אחר והמקרה אחר.
- **q3** (מיון שני אירועים): Read the Ticket. שונה: חשבונות, מספרים והצפנה אחרים.
- **m1** (התאמת אותות להתקפות): הפריימר של The Missing Receipt מציג את העובדות, והמעבדה מבקשת למצוא שורה בלוג, ולא להתאים אות לשם. Whose Secret Burns? מתאים התקפה לתגובה, לא אות להתקפה.
- **ac1** (הבוס): האות המכריע נלמד במעבדה משלו, Escalate or Backlog?, והמושג benign true positive נלמד ב-Three Ways to Close an Alert. שונה: לינק דימות, מעלית, מקרר חיסונים ומדפסות, עם רשומות CHG אחרות, ולא גיבוי ל-NAS.

## סרטונים (כל אחד מסתיים בכרטיס NEXT MISSION עם הפעולה הראשונה, ולא חושף את תשובות התרגול שאחריו)
| סרטון | מתי | הפניה |
|---|---|---|
| Intro: "For Sale" | כניסה | תחנה 1 |
| Chapter 2: "The Night Shift" | אחרי The Cipher Field | תחנה 3 |
| Chapter 3: "No Receipt" | אחרי No Paper Trail | תחנה 5 |
| Finale: "The Last Ticket" | אחרי The Last Ticket | החדר הבא |
