# תסריט חדר 87: Remote Email Collection & Malicious Inbox Rules

**שם המבצע:** Operation Quiet Forward
**רמה:** בינוני
**העולם:** Sable Point Shipping (חברת ספנות בדויה): 240 עובדים, תשע אוניות צובר, ושולחן התחשבנות שמעביר כספי נמל בכל יום שישי.
**המנטור:** Hamid Nyberg, Mail Forensics Analyst. (בטקסטים במעבדות אין לשון זכר או נקבה.)

## סיפור הרקע
סוכן נמל בסנטוס שואל למה פרטי הבנק בחשבון ההוצאות של MV Kestrel Reach השתנו. אף אחד ב-Sable Point לא שינה אותם. המייל יצא מהתיבה האמיתית של i.marchetti, ראש שולחן ההתחשבנות, ולכן Hamid מתייחס לסשן כגנוב. עכשיו המבטח רוצה מספר, הסוכנים רוצים תשובה, והשאלה של החדר היא מה יצא מהתיבה, איך הוא יצא, וכמה נקרא.

## המכניקה הייחודית של החדר
- **What Left, and How?:** מעבדת `hunt` של שישה שלבים עם טבלאות משלה. שורות גישה לדואר מתחברות להתחברויות על חשבון וסשן ביחד, ואז Bind ו-Sync נספרים בנפרד. עשר שורות הופכות ל-1,295 פריטים חשופים, כי שורת Sync אחת היא תיקייה שלמה.
- **One Session, Four Stories:** מעבדת `trace` על אותו סשן. קריאה, שליחה, כלל הפניה והרשאה לחשבון אחר הם ארבעה סיפורים שונים, וכל אחד דורש טיפול משלו.
- **What Does Each Move Leave Running?:** ה-`simulate` של התגובה. כל מהלך נוסה לבדו, ואין שם סדר מוכן: הלומד רואה מה נשאר חי ובונה את הסדר בעצמו במשימה הנבחנת.
- **הגבול מול חדרים אחרים:** חדרים 56 ו-77 עוסקים בזרימת דואר ובפורנזיקה של דואר. כאן העיסוק הוא באיסוף, אחרי שתיבה כבר נלקחה.

## העולם התלת-ממדי
אולם קלפים (`facility`, Hall) של Sable Point עם ליבת `knot` וחמישה קלפים לפי התחנות.

## סדר המשימות
r1, r2, q1 | r3, q2, m1 | r4, la1, o1 | r5, ac1, q3 | qf1, f1, q4

(הסדר המקורי נשמר. הדגל f1 לא מזכיר מספר של Log Analysis.)

## התחנות
| # | תחנה | משימות | המשחקים |
|---|---|---|---|
| 1 | The Mailbox Audit | r1, r2, q1 | **Where Does the Evidence Live?** (sort), **What Is a Mailbox Worth?** (match), **Read a Mail Access Record** (anatomy), **Four Words the Log Uses** (codebreak) |
| 2 | The Quiet Rule | r3, q2, m1 | **Follow One Message Through the Rule** (simulate), **Did It Actually Leave?** (sort) |
| 3 | One Session | r4, la1, o1 | **What Left, and How?** (hunt), **One Session, Four Stories** (trace), **Tune the Burst Rule** (tune), **What Does Each Move Leave Running?** (simulate) |
| 4 | The Cover Story | r5, ac1, q3 | **Prove the Relationship** (queue) |
| 5 (בוס) | What Left | qf1, f1, q4 | **The Way Out With No Rule** (hunt) |

**הפרדה מהשאלות הנבחנות:**
- **שאלת הביניים של r2 (על איזה שדה עושים pivot):** נלמד ב-Read a Mail Access Record, בשורה עם תווית של SessionId, והופעל ב-What Left, and How?. הרשומה היא של עבודת ארכיון תחת כרטיס, לא רשומה חשודה. שאר שדות האפשרויות לא נפסלים בשום מקום.
- **q1 (תת-הטכניקה):** נלמד ב-Where Does the Evidence Live?, על קובצי pst, IMAP, דפדפן וטלפון. הקטגוריות מוצגות כתוויות. אין שם טוקן, API או חיפוש הוראות העברה. הפריימר משתמש במסמכי מכרז.
- **q2 (מה מסוכן בשילוב):** נלמד ב-Follow One Message Through the Rule. כל פרמטר רץ לבדו, ועל כתובת אחרת, והשילוב forward, delete ו-stop לא מופיע. התקציר של DeleteMessage אומר רק שצריך לקרוא פעולות ביחד. הלומד מרכיב את השילוב בעצמו.
- **m1 (התאמת מונחים):** עובדות זיכרון שמופיעות רק כנתון. New-InboxRule בפריימר של הכללים ובפקודות, ForwardTo, RedirectTo ו-DeleteMessage בתרחישים, Set-Mailbox -ForwardingSmtpAddress בתרחיש Mailbox forwarding, MailItemsAccessed ו-SessionId באנטומיה. אף מעבדה לא שואלת אותן כהתאמה, והניסוחים של m1 לא מופיעים.
- **שאלת הביניים של r4 (הצעד הבא):** השיטה נלמדת ב-What Left, and How? על סשן עם התראת התחברות, והבסיס להשוואה נלמד ב-Prove the Relationship.
- **la1, שאלה 1 (מחרוזת REST):** נלמד באנטומיה על עבודת ארכיון חוקית, עם כרטיס שינוי ושרת מוכר. הלקח הפוך מ-la1: המחרוזת לבדה לא מכריעה.
- **la1, שאלה 2 (צורת ה-Bind):** נלמד ב-Tune the Burst Rule, בסשנים עם 38, 17, 90 ו-14 הודעות, לא 24 בארבע דקות. בהאנט יש 9 Bind בלבד.
- **la1, שאלה 3 (מה עושים ראשון):** נלמד ב-One Session, Four Stories, שבו אותו סשן מוביל לכלל, ובמעבדת התגובה. המקור של i.marchetti הוא 203.0.113.140 בהתחברות ו-203.0.113.77 בקריאה, ואין במעבדות את הערכים של r.iversen.
- **o1 (סדר התגובה):** נלמד ב-What Does Each Move Leave Running? בניסוי של מהלך אחד בכל פעם. אף מקום במעבדה לא מציג סדר, והניסוחים של o1 לא מופיעים. הפריימר משתמש בצינור שדולף.
- **ac1 (delegate מאושר):** האות המכריע נלמד ב-Prove the Relationship: claims counsel על shared mailbox, ומול זה t.brandt עם הרשאה שנוצרה בסשן גנוב. אין עוזר של מנהל כספים, ואין Sync של delegate. המושג benign true positive מוגדר בפריימר על הוספה לקבוצה פריבילגית.
- **q3 (רשומה אחת רגילה):** נלמד באותו תור, בהתראה a5: קריאה אחת מהבית בערב, לא מכתובת ארגונית בשעות העבודה. הקריאה נסגרת עם נימוק, בלי שינוי בחוק.
- **qf1 (הבוס):** האות המכריע, לכל דרך יציאה שורה משלה, נלמד במעבדה משלו, The Way Out With No Rule, על Set-Mailbox ו-ForwardingSmtpAddress. אף חלק מהתשובה לא מופיע בשאילתה שלה. `or` בין שני פרמטרים נלמד בפריימר על Add-MailboxPermission. שורת ה-project שונה מהתבנית הנבחנת.
- **f1 (הכתובת):** השדה ClientIPAddress נלמד באנטומיה. הערך נקרא מהרשומה הנבחנת, ולא מופיע באף מעבדה.
- **q4 (מה איפוס משאיר):** נלמד בתרחיש Reset the password, על לקוח REST שעדיין מושך דואר ב-09:40. הניסוחים של q4 לא מופיעים, והמסיחים שלה לא נפסלים.

## דברים שנמצאו בחומר הנבחן (לא שונו)
- ב-r2 וב-r5 כתוב שגם טלפון מייצר Sync. לפי התיעוד של Microsoft, Sync נרשם רק ל-Outlook שולחני ל-Windows או ל-Mac. המעבדה כותבת את זה נכון.
- ב-la1 כתוב שהרשומה חוזרת 24 פעמים. בפועל Exchange מאגד Bind של חלון של שתי דקות לרשומה אחת עם OperationCount. המעבדה מלמדת את הצורה הזאת.
- ב-m1, ב-qf1 וב-r3 כתוב ש-RedirectTo לא משאיר עותק בתיבה. זה לא נכון: מה שמבדיל הפניה מהעברה הוא שהיא שומרת על השולח המקורי, והתשובות חוזרות אליו. המעבדה מלמדת את זה ולא טוענת דבר על עותק. בסימולציה הבדיקה הראשונה שונתה ל-No clean-up, ולכן אין בה תוצאה על מצב התיבה בתרחיש הזה.
- ב-m1 כתוב ש-New-InboxRule נרשם על כל כלל. שינוי כלל מלקוח נרשם גם כ-UpdateInboxRules, ולכן השאילתה של qf1 לא מכסה הכול. הלקח של ההאנט השני מזכיר את זה.
- הרשומות הנבחנות משתמשות בדומיין com וב-IP ציבורי שאינם מטווחי הדוגמה.

## סרטונים (כל אחד מסתיים בכרטיס NEXT MISSION עם הפעולה הראשונה, ולא חושף את תשובות התרגול שאחריו)
| סרטון | מתי | הפניה |
|---|---|---|
| Intro: "A Call From Santos" | כניסה | תחנה 1 |
| Chapter 2: "The Mail Keeps Going" | אחרי The Mailbox Audit | תחנה 2 |
| Chapter 3: "Who Else Has a Key?" | אחרי One Session | תחנה 4 |
| Finale: "Quiet Again" | אחרי What Left | החדר הבא |
