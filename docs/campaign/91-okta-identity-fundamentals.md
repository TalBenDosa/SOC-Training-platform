# תסריט חדר 91: Okta Identity & Authentication Fundamentals

**שם המבצע:** Operation Single Sign-Off
**רמה:** בינוני
**העולם:** Quayside Capital (מנהלת השקעות בדויה על קו המים): הזדהות אחת לפני כל האפליקציות, כולל Settlement Portal שמשחרר כספי לקוחות.
**המנטור:** Ngaire Holm, IAM Security Analyst. (בטקסטים במעבדות אין לשון זכר או נקבה.)

## סיפור הרקע
סוף חודש. תשלום גדול ב-Quayside דורש שני אנשים שחותמים עליו, ושניהם נכנסים דרך אותו ספק זהויות. ביום חמישי בבוקר, שעות לפני החתימה של הצהריים, ה-SIEM מרים דגל על התחברות מהלילה, ועל השולחן של Ngaire Holm נשארת שאלה אחת: מה עוד קרה בארגון מאז.

## המכניקה הייחודית של החדר
- **Work the System Log:** פורטל על skin בשם `entra`, בנוי כקונסולת ניהול של ספק זהויות, עם People, Groups, Sign-on policies, Network zones, API tokens ו-System Log. ה-eventType אמיתיים ונבדקו מול קטלוג האירועים של Okta. הכרום גנרי, בלי שם מוצר. הלומד יוצא מהתחברות אחת, עובר ללשוניות של האירוע, עושה pivot על הכתובת, מוצא טוקן וחשבון ספק ישן, וסוגר. ביטול טוקן לגיטימי עולה בחיים.
- **Approved Policy, Live Policy:** מעבדת `spotdiff` של שתי מדיניות sign-on: העותק המאושר מול החי. שלושה שינויים מחלישים ושני שינויים תמימים.
- **What Did They Actually Get?:** מעבדת `defuse` על ארבעה תיקים קטנים של סוף חודש. בכל אחד מזהים מה באמת אבד ומבטלים בדיוק אותו.

## העולם התלת-ממדי
אולם קלפים (`facility`, hall) עם ליבת `globe`: חמישה קלפים לפי התחנות.

## סדר המשימות
r1, r2, r3, q1 | r4, r5, q2 | r6, la1 | r7, r8, q3 | la2, m1, o1, f1, q4, q5

הסדר המקורי של החדר נשמר. אף flag לא נשען על מספור Log Analysis.

## התחנות
| # | תחנה | משימות | המשחקים |
|---|---|---|---|
| 1 | The System Log | r1, r2, r3, q1 | **Will This Filter Find Anything?** (sort), **Read One System Log Event** (anatomy), **Which Category Would Catch It?** (sort), **How Far Did It Get?** (trace), **What Does the Source Now Hold?** (sort) |
| 2 | Behind the Attempt | r4, r5, q2 | **Whose Network Is This?** (queue), **Read the Authenticator Register** (inspect) |
| 3 | Two Policies | r6, la1 | **Approved Policy, Live Policy** (spotdiff), **Same Job, Different Name** (match), **What Did They Actually Get?** (defuse) |
| 4 | The Admin Trail | r7, r8, q3 | **Count What Had Already Happened** (worksheet), **Routine, or Review Now?** (sort), **Work the System Log** (portal) |
| 5 (בוס) | Single Sign-Off | la2, m1, o1, f1, q4, q5 | ההחלטות הנבחנות |

**הפרדה מהשאלות הנבחנות:**
- **שאלת הביניים של r1 (שדות Entra מחזירים אפס):** נלמד בפריימר של Will This Filter Find Anything? ובמעבדה עצמה. הדוגמה היא `EventID:4625` על `auth.log` של לינוקס, והשדות במעבדה הם UserPrincipalName, AppDisplayName, RiskLevelDuringSignIn ו-AuthenticationRequirement. ResultType ו-ConditionalAccessStatus לא מופיעים. הפריימר לא מדבר על עיכובי יצוא או על אותיות קטנות.
- **שאלת הביניים של r3 (ראיית המשך):** נלמד ב-How Far Did It Get?, שלב 2, על SMS שנשלח באותו `transaction.id` ולא על push. השדה authenticationStep לא מוזכר באף מעבדה, כדי לא לפסול מסיח.
- **q1 (מה שגוי בסגירה):** הרעיון נלמד בפריימר של How Far Did It Get? דרך ביקורת דרכונים, ובמעבדה על spray: הרבה חשבונות, ניסיון אחד לכל חשבון, ולא 80 כשלים על חשבון אחד. אין במעבדות הערת סגירה של אנליסט אחר, ולא נפסלות האפשרויות על autofill או על הרשמת factor.
- **q2 (FIDO2 מול push):** עובדה לזכירה, ולכן מופיעה רק כנתון בשורה של Read the Authenticator Register. אין שאלה עליה, ואין התייחסות לחלון תוקף, לאחסון סיסמה או לרשת הסלולר של push.
- **שאלת הביניים של r6 (איפה נרשם שינוי מדיניות):** מופיע כנתון בכותרת של העותק החי ובשורה בפורטל. אף מעבדה לא שואלת את זה.
- **la1, שאלה 1 (איזה שדה סותר):** האות המכריע נלמד במעבדה משלו, What Does the Source Now Hold?, ובטרייס, על אנשים אחרים ועל כתובת 203.0.113.58. אין שדה threatSuspected ואין credentialType במעבדות.
- **la1, שאלה 2 (מה asOrg מוסיף):** נלמד ב-Whose Network Is This? על Northpier Hosting ו-Greywake Datacentres, עם דוגמאות נגד של ספק סלולר, פס רחב ביתי ו-egress של המשרד. בשורות מופיע `isProxy` כנתון בלבד, והפריימר לא פוסל אף מסיח. Alexhost ובוקרשט לא מופיעים.
- **la1, שאלה 3 (בלימה אחרי סיסמה שאבדה):** העיקרון נלמד ב-What Did They Actually Get? על טוקן, session וחברות בקבוצה. אף סיבוב אינו סיסמה שנחשפה, והחוטים השגויים אינם חסימת IP, איפוס MFA או המתנה.
- **q3 (rate limit):** נלמד ב-Count What Had Already Happened על חשבונות נעולים, לא על סיסמה מאומתת. דוגמת הפריימר היא מחסום של חניון. השורות הן ל-`system.org.rate_limit.warning` ו-`.violation`, ואין התייחסות לאיפוס כפוי או לטביעת אצבע של כלי.
- **שאלת הביניים של r8 (איפוס factors על ידי helpdesk):** נלמד בפריימר ובשורה ב-Routine, or Review Now?: חשבון של Facilities מוסיף עמית ל-Treasury-Readers, בלי כרטיס, מ-session על ASN של אירוח. זו הוספה לקבוצה ולא איפוס factors, ואין פער זמן או רישום של factor חדש.
- **la2, שאלה 1 (actor מול target):** האות המכריע של הבוס נלמד במעבדה משלו, Routine, or Review Now?, על `user.account.privilege.grant` ועל שורות נגד שבהן אותה זהות בשני הצדדים היא שגרה. אין שם הוספה עצמית לקבוצת אדמינים.
- **la2, שאלה 2 (אותה כתובת):** נלמד בשלב ה-pivot בפורטל, על כתובת אחרת ועל שני חשבונות. אין שם push שאושר.
- **la2, שאלה 3 (היקף בלימה משולב):** נלמד בסיבוב האחרון של What Did They Actually Get? ובסוף הפורטל, על session, טוקן ומושב באפליקציה. בסיבוב אין סיסמה, קבוצת אדמינים או תפקיד ישן.
- **m1 (קטגוריות eventType):** השיטה נלמדת ב-Which Category Would Catch It? על ארבע קטגוריות אחרות: `application.user_membership.*`, `user.lifecycle.*`, `system.api_token.*`, `policy.lifecycle.*`. חמש הקטגוריות של m1 מופיעות רק כנתון בשורות של מעבדות אחרות.
- **o1 (סדר הטריאז'):** אף מעבדה לא מבקשת לסדר צעדים. סדר העבודה נלמד בביצוע בפורטל, על תיק אחר. השיעור בסוף הפורטל לא מונה את הצעדים.
- **f1 (מזהה הקבוצה):** השיטה נלמדת ב-Read One System Log Event: `target.1.id` על Treasury-Readers, עם מזהה אחר. הערך הנבחן נקרא מהאירוע של la2 בלבד.
- **q4 (שתי פלטפורמות):** נלמד ב-Same Job, Different Name וב-Will This Filter Find Anything?, בלי לגעת בנרמול של SIEM או בטריאז' לפי IP.
- **q5 (האות המכריע של הבוס):** נלמד במעבדה משלו, What Does the Source Now Hold?, על ראיות מתיקים אחרים. אין שם push שנדחה ואין שם rate limit.

## סרטונים (כל אחד מסתיים בכרטיס NEXT MISSION עם הפעולה הראשונה, ולא חושף את תשובות התרגול שאחריו)
| סרטון | מתי | הפניה |
|---|---|---|
| Intro: "Two Signatures" | כניסה | תחנה 1 |
| Chapter 2: "The Night Shift Log" | אחרי The System Log | תחנה 2 |
| Chapter 3: "Before Noon" | אחרי The Admin Trail | תחנה 5 |
| Finale: "Signed Off" | אחרי Single Sign-Off | החדר הבא |
