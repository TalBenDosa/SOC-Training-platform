# תסריט חדר 68: Google Workspace Security

**שם המבצע:** Operation Shared Drive
**רמה:** בינוני
**העולם:** Larkspur Studios (אולפן אנימציה בדוי): 240 עובדים, דומיין Workspace אחד, ושישה שבועות עד שהסרט The Lantern Keeper מגיע לבתי הקולנוע.
**המנטור:** Mei-Ling Castro, Workspace Security Admin. (בטקסטים במעבדות אין לשון זכר או נקבה.)

## סיפור הרקע
כל פריים של הסרט חי על Shared Drives. הבוקר 12 פריימים מסליל 6 הופיעו בבלוג קולנוע, ולוג ההתחברויות אומר שאף אחד לא נכנס. על Mei-Ling לברר איך הפריימים יצאו, ולמה "contained" על הטיקט לא עצר אותם.

## המכניקה הייחודית של החדר
- **קונסולת Admin בשני חלקים:** מעבדת `portal` על skin `entra` בפריסת קונסולת Workspace, בלי לוגואים, עם דפי Audit and investigation, לוג Gmail, לוג Login, לוג OAuth, לוג Drive, לוג Admin ורשימת אפליקציות. סוג ההתראה הוא Activity Rule, ו-Spam classification מציג Clean ו-Phishing כמו בקונסולה האמיתית. שמות האירועים והפרמטרים אמיתיים: login_success, suspicious_login, change_user_access, change_document_visibility, RESET_SIGNIN_COOKIES, REVOKE_3LO_TOKEN, ADD_TO_BLOCKED_OAUTH2_APPS, originating_app_id, Has delegate. שדות `gws.*` השטוחים של החדר מוצגים רק בלשונית שמוגדרת כיצוא ל-SIEM.
- **Read the Mail Trail:** הודעה עם PASS מלא מתיבה חטופה של מלחינת הסרט, פעולת delegate תמימה, והתחברות שלא קרתה.
- **Contained, or Just Quiet?:** מעקב אחרי טוקן חי, קריאת הרשומה של מה שהפעולה באמת עשתה, ביטול וחסימה לפי client ID, והמעבדה מסתיימת בהוכחה. שתי אפליקציות נושאות אותו שם, וחסימה לפי שם פוגעת בצוות הסטוריבורד.
- **Same Name, Different App:** `spotdiff` של שני מענקי OAuth עם אותו שם, ו-**Two Sharing States:** `spotdiff` של שני מצבי שיתוף.

## העולם התלת-ממדי
אי קמפוס (`facility`) של האולפן: חמישה מבנים לפי התחנות, seed משלו, ואף מבנה לא עומד מאחורי אחר. עיר ה-Hub נושאת את שם החברה. theme: `shareddrive`, scene: `facilityshareddrive`.

## סדר המשימות
r1, r2, r3, q1 | r4, la1 | r5, la2, r6, q2 | r7, r8, ac1, m1 | o1, f1, q3, q4

## התחנות
| # | תחנה | משימות | המשחקים |
|---|---|---|---|
| 1 | The Admin Console | r1, r2, r3, q1 | **Carries Over, or Learn It Again?** (sort), **Name the Log, Name the Event** (codebreak), **Anatomy of a Workspace Event** (anatomy), **Read the Mail Trail** (portal) |
| 2 | The Consent Screen | r4, la1 | **Same Name, Different App** (spotdiff), **What Survives a Password Change?** (worksheet) |
| 3 | The Shared Drive | r5, la2, r6, q2 | **Two Sharing States** (spotdiff), **Whose Downloads?** (worksheet), **Contained, or Just Quiet?** (portal), **Order of Work** (sequence) |
| 4 | Two Suites | r7, r8, ac1, m1 | **Alert or Raw Log?** (sort), **Two Suites, One Desk** (worksheet), **Grant Review** (queue, לפני ac1) |
| 5 (בוס) | Final Cut | o1, f1, q3, q4 | **Foothold to Collection** (worksheet, לפני f1), **Did the Fix Take?** (worksheet, לפני q4) |

**הפרדה מהשאלות הנבחנות:**
- q1 (שלושה PASS בשרשור חשבוניות אמיתי עם ספק): נלמד ב-Read the Mail Trail, בשלבים cueauth ו-cuelink. שם תיבה חטופה של מלחינה, שרשור cue sheet וקישור, בלי ספק ובלי חשבונית. נלמד גם שציון ספאם נמוך לא מרגיע.
- la1 שאלה 1 (היקף ו-offline): נלמד ב-Same Name, Different App (שורת ה-scope) וב-What Survives a Password Change?. שם drive.readonly ו-contacts.readonly ב-Reel Review, לא drive ו-calendar ב-FormFlow Sync.
- la1 שאלה 2 (allowlist ואימות): השורות של TRUSTED מול NOT_CONFIGURED ושל marketplace_verified באותו spotdiff, על אפליקציה אחרת.
- la1 שאלה 3 (מה בודקים אחר כך): ה-lesson של אותו spotdiff, והשלב act ב-Contained, or Just Quiet?.
- la2 שאלות 1 ו-2 (ייחוס להורדות): Whose Downloads?. 90 אירועים ב-6 דקות מ-203.0.113.91, לא 340 ב-11 דקות מאמסטרדם.
- la2 שאלה 3 (תיקון משולב): שאלות first ו-again ב-Whose Downloads?, על מקרה Clip Trimmer, לפני la2: קודם סוגרים את המענק, וחוסמים לפי client ID.
- q2 (CHANGE_PASSWORD עם oauth_tokens_revoked false): נלמד על RESET_SIGNIN_COOKIES בפורטל, לא על CHANGE_PASSWORD. העובדה שאיפוס סיסמה לא מבטל מענק נלמדת ב-What Survives a Password Change? על Contacts ו-Sheets.
- ac1 (מענק רגיל): Grant Review מלמד לקרוא את כל השדות יחד ולהבדיל בין benign true positive ל-false positive, עם שורה אחת שבה הכלל באמת שגה (אירוע revoke). המענק השקט שם הוא calendar.freebusy של Shift Planner, ולא drive.file של אפליקציית כתיבה. drive.file מופיע רק כנתון בהסבר של שורת ה-scope.
- m1 (התאמה): הטבלה ב-Two Suites, One Desk מציגה את המיפוי כנתון בשורות, והשאלות שם שואלות דברים אחרים. אין שם מטלת התאמה.
- o1 (סדר התגובה): Order of Work מלמד את ההיגיון של עצירה, הוכחה, מדידה ותיקון על אירוע אחר, הגדרת העברת דואר החוצה מתיבה ב-Accounts, ולא על מענק OAuth. הפורטל מסתיים בהוכחה ולא מדגים את כל הסדר.
- f1 (16 דקות): Foothold to Collection מתרגל דקות שלמות על זמנים אחרים, והתשובות 12, 24 ו-289.
- q3 (private ל-anyone with the link ואז IP זר): Two Sharing States עובר מ-people_within_domain_with_link ל-people_with_link, עם ספק דיבוב מוכר. Two Suites, One Desk מראה את המקביל ב-SharePoint.
- q4 (הסיווג הסופי): האות המכריע, רשומת הפעולה מול פעילות הטוקן, נלמד במעבדה משלו, Did the Fix Take?, על ארבעה טיקטים אחרים, בלי המקרה הנבחן.

## סרטונים (כל אחד מסתיים בכרטיס NEXT MISSION עם הפעולה הראשונה, ולא חושף את תשובות התרגול שאחריו)
| סרטון | מתי | הפניה |
|---|---|---|
| Intro: "Twelve Frames" | כניסה | תחנה 1 |
| Chapter 2: "Nobody Signed In" | אחרי The Admin Console | תחנה 2 |
| Chapter 3: "Contained" | אחרי The Consent Screen | תחנה 3 |
| Finale: "Final Cut" | אחרי הבוס | החדר הבא |
