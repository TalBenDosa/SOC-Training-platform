# תסריט חדר 97: Unusual Attacks and Edge-Case Use Cases

**שם המבצע:** Operation Fine Print
**רמה:** מתקדם (כל ה-primers מקופלים, `fold: true`)
**העולם:** Wexcombe Estates (קבוצת נדל"ן בדויה): 6,100 דירות בניהול, ומכירת תיק נכסים שנסגרת בעוד שלושה שבועות.
**המנטור:** Ifeoma Larsen, Senior Incident Analyst. (בטקסטים במעבדות אין לשון זכר או נקבה.)

## סיפור הרקע
עורכי הדין של הקונה דורשים שורה אחת חתומה: לא היה אירוע אבטחה בשנים עשר החודשים האחרונים. החתימה של Ifeoma עדיין לא ניתנה, כי יש ערימה של כרטיסים סגורים, כל אחד נסגר כשגרה, ואף אחד מהם לא נראה כמו תקיפה. הלומד פותח אותם מחדש, אחד אחד, ומחזיק בכל כרטיס שני הסברים עד ששדה אחד מכריע.

## המכניקה הייחודית של החדר
**It Doesn't Look Like an Attack:** כל תחנה לוקחת מקרה חריג אחד ומחזיקה שני סיפורים במקביל (Story one, Story two). תמהיל המשחקים: `deduce` + `rush` + `tune`.
- **`deduce`** למקרים שנראים תמימים: חבילה בבילד, הרשאת אפליקציה, התחברות מרוחקת. כל אות מופיע גם אצל חשוד תמים, כך שרק צירוף האותות מכריע.
- **`tune`** לקו בסיס שחייב לתפוס התנהגות שקטה מאוד: קורא סבלני במערכת ההשכרה.
- **`rush`** בתחנת הבוס: האם הפרט הזה מפריד בין הסיפורים, או מתאים לשניהם?

## העולם התלת-ממדי
אולם קלפים (`facility`, hall) של Wexcombe, core מסוג `knot`: חמישה קלפים לפי התחנות.

## סדר המשימות
r1, q1, la1 | r2, la3, r3 | r4, q2, la2, ac2 | r5, ac3, f1, ac1, q3, ac4 | r6, m1

זה סדר חדש. במקור כל הקריאות הגיעו ברצף ואחריהן כל המשימות הנבחנות, ולכן אי אפשר היה לשייך קריאה למשימות שלה בתחנה רציפה. ההפניה "Reading 1" בהסבר של la1 עדיין נכונה, la2 נשארת לפני ac2 ("Two weeks later"), ו-f1 לא נוקבת במספר משימה ועכשיו יושבת מיד אחרי האירוע שהיא שואלת עליו.

## התחנות
| # | תחנה | משימות | המשחקים |
|---|---|---|---|
| 1 | The Odd One | r1, q1, la1 | **How a Build Chooses a Package** (anatomy), **Same in Both Stories?** (sort), **Six Installs, One Odd One** (deduce, לפני la1) |
| 2 | Clean Logs | r2, la3, r3 | **Tune a Baseline for a Patient Reader** (tune), **From Pattern to Case** (sequence), **Follow the Card Data** (trace), **Same Tool, Same Account** (sort) |
| 3 | The Real Screen | r4, q2, la2, ac2 | **What Accept Actually Does** (sequence), **Anatomy of a Consent Record** (anatomy), **Six Grants, One to Revoke** (deduce, לפני la2) |
| 4 | Same Shape | r5, ac3, f1, ac1, q3, ac4 | **Built For, Bent To** (match), **Three Verdicts, Four Alerts** (queue), **Early, Late or On Time** (worksheet), **Which Trip Was a Takeover?** (deduce, לפני ac1), **What a Lookup Gives Away** (worksheet, לפני q3) |
| 5 (בוס) | The Fine Print | r6, m1 | **Where the Proof Lives** (reactor), **Would This Field Differ?** (rush) |

**הפרדה מהשאלות הנבחנות:**
- שאלת הביניים של r1 (למה חבילה ציבורית מנצחת): המידע מופיע כנתון בשורת לוג של pip בלבד, ב-How a Build Chooses a Package, ולא נשאל. שונה מהנבחן: Python על שרת בילד, לא npm על לפטופ.
- q1 (למה זה עובר את ה-EDR): Same in Both Stories? הצמד הנפוץ של הורה וילד, והכוונה שנמצאת בפקודה וביעד. השאלה הנבחנת שואלת למה, המעבדה ממיינת תצפיות.
- la1 ש1 (הפער בין שלב ההתקנה בקוד המקור למה שרץ): העמודות Step in its setup.py source ו-What ran ב-Six Installs. קוד inline משלנו ב-python, לא node ולא PowerShell מוסתר.
- la1 ש2 (שם פנימי, מקור ציבורי, גרסה גבוהה): זוג הגרסאות 2.3.1 ו-31.0.0, לא 0.9.2 ו-1.0.4.
- la1 ש3 (כתובת חשופה ב-HTTP): ה-why של Six Installs, על 203.0.113.77. בלי ה-IP וה-URL הנבחנים.
- la3 ש1 (DLP רואה שעה אחת): Tune a Baseline for a Patient Reader. מערכת השכרה ורשומות, לא SharePoint, ובלי 14, 17, 238 או 50.
- la3 ש2 (מה עושים עם הדפוס): From Pattern to Case, על ה-Accounts assistant ממשחק ה-tune. סדר עבודה בלי רשימת אפשרויות שגויות.
- שאלת הביניים של r3 (Magecart): Follow the Card Data. CSP ו-SRI מוצגים כנתונים בשורות, על ווידג'ט הזמנת תיקונים. לא נשאלת שאלה על מה מזהה skimmer.
- q2 (למה MFA לא קופץ): What Accept Actually Does. סדר השלבים מראה שההתחברות קורית פעם אחת. לא חוזרת על אף אפשרות נבחנת.
- la2 ש1 (התאמת scopes למטרה): ה-primer עובד על אפליקציית הזמנת חדרים, והרשומה ב-Anatomy of a Consent Record היא אפליקציה תקינה עם scopes מתאימים. Quick Doc Viewer לא מופיעה.
- la2 ש2 ו-ac2 (אף אות לבדו אינו מכריע): Six Grants, One to Revoke. האפליקציה הרעה היא Lease Clause Finder שקוראת SharePoint ו-OneNote, לא דואר, אנשי קשר או Files.Read.All, ובלי Latvia או Romania.
- ac3 (benign true positive): Three Verdicts, Four Alerts. משתמש ב-certutil, bitsadmin, rundll32 ו-mshta, אף פעם לא ב-regsvr32. שיעור ההגדרה של שלושת הפסקי הדין בדוגמת חיישן דלת.
- שאלת הביניים של r5 (Squiblydoo): שורה אחת עם תווית ב-Built For, Bent To, נתון בלבד.
- f1 (297 שניות): Early, Late or On Time, עם כרטיסים וזמנים אחרים (492 ו-250 שניות), ובלי CHG0041823.
- ac1 (VPN, ASN, isProxy): Which Trip Was a Takeover? שואלת את השאלה ההפוכה: מי מבין שש ההתראות היא ההשתלטות האמיתית. ערכי ASN וערים אחרים, בלי Chicago, Dublin או AS64500.
- q3 ו-ac4 (ערוץ צד של זמן): What a Lookup Gives Away, על חיפוש פיקדון ולא על איפוס סיסמה. ההשוואה לזמן תגובה רק בלוג של האפליקציה, עם ערכים אחרים (בלי 212, 812 או 94, ובלי python-requests).
- m1 (הבוס): כל אות נלמד בתחנה שלו. Where the Proof Lives מלמדת את שלושת המקומות שבהם ההוכחה יושבת על התראות חדשות, ו-Would This Field Differ? עובדת על המקרים של Wexcombe בלבד, בלי שמות התקיפות ובלי צירופי הזיווג של m1.

## סרטונים (כל אחד מסתיים בכרטיס NEXT MISSION עם הפעולה הראשונה, ולא חושף את תשובות התרגול שאחריו)
| סרטון | מתי | הפניה |
|---|---|---|
| Intro: "One Line to Sign" | כניסה | תחנה 1 |
| Chapter 2: "The Pile Gets Taller" | אחרי The Odd One | תחנה 2 |
| Chapter 3: "The Lawyer's Questions" | אחרי The Real Screen | תחנה 4 |
| Finale: "Signed" | אחרי The Fine Print | החדר הבא |

**הערות לסרטונים:** Intro מציג את Ifeoma, את המכירה ואת ערימת הכרטיסים הסגורים. Chapter 2 מספר שהכרטיס הראשון נפתח מחדש ושיש עוד בערימה, בלי לומר איך זוהה. Chapter 3 מספר שעורך הדין של הקונה מתחיל לשאול שאלות והלו"ז מתהדק, בלי להראות שיטת קריאה של שדות, הרשאות או טבלאות. Finale מספר שהשורה שנחתמת בסוף שונה מזו שהתבקשה, ומפנה לחדר הבא.
