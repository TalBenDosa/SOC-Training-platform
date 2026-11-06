# תסריט חדר 109: Unsecured Credentials & Credential Stores

**שם המבצע:** Operation Plaintext
**רמה:** מתקדם (כל ה-primers מקופלים, `fold: true`)
**העולם:** Oakmere Regional Rail (חברה בדויה): רכבת אזורית עם שני דיפואים, פלטפורמת כרטוס בענן, ו-share של העברת משמרת שאף אחד לא סידר מאז שינוי לוח הזמנים האחרון.
**המנטור:** Valentina Osei, Credential Exposure Analyst. (בטקסטים במעבדות אין לשון זכר או נקבה.)

## סיפור הרקע
ביום שני סריקה שגרתית מוצאת סקריפט עם סיסמת שירות מוקלדת בתוכו, על share שכל קבלן בבניין יכול לקרוא. מחיקת הקובץ הייתה לוקחת דקה. Valentina Osei לא מוחקת: קודם צריך לדעת מי קרא אותו, ולאן השורה הזו הובילה. המעקב עובר מה-share לדיפו, משם לענן, ובסוף לבסיס נתונים נעול.

## המכניקה הייחודית של החדר
**Secrets Left Lying Around:** סקריפטים, shares, רג'יסטרי, bash history, ‏GPP ו-cloud metadata.
- **Who Read depot_sync.ps1?:** `hunt` ב-KQL של שש שורות (חמש מדרגות) על אירועי תהליכים וקבצים. אין טבלה שרושמת קריאה רגילה, ולכן מוצאים את הקובץ ב-command line, מסירים את מה שמוסבר, ומחברים לפי מכשיר ו-PID ואז לפי מכשיר וחשבון.
- **Live Secret or Placeholder?:** `sort` של 14 ערכים: סוד חי מול placeholder. כל הערכים מזויפים לעין: בסיסמאות מופיעה המילה FAKE, ומפתחות AWS מסתיימים ב-EXAMPLE.
- **One Password, Every Depot:** `outbreak` שמראה למה בידוד מארח אחרי מארח מפסיד לסיסמה שמודבקת בכל מקום, ולמה רק רוטציה סוגרת את כל העותקים בבת אחת.

## העולם התלת-ממדי
אולם (`hall`) עם ליבת `knot`, חמישה קלפי תחנה. theme: `plaintext`, scene: `facilityplaintext`, layout: `facility`.

## סדר המשימות
r1, r2, q1 | r3, q2, r4, q3 | r5, la1, r6, ac1 | r7, q4, m1, o1 | la2, f1

הסדר המקורי של החדר נשמר. הדגל מפנה לרשומת ה-analyst_choice בלי מספר "Log Analysis", ולכן אין הפניה שצריכה בדיקה.

## התחנות
| # | תחנה | משימות | המשחקים |
|---|---|---|---|
| 1 | The Share | r1, r2, q1 | **Broke In, or Picked It Up?** (sort), **Walk the Sweep Report** (inspect), **Live Secret or Placeholder?** (sort), **Who Read depot_sync.ps1?** (hunt), **Sweep SYSVOL for Leftovers** (worksheet) |
| 2 | The Keyring | r3, q2, r4, q3 | **Read a Gateway's Shell History** (hotspot), **What Stands Between the File and a Login?** (simulate), **Which Rule Earns a 03:00 Call?** (worksheet), **What Ran Before the Dump?** (trace) |
| 3 | The Cloud Vault | r5, la1, r6, ac1 | **Read a Finding When the Theft Left No Log** (anatomy), **What a Successful Read Leaves in the Trail** (inspect), **Same Role, Two Callers** (spotdiff), **New Pair, or Old Habit?** (worksheet), **Five Gaps, Five Habits** (match), **One Password, Every Depot** (outbreak), **Four Alerts on One Vault** (queue) |
| 4 | The Locked File | r7, q4, m1, o1 | **Read One Object-Access Record** (anatomy), **One Database, Two Routes** (spotdiff), **Follow One Secret to the Next** (sequence) |
| 5 (בוס) | The Last Read | la2, f1 | **Could They, and Should They?** (simulate), **Read a Filter Inside a Request** (anatomy) |

**הפרדה מהשאלות הנבחנות:**
- **שאלת הביניים של r1** (ההבדל בין T1003 ל-T1552/T1555): **Broke In, or Picked It Up?** מלמד את ההבדל דרך מהלכים מדו"ח red team. שונה: ה-primer מראה סיסמה אחת בשני מסלולים על שרת דואר, בלי השוואת סביבות ובלי דיון בהרשאות.
- **q1** (האם cpassword עדיין ניתן לפענוח אחרי MS14-025): ה-primer של **Sweep SYSVOL for Leftovers** מציג את העובדות: מפתח פומבי, SYSVOL קריא, והתיקון הוציא את שדות הסיסמה מהעורך. שונה: השאלות במעבדה הן ספירת קבצים ורוטציה, היא לא שואלת על התיקון, ואין בה דומיין שהותקן בו תיקון לפני 18 חודשים.
- **שאלת הביניים של r3** (למה passphrase חשוב): **What Stands Between the File and a Login?** מראה ארבעה קבצים ומה עומד בין הקובץ להתחברות. שונה: ה-pfx והסיסמה שלידו, בלי שאלה ישירה על הקובץ הגנוב.
- **q2** (למה כותרת מפתח היא סימן מדויק): **Which Rule Earns a 03:00 Call?** מלמד דרך מספרים של חוקי סריקה ב-Git, עם כותרות PGP ו-EC. שונה: לא DLP, לא העלאה החוצה, לא OPENSSH.
- **q3** (למה גניבת Keychain היא שלב שני): **What Ran Before the Dump?** הוא מעקב תהליכים אחורה, דיאלוג מזויף ואז פתיחת הכספת. שונה: המעבדה לא שואלת למה זה שלב שני. ה-primer מלמד שה-keychain צריך להיות פתוח, ודוגמת ה-primer היא Chrome Safe Storage.
- **la1** (מקור ו-user agent, זוג זהות וסוד, errorCode ריק): **Same Role, Two Callers** מלמד את שני השדות, **New Pair, or Old Habit?** מלמד בסיס לפי זוג, **What a Successful Read Leaves in the Trail** מלמד את שני שדות התוצאה. שונה: Parameter Store ו-role של EC2, לא GetSecretValue ולא Lambda, בלי שבעה ARN.
- **ac1** (פסק דין על פרץ קריאות מתוזמן): **Four Alerts on One Vault** מלמד את שלוש המילים ומשווה לשדות ולמה שמתועד. שונה: הגדלת צי, build runner, קריאת רשימה ו-canary, בלי עבודת רוטציה ובלי BatchGetSecretValue. דוגמת ה-primer היא סורק פגיעויות.
- **q4** (למה שכפול לא יוצר 4663): סיכום **Read One Object-Access Record** מראה שירות שמשרת לקוחות דרך handle שנפתח בעלייה, וה-primer מציין ש-DRSUAPI מדבר עם שירות AD DS. שונה: מסד TrackAccess, לא בקר תחום. הלומד מחבר את שני הדברים לבד.
- **m1** (התאמת טכניקה לארטיפקט): **Walk the Sweep Report** מציג את העובדות כנתונים עם תווית ולא שואל אותן. שונה: פריטים מהסריקה של Oakmere ובניסוח אחר. T1552.002 ו-T1552.003 מופיעים בדו"ח כנתון בלבד, ואינם חלק מהמשימה הנבחנת.
- **o1** (סידור שרשרת): **Follow One Secret to the Next** מתרגל את הרעיון על שרשרת אחרת. שונה: מתחיל ב-share ונגמר ב-Parameter Store, בלי קומיט פומבי ובלי בוט.
- **la2** (נתיב device, ‏%%4416, אדמין): **One Database, Two Routes** מלמד את האות המכריע במעבדה משלו, **Read One Object-Access Record** מציג את %%4416 כנתון עם תווית, ו-**Could They, and Should They?** מלמד שהרשאה לא מסבירה כלום. שונה: esentutl ומסד ESE של TrackAccess על שרת רגיל, לא ntdsutil, לא ntds.dit ולא בקר תחום. אין במעבדות שורה ששוללת את אפשרויות המסיח אחת אחת.
- **f1** (הערך המדויק בפילטר): **Read a Filter Inside a Request** מלמד לקרוא Key ו-Values. שונה: ListSecrets עם פילטר `name`, לא פילטר תגית.

## סרטונים (כל אחד מסתיים בכרטיס NEXT MISSION עם הפעולה הראשונה, ולא חושף את תשובות התרגול שאחריו)
| סרטון | מתי | הפניה |
|---|---|---|
| Intro: "One Line in a Script" | כניסה | תחנה 1 |
| Chapter 2: "Friday's Contractor" | אחרי The Share | תחנה 2 |
| Chapter 3: "No Log of the Theft" | אחרי The Cloud Vault | תחנה 4 |
| Finale: "Everything It Opened" | אחרי The Last Read | החדר הבא |

**הערות לסרטונים:**
- Intro: הסריקה של יום שני, הקובץ על ה-share, ו-Valentina שעוצרת את המחיקה. מראים שהסיפור מתחיל בשאלה "מי קרא". לא מראים שאילתה.
- Chapter 2: החשבון של קבלן שסיים לעבוד ביום שישי חוזר ביום ראשון בלילה. מראים את הפער בסיפור בלבד, בלי שורות KQL ובלי מפתחות.
- Chapter 3: הענן הודיע, אבל את הגניבה עצמה איש לא ראה. סיפור בלבד, בלי קריאת שדות.
- Finale: Valentina מציגה להנהלה עד לאן שורה אחת הגיעה, ומה משנים. סיפור בלבד, בלי שיטת ניתוח של רשומה.
